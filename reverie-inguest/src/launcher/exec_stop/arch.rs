// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Per-architecture facts for exec-stop capture and drain.
//!
//! This module is the one place in `exec_stop` where
//! `cfg(target_arch)` may appear (the aarch64 exec-stop port's
//! confinement rule). Everything above it — `EntryContext`,
//! `drain_and_capture`, stack snapshot and read-back — is written
//! against these functions and stays architecture-neutral.
//!
//! x86-64 facts: the register image is `user_regs_struct` including
//! segment and FS/GS base state; the extended state is the opaque
//! NT_X86_XSTATE image; the syscall number at an exec-event stop is
//! `orig_rax`; the audit architecture word is AUDIT_ARCH_X86_64.
//!
//! aarch64 facts: the register image is `user_pt_regs` (x0-x30, sp,
//! pc, pstate) via NT_PRSTATUS; the extended state is the NT_PRFPREG
//! fpsimd image (NT_ARM_SVE is not captured yet: at an exec stop no
//! guest FP/SVE instruction has run, and safeptrace has no SVE
//! regset accessor — named here so nobody assumes it is saved);
//! the thread pointer is TPIDR_EL0 via NT_ARM_TLS; the syscall
//! number at an exec-event stop must be read via NT_ARM_SYSTEM_CALL
//! because `start_thread` zeroes the GPRs (x8 reads 0 there), and
//! kernels before v6.0 forget the number entirely (see
//! `check_event_syscall_number`).

use safeptrace::Regs;
use safeptrace::Stopped;

use super::Result;

/// The audit architecture word PTRACE_GET_SYSCALL_INFO reports.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xc000_003e;
/// The audit architecture word PTRACE_GET_SYSCALL_INFO reports.
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xc000_00b7;

/// The execve syscall number for this architecture.
#[cfg(target_arch = "x86_64")]
pub const EXECVE_SYSCALL: u64 = libc::SYS_execve as u64;
/// The execve syscall number for this architecture.
#[cfg(target_arch = "aarch64")]
pub const EXECVE_SYSCALL: u64 = 221;

/// The extended processor state saved with an entry context:
/// NT_X86_XSTATE bytes on x86-64, the NT_PRFPREG fpsimd image on
/// aarch64 (see the module note on SVE).
#[cfg(target_arch = "x86_64")]
pub type ExtendedState = safeptrace::XState;
/// The extended processor state saved with an entry context.
#[cfg(target_arch = "aarch64")]
pub type ExtendedState = safeptrace::FpRegs;

/// Capture the extended processor state of a stopped task.
pub fn capture_extended_state(task: &Stopped) -> Result<ExtendedState> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(task.getxstate()?)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(task.getfpregs()?)
    }
}

/// Restore a captured extended processor state and return the fresh
/// read-back for comparison by the caller.
pub fn restore_extended_state(task: &Stopped, state: &ExtendedState) -> Result<ExtendedState> {
    #[cfg(target_arch = "x86_64")]
    {
        task.setxstate(state)?;
        Ok(task.getxstate()?)
    }
    #[cfg(target_arch = "aarch64")]
    {
        task.setfpregs(state)?;
        Ok(task.getfpregs()?)
    }
}

/// The saved thread pointer of a stopped task (TPIDR_EL0 on
/// aarch64). x86-64 carries FS/GS base inside the register image,
/// so there is nothing separate to save.
#[cfg(target_arch = "aarch64")]
pub fn capture_thread_pointer(task: &Stopped) -> Result<u64> {
    Ok(task.get_thread_pointer()?)
}

/// Restore a saved thread pointer and return the fresh read-back.
#[cfg(target_arch = "aarch64")]
pub fn restore_thread_pointer(task: &Stopped, value: u64) -> Result<u64> {
    task.set_thread_pointer(value)?;
    Ok(task.get_thread_pointer()?)
}

/// Set the stack pointer of a register image.
pub fn set_stack_pointer(regs: &mut Regs, value: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        regs.rsp = value;
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.sp = value;
    }
}

/// Set the instruction pointer of a register image.
pub fn set_instruction_pointer(regs: &mut Regs, value: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        regs.rip = value;
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.pc = value;
    }
}

/// Instruction pointer of a register image.
pub fn instruction_pointer(regs: &Regs) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        regs.rip
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.pc
    }
}

/// Stack pointer of a register image.
pub fn stack_pointer(regs: &Regs) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        regs.rsp
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.sp
    }
}

/// The syscall number an exec-event stop originated in. On x86-64
/// this is `orig_rax`. On aarch64 the GPRs are zeroed at the stop,
/// so the number comes from the NT_ARM_SYSTEM_CALL regset, and a
/// read of -1 (NO_SYSCALL: a pre-v6.0 kernel forgot the number in
/// `start_thread`) is refused by name rather than guessed.
pub fn event_syscall_number(task: &Stopped, regs: &Regs) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = task;
        Ok(regs.orig_rax)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let _ = regs;
        check_event_syscall_number(task.get_syscall_number()?)
    }
}

/// Refuse a forgotten or foreign syscall number at an exec stop.
///
/// On aarch64 kernels before v6.0, `start_thread_common` calls
/// `forget_syscall()` and NT_ARM_SYSTEM_CALL reads NO_SYSCALL (-1)
/// at the exec stop (arch/arm64/include/asm/processor.h at v5.19);
/// commit de6921856f99 ("arm64: Do not forget syscall when starting
/// a new thread.", first tag v6.0) preserves the number, and v6.16
/// keeps it for the sys_exit_execve tracepoint. x8 reads 0 at the
/// stop on every kernel, so -1 must refuse, never fall back.
#[cfg(target_arch = "aarch64")]
pub fn check_event_syscall_number(syscallno: i32) -> Result<u64> {
    if syscallno == -1 {
        return Err("exec-stop refused: syscall number unavailable at exec stop \
                    (NT_ARM_SYSTEM_CALL read NO_SYSCALL; kernels before v6.0 forget it in start_thread)"
            .into());
    }
    if syscallno < 0 || syscallno as u64 != EXECVE_SYSCALL {
        return Err(format!(
            "exec-stop refused: exec event did not originate in execve (syscall {syscallno})"
        )
        .into());
    }
    Ok(syscallno as u64)
}

/// Exact native register words in this architecture's pinned order.
///
/// x86-64: the existing 27-word order (segments and bases included).
/// aarch64: 34 words — x0-x30, sp, pc, pstate. The thread pointer
/// is not part of this image (it is saved separately, above).
#[cfg(target_arch = "x86_64")]
pub type RegisterWords = [u64; 27];
/// Exact native register words in this architecture's pinned order.
#[cfg(target_arch = "aarch64")]
pub type RegisterWords = [u64; 34];

/// Serialize a register image to [`RegisterWords`].
pub fn register_words(r: &Regs) -> RegisterWords {
    #[cfg(target_arch = "x86_64")]
    {
        [
            r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx,
            r.rdx, r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base,
            r.gs_base, r.ds, r.es, r.fs, r.gs,
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut words = [0u64; 34];
        words[..31].copy_from_slice(&r.regs);
        words[31] = r.sp;
        words[32] = r.pc;
        words[33] = r.pstate;
        words
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    #[test]
    fn a_forgotten_syscall_number_refuses_by_name() {
        // Pre-v6.0 kernels forget the number in start_thread; the
        // drain must refuse, not guess from x8 (which reads 0).
        let err = super::check_event_syscall_number(-1).unwrap_err();
        assert!(err.to_string().contains("NO_SYSCALL"), "{err}");
        assert!(err.to_string().contains("exec-stop refused"), "{err}");
    }

    #[test]
    fn only_execve_is_accepted_at_the_exec_stop() {
        assert_eq!(super::check_event_syscall_number(221).unwrap(), 221);
        assert!(super::check_event_syscall_number(0).is_err());
        assert!(super::check_event_syscall_number(220).is_err());
        assert!(super::check_event_syscall_number(-2).is_err());
    }

    #[test]
    fn register_words_use_the_pinned_aarch64_order() {
        let mut regs = safeptrace::Regs {
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        };
        regs.regs[0] = 10;
        regs.regs[30] = 40;
        regs.sp = 50;
        regs.pc = 60;
        regs.pstate = 70;
        let words = super::register_words(&regs);
        assert_eq!(words.len(), 34);
        assert_eq!(words[0], 10);
        assert_eq!(words[30], 40);
        assert_eq!(words[31], 50);
        assert_eq!(words[32], 60);
        assert_eq!(words[33], 70);
    }
}
