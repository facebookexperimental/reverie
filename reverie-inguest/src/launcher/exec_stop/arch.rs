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
//! fpsimd image plus TPIDR_EL0. SVE/SME state is NOT captured or
//! restored: an NT_PRFPREG restore zero-pads the SVE Z upper bits
//! and leaves P/FFR, vector length, SME streaming state, TPIDR2
//! and FPMR as the runtime left them. That is harmless only while
//! nothing runs between capture and restore (PR1 does not arm);
//! before arming, restore must refuse live SVE/SME state (an
//! NT_ARM_SVE/SSVE header check) — named here as refused-before-
//! arming work, not silently assumed away;
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

/// The extended processor state saved with an entry context.
/// x86-64: the opaque NT_X86_XSTATE bytes (FS/GS base ride inside
/// the register image, so nothing else is separate). aarch64: the
/// NT_PRFPREG fpsimd image plus TPIDR_EL0, which lives outside
/// the GPRs and must ride here so every unchanged-context
/// comparison covers it exactly as x86's fs_base is covered.
#[cfg(target_arch = "x86_64")]
pub type ExtendedState = safeptrace::XState;
/// The extended processor state saved with an entry context.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedState {
    /// NT_PRFPREG fpsimd image.
    pub fp: safeptrace::FpRegs,
    /// TPIDR_EL0 via NT_ARM_TLS.
    pub tpidr_el0: u64,
}

/// Capture the extended processor state of a stopped task.
pub fn capture_extended_state(task: &Stopped) -> Result<ExtendedState> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(task.getxstate()?)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(ExtendedState {
            fp: task.getfpregs()?,
            tpidr_el0: task.get_thread_pointer()?,
        })
    }
}

/// Write a captured extended processor state back. The caller
/// reads the whole context back after all writes (see
/// `EntryContext::restore`), so this function only writes.
pub fn write_extended_state(task: &Stopped, state: &ExtendedState) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(task.setxstate(state)?)
    }
    #[cfg(target_arch = "aarch64")]
    {
        task.set_thread_pointer(state.tpidr_el0)?;
        Ok(task.setfpregs(&state.fp)?)
    }
}

/// Raw syscall for the stopped-child bridge, with this
/// architecture's register convention. x86-64: number in rax,
/// result in rax, arguments rdi/rsi/rdx/r10/r8/r9. aarch64:
/// number in x8 (input only), result in x0, arguments x0-x5 —
/// reading x8 back as the result was the PR1 F1 defect (getpid
/// "returned" 172 and clone3 looked successful to the wrong
/// branch), pinned by the native test below.
///
/// # Safety
/// Pointer-valued arguments must satisfy the selected Linux
/// syscall's ABI.
#[allow(unsafe_code)]
pub(crate) unsafe fn syscall6(number: u64, args: [u64; 6]) -> i64 {
    // SAFETY: the caller owns every pointer operand. All syscall
    // clobbers are declared and the stack is untouched.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let result: i64;
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
        result
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let result: i64;
        core::arch::asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") args[0] => result,
            in("x1") args[1], in("x2") args[2], in("x3") args[3],
            in("x4") args[4], in("x5") args[5],
            options(nostack),
        );
        result
    }
}

/// The stack-pointer word inside a serialized register image.
/// x86-64 word 19 is rsp; aarch64 word 31 is sp. Consumers must
/// never index the image directly.
pub fn stack_pointer_word(words: &RegisterWords) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        words[19]
    }
    #[cfg(target_arch = "aarch64")]
    {
        words[31]
    }
}

/// Substitute the event stop's x7 into an image captured at the
/// following syscall-exit stop. On aarch64, `report_syscall`
/// (arch/arm64/kernel/ptrace.c) overwrites x7 with the stop
/// direction for the length of every syscall stop and discards
/// tracer writes to it, so the exit-stop image's x7 is the
/// kernel's 1, not the guest's value; the event stop is not a
/// syscall stop and its x7 is real. On x86-64 there is no such
/// clobber and this is a no-op.
pub fn substitute_event_x7(captured: &mut Regs, event: &Regs) {
    #[cfg(target_arch = "aarch64")]
    {
        captured.regs[7] = event.regs[7];
    }
    #[cfg(target_arch = "x86_64")]
    {
        let _ = (captured, event);
    }
}

/// Whether a live register image matches a captured one. The
/// captured image carries the event stop's x7; the live task is
/// parked at a syscall stop, where the kernel overwrites x7 with
/// the stop direction and discards tracer writes to it
/// (`report_syscall`), so that one word is unobservable there and
/// is normalized from the captured image before comparing. Every
/// other word must match exactly.
pub fn live_matches_captured(live: &Regs, captured: &Regs) -> bool {
    let mut normalized = *live;
    substitute_event_x7(&mut normalized, captured);
    register_words(&normalized) == register_words(captured)
}

/// The drain predicate, pure so both architectures' refusals are
/// unit-testable: the syscall-info architecture must be this
/// target's, the event must have originated in execve, and the
/// exit-stop image must show no instruction or stack progress.
pub fn drain_accepts(architecture: u32, syscall_number: u64, event: &Regs, exit: &Regs) -> bool {
    architecture == AUDIT_ARCH
        && syscall_number == EXECVE_SYSCALL
        && instruction_pointer(exit) == instruction_pointer(event)
        && stack_pointer(exit) == stack_pointer(event)
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

#[cfg(test)]
mod confinement_tests {
    // The confinement rule (approved design): every cfg on
    // target_arch in the capture/drain surface lives in this
    // module. These sibling sources are read as text; the check
    // is exact, not a pattern that can drift.
    #[test]
    fn no_target_arch_outside_the_arch_module_in_capture_drain() {
        // Plain substring: cfg, cfg!, cfg_attr, not/all/any forms
        // all contain it, so none can slip through spelled wider.
        for source in [
            include_str!("mod.rs"),
            include_str!("child.rs"),
            include_str!("initial_inputs.rs"),
        ] {
            assert!(
                !source.contains("target_arch"),
                "target_arch outside exec_stop/arch.rs"
            );
        }
    }

    #[test]
    fn drain_calls_the_arch_predicate() {
        // Wiring pin (N4): the drain must actually consult
        // drain_accepts; replacing the call with `false` fails here.
        assert!(
            include_str!("mod.rs").contains("!arch::drain_accepts("),
            "drain_and_capture does not call arch::drain_accepts"
        );
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
    #[allow(unsafe_code)]
    fn syscall6_returns_the_result_register_not_the_number() {
        // F1 regression pin: with the old x8 read-back, getpid
        // returned its own syscall number (172) and a failing
        // read returned the number too. The result must come
        // from x0: the real pid, and -EBADF for a bad descriptor.
        let pid = unsafe { super::syscall6(libc::SYS_getpid as u64, [0; 6]) };
        assert_eq!(pid, i64::from(std::process::id()));
        let err = unsafe { super::syscall6(libc::SYS_read as u64, [u64::MAX, 0, 0, 0, 0, 0]) };
        assert_eq!(err, -i64::from(libc::EBADF));
    }

    #[test]
    fn captured_x7_comes_from_the_event_stop() {
        // The exit-stop image's x7 is the kernel stop direction
        // (1); the event stop's x7 is the guest's. Capture must
        // carry the event value (here the post-start_thread 0).
        let mut captured = safeptrace::Regs {
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        };
        captured.regs[7] = 1;
        let event = safeptrace::Regs {
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        };
        super::substitute_event_x7(&mut captured, &event);
        assert_eq!(captured.regs[7], 0);
    }

    #[test]
    fn live_syscall_stop_image_matches_captured_except_x7() {
        // N1: the live task at the drained syscall stop reports
        // x7=1 (kernel stop direction); the captured image holds
        // the event stop's x7=0. They must compare equal, and any
        // other differing word must not.
        let captured = safeptrace::Regs {
            regs: [0; 31],
            sp: 0x5000,
            pc: 0x4000,
            pstate: 0,
        };
        let mut live = captured;
        live.regs[7] = 1;
        assert!(super::live_matches_captured(&live, &captured));
        let mut other = live;
        other.regs[3] = 9;
        assert!(!super::live_matches_captured(&other, &captured));
        let mut moved = live;
        moved.pc += 4;
        assert!(!super::live_matches_captured(&moved, &captured));
    }

    #[test]
    fn drain_predicate_refuses_foreign_arch_and_number() {
        let image = safeptrace::Regs {
            regs: [0; 31],
            sp: 0x5000,
            pc: 0x4000,
            pstate: 0,
        };
        assert!(super::drain_accepts(super::AUDIT_ARCH, 221, &image, &image));
        assert!(!super::drain_accepts(0xc000_003e, 221, &image, &image));
        assert!(!super::drain_accepts(
            super::AUDIT_ARCH,
            220,
            &image,
            &image
        ));
        let mut progressed = image;
        progressed.pc += 4;
        assert!(!super::drain_accepts(
            super::AUDIT_ARCH,
            221,
            &image,
            &progressed
        ));
        let mut moved = image;
        moved.sp += 8;
        assert!(!super::drain_accepts(
            super::AUDIT_ARCH,
            221,
            &image,
            &moved
        ));
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

#[cfg(all(test, target_arch = "x86_64"))]
mod x86_tests {
    #[test]
    fn register_words_use_the_pinned_x86_order() {
        // 27 distinct sentinels, one per field, asserted at every
        // position: any substitution or transposition (the
        // fs_base/gs_base mutant included) fails.
        let regs = safeptrace::Regs {
            r15: 1,
            r14: 2,
            r13: 3,
            r12: 4,
            rbp: 5,
            rbx: 6,
            r11: 7,
            r10: 8,
            r9: 9,
            r8: 10,
            rax: 11,
            rcx: 12,
            rdx: 13,
            rsi: 14,
            rdi: 15,
            orig_rax: 16,
            rip: 17,
            cs: 18,
            eflags: 19,
            rsp: 20,
            ss: 21,
            fs_base: 22,
            gs_base: 23,
            ds: 24,
            es: 25,
            fs: 26,
            gs: 27,
        };
        let words = super::register_words(&regs);
        assert_eq!(words.len(), 27);
        for (index, word) in words.iter().enumerate() {
            assert_eq!(*word, index as u64 + 1, "word {index}");
        }
        assert_eq!(super::stack_pointer_word(&words), 20);
    }

    #[test]
    fn drain_predicate_refuses_foreign_arch_and_number() {
        let image = safeptrace::Regs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0x4000,
            cs: 0,
            eflags: 0,
            rsp: 0x5000,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        };
        assert!(super::drain_accepts(
            super::AUDIT_ARCH,
            super::EXECVE_SYSCALL,
            &image,
            &image
        ));
        assert!(!super::drain_accepts(
            0xc000_00b7,
            super::EXECVE_SYSCALL,
            &image,
            &image
        ));
        assert!(!super::drain_accepts(
            super::AUDIT_ARCH,
            super::EXECVE_SYSCALL + 1,
            &image,
            &image
        ));
        let mut progressed = image;
        progressed.rip += 4;
        assert!(!super::drain_accepts(
            super::AUDIT_ARCH,
            super::EXECVE_SYSCALL,
            &image,
            &progressed
        ));
    }
}
