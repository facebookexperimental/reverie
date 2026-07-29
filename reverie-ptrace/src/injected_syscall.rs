/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Register-frame support for syscall events injected by a binary rewriter.

use reverie::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::Sysno;

/// The register frame produced by e9tool's `state` call-trampoline argument.
///
/// The ptrace controller and e9patch's in-process AOT dispatcher share this
/// exact layout. Backends opt into the fallback trap ABI with
/// [`crate::TracerBuilder::injected_syscall_trap`].
// TODO-HUMAN-REVIEW(PR-102): Review the e9tool state-frame syscall ABI.
// TODO-HUMAN-REVIEW(PR-264): Review exposing the existing e9tool state frame
// to the in-process AOT dispatcher.
// AUTONOMOUS-BOT-IMPLEMENTED
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct InjectedSyscallFrame {
    flags: u64,
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    rsp: u64,
    rip: u64,
}

impl InjectedSyscallFrame {
    const FLAGS_OF: u64 = 0x0001;
    const FLAGS_CF: u64 = 0x0100;
    const FLAGS_PF: u64 = 0x0400;
    const FLAGS_AF: u64 = 0x1000;
    const FLAGS_ZF: u64 = 0x4000;
    const FLAGS_SF: u64 = 0x8000;

    const RFLAGS_CF: u64 = 0x0001;
    const RFLAGS_PF: u64 = 0x0004;
    const RFLAGS_AF: u64 = 0x0010;
    const RFLAGS_ZF: u64 = 0x0040;
    const RFLAGS_SF: u64 = 0x0080;
    const RFLAGS_OF: u64 = 0x0800;
    const STATUS_RFLAGS: u64 = Self::RFLAGS_CF
        | Self::RFLAGS_PF
        | Self::RFLAGS_AF
        | Self::RFLAGS_ZF
        | Self::RFLAGS_SF
        | Self::RFLAGS_OF;

    /// Returns the syscall number without materializing the full [`Syscall`]
    /// enum. Instrumentation bridges use this compact accessor on bounded
    /// trampoline stacks.
    pub fn syscall_number(&self) -> Sysno {
        Sysno::from(self.rax as i32)
    }

    /// Decodes the syscall stored in this e9tool frame.
    pub fn syscall(&self) -> Syscall {
        Syscall::from_raw(
            self.syscall_number(),
            SyscallArgs::new(
                self.rdi as usize,
                self.rsi as usize,
                self.rdx as usize,
                self.r10 as usize,
                self.r8 as usize,
                self.r9 as usize,
            ),
        )
    }

    /// Returns the six raw syscall arguments in Linux x86-64 ABI order.
    pub fn raw_args(&self) -> [u64; 6] {
        [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    /// Returns the address of the syscall instruction replaced by e9tool.
    pub fn instruction_pointer(&self) -> u64 {
        self.rip
    }

    /// Applies the architectural `RCX`/`R11` clobbers of a native syscall.
    pub fn emulate_syscall_entry(&mut self, trap_rflags: u64) {
        // A native x86-64 syscall places the continuation RIP in RCX and the
        // pre-syscall flags in R11 before seccomp delivers its ptrace stop.
        // The replacement trampoline bypasses that instruction, so reproduce
        // those architectural clobbers in the frame restored by e9tool.
        self.rcx = self.rip + 2;
        self.r11 = self.native_rflags(trap_rflags);
    }

    /// Stores a syscall result for e9tool to restore into guest `RAX`.
    pub fn set_result(&mut self, result: i64) {
        self.rax = result as u64;
    }

    pub(crate) fn copy_to_user_regs(&self, regs: &mut libc::user_regs_struct) {
        regs.r15 = self.r15;
        regs.r14 = self.r14;
        regs.r13 = self.r13;
        regs.r12 = self.r12;
        regs.r11 = self.r11;
        regs.r10 = self.r10;
        regs.r9 = self.r9;
        regs.r8 = self.r8;
        regs.rdi = self.rdi;
        regs.rsi = self.rsi;
        regs.rbp = self.rbp;
        regs.rbx = self.rbx;
        regs.rdx = self.rdx;
        regs.rcx = self.rcx;
        regs.rax = self.rax;
        regs.orig_rax = self.rax;
        regs.rsp = self.rsp;
        regs.rip = self.rip + 2;
        regs.eflags = self.native_rflags(regs.eflags);
    }
    // TODO-HUMAN-REVIEW(PR-103): Review representable rewritten-register updates.
    pub(crate) fn validate_user_regs_update(
        current: &libc::user_regs_struct,
        requested: &libc::user_regs_struct,
    ) -> Result<(), Errno> {
        let unsupported = current.orig_rax != requested.orig_rax
            || current.rip != requested.rip
            || current.cs != requested.cs
            || current.ss != requested.ss
            || current.ds != requested.ds
            || current.es != requested.es
            || current.fs != requested.fs
            || current.gs != requested.gs
            || current.fs_base != requested.fs_base
            || current.gs_base != requested.gs_base
            || (current.eflags ^ requested.eflags) & !Self::STATUS_RFLAGS != 0;
        if unsupported {
            Err(Errno::ENOTSUPP)
        } else {
            Ok(())
        }
    }

    pub(crate) fn copy_from_user_regs(&mut self, regs: &libc::user_regs_struct) {
        self.r15 = regs.r15;
        self.r14 = regs.r14;
        self.r13 = regs.r13;
        self.r12 = regs.r12;
        self.r11 = regs.r11;
        self.r10 = regs.r10;
        self.r9 = regs.r9;
        self.r8 = regs.r8;
        self.rdi = regs.rdi;
        self.rsi = regs.rsi;
        self.rbp = regs.rbp;
        self.rbx = regs.rbx;
        self.rdx = regs.rdx;
        self.rcx = regs.rcx;
        self.rax = regs.rax;
        self.rsp = regs.rsp;
        self.flags = Self::e9_flags(regs.eflags);
        // e9tool documents RIP as read-only in this frame. Control flow still
        // returns to the instruction following the replaced syscall.
    }

    fn native_rflags(&self, base: u64) -> u64 {
        let mut flags = base & !Self::STATUS_RFLAGS;
        for (e9, native) in [
            (Self::FLAGS_CF, Self::RFLAGS_CF),
            (Self::FLAGS_PF, Self::RFLAGS_PF),
            (Self::FLAGS_AF, Self::RFLAGS_AF),
            (Self::FLAGS_ZF, Self::RFLAGS_ZF),
            (Self::FLAGS_SF, Self::RFLAGS_SF),
            (Self::FLAGS_OF, Self::RFLAGS_OF),
        ] {
            if self.flags & e9 != 0 {
                flags |= native;
            }
        }
        flags
    }

    fn e9_flags(flags: u64) -> u64 {
        let mut e9 = 0;
        for (native, encoded) in [
            (Self::RFLAGS_CF, Self::FLAGS_CF),
            (Self::RFLAGS_PF, Self::FLAGS_PF),
            (Self::RFLAGS_AF, Self::FLAGS_AF),
            (Self::RFLAGS_ZF, Self::FLAGS_ZF),
            (Self::RFLAGS_SF, Self::FLAGS_SF),
            (Self::RFLAGS_OF, Self::FLAGS_OF),
        ] {
            if flags & native != 0 {
                e9 |= encoded;
            }
        }
        e9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> InjectedSyscallFrame {
        InjectedSyscallFrame {
            flags: InjectedSyscallFrame::FLAGS_ZF | InjectedSyscallFrame::FLAGS_PF,
            r15: 1,
            r14: 2,
            r13: 3,
            r12: 4,
            r11: 5,
            r10: 6,
            r9: 7,
            r8: 8,
            rdi: 9,
            rsi: 10,
            rbp: 11,
            rbx: 12,
            rdx: 13,
            rcx: 14,
            rax: libc::SYS_write as u64,
            rsp: 16,
            rip: 0x401000,
        }
    }

    #[test]
    fn frame_matches_e9tool_state_layout() {
        assert_eq!(core::mem::size_of::<InjectedSyscallFrame>(), 18 * 8);
        assert_eq!(core::mem::offset_of!(InjectedSyscallFrame, rax), 15 * 8);
        assert_eq!(core::mem::offset_of!(InjectedSyscallFrame, rip), 17 * 8);
        assert_eq!(frame().syscall_number(), Sysno::write);
    }

    #[test]
    fn syscall_entry_clobbers_match_x86_64() {
        let mut frame = frame();
        frame.emulate_syscall_entry(0x202);
        assert_eq!(frame.rcx, 0x401002);
        assert_eq!(frame.r11, 0x246);
    }

    #[test]
    fn user_register_round_trip_preserves_writable_fields() {
        let mut frame = frame();
        frame.emulate_syscall_entry(0x202);
        let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        regs.eflags = 0x202;
        frame.copy_to_user_regs(&mut regs);
        assert_eq!(regs.orig_rax, libc::SYS_write as u64);
        assert_eq!(regs.rip, 0x401002);
        assert_eq!(regs.eflags, 0x246);

        regs.rax = 99;
        regs.rdi = 42;
        regs.eflags = 0x203;
        frame.copy_from_user_regs(&regs);
        assert_eq!(frame.rax, 99);
        assert_eq!(frame.rdi, 42);
        assert_eq!(frame.rip, 0x401000);
        assert_eq!(frame.flags, InjectedSyscallFrame::FLAGS_CF);
    }

    #[test]
    fn rejects_register_updates_the_e9_frame_cannot_represent() {
        let frame = frame();
        let mut current = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        current.eflags = 0x202;
        frame.copy_to_user_regs(&mut current);
        let mut requested = current;
        requested.rip += 4;
        assert_eq!(
            InjectedSyscallFrame::validate_user_regs_update(&current, &requested),
            Err(Errno::ENOTSUPP)
        );
    }
}
