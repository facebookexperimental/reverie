/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Keeping a guest's SIGTRAP action and mask as the guest set them across
//! Reverie's own single-steps (<https://github.com/rrnewton/hermit/issues/4409>).
//!
//! Linux reports every `PTRACE_SINGLESTEP`, and every `int3`, with
//! `force_sig`. If SIGTRAP is blocked or ignored when that trap is raised,
//! `force_sig_info_to_task` sets SIGTRAP's handler to `SIG_DFL` (keeping its
//! flags, mask and restorer) and unblocks it for the thread. A guest that
//! never blocks SIGTRAP is not safe either: a Tool's injected
//! `rt_sigprocmask` that blocks every signal is itself stepped, and its trap
//! sees SIGTRAP blocked.
//!
//! The task keeps both as the guest set them in two ways:
//! - the *shield*: SIGTRAP is unblocked for a step of Reverie's own in which
//!   the kernel reads no mask for the guest (a syscall skip, a clone event's
//!   return, an exec's, an instruction after an exec), and blocked again at
//!   the step's stop;
//! - the *repair*: after the step of a Tool's injected syscall, which runs
//!   under the guest's own mask so that the call sees it as natively, the
//!   mask bit is set again and the action, if the trap could have reset it,
//!   is written back with an `rt_sigaction` that is never stepped. So is an
//!   ignored SIGTRAP after a shielded step.
//!
//! This module holds the parts that need no tracee.

use reverie::syscalls::Sysno;

/// SIGTRAP's bit in a kernel signal mask (bit `n - 1` for signal `n`).
pub(crate) const SIGTRAP_BIT: u64 = 1 << (libc::SIGTRAP as u64 - 1);

/// Every signal that can be blocked: all but SIGKILL and SIGSTOP.
pub(crate) const BLOCKABLE_SIGNAL_BITS: u64 =
    !(1 << (libc::SIGKILL as u64 - 1) | 1 << (libc::SIGSTOP as u64 - 1));

/// The kernel's `struct sigaction`, as `rt_sigaction` reads and writes it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct KernelSigaction {
    pub(crate) handler: u64,
    pub(crate) flags: u64,
    pub(crate) restorer: u64,
    pub(crate) mask: u64,
}

impl KernelSigaction {
    /// Whether the action is `SIG_IGN`.
    pub(crate) fn ignored(&self) -> bool {
        self.handler == libc::SIG_IGN as u64
    }
}

/// What a task knows of SIGTRAP's action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigtrapAction {
    /// `SIG_DFL`. A trap's reset leaves it unchanged, so nothing is kept.
    Default,
    /// Ignored or caught: the whole action, to be written back after a trap
    /// that reset it.
    Set(KernelSigaction),
}

/// SIGTRAP's disposition as procfs reports it for a thread: whether it is in
/// `SigIgn` and whether it is in `SigCgt`.
pub(crate) fn parse_sigtrap_disposition(status: &str) -> Option<(bool, bool)> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    };
    Some((
        field("SigIgn:")? & SIGTRAP_BIT != 0,
        field("SigCgt:")? & SIGTRAP_BIT != 0,
    ))
}

/// How a single-step over the injected syscall `nr` is kept from changing
/// SIGTRAP's state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepKind {
    /// The syscall does not set the blocked mask: the trap sees the mask
    /// before it.
    KeepsMask,
    /// `rt_sigprocmask`: the trap sees the mask the call sets.
    SetsMask,
    /// A mask-swapping call: the trap sees the temporary mask if the call
    /// was interrupted, else the restored saved mask.
    SwapsMask,
    /// A clone: the child takes the mask in force when it is created, so the
    /// shield would hand it SIGTRAP unblocked.
    Clones,
    /// `rt_sigreturn`: the trap sees the frame's mask. Reverie injects it only
    /// for an injected-syscall trap (`injected_syscall_trap`).
    Sigreturn,
}

/// The [`StepKind`] of a single-step over the injected syscall `nr`.
pub(crate) fn step_kind(nr: Sysno, swaps_mask: bool) -> StepKind {
    if swaps_mask {
        return StepKind::SwapsMask;
    }
    match nr {
        Sysno::rt_sigprocmask => StepKind::SetsMask,
        Sysno::clone | Sysno::clone3 => StepKind::Clones,
        #[cfg(target_arch = "x86_64")]
        Sysno::fork | Sysno::vfork => StepKind::Clones,
        Sysno::rt_sigreturn => StepKind::Sigreturn,
        _ => StepKind::KeepsMask,
    }
}

/// The blocked mask `rt_sigprocmask(how, set)` leaves when the mask before
/// it is `before`; `set` is `None` for a NULL set. An unknown `how` fails the
/// call (EINVAL) and leaves `before`.
pub(crate) fn mask_after_sigprocmask(before: u64, how: i32, set: Option<u64>) -> u64 {
    let Some(set) = set else {
        return before;
    };
    // SIGKILL and SIGSTOP are never blocked.
    let set = set & BLOCKABLE_SIGNAL_BITS;
    match how {
        libc::SIG_BLOCK => before | set,
        libc::SIG_UNBLOCK => before & !set,
        libc::SIG_SETMASK => set,
        _ => before,
    }
}

/// The offset from the stack pointer at an `rt_sigreturn` instruction to the
/// frame's `uc_sigmask` on x86_64: the frame starts 8 bytes below (its
/// return-address slot, `pretcode`), and `uc_sigmask` follows `uc_flags`
/// (8), `uc_link` (8), `uc_stack` (24) and `uc_mcontext` (256) in the frame's
/// `ucontext`.
#[cfg(target_arch = "x86_64")]
pub(crate) const SIGRETURN_UC_SIGMASK_OFFSET: usize = 8 + 8 + 24 + 256;

/// The offset from the stack pointer at an `rt_sigreturn` instruction to the
/// frame's `uc_sigmask` on aarch64: the stack pointer is the frame
/// (`struct rt_sigframe`), whose `siginfo` (128) precedes its `ucontext`,
/// where `uc_sigmask` follows `uc_flags` (8), `uc_link` (8) and `uc_stack`
/// (24).
#[cfg(target_arch = "aarch64")]
pub(crate) const SIGRETURN_UC_SIGMASK_OFFSET: usize = 128 + 8 + 8 + 24;

/// Whether an x86-64 instruction that begins with `bytes` raises a SIGTRAP
/// of its own: `int3` (`cc`), `int 3` (`cd 03`) or `int1` (`f1`), after any
/// run of legacy and REX prefixes, within the 15-byte limit of an
/// instruction. A prefix does not change what these instructions do, so
/// `66 cc` is an `int3` too; and the CPU ignores a REX prefix that does not
/// directly precede the opcode, so `48 48 cc` and `48 66 cc` are as well.
#[cfg(target_arch = "x86_64")]
pub(crate) fn instruction_raises_sigtrap(bytes: &[u8]) -> bool {
    let bytes = &bytes[..bytes.len().min(15)];
    let mut i = 0;
    while i < bytes.len()
        && matches!(
            bytes[i],
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                ..=0x4f
        )
    {
        i += 1;
    }
    matches!(bytes[i..], [0xcc, ..] | [0xf1, ..] | [0xcd, 0x03, ..])
}

/// Whether the aarch64 instruction that begins with `bytes` raises a SIGTRAP
/// of its own: `brk #imm` (`0xd4200000 | imm16 << 5`), which Linux reports
/// with a forced SIGTRAP as it does a single-step. Instructions are 4 bytes,
/// little-endian.
#[cfg(target_arch = "aarch64")]
pub(crate) fn instruction_raises_sigtrap(bytes: &[u8]) -> bool {
    const BRK_MASK: u32 = 0xffe0_001f;
    const BRK: u32 = 0xd420_0000;
    matches!(bytes, [a, b, c, d, ..] if u32::from_le_bytes([*a, *b, *c, *d]) & BRK_MASK == BRK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_sigaction_has_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<KernelSigaction>(), 32);
        assert_eq!(std::mem::offset_of!(KernelSigaction, flags), 8);
        assert_eq!(std::mem::offset_of!(KernelSigaction, restorer), 16);
        assert_eq!(std::mem::offset_of!(KernelSigaction, mask), 24);
    }

    #[test]
    fn procfs_disposition_reads_sigtrap_bits() {
        let status = "SigPnd:\t0\nSigBlk:\t0\nSigIgn:\t0000000000000004\nSigCgt:\t0\n";
        assert_eq!(parse_sigtrap_disposition(status), Some((false, false)));
        let status = "SigIgn:\t0000000000000010\nSigCgt:\t0000000000000000\n";
        assert_eq!(parse_sigtrap_disposition(status), Some((true, false)));
        let status = "SigIgn:\t0\nSigCgt:\t0000000180000010\n";
        assert_eq!(parse_sigtrap_disposition(status), Some((false, true)));
        assert_eq!(parse_sigtrap_disposition("SigIgn:\t0\n"), None);
    }

    #[test]
    fn step_kinds_name_every_mask_setter_and_clone() {
        assert_eq!(step_kind(Sysno::getppid, false), StepKind::KeepsMask);
        assert_eq!(step_kind(Sysno::ppoll, true), StepKind::SwapsMask);
        assert_eq!(step_kind(Sysno::rt_sigprocmask, false), StepKind::SetsMask);
        for nr in [Sysno::clone, Sysno::clone3] {
            assert_eq!(step_kind(nr, false), StepKind::Clones, "{nr}");
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [Sysno::fork, Sysno::vfork] {
            assert_eq!(step_kind(nr, false), StepKind::Clones, "{nr}");
        }
        assert_eq!(step_kind(Sysno::rt_sigreturn, false), StepKind::Sigreturn);
    }

    #[test]
    fn sigprocmask_result_follows_how() {
        let before = SIGTRAP_BIT | 1;
        assert_eq!(
            mask_after_sigprocmask(before, libc::SIG_BLOCK, Some(2)),
            before | 2
        );
        assert_eq!(
            mask_after_sigprocmask(before, libc::SIG_UNBLOCK, Some(SIGTRAP_BIT)),
            1
        );
        assert_eq!(
            mask_after_sigprocmask(before, libc::SIG_SETMASK, Some(!0)),
            BLOCKABLE_SIGNAL_BITS
        );
        assert_eq!(
            mask_after_sigprocmask(before, libc::SIG_SETMASK, None),
            before
        );
        assert_eq!(mask_after_sigprocmask(before, 7, Some(0)), before);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn trap_instructions_are_found_behind_prefixes() {
        for bytes in [
            &[0xcc][..],
            &[0xf1],
            &[0xcd, 0x03],
            &[0x66, 0xcc],
            &[0xf3, 0x2e, 0x66, 0xcc],
            &[0x48, 0xcc],
            &[0x66, 0x41, 0xcd, 0x03],
            &[0x66, 0xf1, 0x90],
            &[0x48, 0x48, 0xcc],
            &[0x48, 0x66, 0xcc],
            &[0x41, 0x66, 0x48, 0xcd, 0x03],
        ] {
            assert!(instruction_raises_sigtrap(bytes), "{bytes:02x?}");
        }
        for bytes in [
            &[][..],
            &[0x90],
            &[0x0f, 0x05],
            &[0xcd, 0x80],
            &[0xcd],
            &[0x66],
            &[0x48; 3],
            &[0x66; 15],
            &[0x0f, 0xcc],
        ] {
            assert!(!instruction_raises_sigtrap(bytes), "{bytes:02x?}");
        }
        // The 15-byte limit: fourteen prefixes and an int3 still decode; the
        // int3 as a sixteenth byte does not.
        let mut long = vec![0x66; 14];
        long.push(0xcc);
        assert!(instruction_raises_sigtrap(&long));
        let mut too_long = vec![0x66; 15];
        too_long.push(0xcc);
        assert!(!instruction_raises_sigtrap(&too_long));
        let mut rex_long = vec![0x48; 14];
        rex_long.push(0xcc);
        assert!(instruction_raises_sigtrap(&rex_long));
        rex_long.insert(0, 0x48);
        assert!(!instruction_raises_sigtrap(&rex_long));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn brk_raises_sigtrap_and_other_instructions_do_not() {
        // brk #0, brk #1, brk #0xffff, then trailing bytes after a brk.
        for word in [0xd420_0000u32, 0xd420_0020, 0xd43f_ffe0] {
            assert!(instruction_raises_sigtrap(&word.to_le_bytes()), "{word:#x}");
        }
        assert!(instruction_raises_sigtrap(&[
            0x20, 0x00, 0x20, 0xd4, 0x1f, 0x20
        ]));
        // svc #0, hlt #0, udf #0, nop, a brk with nonzero low bits (not a
        // brk encoding), and a partial word.
        for word in [
            0xd400_0001u32,
            0xd440_0000,
            0x0000_0000,
            0xd503_201f,
            0xd420_0001,
        ] {
            assert!(
                !instruction_raises_sigtrap(&word.to_le_bytes()),
                "{word:#x}"
            );
        }
        assert!(!instruction_raises_sigtrap(&[0x00, 0x00, 0x20]));
        assert!(!instruction_raises_sigtrap(&[]));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_sigreturn_mask_offset_matches_the_kernel_frame() {
        // siginfo_t is 128 bytes; ucontext's uc_sigmask follows two words
        // and a stack_t.
        assert_eq!(std::mem::size_of::<libc::siginfo_t>(), 128);
        assert_eq!(std::mem::size_of::<libc::stack_t>(), 24);
        assert_eq!(SIGRETURN_UC_SIGMASK_OFFSET, 168);
    }

    #[test]
    fn only_sig_ign_is_ignored() {
        let mut action = KernelSigaction {
            handler: libc::SIG_IGN as u64,
            ..Default::default()
        };
        assert!(action.ignored());
        action.handler = libc::SIG_DFL as u64;
        assert!(!action.ignored());
        action.handler = 0x401000;
        assert!(!action.ignored());
    }
}
