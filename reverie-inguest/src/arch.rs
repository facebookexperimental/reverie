/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Architecture constants for the trap runtime: the single place that knows
//! which Linux syscall ABI the runtime traps. Everything architecture-shaped
//! that more than one module needs (the seccomp audit architecture today;
//! gate/frame layouts as they are ported) is selected here, by `cfg`, so no
//! other module hardcodes an architecture literal.
//!
//! Page size is deliberately *not* a constant: targeted hosts run both 4 KiB
//! and 64 KiB pages, so every mapping/alignment computation must go through
//! [`page_size`].

/// `AUDIT_ARCH_*` from `<linux/audit.h>` for the ABI this runtime traps.
///
/// The seccomp filter kills any syscall whose `arch` word is not this value,
/// refusing ABIs with a distinct audit architecture (compat32 on aarch64 is
/// `AUDIT_ARCH_ARM`). x32 shares `AUDIT_ARCH_X86_64` and is distinguished
/// only by `__X32_SYSCALL_BIT` in the syscall number, so the arch word alone
/// does not refuse it; filters that must exclude x32 check that bit
/// separately (the native-exec recipe does).
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// The words a seccomp program compares against `seccomp_data`: which audit
/// architecture to admit and which syscall number is `rt_sigreturn` under
/// that architecture. Filter construction takes this explicitly so the
/// verdicts for a non-host architecture can be tested on any host by
/// evaluating the emitted program; production builders always pass
/// [`FILTER_ABI_NATIVE`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterAbi {
    /// `AUDIT_ARCH_*` value admitted by the filter.
    pub audit_arch: u32,
    /// Syscall number of `rt_sigreturn` under `audit_arch`.
    pub rt_sigreturn: u32,
}

/// x86-64 filter ABI (`rt_sigreturn` is syscall 15 there).
pub const FILTER_ABI_X86_64: FilterAbi = FilterAbi {
    audit_arch: 0xc000_003e,
    rt_sigreturn: 15,
};

/// aarch64 filter ABI (`rt_sigreturn` is syscall 139 there; the audit word
/// and the number are pinned by the aarch64 trap probe measurements).
pub const FILTER_ABI_AARCH64: FilterAbi = FilterAbi {
    audit_arch: 0xc000_00b7,
    rt_sigreturn: 139,
};

/// The filter ABI of the architecture this runtime was compiled for.
#[cfg(target_arch = "x86_64")]
pub const FILTER_ABI_NATIVE: FilterAbi = FILTER_ABI_X86_64;
#[cfg(target_arch = "aarch64")]
pub const FILTER_ABI_NATIVE: FilterAbi = FILTER_ABI_AARCH64;

/// Syscall numbers that exist in the x86-64 table but not in the aarch64
/// generic table, where the same operation arrives under a different
/// number (`fork`/`vfork` are `clone` shapes there; `dup2` is `dup3`).
/// Callers compare with `Some(number) == SYS_FORK` so the missing numbers
/// simply never match instead of failing to compile.
#[cfg(target_arch = "x86_64")]
pub const SYS_FORK: Option<i64> = Some(libc::SYS_fork);
#[cfg(target_arch = "aarch64")]
pub const SYS_FORK: Option<i64> = None;
#[cfg(target_arch = "x86_64")]
pub const SYS_VFORK: Option<i64> = Some(libc::SYS_vfork);
#[cfg(target_arch = "aarch64")]
pub const SYS_VFORK: Option<i64> = None;
#[cfg(target_arch = "x86_64")]
pub const SYS_DUP2: Option<i64> = Some(libc::SYS_dup2);
#[cfg(target_arch = "aarch64")]
pub const SYS_DUP2: Option<i64> = None;

/// Whether `number` creates a process that returns from the same trapped
/// syscall in both parent and child, under this architecture's table.
pub fn is_fork_family(number: i64) -> bool {
    number == libc::SYS_clone
        || number == libc::SYS_clone3
        || Some(number) == SYS_FORK
        || Some(number) == SYS_VFORK
}

/// Whether `number` is `vfork` (never on aarch64, where it is a clone flag).
pub fn is_vfork(number: i64) -> bool {
    Some(number) == SYS_VFORK
}

/// Whether `number` duplicates a descriptor onto an exact number
/// (`dup2`/`dup3`; only `dup3` exists on aarch64).
pub fn is_dup_number(number: i64) -> bool {
    number == libc::SYS_dup3 || Some(number) == SYS_DUP2
}

/// The host page size, from the kernel's auxiliary vector.
///
/// Gate pages, trampoline arenas, signal-stack sizing and any other
/// page-granular computation must use this rather than a literal: an
/// aarch64 host with 64 KiB pages rejects 4 KiB-granular `mmap`/`mprotect`
/// arithmetic that an x86-64 host accepts.
///
/// This delegates to the single existing definition,
/// [`crate::guest::support::page_size`], which reads `AT_PAGESZ` through
/// the runtime's own syscall gate. It must not become a `sysconf` call:
/// `sysconf` is an interposable dynamic symbol, so in-guest code calling
/// it would run guest- or preload-defined code.
pub fn page_size() -> std::io::Result<u64> {
    crate::guest::support::page_size()
}

/// Unconditionally trap with SIGILL at a point execution must never
/// reach or must never leave — typically after an `exit_group` the
/// kernel was expected not to return from, where running any further
/// Rust (teardown, unwind, std) would be a correctness hazard. This is
/// the crate's single site for the architecture's undefined
/// instruction (`ud2` on x86-64, `udf #0` on aarch64); call sites never
/// open-code the mnemonic. Always inlined: several callers run where the
/// stack itself may be denied, so reaching the trap must not push a
/// return address the open-coded instruction never needed.
#[inline(always)]
pub fn trap_unreachable() -> ! {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: ud2 unconditionally raises SIGILL and does not return.
    unsafe {
        core::arch::asm!("ud2", options(noreturn, nostack))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: udf unconditionally raises SIGILL and does not return.
    unsafe {
        core::arch::asm!("udf #0", options(noreturn, nostack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_arch_matches_the_compiled_target() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(AUDIT_ARCH_NATIVE, 0xc000_003e);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(AUDIT_ARCH_NATIVE, 0xc000_00b7);
    }

    #[test]
    fn filter_abi_native_matches_libc_and_audit_arch() {
        assert_eq!(FILTER_ABI_NATIVE.audit_arch, AUDIT_ARCH_NATIVE);
        assert_eq!(
            FILTER_ABI_NATIVE.rt_sigreturn,
            libc::SYS_rt_sigreturn as u32
        );
        assert_eq!(FILTER_ABI_X86_64.audit_arch, 0xc000_003e);
        assert_eq!(FILTER_ABI_X86_64.rt_sigreturn, 15);
        assert_eq!(FILTER_ABI_AARCH64.audit_arch, 0xc000_00b7);
        assert_eq!(FILTER_ABI_AARCH64.rt_sigreturn, 139);
    }

    #[test]
    fn page_size_is_a_power_of_two_at_least_4kib() {
        let size = page_size().unwrap();
        assert!(size.is_power_of_two());
        assert!(size >= 4096);
    }
}
