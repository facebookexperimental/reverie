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
/// which is what refuses compat ABIs (x32 on x86-64, compat32 on aarch64).
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// The host page size from `sysconf(_SC_PAGESIZE)`, queried on every call.
///
/// Gate pages, trampoline arenas, signal-stack sizing and any other
/// page-granular computation must use this rather than a literal: an
/// aarch64 host with 64 KiB pages rejects 4 KiB-granular `mmap`/`mprotect`
/// arithmetic that an x86-64 host accepts.
pub fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(size > 0 && (size as usize).is_power_of_two());
    size as usize
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
    fn page_size_is_a_power_of_two_at_least_4kib() {
        let size = page_size();
        assert!(size.is_power_of_two());
        assert!(size >= 4096);
    }
}
