/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Classic-BPF seccomp filter for LD_PRELOAD instrumentation.
//!
//! The filter traps every real syscall entry with `SECCOMP_RET_TRAP` (delivering
//! a thread-directed `SIGSYS`) **except**:
//!
//! * `rt_sigreturn`, which must run to unwind the signal frame; and
//! * the runtime's own *trusted syscall gate* — a single `syscall` instruction
//!   at a known address (see [`crate::trap`]). The gate lets the handler and
//!   dispatcher execute real syscalls without re-trapping, avoiding infinite
//!   recursion.
//!
//! Coverage boundaries (proven by the `research-ldpreload-derisking` task) are
//! documented on [`SeccompFilter`]: vDSO fast paths and the ~40 loader/startup
//! syscalls before the constructor runs are *not* covered, and this filter is
//! for trusted, dynamically linked, non-`AT_SECURE`, no-exec guests only.

use std::io;
use std::ptr;

/// `AUDIT_ARCH_X86_64` from `<linux/audit.h>`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// Offsets into `struct seccomp_data`.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_IP_LOW_OFFSET: u32 = 8;
const SECCOMP_DATA_IP_HIGH_OFFSET: u32 = 12;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// The address range of the trusted syscall gate.
///
/// Both addresses must live in the same 4 GiB half so the classic-BPF filter
/// can match the 64-bit instruction pointer with a single high-word compare
/// plus a low-word compare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedGate {
    /// Address of the trusted `syscall` instruction.
    pub syscall_ip: u64,
    /// Address immediately after it (its return site).
    pub return_ip: u64,
}

impl TrustedGate {
    /// Returns an error if the gate straddles a 4 GiB boundary, which the
    /// single-high-word filter design cannot express.
    fn validate(&self) -> io::Result<()> {
        if self.syscall_ip >> 32 != self.return_ip >> 32 {
            return Err(io::Error::other(
                "trusted syscall gate crosses a 4GiB boundary",
            ));
        }
        Ok(())
    }
}

/// A built seccomp program ready to install.
pub struct SeccompFilter {
    program: Vec<libc::sock_filter>,
}

impl SeccompFilter {
    /// Build the trap-everything-but-the-gate filter for `gate`.
    pub fn for_trusted_gate(gate: TrustedGate) -> io::Result<Self> {
        gate.validate()?;
        let high = (gate.syscall_ip >> 32) as u32;
        let program = vec![
            // Reject any non-x86-64 syscall ABI outright.
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            // Load the syscall number.
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            // rt_sigreturn must always be allowed to unwind the signal frame.
            jump(BPF_JMP_JEQ_K, libc::SYS_rt_sigreturn as u32, 6, 0),
            // Compare the calling instruction pointer against the trusted gate.
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_HIGH_OFFSET),
            jump(BPF_JMP_JEQ_K, high, 0, 3),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_LOW_OFFSET),
            jump(BPF_JMP_JEQ_K, gate.syscall_ip as u32, 2, 0),
            jump(BPF_JMP_JEQ_K, gate.return_ip as u32, 1, 0),
            // Untrusted entry: trap to the SIGSYS handler.
            stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            // Trusted gate (or the allowed return site): let it run.
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ];
        Ok(Self { program })
    }

    /// The number of BPF instructions in the program.
    pub fn len(&self) -> usize {
        self.program.len()
    }

    /// Whether the program is empty (never true for a validly built filter).
    pub fn is_empty(&self) -> bool {
        self.program.is_empty()
    }

    /// Install the filter on every thread of the calling process.
    ///
    /// Sets `PR_SET_NO_NEW_PRIVS` (required to load a filter without privilege)
    /// then `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)`.
    /// The filter is inherited atomically across `fork`/`clone` and persists
    /// across `execve`, so there is no post-fork installation race.
    ///
    /// # Safety
    ///
    /// Installs process-wide, irreversible kernel state. Call exactly once,
    /// before untrusted application threads start, after the SIGSYS handler is
    /// in place.
    pub unsafe fn install(&mut self) -> io::Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let program = libc::sock_fprog {
            len: u16::try_from(self.program.len())
                .map_err(|_| io::Error::other("seccomp filter too long"))?,
            filter: self.program.as_mut_ptr(),
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                ptr::addr_of!(program),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: jump_true,
        jf: jump_false,
        k: value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_gate_across_4gib_boundary() {
        let gate = TrustedGate {
            syscall_ip: 0x0000_0000_ffff_fff8,
            return_ip: 0x0000_0001_0000_0000,
        };
        assert!(SeccompFilter::for_trusted_gate(gate).is_err());
    }

    #[test]
    fn builds_fixed_length_program_for_valid_gate() {
        let gate = TrustedGate {
            syscall_ip: 0x5555_0000_1000,
            return_ip: 0x5555_0000_1002,
        };
        let filter = SeccompFilter::for_trusted_gate(gate).unwrap();
        assert_eq!(filter.len(), 12);
        assert!(!filter.is_empty());
    }

    #[test]
    fn program_traps_untrusted_and_allows_gate() {
        let gate = TrustedGate {
            syscall_ip: 0x1234_5678,
            return_ip: 0x1234_567a,
        };
        let filter = SeccompFilter::for_trusted_gate(gate).unwrap();
        // The two terminal returns must be TRAP (untrusted) then ALLOW (gate).
        let ret_ks: Vec<u32> = filter
            .program
            .iter()
            .filter(|i| i.code == BPF_RET_K)
            .map(|i| i.k)
            .collect();
        assert!(ret_ks.contains(&SECCOMP_RET_TRAP));
        assert!(ret_ks.contains(&SECCOMP_RET_ALLOW));
        assert!(ret_ks.contains(&SECCOMP_RET_KILL_PROCESS));
    }
}
