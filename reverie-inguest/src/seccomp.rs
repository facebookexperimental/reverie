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
//! * the runtime's exact trusted syscall sites (see [`crate::trap`]). The
//!   lifecycle installs a private-memory gate and a guest-permissions gate.
//!   The sites let the handler and
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

    /// Build an exact-address filter for runtime-private and guest-forwarding
    /// gates. Each pair is checked independently, including its full high word;
    /// no address range or low-word alias is implicitly trusted.
    pub fn for_trusted_gates(first: TrustedGate, second: TrustedGate) -> io::Result<Self> {
        Self::for_trusted_gates_with_signal_return(first, second, None)
    }

    /// [`Self::for_trusted_gates`], optionally admitting `rt_sigreturn` only
    /// when Linux reports `signal_return` as its instruction pointer (the
    /// runtime's private restorer, `signal::signal_restorer_return_ip`),
    /// compared over the full 64 bits. That check comes first, so neither gate
    /// admits `rt_sigreturn`; any other `rt_sigreturn` traps. Without it,
    /// `rt_sigreturn` is admitted from anywhere, as before.
    pub fn for_trusted_gates_with_signal_return(
        first: TrustedGate,
        second: TrustedGate,
        signal_return: Option<u64>,
    ) -> io::Result<Self> {
        first.validate()?;
        second.validate()?;
        let mut program = vec![
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        ];
        if let Some(address) = signal_return {
            program.extend([
                // rt_sigreturn: the six instructions below, else the gates.
                jump(BPF_JMP_JEQ_K, libc::SYS_rt_sigreturn as u32, 0, 6),
                stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_HIGH_OFFSET),
                jump(BPF_JMP_JEQ_K, (address >> 32) as u32, 0, 3),
                stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_LOW_OFFSET),
                jump(BPF_JMP_JEQ_K, address as u32, 0, 1),
                stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
                stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            ]);
        } else {
            program.push(jump(BPF_JMP_JEQ_K, libc::SYS_rt_sigreturn as u32, 11, 0));
        }
        program.extend([
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_HIGH_OFFSET),
            jump(BPF_JMP_JEQ_K, (first.syscall_ip >> 32) as u32, 0, 3),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_LOW_OFFSET),
            jump(BPF_JMP_JEQ_K, first.syscall_ip as u32, 7, 0),
            jump(BPF_JMP_JEQ_K, first.return_ip as u32, 6, 0),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_HIGH_OFFSET),
            jump(BPF_JMP_JEQ_K, (second.syscall_ip >> 32) as u32, 0, 3),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_IP_LOW_OFFSET),
            jump(BPF_JMP_JEQ_K, second.syscall_ip as u32, 2, 0),
            jump(BPF_JMP_JEQ_K, second.return_ip as u32, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_TRAP),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]);
        Ok(Self { program })
    }

    /// Build the distinct native first-domain inherited filter.
    ///
    /// The 46-instruction prefix denies namespace changes, process creation,
    /// x32 entry and filter stacking even at trusted gates. The unchanged
    /// exact 23-instruction signal-return/two-gate suffix follows it. This is
    /// one installed filter with a new identity, never the ordinary 23 recipe.
    #[cfg(feature = "exec-native-injection")]
    pub fn for_native_exec_domain() -> io::Result<Self> {
        let mut prefix = vec![
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
            jump(0x45, 0x4000_0000, 0, 1),
            stmt(BPF_RET_K, 0x0005_0000 | libc::EPERM as u32),
        ];
        for number in [
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
            libc::SYS_seccomp,
        ] {
            prefix.extend([
                jump(BPF_JMP_JEQ_K, number as u32, 0, 1),
                stmt(BPF_RET_K, 0x0005_0000 | libc::EPERM as u32),
            ]);
        }
        prefix.extend([
            jump(BPF_JMP_JEQ_K, libc::SYS_prctl as u32, 0, 3),
            stmt(BPF_LD_W_ABS, 16), // Low word of actual prctl arg0.
            jump(BPF_JMP_JEQ_K, libc::PR_SET_SECCOMP as u32, 0, 1),
            stmt(BPF_RET_K, 0x0005_0000 | libc::EPERM as u32),
        ]);
        assert_eq!(prefix.len(), 46);
        let suffix = Self::for_trusted_gates_with_signal_return(
            TrustedGate {
                syscall_ip: 0x5000_0000_0080,
                return_ip: 0x5000_0000_0082,
            },
            TrustedGate {
                syscall_ip: 0x5000_0000_0200,
                return_ip: 0x5000_0000_0202,
            },
            Some(0x5000_0000_030b),
        )?;
        assert_eq!(suffix.program.len(), 23);
        prefix.extend(suffix.program);
        assert_eq!(prefix.len(), 69);
        Ok(Self { program: prefix })
    }

    /// Canonical little-endian bytes of the distinct native filter recipe.
    /// Content comparison is not authority to install or attest a filter.
    #[cfg(feature = "exec-native-injection")]
    pub fn native_exec_recipe_bytes() -> io::Result<[u8; 69 * 8]> {
        let filter = Self::for_native_exec_domain()?;
        let mut bytes = [0; 69 * 8];
        for (chunk, instruction) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(&filter.program) {
            chunk[..2].copy_from_slice(&instruction.code.to_le_bytes());
            chunk[2] = instruction.jt;
            chunk[3] = instruction.jf;
            chunk[4..].copy_from_slice(&instruction.k.to_le_bytes());
        }
        Ok(bytes)
    }

    #[cfg(feature = "exec-native-injection")]
    pub(crate) fn native_program(&mut self) -> libc::sock_fprog {
        // Only a prebuilt exact native recipe is passed by the child owner.
        libc::sock_fprog {
            len: self.program.len() as u16,
            filter: self.program.as_mut_ptr(),
        }
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
        // Raw syscalls, not libc's interposable prctl and syscall wrappers.
        crate::guest::support::raw_zero_result(unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_prctl,
                [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
            )
        })?;
        let program = libc::sock_fprog {
            len: u16::try_from(self.program.len())
                .map_err(|_| io::Error::other("seccomp filter too long"))?,
            filter: self.program.as_mut_ptr(),
        };
        tsync_filter_outcome(unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_seccomp,
                [
                    u64::from(libc::SECCOMP_SET_MODE_FILTER),
                    libc::SECCOMP_FILTER_FLAG_TSYNC,
                    ptr::addr_of!(program) as u64,
                    0,
                    0,
                    0,
                ],
            )
        })?;
        // Recorded without a syscall, so that nothing changes for a process
        // that never registers a creation hook.
        RUNTIME_FILTER_INSTALLED.store(true, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// What `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)`
/// returned, as the installation's outcome. Only 0 means the filter is
/// installed on every thread. A negative value is the error it names. A
/// positive value is the id of a thread the kernel could not synchronize
/// (one with a filter of its own that does not descend from the caller's):
/// the filter was installed on no thread, so that is refused too, naming the
/// thread, rather than taken as success.
fn tsync_filter_outcome(result: i64) -> io::Result<()> {
    if result > 0 {
        return Err(io::Error::other(format!(
            "seccomp filter not installed: SECCOMP_FILTER_FLAG_TSYNC could not \
             synchronize thread {result}, whose own filter does not descend from \
             this thread's"
        )));
    }
    crate::guest::support::raw_zero_result(result)
}

static RUNTIME_FILTER_INSTALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Whether [`SeccompFilter::install`] has succeeded in this process (or the
/// parent it was forked from), so that every later guest syscall is
/// intercepted.
pub fn runtime_filter_installed() -> bool {
    RUNTIME_FILTER_INSTALLED.load(core::sync::atomic::Ordering::Relaxed)
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

    /// Only a 0 return installs the filter: a negative one is its error, and
    /// a positive one (the thread TSYNC could not synchronize) is refused by
    /// that thread's id.
    #[test]
    fn only_a_zero_tsync_return_counts_as_installed() {
        assert!(tsync_filter_outcome(0).is_ok());
        let error = tsync_filter_outcome(-i64::from(libc::EINVAL)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        let error = tsync_filter_outcome(4242).unwrap_err();
        assert_eq!(error.raw_os_error(), None);
        assert!(
            error
                .to_string()
                .contains("could not synchronize thread 4242"),
            "{error}"
        );
    }

    fn evaluate(filter: &SeccompFilter, arch: u32, number: i64, ip: u64) -> u32 {
        let mut accumulator = 0;
        let mut pc = 0;
        loop {
            let instruction = &filter.program[pc];
            match instruction.code {
                BPF_LD_W_ABS => {
                    accumulator = match instruction.k {
                        SECCOMP_DATA_ARCH_OFFSET => arch,
                        SECCOMP_DATA_NR_OFFSET => number as u32,
                        SECCOMP_DATA_IP_LOW_OFFSET => ip as u32,
                        SECCOMP_DATA_IP_HIGH_OFFSET => (ip >> 32) as u32,
                        offset => panic!("unexpected seccomp data offset {offset}"),
                    };
                }
                BPF_JMP_JEQ_K => {
                    pc += usize::from(if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                BPF_RET_K => return instruction.k,
                code => panic!("unexpected BPF instruction {code}"),
            }
            pc += 1;
        }
    }

    /// With the runtime's restorer named, `rt_sigreturn` is admitted only at
    /// its exact full address: not at either gate, not at an address sharing
    /// its low or high word, not anywhere else. Every other syscall is filtered
    /// exactly as without it.
    #[test]
    fn signal_return_is_admitted_only_at_the_restorer() {
        let first = TrustedGate {
            syscall_ip: 0x1234_0000_1000,
            return_ip: 0x1234_0000_1002,
        };
        let second = TrustedGate {
            syscall_ip: 0x5678_0000_2000,
            return_ip: 0x5678_0000_2002,
        };
        let restorer = 0x9abc_0000_3007;
        let filter =
            SeccompFilter::for_trusted_gates_with_signal_return(first, second, Some(restorer))
                .unwrap();
        assert_eq!(filter.len(), 23);
        let sigreturn = libc::SYS_rt_sigreturn;
        assert_eq!(
            evaluate(&filter, AUDIT_ARCH_X86_64, sigreturn, restorer),
            SECCOMP_RET_ALLOW
        );
        for elsewhere in [
            first.syscall_ip,
            first.return_ip,
            second.syscall_ip,
            second.return_ip,
            restorer + 1,
            (restorer & 0xffff_ffff) | (0x1234 << 32),
            (restorer & !0xffff_ffff) | 0x3008,
            0x7fff_dead_beef,
        ] {
            assert_eq!(
                evaluate(&filter, AUDIT_ARCH_X86_64, sigreturn, elsewhere),
                SECCOMP_RET_TRAP,
                "{elsewhere:#x}"
            );
        }
        let plain = SeccompFilter::for_trusted_gates(first, second).unwrap();
        for number in [libc::SYS_write, libc::SYS_openat, libc::SYS_rt_sigaction] {
            for address in [
                first.syscall_ip,
                second.return_ip,
                restorer,
                0x7fff_dead_beef,
            ] {
                assert_eq!(
                    evaluate(&filter, AUDIT_ARCH_X86_64, number, address),
                    evaluate(&plain, AUDIT_ARCH_X86_64, number, address),
                    "{number} at {address:#x}"
                );
            }
        }
        assert_eq!(
            evaluate(&filter, 0x4000_0003, libc::SYS_write, first.syscall_ip),
            SECCOMP_RET_KILL_PROCESS
        );
        // Without a restorer, rt_sigreturn is admitted anywhere, as before.
        assert_eq!(
            evaluate(&plain, AUDIT_ARCH_X86_64, sigreturn, 0x7fff_dead_beef),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn two_gates_allow_only_exact_full_addresses() {
        let first = TrustedGate {
            syscall_ip: 0x1234_0000_1000,
            return_ip: 0x1234_0000_1002,
        };
        let second = TrustedGate {
            syscall_ip: 0x5678_0000_2000,
            return_ip: 0x5678_0000_2002,
        };
        let filter = SeccompFilter::for_trusted_gates(first, second).unwrap();
        assert_eq!(filter.len(), 17);
        for gate in [first, second] {
            for address in [gate.syscall_ip, gate.return_ip] {
                assert_eq!(
                    evaluate(&filter, AUDIT_ARCH_X86_64, libc::SYS_write, address),
                    SECCOMP_RET_ALLOW
                );
                for forbidden in [
                    address - 1,
                    address + 1,
                    address ^ (1 << 32),
                    address as u32 as u64,
                ] {
                    assert_eq!(
                        evaluate(&filter, AUDIT_ARCH_X86_64, libc::SYS_write, forbidden),
                        SECCOMP_RET_TRAP,
                        "{forbidden:#x}"
                    );
                }
                assert_eq!(
                    evaluate(&filter, 0x4000_0003, libc::SYS_write, address),
                    SECCOMP_RET_KILL_PROCESS
                );
            }
        }
        assert_eq!(
            evaluate(&filter, AUDIT_ARCH_X86_64, libc::SYS_rt_sigreturn, 0),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate(&filter, 0x4000_0003, libc::SYS_rt_sigreturn, 0),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            evaluate(
                &filter,
                AUDIT_ARCH_X86_64,
                libc::SYS_write,
                0x1234_0000_2000
            ),
            SECCOMP_RET_TRAP
        );
        assert_eq!(
            evaluate(
                &filter,
                AUDIT_ARCH_X86_64,
                libc::SYS_write,
                0x5678_0000_1000
            ),
            SECCOMP_RET_TRAP
        );
        let invalid = TrustedGate {
            syscall_ip: u32::MAX as u64,
            return_ip: 1 << 32,
        };
        assert!(SeccompFilter::for_trusted_gates(invalid, second).is_err());
        assert!(SeccompFilter::for_trusted_gates(first, invalid).is_err());
    }

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
