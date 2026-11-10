/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pidfd self-sentinel spelling of the kernel that executes a traced
//! guest's syscalls ([`reverie::pidfd_self`]).
//!
//! A traced guest's syscalls run in the tracee, on the same kernel as the
//! tracer. Each tracing session qualifies that kernel once, when it creates
//! its root task, on the tracer thread that creates it and from which the
//! tracee inherited its filters, with a raw signal-0 `pidfd_send_signal`
//! against the tracer itself: no tracee is stopped, injected into or
//! signalled. It qualifies only when that thread carries no seccomp filter,
//! so a success can only be the kernel's own answer; with a filter, or when
//! that cannot be read, nothing is executed and the session's spelling is
//! unknown. The session keeps the answer, Unknown included, for every task it
//! traces, and `Guest::pidfd_self_spelling` reads it without any I/O.

use reverie::Errno;
use reverie::PidfdSelfSpelling;
use reverie::pidfd_self;

/// The session's spelling, qualified on the calling (tracer) thread.
pub(crate) fn qualify_session() -> PidfdSelfSpelling {
    pidfd_self::qualify(pidfd_self::thread_has_exactly_seccomp_filters(0), probe)
}

/// `pidfd_send_signal(pidfd, 0, NULL, 0)` on the tracer's own thread.
fn probe(pidfd: i32) -> Result<usize, Errno> {
    let [a0, a1, a2, a3, _, _] = pidfd_self::probe_args(pidfd);
    // SAFETY: signal 0 with a null siginfo reads and writes no memory.
    let result = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, a0, a1, a2, a3) };
    if result < 0 {
        Err(Errno::last())
    } else {
        Ok(result as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On this host the session's spelling is the kernel's own answer: a
    /// qualified spelling's sentinels answer signal 0, and nothing is ever a
    /// measured absence.
    #[test]
    fn the_session_qualifies_from_the_kernel() {
        let spelling = qualify_session();
        assert_ne!(spelling, PidfdSelfSpelling::Unsupported);
        if spelling != PidfdSelfSpelling::Unknown {
            assert_eq!(probe(spelling.thread_group().unwrap()), Ok(0));
            assert_eq!(probe(spelling.thread().unwrap()), Ok(0));
        }
    }

    /// An ordinary negative descriptor is never a sentinel.
    #[test]
    fn a_non_sentinel_negative_descriptor_is_ebadf() {
        assert_eq!(probe(-10002), Err(Errno::EBADF));
    }

    /// A tracer thread whose filter forges pidfd_send_signal's success, under
    /// an unfiltered leader, qualifies nothing: the session's spelling is
    /// Unknown even though a probe there would answer 0.
    #[test]
    fn a_filtered_tracer_thread_qualifies_nothing() {
        let (spelling, forged) = std::thread::spawn(|| {
            let mut filter = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_pidfd_send_signal as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            // SAFETY: a filter on this thread only, which ends with it.
            unsafe {
                assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                assert_eq!(
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &program as *const libc::sock_fprog,
                    ),
                    0
                );
            }
            (qualify_session(), probe(-10002))
        })
        .join()
        .unwrap();
        assert_eq!(forged, Ok(0), "the filter does not forge");
        assert_eq!(spelling, PidfdSelfSpelling::Unknown);
    }
}
