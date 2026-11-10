/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pidfd self-sentinel spelling of the kernel that executes this guest's
//! syscalls ([`reverie::pidfd_self`]).
//!
//! A process image's runtime qualifies it once, if and when it installs its
//! syscall trap (`lifecycle::install_in_process_trap`), immediately before
//! its own seccomp filter: the last point at which the runtime's syscalls
//! meet no filter of its own, and before any guest code runs. Every syscall
//! there is the runtime's raw gate: the thread's `/proc/thread-self/status`
//! is read with raw `openat`/`read`/`close`, and the probe is a raw signal-0
//! `pidfd_send_signal` naming the process itself. It qualifies only when that
//! status shows no seccomp filter at all, so a success can only be the
//! kernel's own answer; otherwise nothing is executed. The runtime cannot
//! rule out a filter that forges its own evidence; as for
//! `set_physical_creation_hook`, the registering side establishes from
//! outside the process that no filter but the runtime's is attached.
//!
//! The answer, Unknown included, is published once and read by
//! `Guest::pidfd_self_spelling` without any syscall, which a Tool callback
//! under the runtime's filter could not make through an ordinary path. A
//! forked child keeps its parent's answer (the same kernel). A new image
//! starts unqualified and qualifies only if its runtime installs its own
//! trap: the authenticated initial-image path (`exec_private`'s
//! `InitialImageController`) adopts the inherited filter and never does, so
//! its spelling stays Unknown.

use reverie::Errno;
use reverie::PidfdSelfSpelling;
use reverie::pidfd_self;
use reverie::pidfd_self::PidfdSelfFact;

static SPELLING: PidfdSelfFact = PidfdSelfFact::new();

/// Qualifies this image's spelling through the runtime's raw gate, if it has
/// not been. Call only before the runtime's seccomp filter is installed.
pub(crate) fn initialize_before_runtime_filter() -> PidfdSelfSpelling {
    SPELLING.initialize(|| {
        pidfd_self::qualify(thread_has_no_seccomp_filter(), |pidfd| {
            let args = pidfd_self::probe_args(pidfd).map(|arg| arg as u64);
            // SAFETY: signal 0 with a null siginfo reads and writes no memory.
            let raw = unsafe { crate::trap::raw_syscall6(libc::SYS_pidfd_send_signal, args) };
            Errno::from_ret(raw as usize)
        })
    })
}

/// The image's published spelling: Unknown before it is qualified. Makes no
/// syscall.
pub(crate) fn spelling() -> PidfdSelfSpelling {
    SPELLING.get()
}

/// Whether the calling thread's `/proc/thread-self/status`, read through the
/// raw gate, shows no seccomp filter. Anything unreadable is `false`.
fn thread_has_no_seccomp_filter() -> bool {
    const PATH: &[u8] = b"/proc/thread-self/status\0";
    let mut status = [0_u8; 8192];
    // SAFETY: a NUL-terminated path; the descriptor is closed below.
    let fd = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH.as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return false;
    }
    let mut length = 0;
    let complete = loop {
        if length == status.len() {
            break false;
        }
        // SAFETY: reads into the unfilled tail of `status`.
        let read = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_read,
                [
                    fd as u64,
                    status[length..].as_mut_ptr() as u64,
                    (status.len() - length) as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        match read {
            0 => break true,
            read if read > 0 => length += read as usize,
            _ => break false,
        }
    };
    // SAFETY: closes the descriptor opened above.
    unsafe { crate::trap::raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    complete
        && std::str::from_utf8(&status[..length])
            .is_ok_and(|status| pidfd_self::status_has_exactly_seccomp_filters(status, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This (unfiltered) test thread's status reads as unfiltered through the
    /// raw gate, as the shared reader reads it.
    #[test]
    fn the_raw_status_read_agrees_with_the_shared_reader() {
        assert_eq!(
            thread_has_no_seccomp_filter(),
            pidfd_self::thread_has_exactly_seccomp_filters(0)
        );
    }
}
