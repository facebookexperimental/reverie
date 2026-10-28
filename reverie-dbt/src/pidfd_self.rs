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
//! A DBT guest's syscalls run in its own process, on the kernel the runtime
//! runs on. The runtime qualifies that kernel once per process image, at the
//! first Tool lifecycle callback of the image (thread start or post-exec),
//! with a signal-0 `pidfd_send_signal` naming the process itself, made by the
//! runtime's own code as the Tool's other native observations are
//! (`tools.rs`): never through the application syscall invoker, so no guest
//! syscall, interruption state or lifecycle bookkeeping is involved. It
//! qualifies only when the thread making the probe carries no seccomp filter,
//! so a success can only be the kernel's own answer; otherwise nothing is
//! executed. The answer, Unknown included, is published once for the image
//! and `Guest::pidfd_self_spelling` reads it without any I/O. A forked child
//! keeps its parent's answer (the same kernel); an exec starts a new image,
//! which qualifies again.

use reverie::Errno;
use reverie::PidfdSelfSpelling;
use reverie::pidfd_self;
use reverie::pidfd_self::PidfdSelfFact;

static SPELLING: PidfdSelfFact = PidfdSelfFact::new();

/// Qualifies this image's spelling on the calling thread if no earlier
/// lifecycle callback has.
pub(crate) fn initialize() {
    initialize_in(&SPELLING);
}

/// The image's published spelling: Unknown before [`initialize`].
pub(crate) fn spelling() -> PidfdSelfSpelling {
    SPELLING.get()
}

fn initialize_in(fact: &PidfdSelfFact) -> PidfdSelfSpelling {
    fact.initialize(|| {
        pidfd_self::qualify(
            pidfd_self::thread_has_exactly_seccomp_filters(0),
            native_probe,
        )
    })
}

/// `pidfd_send_signal(pidfd, 0, NULL, 0)` from the runtime's own code on the
/// calling thread.
fn native_probe(pidfd: i32) -> Result<usize, Errno> {
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

    /// The image's fact is the kernel's own answer on this host, qualified
    /// once: a qualified spelling's sentinels answer signal 0 natively, and
    /// a second initialization keeps the first answer.
    #[test]
    fn the_image_qualifies_once_from_the_kernel() {
        let fact = PidfdSelfFact::new();
        assert_eq!(fact.get(), PidfdSelfSpelling::Unknown);
        let spelling = initialize_in(&fact);
        assert_eq!(fact.get(), spelling);
        assert_eq!(initialize_in(&fact), spelling);
        assert_ne!(spelling, PidfdSelfSpelling::Unsupported);
        if spelling != PidfdSelfSpelling::Unknown {
            assert_eq!(native_probe(spelling.thread_group().unwrap()), Ok(0));
        }
        assert_eq!(native_probe(-10002), Err(Errno::EBADF));
    }

    /// The qualification has no route to the application syscall invoker:
    /// nothing it calls takes the task's invoker or context, so a guest's
    /// interruption state cannot be touched by it. Pinned by source, as the
    /// review asked: the probe is `libc::syscall` in the runtime's own code.
    #[test]
    fn the_qualification_never_reaches_the_application_invoker() {
        let source = include_str!("pidfd_self.rs");
        let body = source
            .split_once("fn initialize_in(")
            .expect("initialize_in")
            .1
            .split_once("#[cfg(test)]")
            .expect("end of the qualification")
            .0;
        for forbidden in ["host_linux", "invoke", "InjectionPurpose", "context"] {
            assert!(!body.contains(forbidden), "{forbidden} in:\n{body}");
        }
        assert!(body.contains("libc::syscall(libc::SYS_pidfd_send_signal"));
    }
}
