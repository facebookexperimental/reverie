/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A traced guest's `Guest::pidfd_self_spelling` is the answer of the kernel
//! that runs the guest's own syscalls: the guest measures that kernel itself,
//! with untraced signal-0 `pidfd_send_signal` calls, and the tool's answer,
//! read in a syscall callback, must agree with it.

#![cfg(target_arch = "x86_64")]

use reverie::Error;
use reverie::Guest;
use reverie::PidfdSelfSpelling;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// The value the tool returns for the guest's `getpid`, one per spelling.
fn code(spelling: PidfdSelfSpelling) -> i64 {
    match spelling {
        PidfdSelfSpelling::Modern => 1,
        PidfdSelfSpelling::Legacy => 2,
        PidfdSelfSpelling::Unsupported => 3,
        PidfdSelfSpelling::Unknown => 4,
    }
}

/// Answers the guest's `getpid` with the backend's spelling.
#[derive(Default)]
struct SpellingTool;

#[reverie::tool]
impl Tool for SpellingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        Ok(code(guest.pidfd_self_spelling()))
    }
}

/// `pidfd_send_signal(pidfd, 0, NULL, 0)` issued by the guest itself.
fn send_zero(pidfd: i32) -> Result<(), i32> {
    let result =
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd as libc::c_long, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    }
}

#[test]
fn the_tracer_answers_what_the_guests_own_kernel_answers() {
    // The tracer qualifies only without a seccomp filter; the guest, forked
    // from this process, carries the same filters.
    let unfiltered = reverie::pidfd_self::thread_has_exactly_seccomp_filters(0);
    eprintln!(
        "test process unfiltered={unfiltered}; this kernel answers -10001 with {:?} and -20000 with {:?}",
        send_zero(-10001),
        send_zero(-20000)
    );
    reverie_ptrace::testing::check_fn::<SpellingTool, _>(move || {
        let measured = match send_zero(-10001) {
            Ok(()) => PidfdSelfSpelling::Modern,
            Err(libc::EBADF) => match send_zero(-20000) {
                Ok(()) => PidfdSelfSpelling::Legacy,
                Err(_) => PidfdSelfSpelling::Unknown,
            },
            Err(_) => PidfdSelfSpelling::Unknown,
        };
        let answered = unsafe { libc::syscall(libc::SYS_getpid) };
        let expected = if unfiltered {
            measured
        } else {
            PidfdSelfSpelling::Unknown
        };
        eprintln!("pidfd self spelling: measured {measured:?}, tracer answered code {answered}");
        assert_eq!(answered, code(expected));
        // The group sentinel the tracer names is one this kernel accepts.
        if let Some(group) = expected.thread_group() {
            assert_eq!(send_zero(group), Ok(()));
        }
    });
}
