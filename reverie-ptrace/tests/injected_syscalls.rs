/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A traced guest's `Guest::injected_syscalls` counts each syscall the tool
//! injects, through `inject` and its variants, and nothing else: the tool
//! answers the guest's own calls with the difference between two readings.

#![cfg(target_arch = "x86_64")]

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Getppid;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// What the tool answers when the backend does not count injections.
const UNCOUNTED: i64 = 1000;

/// Answers `getpid` after injecting three syscalls and `gettid` after
/// injecting none, each with the number of injections counted meanwhile.
#[derive(Default)]
struct CountingTool;

#[reverie::tool]
impl Tool for CountingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid, Sysno::gettid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let Some(before) = guest.injected_syscalls() else {
            return Ok(UNCOUNTED);
        };
        if syscall.number() == Sysno::getpid {
            guest.inject(Getppid::new()).await?;
            guest.inject_with_retry(Getppid::new()).await?;
            guest.inject_restartable(Getppid::new()).await?;
        }
        let after = guest.injected_syscalls().expect("counted before");
        Ok((after - before) as i64)
    }
}

#[test]
fn each_injection_is_counted_once_and_answers_are_not() {
    reverie_ptrace::testing::check_fn::<CountingTool, _>(|| {
        for _ in 0..3 {
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpid) }, 3);
            assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, 0);
        }
    });
}
