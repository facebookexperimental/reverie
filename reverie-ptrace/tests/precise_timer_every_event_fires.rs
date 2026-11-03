/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Every precise timer a Tool arms fires once: the guest makes a `getpid`, at
//! which the Tool arms a timer 4000 branches out, then retires far more
//! branches than that, twenty times over. The timer's last stretch is single
//! stepped (staged notifications bring the counter within the skid margin of
//! the target first), so a timer notification that arrives during those
//! steps, as a second overflow of the last stage can, must not cost the
//! event. Runs on every architecture with a PMU.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

static ARMED: AtomicU64 = AtomicU64::new(0);
static FIRED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default, Clone)]
struct ArmAtGetpid;

#[reverie::tool]
impl Tool for ArmAtGetpid {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::getpid]);
        s
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            ARMED.fetch_add(1, Ordering::SeqCst);
            guest.set_timer_precise(TimerSchedule::Rcbs(4000))?;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, _guest: &mut G) {
        FIRED.fetch_add(1, Ordering::SeqCst);
    }
}

/// Retires conditional branches well past the timer's target.
#[inline(never)]
fn branch(n: u64) -> u64 {
    let mut x = 0u64;
    for i in 0..n {
        if std::hint::black_box(i) & 1 == 1 {
            x = x.wrapping_add(1);
        }
    }
    x
}

#[test]
fn every_precise_timer_fires_once() {
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    reverie_ptrace::testing::check_fn::<ArmAtGetpid, _>(|| {
        for _ in 0..20 {
            // SAFETY: getpid has no preconditions.
            unsafe { libc::getpid() };
            std::hint::black_box(branch(200_000));
        }
    });
    let (armed, fired) = (ARMED.load(Ordering::SeqCst), FIRED.load(Ordering::SeqCst));
    eprintln!("armed {armed}, fired {fired}");
    assert_eq!(armed, 20);
    assert_eq!(fired, armed, "every armed timer fires once");
}
