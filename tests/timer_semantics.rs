/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Verifies precision, determinism, and cancellation of timer events and clocks.
//!
//! Syscalls are abused to communicate from the guest to the tool instructions
//! necessary to carry out the test, such as setting timers or reading clocks.

#![cfg_attr(feature = "llvm_asm", feature(llvm_asm))]
use core::arch::x86_64::{__cpuid, __rdtscp, _rdtsc};
use libc;
use reverie::{
    syscalls::{Getpid, Gettid, Syscall, SyscallInfo, Sysno, Tgkill},
    Errno, Error, GlobalTool, Guest, Pid, Signal, Subscription, TimerSchedule, Tool,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Serialize, Deserialize, Default)]
struct GlobalState {
    num_timer_evts: AtomicU64,
    num_signals: AtomicU64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
enum IncrMsg {
    Timer,
    Signal,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    sub_syscalls_only: bool,
    run_basic_tests: bool,
    timeout_rcbs: u64,
    timeout_rcbs_alternate: u64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct ThreadClockState {
    /// baseline for clock comparisons
    last_tick: u64,
    /// offset from baseline to assert at a timer event
    timer_assertion: Option<u64>,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = IncrMsg;
    type Response = ();
    type Config = Config;

    async fn init_global_state(_: &Self::Config) -> Self {
        GlobalState {
            num_timer_evts: AtomicU64::new(0),
            num_signals: AtomicU64::new(0),
        }
    }

    async fn receive_rpc(&self, _from: Pid, msg: IncrMsg) -> Self::Response {
        match msg {
            IncrMsg::Timer => self.num_timer_evts.fetch_add(1, Ordering::SeqCst),
            IncrMsg::Signal => self.num_signals.fetch_add(1, Ordering::SeqCst),
        };
    }
}

const BULK_INJECTION_COUNT: u64 = 10;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = GlobalState;
    type ThreadState = ThreadClockState;

    fn subscriptions(cfg: &Config) -> Subscription {
        if cfg.sub_syscalls_only {
            Subscription::all_syscalls()
        } else {
            Subscription::all()
        }
    }

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        if guest.config().run_basic_tests {
            assert_eq!(guest.read_clock().unwrap(), 0);
            assert!(guest.set_timer(TimerSchedule::Rcbs(0)).is_err());
        }
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs);
        let alt_timeout = TimerSchedule::Rcbs(guest.config().timeout_rcbs_alternate);
        let (no, args) = syscall.into_parts();
        match no {
            Sysno::clock_getres => {
                guest.set_timer_precise(timeout).unwrap();
            }
            Sysno::msgrcv => {
                guest.set_timer_precise(alt_timeout).unwrap();
            }
            Sysno::timer_getoverrun => {
                guest.set_timer(timeout).unwrap();
            }
            Sysno::fanotify_init => {
                guest.set_timer_precise(timeout).unwrap();
                let kill_call = raise_sigwinch(guest).await;
                guest.tail_inject(kill_call).await
            }
            Sysno::fanotify_mark => {
                guest.set_timer(timeout).unwrap();
                let kill_call = raise_sigwinch(guest).await;
                guest.tail_inject(kill_call).await
            }
            Sysno::msgctl => {
                guest.set_timer_precise(timeout).unwrap();
                for _ in 0..BULK_INJECTION_COUNT {
                    guest.inject(Getpid::new()).await.unwrap();
                }
                guest.tail_inject(Getpid::new()).await
            }
            Sysno::msgget => {
                guest.set_timer(timeout).unwrap();
                for _ in 0..BULK_INJECTION_COUNT {
                    guest.inject(Getpid::new()).await.unwrap();
                }
                guest.tail_inject(Getpid::new()).await
            }
            Sysno::clock_settime => {
                let clock_value = guest.read_clock().unwrap();
                let ts = guest.thread_state_mut();
                ts.last_tick = clock_value;
                ts.timer_assertion = None;
            }
            Sysno::timer_gettime => {
                let clock_value = guest.read_clock().unwrap();
                let ts = guest.thread_state_mut();
                ts.last_tick = clock_value;
                ts.timer_assertion = Some(args.arg0 as u64);
            }
            Sysno::clock_adjtime => assert_eq!(
                guest.read_clock().unwrap(),
                guest.thread_state_mut().last_tick + args.arg0 as u64
            ),
            _ => guest.tail_inject(syscall).await,
        };
        Ok(0)
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(IncrMsg::Timer).await.unwrap();
        let clock_value = guest.read_clock().unwrap();
        let ts = guest.thread_state();
        if let Some(val) = ts.timer_assertion {
            assert_eq!(ts.last_tick + val, clock_value);
        }
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(IncrMsg::Signal).await.unwrap();
        Ok(Some(signal))
    }
}

async fn raise_sigwinch<T: Guest<LocalState>>(guest: &mut T) -> Tgkill {
    let pid = guest.inject(Getpid::new()).await.unwrap();
    let tid = guest.inject(Gettid::new()).await.unwrap();
    Tgkill::new()
        .with_tgid(pid as _)
        .with_tid(tid as _)
        .with_sig(libc::SIGWINCH)
}

// FIXME: Use the syscalls crate for doing this when it switches to using the
// `asm!()` macro instead of asm inside of a C file.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg(not(feature = "llvm_asm"))]
unsafe fn syscall_no_branches(no: libc::c_long, arg1: libc::c_long) {
    let mut _ret: u64;
    core::arch::asm!(
        "syscall",
        lateout("rax") _ret,
        in("rax") no,
        in("rdi") arg1,
        out("rcx") _, // rcx is used to store old rip
        out("r11") _, // r11 is used to store old rflags
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg(feature = "llvm_asm")]
#[allow(deprecated)]
unsafe fn syscall_no_branches(no: libc::c_long, arg1: libc::c_long) {
    llvm_asm!("
        mov $0, %rax
        mov $1, %rdi
        xor %rsi, %rsi
        xor %rdx, %rdx
        xor %r10, %r10
        xor %r8, %r8
        xor %r9, %r9
        syscall
        "
    : /* no output */
    : "r"(no), "r"(arg1)
    : "cc", "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", /* from syscall: */ "rcx", "r11"
    );
}

fn sched_precise() {
    unsafe { syscall_no_branches(libc::SYS_clock_getres, 0) }
}

fn sched_precise_alternate_rcb_count() {
    unsafe { syscall_no_branches(libc::SYS_msgrcv, 0) }
}

fn sched_imprecise() {
    unsafe { syscall_no_branches(libc::SYS_timer_getoverrun, 0) }
}

fn mark_clock() {
    unsafe { syscall_no_branches(libc::SYS_clock_settime, 0) }
}

fn assert_clock(delta: u64) {
    unsafe { syscall_no_branches(libc::SYS_clock_adjtime, delta as i64) }
}

fn assert_clock_at_next_timer(value: u64) {
    unsafe { syscall_no_branches(libc::SYS_timer_gettime, value as i64) }
}

fn do_syscall() {
    unsafe { syscall_no_branches(libc::SYS_clock_gettime, 0) }
}

fn immediate_exit() {
    unsafe { syscall_no_branches(libc::SYS_exit, 0) }
}

fn sched_precise_and_raise() {
    unsafe { syscall_no_branches(libc::SYS_fanotify_init, 0) }
}

fn sched_imprecise_and_raise() {
    unsafe { syscall_no_branches(libc::SYS_fanotify_mark, 0) }
}

fn sched_precise_and_inject() {
    unsafe { syscall_no_branches(libc::SYS_msgctl, 0) }
}

fn sched_imprecise_and_inject() {
    unsafe { syscall_no_branches(libc::SYS_msgget, 0) }
}

fn cpuid() {
    unsafe {
        __cpuid(0);
    }
}

fn rdtsc() {
    unsafe {
        _rdtsc();
    }
}

fn rdtscp() {
    unsafe {
        let mut x = 0u32;
        __rdtscp(&mut x as *mut _);
    }
}

fn ts_check_fn(rcbs: u64, f: impl FnOnce()) -> GlobalState {
    use reverie_ptrace::testing::check_fn_with_config;
    check_fn_with_config::<LocalState, _>(
        f,
        Config {
            timeout_rcbs: rcbs,
            ..Default::default()
        },
        true,
    )
}

const MANY_RCBS: u64 = 10000; // Normal perf signaling
const LESS_RCBS: u64 = 15; // Low enough to use artificial signaling

#[cfg(all(not(sanitized), test))]
mod timer_tests {
    //! These tests are highly sensitive to the number of branches executed
    //! in the guest, and this must remain consistent between opt and debug
    //! mode. If you pass non-constant values into do_branches and need them to
    //! be exact, be sure to precompute them in the tracer before moving them
    //! into the tracee, otherwise underflow or overflow checks will break the
    //! tests.

    use super::*;
    use reverie_ptrace::ret_without_perf;
    use reverie_ptrace::testing::{check_fn_with_config, do_branches};
    use test_case::test_case;

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    fn timer_delays_timer(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        let rcbd2 = rcbs / 2;
        let rcbx2 = rcbs * 2;
        let gs = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(rcbd2);
            schedule_timer();
            do_branches(rcbd2);
            schedule_timer();
            do_branches(rcbd2);
            schedule_timer();
            do_branches(rcbx2);
        });
        assert_eq!(gs.num_timer_evts.into_inner(), 1);
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    fn timer_is_single(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        let rcbx2 = rcbs * 2;
        let rcbx10 = rcbs * 10;
        let rcbx20 = rcbs * 20;
        let gs = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(rcbx2);
            schedule_timer();
            do_branches(rcbx10);
            schedule_timer();
            do_branches(rcbx20);
        });
        assert_eq!(gs.num_timer_evts.into_inner(), 3);
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_precise_and_inject)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_precise_and_inject)]
    fn precise_delivery_exact(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();

        // `do_branches(n)` does n+1 branches, so `rcbs - 1` will be the
        // first argument resulting in a timer event.
        // Precompute to avoid underflow checks in the guest

        let branch_ct = rcbs - 2;
        let gs3 = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(branch_ct);
            immediate_exit();
        });
        assert_eq!(gs3.num_timer_evts.into_inner(), 0);

        let branch_ct = rcbs - 1;
        let gs2 = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(branch_ct);
            immediate_exit();
        });
        assert_eq!(gs2.num_timer_evts.into_inner(), 1);
    }

    fn early_stop_rcbs(rcbs: u64) -> Vec<u64> {
        // Final value is 2 because do_branches adds 1
        [rcbs / 2, 1000, 100, 10, 2]
            .iter()
            .map(|x| *x)
            .filter(|x| *x < rcbs)
            .collect()
    }
    const LET_PASS_STOP_RCBS: u64 = 1;

    #[test_case(MANY_RCBS, do_syscall, sched_precise, 0)]
    #[test_case(MANY_RCBS, do_syscall, sched_imprecise, 0)]
    #[test_case(MANY_RCBS, cpuid, sched_precise, 0)]
    #[test_case(MANY_RCBS, cpuid, sched_imprecise, 0)]
    #[test_case(MANY_RCBS, rdtsc, sched_precise, 0)]
    #[test_case(MANY_RCBS, rdtsc, sched_imprecise, 0)]
    #[test_case(MANY_RCBS, rdtscp, sched_precise, 0)]
    #[test_case(MANY_RCBS, rdtscp, sched_imprecise, 0)]
    #[test_case(MANY_RCBS, sched_precise, sched_precise, 1)]
    #[test_case(MANY_RCBS, sched_imprecise, sched_precise, 1)]
    #[test_case(MANY_RCBS, sched_imprecise, sched_imprecise, 1)]
    #[test_case(MANY_RCBS, sched_precise, sched_imprecise, 1)]
    #[test_case(LESS_RCBS, do_syscall, sched_precise, 0)]
    #[test_case(LESS_RCBS, do_syscall, sched_imprecise, 0)]
    #[test_case(LESS_RCBS, cpuid, sched_precise, 0)]
    #[test_case(LESS_RCBS, cpuid, sched_imprecise, 0)]
    #[test_case(LESS_RCBS, rdtsc, sched_precise, 0)]
    #[test_case(LESS_RCBS, rdtsc, sched_imprecise, 0)]
    #[test_case(LESS_RCBS, rdtscp, sched_precise, 0)]
    #[test_case(LESS_RCBS, rdtscp, sched_imprecise, 0)]
    #[test_case(LESS_RCBS, sched_precise, sched_precise, 1)]
    #[test_case(LESS_RCBS, sched_imprecise, sched_precise, 1)]
    #[test_case(LESS_RCBS, sched_imprecise, sched_imprecise, 1)]
    #[test_case(LESS_RCBS, sched_precise, sched_imprecise, 1)]
    fn assert_cancels_timers(
        rcbs: u64,
        fun: fn() -> (),
        schedule_timer: fn() -> (),
        additional_evts: u64,
    ) {
        ret_without_perf!();
        let rcbx2 = rcbs * 2;
        for e in early_stop_rcbs(rcbs) {
            // Precompute to avoid underflow checks in the guest
            let branch_ct = rcbs - e;
            let gs = ts_check_fn(rcbs, move || {
                schedule_timer();
                do_branches(branch_ct);
                fun();
                do_branches(rcbx2);
            });
            assert_eq!(
                gs.num_timer_evts.into_inner(),
                0 + additional_evts,
                "iter: {}",
                e
            );
        }
        // Imprecise events can be delayed, in which case nothing fires, so only
        // test this if precise:
        if schedule_timer == sched_precise {
            // Precompute to avoid underflow checks in the guest
            let branch_ct = rcbs - LET_PASS_STOP_RCBS;
            let gs = ts_check_fn(rcbs, move || {
                schedule_timer();
                do_branches(branch_ct);
                fun();
                do_branches(rcbx2);
            });
            assert_eq!(gs.num_timer_evts.into_inner(), 1 + additional_evts);
        }
    }

    #[test_case(MANY_RCBS, sched_precise, sched_precise_and_raise)]
    #[test_case(MANY_RCBS, sched_imprecise, sched_imprecise_and_raise)]
    #[test_case(LESS_RCBS, sched_precise, sched_precise_and_raise)]
    #[test_case(LESS_RCBS, sched_imprecise, sched_imprecise_and_raise)]
    fn signals_cancel_timers(
        rcbs: u64,
        schedule_timer: fn() -> (),
        schedule_timer_and_raise: fn() -> (),
    ) {
        ret_without_perf!();
        let rcbd2 = rcbs / 2;
        let rcbx2 = rcbs * 2;

        // The signal after scheduling should immediately cancel the event
        let gs = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(rcbd2);
            schedule_timer_and_raise();
            do_branches(rcbx2);
            schedule_timer_and_raise();
            do_branches(rcbx2);
        });
        assert_eq!(gs.num_signals.into_inner(), 2); // defensive
        assert_eq!(gs.num_timer_evts.into_inner(), 0);

        // If we don't raise, events delivered as expected:
        let gs = ts_check_fn(rcbs, move || {
            schedule_timer();
            do_branches(rcbd2);
            schedule_timer();
            do_branches(rcbx2);
            schedule_timer();
            do_branches(rcbx2);
        });
        assert_eq!(gs.num_signals.into_inner(), 0); // defensive
        assert_eq!(gs.num_timer_evts.into_inner(), 2);
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    fn not_subscribed_doesnt_cancel(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        let rcbd2 = rcbs / 2;
        let rcbx2 = rcbs * 2;
        let gs = check_fn_with_config::<LocalState, _>(
            move || {
                schedule_timer();
                do_branches(rcbd2);
                cpuid();
                rdtsc();
                rdtscp();
                do_branches(rcbx2);
            },
            Config {
                timeout_rcbs: rcbs,
                sub_syscalls_only: true,
                ..Default::default()
            },
            true,
        );
        assert_eq!(gs.num_timer_evts.into_inner(), 1);
    }

    fn loop_with_branch_ct(
        rcbs: u64,
        branch_ct: u64,
        iters: u64,
        schedule_timer: fn() -> (),
    ) -> GlobalState {
        ts_check_fn(rcbs, move || {
            for _ in 0..iters {
                schedule_timer();
                do_branches(branch_ct);
                schedule_timer(); // cancel timer before loop branch
            }
            immediate_exit(); // RCBs in teardown would trigger the last iter's event
        })
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_precise_and_inject)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_precise_and_inject)]
    fn precise_deterministic_loop(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        let rcbm2 = rcbs - 2;
        let rcbm1 = rcbs - 1;
        const ITERS: u64 = 500;
        assert_eq!(
            loop_with_branch_ct(rcbs, rcbm2, ITERS, schedule_timer)
                .num_timer_evts
                .into_inner(),
            0
        );
        assert_eq!(
            loop_with_branch_ct(rcbs, rcbm1, ITERS, schedule_timer)
                .num_timer_evts
                .into_inner(),
            ITERS
        );
    }

    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(MANY_RCBS, sched_imprecise_and_inject)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_imprecise_and_inject)]
    fn imprecise_not_early_loop(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        const ITERS: u64 = 2000;
        let rcbm2 = rcbs - 2;
        assert_eq!(
            loop_with_branch_ct(rcbs, rcbm2, ITERS, schedule_timer)
                .num_timer_evts
                .into_inner(),
            0
        );
    }

    /// Regression test: Verify that a shorter event isn't cancelled by the
    /// occurrence of longer one if the two happen to align.
    #[test]
    fn long_short_not_cancelled() {
        ret_without_perf!();
        // Doing this test correctly requires correctly predicting the amount of
        // skid in the underlying RCB signal. For that reason, we run the gamut
        // of possibilities in increments of 5, several times for each.
        const ITERS: usize = 50;

        // <============ MANY_RCBS ==============>
        //                <===== SKID_MARGIN ====>
        //                <= skid ==>
        //                        <= overlap =>
        // ----------------------------------------------------
        //  ^             ^       |  ^            ^
        //  sched         timeout |  signal       delivery
        //                        |
        //                        `> schedule short event to cause step overlap
        // schedule time is therefore
        // MANY_RCBS - (SKID_MARGIN - skid) - (LESS_RCBS / 2)
        // skid_param = SKID_MARGIN - skid
        for skid_param in (0u64..200).step_by(5) {
            let branch_ct = MANY_RCBS - skid_param - (LESS_RCBS / 2);
            for _ in 0..ITERS {
                let gs = check_fn_with_config::<LocalState, _>(
                    move || {
                        sched_precise();
                        do_branches(branch_ct);
                        sched_precise_alternate_rcb_count();
                        do_branches(MANY_RCBS * 10);
                    },
                    Config {
                        timeout_rcbs: MANY_RCBS,
                        timeout_rcbs_alternate: LESS_RCBS,
                        ..Default::default()
                    },
                    true,
                );
                assert_eq!(gs.num_timer_evts.into_inner(), 1);
            }
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod clock_tests {
    use super::*;
    use reverie_ptrace::ret_without_perf;
    use reverie_ptrace::testing::{check_fn, do_branches};
    use test_case::test_case;

    #[test]
    fn clock_accuracy() {
        ret_without_perf!();
        for r in [100, 1000, 10000, 100000, 1000000] {
            let rp1 = r + 1; // precompute
            check_fn::<LocalState, _>(move || {
                mark_clock();
                do_branches(r);
                assert_clock(rp1);
            });
        }
    }

    #[test]
    fn clock_stays_without_branch() {
        ret_without_perf!();
        let r = 2000;
        let rp1 = r + 1; // precompute
        check_fn::<LocalState, _>(move || {
            mark_clock();
            do_branches(r);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
            assert_clock(rp1);
        });
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    fn clock_with_timer(rcbs: u64, schedule_timer: fn() -> ()) {
        ret_without_perf!();
        let a = rcbs * 2;
        let b = a + 1;
        let c = rcbs / 2;
        let d = c + 1;
        let gs = ts_check_fn(rcbs, move || {
            mark_clock();
            schedule_timer();
            do_branches(a);
            assert_clock(b); // timer received

            mark_clock();
            schedule_timer();
            do_branches(c);
            assert_clock(d); // timer outstanding
        });
        assert_eq!(gs.num_timer_evts.into_inner(), 1);
    }

    #[test_case(MANY_RCBS)]
    #[test_case(LESS_RCBS)]
    fn clock_at_timer_delivery(rcbs: u64) {
        ret_without_perf!();
        let rcbx2 = rcbs * 2;
        let gs = ts_check_fn(rcbs, move || {
            mark_clock();
            assert_clock_at_next_timer(rcbs);
            sched_precise();
            do_branches(rcbx2);
        });
        assert_eq!(gs.num_timer_evts.into_inner(), 1);
    }
}

#[cfg(all(not(sanitized), test))]
mod general {
    use super::*;
    use reverie_ptrace::ret_without_perf;
    use reverie_ptrace::testing::check_fn_with_config;

    #[test]
    fn basic() {
        ret_without_perf!();
        let _gs = check_fn_with_config::<LocalState, _>(
            move || {
                do_syscall();
            },
            Config {
                run_basic_tests: true,
                ..Default::default()
            },
            true,
        );
    }
}
