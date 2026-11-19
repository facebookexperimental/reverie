/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Verifies precision, determinism, and cancellation of timer events and clocks.
//!
//! Syscalls are abused to communicate from the guest to the tool instructions
//! necessary to carry out the test, such as setting timers or reading clocks.

#[cfg(all(not(sanitized), test))]
use std::sync::Mutex;
#[cfg(all(not(sanitized), test))]
use std::sync::atomic::AtomicU64;
#[cfg(all(not(sanitized), test))]
use std::sync::atomic::Ordering;

#[cfg(all(not(sanitized), test))]
use reverie::Errno;
#[cfg(all(not(sanitized), test))]
use reverie::Error;
#[cfg(all(not(sanitized), test))]
use reverie::GlobalTool;
#[cfg(all(not(sanitized), test))]
use reverie::Guest;
#[cfg(all(not(sanitized), test))]
use reverie::Pid;
#[cfg(all(not(sanitized), test))]
use reverie::Signal;
#[cfg(all(not(sanitized), test))]
use reverie::Subscription;
#[cfg(all(not(sanitized), test))]
use reverie::TimerSchedule;
#[cfg(all(not(sanitized), test))]
use reverie::Tool;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Getpid;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Gettid;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Syscall;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallInfo;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Sysno;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Tgkill;
#[cfg(all(not(sanitized), test))]
use reverie_ptrace::regs::RegAccess;
#[cfg(all(not(sanitized), test))]
use serde::Deserialize;
#[cfg(all(not(sanitized), test))]
use serde::Serialize;

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default)]
struct GlobalState {
    num_timer_evts: AtomicU64,
    num_signals: AtomicU64,
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct LocalState;

#[cfg(all(not(sanitized), test))]
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
enum IncrMsg {
    Timer,
    Signal,
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    sub_syscalls_only: bool,
    run_basic_tests: bool,
    timeout_rcbs: u64,
    timeout_rcbs_alternate: u64,
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct ThreadClockState {
    /// baseline for clock comparisons
    last_tick: u64,
    /// offset from baseline to assert at a timer event
    timer_assertion: Option<u64>,
}

#[cfg(all(not(sanitized), test))]
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

#[cfg(all(not(sanitized), test))]
const BULK_INJECTION_COUNT: u64 = 10;

#[cfg(all(not(sanitized), test))]
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
        guest.send_rpc(IncrMsg::Timer).await;
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
        guest.send_rpc(IncrMsg::Signal).await;
        Ok(Some(signal))
    }
}

#[cfg(all(not(sanitized), test))]
async fn raise_sigwinch<T: Guest<LocalState>>(guest: &mut T) -> Tgkill {
    let pid = guest.inject(Getpid::new()).await.unwrap();
    let tid = guest.inject(Gettid::new()).await.unwrap();
    Tgkill::new()
        .with_tgid(pid as _)
        .with_tid(tid as _)
        .with_sig(libc::SIGWINCH)
}

#[cfg(all(not(sanitized), test))]
#[derive(Default)]
struct InstructionTracingGlobal {
    timer_events: Mutex<Vec<TimerEvent>>,
}

#[cfg(all(not(sanitized), test))]
#[derive(PartialEq, Default, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
struct TimerEvent {
    rcbs: u64,
    rip: reverie_ptrace::regs::Reg,
}

#[cfg(all(not(sanitized), test))]
#[derive(Default, Clone, Serialize, Deserialize)]
struct InstructionTracingConfig {
    set_timer_after_syscall: Option<(u64, Option<u64>)>,
}

#[cfg(all(not(sanitized), test))]
#[derive(Serialize, Deserialize)]
enum InstructionTracingRequest {
    Timer(TimerEvent),
}

#[cfg(all(not(sanitized), test))]
#[reverie::global_tool]
impl GlobalTool for InstructionTracingGlobal {
    type Request = InstructionTracingRequest;
    type Response = ();
    type Config = InstructionTracingConfig;

    async fn receive_rpc(&self, _from: reverie::Tid, message: Self::Request) -> Self::Response {
        match message {
            InstructionTracingRequest::Timer(ev) => self.timer_events.lock().unwrap().push(ev),
        }
    }
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct InstructionTracing;

#[cfg(all(not(sanitized), test))]
#[reverie::tool]
impl Tool for InstructionTracing {
    type GlobalState = InstructionTracingGlobal;
    type ThreadState = ThreadClockState;

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        c: Syscall,
    ) -> Result<i64, Error> {
        match guest.config().set_timer_after_syscall {
            Some((rcb, Some(instr))) => {
                guest.set_timer_precise(reverie::TimerSchedule::RcbsAndInstructions(rcb, instr))?;
            }

            Some((rcb, None)) => {
                guest.set_timer_precise(reverie::TimerSchedule::Rcbs(rcb))?;
            }
            _ => {}
        }
        guest.tail_inject(c).await
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let rcbs = guest.read_clock().expect("clock available");
        let rip = guest.regs().await.ip();
        guest
            .send_rpc(InstructionTracingRequest::Timer(TimerEvent { rcbs, rip }))
            .await;
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    //! These tests are highly sensitive to the number of branches executed
    //! in the guest, and this must remain consistent between opt and debug
    //! mode. If you pass non-constant values into do_branches and need them to
    //! be exact, be sure to precompute them in the tracer before moving them
    //! into the tracee, otherwise underflow or overflow checks will break the
    //! tests.
    //!
    //! Some cases expect x86_64 behaviour and are ignored elsewhere. Each
    //! ignore names one of these causes:
    //!
    //! - RCB arithmetic: the expected counts are x86_64 retired conditional
    //!   branches. The aarch64 counter, `BR_RETIRED`, counts every retired
    //!   branch, so each call and return in the guest (around `do_branches`,
    //!   and around a timer function called through its pointer) adds to the
    //!   count and moves the exact boundaries these cases assert. In an opt
    //!   build the surplus measured 2 RCBs around `do_branches` (its BL and
    //!   RET) and 2 more around a timer function called through its pointer
    //!   (BLR and RET), but which calls survive inlining, and which other
    //!   unconditional branches the compiler emits around the assembly in
    //!   `do_branches`, is the compiler's choice and can change with the build
    //!   mode. x86_64 counts only the conditional branches the tests place, so
    //!   there is no fixed aarch64 count to assert in their place.
    //! - x86-only trapped instructions: `cpuid`, `rdtsc` and `rdtscp` trap to
    //!   the tool on x86_64, which cancels the pending timer. On aarch64 those
    //!   helpers are empty and no instruction traps to the tool in their place.
    //! - imprecise-timer skid: an imprecise timer fires when the PMU overflow
    //!   interrupt arrives. On aarch64 that comes up to hundreds of branches
    //!   late (`reverie::pmu_config` records skids of 194 on Neoverse V2 and
    //!   1,301 on Cortex-A78C), longer than the 7 to 300 branches the
    //!   `LESS_RCBS` imprecise cases leave before the timer is cancelled. Skid
    //!   varies with the core and the load, so it gives no value to assert.

    use reverie_ptrace::ret_without_perf;
    use reverie_ptrace::testing::check_fn;
    use reverie_ptrace::testing::check_fn_with_config;
    use reverie_ptrace::testing::do_branches;
    use test_case::test_case;

    use super::*;

    #[inline(always)]
    unsafe fn syscall_no_branches(no: Sysno, arg1: libc::c_long) {
        syscalls::raw_syscall!(no, arg1, 0, 0, 0, 0, 0);
    }

    fn sched_precise() {
        unsafe { syscall_no_branches(Sysno::clock_getres, 0) }
    }

    fn sched_precise_alternate_rcb_count() {
        unsafe { syscall_no_branches(Sysno::msgrcv, 0) }
    }

    fn sched_imprecise() {
        unsafe { syscall_no_branches(Sysno::timer_getoverrun, 0) }
    }

    fn mark_clock() {
        unsafe { syscall_no_branches(Sysno::clock_settime, 0) }
    }

    fn assert_clock(delta: u64) {
        unsafe { syscall_no_branches(Sysno::clock_adjtime, delta as i64) }
    }

    fn assert_clock_at_next_timer(value: u64) {
        unsafe { syscall_no_branches(Sysno::timer_gettime, value as i64) }
    }

    fn do_syscall() {
        unsafe { syscall_no_branches(Sysno::clock_gettime, 0) }
    }

    fn immediate_exit() {
        unsafe { syscall_no_branches(Sysno::exit, 0) }
    }

    fn sched_precise_and_raise() {
        unsafe { syscall_no_branches(Sysno::fanotify_init, 0) }
    }

    fn sched_imprecise_and_raise() {
        unsafe { syscall_no_branches(Sysno::fanotify_mark, 0) }
    }

    fn sched_precise_and_inject() {
        unsafe { syscall_no_branches(Sysno::msgctl, 0) }
    }

    fn sched_imprecise_and_inject() {
        unsafe { syscall_no_branches(Sysno::msgget, 0) }
    }

    fn cpuid() {
        #[cfg(target_arch = "x86_64")]
        core::arch::x86_64::__cpuid(0);
    }

    fn rdtsc() {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::x86_64::_rdtsc();
        }
    }

    fn rdtscp() {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let mut x = 0u32;
            core::arch::x86_64::__rdtscp(&mut x as *mut _);
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

    /// [`timer_is_single`] with an imprecise timer and `LESS_RCBS`.
    #[test]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "imprecise-timer skid: aarch64 PMU overflow skid is longer than this case's branch windows"
    )]
    fn timer_is_single_less_rcbs_sched_imprecise() {
        timer_is_single(LESS_RCBS, sched_imprecise);
    }

    #[test_case(MANY_RCBS, sched_precise)]
    #[test_case(MANY_RCBS, sched_precise_and_inject)]
    #[test_case(LESS_RCBS, sched_precise)]
    #[test_case(LESS_RCBS, sched_precise_and_inject)]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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
            .copied()
            .filter(|x| *x < rcbs)
            .collect()
    }
    const LET_PASS_STOP_RCBS: u64 = 1;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum TimerKind {
        Precise,
        Imprecise,
    }

    /// A syscall or a scheduled timer cancels a pending timer; the cases that
    /// cancel with a trapped instruction are
    /// [`assert_trapped_instructions_cancel_timers`]. On aarch64 the calls and
    /// returns around `do_branches` and `fun` push the run that should stop 2
    /// RCBs short of the timer's target past it, so even the imprecise cases
    /// pass there only when skid delivers the timer after the syscall.
    #[test_case(MANY_RCBS, do_syscall, TimerKind::Precise, 0)]
    #[test_case(MANY_RCBS, do_syscall, TimerKind::Imprecise, 0)]
    #[test_case(MANY_RCBS, sched_precise, TimerKind::Precise, 1)]
    #[test_case(MANY_RCBS, sched_imprecise, TimerKind::Precise, 1)]
    #[test_case(MANY_RCBS, sched_imprecise, TimerKind::Imprecise, 1)]
    #[test_case(MANY_RCBS, sched_precise, TimerKind::Imprecise, 1)]
    #[test_case(LESS_RCBS, do_syscall, TimerKind::Precise, 0)]
    #[test_case(LESS_RCBS, do_syscall, TimerKind::Imprecise, 0)]
    #[test_case(LESS_RCBS, sched_precise, TimerKind::Precise, 1)]
    #[test_case(LESS_RCBS, sched_imprecise, TimerKind::Precise, 1)]
    #[test_case(LESS_RCBS, sched_imprecise, TimerKind::Imprecise, 1)]
    #[test_case(LESS_RCBS, sched_precise, TimerKind::Imprecise, 1)]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
    fn assert_cancels_timers(
        rcbs: u64,
        fun: fn() -> (),
        timer_kind: TimerKind,
        additional_evts: u64,
    ) {
        ret_without_perf!();
        // Select in the tracer so the guest executes the same timer function
        // without adding branches to its measured work.
        let schedule_timer: fn() = match timer_kind {
            TimerKind::Precise => sched_precise,
            TimerKind::Imprecise => sched_imprecise,
        };
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
                additional_evts,
                "iter: {}",
                e
            );
        }
        // Imprecise events can be delayed, in which case nothing fires, so only
        // test this if precise:
        if timer_kind == TimerKind::Precise {
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

    /// [`assert_cancels_timers`] with an instruction that traps to the tool.
    #[test_case(MANY_RCBS, cpuid, TimerKind::Precise, 0)]
    #[test_case(MANY_RCBS, cpuid, TimerKind::Imprecise, 0)]
    #[test_case(MANY_RCBS, rdtsc, TimerKind::Precise, 0)]
    #[test_case(MANY_RCBS, rdtsc, TimerKind::Imprecise, 0)]
    #[test_case(MANY_RCBS, rdtscp, TimerKind::Precise, 0)]
    #[test_case(MANY_RCBS, rdtscp, TimerKind::Imprecise, 0)]
    #[test_case(LESS_RCBS, cpuid, TimerKind::Precise, 0)]
    #[test_case(LESS_RCBS, cpuid, TimerKind::Imprecise, 0)]
    #[test_case(LESS_RCBS, rdtsc, TimerKind::Precise, 0)]
    #[test_case(LESS_RCBS, rdtsc, TimerKind::Imprecise, 0)]
    #[test_case(LESS_RCBS, rdtscp, TimerKind::Precise, 0)]
    #[test_case(LESS_RCBS, rdtscp, TimerKind::Imprecise, 0)]
    #[cfg_attr(
        not(target_arch = "x86_64"),
        ignore = "x86-only trapped instructions: cpuid, rdtsc and rdtscp have no aarch64 counterpart; the helpers are empty there"
    )]
    fn assert_trapped_instructions_cancel_timers(
        rcbs: u64,
        fun: fn() -> (),
        timer_kind: TimerKind,
        additional_evts: u64,
    ) {
        assert_cancels_timers(rcbs, fun, timer_kind, additional_evts);
    }

    #[test_case(MANY_RCBS, sched_precise, sched_precise_and_raise)]
    #[test_case(MANY_RCBS, sched_imprecise, sched_imprecise_and_raise)]
    #[test_case(LESS_RCBS, sched_precise, sched_precise_and_raise)]
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

    /// [`signals_cancel_timers`] with an imprecise timer and `LESS_RCBS`.
    #[test]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "imprecise-timer skid: aarch64 PMU overflow skid is longer than this case's branch windows"
    )]
    fn signals_cancel_timers_less_rcbs_sched_imprecise() {
        signals_cancel_timers(LESS_RCBS, sched_imprecise, sched_imprecise_and_raise);
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
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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
        // Retries are the runner's, not this case's: the counted runner
        // (scripts/libtest-counts.rs) and the gated runner
        // (run_gated.py --counted-retries) rerun a failed case a
        // counted number of times and record a pass on retry as
        // REVERIE_FLAKY. No lane is assumed quiet. What this case
        // adds is the evidence a retry is judged by: the skid
        // witnesses taken over the run, in the assertion message in
        // the form run_gated.py parses. A contention miss (the
        // overflow handled after the guest passed the delivery
        // point) leaves one Missed detail, notification queued at
        // past_target 0, per undelivered event, so counted +
        // qualifying == ITERS with witnesses == qualifying; a short
        // count without them is a product failure no runner may
        // retry. The counters are process-global: sanctioned runners
        // execute one case at a time in a process (--test-threads=1,
        // nextest, run_gated), which is what attributes them here.
        let _ = reverie::take_skid_overshoot_count();
        let _ = reverie::take_skid_overshoot_details();
        let counted = loop_with_branch_ct(rcbs, rcbm1, ITERS, schedule_timer)
            .num_timer_evts
            .into_inner();
        let witnesses = reverie::take_skid_overshoot_count();
        let details = reverie::take_skid_overshoot_details();
        let qualifying = details
            .iter()
            .filter(|detail| {
                matches!(
                    detail.kind,
                    reverie::SkidOvershootKind::Missed {
                        notification_queued: true,
                        ..
                    }
                ) && detail.past_target() == 0
            })
            .count();
        assert_eq!(
            counted, ITERS,
            "precise timer counted {counted} of {ITERS}; skid witnesses \
             {witnesses}, qualifying {qualifying}: {details:?}"
        );
    }

    #[test_case(MANY_RCBS, sched_imprecise)]
    #[test_case(MANY_RCBS, sched_imprecise_and_inject)]
    #[test_case(LESS_RCBS, sched_imprecise)]
    #[test_case(LESS_RCBS, sched_imprecise_and_inject)]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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

    #[test]
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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
    #[cfg_attr(
        target_arch = "aarch64",
        ignore = "RCB arithmetic: aarch64 BR_RETIRED also counts the guest's calls and returns, whose number is the compiler's inlining and branch lowering, so no fixed aarch64 count exists"
    )]
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

    #[test_case(1000, None, 1000, Some(1))]
    #[test_case(1000, Some(1), 1000, Some(2))]
    #[test_case(1000, Some(100), 1000, Some(101))]
    #[test_case(10, None, 10, Some(1))]
    #[test_case(10, Some(1), 10, Some(2))]
    #[test_case(10, Some(100), 10, Some(101))]
    fn test_set_precice_with_instructions_after_syscall(
        rcb_1: u64,
        instr_1: Option<u64>,
        rcb_2: u64,
        instr_2: Option<u64>,
    ) {
        ret_without_perf!();
        let gs_1 = check_fn_with_config::<InstructionTracing, _>(
            move || {
                do_syscall();
                do_branches(MANY_RCBS);
            },
            InstructionTracingConfig {
                set_timer_after_syscall: Some((rcb_1, instr_1)),
            },
            true,
        );

        let gs_2 = check_fn_with_config::<InstructionTracing, _>(
            move || {
                do_syscall();
                do_branches(MANY_RCBS);
            },
            InstructionTracingConfig {
                set_timer_after_syscall: Some((rcb_2, instr_2)),
            },
            true,
        );
        let rips = [&gs_1, &gs_2].map(|s| s.timer_events.lock().unwrap()[0].rip);
        assert_ne!(rips[0], rips[1]);
    }
}
