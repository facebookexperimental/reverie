/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Counts and verifies the number of reverie events received while the guest is busywaiting
//! or otherwise CPU spinning. The beginning and end of the busywait are marked by `clock_getres`
//! syscalls to avoid errantly counting end-of-process syscalls/events.
//!
//! This verifies that timer events, if requested, are delivered during busywaits and are not delivered
//! if not requested.

use libc;
use raw_cpuid::cpuid;
use reverie::syscalls::Syscall;
use reverie::CpuIdResult;
use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Signal;
use reverie::Tid;
use reverie::TimerSchedule;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize, Default)]
struct GlobalState {
    num_evts: AtomicU64,
    num_timer_evts: AtomicU64,
    collect: AtomicBool,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct Config {
    set_timer: bool,
}

#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum IncrMsg {
    Increment,
    ToggleCollection,
    TimerEvent,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = IncrMsg;
    type Response = ();
    type Config = Config;

    async fn init_global_state(_: &Self::Config) -> Self {
        GlobalState {
            num_evts: AtomicU64::new(0),
            num_timer_evts: AtomicU64::new(0),
            collect: AtomicBool::new(false),
        }
    }

    async fn receive_rpc(&self, _from: Pid, msg: IncrMsg) -> Self::Response {
        match msg {
            IncrMsg::ToggleCollection => {
                self.collect.fetch_xor(true, Ordering::SeqCst);
            }
            IncrMsg::Increment if self.collect.load(Ordering::SeqCst) => {
                self.num_evts.fetch_add(1, Ordering::SeqCst);
            }
            IncrMsg::Increment => {}
            IncrMsg::TimerEvent => {
                self.num_timer_evts.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

// Use RCBs directly to ensure determinism tests are robust to changes in
// conversion from realtime to RCBs.
const TIMEOUT: TimerSchedule = TimerSchedule::Rcbs(120_000_000);

/// Should implement _all_ reverie callbacks.
#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = GlobalState;

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        guest.send_rpc(IncrMsg::Increment).await;
        Ok(())
    }

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        guest.send_rpc(IncrMsg::Increment).await;
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::ClockGetres(_) = syscall {
            // clock_getres denotes the start/end of the busywait
            guest.send_rpc(IncrMsg::ToggleCollection).await;
            if guest.config().set_timer {
                guest.set_timer_precise(TIMEOUT).unwrap();
            }
        } else {
            guest.send_rpc(IncrMsg::Increment).await;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_cpuid_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, Errno> {
        guest.send_rpc(IncrMsg::Increment).await;
        Ok(cpuid!(eax, ecx))
    }

    async fn handle_rdtsc_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        guest.send_rpc(IncrMsg::Increment).await;
        Ok(RdtscResult::new(request))
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(IncrMsg::Increment).await;
        Ok(Some(signal))
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(IncrMsg::TimerEvent).await;
        guest.set_timer_precise(TIMEOUT).unwrap();
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Tid,
        global_state: &G,
        _thread_state: Self::ThreadState,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state.send_rpc(IncrMsg::Increment).await;
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state.send_rpc(IncrMsg::Increment).await;
        Ok(())
    }
}

/// Inform the Tool to begin counting events via a specific syscall
fn do_marker_syscall() {
    unsafe {
        libc::clock_getres(libc::CLOCK_MONOTONIC, std::ptr::null_mut());
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use reverie_ptrace::testing::check_fn_with_config;
    use reverie_ptrace::testing::do_branches;

    #[test]
    fn guest_busywait_no_timer() {
        let start = Instant::now();
        let gs = check_fn_with_config::<LocalState, _>(
            move || {
                // Signal start/end of busywait via marker syscall
                do_marker_syscall();
                do_branches(10_000_000_000);
                do_marker_syscall();
            },
            Config { set_timer: false },
            true,
        );
        // Spin outlasts any reasonable scheduling interval
        assert!(start.elapsed() > Duration::from_millis(2700));
        // No events received during busywait
        assert_eq!(gs.num_evts.into_inner(), 0);
        assert_eq!(gs.num_timer_evts.into_inner(), 0);
    }

    #[test]
    fn guest_busywait_timer() {
        use reverie_ptrace::ret_without_perf;
        ret_without_perf!();
        let start = Instant::now();
        let gs = check_fn_with_config::<LocalState, _>(
            move || {
                // Signal start/end of busywait via marker syscall
                do_marker_syscall();
                do_branches(10_000_000_000);
                do_marker_syscall();
            },
            Config { set_timer: true },
            true,
        );
        // Spin outlasts any reasonable scheduling interval
        assert!(start.elapsed() > Duration::from_millis(2700));
        // Events received only from timer
        assert_eq!(gs.num_evts.into_inner(), 0);
        // Soft test of determinism: assert exact number of timer events
        assert_eq!(gs.num_timer_evts.into_inner(), 83);
    }
}
