/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest thread that holds all but one hardware breakpoint slot through
//! `perf_event_open` leaves too few for branch runs: the timer must take
//! none, leave the guest's breakpoints alone, and deliver every precise
//! event where single steps do.

#![cfg(target_arch = "aarch64")]

use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::check_fn_with_config;
use reverie_ptrace::testing::precise_timer_steps;
use reverie_ptrace::testing::set_block_steps;

const TARGETS: [u64; 4] = [20_000, 20_001, 20_002, 20_003];

/// (clock from the request, pc) at each timer event, and the guest's
/// breakpoint count.
#[derive(Debug, Default)]
struct TimerEvents(Mutex<Vec<(u64, u64)>>);

#[reverie::global_tool]
impl GlobalTool for TimerEvents {
    type Request = (u64, u64);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, event: (u64, u64)) {
        self.0.lock().unwrap().push(event);
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = TimerEvents;
    type ThreadState = u64;

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                *guest.thread_state_mut() = guest.read_clock().unwrap();
                let target = syscall.into_parts().1.arg0 as u64;
                guest
                    .set_timer_precise(TimerSchedule::Rcbs(target))
                    .unwrap();
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let clock = guest.read_clock().unwrap() - *guest.thread_state();
        let pc = guest.regs().await.pc;
        guest.send_rpc((clock, pc)).await;
    }
}

fn request(target: u64) {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") Sysno::clock_getres as usize,
            inlateout("x0") target as usize => _,
            in("x1") 0usize,
            options(nostack),
        );
    }
}

#[inline(never)]
fn countdown(iterations: u64) {
    unsafe {
        core::arch::asm!(
            "2:",
            "tbz {0}, #0, 4f",
            "nop",
            "4:",
            "subs {0}, {0}, #1",
            "b.ne 2b",
            inout(reg) iterations => _,
            options(nostack),
        );
    }
}

/// Never executed: the guest's breakpoints watch it.
#[inline(never)]
extern "C" fn never_called() {}

/// The first fields of `struct perf_event_attr` (include/uapi/linux/perf_event.h)
/// through `bp_len`, `PERF_ATTR_SIZE_VER1`.
#[repr(C)]
#[derive(Default)]
struct BreakpointAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    bp_addr: u64,
    bp_len: u64,
}

const PERF_TYPE_BREAKPOINT: u32 = 5;
const HW_BREAKPOINT_X: u32 = 4;
/// `exclude_kernel` and `exclude_hv` in `flags`.
const EXCLUDE_KERNEL_AND_HV: u64 = (1 << 5) | (1 << 6);

fn open_breakpoint(index: usize) -> i64 {
    let attr = BreakpointAttr {
        type_: PERF_TYPE_BREAKPOINT,
        size: std::mem::size_of::<BreakpointAttr>() as u32,
        flags: EXCLUDE_KERNEL_AND_HV,
        bp_type: HW_BREAKPOINT_X,
        bp_addr: never_called as *const () as u64 + 4 * index as u64,
        bp_len: 4,
        ..Default::default()
    };
    unsafe { libc::syscall(libc::SYS_perf_event_open, &attr as *const _, 0, -1, -1, 0) }
}

/// Whether this thread may hold a `perf_event_open` breakpoint: not where
/// `perf_event_paranoid` forbids it, or a machine has no breakpoint slots.
fn breakpoints_available() -> bool {
    let fd = open_breakpoint(0);
    if fd >= 0 {
        unsafe { libc::close(fd as i32) };
    }
    fd >= 0
}

/// Opens execute breakpoints on this thread until the slots run out, then
/// closes one, so that exactly one slot is free. Returns how many it holds.
fn hold_all_but_one_breakpoint() -> usize {
    let mut fds = Vec::new();
    loop {
        let fd = open_breakpoint(fds.len());
        if fd < 0 {
            break;
        }
        fds.push(fd);
    }
    if let Some(fd) = fds.pop() {
        unsafe { libc::close(fd as i32) };
    }
    let held = fds.len();
    // Kept open for the rest of the guest.
    std::mem::forget(fds);
    held
}

fn run() -> (
    Vec<(u64, u64)>,
    reverie_ptrace::testing::PreciseTimerSteps,
    u64,
) {
    let _ = reverie::take_skid_overshoot_count();
    let before = precise_timer_steps();
    let events = check_fn_with_config::<PreciseTimerTool, _>(
        || {
            let held = hold_all_but_one_breakpoint();
            assert!(held >= 1, "the guest holds breakpoints");
            for target in TARGETS {
                request(target);
                countdown(target);
            }
        },
        (),
        true,
    );
    let steps = precise_timer_steps() - before;
    let witnesses = reverie::take_skid_overshoot_count();
    (events.0.into_inner().unwrap(), steps, witnesses)
}

#[test]
fn branch_runs_leave_a_guests_breakpoints_alone() {
    ret_without_perf!();
    if !breakpoints_available() {
        eprintln!("skipping: perf_event_open breakpoints are unavailable here");
        return;
    }
    set_block_steps(true);
    let (ran, run_steps, run_witnesses) = run();
    set_block_steps(false);
    let (single, _, single_witnesses) = run();
    set_block_steps(true);
    eprintln!("branch runs on: {run_steps:?}, events {ran:?}");
    assert_eq!(ran.len(), TARGETS.len(), "each timer fires once");
    assert_eq!(
        run_steps.branch, 0,
        "one free slot is too few for a branch run: {run_steps:?}"
    );
    assert_eq!(run_steps.branch_mismatches, 0, "{run_steps:?}");
    if run_witnesses + single_witnesses > 0 {
        // A late PMU notification is delivered at the observed counter, so
        // that event's point is the host's, not the stepping's.
        eprintln!(
            "skipping the comparison: {run_witnesses} and {single_witnesses} witnessed skid overshoots"
        );
        return;
    }
    assert_eq!(ran, single, "events land where single steps deliver them");
}
