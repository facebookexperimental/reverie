/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A stop that interrupts a single step toward a precise timer event with an
//! instruction offset, past the target branch, at an instruction that can run
//! without moving `rip` or the branch counter (`runs_in_place`), leaves the
//! tracer unable to tell whether the instruction ran, so the event could land
//! one instruction late. `Timer::attempt_single_step` records a skid overshoot
//! there (`uncounted_step_may_miscount`), and the stepping resumes once the
//! stop is disregarded (`Task::disregard_stop_for_timer`).
//!
//! The stop is forced, not raced: just before the step that would run the
//! guest's `rep stosb` for the first time, the test's step hook arms a
//! hardware instruction breakpoint on it through the thread's debug
//! registers, so the step stops with a breakpoint `SIGTRAP` before the
//! instruction runs, a trap that is neither the step's report nor any trap
//! Reverie claims. The hook disarms it before the next step.

use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

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
use safeptrace::Stopped;
use serde::Deserialize;
use serde::Serialize;

use crate::testing::check_fn_with_config;
use crate::testing::do_branches;

/// Far above any skid margin, so the request programs a real PMU notification.
const TIMEOUT_RCBS: u64 = 100_000;

/// More instructions than the guest runs between its last branches and its
/// `rep stosb`, and fewer than that instruction's iterations: the steps toward
/// the event reach the `rep stosb` and end inside it.
const OFFSET_INSTRS: u64 = 1_000;

/// Branches the guest takes past the timer's target before its `rep stosb`:
/// a margin for the few branches by which the target can sit off the guest's
/// own count, far fewer than the offset's instructions can step through.
const TARGET_LEAD: u64 = 50;

/// Iterations of the guest's `rep stosb`.
const STOSB_BYTES: usize = 4_096;

/// The encoding of `rep stosb`.
const REP_STOSB: [u8; 2] = [0xf3, 0xaa];

/// DR7's local-enable bit for slot 0; with its type and length bits clear,
/// the slot breaks on executing the instruction at DR0.
const DR7_L0_EXECUTE: u64 = 1;

/// The byte offset of debug register `n` in `struct user`.
fn debugreg(n: usize) -> usize {
    core::mem::offset_of!(libc::user, u_debugreg) + n * core::mem::size_of::<u64>()
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
enum Report {
    TimerEvent,
    Exit,
}

#[derive(Debug, Default)]
struct Log {
    timer_events: AtomicU64,
    exits: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::TimerEvent => &self.timer_events,
            Report::Exit => &self.exits,
        }
        .fetch_add(1, Ordering::SeqCst);
    }
}

/// What the step hook has done, shared by its successive installations.
#[derive(Debug, Default)]
struct Probe {
    /// Steps the hook saw before the `rep stosb`.
    steps_before: u64,
    /// Where the breakpoint was armed, once it was.
    armed_at: Option<u64>,
    /// Whether the hook disarmed it, before the step after.
    disarmed: bool,
}

static PROBE: Mutex<Option<Probe>> = Mutex::new(None);

/// Installs the step hook for the timer's next single step. It reinstalls
/// itself until it has armed the breakpoint on the guest's `rep stosb` and,
/// one step later, disarmed it.
fn install_step_hook() {
    crate::task::TIMER_STEP_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|task: &Stopped| {
            let mut probe = PROBE.lock().unwrap();
            let probe = probe.as_mut().expect("probe set up");
            if probe.armed_at.is_some() {
                task.pokeuser(debugreg(7), 0).expect("clear DR7");
                probe.disarmed = true;
                return;
            }
            let rip = task.getregs().expect("registers").rip;
            if read_code(task, rip) == REP_STOSB {
                task.pokeuser(debugreg(0), rip).expect("set DR0");
                task.pokeuser(debugreg(7), DR7_L0_EXECUTE).expect("set DR7");
                probe.armed_at = Some(rip);
            } else {
                probe.steps_before += 1;
            }
            install_step_hook();
        }));
    });
}

/// The two bytes of code at `rip`.
fn read_code(task: &Stopped, rip: u64) -> [u8; 2] {
    use reverie::syscalls::MemoryAccess;
    let addr = reverie::syscalls::Addr::<[u8; 2]>::from_raw(rip as usize).expect("non-null rip");
    task.read_value(addr).expect("readable code")
}

#[derive(Default)]
struct InterruptedStepTool;

#[reverie::tool]
impl Tool for InterruptedStepTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres, Sysno::exit_group, Sysno::exit]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                guest
                    .set_timer_precise(TimerSchedule::RcbsAndInstructions(
                        TIMEOUT_RCBS,
                        OFFSET_INSTRS,
                    ))
                    .unwrap();
                install_step_hook();
                Ok(0)
            }
            _ => {
                guest.send_rpc(Report::Exit).await;
                guest.tail_inject(syscall).await
            }
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(Report::TimerEvent).await;
    }
}

/// A syscall with no conditional branch around it.
#[inline(always)]
unsafe fn syscall_no_branches(no: Sysno) {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") no as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

/// `rep stosb` over `len` bytes at `dst`: each iteration leaves `rip` and the
/// branch counter as they were, but the last.
#[inline(always)]
unsafe fn rep_stosb(dst: *mut u8, len: usize) {
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rdi") dst => _,
            inout("rcx") len => _,
            in("al") 0x5au8,
            options(nostack),
        );
    }
}

/// The interrupted step past the target branch at an in-place instruction is
/// witnessed exactly once; the breakpoint's trap, which no Tool sees, is
/// disregarded, the steps resume after it, and the event is delivered once,
/// with no second witness. The guest's buffer shows the instruction ran to
/// completion.
#[test]
fn an_interrupted_in_place_step_past_the_target_is_witnessed_once() {
    crate::ret_without_perf!();
    *PROBE.lock().unwrap() = Some(Probe::default());
    let _ = reverie::take_skid_overshoot_count();
    let suppressed_before = crate::task::UNCLAIMED_SIGTRAPS_SUPPRESSED.load(Ordering::SeqCst);

    let log = check_fn_with_config::<InterruptedStepTool, _>(
        move || {
            let mut buffer = [0u8; STOSB_BYTES];
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            // The target branch comes TARGET_LEAD branches before the end
            // of these, so the offset's steps run the rest of the loop and
            // reach the `rep stosb`.
            do_branches(TIMEOUT_RCBS - 1 + TARGET_LEAD);
            unsafe { rep_stosb(buffer.as_mut_ptr(), buffer.len()) };
            assert!(
                std::hint::black_box(&buffer)
                    .iter()
                    .all(|byte| *byte == 0x5a),
                "the rep stosb did not run to completion"
            );
        },
        (),
        true,
    );

    let probe = PROBE.lock().unwrap().take().unwrap();
    assert!(
        probe.armed_at.is_some(),
        "the steps toward the event never reached the rep stosb ({} steps)",
        probe.steps_before
    );
    assert!(
        probe.disarmed,
        "the steps did not resume after the breakpoint"
    );
    assert_eq!(
        crate::task::UNCLAIMED_SIGTRAPS_SUPPRESSED.load(Ordering::SeqCst) - suppressed_before,
        1,
        "the breakpoint's trap is disregarded once, with no Tool callback (none at all means \
         the host's hardware breakpoint did not stop the single step, as on hosts where \
         watchpoints::a_hit_inside_the_timers_single_steps_is_reported_once fails)"
    );
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the event is delivered once, after the interrupted step"
    );
    assert_eq!(
        reverie::take_skid_overshoot_count(),
        1,
        "the interrupted in-place step is witnessed exactly once"
    );
    assert_eq!(log.exits.load(Ordering::SeqCst), 1);
}
