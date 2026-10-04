/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer event single-steps the guest to its target. Each step runs
//! one instruction with the trap flag (TF) set, and that TF must not reach the
//! guest. It could leak in two ways:
//!
//! - A stepped `pushf` stores flags with TF=1 although the guest never set it.
//!   If the guest later restores that image with `popf` while it is not being
//!   stepped, TF stays set and every instruction after it traps. LiteInst's
//!   trampolines save and restore flags exactly that way.
//! - After a stepped `popf`, Linux treats TF as the guest's own for the rest
//!   of the stepping, even though `popf` loaded flags without TF, and leaves
//!   it set when the guest resumes.
//!
//! A stepped `syscall` also saves TF in r11, which the guest reads when the
//! syscall returns. A traced syscall ends the stepping at its seccomp stop
//! instead of a SIGTRAP, and TF must not leak there either. A load of SS holds
//! the step's trap back until the next instruction has run, so one step can
//! run a `pushf` or `popf` as well.
//!
//! The fix must not take TF from a guest that sets it itself: once a stepped
//! `popf`, `iret` or `rt_sigreturn` loads TF, the steps after it leave it
//! alone. `rt_sigreturn` also restores r11 from the signal frame, which the
//! fix must leave as the frame has it.
//!
//! Reverie resumes the guest after each SIGTRAP it cannot attribute, so the
//! extra traps a leaked TF causes do not kill the guest, which sees the leak
//! only by reading its flags. The `pushf` and `popf` guests run their loops
//! across the timer's target and push their flags in every round; the `pushf`
//! guest's loop stores them with a stepped `pushf`, and the `popf` guest's
//! loop reads them after a `popf` of flags without TF. The other guests run
//! the instruction under test once, before the target or just past it, and
//! then push their flags.

#![cfg(target_arch = "x86_64")]

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
use reverie_ptrace::ret_without_perf;
use reverie_ptrace::testing::check_fn_with_config;
use serde::Deserialize;
use serde::Serialize;
use test_case::test_case;

/// The x86 trap flag in RFLAGS.
const TRAP_FLAG: u64 = 0x100;

/// Flags without TF for the guest to load: IF and the reserved bit 1.
const CLEAN_FLAGS: u64 = 0x202;

/// The x86 resume flag in RFLAGS, which the processor sets in the flags it
/// saves for a fault.
const RESUME_FLAG: u64 = 0x10000;

/// The flags that `test` sets for a zero result: ZF and PF.
const ZERO_RESULT_FLAGS: u64 = 0x44;

/// The x86 adjust flag in RFLAGS, which `test` leaves undefined.
const ADJUST_FLAG: u64 = 0x10;

/// Far above any skid margin, so the request programs a real PMU notification.
const MANY_RCBS: u64 = 10_000;

/// Low enough that the timer is delivered with an artificial signal. The
/// stepping then starts at the syscall that requested the timer, so every
/// instruction from there to the target is stepped, however late the
/// processor would have raised a PMU signal.
const LESS_RCBS: u64 = 15;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct Schedule {
    rcbs: u64,
    /// Instructions past the target branch, if any.
    instructions: Option<u64>,
}

/// What the Tool tells the global state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum Note {
    TimerEvent,
    /// The Tool intercepted the sleep of the restart test.
    Sleep,
}

#[derive(Debug, Default)]
struct Log {
    timer_events: AtomicU64,
    sleeps: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Note;
    type Response = ();
    type Config = Schedule;

    async fn receive_rpc(&self, _from: Pid, note: Note) {
        match note {
            Note::TimerEvent => &self.timer_events,
            Note::Sleep => &self.sleeps,
        }
        .fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = Log;
    /// Whether the Tool requested the timer at a `pselect6`.
    type ThreadState = bool;

    fn subscriptions(_cfg: &Schedule) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([
            Sysno::clock_getres,
            Sysno::getppid,
            Sysno::clock_nanosleep,
            Sysno::pselect6,
        ]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                guest.set_timer_precise(schedule(guest.config())).unwrap();
                Ok(0)
            }
            // The timer's artificial signal is sent before the syscall runs,
            // and interrupts it.
            Sysno::clock_nanosleep
                if syscall.into_parts().1.arg0 == libc::CLOCK_BOOTTIME as usize =>
            {
                guest.send_rpc(Note::Sleep).await;
                guest.set_timer_precise(schedule(guest.config())).unwrap();
                guest.tail_inject(syscall).await
            }
            // The timer only once: Linux restarts the interrupted `pselect6`
            // as a new `pselect6`, which comes back here.
            Sysno::pselect6 if syscall.into_parts().1.arg0 == 0 => {
                guest.send_rpc(Note::Sleep).await;
                if !*guest.thread_state() {
                    *guest.thread_state_mut() = true;
                    guest.set_timer_precise(schedule(guest.config())).unwrap();
                }
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        guest.send_rpc(Note::TimerEvent).await;
    }
}

fn schedule(config: &Schedule) -> TimerSchedule {
    match config.instructions {
        None => TimerSchedule::Rcbs(config.rcbs),
        Some(instructions) => TimerSchedule::RcbsAndInstructions(config.rcbs, instructions),
    }
}

/// A syscall with no conditional branch between its caller and the kernel
/// entry, so the guest's branch count at the stop is exact.
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

/// Runs `iterations` rounds of `pushfq` and `popfq`, one conditional branch
/// each, and returns the OR of every flags image the guest pushed.
#[inline(always)]
fn pushf_loop(iterations: u64) -> u64 {
    let mut pushed: u64 = 0;
    unsafe {
        core::arch::asm!(
            "2:",
            "pushfq",
            "pop {image}",
            "or {pushed}, {image}",
            "pushfq",
            "popfq",
            "dec {n}",
            "jnz 2b",
            n = inout(reg) iterations => _,
            pushed = inout(reg) pushed,
            image = out(reg) _,
        );
    }
    pushed
}

/// Runs `iterations` rounds of `popfq` with flags that do not set TF, one
/// conditional branch each, and returns the OR of the flags after every
/// `popfq`.
#[inline(always)]
fn popf_loop(iterations: u64) -> u64 {
    let mut flags: u64 = 0;
    unsafe {
        core::arch::asm!(
            "2:",
            "push {image}",
            "popfq",
            "pushfq",
            "pop {loaded}",
            "or {flags}, {loaded}",
            "dec {n}",
            "jnz 2b",
            n = inout(reg) iterations => _,
            image = in(reg) CLEAN_FLAGS,
            flags = inout(reg) flags,
            loaded = out(reg) _,
        );
    }
    flags
}

// The loop runs twice as many branches as the timer's target, so the target
// and every step before it fall inside the loop. The loop body has seven
// instructions, so the instruction offsets 1 to 7 end the steps on each of
// them, including each `pushfq`.
#[test_case(MANY_RCBS, None; "perf signal")]
#[test_case(LESS_RCBS, None; "artificial signal")]
#[test_case(MANY_RCBS, Some(1); "one instruction past the target")]
#[test_case(MANY_RCBS, Some(2); "two instructions past the target")]
#[test_case(MANY_RCBS, Some(3); "three instructions past the target")]
#[test_case(MANY_RCBS, Some(4); "four instructions past the target")]
#[test_case(MANY_RCBS, Some(5); "five instructions past the target")]
#[test_case(MANY_RCBS, Some(6); "six instructions past the target")]
#[test_case(MANY_RCBS, Some(7); "seven instructions past the target")]
fn stepped_pushf_does_not_leak_the_trap_flag(rcbs: u64, instructions: Option<u64>) {
    ret_without_perf!();
    let iterations = 2 * rcbs;

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            let pushed = pushf_loop(iterations);
            assert_eq!(
                pushed & TRAP_FLAG,
                0,
                "pushf stored flags with TF set: {pushed:#x}"
            );
        },
        Schedule { rcbs, instructions },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

// The loop body has seven instructions; offsets 1 to 7 end the steps on each.
#[test_case(MANY_RCBS, None; "perf signal")]
#[test_case(LESS_RCBS, None; "artificial signal")]
#[test_case(MANY_RCBS, Some(1); "one instruction past the target")]
#[test_case(MANY_RCBS, Some(2); "two instructions past the target")]
#[test_case(MANY_RCBS, Some(3); "three instructions past the target")]
#[test_case(MANY_RCBS, Some(4); "four instructions past the target")]
#[test_case(MANY_RCBS, Some(5); "five instructions past the target")]
#[test_case(MANY_RCBS, Some(6); "six instructions past the target")]
#[test_case(MANY_RCBS, Some(7); "seven instructions past the target")]
fn stepped_popf_does_not_leak_the_trap_flag(rcbs: u64, instructions: Option<u64>) {
    ret_without_perf!();
    let iterations = 2 * rcbs;

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            unsafe { syscall_no_branches(Sysno::clock_getres) };
            let flags = popf_loop(iterations);
            assert_eq!(
                flags & TRAP_FLAG,
                0,
                "popf loaded flags with TF set: {flags:#x}"
            );
        },
        Schedule { rcbs, instructions },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, then runs
/// `iterations` rounds of a loop with one conditional branch each, so the
/// last round's `jnz` is the timer's target. After the loop the guest sets
/// TF itself with `popfq`, pushes its flags, and clears TF again. Returns the
/// flags it pushed. There is no conditional branch between the syscall and
/// the loop, so the target is exact.
#[inline(always)]
fn own_trap_flag_after_loop(iterations: u64) -> u64 {
    let pushed: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "2:",
            "dec {n}",
            "jnz 2b",
            "push {own}",
            "popfq",
            "pushfq",
            "pop {pushed}",
            "push {clean}",
            "popfq",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            // Not lateout: the syscall clobbers them before the inputs below
            // are read.
            out("rcx") _,
            out("r11") _,
            n = inout(reg) iterations => _,
            own = in(reg) CLEAN_FLAGS | TRAP_FLAG,
            clean = in(reg) CLEAN_FLAGS,
            pushed = out(reg) pushed,
        );
    }
    pushed
}

// The guest's own TF must survive the stepping. The steps end at the target
// or 1 to 8 instructions past it: offset 2 steps the `popfq` that sets TF,
// and offsets 3 to 8 step the `pushfq` after it as well. While its own TF is
// set the guest takes SIGTRAPs, which Reverie does not deliver.
//
// The artificial signal starts the stepping at the `clock_getres` return,
// before the guest sets TF. A PMU signal that Linux raises more than the skid
// margin late would arrive after the guest had set TF; the SIGTRAP stop of the
// guest's own TF would then reach Reverie first and cancel the timer, which
// loses the event. That loss is older than this test and is not what it
// checks.
#[test_case(None; "at the target")]
#[test_case(Some(1); "one instruction past the target")]
#[test_case(Some(2); "two instructions past the target")]
#[test_case(Some(3); "three instructions past the target")]
#[test_case(Some(4); "four instructions past the target")]
#[test_case(Some(5); "five instructions past the target")]
#[test_case(Some(6); "six instructions past the target")]
#[test_case(Some(7); "seven instructions past the target")]
#[test_case(Some(8); "eight instructions past the target")]
fn stepping_keeps_the_guests_own_trap_flag(instructions: Option<u64>) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let pushed = own_trap_flag_after_loop(LESS_RCBS);
            assert_eq!(
                pushed & TRAP_FLAG,
                TRAP_FLAG,
                "the guest set TF but pushf stored {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire at the end of the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, runs
/// `iterations` rounds of a loop with one conditional branch each, loads flags
/// without TF with `popfq`, and makes a syscall with the number `no` in rax.
/// Then it runs `after` more rounds and pushes its flags. Returns the flags it
/// pushed and the value the kernel left in r11, which the `syscall`
/// instruction loads with RFLAGS.
#[inline(always)]
fn syscall_after_popf(iterations: u64, no: u64, after: u64) -> (u64, u64) {
    let pushed: u64;
    let r11: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "2:",
            "dec {n}",
            "jnz 2b",
            "push {clean}",
            "popfq",
            "mov rax, {no}",
            "syscall",
            "mov {r11}, r11",
            "3:",
            "dec {after}",
            "jnz 3b",
            "pushfq",
            "pop {pushed}",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) iterations => _,
            after = inout(reg) after => _,
            no = in(reg) no,
            clean = in(reg) CLEAN_FLAGS,
            r11 = out(reg) r11,
            pushed = out(reg) pushed,
        );
    }
    (pushed, r11)
}

// The steps run the `popfq` and then the syscall, a few branches before the
// target. `getppid` is traced, so its seccomp stop ends the stepping before
// the target. With the artificial signal the stepping starts at the
// `clock_getres` return, so the seccomp stop always ends a step.
//
// No timer event is expected. Reverie cancels a timer at any event it
// delivers to the Tool before the timer's, as `set_timer_precise` and
// `EventStatus` document, and the seccomp stop comes before the target: the
// `syscall` is a few branches short of it, the stop comes before the
// `syscall` completes, and the counter counts no branch in the kernel. With
// the perf signal, an interrupt late by nearly the whole skid margin comes
// after the seccomp stop, so no step runs; that stop still came first and
// cancels the timer. The review of
// https://github.com/rrnewton/reverie/pull/654 called this a loss of the
// event; it is not one, since the target was never reached. A stop after the
// target is reached does lose the event
// (https://github.com/rrnewton/reverie/issues/658), which this test does not
// build.
#[test_case(MANY_RCBS; "perf signal")]
#[test_case(LESS_RCBS; "artificial signal")]
fn stepping_that_ends_at_a_syscall_stop_does_not_leak_the_trap_flag(rcbs: u64) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let (pushed, r11) = syscall_after_popf(rcbs - 4, Sysno::getppid as u64, 8);
            assert_eq!(
                pushed & TRAP_FLAG,
                0,
                "pushf stored flags with TF set: {pushed:#x}"
            );
            assert_eq!(r11 & TRAP_FLAG, 0, "the syscall saved TF in r11: {r11:#x}");
        },
        Schedule {
            rcbs,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the syscall's stop must end the stepping before the target"
    );
}

/// `getpid` with bits set above the low 32, which Linux ignores when it reads
/// the syscall number. orig_rax keeps them, so it is negative.
const GETPID_WITH_HIGH_BITS: u64 = 0xffff_ffff_0000_0000 | Sysno::getpid as u64;

// The steps run the `popfq` and an untraced syscall, and the target is in the
// loop after it. rax = -1 is no syscall, and Linux fails it with ENOSYS; like
// the high bits above, it leaves orig_rax negative.
#[test_case(MANY_RCBS, Sysno::getpid as u64; "getpid, perf signal")]
#[test_case(LESS_RCBS, Sysno::getpid as u64; "getpid, artificial signal")]
#[test_case(MANY_RCBS, GETPID_WITH_HIGH_BITS; "getpid with high bits, perf signal")]
#[test_case(LESS_RCBS, GETPID_WITH_HIGH_BITS; "getpid with high bits, artificial signal")]
#[test_case(MANY_RCBS, u64::MAX; "invalid number, perf signal")]
#[test_case(LESS_RCBS, u64::MAX; "invalid number, artificial signal")]
fn stepped_syscall_does_not_leak_the_trap_flag(rcbs: u64, no: u64) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let (pushed, r11) = syscall_after_popf(rcbs - 4, no, 8);
            assert_eq!(
                pushed & TRAP_FLAG,
                0,
                "pushf stored flags with TF set: {pushed:#x}"
            );
            assert_eq!(r11 & TRAP_FLAG, 0, "the syscall saved TF in r11: {r11:#x}");
        },
        Schedule {
            rcbs,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire in the loop after the syscall"
    );
}

/// A sleep at which the Tool requests the timer, and the error with which it
/// asks to be restarted when a signal interrupts it.
#[derive(Clone, Copy, Debug)]
enum Sleep {
    /// A relative `clock_nanosleep` of CLOCK_BOOTTIME: ERESTART_RESTARTBLOCK,
    /// which Linux restarts as `restart_syscall`.
    ClockNanosleep,
    /// A `pselect6` of no descriptors: ERESTARTNOHAND, which Linux restarts
    /// with the same syscall number.
    Pselect6,
}

/// Sleeps for a millisecond with `sleep`, and then runs `after` rounds of a
/// loop with one conditional branch each. Returns what the syscall returned
/// and the value the kernel left in r11.
#[inline(always)]
fn interrupted_sleep_before_loop(sleep: Sleep, after: u64) -> (i64, u64) {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    let time = &mut time as *mut libc::timespec as u64;
    let [no, arg0, arg2, arg4] = match sleep {
        Sleep::ClockNanosleep => [
            Sysno::clock_nanosleep as u64,
            libc::CLOCK_BOOTTIME as u64,
            time,
            0,
        ],
        Sleep::Pselect6 => [Sysno::pselect6 as u64, 0, 0, time],
    };
    let ret: i64;
    let r11: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov {r11}, r11",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") no as i64 => ret,
            in("rdi") arg0,
            in("rsi") 0u64,
            in("rdx") arg2,
            in("r10") 0u64,
            in("r8") arg4,
            in("r9") 0u64,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) after => _,
            r11 = out(reg) r11,
        );
    }
    (ret, r11)
}

// The timer's artificial signal interrupts the sleep, which then asks to be
// restarted, and the stepping starts at the signal's stop. The first step
// resumes the guest without a signal, so Linux runs the `syscall` again
// with TF set, and the target is in the loop after it. A rerun `pselect6`
// stops at its seccomp stop, before the target, which reaches the Tool
// (intercepted twice) and cancels the timer, as in the syscall-stop test;
// `restart_syscall` is not traced by this Tool (intercepted once), so that
// stepping reaches the target.
#[test_case(Sleep::ClockNanosleep, 1, 1; "restart block")]
#[test_case(Sleep::Pselect6, 2, 0; "same syscall")]
fn stepping_a_restarted_syscall_does_not_leak_the_trap_flag(
    sleep: Sleep,
    intercepted: u64,
    events: u64,
) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let (ret, r11) = interrupted_sleep_before_loop(sleep, 2 * LESS_RCBS);
            assert_eq!(ret, 0, "the sleep must complete");
            assert_eq!(r11 & TRAP_FLAG, 0, "the syscall saved TF in r11: {r11:#x}");
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.sleeps.load(Ordering::SeqCst),
        intercepted,
        "the Tool must see the sleep, and a restarted pselect6 again"
    );
    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        events,
        "the timer must fire inside the loop unless the rerun syscall's seccomp stop cancels it"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, pushes its
/// flags with the two-byte `pushfw`, and then runs `after` rounds of a loop
/// with one conditional branch each. Returns the flags it pushed.
#[inline(always)]
fn pushfw_before_loop(after: u64) -> u64 {
    let pushed: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "pushfw",
            "pop {pushed:x}",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) after => _,
            pushed = out(reg) pushed,
        );
    }
    pushed & 0xffff
}

// The artificial signal starts the stepping at the `clock_getres` return, so
// the `pushfw` is stepped, and the target is in the loop after it.
#[test]
fn stepped_pushfw_does_not_leak_the_trap_flag() {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let pushed = pushfw_before_loop(2 * LESS_RCBS);
            assert_eq!(
                pushed & TRAP_FLAG,
                0,
                "pushfw stored flags with TF set: {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, and then
/// loads SS with its own value just before `pushfq`. A load of SS holds the
/// debug trap back for one instruction, so a single step runs both. Then it
/// runs `after` rounds of a loop with one conditional branch each. Returns the
/// flags it pushed.
#[inline(always)]
fn mov_ss_pushf_before_loop(after: u64) -> u64 {
    let pushed: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov {ss:e}, ss",
            "mov ss, {ss:e}",
            "pushfq",
            "pop {pushed}",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) after => _,
            ss = out(reg) _,
            pushed = out(reg) pushed,
        );
    }
    pushed
}

// One step runs the load of SS and the `pushfq` after it, and the target is in
// the loop after them.
#[test]
fn stepped_pushf_after_a_load_of_ss_does_not_leak_the_trap_flag() {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let pushed = mov_ss_pushf_before_loop(2 * LESS_RCBS);
            assert_eq!(
                pushed & TRAP_FLAG,
                0,
                "pushf stored flags with TF set: {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, and then a
/// `getpid` just after two loads of SS. Of consecutive loads of SS, Intel
/// documents only the first as sure to hold the debug trap back, but an AMD
/// EPYC 9D85 runs both and the `syscall` in one step. Then it runs `after`
/// rounds of a loop with one conditional branch each. Returns what `getpid`
/// returned and the value the kernel left in r11, which the `syscall`
/// instruction loads with RFLAGS.
#[inline(always)]
fn two_mov_ss_syscall_before_loop(after: u64) -> (u64, u64) {
    let pid: u64;
    let r11: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov {ss:e}, ss",
            "mov eax, {getpid}",
            "mov ss, {ss:e}",
            "mov ss, {ss:e}",
            "syscall",
            "2:",
            "dec {n}",
            "jnz 2b",
            getpid = const libc::SYS_getpid,
            inlateout("rax") Sysno::clock_getres as usize => pid,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            lateout("r11") r11,
            n = inout(reg) after => _,
            ss = out(reg) _,
        );
    }
    (pid, r11)
}

// One step runs both loads of SS and the `getpid` after them, where the
// processor holds the trap back for both, and the target is in the loop after
// them. The step must be taken for the step of a `syscall`, whose TF in r11 is
// removed. A processor that holds the trap back only for the first load stops
// at the `syscall`, and steps it on its own.
#[test]
fn stepped_syscall_after_two_loads_of_ss_does_not_leak_the_trap_flag() {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let expected = unsafe { libc::getpid() } as u64;
            let (pid, r11) = two_mov_ss_syscall_before_loop(2 * LESS_RCBS);
            assert_eq!(pid, expected, "getpid returned {pid:#x}");
            assert_eq!(r11 & TRAP_FLAG, 0, "the syscall saved TF in r11: {r11:#x}");
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, and then
/// loads `flags` with a `popfq` just after a load of SS, so a single step runs
/// both. It pushes the flags it now has, loads flags without TF, and runs
/// `after` rounds of a loop with one conditional branch each. Returns the
/// flags it pushed.
#[inline(always)]
fn mov_ss_popf_before_loop(flags: u64, after: u64) -> u64 {
    let pushed: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "push {flags}",
            "mov {ss:e}, ss",
            "mov ss, {ss:e}",
            "popfq",
            "pushfq",
            "pop {pushed}",
            "push {clean}",
            "popfq",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) after => _,
            flags = in(reg) flags,
            clean = in(reg) CLEAN_FLAGS,
            ss = out(reg) _,
            pushed = out(reg) pushed,
        );
    }
    pushed
}

// One step runs the load of SS and the `popfq` after it. Linux looks only at
// the load of SS, and does not see that the step loads the guest's flags.
#[test_case(CLEAN_FLAGS | TRAP_FLAG; "own trap flag")]
#[test_case(CLEAN_FLAGS; "no trap flag")]
fn stepped_popf_after_a_load_of_ss_loads_the_guests_trap_flag(flags: u64) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let pushed = mov_ss_popf_before_loop(flags, 2 * LESS_RCBS);
            assert_eq!(
                pushed & TRAP_FLAG,
                flags & TRAP_FLAG,
                "the guest loaded {flags:#x} but pushf stored {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer, and then
/// loads `flags` with an `iretq` to the next instruction. If `twice` is set,
/// the `iretq` first returns to itself, with rsp at the frame it then pops.
/// It pushes the flags it now has, loads flags without TF, and runs `after`
/// rounds of a loop with one conditional branch each. Returns the flags it
/// pushed.
#[inline(always)]
fn iret_before_loop(flags: u64, twice: bool, after: u64) -> u64 {
    let pushed: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov {sp}, rsp",
            "mov {selector:e}, ss",
            "push {selector}",
            "push {sp}",
            "push {flags}",
            "mov {selector:e}, cs",
            "push {selector}",
            "lea {sp}, [rip + 3f]",
            "push {sp}",
            "test {twice}, {twice}",
            "jz 4f",
            "mov {sp}, rsp",
            "mov {selector:e}, ss",
            "push {selector}",
            "push {sp}",
            "push {flags}",
            "mov {selector:e}, cs",
            "push {selector}",
            "lea {sp}, [rip + 4f]",
            "push {sp}",
            "4:",
            "iretq",
            "3:",
            "pushfq",
            "pop {pushed}",
            "push {clean}",
            "popfq",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            n = inout(reg) after => _,
            flags = in(reg) flags,
            twice = in(reg) twice as u64,
            clean = in(reg) CLEAN_FLAGS,
            sp = out(reg) _,
            selector = out(reg) _,
            pushed = out(reg) pushed,
        );
    }
    pushed
}

// The `iretq` is stepped, and the target is in the loop after it. Like
// `popf`, `iret` loads the guest's own flags. An `iretq` that returns to
// itself is stepped twice, and the second step loads the flags again, so the
// flags the first step loads cannot be seen at the `pushfq`.
#[test_case(CLEAN_FLAGS | TRAP_FLAG, false; "own trap flag")]
#[test_case(CLEAN_FLAGS, false; "no trap flag")]
#[test_case(CLEAN_FLAGS | TRAP_FLAG, true; "own trap flag, twice")]
#[test_case(CLEAN_FLAGS, true; "no trap flag, twice")]
fn stepped_iret_loads_the_guests_trap_flag(flags: u64, twice: bool) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let pushed = iret_before_loop(flags, twice, 2 * LESS_RCBS);
            assert_eq!(
                pushed & TRAP_FLAG,
                flags & TRAP_FLAG,
                "the guest loaded {flags:#x} but pushf stored {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire inside the loop"
    );
}

/// The flags of the guest when `record_flags` last caught a signal, as the
/// signal frame holds them.
static SIGNAL_FLAGS: AtomicU64 = AtomicU64::new(0);

/// The number of the signal `record_flags` last caught.
static SIGNAL_NUMBER: AtomicU64 = AtomicU64::new(0);

/// Whether the signal `record_flags` last caught was raised at the address in
/// r14, where the guest expects the fault.
static SIGNAL_AT_R14: AtomicU64 = AtomicU64::new(0);

/// r11 when `record_flags` last caught a signal, as the signal frame holds it.
static SIGNAL_R11: AtomicU64 = AtomicU64::new(0);

/// Records the signal, where it was raised, and the flags and r11 in the
/// signal frame, clears TF in the flags, and continues at the address in r12.
extern "C" fn record_flags(
    signal: libc::c_int,
    _: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: Linux passes the context of the signal frame to a handler
    // installed with SA_SIGINFO.
    let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
    let gregs = &mut context.uc_mcontext.gregs;
    SIGNAL_NUMBER.store(signal as u64, Ordering::SeqCst);
    SIGNAL_AT_R14.store(
        (gregs[libc::REG_RIP as usize] == gregs[libc::REG_R14 as usize]) as u64,
        Ordering::SeqCst,
    );
    SIGNAL_FLAGS.store(gregs[libc::REG_EFL as usize] as u64, Ordering::SeqCst);
    SIGNAL_R11.store(gregs[libc::REG_R11 as usize] as u64, Ordering::SeqCst);
    gregs[libc::REG_EFL as usize] &= !(TRAP_FLAG as i64);
    gregs[libc::REG_RIP as usize] = gregs[libc::REG_R12 as usize];
}

/// Asserts that `record_flags` caught `signal`, raised where the guest put the
/// address in r14, and returns the flags in its frame.
fn caught(signal: libc::c_int) -> u64 {
    let number = SIGNAL_NUMBER.load(Ordering::SeqCst);
    assert_eq!(number, signal as u64, "the handler caught signal {number}");
    assert_eq!(
        SIGNAL_AT_R14.load(Ordering::SeqCst),
        1,
        "the signal was not raised by the expected instruction"
    );
    SIGNAL_FLAGS.load(Ordering::SeqCst)
}

/// Makes `record_flags` the handler of `signal`.
fn catch(signal: libc::c_int) {
    // SAFETY: an all-zero sigaction is valid, and the handler only reads and
    // writes the frame and an atomic.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = record_flags as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO;
        assert_eq!(libc::sigaction(signal, &action, core::ptr::null_mut()), 0);
    }
}

/// The instruction that follows a load of SS and faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// An `iretq` to a null code segment, which raises #GP and SIGSEGV.
    Iret,
    /// `rt_sigreturn` made with a lock prefix, which raises #UD and SIGILL
    /// before the `syscall` runs. The frame it would read has TF set.
    LockedRtSigreturn,
}

/// Makes the `clock_getres` at which the Tool requests the timer, and, if
/// `popf` is set, loads flags without TF with `popfq`. Then it loads SS, so a
/// single step runs the load and the `fault` after it, which faults. The
/// handler of the signal continues after the fault, where it runs `after`
/// rounds of a loop with one conditional branch each.
#[inline(always)]
fn fault_after_mov_ss(fault: Fault, popf: bool, after: u64) {
    catch(libc::SIGSEGV);
    catch(libc::SIGILL);
    // Where rsp points at the locked `rt_sigreturn`: its frame's flags at
    // rsp + 176, with room below for the frame of SIGILL.
    let mut stack = vec![0u64; 8192];
    let context = 6144;
    stack[context + 176 / 8] = CLEAN_FLAGS | TRAP_FLAG;
    let context = stack[context..].as_mut_ptr();
    unsafe {
        core::arch::asm!(
            "syscall",
            "test {popf}, {popf}",
            "jz 3f",
            "push {clean}",
            "popfq",
            "3:",
            "mov r13, rsp",
            "lea r12, [rip + 5f]",
            "mov {selector:e}, ss",
            "test {sigreturn}, {sigreturn}",
            "jnz 4f",
            // A frame with a null code segment.
            "push 0",
            "push 0",
            "push {clean}",
            "push 0",
            "push r12",
            "lea r14, [rip + 6f]",
            "mov ss, {selector:e}",
            "6:",
            "iretq",
            "4:",
            "mov rsp, {context}",
            "mov eax, {rt_sigreturn}",
            "lea r14, [rip + 7f]",
            "mov ss, {selector:e}",
            "7:",
            ".byte 0xf0, 0x0f, 0x05",
            "5:",
            "mov rsp, r13",
            "2:",
            "dec {n}",
            "jnz 2b",
            rt_sigreturn = const libc::SYS_rt_sigreturn,
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            n = inout(reg) after => _,
            popf = in(reg) popf as u64,
            sigreturn = in(reg) (fault == Fault::LockedRtSigreturn) as u64,
            context = in(reg) context,
            clean = in(reg) CLEAN_FLAGS,
            selector = out(reg) _,
        );
    }
}

// One step runs the load of SS and the instruction after it, which faults
// without returning. The signal frame must hold the flags the guest had, and
// the guest had no TF. Without a stepped `popfq` before, Linux hides the
// stepping TF and clears it itself before it builds the frame; after one, it
// sees the TF as the guest's. Beyond TF, the frame must hold the flags the
// guest had untraced, except AF, which `test` leaves undefined. The signal
// stop comes before the target, since the fault comes 2 branches after the
// `clock_getres`, 13 short of the target, and the stop comes before the
// faulting instruction completes. It cancels the timer, as for the syscall
// stop above.
#[test_case(Fault::Iret, false; "iret")]
#[test_case(Fault::Iret, true; "iret after popf")]
#[test_case(Fault::LockedRtSigreturn, false; "locked rt_sigreturn")]
#[test_case(Fault::LockedRtSigreturn, true; "locked rt_sigreturn after popf")]
fn fault_after_a_load_of_ss_does_not_leak_the_trap_flag(fault: Fault, popf: bool) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            fault_after_mov_ss(fault, popf, 2 * LESS_RCBS);
            let flags = SIGNAL_FLAGS.load(Ordering::SeqCst);
            assert_ne!(flags, 0, "the fault did not reach the handler");
            caught(match fault {
                Fault::Iret => libc::SIGSEGV,
                Fault::LockedRtSigreturn => libc::SIGILL,
            });
            assert_eq!(
                flags & TRAP_FLAG,
                0,
                "the signal frame held the flags {flags:#x}"
            );
            // The `test` of `sigreturn` last wrote the arithmetic flags: ZF
            // and PF for the iret (0), neither for the rt_sigreturn (1).
            let expected = match fault {
                Fault::Iret => CLEAN_FLAGS | ZERO_RESULT_FLAGS | RESUME_FLAG,
                Fault::LockedRtSigreturn => CLEAN_FLAGS | RESUME_FLAG,
            };
            assert_eq!(
                flags & !ADJUST_FLAG,
                expected,
                "the guest had {expected:#x}, so the frame of the fault must hold it"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the signal stop cancels the timer"
    );
}

/// Makes the `clock_getres` at which the Tool requests the timer. Then an
/// `iretq` loads `flags` and returns to itself, with rsp at a second frame
/// that has a null code segment, so the second `iretq` raises #GP. The handler
/// of SIGSEGV continues after it, where the guest runs `after` rounds of a
/// loop with one conditional branch each.
#[inline(always)]
fn iret_to_itself_then_fault(flags: u64, after: u64) {
    catch(libc::SIGSEGV);
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov r13, rsp",
            "lea r12, [rip + 5f]",
            "lea r14, [rip + 4f]",
            // The second frame, with a null code segment.
            "push 0",
            "push 0",
            "push {clean}",
            "push 0",
            "push r12",
            "mov {sp}, rsp",
            // The first frame, which returns to the `iretq` with rsp at the
            // second frame.
            "mov {selector:e}, ss",
            "push {selector}",
            "push {sp}",
            "push {flags}",
            "mov {selector:e}, cs",
            "push {selector}",
            "push r14",
            "4:",
            "iretq",
            "5:",
            "mov rsp, r13",
            "2:",
            "dec {n}",
            "jnz 2b",
            inlateout("rax") Sysno::clock_getres as usize => _,
            in("rdi") 0usize,
            in("rsi") 0usize,
            out("rcx") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            n = inout(reg) after => _,
            flags = in(reg) flags,
            clean = in(reg) CLEAN_FLAGS,
            sp = out(reg) _,
            selector = out(reg) _,
        );
    }
}

// The first step runs the `iretq`, which returns to itself: rip is where the
// step started, and only rsp shows that it ran. The second step raises #GP at
// the same `iretq`. Untraced, the fault comes before the trap of any TF the
// first `iretq` loaded, so the SIGSEGV frame holds exactly the flags the first
// frame loaded, with RF, which the processor sets for a fault. If the first
// step were judged not run, its TF would be taken for the stepping TF and
// cleared. The signal stop comes before the target and cancels the timer, as
// for the faults above.
#[test_case(CLEAN_FLAGS | TRAP_FLAG; "own trap flag")]
#[test_case(CLEAN_FLAGS; "no trap flag")]
fn iret_that_returns_to_itself_keeps_the_flags_it_loaded(flags: u64) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            iret_to_itself_then_fault(flags, 2 * LESS_RCBS);
            let frame = caught(libc::SIGSEGV);
            assert_eq!(
                frame & TRAP_FLAG,
                flags & TRAP_FLAG,
                "the guest loaded {flags:#x} but the signal frame held {frame:#x}"
            );
            assert_eq!(
                frame,
                flags | RESUME_FLAG,
                "the guest loaded {flags:#x}, so the frame of the fault must hold it with RF"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the signal stop cancels the timer"
    );
}

/// A signal frame as Linux builds it on the stack for a handler, which
/// `rt_sigreturn` reads back: the handler's return address, which its `ret`
/// pops, and then the context to restore.
#[repr(C)]
struct SignalFrame {
    return_address: u64,
    context: libc::ucontext_t,
    info: libc::siginfo_t,
}

/// Where the frame holds the general register `reg`.
const fn frame_register(reg: libc::c_int) -> usize {
    core::mem::offset_of!(SignalFrame, context)
        + core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
        + core::mem::offset_of!(libc::mcontext_t, gregs)
        + reg as usize * core::mem::size_of::<libc::greg_t>()
}

/// The value the signal frame restores to r11. It has bit 8, where `syscall`
/// saves TF, set.
const R11_MARKER: u64 = 0xfeed_0346;

/// Where the signal frame of `rt_sigreturn_after_loop` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Return {
    /// To the next instruction.
    Next,
    /// To the `syscall` of `rt_sigreturn` itself, with the number of `getpid`
    /// in rax, so the `syscall` runs again as `getpid`.
    Again,
    /// As `Again`, and with rsp as it is at `rt_sigreturn`, so only rax tells
    /// that `rt_sigreturn` ran.
    AgainOnTheSameStack,
}

/// Makes the `clock_getres` at which the Tool requests the timer, runs
/// `iterations` rounds of a loop with one conditional branch each, and, if
/// `popf` is set, loads flags without TF with `popfq`. Then it makes
/// `rt_sigreturn` with a signal frame that restores `flags`, r11 and its other
/// registers, and returns as `ret` says. It stores r11 and pushes its flags,
/// loads flags without TF, and runs `after` rounds of the loop. Returns the
/// value of r11 and the flags it pushed.
///
/// The frame keeps the alternate signal stack and the blocked signals as they
/// are. It has no floating-point state, so Linux resets it.
#[inline(always)]
fn rt_sigreturn_after_loop(
    iterations: u64,
    popf: bool,
    flags: u64,
    ret: Return,
    after: u64,
) -> [u64; 2] {
    let mut saved = [0u64; 2];
    // SAFETY: all zeros is a valid value for these C structures.
    let mut frame: SignalFrame = unsafe { core::mem::zeroed() };
    let context = &mut frame.context;
    // SAFETY: both only store into the structures they are given.
    unsafe {
        assert_eq!(
            libc::sigaltstack(core::ptr::null(), &mut context.uc_stack),
            0
        );
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &mut context.uc_sigmask),
            0
        );
    }
    let (cs, ss): (u64, u64);
    // SAFETY: reads the segment selectors.
    unsafe {
        core::arch::asm!(
            "mov {cs:e}, cs",
            "mov {ss:e}, ss",
            cs = out(reg) cs,
            ss = out(reg) ss,
            options(nomem, nostack, preserves_flags),
        );
    }
    let gregs = &mut context.uc_mcontext.gregs;
    gregs[libc::REG_EFL as usize] = flags as i64;
    // cs is the low 16 bits, and ss the high 16.
    gregs[libc::REG_CSGSFS as usize] = (cs | ss << 48) as i64;
    gregs[libc::REG_R11 as usize] = R11_MARKER as i64;
    gregs[libc::REG_R13 as usize] = saved.as_mut_ptr() as i64;
    gregs[libc::REG_R14 as usize] = after as i64;
    if ret != Return::Next {
        gregs[libc::REG_RAX as usize] = libc::SYS_getpid;
    }
    if ret == Return::AgainOnTheSameStack {
        let context = core::ptr::addr_of!(frame.context);
        frame.context.uc_mcontext.gregs[libc::REG_RSP as usize] = context as i64;
    }
    // SAFETY: the frame restores rbx and rbp as they are at the
    // `rt_sigreturn`, and r15 to the rsp there, which is restored from it.
    // Every register the frame changes is marked clobbered.
    unsafe {
        core::arch::asm!(
            "syscall",
            "2:",
            "dec r8",
            "jnz 2b",
            "test r9, r9",
            "jz 3f",
            "push r10",
            "popfq",
            "3:",
            "mov [r12 + {rbx}], rbx",
            "mov [r12 + {rbp}], rbp",
            "mov [r12 + {r15}], rsp",
            // rsp and rip as `ret` says; the frame holds rsp already if it
            // is the stack of `rt_sigreturn`.
            "mov rax, [r12 + {rsp}]",
            "test rax, rax",
            "cmovz rax, rsp",
            "mov [r12 + {rsp}], rax",
            "lea rax, [rip + 4f]",
            "lea rdx, [rip + 6f]",
            "test r15, r15",
            "cmovnz rax, rdx",
            "mov [r12 + {rip}], rax",
            "lea rsp, [r12 + {context}]",
            "mov eax, {rt_sigreturn}",
            "6:",
            "syscall",
            "4:",
            "mov rsp, r15",
            "mov [r13], r11",
            "pushfq",
            "pop qword ptr [r13 + 8]",
            "push {clean}",
            "popfq",
            "5:",
            "dec r14",
            "jnz 5b",
            rbx = const frame_register(libc::REG_RBX),
            rbp = const frame_register(libc::REG_RBP),
            rsp = const frame_register(libc::REG_RSP),
            r15 = const frame_register(libc::REG_R15),
            rip = const frame_register(libc::REG_RIP),
            context = const core::mem::offset_of!(SignalFrame, context),
            rt_sigreturn = const libc::SYS_rt_sigreturn,
            clean = const CLEAN_FLAGS,
            inlateout("rax") Sysno::clock_getres as usize => _,
            inlateout("rdi") 0usize => _,
            inlateout("rsi") 0usize => _,
            out("rcx") _,
            out("rdx") _,
            inout("r8") iterations => _,
            inout("r9") popf as u64 => _,
            inout("r10") CLEAN_FLAGS => _,
            out("r11") _,
            inout("r12") &mut frame as *mut SignalFrame => _,
            inout("r13") saved.as_mut_ptr() => _,
            inout("r14") after => _,
            inout("r15") (ret != Return::Next) as u64 => _,
            clobber_abi("C"),
        );
    }
    saved
}

// The steps run the loop, the `popfq` if there is one, and `rt_sigreturn`,
// and the target is in the loop after it. `rt_sigreturn` restores r11 and
// RFLAGS from the frame. TF in the frame is the guest's own, and a TF-like
// bit in r11 is only the frame's value. Where the frame returns to the
// `syscall`, the steps run it again as `getpid`, which saves the guest's
// flags, with its own TF, in r11. Linux hides a TF that `rt_sigreturn` loads
// unless a stepped `popfq` came before it.
#[test_case(false, CLEAN_FLAGS | TRAP_FLAG, Return::Next; "own trap flag")]
#[test_case(false, CLEAN_FLAGS, Return::Next; "no trap flag")]
#[test_case(true, CLEAN_FLAGS | TRAP_FLAG, Return::Next; "own trap flag after popf")]
#[test_case(true, CLEAN_FLAGS, Return::Next; "no trap flag after popf")]
#[test_case(false, CLEAN_FLAGS | TRAP_FLAG, Return::Again; "own trap flag, again")]
#[test_case(false, CLEAN_FLAGS, Return::Again; "no trap flag, again")]
#[test_case(true, CLEAN_FLAGS | TRAP_FLAG, Return::Again; "own trap flag after popf, again")]
#[test_case(true, CLEAN_FLAGS, Return::Again; "no trap flag after popf, again")]
#[test_case(false, CLEAN_FLAGS | TRAP_FLAG, Return::AgainOnTheSameStack; "own trap flag, again on the same stack")]
#[test_case(true, CLEAN_FLAGS | TRAP_FLAG, Return::AgainOnTheSameStack; "own trap flag after popf, again on the same stack")]
fn stepped_rt_sigreturn_restores_the_frames_flags(popf: bool, flags: u64, ret: Return) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            let [r11, pushed] = rt_sigreturn_after_loop(4, popf, flags, ret, 2 * LESS_RCBS);
            if ret == Return::Next {
                assert_eq!(
                    r11, R11_MARKER,
                    "rt_sigreturn restored r11 as {r11:#x}, not the frame's"
                );
            } else {
                assert_eq!(
                    r11 & TRAP_FLAG,
                    flags & TRAP_FLAG,
                    "the frame held {flags:#x} but getpid saved {r11:#x} in r11"
                );
            }
            assert_eq!(
                pushed & TRAP_FLAG,
                flags & TRAP_FLAG,
                "the frame held {flags:#x} but pushf stored {pushed:#x}"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        1,
        "the timer must fire in the loop after rt_sigreturn"
    );
}

/// Makes `record_flags` the handler of `signal`, run on an alternate signal
/// stack, which this sets up.
fn catch_on_an_alternate_stack(signal: libc::c_int) {
    let size = 64 * 1024;
    let stack = libc::stack_t {
        ss_sp: Box::leak(vec![0u8; size].into_boxed_slice())
            .as_mut_ptr()
            .cast(),
        ss_flags: 0,
        ss_size: size,
    };
    // SAFETY: the stack is leaked, so it outlives the thread, and the handler
    // only reads and writes the frame and atomics.
    unsafe {
        assert_eq!(libc::sigaltstack(&stack, core::ptr::null_mut()), 0);
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = record_flags as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        assert_eq!(libc::sigaction(signal, &action, core::ptr::null_mut()), 0);
    }
}

/// Makes the `clock_getres` at which the Tool requests the timer. Then
/// `rt_sigreturn` restores `flags` from a frame that returns to its own
/// `syscall`, with the number of `rt_sigreturn` in rax and rsp one word into
/// a page that cannot be read. The rerun `rt_sigreturn` fails at its first
/// read of the frame, so Linux restores no register from it, returns 0 in rax
/// and forces SIGSEGV; the `syscall` itself still sets rcx and r11. The
/// handler runs on an alternate stack and continues after the `syscall`,
/// where the guest runs `after` rounds of a loop with one conditional branch
/// each.
#[inline(always)]
fn rt_sigreturn_to_itself_then_fault(flags: u64, after: u64) {
    // SAFETY: maps a fresh page, which nothing else uses.
    let unreadable = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(unreadable, libc::MAP_FAILED);
    catch_on_an_alternate_stack(libc::SIGSEGV);
    // SAFETY: all zeros is a valid value for these C structures.
    let mut frame: SignalFrame = unsafe { core::mem::zeroed() };
    let context = &mut frame.context;
    // SAFETY: both only store into the structures they are given.
    unsafe {
        assert_eq!(
            libc::sigaltstack(core::ptr::null(), &mut context.uc_stack),
            0
        );
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &mut context.uc_sigmask),
            0
        );
    }
    let (cs, ss): (u64, u64);
    // SAFETY: reads the segment selectors.
    unsafe {
        core::arch::asm!(
            "mov {cs:e}, cs",
            "mov {ss:e}, ss",
            cs = out(reg) cs,
            ss = out(reg) ss,
            options(nomem, nostack, preserves_flags),
        );
    }
    let gregs = &mut context.uc_mcontext.gregs;
    gregs[libc::REG_EFL as usize] = flags as i64;
    // cs is the low 16 bits, and ss the high 16.
    gregs[libc::REG_CSGSFS as usize] = (cs | ss << 48) as i64;
    gregs[libc::REG_RAX as usize] = libc::SYS_rt_sigreturn;
    // The rerun `rt_sigreturn` reads its frame one word below rsp.
    gregs[libc::REG_RSP as usize] = unreadable as i64 + 8;
    gregs[libc::REG_R15 as usize] = after as i64;
    // SAFETY: the frame restores rbx and rbp as they are at the
    // `rt_sigreturn`, and r13 to the rsp before the guest moves it to the
    // frame, which the guest restores from r13 after the handler. The handler
    // continues at the address in r12 with the registers as the frame restored
    // them. Every register the frame changes is marked clobbered.
    unsafe {
        core::arch::asm!(
            "syscall",
            "mov [r12 + {rbx}], rbx",
            "mov [r12 + {rbp}], rbp",
            "mov [r12 + {r13}], rsp",
            "lea rax, [rip + 5f]",
            "mov [r12 + {r12}], rax",
            // Where the SIGSEGV is raised, just past the `syscall`.
            "lea rax, [rip + 4f]",
            "mov [r12 + {r14}], rax",
            "lea rax, [rip + 6f]",
            "mov [r12 + {rip}], rax",
            "lea rsp, [r12 + {context}]",
            "mov eax, {rt_sigreturn}",
            "6:",
            "syscall",
            "4:",
            "ud2",
            "5:",
            "mov rsp, r13",
            "2:",
            "dec r15",
            "jnz 2b",
            rbx = const frame_register(libc::REG_RBX),
            rbp = const frame_register(libc::REG_RBP),
            r12 = const frame_register(libc::REG_R12),
            r13 = const frame_register(libc::REG_R13),
            r14 = const frame_register(libc::REG_R14),
            rip = const frame_register(libc::REG_RIP),
            context = const core::mem::offset_of!(SignalFrame, context),
            rt_sigreturn = const libc::SYS_rt_sigreturn,
            inlateout("rax") Sysno::clock_getres as usize => _,
            inlateout("rdi") 0usize => _,
            inlateout("rsi") 0usize => _,
            out("rcx") _,
            out("r11") _,
            inout("r12") &mut frame as *mut SignalFrame => _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            clobber_abi("C"),
        );
    }
}

// The first step runs `rt_sigreturn`, which returns to its own `syscall` with
// its own number in rax: rip and rax are as they were when the step started,
// and only rsp shows that it ran. The second step runs `rt_sigreturn` again,
// which cannot read its frame and forces SIGSEGV. Untraced, the SIGSEGV frame
// holds exactly the flags the first frame restored, and in r11 the same flags,
// which the rerun `syscall` saved. If the first step were judged not run,
// Linux would keep hiding the TF it restored as its own, and clear it before
// building the SIGSEGV frame. The signal stop comes before the target and
// cancels the timer, as for the faults above.
#[test_case(CLEAN_FLAGS | TRAP_FLAG; "own trap flag")]
#[test_case(CLEAN_FLAGS; "no trap flag")]
fn rt_sigreturn_that_returns_to_itself_keeps_the_flags_it_restored(flags: u64) {
    ret_without_perf!();

    let log = check_fn_with_config::<PreciseTimerTool, _>(
        move || {
            rt_sigreturn_to_itself_then_fault(flags, 2 * LESS_RCBS);
            let frame = caught(libc::SIGSEGV);
            assert_eq!(
                frame & TRAP_FLAG,
                flags & TRAP_FLAG,
                "the frame restored {flags:#x} but the SIGSEGV frame held {frame:#x}"
            );
            assert_eq!(
                frame, flags,
                "the frame restored {flags:#x} but the SIGSEGV frame held {frame:#x}"
            );
            let r11 = SIGNAL_R11.load(Ordering::SeqCst);
            assert_eq!(
                r11, flags,
                "the rerun `syscall` saved {r11:#x} in r11, not the {flags:#x} it ran with"
            );
        },
        Schedule {
            rcbs: LESS_RCBS,
            instructions: None,
        },
        true,
    );

    assert_eq!(
        log.timer_events.load(Ordering::SeqCst),
        0,
        "the signal stop cancels the timer"
    );
}
