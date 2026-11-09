/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest's SIGTRAP action and mask survive the single-steps of a precise
//! timer, for a Tool that enforces serialized execution (`sigtrap_state`).
//! Linux reports each single-step with a forced SIGTRAP, which resets a
//! blocked or ignored SIGTRAP to `SIG_DFL` and unblocks it; Reverie keeps the
//! guest's own state across those steps on every architecture it supports.
//!
//! For each state the guest makes a `getpid`, at which the Tool arms a precise
//! timer a few thousand branches out, then branches past it and reads back
//! SIGTRAP's action and its mask bit with `rt_sigaction` and
//! `rt_sigprocmask`, which the Tool sees, so a repair the steps left owed is
//! made at those calls' seccomp stops.

use std::io::Write;
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

/// Timer events delivered to `SteppingTool`, across every run in this
/// process.
static TIMER_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Timer events delivered to `SigreturnSteppingTool`.
static SIGRETURN_TIMER_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Timers armed from the guest's SIGUSR1 handler, across every run.
static HANDLER_ARMINGS: AtomicU64 = AtomicU64::new(0);

/// Arms a precise timer at each `getpid` and passes every syscall on.
#[derive(Debug, Default, Clone)]
struct SteppingTool;

#[reverie::tool]
impl Tool for SteppingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all_syscalls()
    }

    fn enforces_serialized_execution(_config: &()) -> bool {
        true
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            guest.set_timer_precise(TimerSchedule::Rcbs(4000))?;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, _guest: &mut G) {
        TIMER_EVENTS.fetch_add(1, Ordering::SeqCst);
    }
}

/// Arms a precise timer 1 to 8 branches out at each `getppid`, which the
/// guest's SIGUSR1 handler makes, so that the timer's steps cover the rest of
/// the handler and its `rt_sigreturn`; passes every syscall on.
#[derive(Debug, Default, Clone)]
struct SigreturnSteppingTool;

#[reverie::tool]
impl Tool for SigreturnSteppingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all_syscalls()
    }

    fn enforces_serialized_execution(_config: &()) -> bool {
        true
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getppid {
            let k = HANDLER_ARMINGS.fetch_add(1, Ordering::SeqCst) % 8 + 1;
            guest.set_timer_precise(TimerSchedule::Rcbs(k))?;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, _guest: &mut G) {
        SIGRETURN_TIMER_EVENTS.fetch_add(1, Ordering::SeqCst);
    }
}

/// Arms a precise timer 40 branches out at each `getpid`, so that the timer's
/// single steps reach the guest's next syscall, whose seccomp stop ends the
/// stepping with a SIGTRAP repair owed (the event itself is not delivered);
/// passes every syscall on.
#[derive(Debug, Default, Clone)]
pub struct SyscallSteppingTool;

#[reverie::tool]
impl Tool for SyscallSteppingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all_syscalls()
    }

    fn enforces_serialized_execution(_config: &()) -> bool {
        true
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            guest.set_timer_precise(TimerSchedule::Rcbs(40))?;
        }
        guest.tail_inject(syscall).await
    }
}

/// Timer events delivered to `NearSteppingTool`.
static NEAR_TIMER_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Arms a precise timer 300 branches out at each `getpid`, nearer than any
/// processor's skid margin, so that no counter overflow drives it and its
/// whole approach is single steps; passes every syscall on.
#[derive(Debug, Default, Clone)]
struct NearSteppingTool;

#[reverie::tool]
impl Tool for NearSteppingTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all_syscalls()
    }

    fn enforces_serialized_execution(_config: &()) -> bool {
        true
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            guest.set_timer_precise(TimerSchedule::Rcbs(300))?;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, _guest: &mut G) {
        NEAR_TIMER_EVENTS.fetch_add(1, Ordering::SeqCst);
    }
}

pub extern "C" fn trap_handler(_: libc::c_int) {}

/// Retires conditional branches well past the timer's target.
#[inline(never)]
pub fn branch(n: u64) -> u64 {
    let mut x = 0u64;
    for i in 0..n {
        if std::hint::black_box(i) & 1 == 1 {
            x = x.wrapping_add(1);
        }
    }
    x
}

/// Sets SIGTRAP's action and mask bit, lets the timer fire in a branch loop,
/// and returns the action handler and mask bit read back after it.
fn survive(handler: libc::sighandler_t, blocked: bool) -> (libc::sighandler_t, bool) {
    // SAFETY: plain libc signal calls on this thread's own state.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()),
            0
        );
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTRAP);
        let how = if blocked {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        };
        assert_eq!(libc::pthread_sigmask(how, &set, std::ptr::null_mut()), 0);
        libc::getpid();
        std::hint::black_box(branch(200_000));
        let mut now: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
            0
        );
        let mut mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask),
            0
        );
        let still_blocked = libc::sigismember(&mask, libc::SIGTRAP) == 1;
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        (now.sa_sigaction, still_blocked)
    }
}

/// The five SIGTRAP states across a precise timer's single steps.
pub fn sigtrap_action_and_mask_survive_precise_timer_steps() {
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let before = TIMER_EVENTS.load(Ordering::SeqCst);
    reverie_ptrace::testing::check_fn::<SteppingTool, _>(|| {
        let caught = trap_handler as *const () as libc::sighandler_t;
        for (name, handler, blocked) in [
            ("ign-blocked", libc::SIG_IGN, true),
            ("ign", libc::SIG_IGN, false),
            ("handler-blocked", caught, true),
            ("handler", caught, false),
            ("dfl-blocked", libc::SIG_DFL, true),
        ] {
            let (now, still_blocked) = survive(handler, blocked);
            // The guest's panic message is not shown; this line is.
            let _ = writeln!(
                std::io::stderr(),
                "{name}: action {now:#x} (set {handler:#x}), blocked {still_blocked} (set {blocked})"
            );
            assert!(
                now == handler && still_blocked == blocked,
                "{name}: action {now:#x} (set {handler:#x}), blocked {still_blocked} (set {blocked})"
            );
        }
    });
    let events = TIMER_EVENTS.load(Ordering::SeqCst) - before;
    assert_eq!(events, 5, "every state's timer must have fired");
}

extern "C" fn arming_handler(_: libc::c_int) {
    // SAFETY: getppid has no preconditions.
    unsafe { libc::getppid() };
}

/// A caught, blocked SIGTRAP survives a timer step over a guest
/// `rt_sigreturn` whose frame blocks it: the guest raises SIGUSR1, whose
/// handler arms a timer 1 to 8 branches out, so the timer single-steps the
/// rest of the handler and its return, which restores the mask the frame
/// saved, SIGTRAP blocked.
pub fn sigtrap_state_survives_a_timer_step_over_sigreturn() {
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let before = SIGRETURN_TIMER_EVENTS.load(Ordering::SeqCst);
    reverie_ptrace::testing::check_fn::<SigreturnSteppingTool, _>(|| {
        // SAFETY: plain libc signal calls on this thread's own state.
        unsafe {
            let mut usr1: libc::sigaction = std::mem::zeroed();
            usr1.sa_sigaction = arming_handler as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut usr1.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &usr1, std::ptr::null_mut()),
                0
            );
            let caught = trap_handler as *const () as libc::sighandler_t;
            let mut trap: libc::sigaction = std::mem::zeroed();
            trap.sa_sigaction = caught;
            libc::sigemptyset(&mut trap.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, &trap, std::ptr::null_mut()),
                0
            );
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTRAP);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                0
            );
            for k in 1..=8 {
                libc::raise(libc::SIGUSR1);
                std::hint::black_box(branch(64));
                let mut now: libc::sigaction = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
                    0
                );
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
                let blocked = libc::sigismember(&mask, libc::SIGTRAP) == 1;
                let _ = writeln!(
                    std::io::stderr(),
                    "sigreturn k={k}: action {:#x} (set {caught:#x}), blocked {blocked}",
                    now.sa_sigaction
                );
                assert!(now.sa_sigaction == caught && blocked, "k={k}");
            }
        }
    });
    let events = SIGRETURN_TIMER_EVENTS.load(Ordering::SeqCst) - before;
    assert_eq!(events, 8, "every arming's timer must have fired");
}

/// An ignored SIGTRAP that a timer's single steps reset is written back at
/// the seccomp stop where the steps end, before the syscall runs: the repair
/// skips the syscall, writes the action back, and re-executes the syscall
/// once, with its own number and arguments. Each `mkdirat` must run exactly
/// once, returning 0 (not `EEXIST` from a second run, nor `ENOSYS` from a
/// re-executed call that lost its number), and SIGTRAP must stay ignored.
pub fn a_repair_at_a_seccomp_stop_runs_the_syscall_once() {
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let base = std::env::temp_dir().join(format!(
        "reverie-sigtrap-repair-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dirs: Vec<std::ffi::CString> = (0..4)
        .map(|i| std::ffi::CString::new(format!("{}-{i}", base.display())).unwrap())
        .collect();
    let guest_dirs = dirs.clone();
    reverie_ptrace::testing::check_fn::<SyscallSteppingTool, _>(move || {
        // SAFETY: plain libc calls on this thread's own state and on
        // NUL-terminated paths.
        unsafe {
            let mut ignore: libc::sigaction = std::mem::zeroed();
            ignore.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ignore.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, &ignore, std::ptr::null_mut()),
                0
            );
            for (i, dir) in guest_dirs.iter().enumerate() {
                libc::getpid();
                let ret = libc::syscall(
                    libc::SYS_mkdirat,
                    libc::AT_FDCWD,
                    dir.as_ptr(),
                    0o755 as libc::c_long,
                );
                let errno = std::io::Error::last_os_error();
                let mut now: libc::sigaction = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
                    0
                );
                let _ = writeln!(
                    std::io::stderr(),
                    "mkdirat {i}: {ret} ({errno}), action {:#x}",
                    now.sa_sigaction
                );
                assert!(ret == 0 && now.sa_sigaction == libc::SIG_IGN, "mkdirat {i}");
            }
        }
    });
    let made = dirs
        .iter()
        .filter(|dir| std::path::Path::new(dir.to_str().unwrap()).is_dir())
        .count();
    for dir in &dirs {
        let _ = std::fs::remove_dir(dir.to_str().unwrap());
    }
    assert_eq!(
        made,
        dirs.len(),
        "every mkdirat must have made its directory"
    );
}

/// `SI_QUEUE` (include/uapi/asm-generic/siginfo.h), `sigqueue`'s code.
const SI_QUEUE: libc::c_int = -1;
/// The pid the guest's SIGTRAP claims to come from.
const QUEUED_SIGTRAP_PID: libc::pid_t = 4242;

/// SIGTRAPs `record_trap` handled, and the code and pid of the last, in the
/// guest.
static TRAPS_HANDLED: AtomicU64 = AtomicU64::new(0);
static TRAP_CODE_AND_PID: AtomicU64 = AtomicU64::new(0);

extern "C" fn record_trap(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler, and
    // si_pid reads the member a queued signal fills in.
    let (code, pid) = unsafe { ((*info).si_code, (*info).si_pid()) };
    TRAP_CODE_AND_PID.store(
        (u64::from(code as u32) << 32) | u64::from(pid as u32),
        Ordering::SeqCst,
    );
    TRAPS_HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// Whether this thread has a SIGTRAP pending in its own queue, from procfs.
fn sigtrap_pending_for_thread() -> bool {
    let status = std::fs::read_to_string("/proc/thread-self/status").expect("read status");
    let pending = status
        .lines()
        .find_map(|line| line.strip_prefix("SigPnd:"))
        .map(|bits| u64::from_str_radix(bits.trim(), 16).expect("SigPnd is hex"))
        .expect("a SigPnd line");
    pending & (1 << (libc::SIGTRAP - 1)) != 0
}

/// A SIGTRAP the guest queued itself while blocking it, with its own code
/// and pid, is kept across a precise timer's single steps, as natively:
/// procfs shows it pending after the steps, no handler ran during them, and
/// unblocking it runs the handler once, with that code and pid. The steps
/// take it out of the queue at the timer's stop and queue it again after
/// (`TracedTask::stash_pending_sigtrap`); before that, each step refused it
/// and ended the run (`PendingSigtrapAtStep`). The timer is near enough that
/// no counter overflow drives it, so the run does not depend on how a
/// processor delivers overflow notifications. Runs on every architecture
/// with a PMU.
pub fn a_pending_blocked_sigtrap_is_kept_across_timer_steps() {
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let before = NEAR_TIMER_EVENTS.load(Ordering::SeqCst);
    reverie_ptrace::testing::check_fn::<NearSteppingTool, _>(|| {
        // SAFETY: plain libc signal calls on this thread's own state.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_trap as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()),
                0
            );
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTRAP);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                0
            );
            let mut info: libc::siginfo_t = std::mem::zeroed();
            info.si_signo = libc::SIGTRAP;
            info.si_code = SI_QUEUE;
            // si_pid, the first member of the siginfo's union, 16 bytes in.
            std::ptr::from_mut(&mut info)
                .cast::<u8>()
                .add(16)
                .cast::<libc::pid_t>()
                .write(QUEUED_SIGTRAP_PID);
            assert_eq!(
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    libc::getpid(),
                    libc::syscall(libc::SYS_gettid),
                    libc::SIGTRAP,
                    &raw const info,
                ),
                0
            );
            let queued = sigtrap_pending_for_thread();
            libc::getpid();
            std::hint::black_box(branch(200_000));
            let kept = sigtrap_pending_for_thread();
            let handled_while_blocked = TRAPS_HANDLED.load(Ordering::SeqCst);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            let handled = TRAPS_HANDLED.load(Ordering::SeqCst);
            let code_and_pid = TRAP_CODE_AND_PID.load(Ordering::SeqCst);
            let (code, pid) = ((code_and_pid >> 32) as i32, code_and_pid as u32 as i32);
            let report = format!(
                "queued {queued}, kept {kept}, handled while blocked {handled_while_blocked}, \
                 handled {handled}, code {code}, pid {pid}"
            );
            // The guest's panic message is not shown; this line is.
            let _ = writeln!(std::io::stderr(), "{report}");
            assert!(
                queued
                    && kept
                    && handled_while_blocked == 0
                    && handled == 1
                    && code == SI_QUEUE
                    && pid == QUEUED_SIGTRAP_PID,
                "{report}"
            );
        }
    });
    let events = NEAR_TIMER_EVENTS.load(Ordering::SeqCst) - before;
    assert_eq!(events, 1, "the timer fired over the pending SIGTRAP");
}
