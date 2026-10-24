/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Syscall restarts under plain ptrace, both those a Tool manufactures by
//! returning a Linux restart code and those the kernel makes itself.
//!
//! The guest (`fixtures/tool_restart.c`) routes every syscall under test
//! through one asm site. A Tool-returned `-ERESTART*` must not reach the
//! guest as a raw result: the syscall restarts, re-invoking the Tool, or
//! fails with `EINTR`, by the rule Linux applies to the signal (if any) that
//! interrupts it and to its handler's `SA_RESTART`. These are the plain
//! ptrace arms of the deleted LiteInst host-hybrid restart tests, which
//! compared each run with a run of that backend; the plain assertions are
//! kept as they were.

#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::LazyLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

// The fixture's descriptors and results; they must match tool_restart.c.
const RESTART_WARM_FD: u64 = 0x7e56;
const RESTART_MAGIC_FD: u64 = 0x7e57;
const RESTART_QUERY_FD: u64 = 0x7e58;
const RESTART_RESULT: i64 = 4243;
/// Read by the `handler-nested` handlers; see `RestartTool`.
const RESTART_NESTED_FD: u64 = 0x7e59;
const RESTART_NESTED_RESULT: i64 = 4244;

/// The site counters the fixture prints when no preloaded runtime provides
/// them, which under plain ptrace is always.
const NO_SITE_COUNTS: &str = "traps=- hooks=-";

/// `RestartTool` configuration, packed into the `u64` Tool config.
#[derive(Clone, Copy, Default)]
struct RestartPlan {
    /// Linux restart code returned for the first `restarts` magic reads.
    errno: i32,
    /// How many magic invocations return `errno` before `RESTART_RESULT`.
    restarts: u8,
    /// A signal the Tool sends the thread on the first magic invocation.
    signal: i32,
    /// Also subscribe `restart_syscall`.
    subscribe_restart_syscall: bool,
    /// Request a precise timer due within the skid margin on the first magic
    /// invocation, so the timer's single-step runs across the restart.
    timer: bool,
    /// A syscall the Tool injects on the first magic invocation, after any
    /// `signal`.
    inject: RestartInject,
    /// Request a precise timer `SIGNAL_TIMER_RCBS` ahead from the signal
    /// event of `signal`, due after the guest handler returns.
    signal_timer: bool,
    /// Deliver `SIGTRAP` in place of `signal` from its signal event.
    deliver_sigtrap: bool,
    /// With `signal_timer`, request the timer `SIGNAL_TIMER_NEAR_RCBS` ahead
    /// instead, so its single-step window covers the handler's return.
    signal_timer_near: bool,
    /// Pass the original magic read through (`Guest::inject`) right after
    /// sending `signal`, instead of returning a result.
    inject_original: bool,
}

/// Far enough past the delivery of a quiet guest handler that neither the
/// timer's notification nor its single-step window reaches the handler's
/// return, and well within the fixture's `-spin` loop after the read.
const SIGNAL_TIMER_RCBS: u64 = 50_000;

/// Near enough that, with the skid margin pinned to `TIMER_TEST_SKID_MARGIN`,
/// the timer's single-step window covers the quiet handler's return.
const SIGNAL_TIMER_NEAR_RCBS: u64 = 1000;

/// A syscall `RestartTool` injects inside the first magic invocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RestartInject {
    #[default]
    None,
    /// `getpid`, with the Tool's signal already pending: the signal arrives
    /// during the injection, and the tracer holds it for the resume.
    Getpid,
    /// `rt_sigprocmask(SIG_UNBLOCK, arg1)`: the magic read's buffer is the
    /// guest's blocked set, so this unblocks a signal already pending.
    UnblockBuffer,
}

impl RestartPlan {
    fn encode(self) -> u64 {
        (self.errno as u64 & 0xffff)
            | ((self.signal as u64 & 0xff) << 16)
            | ((self.restarts as u64) << 24)
            | ((self.subscribe_restart_syscall as u64) << 32)
            | ((self.timer as u64) << 33)
            | ((self.inject as u64) << 34)
            | ((self.signal_timer as u64) << 36)
            | ((self.deliver_sigtrap as u64) << 38)
            | ((self.signal_timer_near as u64) << 39)
            | ((self.inject_original as u64) << 40)
    }

    fn decode(config: u64) -> Self {
        Self {
            errno: (config & 0xffff) as i32,
            signal: ((config >> 16) & 0xff) as i32,
            restarts: ((config >> 24) & 0xff) as u8,
            subscribe_restart_syscall: (config >> 32) & 1 != 0,
            timer: (config >> 33) & 1 != 0,
            inject: match (config >> 34) & 3 {
                0 => RestartInject::None,
                1 => RestartInject::Getpid,
                2 => RestartInject::UnblockBuffer,
                other => panic!("bad RestartInject {other}"),
            },
            signal_timer: (config >> 36) & 1 != 0,
            deliver_sigtrap: (config >> 38) & 1 != 0,
            signal_timer_near: (config >> 39) & 1 != 0,
            inject_original: (config >> 40) & 1 != 0,
        }
    }
}

#[derive(Debug, Default)]
struct RestartLog {
    events: std::sync::Mutex<Vec<String>>,
    magic_calls: AtomicU64,
    nested_calls: AtomicU64,
    signals: AtomicU64,
}

impl RestartLog {
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for RestartLog {
    type Request = String;
    type Response = u64;
    type Config = u64;

    /// Records one Tool-visible event. A magic or nested call returns its
    /// 0-based index among its kind; `query` returns the number of signals
    /// seen, without recording.
    async fn receive_rpc(&self, _from: Tid, event: String) -> u64 {
        if event == "query" {
            return self.signals.load(Ordering::SeqCst);
        }
        let index = if event.starts_with("magic ") {
            self.magic_calls.fetch_add(1, Ordering::SeqCst)
        } else if event.starts_with("nested ") {
            self.nested_calls.fetch_add(1, Ordering::SeqCst)
        } else {
            0
        };
        if event.starts_with("signal ") {
            self.signals.fetch_add(1, Ordering::SeqCst);
        }
        self.events.lock().unwrap().push(event);
        index
    }
}

#[derive(Default)]
struct RestartTool;

#[reverie::tool]
impl Tool for RestartTool {
    type GlobalState = RestartLog;
    /// The clock when the signal event requested its precise timer, so the
    /// timer event can report how many RCBs later it fired.
    type ThreadState = Option<u64>;

    fn subscriptions(config: &u64) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::read);
        if RestartPlan::decode(*config).subscribe_restart_syscall {
            subscription.syscall(Sysno::restart_syscall);
        }
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        let plan = RestartPlan::decode(*guest.config());
        if nr == Sysno::read && args.arg0 as u64 == RESTART_WARM_FD {
            guest.send_rpc("read(warm)".to_owned()).await;
            return Ok(0);
        }
        if nr == Sysno::read && args.arg0 as u64 == RESTART_QUERY_FD {
            return Ok(guest.send_rpc("query".to_owned()).await as i64);
        }
        if nr == Sysno::read && args.arg0 as u64 == RESTART_NESTED_FD {
            // A restart with no signal, made from inside a signal handler.
            let index = guest
                .send_rpc(format!("nested {nr}({:#x},{})", args.arg0, args.arg2))
                .await;
            if index == 0 {
                return Err(reverie::Errno::ERESTARTSYS.into());
            }
            return Ok(RESTART_NESTED_RESULT);
        }
        if args.arg0 as u64 == RESTART_MAGIC_FD
            && (nr == Sysno::read || nr == Sysno::restart_syscall)
        {
            let index = guest
                .send_rpc(format!("magic {nr}({:#x},{})", args.arg0, args.arg2))
                .await;
            if index == 0 && plan.signal != 0 {
                // SAFETY: tgkill has no memory effects.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        guest.pid().as_raw(),
                        guest.tid().as_raw(),
                        plan.signal,
                    )
                };
                assert_eq!(sent, 0, "tgkill failed");
            }
            if plan.inject_original {
                return Ok(guest.inject(syscall).await?);
            }
            if index == 0 {
                match plan.inject {
                    RestartInject::None => {}
                    RestartInject::Getpid => {
                        // The result is not asserted: the pending signal can
                        // interrupt the injection itself.
                        let getpid =
                            Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                        let _ = guest.inject(getpid).await;
                    }
                    RestartInject::UnblockBuffer => {
                        let unblock = Syscall::from_raw(
                            Sysno::rt_sigprocmask,
                            SyscallArgs::new(libc::SIG_UNBLOCK as usize, args.arg1, 0, 8, 0, 0),
                        );
                        assert_eq!(guest.inject(unblock).await, Ok(0), "unblock failed");
                    }
                }
            }
            if index == 0 && plan.timer {
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(1))
                    .unwrap();
            }
            if index < plan.restarts as u64 {
                return Err(reverie::Errno::new(plan.errno).into());
            }
            return Ok(RESTART_RESULT);
        }
        if nr == Sysno::restart_syscall {
            guest.send_rpc("restart_syscall".to_owned()).await;
        }
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, reverie::Errno> {
        guest.send_rpc(format!("signal {}", signal.as_str())).await;
        let plan = RestartPlan::decode(*guest.config());
        if signal as i32 == plan.signal {
            if plan.signal_timer {
                let rcbs = if plan.signal_timer_near {
                    SIGNAL_TIMER_NEAR_RCBS
                } else {
                    SIGNAL_TIMER_RCBS
                };
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(rcbs))
                    .unwrap();
                let armed = guest.read_clock().unwrap();
                *guest.thread_state_mut() = Some(armed);
            }
            if plan.deliver_sigtrap {
                return Ok(Some(reverie::Signal::SIGTRAP));
            }
        }
        Ok(Some(signal))
    }

    /// A timer requested from a signal event reports the RCBs since the
    /// request, which a precise timer makes exactly the requested count.
    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let event = match guest.thread_state_mut().take() {
            Some(armed) => format!("timer +{}", guest.read_clock().unwrap() - armed),
            None => "timer".to_owned(),
        };
        guest.send_rpc(event).await;
    }
}

/// Compiles `tests/fixtures/tool_restart.c` once, beside the test binary.
fn guest() -> &'static PathBuf {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
        // BUCK rule set. The compile-time value is a directory on the build
        // host and is missing on the test host when the binary was built
        // remotely.
        let source = std::env::var_os("CARGO_MANIFEST_DIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
            .join("tests/fixtures/tool_restart.c");
        // One guest beside the test binary, compiled by each process and
        // renamed into place.
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        let path = directory.join("reverie-tool-restart");
        let staging = directory.join(format!("reverie-tool-restart.{}.tmp", std::process::id()));
        let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
        let result = ProcessCommand::new(&compiler)
            .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .output()
            .unwrap_or_else(|error| panic!("invoke {compiler:?}: {error}"));
        assert!(
            result.status.success(),
            "failed to compile {}:\n{}",
            source.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        std::fs::rename(&staging, &path)
            .unwrap_or_else(|error| panic!("publish {}: {error}", path.display()));
        path
    });
    &GUEST
}

/// Runs the fixture in `mode` under plain ptrace and `RestartTool` with
/// `plan`, requires it to succeed, and returns its output and the Tool's
/// events.
async fn run_restart_fixture(mode: &str, plan: RestartPlan) -> (String, Vec<String>) {
    let (output, events) = run_restart_fixture_output(mode, plan).await.unwrap();
    assert!(output.status.success(), "{mode} guest failed: {output:?}");
    (String::from_utf8(output.stdout).unwrap(), events)
}

/// As `run_restart_fixture`, for a guest that may exit unsuccessfully.
async fn run_restart_fixture_output(
    mode: &str,
    plan: RestartPlan,
) -> Result<(reverie::process::Output, Vec<String>), Error> {
    let mut command = Command::new(guest());
    command.arg(mode);
    command
        .stdout(reverie::process::Stdio::piped())
        .stderr(reverie::process::Stdio::piped());
    let (output, log) = reverie_ptrace::TracerBuilder::<RestartTool>::new(command)
        .config(plan.encode())
        .spawn()
        .await?
        .wait_with_output()
        .await?;
    Ok((output, log.events()))
}

/// A Tool-returned restart code re-invokes the syscall, and the Tool, as the
/// kernel restarts it, instead of reaching the guest as a raw `-ERESTART*`.
#[tokio::test(flavor = "current_thread")]
async fn tool_restart_codes_re_invoke_the_syscall() {
    for errno in [
        reverie::Errno::ERESTARTSYS,
        reverie::Errno::ERESTARTNOINTR,
        reverie::Errno::ERESTARTNOHAND,
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 2,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture("read", plan).await;
        assert_eq!(
            stdout,
            format!("read-result={RESTART_RESULT} {NO_SITE_COUNTS}\n"),
            "{errno}"
        );
        assert_eq!(
            events,
            [
                "read(warm)",
                "magic read(0x7e57,1)",
                "magic read(0x7e57,1)",
                "magic read(0x7e57,1)"
            ],
            "{errno}"
        );
    }
}

/// `-ERESTART_RESTARTBLOCK` re-dispatches as `restart_syscall` with the
/// original argument registers, as Linux does.
#[tokio::test(flavor = "current_thread")]
async fn restartblock_re_invokes_restart_syscall() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTART_RESTARTBLOCK.into_raw(),
        restarts: 2,
        subscribe_restart_syscall: true,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("read", plan).await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} {NO_SITE_COUNTS}\n")
    );
    assert_eq!(
        events,
        [
            "read(warm)",
            "magic read(0x7e57,1)",
            "magic restart_syscall(0x7e57,1)",
            "magic restart_syscall(0x7e57,1)"
        ]
    );
}

/// A signal pending when the Tool returns `-ERESTARTSYS` is delivered, and
/// seen by the Tool, before the syscall is re-invoked.
#[tokio::test(flavor = "current_thread")]
async fn restart_delivers_the_signal_before_re_invoking() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGURG,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("read", plan).await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} {NO_SITE_COUNTS}\n")
    );
    assert_eq!(
        events,
        [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGURG",
            "magic read(0x7e57,1)"
        ]
    );
}

/// Attempts `timer_restart_check` may make when an attempt diverges.
const SKID_ATTEMPTS: usize = 3;

/// Skid margin the precise-timer restart tests pin in their child process,
/// through reverie-ptrace's `REVERIE_SKID_MARGIN_OVERRIDE`. A precise timer
/// single-steps its last `skid margin` RCBs, so with this margin the window
/// of a timer due `SIGNAL_TIMER_NEAR_RCBS` after its request starts at the
/// request and covers the quiet handler's return on every host. The
/// processor defaults differ (100 or 125 RCBs on the Intel profiles), and
/// with them the landing would come before the window.
const TIMER_TEST_SKID_MARGIN: u64 = SIGNAL_TIMER_NEAR_RCBS;

/// Names the precise-timer restart test that a child test process runs.
const TIMER_TEST_CHILD_ENV: &str = "REVERIE_PTRACE_TIMER_TEST_CHILD";

/// Whether this process is the child test process that runs `test`. If it
/// is not, runs `test` in a fresh exact-test child process with one test
/// thread and the skid margin pinned to `TIMER_TEST_SKID_MARGIN`, and
/// requires it to pass. The skid-overshoot count and the reverie-ptrace
/// test counters `timer_restart_check` reads are process-global, so only a
/// process that runs one test at a time can attribute them to one run.
fn in_timer_test_child(test: &str) -> bool {
    if std::env::var(TIMER_TEST_CHILD_ENV).as_deref() == Ok(test) {
        let args: Vec<String> = std::env::args().collect();
        assert!(
            args.iter().any(|arg| arg == "--exact")
                && args.iter().any(|arg| arg == "--test-threads=1"),
            "{test} must run as the only test of its process: {args:?}"
        );
        return true;
    }
    let status = ProcessCommand::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(TIMER_TEST_CHILD_ENV, test)
        .env(
            "REVERIE_SKID_MARGIN_OVERRIDE",
            TIMER_TEST_SKID_MARGIN.to_string(),
        )
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated precise-timer test {test} failed: {status}"
    );
    false
}

/// One run in a `timer_restart_check` attempt.
struct TimerRun {
    stdout: String,
    events: Vec<String>,
    /// Skid overshoots recorded during the run
    /// (`reverie::take_skid_overshoot_count`).
    overshoots: u64,
    /// SIGTRAP stops resumed with nothing claiming them.
    unclaimed_sigtraps: u64,
}

async fn run_timer_fixture(mode: &str, plan: RestartPlan) -> TimerRun {
    let _ = reverie::take_skid_overshoot_count();
    let unclaimed_sigtraps = reverie_ptrace::testing::unclaimed_sigtraps_suppressed();
    let (stdout, events) = run_restart_fixture(mode, plan).await;
    TimerRun {
        stdout,
        events,
        overshoots: reverie::take_skid_overshoot_count(),
        unclaimed_sigtraps: reverie_ptrace::testing::unclaimed_sigtraps_suppressed()
            - unclaimed_sigtraps,
    }
}

/// Whether `events` differ from `expected` only in the last event, and that
/// event is `timer +N` for an `expected` last event `timer +R` with N > R:
/// the timer fired late, the one divergence a skid overshoot causes.
fn is_late_timer(events: &[String], expected: &[&str]) -> bool {
    let (Some((last, prefix)), Some((expected_last, expected_prefix))) =
        (events.split_last(), expected.split_last())
    else {
        return false;
    };
    let rcbs = |event: &str| {
        event
            .strip_prefix("timer +")
            .and_then(|rcbs| rcbs.parse::<u64>().ok())
    };
    prefix == expected_prefix
        && matches!((rcbs(last), rcbs(expected_last)), (Some(late), Some(requested)) if late > requested)
}

/// Whether skid explains every difference between the run's events and
/// `expected`: the events equal `expected`, or the run recorded a skid
/// overshoot and its events differ only in a late last timer event
/// (`is_late_timer`). The caller has already required everything else to
/// match exactly.
fn skid_explains_divergence(run: &TimerRun, expected: &[&str]) -> bool {
    run.events == expected || (run.overshoots > 0 && is_late_timer(&run.events, expected))
}

/// For a plan whose Tool requests a precise timer, run inside
/// `in_timer_test_child`. Requires the output to equal `expected_stdout`, the
/// events to equal `expected`, and no unclaimed SIGTRAP stop to be resumed,
/// which is what a single-step trap flag left set in the guest produces.
///
/// A precise timer that the PMU delivers past its programmed target
/// (`reverie::SKID_OVERSHOOT_MARKER`) fires late, so its `timer +N` event
/// exceeds the requested distance. The skid tail is heavy and no fixed
/// margin covers it; reverie's documented policy is that a divergence caused
/// by skid may be retried. An attempt is therefore retried, up to
/// `SKID_ATTEMPTS`, only when `skid_explains_divergence`: the only
/// difference is a late last timer event of a run that recorded an
/// overshoot. Any other difference fails the attempt at once.
async fn timer_restart_check(
    mode: &str,
    plan: RestartPlan,
    expected_stdout: &str,
    expected: &[&str],
) {
    assert!(
        std::env::var_os(TIMER_TEST_CHILD_ENV).is_some(),
        "timer_restart_check runs only inside in_timer_test_child"
    );
    for attempt in 1..=SKID_ATTEMPTS {
        let run = run_timer_fixture(mode, plan).await;
        let context = format!(
            "{mode}: attempt {attempt}, skid overshoots: {}",
            run.overshoots
        );
        assert_eq!(
            run.stdout, expected_stdout,
            "{context}: output differs from the expected"
        );
        assert_eq!(
            run.unclaimed_sigtraps, 0,
            "{context}: unclaimed SIGTRAP stops resumed; a single-step trap flag was left set"
        );
        if run.events == expected {
            return;
        }
        if attempt < SKID_ATTEMPTS && skid_explains_divergence(&run, expected) {
            eprintln!(
                "{context}: only a late timer event of a run that overshot differs ({:?}); \
                 retrying",
                run.events
            );
            continue;
        }
        assert_eq!(
            run.events, expected,
            "{context}: Tool events differ from the expected"
        );
    }
    unreachable!("the last attempt returns or fails an assertion")
}

fn timer_run(events: &[&str], overshoots: u64) -> TimerRun {
    TimerRun {
        stdout: String::new(),
        events: events.iter().map(|event| event.to_string()).collect(),
        overshoots,
        unclaimed_sigtraps: 0,
    }
}

/// `timer_restart_check` retries only a late last timer event of a run that
/// recorded a skid overshoot.
#[test]
fn skid_explains_only_a_late_timer_of_a_run_that_overshot() {
    let expected = ["read(warm)", "signal SIGUSR1", "timer +50000"];
    let exact = ["read(warm)", "signal SIGUSR1", "timer +50000"];
    let late = ["read(warm)", "signal SIGUSR1", "timer +50075"];
    let early = ["read(warm)", "signal SIGUSR1", "timer +49990"];
    let extra = ["read(warm)", "signal SIGUSR1", "timer +50000", "bogus"];
    let late_and_extra = ["read(warm)", "signal SIGUSR2", "timer +50075"];
    let missing = ["read(warm)", "signal SIGUSR1"];
    for (run, explained, case) in [
        (timer_run(&exact, 0), true, "exact"),
        (timer_run(&exact, 1), true, "exact, overshot"),
        (timer_run(&late, 1), true, "late, overshot"),
        (timer_run(&late, 0), false, "late with no overshoot"),
        (timer_run(&early, 1), false, "early timer"),
        (timer_run(&extra, 1), false, "extra event, overshot"),
        (timer_run(&extra, 0), false, "extra event"),
        (timer_run(&missing, 1), false, "missing timer"),
        (
            timer_run(&late_and_extra, 1),
            false,
            "late timer and another difference",
        ),
    ] {
        assert_eq!(
            skid_explains_divergence(&run, &expected),
            explained,
            "{case}"
        );
    }
    let restarted = ["read(warm)", "signal SIGUSR1", "magic read(0x7e57,1)"];
    assert!(
        !skid_explains_divergence(&timer_run(&late, 1), &restarted),
        "a timer where none is expected"
    );
}

/// A restart code with a signal whose guest handler lacks `SA_RESTART`
/// follows Linux: `-ERESTARTSYS`, `-ERESTARTNOHAND` and
/// `-ERESTART_RESTARTBLOCK` become `EINTR` after the handler runs, and
/// `-ERESTARTNOINTR` restarts.
#[tokio::test(flavor = "current_thread")]
async fn restart_with_a_guest_handler_follows_linux() {
    for (errno, result) in [
        (reverie::Errno::ERESTARTSYS, -4),
        (reverie::Errno::ERESTARTNOHAND, -4),
        (reverie::Errno::ERESTART_RESTARTBLOCK, -4),
        (reverie::Errno::ERESTARTNOINTR, RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture("handler", plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{errno}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{errno}");
    }
}

/// An `SA_RESTART` handler restarts `-ERESTARTSYS` but not
/// `-ERESTARTNOHAND`, as Linux does.
#[tokio::test(flavor = "current_thread")]
async fn restart_with_an_sa_restart_handler_follows_linux() {
    for (errno, result) in [
        (reverie::Errno::ERESTARTSYS, RESTART_RESULT),
        (reverie::Errno::ERESTARTNOHAND, -4),
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture("handler-restart", plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{errno}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{errno}");
    }
}

/// The guest handler of the signal that interrupts a restart makes a syscall
/// that itself restarts, before the kernel's decision for the outer one.
/// Both restarts are pending at once; each resolves as Linux resolves it:
/// the nested one restarts (no signal), and the outer one follows the
/// handler's `SA_RESTART`.
#[tokio::test(flavor = "current_thread")]
async fn restart_nested_inside_the_handler_resolves_both() {
    for (mode, result) in [
        ("handler-nested", -4),
        ("handler-nested-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{mode}"
        );
        let mut expected = vec![
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            "nested read(0x7e59,1)",
            "nested read(0x7e59,1)",
        ];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// The shell pattern (bash reaps children from an `SA_RESTART` SIGCHLD
/// handler): a real child exits, and its SIGCHLD reaches that handler while a
/// Tool-restarted syscall is in progress. The syscall restarts.
#[tokio::test(flavor = "current_thread")]
async fn restart_with_an_sa_restart_sigchld_handler_restarts() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        inject: RestartInject::UnblockBuffer,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("sigchld", plan).await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} reaped=1 traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGCHLD",
            "magic read(0x7e57,1)"
        ]
    );
}

/// The signal arrives while the Tool injects a syscall, so the tracer holds
/// it and delivers it on the restart's resume instead of at a fresh signal
/// stop. The Linux rule applies to that delivery too: a handler without
/// `SA_RESTART` interrupts, an `SA_RESTART` one restarts, and no handler
/// restarts. The handler count is the evidence of delivery, and the Tool
/// sees the held signal before the resume that delivers it
/// (https://github.com/rrnewton/hermit/issues/3468,
/// https://github.com/rrnewton/reverie/issues/853).
#[tokio::test(flavor = "current_thread")]
async fn restart_with_a_signal_held_across_an_injection_follows_linux() {
    for (mode, signal, result) in [
        ("handler", libc::SIGUSR1, -4),
        ("handler-restart", libc::SIGUSR1, RESTART_RESULT),
        ("read", libc::SIGURG, RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal,
            inject: RestartInject::Getpid,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        let handled = if mode == "read" {
            ""
        } else {
            " handled=1 nested-ok=1"
        };
        assert_eq!(
            stdout,
            format!("read-result={result}{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        let signal_event = format!(
            "signal {}",
            reverie::Signal::try_from(signal).unwrap().as_str()
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        expected.insert(2, signal_event.as_str());
        assert_eq!(events, expected, "{mode}");
    }
}

/// A precise timer due within the skid margin, requested at the first magic
/// read, which the Tool restarts: the re-invoked syscall is the next event,
/// so the timer is cancelled and never fires.
#[tokio::test(flavor = "current_thread")]
async fn restart_cancels_an_imminent_precise_timer() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        timer: true,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("read", plan).await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "magic read(0x7e57,1)"]
    );
}

/// A real kernel interruption of an unsubscribed syscall: a timer's SIGURG
/// interrupts a 400 ms nanosleep. The guest sees 0 after the full sleep, and
/// the Tool sees the signal.
#[tokio::test(flavor = "current_thread")]
async fn interrupted_unsubscribed_sleep_restarts() {
    let (stdout, events) = run_restart_fixture("sleep", RestartPlan::default()).await;
    assert_eq!(
        stdout,
        format!("sleep-result=0 slept-enough=1 {NO_SITE_COUNTS}\n")
    );
    assert_eq!(events, ["read(warm)", "signal SIGURG"]);
}

/// A blocking pipe readv the Tool does not subscribe, interrupted by a real
/// signal: the kernel's ERESTARTSYS restarts the readv, which returns the byte
/// written later, never -512 or EINTR.
#[tokio::test(flavor = "current_thread")]
async fn interrupted_unsubscribed_readv_restarts() {
    let (stdout, events) = run_restart_fixture("readv", RestartPlan::default()).await;
    assert_eq!(stdout, format!("readv-result=1 byte=x {NO_SITE_COUNTS}\n"));
    assert_eq!(events, ["read(warm)", "signal SIGURG"]);
}

/// The interrupted nanosleep continues through `restart_syscall`, which a
/// subscribing Tool sees after the signal.
#[tokio::test(flavor = "current_thread")]
async fn interrupted_sleep_continues_through_restart_syscall() {
    let plan = RestartPlan {
        subscribe_restart_syscall: true,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("sleep", plan).await;
    assert_eq!(
        stdout,
        format!("sleep-result=0 slept-enough=1 {NO_SITE_COUNTS}\n")
    );
    assert_eq!(events, ["read(warm)", "signal SIGURG", "restart_syscall"]);
}

/// A syscall that completes with a signal pending is not re-executed: the
/// thread's self-sent SIGURG reaches the Tool exactly once.
#[tokio::test(flavor = "current_thread")]
async fn completed_syscall_with_pending_signal_runs_once() {
    let (stdout, events) = run_restart_fixture("tgkill", RestartPlan::default()).await;
    assert_eq!(stdout, format!("tgkill-result=0 {NO_SITE_COUNTS}\n"));
    assert_eq!(events, ["read(warm)", "signal SIGURG"]);
}

/// Signals race the site's unsubscribed getppid and nanosleep calls, landing
/// before the call, during a sleep, or at completion. A second thread sends
/// each SIGURG only after the Tool saw the previous one, so every result
/// must be correct and the Tool must see all 300 exactly once.
#[tokio::test(flavor = "current_thread")]
async fn signals_racing_unsubscribed_syscalls_are_seen_once() {
    let (stdout, events) = run_restart_fixture("stress", RestartPlan::default()).await;
    let prefix = "stress-bad=0 ran=1 tool-signals=300 ";
    let counts = stdout
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{stdout}"));
    assert_eq!(counts, "traps=- hooks=-\n");
    assert_eq!(events[0], "read(warm)");
    assert_eq!(events.len(), 301, "{events:?}");
    assert!(
        events[1..].iter().all(|event| event == "signal SIGURG"),
        "{events:?}"
    );
}

/// The guest's own `SECCOMP_RET_TRAP` SIGSYS for an unsubscribed syscall
/// kills this handler-less guest after the Tool saw it once.
#[tokio::test(flavor = "current_thread")]
async fn guest_seccomp_trap_kills_a_handlerless_guest_after_one_signal_event() {
    let (output, events) = run_restart_fixture_output("seccomp", RestartPlan::default())
        .await
        .unwrap();
    // Whether a core is dumped is host policy; only the signal is asserted.
    assert!(
        matches!(
            output.status,
            ExitStatus::Signaled(reverie::Signal::SIGSYS, _)
        ),
        "{output:?}"
    );
    assert_eq!(events, ["read(warm)", "signal SIGSYS"]);
}

/// A synchronous-class signal that becomes deliverable only under the
/// temporary mask of an unsubscribed `rt_sigsuspend`: the handler runs once,
/// the sleep fails with `EINTR`, the saved mask that blocks the signal is
/// restored, and the Tool sees the signal once.
#[tokio::test(flavor = "current_thread")]
async fn signal_held_after_a_mask_swapping_syscall_is_handled_once() {
    let (stdout, events) = run_restart_fixture("sigsuspend-held", RestartPlan::default()).await;
    assert_eq!(
        stdout,
        "sigsuspend-result=-4 handled=1 blocked=1 traps=- hooks=-\n"
    );
    assert_eq!(events, ["read(warm)", "signal SIGSYS"]);
}

/// A handler that decides the magic read's restart leaves a nested
/// unsubscribed nanosleep by `siglongjmp` from a SIGALRM handler, abandoning
/// that sleep's own restart, and then returns: the read is interrupted or
/// restarted by the handler's `SA_RESTART`, and the sleep never resumes.
#[tokio::test(flavor = "current_thread")]
async fn a_siglongjmp_out_of_a_nested_sleep_resolves_the_outer_restart() {
    for (mode, result) in [
        ("handler-longjmp", -4),
        ("handler-longjmp-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\nafter-sleep=0\n"),
            "{mode}"
        );
        let mut expected = vec![
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            "signal SIGALRM",
        ];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A handler that abandons 70 nested restarts, each by `siglongjmp` out of a
/// nested handler from the same frame, still resolves the restart it
/// interrupted by its own `SA_RESTART`.
#[tokio::test(flavor = "current_thread")]
async fn restarts_abandoned_at_one_depth_keep_the_live_restart() {
    const ABANDONED: usize = 70;
    for (mode, result) in [
        ("handler-abandon", -4),
        ("handler-abandon-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\nafter-sleep=0\n"),
            "{mode}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        expected.extend(std::iter::repeat_n("signal SIGALRM", ABANDONED));
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A handler that edits the saved `rax` of the syscall it interrupted changes
/// the result of an interrupted syscall, and the syscall number of a
/// restarted one.
#[tokio::test(flavor = "current_thread")]
async fn handler_edit_of_rax_follows_linux() {
    for (mode, result) in [
        ("handler-edit-rax", 777),
        ("handler-edit-rax-restart", -libc::EBADF as i64),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n"),
            "{mode}"
        );
        assert_eq!(
            events,
            ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"],
            "{mode}"
        );
    }
}

/// The guest's handler may edit the saved r11 of the syscall it interrupted,
/// which the syscall clobbers anyway: the read is interrupted with EINTR.
#[tokio::test(flavor = "current_thread")]
async fn handler_edit_of_r11_interrupts_the_read() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGUSR1,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("handler-edit-r11", plan).await;
    assert_eq!(
        stdout,
        "read-result=-4 handled=1 nested-ok=0 traps=- hooks=-\n"
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"]
    );
}

/// The handler deciding a restart forks. The child returns from its copy of
/// the handler to its copy of the interrupted read, which resolves by the
/// same rule as the parent's (its exit code encodes the result: 4 for EINTR,
/// 43 for the restarted read's result).
#[tokio::test(flavor = "current_thread")]
async fn fork_inside_the_deciding_handler_resolves_the_child_restart() {
    for (mode, result, child_exit) in [
        ("handler-fork", -4, 4),
        ("handler-fork-restart", RESTART_RESULT, 43),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 child-exit={child_exit} traps=- hooks=-\n"),
            "{mode}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            // The child's restarted read, then the parent's.
            expected.push("magic read(0x7e57,1)");
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A precise timer the Tool requests at the signal that decides a restart is
/// due after the quiet handler returns. There is no stop between the
/// delivery and the timer when the read is interrupted, so the timer fires
/// exactly `SIGNAL_TIMER_RCBS` after the request; a restarted read's
/// re-entry is a stop, so the timer is cancelled.
#[tokio::test(flavor = "current_thread")]
async fn a_signal_requested_timer_fires_unless_the_read_restarts() {
    if !in_timer_test_child("a_signal_requested_timer_fires_unless_the_read_restarts") {
        return;
    }
    for (mode, restarted) in [
        ("handler-quiet-spin", false),
        ("handler-quiet-spin-restart", true),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            signal_timer: true,
            ..Default::default()
        };
        let last = if restarted {
            "magic read(0x7e57,1)".to_owned()
        } else {
            format!("timer +{SIGNAL_TIMER_RCBS}")
        };
        let expected = [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            last.as_str(),
        ];
        let result = if restarted { RESTART_RESULT } else { -4 };
        let stdout = format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n");
        timer_restart_check(mode, plan, &stdout, &expected).await;
    }
}

/// As `a_signal_requested_timer_fires_unless_the_read_restarts`, with the
/// timer due `SIGNAL_TIMER_NEAR_RCBS` after the deciding signal. With the
/// skid margin pinned to `TIMER_TEST_SKID_MARGIN`, the timer's single-step
/// window starts at the request and covers the handler's return: an
/// interrupted read continues and the timer fires in the spin loop exactly
/// `SIGNAL_TIMER_NEAR_RCBS` after the request; a restarted read stops at its
/// re-entry.
#[tokio::test(flavor = "current_thread")]
async fn a_near_signal_requested_timer_fires_unless_the_read_restarts() {
    if !in_timer_test_child("a_near_signal_requested_timer_fires_unless_the_read_restarts") {
        return;
    }
    for (mode, restarted) in [
        ("handler-quiet-spin", false),
        ("handler-quiet-spin-restart", true),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            signal_timer: true,
            signal_timer_near: true,
            ..Default::default()
        };
        let last = if restarted {
            "magic read(0x7e57,1)".to_owned()
        } else {
            format!("timer +{SIGNAL_TIMER_NEAR_RCBS}")
        };
        let expected = [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            last.as_str(),
        ];
        let result = if restarted { RESTART_RESULT } else { -4 };
        let stdout = format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n");
        timer_restart_check(mode, plan, &stdout, &expected).await;
    }
}

/// The Tool sends a signal and then passes the original magic read through
/// (`Guest::inject`) while the signal is still pending: the read of the
/// unopened descriptor fails with `EBADF` at once, and the signal is
/// delivered on the way back to the guest, as a signal event the Tool sees.
/// Covered with a handler without and with `SA_RESTART`, and with a signal
/// that has no handler.
#[tokio::test(flavor = "current_thread")]
async fn original_injection_with_a_pending_signal_delivers_it_after_the_call() {
    for (mode, signal, handled) in [
        ("handler", libc::SIGUSR1, " handled=1 nested-ok=1"),
        ("handler-restart", libc::SIGUSR1, " handled=1 nested-ok=1"),
        ("read", libc::SIGURG, ""),
    ] {
        let plan = RestartPlan {
            signal,
            inject_original: true,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        assert_eq!(
            stdout,
            format!("read-result=-9{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        let signal_event = format!(
            "signal {}",
            reverie::Signal::try_from(signal).unwrap().as_str()
        );
        assert_eq!(
            events,
            ["read(warm)", "magic read(0x7e57,1)", signal_event.as_str()],
            "{mode}"
        );
    }
}

/// A restart decided by a signal the Tool sends, with no injection at the
/// signal event: a handler without `SA_RESTART` interrupts the read, an
/// `SA_RESTART` handler restarts it, and a signal without a handler restarts
/// it.
#[tokio::test(flavor = "current_thread")]
async fn a_signal_decided_restart_follows_the_handler() {
    for (mode, signal, result) in [
        ("handler", libc::SIGUSR1, -4),
        ("handler-restart", libc::SIGUSR1, RESTART_RESULT),
        ("read", libc::SIGURG, RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal,
            ..Default::default()
        };
        let (stdout, events) = run_restart_fixture(mode, plan).await;
        let handled = if mode == "read" {
            ""
        } else {
            " handled=1 nested-ok=1"
        };
        assert_eq!(
            stdout,
            format!("read-result={result}{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        let signal = if mode == "read" {
            "signal SIGURG"
        } else {
            "signal SIGUSR1"
        };
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", signal];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// The guest installs its own SIGTRAP handler without `SA_RESTART` while a
/// `-ERESTARTSYS` restart is pending. A SIGTRAP the guest sends itself never
/// reaches the guest: the tracer suppresses a SIGTRAP it did not cause, so
/// the read restarts with no Tool signal event. When the Tool instead
/// delivers SIGTRAP from the deciding signal event, the guest handler runs
/// and interrupts the read.
#[tokio::test(flavor = "current_thread")]
async fn a_sigtrap_deciding_a_restart_follows_its_origin() {
    let sent = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGTRAP,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture("handler-sigtrap", sent).await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} handled=0 traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "magic read(0x7e57,1)"]
    );

    let delivered = RestartPlan {
        signal: libc::SIGUSR1,
        deliver_sigtrap: true,
        ..sent
    };
    let (stdout, events) = run_restart_fixture("handler-sigtrap", delivered).await;
    assert_eq!(stdout, "read-result=-4 handled=1 traps=- hooks=-\n");
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"]
    );
}
