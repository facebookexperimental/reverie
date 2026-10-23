/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer requested from the signal event that decides a
//! Tool-manufactured restart, with timers that map no overflow records, as
//! on a kernel that is or may be `PREEMPT_RT`. Turning the records off is
//! process global and permanent, so these tests have a binary of their own;
//! reverie-ptrace/tests/tool_restart.rs has the same restarts with records.
//!
//! These are the plain ptrace arms of the deleted LiteInst host-hybrid
//! landing tests without records, which compared each run with a run of that
//! backend; the plain assertions are kept as they were.

#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::LazyLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::KeptTimerProgrammingChecks;

/// The skid witness count and the kept programming checks are process
/// global; each test owns them while it runs.
static COUNTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `test` on a current-thread runtime of its own, owning `COUNTS`.
fn with_counts(test: impl std::future::Future<Output = ()>) {
    let _owner = COUNTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
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

/// The restart fixture's descriptors, and the magic read's result once it is
/// no longer restarted, as reverie-ptrace/tests/tool_restart.rs's
/// `RestartTool` uses them.
const RESTART_WARM_FD: u64 = 0x7e56;
const RESTART_MAGIC_FD: u64 = 0x7e57;
const RESTART_RESULT: i64 = 4243;

/// tool_restart.rs's `SIGNAL_TIMER_NEAR_RCBS`: a timer this far past the
/// deciding signal has its single steps under way at the quiet handler's
/// return when the skid margin is `LANDING_SKID_MARGIN`.
const LANDING_NEAR_RCBS: u64 = 1_000;

/// The skid margin the tests' re-runs pin, tool_restart.rs's
/// `TIMER_TEST_SKID_MARGIN`. A precise timer single-steps its last `skid
/// margin` RCBs, so at this margin the steps of a timer due
/// `LANDING_NEAR_RCBS` after its request start at the request.
const LANDING_SKID_MARGIN: u64 = LANDING_NEAR_RCBS;

/// Attempts `a_timer_beyond_the_keep_margin_fires_at_its_target_without_records`
/// may make when only a witnessed skid overshoot differs, tool_restart.rs's
/// `SKID_ATTEMPTS`.
const SKID_ATTEMPTS: usize = 3;

#[derive(Debug, Default)]
struct LandingTimerLog {
    events: std::sync::Mutex<Vec<String>>,
    magic_calls: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for LandingTimerLog {
    type Request = String;
    type Response = u64;
    /// The precise timer's RCBs from the deciding signal to its target.
    type Config = u64;

    /// Records one Tool-visible event. A magic read returns its 0-based
    /// index among the magic reads.
    async fn receive_rpc(&self, _from: Tid, event: String) -> u64 {
        let index = if event.starts_with("magic ") {
            self.magic_calls.fetch_add(1, Ordering::SeqCst)
        } else {
            0
        };
        self.events.lock().unwrap().push(event);
        index
    }
}

/// tool_restart.rs's `RestartTool` with the plan of its signal-requested
/// timer tests, and its event names: the first magic read sends the thread
/// SIGUSR1 and returns `ERESTARTSYS`, later ones `RESTART_RESULT`; SIGUSR1's
/// signal event requests a precise timer the configured RCBs ahead; and the
/// timer event reports the RCBs since the request.
#[derive(Default)]
struct LandingTimerTool;

#[reverie::tool]
impl Tool for LandingTimerTool {
    type GlobalState = LandingTimerLog;
    /// The clock when the signal event requested the timer.
    type ThreadState = Option<u64>;

    fn subscriptions(_config: &u64) -> Subscription {
        [Sysno::read].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        match args.arg0 as u64 {
            RESTART_WARM_FD => {
                guest.send_rpc("read(warm)".to_owned()).await;
                Ok(0)
            }
            RESTART_MAGIC_FD => {
                let index = guest
                    .send_rpc(format!("magic {nr}({:#x},{})", args.arg0, args.arg2))
                    .await;
                if index > 0 {
                    return Ok(RESTART_RESULT);
                }
                // SAFETY: tgkill has no memory effects.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        guest.pid().as_raw(),
                        guest.tid().as_raw(),
                        libc::SIGUSR1,
                    )
                };
                assert_eq!(sent, 0, "tgkill failed");
                Err(reverie::Errno::ERESTARTSYS.into())
            }
            _ => Ok(guest.inject(syscall).await?),
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, reverie::Errno> {
        guest.send_rpc(format!("signal {}", signal.as_str())).await;
        if signal == reverie::Signal::SIGUSR1 {
            guest
                .set_timer_precise(TimerSchedule::Rcbs(*guest.config()))
                .unwrap();
            let armed = guest.read_clock().unwrap();
            *guest.thread_state_mut() = Some(armed);
        }
        Ok(Some(signal))
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let event = match guest.thread_state_mut().take() {
            Some(armed) => format!("timer +{}", guest.read_clock().unwrap() - armed),
            None => "timer".to_owned(),
        };
        guest.send_rpc(event).await;
    }
}

/// One run of the restart fixture under `LandingTimerTool`.
struct LandingRun {
    stdout: String,
    events: Vec<String>,
    /// Skid overshoots recorded during the run
    /// (`reverie::take_skid_overshoot_count`).
    witnesses: u64,
    /// SIGTRAP stops resumed with nothing claiming them, which a single-step
    /// trap flag left set in the guest produces.
    unclaimed_sigtraps: u64,
    /// Stops that kept the timer's event with its programming unchanged
    /// (`KeptTimerProgrammingChecks::keeps`).
    keeps: u64,
}

/// Runs the restart fixture in `mode` under plain ptrace, with the timer due
/// `rcbs` after the deciding signal.
async fn run_landing_timer(mode: &str, rcbs: u64) -> LandingRun {
    let mut command = Command::new(guest());
    command.arg(mode);
    // The counts are process global; see `COUNTS`.
    let _ = reverie::take_skid_overshoot_count();
    let unclaimed_sigtraps = reverie_ptrace::testing::unclaimed_sigtraps_suppressed();
    let checks = KeptTimerProgrammingChecks::start();
    let run = async {
        command
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        reverie_ptrace::TracerBuilder::<LandingTimerTool>::new(command)
            .config(rcbs)
            .spawn()
            .await?
            .wait_with_output()
            .await
    };
    let (output, log) = tokio::time::timeout(Duration::from_secs(120), run)
        .await
        .unwrap_or_else(|_| panic!("the {mode} guest did not complete"))
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{mode}: {output:?}");
    LandingRun {
        stdout: String::from_utf8(output.stdout).unwrap(),
        events: log.events.into_inner().unwrap(),
        witnesses: reverie::take_skid_overshoot_count(),
        unclaimed_sigtraps: reverie_ptrace::testing::unclaimed_sigtraps_suppressed()
            - unclaimed_sigtraps,
        keeps: checks.keeps(),
    }
}

/// The fixture's output for a read that returned `result`, with the site
/// counters it prints when nothing is preloaded.
fn landing_stdout(result: i64) -> String {
    format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n")
}

/// The Tool's events up to the deciding signal, then `last`.
fn landing_events(last: Option<String>) -> Vec<String> {
    ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"]
        .into_iter()
        .map(str::to_owned)
        .chain(last)
        .collect()
}

/// This test's name, which its re-run selects.
const NEAR_TIMER_TEST: &str = "a_near_signal_requested_timer_fires_at_its_target_without_records";

// The signal that decides the restart requests a timer `LANDING_NEAR_RCBS`
// ahead, at the skid margin `LANDING_SKID_MARGIN`, which needs a process of
// its own, so that its single steps start at the request. The handler makes
// no syscall, and there is no stop between the signal's delivery and the
// timer: an interrupted read returns to the guest, and the event fires at
// its target in the spin loop after it. Its steps start at the request, so
// no skid can carry it past the target and nothing is witnessed. A restarted
// read re-enters the Tool at a stop, which cancels the event. No stop keeps
// the event, and no single-step trap flag is left set.
#[test]
fn a_near_signal_requested_timer_fires_at_its_target_without_records() {
    reverie_ptrace::ret_without_perf!();
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            // The re-run's output, with each run's counts.
            eprint!(
                "{}",
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[NEAR_TIMER_TEST, "--exact"],
                    LANDING_SKID_MARGIN,
                    1,
                    Duration::from_secs(300),
                )
            );
        }
        Some(_) => with_counts(near_signal_requested_timer_fires_at_its_target()),
    }
}

async fn near_signal_requested_timer_fires_at_its_target() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    for (mode, result, last) in [
        (
            "handler-quiet-spin",
            -4,
            format!("timer +{LANDING_NEAR_RCBS}"),
        ),
        (
            "handler-quiet-spin-restart",
            RESTART_RESULT,
            "magic read(0x7e57,1)".to_owned(),
        ),
    ] {
        let ptrace = run_landing_timer(mode, LANDING_NEAR_RCBS).await;
        assert_eq!(ptrace.stdout, landing_stdout(result), "{mode}");
        assert_eq!(
            ptrace.events,
            landing_events(Some(last)),
            "{mode}: there is no stop before the timer, unless the read restarts"
        );
        assert_eq!(
            ptrace.witnesses, 0,
            "{mode}: no skid overshoot may be witnessed"
        );
        assert_eq!(ptrace.keeps, 0, "{mode}: no stop keeps the event");
        assert_eq!(
            ptrace.unclaimed_sigtraps, 0,
            "{mode}: unclaimed SIGTRAP stops resumed; a single-step trap flag was left set"
        );
    }
}

/// This test's name, which its re-run selects.
const KEEP_MARGIN_TEST: &str = "a_timer_beyond_the_keep_margin_fires_at_its_target_without_records";

// As above, with the timer due `PmuConfig::keep_margin` plus twice
// `LANDING_NEAR_RCBS` after the deciding signal. The interrupted read spins
// past the target, and the event must fire at exactly its target. No stop
// keeps the event, and no single-step trap flag is left set. A witnessed
// skid overshoot that makes the event fire late is retried, up to
// `SKID_ATTEMPTS`; any other difference fails at once. Only the interrupted
// read is covered: a restarted read re-enters the Tool at a stop, which
// cancels the event before its target.
#[test]
fn a_timer_beyond_the_keep_margin_fires_at_its_target_without_records() {
    reverie_ptrace::ret_without_perf!();
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            // The re-run's output, with each run's counts.
            eprint!(
                "{}",
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[KEEP_MARGIN_TEST, "--exact"],
                    LANDING_SKID_MARGIN,
                    1,
                    Duration::from_secs(300),
                )
            );
        }
        Some(_) => with_counts(timer_beyond_the_keep_margin_fires_at_its_target()),
    }
}

async fn timer_beyond_the_keep_margin_fires_at_its_target() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    let mode = "handler-quiet-spin";
    let rcbs = reverie_ptrace::PmuConfig::new()
        .expect("this host has a PMU profile")
        .keep_margin()
        + 2 * LANDING_NEAR_RCBS;
    let expected = landing_events(Some(format!("timer +{rcbs}")));
    // A run's events are explained by skid if they are the expected events,
    // or if the run witnessed an overshoot and only its timer event, the last,
    // fired past the target.
    let explained = |run: &LandingRun| {
        run.events == expected
            || (run.witnesses > 0
                && run.events.split_last().is_some_and(|(last, prefix)| {
                    prefix == &expected[..expected.len() - 1]
                        && last
                            .strip_prefix("timer +")
                            .and_then(|fired| fired.parse::<u64>().ok())
                            .is_some_and(|fired| fired > rcbs)
                }))
    };
    for attempt in 1..=SKID_ATTEMPTS {
        let ptrace = run_landing_timer(mode, rcbs).await;
        let context = format!(
            "attempt {attempt}, timer {rcbs} RCBs ahead, skid overshoots: {}",
            ptrace.witnesses
        );
        assert_eq!(ptrace.stdout, landing_stdout(-4), "{context}");
        assert_eq!(ptrace.keeps, 0, "{context}: no stop keeps the event");
        assert_eq!(
            ptrace.unclaimed_sigtraps, 0,
            "{context}: unclaimed SIGTRAP stops resumed; a single-step trap flag was left set"
        );
        if ptrace.events == expected {
            assert_eq!(
                ptrace.witnesses, 0,
                "{context}: an event that fired at its target cannot be a skid overshoot"
            );
            return;
        }
        if attempt < SKID_ATTEMPTS && explained(&ptrace) {
            eprintln!(
                "{context}: only a witnessed late timer event differs ({:?}); retrying",
                ptrace.events
            );
            continue;
        }
        assert_eq!(
            ptrace.events, expected,
            "{context}: the event must fire at its target"
        );
    }
    unreachable!("the last attempt returns or fails an assertion")
}
