/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! LiteInst hook traps and restart landings with precise timers that map no
//! overflow records, as on a kernel that is or may be `PREEMPT_RT`. Turning
//! the records off is process global and permanent, so these tests have a
//! binary of their own; reverie-liteinst/tests/hybrid.rs has the same traps
//! and landings with records.

#![cfg(target_arch = "x86_64")]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
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
use reverie_liteinst::LiteinstBackend;
use reverie_ptrace::testing::KeptTimerProgrammingChecks;
use reverie_ptrace::testing::assert_at_target_unless_witnessed;

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

fn preload_path() -> PathBuf {
    let launcher = PathBuf::from(env!("CARGO_BIN_EXE_reverie-liteinst-strace"));
    let target = launcher.parent().unwrap();
    [
        target.join("libreverie_liteinst.so"),
        target.join("deps/libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the LiteInst preload cdylib")
}

fn compile_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

#[derive(Debug, Default)]
struct SigreturnHookTimerEvents {
    requests: AtomicU64,
    /// The guest's RCBs from the request to each timer event.
    timer_events: std::sync::Mutex<Vec<u64>>,
}

#[reverie::global_tool]
impl GlobalTool for SigreturnHookTimerEvents {
    /// A timer event's RCBs from its request, or `None` for a request.
    type Request = Option<u64>;
    type Response = ();
    /// The timer's RCBs from each request to its target.
    type Config = u64;

    async fn receive_rpc(&self, _from: Tid, note: Option<u64>) {
        match note {
            None => {
                self.requests.fetch_add(1, Ordering::SeqCst);
            }
            Some(rcbs) => self.timer_events.lock().unwrap().push(rcbs),
        }
    }
}

/// Answers every getpid itself, with 0x4242, and requests a precise timer at
/// a getpid whose first argument is 1. It subscribes nothing else, so the
/// rt_sigreturn of `hybrid_sigreturn_hook_timer.c`'s restorer is a hook trap
/// that makes no Tool callback.
#[derive(Default)]
struct SigreturnHookTimerTool;

#[reverie::tool]
impl Tool for SigreturnHookTimerTool {
    type GlobalState = SigreturnHookTimerEvents;
    /// The guest's RCB clock at the latest request.
    type ThreadState = u64;

    fn subscriptions(_config: &u64) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let (_, args) = syscall.into_parts();
        if args.arg0 == 1 {
            *guest.thread_state_mut() = guest.read_clock()?;
            guest.send_rpc(None).await;
            guest.set_timer_precise(TimerSchedule::Rcbs(*guest.config()))?;
        }
        Ok(0x4242)
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let rcbs = guest.read_clock().unwrap() - *guest.thread_state();
        guest.send_rpc(Some(rcbs)).await;
    }
}

// The rt_sigreturn hook's trap past the target, with the timer's signal
// blocked, so that no notification can deliver the event before the trap.
// Without records the trap, a stop past the period, cancels the event as a
// stop the Tool observes does, and records its delivery point as a skid
// overshoot; the rt_sigreturn trap then retires the event, which must not
// record it a second time. So each round is witnessed exactly once, and
// nothing fires. The notification is queued at the trap, held back by the
// blocked signal, but without records a queued notification cannot be told
// from a lost one, so no witness may be counted as overtaken with its
// notification queued (see
// `reverie_ptrace::testing::precise_events_overtaken_with_notification_queued`).
// No trap keeps an event, so none has its programming checked.
#[test]
fn an_rt_sigreturn_hook_trap_past_the_target_is_witnessed_once() {
    reverie_ptrace::ret_without_perf!();
    with_counts(rt_sigreturn_hook_trap_past_the_target_is_witnessed_once());
}

async fn rt_sigreturn_hook_trap_past_the_target_is_witnessed_once() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    let rcbs = 10_000 + margin;
    let rounds: u64 = 16;
    let (_directory, guest) = compile_fixture("hybrid_sigreturn_hook_timer.c");
    let mut command = Command::new(guest);
    // The handler returns twice the timer's RCBs after its request, with the
    // timer's signal blocked throughout.
    command.args([
        (2 * rcbs).to_string(),
        rounds.to_string(),
        1_000.to_string(),
        1.to_string(),
        0.to_string(),
        1.to_string(),
    ]);
    // The counts are process global; see `COUNTS`.
    let _ = reverie::take_skid_overshoot_count();
    let overtaken_before =
        reverie_ptrace::testing::precise_events_overtaken_with_notification_queued();
    let checks = KeptTimerProgrammingChecks::start();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(120),
        LiteinstBackend::run_host_with_output_and_preload::<SigreturnHookTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the rt_sigreturn hook guest did not complete")
    .unwrap();
    let keeps = checks.keeps();
    let witnesses = reverie::take_skid_overshoot_count();
    let overtaken = reverie_ptrace::testing::precise_events_overtaken_with_notification_queued()
        - overtaken_before;
    assert_eq!(keeps, 0, "no trap here keeps its event");
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rounds={rounds} handled={rounds} wrong=0\n")
    );
    assert_eq!(global.requests.load(Ordering::SeqCst), rounds);
    assert_eq!(
        global.timer_events.into_inner().unwrap(),
        Vec::<u64>::new(),
        "the cancelled timer must not fire"
    );
    assert_eq!(
        witnesses, rounds,
        "each round's trap overtook its due event, and must be witnessed once"
    );
    assert_eq!(
        overtaken, 0,
        "without overflow records no witness may be counted as overtaken with its \
         notification queued"
    );
}

// The rt_sigreturn hook's trap before the keep point, as in
// reverie-liteinst/tests/hybrid.rs's
// `an_rt_sigreturn_hook_trap_keeps_the_timer_event`, without records: each
// handler returns 5000 RCBs after its request for an event 30000 RCBs past
// it, above the largest skid margin in Reverie's PMU table, and the trap
// must keep the event with its PMU programming as the request made it,
// checked at the trap and again at the thread's next stop (see
// `reverie_ptrace::testing::check_kept_timer_programming`). Without records
// the trap reads the guest's clock from the counter alone, so this is the
// check's only coverage of that path.
//
// Every event must fire at its target, or past it only as a witnessed skid
// overshoot. The one exception is the host timing that hybrid.rs's
// `overtaken_rounds` identifies with records: a notification serviced only
// at the next round's signal, which overtakes the kept event past its
// target and witnesses it. Without records a queued notification cannot be
// told from a lost one, so such a round is not listed as overtaken; it is
// missing, and witnessed. At most `MISSING_CAP` rounds may be missing, the
// cap hybrid.rs's `overtaken_cap` gives for the 15 rounds that could be
// overtaken (the last cannot be, since the guest makes no stop between its
// handler's return and its exit), and every witness must be a late event
// or a missing round. Since a lost notification is also a missing round,
// and witnessed, the cap admits as many witnessed losses too.
#[test]
fn an_rt_sigreturn_hook_trap_keeps_the_timer_event_without_records() {
    reverie_ptrace::ret_without_perf!();
    with_counts(rt_sigreturn_hook_trap_keeps_the_timer_event_without_records());
}

async fn rt_sigreturn_hook_trap_keeps_the_timer_event_without_records() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    /// hybrid.rs's `overtaken_cap(15)`.
    const MISSING_CAP: u64 = 2;
    let rcbs: u64 = 30_000;
    let (lead, after) = (5_000, 2 * rcbs);
    let rounds: u64 = 16;
    let (_directory, guest) = compile_fixture("hybrid_sigreturn_hook_timer.c");
    let mut command = Command::new(guest);
    command.args([lead, rounds, after, 1, 0, 0].iter().map(u64::to_string));
    // The counts are process global; see `COUNTS`.
    let _ = reverie::take_skid_overshoot_count();
    let checks = KeptTimerProgrammingChecks::start();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(120),
        LiteinstBackend::run_host_with_output_and_preload::<SigreturnHookTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the rt_sigreturn hook guest did not complete")
    .unwrap();
    let keeps = checks.keeps();
    let witnesses = reverie::take_skid_overshoot_count();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rounds={rounds} handled={rounds} wrong=0\n")
    );
    assert_eq!(global.requests.load(Ordering::SeqCst), rounds);
    assert_eq!(
        keeps, rounds,
        "each round's trap must keep its event, with its programming unchanged"
    );
    let events = global.timer_events.into_inner().unwrap();
    assert!(events.len() as u64 <= rounds, "{events:?}");
    let missing = rounds - events.len() as u64;
    assert!(
        missing <= MISSING_CAP,
        "{missing} of {rounds} kept events did not fire: {events:?}"
    );
    let late = events.iter().filter(|&&clock| clock > rcbs).count() as u64;
    eprintln!(
        "{missing} of {rounds} kept events missing, at most {MISSING_CAP}; {late} of {} fired \
         past the target {rcbs}; {witnesses} witnessed",
        events.len()
    );
    assert_eq!(
        witnesses,
        late + missing,
        "every witness must be a late event or a missing round: {events:?}"
    );
    assert_at_target_unless_witnessed(&events, rcbs, witnesses - missing);
}

/// The restart fixture's descriptors, and the magic read's result once it is
/// no longer restarted, as reverie-liteinst/tests/hybrid.rs's `RestartTool`
/// uses them.
const RESTART_WARM_FD: u64 = 0x7e56;
const RESTART_MAGIC_FD: u64 = 0x7e57;
const RESTART_RESULT: i64 = 4243;

/// hybrid.rs's `SIGNAL_TIMER_NEAR_RCBS`: a timer this far past the deciding
/// signal has its single steps under way at the quiet handler's return when
/// the skid margin is `LANDING_SKID_MARGIN`.
const LANDING_NEAR_RCBS: u64 = 1_000;

/// The skid margin the landing tests' re-runs pin, hybrid.rs's
/// `TIMER_TEST_SKID_MARGIN`. A precise timer single-steps its last `skid
/// margin` RCBs, so at this margin the steps of a timer due
/// `LANDING_NEAR_RCBS` after its request start at the request.
const LANDING_SKID_MARGIN: u64 = LANDING_NEAR_RCBS;

/// Attempts `a_restart_landing_beyond_the_keep_margin_keeps_the_event_without_records`
/// may make when only a witnessed skid overshoot differs, hybrid.rs's
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

/// hybrid.rs's `RestartTool` with the plan of its landing timer tests, and
/// its event names: the first magic read sends the thread SIGUSR1 and returns
/// `ERESTARTSYS`, later ones `RESTART_RESULT`; SIGUSR1's signal event
/// requests a precise timer the configured RCBs ahead; and the timer event
/// reports the RCBs since the request.
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

#[derive(Clone, Copy, Debug)]
enum LandingBackend {
    HostHybrid,
    Ptrace,
}

/// One backend's run of the restart fixture under `LandingTimerTool`.
struct LandingRun {
    stdout: String,
    events: Vec<String>,
    /// Skid overshoots recorded during the run
    /// (`reverie::take_skid_overshoot_count`).
    witnesses: u64,
    /// Restart landings that interrupted a precise timer's single steps,
    /// after which the steps continued
    /// (`reverie_ptrace::testing::liteinst_timer_step_landings_resolved`).
    step_landings: u64,
    /// SIGTRAP stops resumed with nothing claiming them, which a single-step
    /// trap flag left set in the guest produces.
    unclaimed_sigtraps: u64,
    /// Stops that kept the timer's event with its programming unchanged
    /// (`KeptTimerProgrammingChecks::keeps`).
    keeps: u64,
}

/// Runs the restart fixture in `mode` on `backend`, with the timer due `rcbs`
/// after the deciding signal.
async fn run_landing_timer(backend: LandingBackend, mode: &str, rcbs: u64) -> LandingRun {
    let (_directory, guest) = compile_fixture("hybrid_restart.c");
    let mut command = Command::new(guest);
    command.arg(mode);
    // The counts are process global; see `COUNTS`.
    let _ = reverie::take_skid_overshoot_count();
    let step_landings = reverie_ptrace::testing::liteinst_timer_step_landings_resolved();
    let unclaimed_sigtraps = reverie_ptrace::testing::unclaimed_sigtraps_suppressed();
    let checks = KeptTimerProgrammingChecks::start();
    let run = async {
        Ok::<_, Error>(match backend {
            LandingBackend::HostHybrid => {
                LiteinstBackend::run_host_with_output_and_preload::<LandingTimerTool>(
                    command,
                    rcbs,
                    preload_path(),
                )
                .await?
            }
            LandingBackend::Ptrace => {
                command
                    .stdout(reverie::process::Stdio::piped())
                    .stderr(reverie::process::Stdio::piped());
                reverie_ptrace::TracerBuilder::<LandingTimerTool>::new(command)
                    .config(rcbs)
                    .spawn()
                    .await?
                    .wait_with_output()
                    .await?
            }
        })
    };
    let (output, log) = tokio::time::timeout(Duration::from_secs(120), run)
        .await
        .unwrap_or_else(|_| panic!("the {backend:?} {mode} guest did not complete"))
        .unwrap();
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "{backend:?} {mode}: {output:?}"
    );
    LandingRun {
        stdout: String::from_utf8(output.stdout).unwrap(),
        events: log.events.into_inner().unwrap(),
        witnesses: reverie::take_skid_overshoot_count(),
        step_landings: reverie_ptrace::testing::liteinst_timer_step_landings_resolved()
            - step_landings,
        unclaimed_sigtraps: reverie_ptrace::testing::unclaimed_sigtraps_suppressed()
            - unclaimed_sigtraps,
        keeps: checks.keeps(),
    }
}

/// The fixture's output for a read that returned `result`, with the site
/// counters host-hybrid prints for the magic read's single hook entry, or
/// those plain ptrace prints.
fn landing_stdout(backend: LandingBackend, result: i64) -> String {
    let counts = match backend {
        LandingBackend::HostHybrid => "traps=1 hooks=1",
        LandingBackend::Ptrace => "traps=- hooks=-",
    };
    format!("read-result={result} handled=1 nested-ok=0 {counts}\n")
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
const LANDING_IN_STEPS_TEST: &str =
    "a_restart_landing_inside_the_timer_steps_cancels_the_event_without_records";

// hybrid.rs's `host_hybrid_landing_inside_a_timer_step_window_keeps_the_timer`
// without records, at the skid margin `LANDING_SKID_MARGIN`, which needs a
// process of its own. The signal that decides the restart requests a timer
// `LANDING_NEAR_RCBS` ahead, whose single steps start at the request, so the
// quiet handler's return, and the restart landing after it, come inside them.
// The handler makes no syscall, and its restorer's rt_sigreturn is never a
// LiteInst site, since seccomp always allows it, so the landing is the first
// stop after the request.
//
// Without records a stop within `PmuConfig::keep_margin` of a precise
// event's target cancels the event, and a stop inside its single steps always
// is, so the landing cancels the event. Nothing fires; nothing is witnessed,
// since the landing comes before the target; no landing has the steps
// continue after it; no stop keeps the event; and no single-step trap flag is
// left set. This is a documented departure from plain ptrace, which has no
// stop between the signal's delivery and the timer: there an interrupted read
// returns to the guest, and the event fires at its target in the spin loop
// after it. The test measures plain ptrace in the same run. Its steps start at
// the request, so no skid can carry it past the target. A restarted read
// re-enters the Tool at a stop on both backends, and neither fires, so there
// the departure shows only in the steps not continuing past the landing.
//
// Whether a landing keeps or cancels the event thus depends on whether the
// host maps overflow records, which
// https://github.com/rrnewton/reverie/issues/744 tracks for every stop
// without a Tool callback.
#[test]
fn a_restart_landing_inside_the_timer_steps_cancels_the_event_without_records() {
    reverie_ptrace::ret_without_perf!();
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            // The re-run's output, with each run's counts.
            eprint!(
                "{}",
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[LANDING_IN_STEPS_TEST, "--exact"],
                    LANDING_SKID_MARGIN,
                    1,
                    Duration::from_secs(300),
                )
            );
        }
        Some(_) => with_counts(restart_landing_inside_the_timer_steps_cancels_the_event()),
    }
}

async fn restart_landing_inside_the_timer_steps_cancels_the_event() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    for (mode, result, ptrace_last) in [
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
        let ptrace = run_landing_timer(LandingBackend::Ptrace, mode, LANDING_NEAR_RCBS).await;
        let hybrid = run_landing_timer(LandingBackend::HostHybrid, mode, LANDING_NEAR_RCBS).await;
        let restarted = result == RESTART_RESULT;
        assert_eq!(
            ptrace.stdout,
            landing_stdout(LandingBackend::Ptrace, result),
            "{mode}: plain ptrace"
        );
        assert_eq!(
            hybrid.stdout,
            landing_stdout(LandingBackend::HostHybrid, result),
            "{mode}: host-hybrid"
        );
        assert_eq!(
            ptrace.events,
            landing_events(Some(ptrace_last)),
            "{mode}: plain ptrace has no stop before the timer, unless the read restarts"
        );
        assert_eq!(
            hybrid.events,
            landing_events(restarted.then(|| "magic read(0x7e57,1)".to_owned())),
            "{mode}: without records the landing must cancel the event"
        );
        assert_eq!(
            (ptrace.witnesses, hybrid.witnesses),
            (0, 0),
            "{mode}: no skid overshoot may be witnessed (plain ptrace, host-hybrid)"
        );
        assert_eq!(
            hybrid.step_landings, 0,
            "{mode}: without records no single steps may continue past the landing"
        );
        assert_eq!(
            (ptrace.keeps, hybrid.keeps),
            (0, 0),
            "{mode}: no stop keeps the event (plain ptrace, host-hybrid)"
        );
        assert_eq!(
            (ptrace.unclaimed_sigtraps, hybrid.unclaimed_sigtraps),
            (0, 0),
            "{mode}: unclaimed SIGTRAP stops resumed (plain ptrace, host-hybrid); a \
             single-step trap flag was left set"
        );
    }
}

/// This test's name, which its re-run selects.
const LANDING_KEPT_TEST: &str =
    "a_restart_landing_beyond_the_keep_margin_keeps_the_event_without_records";

// As above, with the timer due `PmuConfig::keep_margin` plus twice
// `LANDING_NEAR_RCBS` after the deciding signal. The landing comes within
// `LANDING_NEAR_RCBS` of the request, as the case above shows, so more than
// the keep margin short of the target, and the landing keeps the event, with
// its programming as the request made it, checked at the landing and again at
// the thread's next stop. The interrupted read then spins past the target,
// and the event must fire at exactly its target on both backends. A witnessed
// skid overshoot that makes one backend's event fire late is retried, up to
// `SKID_ATTEMPTS`, as hybrid.rs's `timer_restart_parity` retries it; any other
// difference fails at once. Only the interrupted read is covered: a restarted
// read re-enters the Tool at a stop on both backends, which cancels the event
// before its target whatever the landing did.
#[test]
fn a_restart_landing_beyond_the_keep_margin_keeps_the_event_without_records() {
    reverie_ptrace::ret_without_perf!();
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            // The re-run's output, with each run's counts.
            eprint!(
                "{}",
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[LANDING_KEPT_TEST, "--exact"],
                    LANDING_SKID_MARGIN,
                    1,
                    Duration::from_secs(300),
                )
            );
        }
        Some(_) => with_counts(restart_landing_beyond_the_keep_margin_keeps_the_event()),
    }
}

async fn restart_landing_beyond_the_keep_margin_keeps_the_event() {
    reverie_ptrace::testing::disable_timer_overflow_records();
    let mode = "handler-quiet-spin";
    let rcbs = reverie_ptrace::PmuConfig::new().keep_margin() + 2 * LANDING_NEAR_RCBS;
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
        let ptrace = run_landing_timer(LandingBackend::Ptrace, mode, rcbs).await;
        let hybrid = run_landing_timer(LandingBackend::HostHybrid, mode, rcbs).await;
        let context = format!(
            "attempt {attempt}, timer {rcbs} RCBs ahead, skid overshoots: plain ptrace {}, \
             host-hybrid {}",
            ptrace.witnesses, hybrid.witnesses
        );
        assert_eq!(
            ptrace.stdout,
            landing_stdout(LandingBackend::Ptrace, -4),
            "{context}: plain ptrace"
        );
        assert_eq!(
            hybrid.stdout,
            landing_stdout(LandingBackend::HostHybrid, -4),
            "{context}: host-hybrid"
        );
        assert_eq!(
            hybrid.step_landings, 0,
            "{context}: the landing comes before the timer's single steps"
        );
        assert_eq!(
            (ptrace.keeps, hybrid.keeps),
            (0, 1),
            "{context}: the landing, and nothing else, must keep the event, with its \
             programming unchanged (plain ptrace, host-hybrid)"
        );
        assert_eq!(
            (ptrace.unclaimed_sigtraps, hybrid.unclaimed_sigtraps),
            (0, 0),
            "{context}: unclaimed SIGTRAP stops resumed (plain ptrace, host-hybrid); a \
             single-step trap flag was left set"
        );
        if ptrace.events == expected && hybrid.events == expected {
            assert_eq!(
                (ptrace.witnesses, hybrid.witnesses),
                (0, 0),
                "{context}: an event that fired at its target cannot be a skid overshoot"
            );
            return;
        }
        if attempt < SKID_ATTEMPTS && explained(&ptrace) && explained(&hybrid) {
            eprintln!(
                "{context}: only a witnessed late timer event differs (plain ptrace {:?}, \
                 host-hybrid {:?}); retrying",
                ptrace.events, hybrid.events
            );
            continue;
        }
        assert_eq!(
            ptrace.events, expected,
            "{context}: plain ptrace must fire the event at its target"
        );
        assert_eq!(
            hybrid.events, expected,
            "{context}: the landing must keep the event, which must fire at its target"
        );
    }
    unreachable!("the last attempt returns or fails an assertion")
}
