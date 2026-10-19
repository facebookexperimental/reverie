/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Plain ptrace regression checks on real guests.
//!
//! Two fixtures run under plain ptrace with a recording Tool:
//!
//! - `tests/fixtures/plain_fork_vfork_exec.c` forks, vforks, raises a signal
//!   and execs itself. Its runs are checked for every stop class, for the
//!   PID-bearing return values the Tool sees, and for being repeatable PID
//!   for PID in a fresh PID namespace.
//! - `tests/fixtures/plain_guest_regression.c` runs one mode per test and
//!   reports its results, registers and signal frames to a file. Each test
//!   checks that report, the stop sequence, the signal-delivery stops and the
//!   Tool-visible events of the plain run.
//!
//! The stop sequence is the tracer's run-loop waits (the stops that
//! `record_wait` sees). Stops consumed inside `inject`, `tail_inject` or
//! single-step paths are not recorded.
//!
//! These are the plain ptrace arms of the deleted trap-only LiteInst parity
//! tests, which compared each of these runs with a run of the deleted
//! backend; the plain assertions are kept as they were.

use std::collections::BTreeMap;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::sync::Mutex;

use reverie::Guest;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;

use super::*;
use crate::PtraceBackendStatsSnapshot;

fn tempfile_path(label: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Fixed width: a guest that opens this path executes a number of
    // branches that depends on its length.
    let path = std::env::temp_dir().join(format!(
        "reverie-{label}-{}-{serial:08}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[derive(Default)]
struct Log(Mutex<Vec<(Pid, String)>>);

#[reverie::global_tool]
impl GlobalTool for Log {
    /// `true` records every syscall's return value (through `inject`);
    /// `false` behaves as the default Tool (through `tail_inject`).
    type Config = bool;
    type Request = String;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, event: String) {
        self.0.lock().unwrap().push((from, event));
    }
}

/// Records every Tool-visible event. With the default configuration it
/// otherwise behaves as the default Tool; with `true` it also records each
/// syscall's return value.
#[derive(Default)]
struct RecordTool;

#[reverie::tool]
impl Tool for RecordTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &bool) -> Subscription {
        Subscription::all()
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        guest.send_rpc("thread-start".to_owned()).await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc("post-exec".to_owned()).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        // exit and a successful execve never return a value to the caller.
        let no_return = matches!(
            call,
            Syscall::Exit(_) | Syscall::ExitGroup(_) | Syscall::Execve(_) | Syscall::Execveat(_)
        );
        if !*guest.config() || no_return {
            guest.send_rpc(format!("syscall {}", call.number())).await;
            guest.tail_inject(call).await
        } else {
            let result = guest.inject(call).await;
            let value = match result {
                Ok(value) => value,
                Err(errno) => -i64::from(errno.into_raw()),
            };
            guest
                .send_rpc(format!("syscall {} = {value}", call.number()))
                .await;
            Ok(result?)
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        guest.send_rpc(format!("signal {signal:?}")).await;
        Ok(Some(signal))
    }
}

/// Names a prebuilt fork/vfork/exec guest for a re-executed namespace arm.
const FORK_VFORK_EXEC_GUEST_ENV: &str = "REVERIE_PLAIN_FORK_VFORK_EXEC_GUEST";

fn fork_vfork_exec_guest() -> &'static std::path::Path {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        if let Some(prebuilt) = std::env::var_os(FORK_VFORK_EXEC_GUEST_ENV) {
            return PathBuf::from(prebuilt);
        }
        let source = crate::tracer::tests::fixture("plain_fork_vfork_exec.c");
        // One fixture beside the test binary, inside the build tree, rather
        // than one leaked file per test process under /tmp. Each process
        // compiles its own copy and renames it into place, so the source is
        // never stale and a concurrent process still running the previous
        // copy keeps its inode.
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        let output = directory.join("reverie-plain-fork-vfork-exec");
        let staging = directory.join(format!(
            "reverie-plain-fork-vfork-exec.{}.tmp",
            std::process::id()
        ));
        let status = std::process::Command::new("cc")
            .args(["-O0", "-g"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .expect("invoke cc for the fork/vfork/exec fixture");
        assert!(status.success(), "compile {}", source.display());
        std::fs::rename(&staging, &output).expect("publish the fork/vfork/exec fixture");
        output
    });
    GUEST.as_path()
}

/// Syscalls whose positive return value is a PID or TID, by the name the
/// Tool records.
const PID_RETURNING: [&str; 8] = [
    "getpid",
    "gettid",
    "set_tid_address",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "wait4",
];

/// How a trace names the tasks and PID values it contains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Identity {
    /// Run in the host PID namespace: PIDs differ from run to run, so each
    /// traced PID, wherever it appears, is renamed `task#N` in order of first
    /// appearance. The relation between tasks and PID values is kept.
    Renamed,
    /// Run in a fresh PID namespace: PIDs are compared exactly.
    Exact,
}

/// Renames the traced PIDs in a stop trace and a Tool event trace, and groups
/// both per task.
struct TaskNames(BTreeMap<Pid, String>);

impl TaskNames {
    fn new(identity: Identity, stops: &[(Pid, String)]) -> Self {
        let mut names = BTreeMap::new();
        for (pid, _) in stops {
            let next = names.len();
            names.entry(*pid).or_insert_with(|| match identity {
                Identity::Renamed => format!("task#{next}"),
                Identity::Exact => format!("pid {pid}"),
            });
        }
        Self(names)
    }

    fn name(&self, pid: Pid) -> String {
        self.0
            .get(&pid)
            .cloned()
            .unwrap_or_else(|| format!("untraced pid {pid}"))
    }

    fn value(&self, raw: &str) -> String {
        match raw.parse::<i32>() {
            Ok(value) if value > 0 => self
                .0
                .get(&Pid::from_raw(value))
                .cloned()
                .unwrap_or_else(|| raw.to_owned()),
            _ => raw.to_owned(),
        }
    }

    /// Replaces PID values inside one event. In [`Identity::Exact`] mode the
    /// names are the PIDs themselves, so only the spelling changes.
    fn event(&self, event: &str) -> String {
        if let Some((operation, pid)) = event
            .strip_prefix("new-child ")
            .and_then(|rest| rest.rsplit_once(' '))
        {
            return format!("new-child {operation} {}", self.value(pid));
        }
        if let Some((number, value)) = event
            .strip_prefix("syscall ")
            .and_then(|rest| rest.split_once(" = "))
            && PID_RETURNING.contains(&number)
        {
            return format!("syscall {number} = {}", self.value(value));
        }
        event.to_owned()
    }

    fn per_task(&self, trace: Vec<(Pid, String)>) -> BTreeMap<String, Vec<String>> {
        let mut tasks = BTreeMap::<String, Vec<String>>::new();
        for (pid, event) in trace {
            tasks
                .entry(self.name(pid))
                .or_default()
                .push(self.event(&event));
        }
        tasks
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Observed {
    status: ExitStatus,
    /// Name of the first task the tracer saw.
    root: String,
    tool_events: BTreeMap<String, Vec<String>>,
    stops: BTreeMap<String, Vec<String>>,
    counts: PtraceBackendStatsSnapshot,
}

async fn run_fork_vfork_exec_guest(record_values: bool, identity: Identity) -> Observed {
    let tracer = TracerBuilder::<RecordTool>::new(Command::new(fork_vfork_exec_guest()))
        .config(record_values)
        .backend_stats(BackendStatsRequest::ENABLED)
        .spawn()
        .await
        .expect("spawn the fork/vfork/exec guest");
    let stats = tracer.backend_stats().expect("stats were requested");
    let (status, log) = tokio::time::timeout(Duration::from_secs(20), tracer.wait())
        .await
        .expect("fork/vfork/exec guest timed out")
        .expect("fork/vfork/exec guest run failed");
    let stop_trace = stats.stop_trace();
    let names = TaskNames::new(identity, &stop_trace);
    let root = names.name(stop_trace.first().expect("no stop was recorded").0);
    Observed {
        status,
        root,
        tool_events: names.per_task(std::mem::take(&mut *log.0.lock().unwrap())),
        stops: names.per_task(stop_trace),
        counts: reverie::BackendStatsSource::backend_stats(&stats),
    }
}

/// Checks that a plain-ptrace run of the fork/vfork/exec guest has every
/// class of stop and Tool event the guest exercises, so that a comparison
/// against it is not vacuous.
///
/// With `record_values`, the Tool resumes syscalls through `inject`, which
/// consumes the fork and vfork event stops itself, so the run loop never sees
/// them; the children's identities are then required in the return values.
fn assert_baseline_is_not_vacuous(
    ptrace: &Observed,
    record_values: bool,
    root: &str,
    fork: &str,
    vfork: &str,
) {
    assert_eq!(ptrace.status, ExitStatus::Exited(0));
    assert_eq!(ptrace.root, root);
    let all_stops = ptrace.stops.values().flatten().collect::<Vec<_>>();
    let required_stops = if record_values {
        vec!["exec".to_owned(), "Signal(SIGUSR1)".to_owned()]
    } else {
        vec![
            "exec".to_owned(),
            format!("new-child Fork {fork}"),
            format!("new-child Vfork {vfork}"),
            // The parent is still inside the tail-injected vfork, with the
            // entry's -ENOSYS in rax.
            "VforkDone rax=-38".to_owned(),
            "Signal(SIGUSR1)".to_owned(),
        ]
    };
    for required in required_stops {
        assert!(
            all_stops.iter().any(|stop| **stop == required),
            "plain-ptrace baseline lacks a {required} stop: {all_stops:?}"
        );
    }
    let seccomp_stops = all_stops
        .iter()
        .filter(|stop| stop.starts_with("seccomp "))
        .count();
    assert!(
        seccomp_stops > 50,
        "baseline has only {seccomp_stops} seccomp stops"
    );
    // The fixture keeps SIGCHLD blocked from before each fork and vfork until
    // after the matching waitpid, so each child's SIGCHLD is delivered at a
    // fixed point: when the rt_sigprocmask that follows the parent's wait4
    // restores the old mask, never before the wait4.
    let root_stops = ptrace
        .stops
        .get(root)
        .unwrap_or_else(|| panic!("no stop sequence for root {root}"));
    let sigchld_stops = root_stops
        .iter()
        .filter(|stop| *stop == "Signal(SIGCHLD)")
        .count();
    let sigchld_after_wait4 = root_stops
        .windows(3)
        .filter(|stops| stops == &["seccomp 61", "seccomp 14", "Signal(SIGCHLD)"])
        .count();
    assert_eq!(
        (sigchld_stops, sigchld_after_wait4),
        (2, 2),
        "root's two SIGCHLD stops must each follow its wait4 and unblock stops: {root_stops:?}"
    );
    let mut expected_tasks = vec![root.to_owned(), fork.to_owned(), vfork.to_owned()];
    expected_tasks.sort();
    assert_eq!(
        ptrace.stops.keys().cloned().collect::<Vec<_>>(),
        expected_tasks,
        "root, fork child, and vfork child each own a stop sequence"
    );
    let all_events = ptrace.tool_events.values().flatten().collect::<Vec<_>>();
    assert!(all_events.iter().any(|event| *event == "post-exec"));
    assert!(all_events.iter().any(|event| *event == "signal SIGUSR1"));
    if record_values {
        let values = all_events
            .iter()
            .filter(|event| event.contains(" = "))
            .count();
        assert!(values > 50, "only {values} syscall return values recorded");
        let root_events = &ptrace.tool_events[root];
        for expected in [
            format!("syscall set_tid_address = {root}"),
            format!("syscall getpid = {root}"),
            format!("syscall gettid = {root}"),
            format!("syscall clone = {fork}"),
            format!("syscall wait4 = {fork}"),
            format!("syscall vfork = {vfork}"),
            format!("syscall wait4 = {vfork}"),
        ] {
            assert!(
                root_events.contains(&expected),
                "root lacks {expected}: {root_events:?}"
            );
        }
    }
}

/// A plain ptrace run of the fork/vfork/exec guest with the default
/// (tail-injecting) Tool has its fork, vfork and exec stops, the vfork-done
/// stop with the entry's -ENOSYS in rax, the delivered SIGUSR1, each child's
/// SIGCHLD right after the parent's wait4 and unblock, and a stop sequence
/// for each of its three tasks.
#[tokio::test(flavor = "current_thread")]
async fn plain_fork_vfork_exec_run_has_every_stop_class() {
    let ptrace = run_fork_vfork_exec_guest(false, Identity::Renamed).await;
    assert_baseline_is_not_vacuous(&ptrace, false, "task#0", "task#1", "task#2");
}

/// The same run with every syscall's return value recorded: the root's
/// set_tid_address, getpid, gettid, clone, vfork and wait4 return the PIDs of
/// the tasks the tracer saw. PID values are renamed consistently with task
/// identity, because host PIDs differ between runs.
#[tokio::test(flavor = "current_thread")]
async fn plain_fork_vfork_exec_run_returns_the_traced_pids() {
    let ptrace = run_fork_vfork_exec_guest(true, Identity::Renamed).await;
    assert_baseline_is_not_vacuous(&ptrace, true, "task#0", "task#1", "task#2");
}

/// Selects the arm a re-executed namespace child runs.
const NAMESPACE_ARM_ENV: &str = "REVERIE_PLAIN_NAMESPACE_ARM";
const NAMESPACE_MARK: &str = "@@plain-namespace-arm@@ ";

/// Runs one arm in a fresh user, PID and mount namespace with its own /proc,
/// the way Hermit runs the tracer, and returns the child's printed record.
fn run_arm_in_fresh_pid_namespace(test_name: &str, arm: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut child = std::process::Command::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(NAMESPACE_ARM_ENV, arm)
        .env(FORK_VFORK_EXEC_GUEST_ENV, fork_vfork_exec_guest())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn /usr/bin/unshare");
    // Drain both pipes while the child runs. Once the user's pipe pages pass
    // fs.pipe-user-pages-soft, a new pipe holds only 8 KiB, and a child
    // blocked writing a longer record would never exit.
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).expect("read the arm's output");
            bytes
        })
    }
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{arm} arm in a fresh PID namespace exceeded 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        status.success(),
        "{arm} arm in a fresh PID namespace failed ({status}):\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&stderr)
    );
    let record = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(NAMESPACE_MARK))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!record.is_empty(), "{arm} arm printed no record:\n{stdout}");
    record
}

/// Two plain ptrace runs of the fork/vfork/exec guest, each in its own fresh
/// PID namespace, are exactly equal: exit status, root, every Tool event and
/// return value (PIDs included, compared exactly), every stop, and the stop
/// counts. Each run also passes the baseline checks with its exact
/// namespace PIDs.
#[test]
fn plain_ptrace_repeats_pid_for_pid_in_a_fresh_pid_namespace() {
    if let Ok(arm) = std::env::var(NAMESPACE_ARM_ENV) {
        assert_eq!(arm, "ptrace", "unknown arm {arm}");
        let observed = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_fork_vfork_exec_guest(true, Identity::Exact));
        // PIDs in a fresh namespace are small and increase without wrapping,
        // so the fork child precedes the vfork child.
        let mut children = observed
            .stops
            .keys()
            .filter(|task| **task != observed.root)
            .cloned()
            .collect::<Vec<_>>();
        children.sort_by_key(|task| task["pid ".len()..].parse::<i32>().unwrap());
        let [fork, vfork] = children.as_slice() else {
            panic!("expected exactly two children: {children:?}");
        };
        assert_baseline_is_not_vacuous(&observed, true, &observed.root, fork, vfork);
        // libtest has already printed "test <name> ... " without a newline.
        println!("\n{NAMESPACE_MARK}{observed:?}");
        return;
    }
    let module = module_path!()
        .split_once("::")
        .map(|(_, rest)| rest)
        .unwrap();
    let test_name = format!("{module}::plain_ptrace_repeats_pid_for_pid_in_a_fresh_pid_namespace");
    let ptrace = run_arm_in_fresh_pid_namespace(&test_name, "ptrace");
    let ptrace_again = run_arm_in_fresh_pid_namespace(&test_name, "ptrace");
    assert!(
        ptrace.contains("root: \"pid ") && ptrace.contains("\"syscall clone = pid "),
        "record lacks PID-bearing values: {ptrace}"
    );
    assert_eq!(
        ptrace_again, ptrace,
        "plain ptrace is not repeatable in a fresh namespace"
    );
}

const TP_MAGIC: u64 = 0x7e57_0000_0000_0000;
const TP_MAGIC_MASK: u64 = 0xffff_0000_0000_0000;
const SHAPE_INJECT: u64 = 0;
const SHAPE_TAIL: u64 = 1;
const SHAPE_EMULATE: u64 = 2;
const SHAPE_PRIVATE: u64 = 3;
const SHAPE_TWO_INJECTS: u64 = 4;
const SHAPE_TWO_PRIVATE: u64 = 5;
/// Blocks every signal with an injected `rt_sigprocmask`, injects the call,
/// and restores the mask, as Detcore's disposition check
/// (`block_signals_for_disposition`) brackets its calls.
const SHAPE_BLOCK_ALL: u64 = 6;
/// Injects a getpid first, which takes the pending syscall's place, then the
/// call itself, which therefore runs on the private page, single-stepped.
const SHAPE_PRIVATE_CALL: u64 = 7;
/// Injects a `ppoll` of no descriptors with a zero timeout and an empty
/// temporary mask, which a pending signal the guest blocks interrupts (the
/// signal is held and the mask's restore left pending), then the call itself
/// on the private page, through the held-signal retry
/// (`Guest::inject_with_retry`).
const SHAPE_PPOLL_THEN_CALL: u64 = 8;
const SEND_SIGUSR1: u64 = 0x100;
const SEND_SIGWINCH: u64 = 0x200;
const SEND_QUEUE: u64 = 0x400;
/// The tracer leaves SIGUSR1 pending for its final resume of the stop.
const SEND_RESUME: u64 = 0x800;
/// The Tool requests a precise timer of r8 (the fifth argument) branches.
const ARM_TIMER: u64 = 0x1000;
/// The Tool sends SIGSTOP to the calling thread while it is parked.
const SEND_SIGSTOP: u64 = 0x2000;
/// The Tool checks that `Guest::ppid` equals the tagged `getppid`'s kernel
/// result.
const CHECK_KERNEL_PPID: u64 = 0x8000;
/// The Tool notifies the guest's parent again (SIGUSR2) when the kernel
/// restarts the call.
const NOTIFY_AGAIN: u64 = 0x4000;
/// Bits 32-36: a signal the parent sends when the Tool, at the call's seccomp
/// stop, notifies it; the Tool waits until the signal has arrived.
const TOOL_PARK_SHIFT: u32 = 32;
/// Bit 38: after the call's inject returned, the Tool notifies the parent,
/// waits until its SIGCONT has arrived, then queues SIGSTOP (SI_QUEUE, value 7)
/// to the thread.
const TOOL_AFTER_CONT: u64 = 0x40 << TOOL_PARK_SHIFT;
/// Bits 40-44: the same as the Tool's park signal, from the pre-syscall hook
/// (immediately before the call runs), at its `Early` point unless
/// `HOOK_LATE`.
const HOOK_PARK_SHIFT: u32 = 40;
/// Bit 45: the hook parks at its `Late` point.
const HOOK_LATE: u64 = 0x20 << HOOK_PARK_SHIFT;
/// Bit 46: at its `Early` point the hook sends SIGSTOP to the process (the
/// shared queue) and to the thread (its private queue).
const HOOK_SEND_STOPS: u64 = 0x40 << HOOK_PARK_SHIFT;
/// Bit 47: at its `Early` point the hook sends SIGKILL to the process and
/// returns at once; at its `Late` point it waits until the kill has taken
/// effect and stays parked.
const HOOK_KILL: u64 = 0x80 << HOOK_PARK_SHIFT;

/// The regression Tool's configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
struct GuestConfig {
    /// Resumes untagged syscalls through `tail_inject`; otherwise runs them
    /// through `inject` and records each return value.
    tail: bool,
    /// Leaves getuid unsubscribed, so the subscription is partial.
    partial: bool,
    /// Observes sigreturns (`Tool::observes_sigreturns`), recording each
    /// report in `SIGRETURN_REPORTS`.
    sigreturns: bool,
    /// Declares a serialized-execution contract
    /// (`Tool::enforces_serialized_execution`), as Hermit's Tool does, so that
    /// Reverie keeps the guest's SIGTRAP state across its steps. This Tool
    /// does not enforce it: the tests run guest threads at once, and install
    /// guest filters, to exercise the repair beyond the contract.
    serialized: bool,
}

/// The `rt_sigreturn` reports the regression Tool was given, as (thread,
/// frame). Only the tests that observe sigreturns add to it, each while
/// holding `SIGRETURN_TESTS`.
static SIGRETURN_REPORTS: Mutex<Vec<(i32, reverie::SigreturnFrame)>> = Mutex::new(Vec::new());

/// Held by each test that observes sigreturns for its whole run, so that
/// tests run in one process (plain `cargo test`) never share
/// `SIGRETURN_REPORTS`.
static SIGRETURN_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct GuestLog(Mutex<Vec<(Pid, String)>>);

#[reverie::global_tool]
impl GlobalTool for GuestLog {
    type Config = GuestConfig;
    type Request = String;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, event: String) {
        self.0.lock().unwrap().push((from, event));
    }
}

/// Single-step count of each tid when its thread started.
static STEP_BASE: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// Stepped-seccomp count of each tid at its thread start or its latest
/// syscall entry, whichever is later.
static STEPPED_SEEN: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// Prefixes the Tool's report of a syscall entry that a timer single-step
/// reached. `run_guest_options` moves these reports out of `tool_events`
/// into `stepped_entries`.
const STEPPED_ENTRY_PREFIX: &str = "stepped-entry ";
/// The last tagged call (sequence number) each tid acted on, so that a call
/// the kernel restarts does not send its signals again.
static ACTED: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// The restarted tagged calls (tid, sequence) the Tool notified the parent of.
static NOTIFIED: Mutex<std::collections::BTreeSet<(i32, u64)>> =
    Mutex::new(std::collections::BTreeSet::new());

/// The tracer's single-step requests for `tid` since its thread started.
fn steps(tid: Pid) -> u64 {
    let base = STEP_BASE
        .lock()
        .unwrap()
        .get(&tid.as_raw())
        .copied()
        .unwrap_or(0);
    crate::task::step_count_for_test(tid) - base
}

/// Names an address: the fixture is linked -no-pie, so its own text is at
/// the same address in every run, as is the private page. Library and stack
/// addresses are not, and are only reported as `other`.
fn code(address: u64) -> String {
    let page = crate::cp::PRIVATE_PAGE_OFFSET as u64;
    if (0x40_0000..0x100_0000).contains(&address) {
        format!("{address:#x}")
    } else if (page..page + 0x1000).contains(&address) {
        format!("page+{:#x}", address - page)
    } else {
        "other".to_owned()
    }
}

/// Renders a register value that may hold a return value.
fn value(raw: u64, pid: Pid) -> String {
    let signed = raw as i64;
    if signed == i64::from(pid.as_raw()) {
        "<pid>".to_owned()
    } else if signed.unsigned_abs() >= 1 << 32 {
        "pointer".to_owned()
    } else {
        signed.to_string()
    }
}

fn send_queued(pid: Pid, tid: Pid, signal: i32, value: i32, thread: bool) {
    // A kernel siginfo: signo at 0, code at 8 (SI_QUEUE), pid at 16, uid at
    // 20 and the value at 24.
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&signal.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    info[16..20].copy_from_slice(&std::process::id().to_ne_bytes());
    info[20..24].copy_from_slice(&unsafe { libc::getuid() }.to_ne_bytes());
    info[24..28].copy_from_slice(&value.to_ne_bytes());
    let result = unsafe {
        if thread {
            libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                pid.as_raw(),
                tid.as_raw(),
                signal,
                info.as_ptr(),
            )
        } else {
            libc::syscall(
                libc::SYS_rt_sigqueueinfo,
                pid.as_raw(),
                signal,
                info.as_ptr(),
            )
        }
    };
    assert_eq!(result, 0, "queue signal {signal}");
}

fn tgkill(pid: Pid, tid: Pid, signal: i32) {
    let result = unsafe { libc::syscall(libc::SYS_tgkill, pid.as_raw(), tid.as_raw(), signal) };
    assert_eq!(result, 0, "tgkill {signal}");
}

/// Sends the signals a tagged call asks for, while it is parked at its stop.
fn send_signals(pid: Pid, tid: Pid, action: u64) {
    if action & SEND_SIGUSR1 != 0 {
        tgkill(pid, tid, libc::SIGUSR1);
    }
    if action & SEND_SIGWINCH != 0 {
        tgkill(pid, tid, libc::SIGWINCH);
    }
    if action & SEND_SIGSTOP != 0 {
        tgkill(pid, tid, libc::SIGSTOP);
    }
    if action & SEND_QUEUE != 0 {
        // Standard signals only: the ptrace backend cannot handle a
        // real-time signal stop.
        send_queued(pid, tid, libc::SIGUSR1, 1, true);
        send_queued(pid, tid, libc::SIGUSR2, 2, false);
        send_queued(pid, tid, libc::SIGHUP, 3, false);
        tgkill(pid, tid, libc::SIGALRM);
        assert_eq!(unsafe { libc::kill(pid.as_raw(), libc::SIGURG) }, 0);
        // Coalesces with the pending SIGUSR1.
        send_queued(pid, tid, libc::SIGUSR1, 5, true);
    }
}

/// A field of `/proc/<tid>/status`, if the thread still exists.
fn proc_status_field(tid: Pid, field: &str) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|value| value.trim().to_owned())
}

/// Notifies the (traced) parent of process `pid` with SIGUSR2.
fn notify_parent(pid: Pid) {
    let ppid: i32 = proc_status_field(pid, "PPid:")
        .expect("the parked guest exists")
        .parse()
        .expect("a PPid");
    let ppid = Pid::from_raw(ppid);
    tgkill(ppid, ppid, libc::SIGUSR2);
}

/// Whether a SIGKILL has arrived at thread `tid` and taken effect.
///
/// A pending SIGKILL is not enough: the killed thread leaves its ptrace stop
/// and, with PTRACE_O_TRACEEXIT, stops again at PTRACE_EVENT_EXIT, with the
/// entry registers. A ptrace request the tracer makes in between fails with
/// ESRCH, one made after it succeeds. The kill has taken effect once the
/// thread is a zombie or gone, or is in a tracing stop again with its private
/// SIGKILL dequeued (the process-wide bit stays set until the process is
/// reaped). A Tool handler or hook parked on a SIGKILL does not return after
/// this (see their callers): the exit then races the handler inside the
/// tracer, whatever this function observes.
///
/// Each field is a separate read of `/proc/<tid>/status`, so the reads are
/// ordered to be sound across the gaps: the process-wide bit first (the kill
/// has been sent; the kernel sets both bits under one lock), then the private
/// bit (clear now means dequeued, so the thread has left the stop it was in),
/// then the state (a tracing stop now must be the exit stop).
fn kill_took_effect(tid: Pid) -> bool {
    let state = proc_status_field(tid, "State:");
    if state
        .as_deref()
        .is_none_or(|state| state.starts_with('Z') || state.starts_with('X'))
    {
        return true;
    }
    let bit = 1u64 << (libc::SIGKILL - 1);
    let pending = |field: &str| {
        proc_status_field(tid, field)
            .and_then(|mask| u64::from_str_radix(&mask, 16).ok())
            .is_some_and(|mask| mask & bit != 0)
    };
    pending("ShdPnd:")
        && !pending("SigPnd:")
        && proc_status_field(tid, "State:").is_some_and(|state| {
            state.starts_with('t') || state.starts_with('Z') || state.starts_with('X')
        })
}

/// The private and shared pending signals of thread `tid`, from one read.
fn pending_masks(tid: Pid) -> (u64, u64) {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))
        .unwrap_or_else(|error| panic!("read the status of parked thread {tid}: {error}"));
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .unwrap_or_else(|| panic!("no {name} for {tid}"))
    };
    (field("SigPnd:"), field("ShdPnd:"))
}

/// Waits, without blocking the tracer's other tasks, until `arrived`.
async fn wait_until(what: &str, mut arrived: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !arrived() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Notifies the parent of the parked `tid` (of process `pid`), then waits,
/// without blocking the tracer's other tasks, until the signal the parent
/// sends in response has arrived: for SIGKILL, until it has taken effect;
/// for any other signal, until it is newly pending in either queue. The
/// parked thread dequeues nothing meanwhile, so a bit that becomes set is
/// the parent's signal; a test must not send one into a queue that already
/// holds it (it would coalesce, and never be seen to arrive).
async fn park_for(pid: Pid, tid: Pid, signal: i32) {
    let what = format!("signal {signal} did not arrive at parked thread {tid}");
    if signal == libc::SIGKILL {
        notify_parent(pid);
        return wait_until(&what, || kill_took_effect(tid)).await;
    }
    let bit = 1u64 << (signal - 1);
    let (private, shared) = pending_masks(tid);
    notify_parent(pid);
    wait_until(&what, || {
        let (now_private, now_shared) = pending_masks(tid);
        ((now_private & !private) | (now_shared & !shared)) & bit != 0
    })
    .await;
}

/// The pre-syscall hook: acts once on each call tagged with a hook action, at
/// the point the tag names (see `HOOK_PARK_SHIFT` and the flags after it).
fn park_hook() -> crate::task::PreSyscallForTest {
    type Fired = std::collections::BTreeSet<(i32, u64, crate::task::PreSyscallPoint)>;
    let fired = std::sync::Arc::new(Mutex::new(Fired::new()));
    std::sync::Arc::new(
        move |tid: Pid, regs: &libc::user_regs_struct, point: crate::task::PreSyscallPoint| {
            use crate::task::PreSyscallPoint::Early;
            use crate::task::PreSyscallPoint::Late;
            let signal = ((regs.r9 >> HOOK_PARK_SHIFT) & 0x1f) as i32;
            let park_point = if regs.r9 & HOOK_LATE != 0 {
                Late
            } else {
                Early
            };
            let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
            let tagged = regs.r9 & TP_MAGIC_MASK == TP_MAGIC
                && regs.r9 & (0xff << HOOK_PARK_SHIFT) != 0
                && fired
                    .lock()
                    .unwrap()
                    .insert((tid.as_raw(), sequence, point));
            // The fixture parks only single-threaded children: pid == tid.
            let (send_stops, kill, wait_kill, park) = (
                tagged && point == Early && regs.r9 & HOOK_SEND_STOPS != 0,
                tagged && point == Early && regs.r9 & HOOK_KILL != 0,
                tagged && point == Late && regs.r9 & HOOK_KILL != 0,
                tagged && point == park_point && signal != 0,
            );
            if send_stops {
                // SAFETY: kill takes no pointers.
                assert_eq!(unsafe { libc::kill(tid.as_raw(), libc::SIGSTOP) }, 0);
                tgkill(tid, tid, libc::SIGSTOP);
            }
            if kill {
                // SAFETY: kill takes no pointers.
                assert_eq!(unsafe { libc::kill(tid.as_raw(), libc::SIGKILL) }, 0);
            }
            Box::pin(async move {
                if park {
                    park_for(tid, tid, signal).await;
                }
                if wait_kill || (park && signal == libc::SIGKILL) {
                    if !park {
                        let what = format!("the hook's SIGKILL did not take effect on {tid}");
                        wait_until(&what, || kill_took_effect(tid)).await;
                    }
                    // Stay parked, so that the exit always wins the race
                    // with the rest of the syscall (see the Tool's SIGKILL
                    // park).
                    std::future::pending::<()>().await;
                }
            })
        },
    )
}

fn errno_value(result: &Result<i64, Errno>) -> i64 {
    match result {
        Ok(value) => *value,
        Err(errno) => -i64::from(errno.into_raw()),
    }
}

/// Records every Tool-visible event with the registers the Tool sees, and
/// handles each tagged call the way its tag asks.
#[derive(Default)]
struct GuestTool;

/// The RFLAGS status flags (CF, PF, AF, ZF, SF, OF).
const RFLAGS_STATUS: u64 = 0x8d5;

/// The root's thread-start is the SIGSTOP that the launcher's fork child
/// raises in `traceme_and_stop`, before `execve`. Its r11 is the RFLAGS image
/// the kernel saved at glibc's `raise` -> `tgkill`, so the status flags are
/// whatever that libc code last computed (platform010's glibc tests the host
/// tid there, making PF follow it); the tracer does not set them, and `execve`
/// discards them. Every other thread-start keeps its exact r11.
fn mask_launcher_status_flags(event: String) -> String {
    if !event.starts_with("thread-start ") {
        return event;
    }
    event
        .split(' ')
        .map(|token| match token.strip_prefix("r11=0x") {
            Some(hex) => format!(
                "r11={:#x}",
                u64::from_str_radix(hex, 16).expect("a hex r11") & !RFLAGS_STATUS
            ),
            None => token.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[reverie::tool]
impl Tool for GuestTool {
    type GlobalState = GuestLog;
    type ThreadState = ();

    fn subscriptions(config: &GuestConfig) -> Subscription {
        let mut subscription = Subscription::all();
        if config.partial {
            subscription.disable_syscall(reverie::syscalls::Sysno::getuid);
        }
        subscription
    }

    fn observes_sigreturns(config: &GuestConfig) -> bool {
        config.sigreturns
    }

    fn enforces_serialized_execution(config: &GuestConfig) -> bool {
        config.serialized
    }

    fn handle_sigreturn(&self, _thread_state: &mut (), report: reverie::SigreturnReport) {
        SIGRETURN_REPORTS
            .lock()
            .unwrap()
            .push((report.tid().as_raw(), report.frame()));
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        let tid = guest.tid();
        STEP_BASE
            .lock()
            .unwrap()
            .insert(tid.as_raw(), crate::task::step_count_for_test(tid));
        STEPPED_SEEN.lock().unwrap().insert(
            tid.as_raw(),
            crate::task::stepped_seccomp_count_for_test(tid),
        );
        let regs = guest.regs().await;
        guest
            .send_rpc(format!(
                "thread-start rip={} rax={} rcx={} r11={:#x}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                code(regs.rcx),
                regs.r11
            ))
            .await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc("post-exec".to_owned()).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let tid = guest.tid();
        let pid = guest.pid();
        let regs = guest.regs().await;
        let name = call.number();
        guest
            .send_rpc(format!(
                "entry {name} steps={} rcx=rip:{} r11=rflags:{} rip={} orig_rax={}",
                steps(tid),
                regs.rcx == regs.rip,
                regs.r11 == regs.eflags,
                code(regs.rip),
                regs.orig_rax as i64,
            ))
            .await;
        let stepped_seccomp = crate::task::stepped_seccomp_count_for_test(tid);
        let stepped = STEPPED_SEEN
            .lock()
            .unwrap()
            .insert(tid.as_raw(), stepped_seccomp)
            .is_some_and(|seen| stepped_seccomp > seen);
        if stepped {
            guest
                .send_rpc(format!(
                    "{STEPPED_ENTRY_PREFIX}{name} rip={}",
                    code(regs.rip)
                ))
                .await;
        }
        let tagged = regs.r9 & TP_MAGIC_MASK == TP_MAGIC;
        let no_return = matches!(
            call,
            Syscall::Exit(_) | Syscall::ExitGroup(_) | Syscall::Execve(_) | Syscall::Execveat(_)
        );
        let shape = if no_return {
            SHAPE_TAIL
        } else if tagged {
            regs.r9 & 0xff
        } else if guest.config().tail {
            SHAPE_TAIL
        } else {
            SHAPE_INJECT
        };
        if tagged {
            let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
            guest
                .send_rpc(format!(
                    "tagged {name} rip={} orig_rax={} action={:#x}",
                    code(regs.rip),
                    regs.orig_rax as i64,
                    regs.r9 & 0xffff
                ))
                .await;
            let first = ACTED.lock().unwrap().insert(tid.as_raw(), sequence) != Some(sequence);
            if first {
                send_signals(pid, tid, regs.r9 & 0xff00);
                let park = ((regs.r9 >> TOOL_PARK_SHIFT) & 0x1f) as i32;
                if park != 0 {
                    park_for(pid, tid, park).await;
                }
                if park == libc::SIGKILL {
                    // The killed thread is at its PTRACE_EVENT_EXIT stop.
                    // The task's driver selects, biased towards the exit,
                    // between that exit and the run loop holding this
                    // handler, so whether the rest of the handler and its
                    // final resume ever run depends only on whether the
                    // tracer's waiter has reported the exit stop by the time
                    // this future is polled again. Stay parked, so the exit
                    // always wins.
                    return std::future::pending().await;
                }
            } else if regs.r9 & NOTIFY_AGAIN != 0
                && NOTIFIED.lock().unwrap().insert((tid.as_raw(), sequence))
            {
                notify_parent(pid);
            }
            if regs.r9 & ARM_TIMER != 0 {
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(regs.r8))
                    .expect("arm the precise timer");
            }
        }
        match shape {
            SHAPE_TAIL => guest.tail_inject(call).await,
            SHAPE_EMULATE => {
                guest.send_rpc(format!("syscall {name} = 4242")).await;
                Ok(4242)
            }
            SHAPE_PRIVATE => {
                let result = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!("syscall {name} = {}", errno_value(&result)))
                    .await;
                Ok(result?)
            }
            SHAPE_TWO_INJECTS => {
                let first = guest.inject(call).await;
                let second = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} then getpid {}",
                        errno_value(&first),
                        errno_value(&second)
                    ))
                    .await;
                Ok(first?)
            }
            SHAPE_BLOCK_ALL => {
                use reverie::Stack;
                let mut stack = guest.stack().await;
                let all: u64 = !0;
                let all_addr = stack.push(all);
                let old_addr = stack.reserve::<u64>();
                let _guard = stack.commit()?;
                let block = reverie::syscalls::RtSigprocmask::new()
                    .with_how(libc::SIG_SETMASK)
                    .with_set(Some(all_addr.cast()))
                    .with_oldset(Some(old_addr.cast()))
                    .with_sigsetsize(8);
                guest.inject(block).await?;
                let result = guest.inject(call).await;
                let restore = reverie::syscalls::RtSigprocmask::new()
                    .with_how(libc::SIG_SETMASK)
                    .with_set(Some(reverie::syscalls::Addr::from(old_addr).cast()))
                    .with_oldset(None)
                    .with_sigsetsize(8);
                guest.inject(restore).await?;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} under all blocked",
                        errno_value(&result)
                    ))
                    .await;
                Ok(result?)
            }
            SHAPE_PPOLL_THEN_CALL => {
                use reverie::Stack;
                let mut stack = guest.stack().await;
                let timeout_addr = stack.push([0u64; 2]);
                let empty_addr = stack.push(0u64);
                let _guard = stack.commit()?;
                let ppoll = reverie::syscalls::Ppoll::new()
                    .with_fds(None)
                    .with_nfds(0)
                    .with_timeout(reverie::syscalls::AddrMut::from_raw(timeout_addr.as_raw()))
                    .with_sigmask(Some(empty_addr.cast()))
                    .with_sigsetsize(8);
                let interrupted = guest.inject(ppoll).await;
                // With the signal held, the call runs through the held-signal
                // retry (`Guest::inject_with_retry`).
                let result = guest.inject_with_retry(call).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} after ppoll {}",
                        errno_value(&result),
                        errno_value(&interrupted)
                    ))
                    .await;
                Ok(result?)
            }
            SHAPE_PRIVATE_CALL => {
                guest.inject(reverie::syscalls::Getpid::new()).await?;
                let result = guest.inject(call).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} privately",
                        errno_value(&result)
                    ))
                    .await;
                Ok(result?)
            }
            SHAPE_TWO_PRIVATE => {
                let first = guest.inject(reverie::syscalls::Getpid::new()).await;
                let second = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} then {}",
                        errno_value(&first),
                        errno_value(&second)
                    ))
                    .await;
                Ok(second?)
            }
            _ => {
                assert_eq!(shape, SHAPE_INJECT, "unknown shape");
                let result = guest.inject(call).await;
                if tagged && regs.r9 & CHECK_KERNEL_PPID != 0 {
                    assert_eq!(name, reverie::syscalls::Sysno::getppid);
                    let actual = *result.as_ref().expect("tagged kernel getppid failed");
                    assert!(actual > 0, "kernel getppid must be positive");
                    assert_eq!(
                        guest.ppid().map(|parent| i64::from(parent.as_raw())),
                        Some(actual),
                        "Tool Guest::ppid disagrees with the actual kernel getppid"
                    );
                    guest.send_rpc("checked kernel PPid".to_owned()).await;
                }
                if tagged && regs.r9 & TOOL_AFTER_CONT != 0 {
                    park_for(pid, tid, libc::SIGCONT).await;
                    // Shaped like a re-raise (SI_QUEUE), with a value that
                    // is not a re-raise's tag.
                    send_queued(pid, tid, libc::SIGSTOP, 7, true);
                }
                let rendered = match result {
                    // The guest's parent is not traced, and differs per run.
                    Ok(value) if name == reverie::syscalls::Sysno::getppid && value > 0 => {
                        "<ppid>".to_owned()
                    }
                    _ => errno_value(&result).to_string(),
                };
                guest.send_rpc(format!("syscall {name} = {rendered}")).await;
                let after = guest.regs().await;
                guest
                    .send_rpc(format!(
                        "exit {name} rip={} rax={} rcx={} r11=rflags:{} steps={}",
                        code(after.rip),
                        value(after.rax, pid),
                        code(after.rcx),
                        after.r11 == after.eflags,
                        steps(tid)
                    ))
                    .await;
                Ok(result?)
            }
        }
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let regs = guest.regs().await;
        let clock = guest.read_clock().expect("read the timer clock");
        guest
            .send_rpc(format!(
                "timer rip={} clock={clock} rax={} steps={}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                steps(guest.tid())
            ))
            .await;
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        let regs = guest.regs().await;
        guest
            .send_rpc(format!(
                "signal {signal:?} rip={} rax={} orig_rax={} rcx={} steps={}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                regs.orig_rax as i64,
                code(regs.rcx),
                steps(guest.tid()),
            ))
            .await;
        // `sigtrap_signal_callback`: inject from the callback, then resume
        // the signal. SIGPROF injects getpid; SIGXCPU brackets it with
        // rt_sigprocmask injections that block every signal, as Detcore's
        // disposition check does.
        match signal {
            reverie::Signal::SIGPROF => {
                let _ = guest.inject(reverie::syscalls::Getpid::new()).await;
            }
            reverie::Signal::SIGXCPU => {
                use reverie::Stack;
                let mut stack = guest.stack().await;
                let all = stack.push(!0u64);
                let old = stack.reserve::<u64>();
                let _guard = stack.commit()?;
                guest
                    .inject(
                        reverie::syscalls::RtSigprocmask::new()
                            .with_how(libc::SIG_SETMASK)
                            .with_set(Some(all.cast()))
                            .with_oldset(Some(old.cast()))
                            .with_sigsetsize(8),
                    )
                    .await?;
                let _ = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .inject(
                        reverie::syscalls::RtSigprocmask::new()
                            .with_how(libc::SIG_SETMASK)
                            .with_set(Some(reverie::syscalls::Addr::from(old).cast()))
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await?;
            }
            _ => {}
        }
        if signal == reverie::Signal::SIGWINCH {
            // Suppressed: the interrupted call restarts.
            Ok(None)
        } else {
            Ok(Some(signal))
        }
    }
}

fn regression_guest() -> &'static std::path::Path {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        let source = crate::tracer::tests::fixture("plain_guest_regression.c");
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        // Every test binary in this directory shares it, and another checkout
        // or commit may build into the same target: key the published name
        // by the source (FNV-1a, fixed width, so argv length never changes).
        let text = std::fs::read(&source).expect("read the regression fixture source");
        let hash = text.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        let output = directory.join(format!("reverie-plain-guest-regression-{hash:016x}"));
        let staging = directory.join(format!(
            "reverie-plain-guest-regression-{hash:016x}.{}.tmp",
            std::process::id()
        ));
        // -no-pie: the fixture's text addresses are the same in every run.
        let status = std::process::Command::new("cc")
            .args(["-O0", "-g", "-Wall", "-no-pie", "-pthread"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .expect("invoke cc for the regression fixture");
        assert!(status.success(), "compile {}", source.display());
        std::fs::rename(&staging, &output).expect("publish the regression fixture");
        output
    });
    GUEST.as_path()
}

#[derive(Debug)]
struct GuestRun {
    status: ExitStatus,
    stops: BTreeMap<String, Vec<String>>,
    tool_events: BTreeMap<String, Vec<String>>,
    counts: PtraceBackendStatsSnapshot,
    /// The registers at every final resume of a Tool-visible syscall stop:
    /// rip, rax (the result, unless the Tool tail-injected) and orig_rax.
    resumes: BTreeMap<String, Vec<String>>,
    report: String,
    site: u64,
    /// Every signal-delivery stop the run loop handled: the signal, its
    /// siginfo and where it took effect.
    signals: BTreeMap<String, Vec<String>>,
    /// The Tool's `stepped-entry` reports, taken out of `tool_events`: each
    /// syscall entry that a timer single-step reached, in order.
    stepped_entries: BTreeMap<String, Vec<String>>,
}

impl GuestRun {
    fn all_events(&self) -> Vec<&String> {
        self.tool_events.values().flatten().collect()
    }

    fn count_events(&self, prefix: &str) -> usize {
        self.all_events()
            .iter()
            .filter(|event| event.starts_with(prefix))
            .count()
    }
}

/// Renames traced PIDs in a Tool event with the task names of the run: any
/// token that is, or ends in `=` followed by, a traced PID.
fn rename_event(names: &TaskNames, event: &str) -> String {
    let event = names.event(event);
    event
        .split(' ')
        .map(|token| match token.rsplit_once('=') {
            Some((key, number)) if !key.is_empty() => format!("{key}={}", names.value(number)),
            _ => names.value(token),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn run_guest(mode: &str, tail: bool) -> GuestRun {
    run_guest_with(mode, tail)
        .await
        .unwrap_or_else(|error| panic!("regression fixture run {mode} tail={tail} failed: {error}"))
}

async fn run_guest_with(mode: &str, tail: bool) -> Result<GuestRun, Error> {
    let options = GuestOptions {
        tail,
        ..Default::default()
    };
    run_guest_options(mode, options).await
}

/// How a run is configured beyond its mode.
#[derive(Clone, Copy, Debug, Default)]
struct GuestOptions {
    tail: bool,
    partial: bool,
    /// `TP_ORDER` in the guest's environment (see the fixture's
    /// `order_delay`).
    order: Option<&'static str>,
    /// Observes sigreturns (`GuestConfig::sigreturns`).
    sigreturns: bool,
    /// The run's deadline, if not the default 60 s: for a mode that runs
    /// many children.
    deadline: Option<Duration>,
    /// A seccomp filter returning this action for `mseal`, which the caller
    /// installs in a `pre_exec` callback (`caller_mseal_filter`).
    caller_mseal_filter: Option<u32>,
    /// The Tool declares no serialized-execution contract
    /// (`GuestConfig::serialized`), as a plain Reverie Tool: SIGTRAP is left
    /// as at base.
    no_serialization_contract: bool,
}

/// Installs a seccomp filter on the calling thread that returns `action` for
/// x86_64 `mseal` (462) and allows every other call. Runs in a `pre_exec`
/// callback, so it only makes system calls.
fn caller_mseal_filter(action: u32) -> Result<(), Errno> {
    const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let statement = |code, k| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k, jt, jf| libc::sock_filter {
        code: JEQ_K,
        jt,
        jf,
        k,
    };
    let mut filter = [
        // seccomp_data.arch
        statement(LD_W_ABS, 4),
        jump(0xc000_003e, 1, 0),
        statement(RET_K, libc::SECCOMP_RET_ALLOW),
        // seccomp_data.nr
        statement(LD_W_ABS, 0),
        jump(462, 0, 1),
        statement(RET_K, action),
        statement(RET_K, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: `program` points at `filter`, which outlives both calls.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ) != 0
        {
            return Err(Errno::last());
        }
    }
    Ok(())
}

async fn run_guest_options(mode: &str, options: GuestOptions) -> Result<GuestRun, Error> {
    let report_path = tempfile_path(&format!("plain-guest-{mode}"));
    let mut command = Command::new(regression_guest());
    command.arg(mode).arg(&report_path);
    if let Some(order) = options.order {
        command.env("TP_ORDER", order);
    }
    if let Some(action) = options.caller_mseal_filter {
        // SAFETY: the callback only makes system calls.
        unsafe {
            command.pre_exec(move || caller_mseal_filter(action));
        }
    }
    let resumes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let tracer = TracerBuilder::<GuestTool>::new(command)
        .config(GuestConfig {
            tail: options.tail,
            partial: options.partial,
            sigreturns: options.sigreturns,
            serialized: !options.no_serialization_contract,
        })
        .backend_stats(BackendStatsRequest::ENABLED)
        .final_resume_signal_for_test(resume_recorder(resumes.clone()))
        .pre_syscall_for_test(park_hook())
        .spawn()
        .await?;
    let stats = tracer.backend_stats().expect("stats were requested");
    let deadline = options.deadline.unwrap_or(Duration::from_secs(60));
    let result = tokio::time::timeout(deadline, finish_run(tracer, &stats))
        .await
        .unwrap_or_else(|_| panic!("regression fixture mode {mode} timed out"));
    let report = std::fs::read_to_string(&report_path).unwrap_or_default();
    let _ = std::fs::remove_file(&report_path);
    let (status, log) = result?;
    let site = report
        .lines()
        .next()
        .and_then(|line| line.split_once(" site=0x"))
        .and_then(|(_, hex)| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| panic!("no site line in the report: {report}"));
    let stop_trace = stats.stop_trace();
    let names = TaskNames::new(Identity::Renamed, &stop_trace);
    let mut tool_events = BTreeMap::<String, Vec<String>>::new();
    let mut stepped_entries = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in std::mem::take(&mut *log.0.lock().unwrap()) {
        let event = rename_event(&names, &event);
        match event.strip_prefix(STEPPED_ENTRY_PREFIX) {
            Some(entry) => stepped_entries
                .entry(names.name(pid))
                .or_default()
                .push(entry.to_owned()),
            None => {
                let task = names.name(pid);
                let events = tool_events.entry(task.clone()).or_default();
                if task == "task#0" && events.is_empty() {
                    events.push(mask_launcher_status_flags(event));
                } else {
                    events.push(event);
                }
            }
        }
    }
    let mut resume_events = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in std::mem::take(&mut *resumes.lock().unwrap()) {
        resume_events
            .entry(names.name(pid))
            .or_default()
            .push(rename_event(&names, &event));
    }
    let mut signals = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in stats.signal_trace() {
        // The tracer's own traps: a kernel SIGSEGV (si_code SI_KERNEL) is its
        // rdtsc or cpuid trap, whose rax holds whatever the guest computed
        // last, and SIGSTKFLT is its timer's perf overflow, which lands
        // wherever the counter's skid left it. Their registers are not
        // recorded.
        let tracer_trap =
            event.starts_with("SIGSEGV signo=11 code=128 ") || event.starts_with("SIGSTKFLT ");
        let event = event
            .split(' ')
            .filter(|token| {
                !(tracer_trap && (token.starts_with("rax=") || token.starts_with("rip=")))
            })
            .map(|token| match token.strip_prefix("rip=0x") {
                Some(hex) => format!(
                    "rip={}",
                    code(u64::from_str_radix(hex, 16).expect("a hex rip"))
                ),
                // A signal the tracer (this process) sent.
                None if token == format!("pid={}", std::process::id()) => "pid=tracer".to_owned(),
                None => token.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ");
        signals
            .entry(names.name(pid))
            .or_default()
            .push(rename_event(&names, &event));
    }
    Ok(GuestRun {
        status,
        stops: names.per_task(stop_trace),
        tool_events,
        counts: reverie::BackendStatsSource::backend_stats(&stats),
        resumes: resume_events,
        report,
        site,
        signals,
        stepped_entries,
    })
}

/// Waits for a run like `Tracer::wait`, except that a run whose cleanup is
/// left pending is terminated, its root is killed, and the same cleanup is
/// resumed once; if it is still pending, every tracee of the run that this
/// process still traces is killed (and named on stderr) and the owner is
/// dropped, rather than quarantined. `Tracer::wait` (and `quarantine`) take a
/// process-wide quarantine permit that is never released, so one failed run
/// would refuse every later spawn in this test binary and hide which test
/// failed. The run still fails, with its original cause.
async fn finish_run(
    tracer: Tracer<GuestLog>,
    stats: &crate::PtraceBackendStatsSource,
) -> Result<(ExitStatus, GuestLog), Error> {
    let Some(termination) = tracer.termination_handle() else {
        return tracer.wait().await;
    };
    // SAFETY: pidfd_open takes no pointers; a failure leaves -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, tracer.guest_pid().as_raw(), 0) };
    // SAFETY: a non-negative result is a new descriptor owned here.
    let root = (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw as RawFd) });
    match tracer.wait_completion().await {
        ToolRunOutcome::Complete(completion) => completion
            .result
            .map(|status| (status, completion.global_state))
            .map_err(crate::PtraceRunFailure::into_legacy_error),
        ToolRunOutcome::CleanupPending(pending) => {
            let cause = pending.failure().to_string();
            termination.terminate(Error::Tool(anyhow::anyhow!(
                "regression rescue after: {cause}"
            )));
            if let Some(root) = &root {
                // SAFETY: a valid pidfd, and a null siginfo.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        root.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }
            match tokio::time::timeout(Duration::from_secs(5), pending.resume_cleanup()).await {
                Ok(ToolRunOutcome::Complete(_)) => Err(Error::Tool(anyhow::anyhow!(
                    "{cause} (cleanup completed after the rescue)"
                ))),
                Ok(ToolRunOutcome::CleanupPending(pending)) => {
                    kill_remaining_tracees(stats);
                    drop(pending);
                    Err(Error::Tool(anyhow::anyhow!(
                        "{cause} (cleanup still pending after the rescue)"
                    )))
                }
                Ok(ToolRunOutcome::UnsupportedBackend(_)) => {
                    unreachable!("a pending ordinary cleanup resumes on the same backend")
                }
                Err(_) => Err(Error::Tool(anyhow::anyhow!(
                    "{cause} (cleanup rescue timed out)"
                ))),
            }
        }
        ToolRunOutcome::UnsupportedBackend(tracer) => tracer.wait().await,
    }
}

/// Kills, with SIGKILL, each thread group of a tracee in `stats`' stop trace
/// that a thread of this process still traces, and names each on stderr, so
/// that a run whose cleanup stayed pending leaves no tracee behind.
/// `TracerPid` is checked first, so a reused PID of an unrelated process is
/// not signalled.
fn kill_remaining_tracees(stats: &crate::PtraceBackendStatsSource) {
    let tids: std::collections::BTreeSet<i32> = stats
        .stop_trace()
        .into_iter()
        .map(|(pid, _)| pid.as_raw())
        .collect();
    for tid in tids {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{tid}/status")) else {
            continue;
        };
        // The tracer is a thread (TracerPid is its TID) of this process.
        let tracer = status.lines().find_map(|line| {
            line.strip_prefix("TracerPid:")
                .and_then(|value| value.trim().parse::<i32>().ok())
        });
        let traced_here = tracer.is_some_and(|tracer| {
            tracer != 0 && std::path::Path::new(&format!("/proc/self/task/{tracer}")).exists()
        });
        if traced_here {
            // SAFETY: kill takes no pointers.
            let rc = unsafe { libc::kill(tid, libc::SIGKILL) };
            eprintln!("regression rescue: killed remaining tracee {tid} (rc={rc})");
        }
    }
}

/// Records the registers at every final resume of a Tool-visible syscall
/// stop in `log`, and leaves SIGUSR1 pending for the final resume of each
/// `SEND_RESUME` call, once per call.
fn resume_recorder(
    log: std::sync::Arc<Mutex<Vec<(Pid, String)>>>,
) -> crate::task::FinalResumeSignalForTest {
    let fired = std::sync::Arc::new(Mutex::new(std::collections::BTreeSet::<(i32, u64)>::new()));
    std::sync::Arc::new(move |tid: Pid, regs: &libc::user_regs_struct| {
        // The guest's pid is the thread-group id, which the hook does not
        // see; a result equal to the tid is the common case (getpid in the
        // root thread) and is rendered as `<pid>` too.
        log.lock().unwrap().push((
            tid,
            format!(
                "resume rip={} rax={} orig_rax={} rcx={} r11=rflags:{}",
                code(regs.rip),
                value(regs.rax, tid),
                regs.orig_rax as i64,
                code(regs.rcx),
                // The raw flags depend on guest arithmetic on its own pid,
                // which differs per run.
                regs.r11 == regs.eflags
            ),
        ));
        if regs.r9 & TP_MAGIC_MASK != TP_MAGIC || regs.r9 & SEND_RESUME == 0 {
            return None;
        }
        let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
        fired
            .lock()
            .unwrap()
            .insert((tid.as_raw(), sequence))
            .then_some(nix::sys::signal::Signal::SIGUSR1)
    })
}

/// Runs `mode` in both Tool configurations, and requires each run to exit 0
/// with a complete report. Returns the two runs as (inject, tail).
async fn run_both_configurations(mode: &str) -> [GuestRun; 2] {
    let inject = run_guest(mode, false).await;
    let tail = run_guest(mode, true).await;
    for run in [&inject, &tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
    }
    [inject, tail]
}

/// `run_both_configurations` for a mode that runs long (many children, or
/// thousands of injections): each run has `deadline` instead of 60 s.
async fn run_both_configurations_within(mode: &str, deadline: Duration) -> [GuestRun; 2] {
    run_both_configurations_with(
        mode,
        GuestOptions {
            deadline: Some(deadline),
            ..Default::default()
        },
    )
    .await
}

/// `run_both_configurations` with `options` for each run, but its `tail`.
async fn run_both_configurations_with(mode: &str, options: GuestOptions) -> [GuestRun; 2] {
    let mut runs = Vec::new();
    for tail in [false, true] {
        let options = GuestOptions { tail, ..options };
        let run = run_guest_options(mode, options)
            .await
            .unwrap_or_else(|error| {
                panic!("regression fixture run {mode} tail={tail} failed: {error}")
            });
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
        runs.push(run);
    }
    let [inject, tail]: [GuestRun; 2] = runs.try_into().unwrap_or_else(|_| unreachable!());
    [inject, tail]
}

fn assert_report_has(run: &GuestRun, lines: &[&str]) {
    for line in lines {
        assert!(
            run.report
                .lines()
                .any(|candidate| candidate.starts_with(line)),
            "report lacks a line starting {line:?}:\n{}",
            run.report
        );
    }
}

/// The signal-delivery stop of `signal` sent by `sender` with `code`, where
/// the call at the shared site (orig_rax `nr`) returned `rax`.
fn delivery_after_the_call(
    run: &GuestRun,
    signal: &str,
    code: i32,
    sender: &str,
    rax: &str,
    nr: i64,
) -> String {
    let number = match signal {
        "SIGSTOP" => libc::SIGSTOP,
        "SIGCONT" => libc::SIGCONT,
        "SIGTSTP" => libc::SIGTSTP,
        "SIGTTIN" => libc::SIGTTIN,
        "SIGTTOU" => libc::SIGTTOU,
        _ => unreachable!("{signal}"),
    };
    format!(
        "{signal} signo={number} code={code} errno=0 pid={sender} uid={} rip={:#x} rax={rax} orig_rax={nr}",
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() },
        run.site + 2
    )
}

/// Syscall user dispatch with the allowed region excluding the shared site:
/// the dispatched SIGSYS reports the x86_64 `getpid` at the site's end, the
/// handler's result (1234) is the call's, and after dispatch is turned off
/// the parent and a forked child run getpid normally.
#[tokio::test(flavor = "current_thread")]
async fn syscall_user_dispatch_sees_the_original_site() {
    let [inject, _] = run_both_configurations("sud").await;
    assert_report_has(
        &inject,
        &[
            "sud on ret=0",
            "after sud site bytes 0f 05",
            "dispatched getpid ret=1234 count=1 syscall=39 arch=0xc000003e call=tp_site_end",
            "sud off ret=0",
            "getpid 2 pid=1",
            "child getpid 2 pid=1",
            "child exited=1 code=0",
            "sud handled=1",
        ],
    );
}

/// A CLONE_UNTRACED thread gets no new-child stop: it executes the original
/// `syscall` at the shared site, whose getpid the inherited filter refuses
/// with ENOSYS (no tracer), and whose rcx is the site's end. Cloned from
/// libc and through the shared site itself.
#[tokio::test(flavor = "current_thread")]
async fn untraced_thread_runs_the_original_syscall() {
    for mode in ["untraced_thread", "untraced_thread_site"] {
        let [inject, _] = run_both_configurations(mode).await;
        assert_report_has(
            &inject,
            &[
                "untraced clone ok=1",
                "untraced thread getpid ret=-38 rcx=tp_site_end",
                "after untraced site bytes 0f 05",
            ],
        );
    }
}

/// A fork-like CLONE_UNTRACED child (without CLONE_VM), cloned through the
/// shared site, gets no new-child stop and its own copy of the text: it
/// starts after the guest's own `syscall` (rcx at the site's end, r11 0x246),
/// executes the original instruction there (getpid refused with ENOSYS by the
/// inherited filter), and is killed by its parent.
#[tokio::test(flavor = "current_thread")]
async fn untraced_fork_runs_the_original_syscall() {
    let [inject, tail] = run_both_configurations("untraced_fork").await;
    assert_report_has(
        &inject,
        &[
            "untraced fork clone ok=1",
            "untraced fork child done=1 clone rcx=tp_site_end r11=0x246 \
             getpid ret=-38 rcx=tp_site_end bytes 0f 05",
            // CLD_KILLED by the parent's SIGKILL.
            "untraced fork child code=2 status=9",
            "after untraced fork site bytes 0f 05",
        ],
    );
    // The child is untraced: no new-child stop.
    assert_eq!(tail.counts.fork_stops(), 0);
    assert_eq!(tail.counts.clone_stops(), 0);
}

/// The guest's own seccomp filter returns `SECCOMP_RET_TRACE` for number 500,
/// which the syscall table does not know (the tracer's filter does not trace
/// it). The seccomp stop's number cannot be decoded: `get_syscall` used to
/// panic in `Sysno::from` here, and now ends the run with an ENOSYS error
/// whose context names the stop. Returning -ENOSYS to the guest instead is a
/// tracked follow-up.
#[tokio::test(flavor = "current_thread")]
async fn guest_trace_of_an_unknown_number_ends_the_run() {
    let error = run_guest_with("guest_trace_unknown", false)
        .await
        .expect_err("an undecodable seccomp stop must end the run");
    let text = format!("{error:#} {error:?}");
    eprintln!("{text}");
    assert!(text.contains("read registers at seccomp stop"), "{text}");
    assert!(text.contains("ENOSYS"), "{text}");
}

/// A parent stops its child (SIGSTOP) while the child's write at the shared
/// site is parked at its seccomp stop, then continues it (SIGCONT)
/// immediately before the write runs. The SIGCONT discards the pending
/// SIGSTOP: the write returns 4, the guest's SIGCONT handler runs once at the
/// site's end, the run loop sees exactly one signal-delivery stop (the
/// SIGCONT, after the write) and the Tool one SIGCONT event, and the parent
/// sees no stop.
#[tokio::test(flavor = "current_thread")]
async fn sigcont_before_the_call_discards_the_pending_sigstop() {
    for tail in [false, true] {
        let ptrace = run_guest("sigstop_cont_late", tail).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        let cont = delivery_after_the_call(&ptrace, "SIGCONT", libc::SI_USER, "task#0", "4", 1);
        for tag in ["tail", "inject"] {
            let common = [
                format!("{tag} child call ret=4 byte=0"),
                format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ];
            let common: Vec<&str> = common.iter().map(String::as_str).collect();
            assert_report_has(&ptrace, &common);
            let handled =
                format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4");
            assert_report_has(&ptrace, &[&handled]);
        }
        for child in ["task#1", "task#2"] {
            assert_eq!(ptrace.signals[child], std::slice::from_ref(&cont));
            let sigcont_events = ptrace.tool_events[child]
                .iter()
                .filter(|event| event.starts_with("signal SIGCONT "))
                .count();
            assert_eq!(sigcont_events, 1, "{:#?}", ptrace.tool_events);
        }
    }
}

/// A SIGSTOP sent while the child's write is parked at its seccomp stop, then
/// a SIGCONT and a SIGTSTP, SIGTTIN or SIGTTOU (handled) immediately before
/// the write runs. The stop signal discards the SIGCONT, which had discarded
/// the SIGSTOP: only the stop signal is delivered, after the write, its
/// handler runs once at the site's end, and there is no SIGSTOP delivery
/// stop and no SIGCONT.
#[tokio::test(flavor = "current_thread")]
async fn sigcont_then_a_stop_signal_delivers_only_the_stop_signal() {
    for (mode, tag, name, signal) in [
        ("sigstop_cont_tstp", "tstp", "SIGTSTP", libc::SIGTSTP),
        ("sigstop_cont_ttin", "ttin", "SIGTTIN", libc::SIGTTIN),
        ("sigstop_cont_ttou", "ttou", "SIGTTOU", libc::SIGTTOU),
    ] {
        let ptrace = run_guest(mode, false).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!(
                    "{tag} child signal 0: sig={signal} code=0 from-parent=1 rip=tp_site_end rax=4"
                ),
                &format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
        assert!(
            !ptrace.report.contains(&format!("{tag} child signal 1:")),
            "{}",
            ptrace.report
        );
        let only = delivery_after_the_call(&ptrace, name, libc::SI_USER, "task#0", "4", 1);
        assert_eq!(
            ptrace.signals["task#1"],
            std::slice::from_ref(&only),
            "{mode}"
        );
    }
}

/// Unknown and out-of-range syscall numbers through generic sites return
/// -ENOSYS (rcx the next instruction, r11 0x246) without any Tool event, and
/// a number with high bits set runs as its low 32 bits: high-getpid returns
/// the pid, and the Tool, the stop trace and the final resume each see its
/// full orig_rax exactly once.
#[tokio::test(flavor = "current_thread")]
async fn unknown_numbers_return_enosys_without_a_tool_event() {
    let high = 0x1_0000_0027u64;
    for tail in [false, true] {
        let ptrace = run_guest("unknown", tail).await;
        eprintln!("unknown report:\n{}", ptrace.report);
        let count = |events: &BTreeMap<String, Vec<String>>, needle: &str| {
            events
                .values()
                .flatten()
                .filter(|event| event.contains(needle))
                .count()
        };
        assert_eq!(
            count(&ptrace.tool_events, &format!("orig_rax={high}")),
            1,
            "one Tool entry shows the full number"
        );
        assert_eq!(
            count(&ptrace.stops, &format!("seccomp {high}")),
            1,
            "one stop shows the full number"
        );
        assert_eq!(
            count(&ptrace.resumes, &format!("orig_rax={high}")),
            1,
            "one resume shows the full number"
        );
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                "nr500 ret=-38 rcx-next=1 r11=0x246",
                "nr500 getpid after=1",
                "nr500 bytes after 0f 05",
                "nr-1 ret=-38 rcx-next=1 r11=0x246",
                "nr-1 bytes after 0f 05",
                "gap337 ret=-38 rcx-next=1 r11=0x246",
                "gap337 bytes after 0f 05",
                "high-getpid ret=<pid> rcx-next=1 r11=0x246",
                "high-getpid getpid after=1",
                "high500 ret=-38 rcx-next=1 r11=0x246",
                "high500 bytes after 0f 05",
            ],
        );
        assert!(
            !ptrace
                .all_events()
                .iter()
                .any(|event| event.contains("orig_rax=500") || event.contains("orig_rax=-1")),
            "an unknown number reached the Tool: {:#?}",
            ptrace.all_events()
        );
    }
}

/// Each Tool handler shape single-steps a fixed number of times. The guest's
/// ignored and blocked SIGTRAP stays so after every shape, stepped or not
/// (<https://github.com/rrnewton/hermit/issues/4409>;
/// `sigtrap_state_survives_each_handler_shape` covers the other states).
/// The last trap the SIGUSR1 frame records still differs: after a shape
/// that single-steps it is the step's debug trap (1) instead of the
/// syscall's (13), a documented difference. In the fixture's order of the
/// shapes (exact inject, tail, emulate, private inject, two injects, two
/// private injects) the steps are 0, 0, 1, 2, 1 and 3.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_profile_follows_each_handler_shape() {
    let [inject, tail] = run_both_configurations("sigtrap_profile").await;
    eprintln!("sigtrap profile report:\n{}", inject.report);
    let mut guest_visible = Vec::new();
    for (shape, result, stepped) in [
        ("inject", "ppid", false),
        ("tail", "ppid", false),
        ("emulate", "4242", true),
        ("private", "pid", true),
        ("two-injects", "ppid", true),
        ("two-private", "pid", true),
    ] {
        let (disposition, blocked) = ("ign", 1);
        let trapno = if stepped { 1 } else { 13 };
        guest_visible.push(format!("{shape} getppid={result}"));
        guest_visible.push(format!("{shape} sigtrap={disposition} blocked={blocked}"));
        guest_visible.push(format!(
            "{shape} 0: sig=10 code=-6 value=-1 rip=other rax=0 rcx=other r11=0x246 \
             trapno={trapno} err=0"
        ));
    }
    let lines: Vec<&str> = inject
        .report
        .lines()
        .filter(|line| !line.starts_with("mode ") && *line != "done")
        .collect();
    assert_eq!(lines, guest_visible, "{}", inject.report);
    // The tail configuration keeps SIGTRAP's state too; its frames and steps
    // follow that configuration's own shapes, so only the state is compared.
    let state = |report: &str| -> Vec<String> {
        report
            .lines()
            .filter(|line| line.contains(" sigtrap="))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(
        state(&tail.report),
        state(&inject.report),
        "{}",
        tail.report
    );
    let expected = [0, 0, 1, 2, 1, 3];
    let steps = steps_per_shape(&inject);
    eprintln!("steps per shape: {steps:?}");
    assert_eq!(steps, expected, "step profile");
}

/// A guest's SIGTRAP state survives every Tool handler shape, as it does
/// natively (https://github.com/rrnewton/hermit/issues/4409). Linux reports
/// each `PTRACE_SINGLESTEP` with `force_sig`, which resets a blocked or
/// ignored SIGTRAP to `SIG_DFL` and unblocks it. Five states (ignored or
/// caught, blocked or not, and default blocked) go through each shape, and
/// the guest reads back the handler, the flags and `sa_mask` it set, and the
/// mask bit. The step profile is asserted too, so the stepping shapes are
/// known to have stepped.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_each_handler_shape() {
    let runs = run_both_configurations("sigtrap_states").await;
    let shapes = [
        "inject",
        "tail",
        "emulate",
        "private",
        "two-injects",
        "two-private",
        "block-all",
    ];
    let mut expected = Vec::new();
    for (state, action, blocked) in [
        ("ign-blocked", "ign", 1),
        ("ign", "ign", 0),
        ("handler-blocked", "trap_handler", 1),
        ("handler", "trap_handler", 0),
        ("dfl-blocked", "dfl", 1),
    ] {
        for shape in shapes {
            expected.push(format!(
                "{state} {shape} sigtrap={action} flags=0x50000000 usr2-in-mask=1 \
                 blocked={blocked}"
            ));
        }
    }
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| !line.starts_with("mode ") && *line != "done")
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
    let steps = steps_per_shape(&runs[0]);
    assert_eq!(steps, [0, 0, 1, 2, 1, 3, 4].repeat(5), "step profile");
}

/// Steps taken by each tagged call: the cumulative count at the next
/// syscall entry minus the count at the call's entry.
fn steps_per_shape(run: &GuestRun) -> Vec<u64> {
    let root = &run.tool_events["task#0"];
    let entry_steps = |event: &String| -> u64 {
        event
            .split_once(" steps=")
            .and_then(|(_, rest)| rest.split(' ').next())
            .and_then(|value| value.parse().ok())
            .unwrap()
    };
    let mut per_shape = Vec::new();
    for (index, event) in root.iter().enumerate() {
        if !event.starts_with("tagged getppid") {
            continue;
        }
        let before = entry_steps(&root[index - 1]);
        let after = root[index + 1..]
            .iter()
            .find(|event| event.starts_with("entry "))
            .map(entry_steps)
            .unwrap();
        per_shape.push(after - before);
    }
    per_shape
}

/// rcx and r11 after `syscall` at a site that loads sentinels into both
/// first, including with DF and AC set, in a signal frame interrupting a
/// blocking read at the shared site, and in a fork child created there.
#[tokio::test(flavor = "current_thread")]
async fn rcx_and_r11_after_syscall_hold_the_return_address_and_flags() {
    let [inject, _] = run_both_configurations("rcx_r11").await;
    assert_report_has(
        &inject,
        &[
            "t8 0 pid=1 rcx=t8_site_end r11=0x293",
            "t8 3 pid=1 rcx=t8_site_end r11=0x293",
            "t8 df pid=1 rcx=t8_site_end r11=0x697",
            "t8 ac pid=1 rcx=t8_site_end r11=0x40246",
            "fork child rcx=tp_site_end r11=0x246",
        ],
    );
    assert!(
        inject.report.contains("read 0: sig=10") && inject.report.contains("rcx=tp_site_end r11="),
        "{}",
        inject.report
    );
}

/// A signal left pending for the tracer's final resume of a seccomp stop:
/// after an in-place inject or an emulation the resume is from a
/// syscall-exit stop, where the kernel sends it, so the guest handles it
/// with the call's result; after a tail inject the resume is from the
/// seccomp stop, where the kernel ignores it.
#[tokio::test(flavor = "current_thread")]
async fn a_final_resume_signal_is_sent_only_from_a_syscall_exit_stop() {
    let [inject, _] = run_both_configurations("resume_signal").await;
    assert_report_has(
        &inject,
        &[
            "getpid returned pid=1",
            "resume_inject 0: sig=10 code=128 value=-1 rip=tp_site_end rax=<pid> ",
            "emulated getpid returned 4242",
            "resume_emulate 0: sig=10 code=0 value=-1 rip=tp_site_end rax=4242 ",
            "tail getpid returned pid=1",
        ],
    );
    assert!(
        !inject.report.contains("resume_tail 0:"),
        "ptrace drops a signal passed on resume from the seccomp stop:\n{}",
        inject.report
    );
}

/// Interrupted and restarted calls at the shared site: each sleep reports
/// about its whole request as remaining time, read, futex, ppoll,
/// epoll_pwait and pause restart or fail with EINTR by the kernel's rules,
/// a suppressed signal restarts a sleep through at least three
/// `restart_syscall` entries the Tool sees, and the SA_RESTART frame of a
/// restarted read shows rip at the `syscall` instruction.
#[tokio::test(flavor = "current_thread")]
async fn interrupted_calls_restart_or_fail_by_the_kernel_rules() {
    let [inject, _] = run_both_configurations("restart").await;
    assert_report_has(
        &inject,
        &[
            "nanosleep-suppressed ret=0 errno=0 rcx=tp_site_end r11=0x246",
            // The signal is pending when each sleep starts, so every
            // interrupted sleep (restarted or not) reports about the whole
            // request as its remaining time (the fixture's rem_class).
            "nanosleep-suppressed rem=whole",
            "nanosleep-handled rem=whole",
            "clock_nanosleep-suppressed rem=whole",
            "clock_nanosleep-handled rem=whole",
            "nanosleep-suppressed-tail rem=whole",
            "read-eintr ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "read-restart ret=1 errno=0 rcx=tp_site_end r11=0x246",
            "futex-restart ret=-11 errno=11 rcx=tp_site_end r11=0x246",
            "futex-eintr ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "ppoll ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "epoll_pwait ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "pause ret=-4 errno=4 rcx=tp_site_end r11=0x246",
        ],
    );
    assert!(
        inject.count_events("tagged restart_syscall") >= 3,
        "restart_syscall re-entries: {:#?}",
        inject.all_events()
    );
    assert!(
        inject
            .report
            .contains("read-restart 0: sig=10 code=-6 value=-1 rip=tp_site rax=0 "),
        "SA_RESTART frame shows rip == S:\n{}",
        inject.report
    );
}

/// A child exits while the parent sleeps in a nanosleep at the shared site.
/// With SIGCHLD ignored by default the sleep restarts and sleeps its full
/// time; with a handler it returns EINTR, and the handler's frame is at the
/// site's end.
#[tokio::test(flavor = "current_thread")]
async fn sigchld_during_a_nanosleep_restarts_it_unless_handled() {
    let [inject, _] = run_both_configurations("sigchld_nanosleep").await;
    eprintln!("sigchld report:\n{}", inject.report);
    assert_report_has(
        &inject,
        &[
            "sigchld-dfl ret=0 errno=0 rcx=tp_site_end r11=0x246",
            "sigchld-dfl slept-full=1 rem-set=1",
            "sigchld-dfl child exited=1 code=5",
            "sigchld-handled ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "sigchld-handled slept-full=0 rem-set=1",
            "sigchld-handled 0: sig=17 code=1 value=-1 rip=tp_site_end rax=-4 rcx=tp_site_end r11=0x246 ",
            "sigchld-handled child exited=1 code=5",
        ],
    );
}

/// rt_sigreturn through the shared site to a frame whose saved rip is the
/// private page's `syscall; ud2` return address: the frame's registers win,
/// so the guest takes SIGILL at exactly that address, and then continues.
#[tokio::test(flavor = "current_thread")]
async fn rt_sigreturn_to_the_private_page_return_keeps_the_frame() {
    let [inject, _] = run_both_configurations("sigreturn_slot_ret").await;
    eprintln!("slot-ret report:\n{}", inject.report);
    assert_report_has(
        &inject,
        &[
            "slot-ret SIGILL addr-is-slot-ret=1 rip-is-slot-ret=1",
            "slot-ret getpid after pid=1",
            "slot-ret after site bytes 0f 05",
        ],
    );
}

/// The guest's `rt_sigreturn` is reported, before it runs, to a Tool that
/// observes sigreturns, with the mask its frame installs, and the call still
/// runs exactly as before: the `sigreturn` mode's handler adds SIGUSR2 to its
/// frame's mask, so both returns report SIGUSR2 blocked and SIGUSR1 not, and
/// the guest sees the same mask and registers as without the hook. A frame
/// on an unmapped page is reported as unmapped, and one on a PROT_NONE page,
/// which ptrace itself could read but the guest cannot, as protected; the
/// kernel forces SIGSEGV in both, as without the opt-in. A Tool that does not
/// observe sigreturns is told of none.
#[tokio::test(flavor = "current_thread")]
async fn sigreturn_reports_carry_the_mask_each_frame_installs() {
    let usr1 = 1u64 << (libc::SIGUSR1 - 1);
    let usr2 = 1u64 << (libc::SIGUSR2 - 1);
    let observing = GuestOptions {
        sigreturns: true,
        ..Default::default()
    };
    let _serial = SIGRETURN_TESTS.lock().await;
    let take = || std::mem::take(&mut *SIGRETURN_REPORTS.lock().unwrap());
    take();

    let run = run_guest_options("sigreturn", observing)
        .await
        .expect("sigreturn run");
    assert_report_has(
        &run,
        &[
            "sigreturn 0: sig=10 code=-6 value=-1 ",
            "after sigreturn usr1-blocked=0 usr2-blocked=1",
            "sigreturn again 0: sig=10 code=-6 value=-1 ",
        ],
    );
    let reports = take();
    assert_eq!(
        reports.len(),
        2,
        "one report per handler return: {reports:?}"
    );
    for (_, frame) in &reports {
        let reverie::SigreturnFrame::Readable { mask } = *frame else {
            panic!("the frame is readable: {frame:?}");
        };
        assert_eq!(mask & (usr1 | usr2), usr2, "frame mask {mask:#x}");
    }

    let plain = run_guest_options("sigreturn", GuestOptions::default())
        .await
        .expect("sigreturn run without the opt-in");
    assert_report_has(&plain, &["after sigreturn usr1-blocked=0 usr2-blocked=1"]);
    assert_eq!(take(), [], "a Tool that does not observe sigreturns");

    let bad = run_guest_options("sigreturn_bad_frame", observing)
        .await
        .expect("bad-frame run");
    assert_report_has(
        &bad,
        &["bad-frame SIGSEGV code=128 rip-next=1 rax=0 bytes after 0f 05"],
    );
    let reports = take();
    assert!(
        reports
            .iter()
            .any(|(_, frame)| *frame == reverie::SigreturnFrame::Unmapped),
        "the frame on an unmapped page is reported as unmapped: {reports:?}"
    );

    let prot_none = run_guest_options("sigreturn_prot_none_frame", observing)
        .await
        .expect("PROT_NONE-frame run");
    let plain_prot_none = run_guest_options("sigreturn_prot_none_frame", GuestOptions::default())
        .await
        .expect("PROT_NONE-frame run without the opt-in");
    assert_eq!(
        prot_none.report, plain_prot_none.report,
        "the guest sees no difference"
    );
    let reports = take();
    assert!(
        reports
            .iter()
            .any(|(_, frame)| *frame == reverie::SigreturnFrame::Protected),
        "a PROT_NONE frame is reported as protected: {reports:?}"
    );
}

/// rt_sigreturn through a generic site with rsp at an unmapped page: the
/// kernel returns 0 right after the `syscall` and forces SIGSEGV there.
#[tokio::test(flavor = "current_thread")]
async fn rt_sigreturn_with_an_unreadable_frame_forces_sigsegv_after_the_syscall() {
    let [inject, _] = run_both_configurations("sigreturn_bad_frame").await;
    eprintln!("bad-frame report:\n{}", inject.report);
    assert_report_has(
        &inject,
        &[
            "bad-frame SIGSEGV code=128 rip-next=1 rax=0 bytes after 0f 05",
            "bad-frame getpid after=1",
        ],
    );
}

/// rt_sigreturn through a generic site at a frame on a PROT_NONE page whose
/// saved rip is the private page's return address: the kernel loads no
/// register, returns 0 right after the `syscall` and forces SIGSEGV there,
/// not at the saved rip.
#[tokio::test(flavor = "current_thread")]
async fn rt_sigreturn_from_a_prot_none_frame_forces_sigsegv_after_the_syscall() {
    let [inject, _] = run_both_configurations("sigreturn_prot_none_frame").await;
    eprintln!("prot-none-frame report:\n{}", inject.report);
    assert_report_has(
        &inject,
        &[
            "prot-none-frame SIGSEGV code=128 rip-next=1 rip-is-slot-ret=0 rax=0 bytes after 0f 05",
            "prot-none-frame getpid after=1",
        ],
    );
}

/// The guest's (traced) parent sends SIGSTOP to its child parked at a write
/// at the shared site, then SIGCONT once the write's data and the child's
/// next output arrived. The write lands before the stop: the SIGSTOP
/// delivery stop is at the site's end with the write's result, carrying the
/// parent's siginfo (SI_USER), and the SIGCONT is the child's second and
/// last signal-delivery stop. The tracer suppresses the SIGSTOP, so the
/// parent never sees the child stopped or continued.
#[tokio::test(flavor = "current_thread")]
async fn a_delivered_sigstop_then_sigcont_reach_the_child_after_the_write() {
    let [inject, _] = run_both_configurations("sigstop_parent").await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &inject,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=other rax=0"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    let stop = delivery_after_the_call(&inject, "SIGSTOP", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        let signals = &inject.signals[child];
        assert_eq!(signals.len(), 2, "{signals:#?}");
        assert_eq!(signals[0], stop);
        assert!(
            signals[1].starts_with("SIGCONT signo=18 code=0 errno=0 pid=task#0 "),
            "{signals:#?}"
        );
    }
}

/// Several SIGSTOPs in one call, into both queues: each queue delivers one
/// SIGSTOP, with the siginfo of the first sent to it. `parent-kill`: the
/// tracer's tgkill and the parent's kill at the write's stop, then the
/// tracer's kill and tgkill immediately before the write runs; the shared
/// queue keeps the parent's siginfo. `parent-tgkill`: the parent's tgkill at
/// the write's stop, then the tracer's kill and tgkill; the private queue
/// keeps the parent's.
#[tokio::test(flavor = "current_thread")]
async fn several_sigstops_deliver_one_per_queue_with_the_first_siginfo() {
    let [inject, _] = run_both_configurations("sigstop_many").await;
    for tag in [
        "parent-kill-tail",
        "parent-kill-inject",
        "parent-tgkill-tail",
        "parent-tgkill-inject",
    ] {
        assert_report_has(
            &inject,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    assert!(
        !inject.report.contains(" child signal "),
        "{}",
        inject.report
    );
    let stop = |code, sender| delivery_after_the_call(&inject, "SIGSTOP", code, sender, "4", 1);
    let parent_kill_stops = [
        stop(libc::SI_TKILL, "tracer"),
        stop(libc::SI_USER, "task#0"),
    ];
    let parent_tgkill_stops = [
        stop(libc::SI_TKILL, "task#0"),
        stop(libc::SI_USER, "tracer"),
    ];
    for (child, stops) in [
        ("task#1", &parent_kill_stops),
        ("task#2", &parent_kill_stops),
        ("task#3", &parent_tgkill_stops),
        ("task#4", &parent_tgkill_stops),
    ] {
        assert_eq!(&inject.signals[child], stops, "{child}");
    }
}

/// A SIGCONT discards a SIGSTOP pending after an injected write, and the
/// Tool then queues a new SIGSTOP (SI_QUEUE, value 7) before the thread
/// returns to user mode: its delivery stop keeps its own siginfo.
#[tokio::test(flavor = "current_thread")]
async fn a_later_queued_sigstop_keeps_its_own_siginfo() {
    let [inject, _] = run_both_configurations("sigstop_stale").await;
    assert_report_has(
        &inject,
        &[
            "inject child call ret=4 byte=0",
            "inject parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7",
        ],
    );
    assert!(
        !inject.report.contains(" child signal "),
        "{}",
        inject.report
    );
    let stop = delivery_after_the_call(&inject, "SIGSTOP", libc::SI_QUEUE, "tracer", "4", 1);
    assert_eq!(inject.signals["task#1"], std::slice::from_ref(&stop));
}

/// A child with a second thread (which blocks every signal) parked at the
/// shared site, with a SIGSTOP from its parent and a SIGCONT immediately
/// before the write runs (the SIGCONT discards the SIGSTOP and is handled at
/// the site's end) or after the write (the SIGCONT is handled later).
#[tokio::test(flavor = "current_thread")]
async fn a_threaded_child_handles_sigcont_inside_and_after_the_call() {
    let [inject, _] = run_both_configurations("sigstop_threaded").await;
    assert_report_has(
        &inject,
        &[
            "window child call ret=4 byte=0",
            "window child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4",
            "window parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7",
            "late-cont child call ret=4 byte=0",
            "late-cont child signal 0: sig=18 code=0 from-parent=1 rip=other rax=0",
            "late-cont parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7",
        ],
    );
}

/// A SIGSTOP pending when a blocking read starts interrupts it
/// (ERESTARTSYS at the delivery stop), and the read restarts after the
/// suppressed stop, before any data arrived: the parent writes the data only
/// once the restarted read reached the Tool (or after 10 s without it).
#[tokio::test(flavor = "current_thread")]
async fn a_sigstop_interrupts_a_blocking_read_which_restarts() {
    let [inject, _] = run_both_configurations("sigstop_blocking_read").await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &inject,
            &[
                &format!("{tag} child call ret=1 byte=100"),
                &format!("{tag} parent notified=1 data=-1 after=5 restarted=1 waitpid exited:7"),
            ],
        );
    }
    let stop = delivery_after_the_call(&inject, "SIGSTOP", libc::SI_USER, "task#0", "-512", 0);
    for child in ["task#1", "task#2"] {
        assert_eq!(inject.signals[child], std::slice::from_ref(&stop));
    }
}

/// The Tool's timer events of a run, in order.
fn timer_events(run: &GuestRun) -> Vec<&String> {
    run.all_events()
        .into_iter()
        .filter(|event| event.starts_with("timer "))
        .collect()
}

/// A precise timer armed in a forked child far beyond any skid margin, whose
/// signal the child blocks, so that no notification is ever handled; the
/// child then runs well past the target. When it ends with a foreign
/// `int 0x80`, which the filter kills with no stop, the event is witnessed
/// once at the thread's exit as a skid overshoot, counted as no event
/// overtaken with its notification queued, and reaches no timer callback.
/// When it ends with an ordinary getpid instead, its stop witnesses the
/// event once and counts one overtaken event with its notification queued,
/// and the stop decides the event after the overflow was due (one
/// preempted-overflow outcome).
///
/// The witness and overtaken counts are process-global and other tests in
/// this binary can write them, so the runs happen in a fresh exact-test
/// process.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_past_its_target_is_witnessed_at_exit_or_at_the_next_stop() {
    const LATE_TIMER_CHILD: &str = "REVERIE_PTRACE_LATE_TIMER_CHILD";
    if std::env::var_os(LATE_TIMER_CHILD).is_some() {
        late_timer_witnesses().await;
        return;
    }
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let (_, module) = module_path!()
        .split_once("::")
        .expect("the module path names the crate");
    let output = std::process::Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            &format!("{module}::a_timer_past_its_target_is_witnessed_at_exit_or_at_the_next_stop"),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LATE_TIMER_CHILD, "1")
        .output()
        .expect("run the late-timer child test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "late-timer child test failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The late-timer runs, in the exact-test child process that owns the
/// witness and overtaken counts.
async fn late_timer_witnesses() {
    let preempted = crate::timer::HostTimedTimerEvents {
        preempted_overflow: 1,
        ..Default::default()
    };
    for (mode, child_report, witnesses, overtaken, host_timed) in [
        (
            "late_timer_int80",
            "child signaled=1 termsig=31 exited=0 status=0",
            1,
            0,
            Default::default(),
        ),
        (
            "late_timer_getpid",
            "child signaled=0 termsig=0 exited=1 status=0",
            1,
            1,
            preempted,
        ),
    ] {
        let _ = reverie::take_skid_overshoot_count();
        let _ = crate::timer::take_host_timed_timer_events();
        let overtaken_before = crate::testing::precise_events_overtaken_with_notification_queued();
        let ptrace = run_guest(mode, false).await;
        let ptrace_witnesses = reverie::take_skid_overshoot_count();
        let ptrace_host_timed = crate::timer::take_host_timed_timer_events();
        let ptrace_overtaken =
            crate::testing::precise_events_overtaken_with_notification_queued() - overtaken_before;
        assert!(
            ptrace.report.contains(child_report),
            "{mode}: {}",
            ptrace.report
        );
        assert!(
            !ptrace.report.contains("int80 returned"),
            "{mode}: {}",
            ptrace.report
        );
        assert_eq!(
            ptrace.report.contains("late timer getpid=1"),
            mode == "late_timer_getpid",
            "{mode}: {}",
            ptrace.report
        );
        assert!(
            timer_events(&ptrace).is_empty(),
            "{mode}: {:#?}",
            ptrace.tool_events
        );
        assert_eq!(
            ptrace_witnesses, witnesses,
            "{mode}: skid-overshoot witnesses"
        );
        assert_eq!(
            ptrace_overtaken, overtaken,
            "{mode}: events overtaken with their notification queued"
        );
        assert_eq!(
            ptrace_host_timed, host_timed,
            "{mode}: host-timed timer outcomes"
        );
    }
}

/// JIT code through ordinary and tail injection of every mapping syscall:
/// code replaced after an mprotect, unmapped and mapped again, mapped over
/// with MAP_FIXED, moved with mremap and left writable runs at each step,
/// a fork child's change to its own copy leaves the parent's running, the
/// guest reads its own syscall bytes after each change, and madvise of the
/// fixture's own text leaves it running.
#[tokio::test(flavor = "current_thread")]
async fn jit_code_runs_across_mapping_changes() {
    let [inject, _] = run_both_configurations("jit").await;
    assert_report_has(
        &inject,
        &[
            "jit a 2 pid=1",
            "jit fork child a bytes 0f 05",
            "jit fork child exited=1 code=0",
            "jit a after fork pid=1",
            "jit a after mprotect rw bytes 0f 05",
            "jit a2 2 ppid=1",
            "jit b2 2 tid=1",
            "jit d after mmap fixed bytes 00 00",
            "jit c after mremap bytes 0f 05",
            "jit c2 2 pid=1",
            "jit e 2 pid=1",
            "jit e bytes 0f 05",
            "after madvise site bytes 0f 05",
            "done",
        ],
    );
}

/// A byte the guest stores over a JIT syscall through `/proc/self/mem`
/// survives the next mprotect, and code moved with `mremap(MREMAP_FIXED)`
/// onto another JIT page replaces it and runs at its new address.
#[tokio::test(flavor = "current_thread")]
async fn a_self_written_byte_and_an_mremap_destination_take_effect() {
    let [inject, _] = run_both_configurations("jit_more").await;
    assert_report_has(
        &inject,
        &[
            "more a 2 pid=1",
            "more a after self write bytes 90 05",
            "more f 2 pid=1",
            "more f after mremap bytes 00 00",
            "more f2 2 tid=1",
            "done",
        ],
    );
}

/// Whether this host's kernel lets a process pass `MADV_DONTNEED` for
/// itself to `process_madvise` (Linux 6.13 and later; older kernels accept
/// only the advice that newer ones allow for another address space, and
/// fail with EINVAL).
fn process_madvise_dontneed_on_self() -> bool {
    // SAFETY: an anonymous private page of our own, a pidfd for ourselves,
    // and an iovec that names only that page; all are released below.
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(page, libc::MAP_FAILED, "map a probe page");
        let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
        assert!(
            pidfd >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        let iov = libc::iovec {
            iov_base: page,
            iov_len: 4096,
        };
        let result = libc::syscall(
            libc::SYS_process_madvise,
            pidfd,
            &iov as *const libc::iovec,
            1,
            libc::MADV_DONTNEED,
            0,
        );
        let error = std::io::Error::last_os_error();
        libc::close(pidfd as libc::c_int);
        libc::munmap(page, 4096);
        match result {
            4096 => true,
            -1 if error.raw_os_error() == Some(libc::EINVAL) => false,
            _ => panic!("process_madvise probe returned {result}: {error}"),
        }
    }
}

/// `process_madvise(MADV_DONTNEED)` through a pidfd for the guest itself, on
/// the fixture's own text page, returns what the host kernel returns natively
/// (see `process_madvise_dontneed_on_self`), and the guest's text and a JIT
/// page the call does not name keep running.
#[tokio::test(flavor = "current_thread")]
async fn process_madvise_returns_the_native_result_and_the_guest_runs_on() {
    let expected_call = if process_madvise_dontneed_on_self() {
        "process_madvise ret=4096 errno=0"
    } else {
        "process_madvise ret=-1 errno=22"
    };
    let [inject, _] = run_both_configurations("process_madvise").await;
    assert_report_has(
        &inject,
        &[
            "pm jit 2 pid=1",
            expected_call,
            "after process_madvise site bytes 0f 05",
            "after process_madvise jit bytes 0f 05",
            "pm jit2 2 pid=1",
            "done",
        ],
    );
}

/// The shared site's first call is `process_madvise(MADV_DONTNEED)` on its
/// own page, through a pidfd for the guest itself: in both Tool
/// configurations it returns what the host kernel returns natively, and the
/// site reads `0f 05` after the call and after warm().
#[tokio::test(flavor = "current_thread")]
async fn process_madvise_as_the_first_call_returns_the_native_result() {
    let mode = "process_madvise_first";
    let expected_call = if process_madvise_dontneed_on_self() {
        "process_madvise first ret=4096"
    } else {
        "process_madvise first ret=-22"
    };
    for tail in [false, true] {
        let ptrace = run_guest(mode, tail).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                expected_call,
                "after process_madvise first site bytes 0f 05",
                "after warm site bytes 0f 05",
                "done",
            ],
        );
    }
}

/// A guest seccomp filter installed through the shared site, with TSYNC from
/// a two-thread process, or with prctl(PR_SET_SECCOMP): the install
/// succeeds, the filter denies getppid with EPERM (on the second thread too
/// under TSYNC), a fork child inherits it, and the image the child execs
/// runs under it; the filter's KILL_PROCESS for a foreign architecture never
/// fires, and no SIGSYS is delivered.
#[tokio::test(flavor = "current_thread")]
async fn a_guest_seccomp_filter_is_inherited_across_fork_and_exec() {
    for (mode, how) in [
        ("guest_seccomp", "site"),
        ("guest_seccomp_tsync", "tsync"),
        ("guest_seccomp_prctl", "prctl"),
    ] {
        let [inject, _] = run_both_configurations(mode).await;
        assert_report_has(
            &inject,
            &[
                &format!("install {how} ret=0"),
                "after install site bytes 0f 05",
                "getpid 2 pid=1",
                "getppid ret=-1",
                "child getpid 2 pid=1",
                "exec image getpid ok",
                "child exited=1 code=0 signaled=0 sig=0",
                "sigsys handled=0",
            ],
        );
        if how == "tsync" {
            assert_report_has(&inject, &["thread getppid ret=-1"]);
        }
    }
}

/// A signal sent while a call at the shared site is parked at its stop is
/// delivered after the call returned, at the site's end, with the call's
/// result in rax and the `syscall` instruction's rcx/r11, and the Tool sees
/// it there with orig_rax 39 (getpid).
#[tokio::test(flavor = "current_thread")]
async fn a_signal_pending_at_the_stop_is_delivered_after_the_call() {
    let [inject, _] = run_both_configurations("sig_pending").await;
    let s2 = format!("{:#x}", inject.site + 2);
    assert_report_has(
        &inject,
        &[
            "getpid returned pid=1",
            "sig_pending 0: sig=10 code=-6 value=-1 rip=tp_site_end rax=<pid> rcx=tp_site_end r11=0x246 ",
            "sig_pending_tail 0: sig=10 code=-6 value=-1 rip=tp_site_end rax=<pid> rcx=tp_site_end r11=0x246 ",
        ],
    );
    let all = inject.all_events();
    let event = format!("signal SIGUSR1 rip={s2} rax=<pid> orig_rax=39 rcx={s2} steps=");
    assert!(
        all.iter().any(|candidate| candidate.starts_with(&event)),
        "no Tool event starting {event:?} in {all:#?}"
    );
}

/// Queued thread- and process-directed signals sent while a call is parked
/// are delivered as five distinct signals, the first SIGUSR1 with its
/// SI_QUEUE value 1.
#[tokio::test(flavor = "current_thread")]
async fn queued_signals_keep_their_order_and_values() {
    let [inject, _] = run_both_configurations("rt_queue").await;
    let queued = inject
        .report
        .lines()
        .filter(|line| line.starts_with("queue "))
        .count();
    assert_eq!(
        queued, 5,
        "five distinct signals delivered:\n{}",
        inject.report
    );
    assert!(
        inject.report.contains("sig=10 code=-1 value=1"),
        "{}",
        inject.report
    );
}

/// Signals the call at the shared site raises itself (kill of self, a write
/// to a closed pipe, an unblock of a pending signal) are delivered at the
/// site's end with the call's result and the `syscall` rcx/r11.
#[tokio::test(flavor = "current_thread")]
async fn self_raised_signals_are_delivered_after_the_call() {
    let [inject, _] = run_both_configurations("self_raise").await;
    assert_report_has(
        &inject,
        &[
            "kill 0: sig=10 code=0 value=-1 rip=tp_site_end rax=0 rcx=tp_site_end r11=0x246 ",
            "sigpipe 0: sig=13 code=0 value=-1 rip=tp_site_end rax=-32 rcx=tp_site_end r11=0x246 ",
            "unblock 0: sig=12 code=-6 value=-1 rip=tp_site_end rax=0 rcx=tp_site_end r11=0x246 ",
        ],
    );
}

/// fork (whose child forks a grandchild), vfork, clone3 and a raw
/// CLONE_THREAD thread through the shared site: each child exits 7, the
/// fork child sees rcx/r11 of the `syscall`, and the parent keeps running.
/// With the Tool injecting every call, the injections consume the fork and
/// clone event stops; tail-injected, the run loop sees three fork stops
/// (fork, grandchild, clone3), one vfork and one clone stop, and the vfork
/// parent's vfork-done stop has the entry's -ENOSYS in rax.
#[tokio::test(flavor = "current_thread")]
async fn the_fork_family_runs_through_the_site() {
    let inject = run_guest("fork_family", false).await;
    let tail = run_guest("fork_family", true).await;
    for run in [&inject, &tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert_report_has(
            run,
            &[
                "before thread site bytes 0f 05",
                "fork child rcx=tp_site_end r11=0x246",
                "fork child status exited=1 code=7",
                "vfork child status exited=1 code=7",
                "clone3 child status exited=1 code=7",
                "after thread site bytes 0f 05",
                "getpid after thread pid=1",
                "done",
            ],
        );
    }
    assert_eq!(inject.counts.fork_stops() + inject.counts.clone_stops(), 0);
    assert_eq!(tail.counts.fork_stops(), 3, "fork, grandchild, clone3");
    assert_eq!(tail.counts.vfork_stops(), 1);
    assert_eq!(tail.counts.clone_stops(), 1);
    let vfork_done: Vec<&String> = tail
        .stops
        .values()
        .flatten()
        .filter(|stop| stop.starts_with("VforkDone"))
        .collect();
    assert_eq!(vfork_done, ["VforkDone rax=-38"], "{:#?}", tail.stops);
}

/// A clone without CLONE_THREAD, with exit signal 0, is reported as a clone
/// event but is its own process
/// (https://github.com/rrnewton/hermit/issues/4012). The Tool signals the
/// child's parked call with `tgkill(guest.pid(), guest.tid())`, which fails,
/// and fails the run, if the child is given its creator's process id.
#[tokio::test(flavor = "current_thread")]
async fn a_clone_without_clone_thread_is_its_own_process() {
    let run = run_guest("raw_clone_process", false).await;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    assert_report_has(&run, &["raw clone child status exited=1 code=7"]);
}

/// A clone with `CLONE_PARENT` and exit signal SIGUSR1, without
/// `CLONE_THREAD`, is a process whose parent is its creator's parent: the
/// Tool's `Guest::ppid` must name that parent, as the kernel's `getppid` does
/// (<https://github.com/rrnewton/hermit/issues/4012>). The creator stays
/// alive on a pipe until the child has checked.
#[tokio::test(flavor = "current_thread")]
async fn a_clone_parent_child_exposes_its_kernel_parent_to_the_tool() {
    let run = run_guest("raw_clone_parent_ppid", false).await;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    assert_report_has(&run, &["clone parent checked child=1 creator=1"]);
    assert_eq!(run.count_events("checked kernel PPid"), 1);
}

/// A real IA-32 `int 0x80` in a forked child kills it with SIGSYS, without a
/// seccomp stop, without returning and without any Tool event naming SIGSYS.
/// This needs no perf counters.
#[tokio::test(flavor = "current_thread")]
async fn a_foreign_int_0x80_dies_of_sigsys_without_a_tool_event() {
    let ptrace = run_guest("foreign_int80", false).await;
    assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
    assert!(
        ptrace
            .report
            .contains("child signaled=1 termsig=31 coredump="),
        "{}",
        ptrace.report
    );
    assert!(
        !ptrace.report.contains("int80 returned"),
        "{}",
        ptrace.report
    );
    assert!(
        !ptrace
            .stops
            .values()
            .flatten()
            .any(|stop| stop == "seccomp 20"),
        "the filter stopped the int 0x80: {:#?}",
        ptrace.stops
    );
    assert!(
        !ptrace
            .all_events()
            .iter()
            .any(|event| event.contains("SIGSYS")),
        "the Tool saw the SIGSYS: {:#?}",
        ptrace.all_events()
    );
}

/// An exec by the leader or by a non-leader thread installs the new image,
/// whose own calls through the site work.
#[tokio::test(flavor = "current_thread")]
async fn an_exec_by_the_leader_or_a_thread_runs_the_new_image() {
    for mode in ["exec_leader", "exec_thread"] {
        let [inject, _] = run_both_configurations(mode).await;
        assert_report_has(
            &inject,
            &["mode exec_image site=", "exec image getpid ok", "done"],
        );
    }
}

/// A fork, a vfork and a raw CLONE_THREAD thread through the shared site, in
/// both Tool configurations: each child exits 7 (the thread returns 1 to its
/// parent), and every copy of the address space reads the original bytes.
#[tokio::test(flavor = "current_thread")]
async fn fork_vfork_and_thread_children_read_the_original_bytes() {
    for tail in [false, true] {
        for (mode, lines) in [
            (
                "fork_undecided",
                &[
                    "undecided fork child site bytes 0f 05",
                    "undecided fork child exited=1 code=7",
                    "undecided fork parent site bytes 0f 05",
                    "done",
                ][..],
            ),
            (
                "vfork_undecided",
                &[
                    "undecided vfork child site bytes 0f 05",
                    "undecided vfork child exited=1 code=7",
                    "undecided vfork parent site bytes 0f 05",
                    "done",
                ][..],
            ),
            (
                "thread_mismatch",
                &[
                    "mismatch thread ret=1",
                    "mismatch thread parent site bytes 0f 05",
                    "done",
                ][..],
            ),
        ] {
            let ptrace = run_guest(mode, tail).await;
            assert_eq!(ptrace.status, ExitStatus::Exited(0), "{mode} tail={tail}");
            assert_report_has(&ptrace, lines);
        }
    }
}

/// posix_spawn and system() (both vfork-style) from a process with a warm
/// site: both children exec and exit as expected, and the parent's site
/// still works afterwards.
#[tokio::test(flavor = "current_thread")]
async fn vfork_style_spawns_exec_and_the_parent_runs_on() {
    let [inject, _] = run_both_configurations("vfork_spawn").await;
    assert_report_has(
        &inject,
        &[
            "exec image getpid ok",
            "spawn child exited=1 code=0",
            "system exited=1 code=3",
            "parent getpid ok",
            "done",
        ],
    );
}

/// The guest-filter TSYNC mode has two host-timed interleavings: the TSYNC
/// thread's exit against the leader's join, and the fork child's exit
/// (SIGCHLD) against the parent's wait4. Neither may reach the Tool:
/// `TP_ORDER=early` makes the thread and the child almost surely finish
/// first, `TP_ORDER=late` almost surely last, and the two runs must be
/// equal: exit status, report, every Tool event, final-resume registers,
/// stop sequence, signal-delivery stops and stop counts.
#[tokio::test(flavor = "current_thread")]
async fn thread_and_child_exit_order_does_not_reach_the_tool() {
    let run = |order| async move {
        let options = GuestOptions {
            order: Some(order),
            ..Default::default()
        };
        run_guest_options("guest_seccomp_tsync", options)
            .await
            .unwrap_or_else(|error| panic!("TP_ORDER={order} failed: {error}"))
    };
    let early = run("early").await;
    let late = run("late").await;
    assert_eq!(late.status, early.status, "exit status diverged");
    assert_eq!(late.report, early.report, "guest reports diverged");
    assert_eq!(late.tool_events, early.tool_events, "Tool events diverged");
    assert_eq!(
        late.resumes, early.resumes,
        "final-resume registers diverged"
    );
    assert_eq!(late.stops, early.stops, "stop sequences diverged");
    assert_eq!(
        late.signals, early.signals,
        "signal-delivery stops diverged"
    );
    assert_eq!(late.counts, early.counts, "stop counts diverged");
    assert_report_has(&early, &["thread getppid ret=-1", "sigsys handled=0"]);
}

/// Attempts of one precise-timer check; see `timer_mode_runs`.
const TIMER_ATTEMPTS: usize = 3;

/// The text of a caught panic.
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

/// Runs a mode whose Tool arms precise timers in both Tool configurations,
/// requires both runs to exit 0 with a complete report, then the test's own
/// `check` of the (inject, tail) runs. An attempt is retried, up to
/// `TIMER_ATTEMPTS` attempts, only when it failed and one of its runs had a
/// host-timed timer outcome (`HostTimedTimerEvents`, counted by the timer on
/// this thread): the perf overflow signal was handled past the target, or
/// exactly at the target with no step to place the event, or after another
/// stop had already ended the timer although its overflow was due. Each of
/// these puts the timer event (or its absence) where the host's signal
/// delivery put it.
///
/// A failed attempt without such an outcome fails the test at once. If
/// every attempt fails, each with such an outcome, the test fails too,
/// reporting that it measured nothing.
async fn timer_mode_runs(mode: &str, check: impl Fn(&[GuestRun; 2])) -> [GuestRun; 2] {
    timer_mode_runs_with(mode, GuestOptions::default(), check).await
}

/// [`timer_mode_runs`] with `options` beyond the mode and the Tool shape.
async fn timer_mode_runs_with(
    mode: &str,
    options: GuestOptions,
    check: impl Fn(&[GuestRun; 2]),
) -> [GuestRun; 2] {
    let shaped = |tail| GuestOptions { tail, ..options };
    let mut failures = Vec::new();
    for attempt in 1..=TIMER_ATTEMPTS {
        let _ = crate::timer::take_host_timed_timer_events();
        let runs = [
            run_guest_options(mode, shaped(false))
                .await
                .unwrap_or_else(|error| panic!("{mode} failed: {error}")),
            run_guest_options(mode, shaped(true))
                .await
                .unwrap_or_else(|error| panic!("{mode} failed: {error}")),
        ];
        let host_timed = crate::timer::take_host_timed_timer_events();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for run in &runs {
                assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
                assert!(run.report.ends_with("done\n"), "{}", run.report);
            }
            check(&runs);
        }));
        eprintln!(
            "TIMER-ATTEMPT {mode} attempt={attempt} passed={} host-timed={host_timed:?}",
            outcome.is_ok()
        );
        match outcome {
            Ok(()) => return runs,
            Err(panic) if host_timed.total() == 0 => std::panic::resume_unwind(panic),
            Err(panic) => {
                eprintln!(
                    "TIMER-RETRY {mode}: attempt {attempt} of {TIMER_ATTEMPTS} failed with \
                     host-timed timer outcomes {host_timed:?}"
                );
                failures.push(format!(
                    "attempt {attempt}: {host_timed:?}: {}",
                    panic_text(panic.as_ref())
                ));
            }
        }
    }
    panic!(
        "{mode}: no signal: all {TIMER_ATTEMPTS} attempts failed, each with a host-timed \
         timer outcome:\n{}",
        failures.join("\n")
    );
}

/// The number of the root task's `name` syscall entries that a timer
/// single-step reached.
fn stepped_entries(run: &GuestRun, name: &str) -> usize {
    let prefix = format!("{name} ");
    run.stepped_entries.get("task#0").map_or(0, |entries| {
        entries
            .iter()
            .filter(|entry| entry.starts_with(&prefix))
            .count()
    })
}

/// A precise timer armed at the site's getppid, k = 1..9 branches out, in a
/// loop of 200 iterations: only k = 1 and 2 fire (46 timer events); for
/// k >= 3 the timer's single-steps reach the traced getpid first, which
/// cancels the timer, and that getpid is entered by a single-step (154
/// stepped entries). The stepped `syscall` saved TF in r11, and the timer
/// clears it at the seccomp stop, so the Tool and the guest see r11 equal to
/// rflags at every getpid.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_loop_fires_or_steps_onto_the_next_syscall() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    timer_mode_runs("timer_loop", |[inject, _]| {
        let timers = timer_events(inject);
        eprintln!("timer loop timer events: {}", timers.len());
        assert_eq!(timers.len(), 46, "{timers:#?}");
        let stepped = stepped_entries(inject, "getpid");
        assert_eq!(
            stepped, 154,
            "stepped getpid entries: {:#?}",
            inject.stepped_entries
        );
        let leaked = inject.tool_events["task#0"]
            .iter()
            .filter(|event| {
                event.starts_with("entry getpid ") && event.contains(" r11=rflags:false ")
            })
            .count();
        assert_eq!(
            leaked, 0,
            "getpid entries whose r11 is not rflags: {:#?}",
            inject.tool_events
        );
        assert!(
            inject.report.contains("timer loop sum=400\n"),
            "{}",
            inject.report
        );
        // The guest sees the stepped getpid's r11 too: the fixture reports
        // every iteration whose r11 is not 0x246, and there is none.
        let iters: Vec<&str> = inject
            .report
            .lines()
            .filter(|line| line.starts_with("iter "))
            .collect();
        assert_eq!(iters, Vec::<&str>::new(), "{}", inject.report);
    })
    .await;
}

/// A timer far enough out that perf's own overflow signal starts the
/// single-steps, targeted at branch counts that land before, at and after
/// the getpid that follows a long loop: the targets before the getpid fire
/// (two timer events); the targets at and after it are cancelled when the
/// steps reach the traced getpid, which is then entered by a single-step
/// (two stepped entries). The guest's r11 is 0x246 at all four getpids.
#[tokio::test(flavor = "current_thread")]
async fn a_perf_marker_timer_steps_onto_the_next_syscall() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    timer_mode_runs("perf_marker", |[inject, _]| {
        let timers = timer_events(inject);
        eprintln!("perf marker timer events: {timers:#?}");
        assert_eq!(timers.len(), 2, "{timers:#?}");
        assert_eq!(
            stepped_entries(inject, "getpid"),
            2,
            "stepped getpid entries: {:#?}",
            inject.stepped_entries
        );
        for (c, r11) in [(0, "0x246"), (1, "0x246"), (2, "0x246"), (3, "0x246")] {
            assert!(
                inject
                    .report
                    .contains(&format!("marker {c} getpid=1 r11={r11}\n")),
                "{}",
                inject.report
            );
        }
    })
    .await;
}

/// A guest's ignored or blocked SIGTRAP survives exec as it does natively
/// (<https://github.com/rrnewton/hermit/issues/4409>). Reverie single-steps an
/// `mmap` of its private page in every new image before the guest's first
/// instruction (`setup_special_mmap_page`); each image reads the state its
/// predecessor set before any Tool injection. Exec keeps `SIG_IGN` and the
/// mask, and clears every action's flags and `sa_mask`.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_reverie_preinit_at_exec() {
    for run in run_both_configurations("sigtrap_exec").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("exec "))
            .collect();
        assert_eq!(
            lines,
            [
                "exec ign-blocked sigtrap=ign flags=0 usr2-in-mask=0 blocked=1",
                "exec ign sigtrap=ign flags=0 usr2-in-mask=0 blocked=0",
                "exec dfl-blocked sigtrap=dfl flags=0 usr2-in-mask=0 blocked=1",
            ],
            "{}",
            run.report
        );
    }
}

/// A guest's SIGTRAP state survives a guest `fork` run in place, whose parent
/// Reverie single-steps from its clone event stop (`handle_new_task`), in
/// both the parent and the child
/// (<https://github.com/rrnewton/hermit/issues/4409>).
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_a_guest_fork() {
    let runs = run_both_configurations("sigtrap_fork").await;
    let mut expected = Vec::new();
    for (state, action, blocked) in [
        ("ign-blocked", "ign", 1),
        ("ign", "ign", 0),
        ("handler-blocked", "trap_handler", 1),
    ] {
        for who in ["child", "parent"] {
            expected.push(format!(
                "fork {who} {state} sigtrap={action} flags=0x50000000 usr2-in-mask=1 \
                 blocked={blocked}"
            ));
        }
    }
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("fork "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// Calls that set SIGTRAP's action or the blocked mask, injected on the
/// private page and single-stepped, leave what they set
/// (<https://github.com/rrnewton/hermit/issues/4409>):
/// - `rt_sigaction(SIGTRAP, act)` with SIGTRAP blocked: the trap after the
///   call resets `act`, and the repair writes back `act`, not the action
///   before the call; from a write-only page too, which the kernel reads;
///   but from an inaccessible page, or one whose protection key denies
///   access (with or without `oldact`), the call fails before installing
///   `act`, and the repair writes back the action before the call; and with
///   an `oldact` the kernel cannot write, it installs `act` and then fails;
/// - `ppoll` with SIGTRAP in its temporary mask and a zero timeout: the kernel
///   restores the guest's mask before the step's trap, which then sees
///   SIGTRAP blocked only if the guest blocks it.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_private_calls_that_set_it() {
    // Protection keys need the CPU's and the kernel's support.
    let pkeys = std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|cpuinfo| {
        cpuinfo
            .lines()
            .find(|line| line.starts_with("flags"))
            .is_some_and(|flags| {
                let flags: Vec<&str> = flags.split_whitespace().collect();
                flags.contains(&"pku") && flags.contains(&"ospke")
            })
    });
    let pkey_rows = if pkeys {
        [
            "private-sigaction-pkey dfl r=efault sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
            "private-sigaction-pkey-oldact dfl r=efault sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
        ]
    } else {
        [
            "private-sigaction-pkey unavailable",
            "private-sigaction-pkey-oldact unavailable",
        ]
    };
    for run in run_both_configurations("sigtrap_private_calls").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("private-"))
            .collect();
        assert_eq!(
            lines,
            [
                "private-sigaction ign sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-sigaction handler sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-sigaction-writeonly ign sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-sigaction-noaccess dfl r=efault sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                pkey_rows[0],
                pkey_rows[1],
                "private-sigaction-badoldact ign r=efault sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-ppoll handler-blocked sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-ppoll ign-blocked sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                "private-ppoll handler sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=0",
            ],
            "{}",
            run.report
        );
    }
}

/// A guest's SIGTRAP state survives a mask-swapping wait that a handled
/// signal interrupts (<https://github.com/rrnewton/hermit/issues/4409>). The
/// wait, injected on the private page, returns with its temporary mask's
/// restore pending, so the action cannot be written back there; it is
/// written back at the guest's next seccomp stop, before the Tool or the
/// syscall reads it (`repair_sigtrap_at_seccomp_stop`). `rt_sigsuspend` and
/// `ppoll`, with SIGTRAP ignored or caught, in the temporary mask or not, and
/// blocked; both configurations.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_interrupted_waits() {
    let mut expected = Vec::new();
    for op in ["sigsuspend", "ppoll"] {
        for (state, action, blocked) in [
            ("ign", "ign", 0),
            ("ign-tmask", "ign", 0),
            ("handler-tmask", "trap_handler", 0),
            ("handler-blocked", "trap_handler", 1),
        ] {
            expected.push(format!(
                "wait {op} {state} r=eintr sigtrap={action} flags=0x50000000 usr2-in-mask=1 \
                 blocked={blocked}"
            ));
        }
    }
    for run in run_both_configurations("sigtrap_interrupted_waits").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("wait "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// A repair Reverie owes for SIGTRAP never overwrites an action the guest
/// sets itself (<https://github.com/rrnewton/hermit/issues/4409>): after a
/// guest fork resets an ignored SIGTRAP, the guest installs a handler with a
/// call the Tool runs in place (tail configuration) or injects exactly, and a
/// later private injection must leave that handler. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sigtrap_repair_never_overwrites_the_guests_own_action() {
    for run in run_both_configurations("sigtrap_fork_then_sigaction").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("stale "))
            .collect();
        assert_eq!(
            lines,
            [
                "stale after-fork sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=0",
                "stale after-sigaction sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=0",
                "stale after-private sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=0",
            ],
            "{}",
            run.report
        );
    }
}

/// A guest `int3` that a precise timer single-steps, with SIGTRAP caught and
/// blocked or ignored, resets SIGTRAP by its own `force_sig` and kills the
/// process, as natively: Reverie neither shields that step nor repairs it
/// (<https://github.com/rrnewton/hermit/issues/4409>). Also behind an
/// operand-size prefix (`66 cc`), and behind REX prefixes that are not last
/// (`48 48 cc`, `48 66 cc`), which the CPU ignores: each is an `int3` too.
/// And an `int3` in an execute-only page, which `process_vm_readv` cannot
/// read.
#[tokio::test(flavor = "current_thread")]
async fn a_guest_int3_in_a_timer_window_takes_sigtraps_default_action() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let mut expected = Vec::new();
    for encoding in ["cc", "66cc", "4848cc", "4866cc", "xo-cc"] {
        for case in [
            "handler-blocked-notimer",
            "handler-blocked",
            "ign",
            "ign-blocked",
        ] {
            for c in 2..6 {
                expected.push(format!("int3 {encoding} {case} c={c} signaled=1 sig=5"));
            }
        }
    }
    // 80 children per configuration: about 25 s quiet, and up to 85 s under
    // a loaded host, so each run has 240 s rather than the default 60 s.
    for run in run_both_configurations_within("sigtrap_int3_timer", Duration::from_secs(240)).await
    {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("int3 "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// A blocked SIGTRAP that is pending when Reverie must single-step the
/// thread cannot be kept, so the run ends with the named failure
/// `PendingSigtrapAtStep` instead of losing it
/// (<https://github.com/rrnewton/hermit/issues/4409>). Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_pending_blocked_sigtrap_at_a_step_ends_the_run_by_name() {
    for tail in [false, true] {
        let error = match run_guest_with("sigtrap_pending_at_step", tail).await {
            Ok(run) => panic!(
                "the run continued past a pending SIGTRAP (tail={tail}): {:?}\n{}",
                run.status, run.report
            ),
            Err(error) => error,
        };
        let refusal = match &error {
            Error::Tool(inner) => inner.downcast_ref::<crate::PendingSigtrapAtStep>(),
            _ => None,
        };
        let refusal = refusal.unwrap_or_else(|| {
            panic!("expected PendingSigtrapAtStep (tail={tail}), got {error:?}")
        });
        assert_eq!(refusal.site, "syscall skip", "{refusal}");
    }
}

/// Reverie's SIGTRAP repair keeps its scratch out of guest memory
/// (<https://github.com/rrnewton/hermit/issues/4409>): an emulated call with
/// SIGTRAP ignored and blocked, on a one-page stack between inaccessible
/// guard pages, 512 and 2048 bytes above the lower guard, succeeds, leaves
/// 32 canary bytes below the stack pointer unchanged (where that address is
/// on the page), and leaves SIGTRAP's state. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sigtrap_repair_touches_no_guest_stack() {
    for run in run_both_configurations("sigtrap_tight_stack").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("tight "))
            .collect();
        assert_eq!(
            lines,
            [
                "tight 512 r=4242 changed=-1 sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
                "tight 2048 r=4242 changed=0 sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
            ],
            "{}",
            run.report
        );
    }
}

/// A sibling thread that reads SIGTRAP's action after another thread's wait
/// was interrupted, while that thread's handler runs and before it makes
/// another syscall, reads the guest's action, not the reset `SIG_DFL`: the
/// repair is owed by the thread group, and the sibling's own syscall stop
/// writes it first (<https://github.com/rrnewton/hermit/issues/4409>). Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_never_reads_a_reset_sigtrap_action() {
    let mut expected = Vec::new();
    for op in ["sigsuspend", "ppoll"] {
        for (state, action) in [
            ("ign", "ign"),
            ("ign-tmask", "ign"),
            ("handler-tmask", "trap_handler"),
            ("handler-blocked", "trap_handler"),
        ] {
            expected.push(format!("observed {op} {state} r=eintr sibling={action}"));
        }
    }
    for run in run_both_configurations("sigtrap_interrupted_waits_observed").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("observed "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// The same observer as `a_sibling_never_reads_a_reset_sigtrap_action`, as
/// another process that shares the address space and the signal actions
/// (`CLONE_VM | CLONE_SIGHAND` without `CLONE_THREAD`): the repair is owed to
/// the signal-action table, not to a thread group, so the observer's own
/// syscall stop writes it first, and it reads the guest's action in every row
/// (<https://github.com/rrnewton/hermit/issues/4409>). Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_process_sharing_the_signal_actions_never_reads_a_reset_sigtrap_action() {
    let mut expected = Vec::new();
    for op in ["sigsuspend", "ppoll"] {
        for (state, action) in [
            ("ign", "ign"),
            ("ign-tmask", "ign"),
            ("handler-tmask", "trap_handler"),
            ("handler-blocked", "trap_handler"),
        ] {
            expected.push(format!("observed {op} {state} r=eintr sibling={action}"));
        }
    }
    for run in run_both_configurations("sigtrap_interrupted_waits_observed_process").await {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("observed "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// A thread named by bytes that are not UTF-8 keeps its blocked, caught
/// SIGTRAP through every handler shape. procfs reports the name as set, and
/// Reverie's reads of the thread's status once failed to decode it, which
/// they reported as a thread that is gone (ESRCH), ending the run.
#[tokio::test(flavor = "current_thread")]
async fn a_thread_with_a_raw_byte_name_keeps_its_sigtrap_state() {
    let runs = run_both_configurations("sigtrap_raw_name").await;
    let expected: Vec<String> = (0..7)
        .map(|shape| {
            format!(
                "raw-name shape={shape} sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"
            )
        })
        .collect();
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("raw-name "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// Reverie remembers whether SIGTRAP is ignored (`TracedTask::sigtrap_ignored`)
/// across the syscall skips of calls the Tool emulates. Each flip of the
/// action between `SIG_DFL` and `SIG_IGN` must reach what it remembers: a
/// stale "not ignored" lets a skip's trap reset `SIG_IGN` unrepaired, and a
/// stale "ignored" writes `SIG_IGN` over the guest's `SIG_DFL`.
#[tokio::test(flavor = "current_thread")]
async fn each_flip_of_sigtrap_reaches_the_remembered_disposition() {
    let runs = run_both_configurations("sigtrap_cache_flip").await;
    let expected: Vec<String> = [
        ("dfl", "dfl"),
        ("ign", "ign"),
        ("dfl-again", "dfl"),
        ("ign-again", "ign"),
    ]
    .iter()
    .map(|(flip, action)| {
        format!("flip {flip} sigtrap={action} flags=0x50000000 usr2-in-mask=1 blocked=0")
    })
    .collect();
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("flip "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// What an injected call reads of the thread's own signal state is what it
/// reads natively. For each SIGTRAP state the guest reads its procfs `status`
/// with a read the Tool handles in four shapes: injected in place, injected
/// in place and followed by another injection, injected on the private page
/// after a private getpid (`private-call`, the only shape whose read is
/// single-stepped), and run from its own seccomp stop (`tail`, a control).
/// `SigBlk` must hold SIGTRAP exactly when the guest blocked it, and `SigIgn`
/// and `SigCgt` must name the action it set. A step shield that unblocked
/// SIGTRAP for the private-page read made a blocked SIGTRAP read as
/// unblocked there (<https://github.com/rrnewton/hermit/issues/4485>). Pinned
/// limit: a caught SIGTRAP that the guest blocks keeps the shield, so that
/// its handler is never reset, and its private-page read still sees SIGTRAP
/// unblocked.
#[tokio::test(flavor = "current_thread")]
async fn an_injected_read_of_status_sees_the_guests_own_sigtrap_mask() {
    let runs = run_both_configurations("sigtrap_sigblk").await;
    let mut expected = Vec::new();
    for (state, ignored, caught, blocked) in [
        ("ign-blocked", 1, 0, 1),
        ("ign", 1, 0, 0),
        ("handler-blocked", 0, 1, 1),
        ("handler", 0, 1, 0),
        ("dfl-blocked", 0, 0, 1),
    ] {
        for shape in ["inject", "two-injects", "private-call", "tail"] {
            let sigblk = if state == "handler-blocked" && shape == "private-call" {
                0
            } else {
                blocked
            };
            expected.push(format!(
                "{state} {shape} SigBlk={sigblk} SigIgn={ignored} SigCgt={caught} \
                 blocked={blocked}"
            ));
        }
    }
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.contains(" SigBlk="))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// The SigBlk matrix of `an_injected_read_of_status_sees_the_guests_own_sigtrap_mask`
/// while a second thread of the process is parked in a read, so that the
/// signal-action table is shared (`SigtrapTables::shared`). There every step
/// keeps the shield exactly as on Reverie 9ded00ff: the private-page read
/// sees each blocked SIGTRAP unblocked (SigBlk=0), and every other field and
/// row reads as natively. Reverie 9ded00ff gives exactly these lines.
/// Unshielded, the default and ignored blocked private-page rows read
/// SigBlk=1. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_shared_table_keeps_the_step_shield_as_before() {
    let runs = run_both_configurations("sigtrap_sigblk_shared").await;
    let mut expected = Vec::new();
    for (state, ignored, caught, blocked) in [
        ("ign-blocked", 1, 0, 1),
        ("ign", 1, 0, 0),
        ("handler-blocked", 0, 1, 1),
        ("handler", 0, 1, 0),
        ("dfl-blocked", 0, 0, 1),
    ] {
        for shape in ["inject", "two-injects", "private-call", "tail"] {
            let sigblk = if shape == "private-call" { 0 } else { blocked };
            expected.push(format!(
                "shared {state} {shape} SigBlk={sigblk} SigIgn={ignored} SigCgt={caught} \
                 blocked={blocked}"
            ));
        }
    }
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("shared "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// The SigBlk matrix after a `CLONE_SIGHAND | CLONE_THREAD | CLONE_UNTRACED`
/// thread, which gives no new-child stop, has started spinning in the same
/// process: the table is shared, which Reverie learns from the clone the Tool
/// runs and from procfs (`may_unshield_step`), so every step keeps the shield
/// exactly as on Reverie 63934937, whose own lines these are. Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn an_untraced_sharer_keeps_the_step_shield_as_before() {
    let runs = run_both_configurations("sigtrap_sigblk_untraced").await;
    let mut expected = Vec::new();
    for (state, ignored, caught, blocked) in [
        ("ign-blocked", 1, 0, 1),
        ("ign", 1, 0, 0),
        ("handler-blocked", 0, 1, 1),
        ("handler", 0, 1, 0),
        ("dfl-blocked", 0, 0, 1),
    ] {
        for shape in ["inject", "two-injects", "private-call", "tail"] {
            let sigblk = if shape == "private-call" { 0 } else { blocked };
            expected.push(format!(
                "untraced {state} {shape} SigBlk={sigblk} SigIgn={ignored} SigCgt={caught} \
                 blocked={blocked}"
            ));
        }
    }
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("untraced "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
    }
}

/// On a shared table (a second thread parked), the mask-transition sequence
/// of a held signal: SIGRTMIN+2 blocked and pending, the Tool injects a ppoll
/// whose empty temporary mask lets it interrupt the call (Reverie holds the
/// signal, and the mask's restore is left pending), then the guest's status
/// read through the held-signal retry, whose path restores the saved mask
/// before the read's step. The shield is decided at that step, from the mask
/// then (`step_private_syscall`), as on Reverie 63934937, whose own lines
/// these are: each blocked SIGTRAP reads unblocked. (An ignored SIGTRAP reads
/// `SIG_DFL` during the read: the ppoll step's reset is owed until the
/// restore, as before; it is `SIG_IGN` again afterwards.) Deciding before the
/// held-signal path changed the mask let the read run unshielded. Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_held_signal_mask_transition_decides_the_shield_as_before() {
    let expected = [
        "hold ign-blocked SigBlk=0 SigIgn=0 SigCgt=0 blocked=1 hits=1",
        "hold ign-blocked after sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=1",
        "hold handler-blocked SigBlk=0 SigIgn=0 SigCgt=1 blocked=1 hits=1",
        "hold handler-blocked after sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1",
        "hold dfl-blocked SigBlk=0 SigIgn=0 SigCgt=0 blocked=1 hits=1",
        "hold dfl-blocked after sigtrap=dfl flags=0x50000000 usr2-in-mask=1 blocked=1",
        "hold dfl SigBlk=0 SigIgn=0 SigCgt=0 blocked=0 hits=1",
        "hold dfl after sigtrap=dfl flags=0x50000000 usr2-in-mask=1 blocked=0",
    ];
    for run in run_both_configurations("sigtrap_ppoll_hold_then_read").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("hold "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
        let reads = run
            .all_events()
            .iter()
            .filter(|event| event.contains("after ppoll -514"))
            .count();
        assert_eq!(reads, 4, "{}", run.report);
    }
}

/// An injection at a signal stop while a temporary mask's restore is pending
/// (the Tool's SIGPROF callback injects getpid after a private-page ppoll was
/// interrupted): resuming the thread for the getpid restores the saved mask
/// first, so its trap sees SIGTRAP as the saved mask has it. The ignored and
/// default states the saved mask blocks must keep their action and mask bit,
/// and so must a caught SIGTRAP the temporary mask blocked and the saved mask
/// admits. A caught SIGTRAP the saved mask blocks keeps its bit but loses its
/// handler (pinned below). On Reverie 9ded00ff, before injected calls ran
/// under the guest's own mask, the three blocked states came back unblocked.
/// Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn an_injection_at_a_pending_restore_keeps_sigtrap_under_either_mask() {
    let runs = run_both_configurations("sigtrap_callback_restore").await;
    let expected = [
        // Pinned limit: the handler is lost (the unstepped query that would
        // read it is refused while the restore is pending), as on Reverie
        // 9ded00ff; its mask bit is kept.
        ("handler-blocked-topen", "dfl", 1),
        ("ign-blocked-topen", "ign", 1),
        ("dfl-blocked-topen", "dfl", 1),
        ("handler-tshut", "trap_handler", 0),
    ]
    .map(|(state, action, blocked)| {
        format!(
            "restore {state} hits=1 sigtrap={action} flags=0x50000000 usr2-in-mask=1 \
             blocked={blocked}"
        )
    });
    for run in &runs {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("restore "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
        // Each state's SIGPROF reached the Tool's callback, whose getpid is
        // the injection under test. It reaches it a second time at the
        // guest's unblock: resuming for the getpid restored the saved mask,
        // which blocks SIGPROF, so the delivery waits for the unblock and the
        // ppoll returns getpid's result. That deferral predates the keep
        // (Reverie 9ded00ff does the same) and is not what this test pins.
        let callbacks = run
            .all_events()
            .iter()
            .filter(|event| event.starts_with("signal SIGPROF"))
            .count();
        assert!(callbacks >= 4, "{}", run.report);
    }
}

/// A caught SIGTRAP that the guest blocks, through 200 private injections (as
/// Detcore's polling loops run them under a mask that blocks every signal):
/// each step is shielded, so no trap resets the handler, and the run makes no
/// unstepped injection (`UNSTEPPED_INJECTIONS_FOR_TEST`); the handler and the
/// mask bit stay the guest's.
#[tokio::test(flavor = "current_thread")]
async fn a_caught_blocked_sigtrap_takes_no_repair_injection() {
    let before = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get());
    let run = run_guest("sigtrap_caught_blocked_injections", false).await;
    let made = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get()) - before;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    let lines: Vec<&str> = run
        .report
        .lines()
        .filter(|line| line.starts_with("caught-blocked "))
        .collect();
    assert_eq!(
        lines,
        ["caught-blocked after 200 sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"],
        "{}",
        run.report
    );
    assert_eq!(made, 0, "unstepped injections for 200 private steps");
}

/// A caught SIGTRAP that the guest blocks, where Reverie cannot read its
/// handler: a guest seccomp filter refuses `rt_sigaction` into Reverie's
/// repair page. The steps are shielded, so the handler is never read or
/// reset, and it and the mask bit stay the guest's through 20 private steps.
/// Reverie 9ded00ff passes this too; it guards the shield this state keeps.
/// Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_caught_blocked_sigtrap_whose_handler_cannot_be_read_is_kept() {
    for run in run_both_configurations("sigtrap_caught_blocked_no_repair").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("no-repair "))
            .collect();
        assert_eq!(
            lines,
            ["no-repair after 20 sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"],
            "{}",
            run.report
        );
    }
}

/// A caught SIGTRAP that the guest blocks, then a seccomp filter installed by
/// a call the Tool injects on the private page, then five more private
/// injections. Reverie gives up its repair page once the guest has a filter
/// of its own; every step is shielded, so none needs it, and the handler and
/// mask bit stay the guest's. (A Tool that declares serialized execution
/// refuses such calls; this one does not.) Reverie 9ded00ff passes this too;
/// it guards the shield this state keeps. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_filter_installing_injection_keeps_a_caught_blocked_sigtrap() {
    for run in run_both_configurations("sigtrap_caught_blocked_filter_install").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("filter-install "))
            .collect();
        assert_eq!(
            lines,
            ["filter-install after sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"],
            "{}",
            run.report
        );
    }
}

/// A sibling changes SIGTRAP's handler while this thread, with a caught
/// SIGTRAP blocked, is blocked in a private-page read (this Tool lets threads
/// run meanwhile, as Detcore does with a maybe-blocking external call). The
/// read's step is shielded, so its trap resets nothing, and the sibling's
/// handler is what the guest reads afterwards. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_change_during_an_injected_call_is_never_overwritten() {
    for run in run_both_configurations("sigtrap_sibling_change_during_call").await {
        let line = run
            .report
            .lines()
            .find(|line| line.starts_with("sibling-change "))
            .unwrap_or_else(|| panic!("no sibling-change line: {}", run.report));
        assert_eq!(line, "sibling-change sigtrap=sibling", "{}", run.report);
    }
}

/// The same sibling change, starting from a default or an ignored SIGTRAP
/// that this thread blocks. The table is shared (`SigtrapTables::shared`), so
/// the read's step keeps the shield, its trap resets nothing, and the
/// sibling's handler survives, as natively and on Reverie 9ded00ff. Unshielded,
/// the trap reset it to `SIG_DFL` (and, from an ignored start, the ignored
/// repair wrote `SIG_IGN` over it). Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_change_during_a_blocked_default_or_ignored_call_is_kept() {
    for (mode, expected) in [
        (
            "sigtrap_sibling_change_from_dfl",
            "sibling-change sigtrap=sibling",
        ),
        (
            "sigtrap_sibling_change_from_ign",
            "sibling-change sigtrap=sibling",
        ),
    ] {
        for run in run_both_configurations(mode).await {
            let line = run
                .report
                .lines()
                .find(|line| line.starts_with("sibling-change "))
                .unwrap_or_else(|| panic!("no sibling-change line: {}", run.report));
            assert_eq!(line, expected, "{mode}: {}", run.report);
        }
    }
}

/// A default SIGTRAP that the guest blocks, then a handler installed by an
/// `rt_sigaction` the Tool injects on the private page: the step is shielded,
/// as for a caught SIGTRAP, since the call installs one, so its trap resets
/// nothing, no other thread can meet a reset `SIG_DFL`, and the run makes no
/// unstepped injection. Unshielded, the handler was reset and written back
/// with one, which makes this the positive control of the counter the
/// zero-injection tests read.
#[tokio::test(flavor = "current_thread")]
async fn an_injected_handler_install_while_blocked_is_shielded() {
    let before = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get());
    let run = run_guest("sigtrap_blocked_installs_handler", false).await;
    let made = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get()) - before;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    let lines: Vec<&str> = run
        .report
        .lines()
        .filter(|line| line.starts_with("installs-handler "))
        .collect();
    assert_eq!(
        lines,
        ["installs-handler sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"],
        "{}",
        run.report
    );
    assert_eq!(made, 0, "unstepped injections");
}

/// Runs `mode` with injections and with tail injections, with sigreturns
/// reported, which the SIGSEGV keep needs (`GlobalState::keeps_segv_state`).
async fn run_segv_configurations(mode: &str) -> Vec<GuestRun> {
    let mut runs = Vec::new();
    for tail in [false, true] {
        let run = run_guest_options(
            mode,
            GuestOptions {
                tail,
                sigreturns: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| {
            panic!("regression fixture run {mode} tail={tail} failed: {error}")
        });
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
        runs.push(run);
    }
    runs
}

/// The SIGSEGV state lines (` sigsegv=`) of a report.
fn segv_lines(report: &str) -> Vec<String> {
    report
        .lines()
        .filter(|line| line.contains(" sigsegv="))
        .map(str::to_owned)
        .collect()
}

/// The SIGSEGV state lines of `mode` run natively, untraced, where neither
/// rdtsc nor cpuid faults.
fn native_segv_lines(mode: &str) -> Vec<String> {
    let report = tempfile_path(&format!("plain-guest-native-{mode}"));
    let status = std::process::Command::new(regression_guest())
        .arg(mode)
        .arg(&report)
        .status()
        .expect("run the regression fixture natively");
    assert!(status.success(), "native {mode}: {status}");
    let text = std::fs::read_to_string(&report).expect("read the native report");
    assert!(text.ends_with("done\n"), "{text}");
    segv_lines(&text)
}

/// Asserts that every traced run of `mode` reads SIGSEGV's state exactly as
/// `expected`, and so does a native run, which shows that `expected` is
/// Linux's own answer.
async fn assert_segv_lines(mode: &str, expected: &[String]) -> Vec<GuestRun> {
    assert_eq!(native_segv_lines(mode), expected, "native {mode}");
    let runs = run_segv_configurations(mode).await;
    for run in &runs {
        assert_eq!(segv_lines(&run.report), expected, "{}", run.report);
    }
    runs
}

/// The lines `segv_states` gives where SIGSEGV's state is kept, as natively.
fn kept_segv_states() -> Vec<String> {
    let mut expected = Vec::new();
    for (state, action, blocked) in [
        ("ign", "ign", 0),
        ("ign-blocked", "ign", 1),
        ("handler", "segv_handler", 0),
        ("handler-blocked", "segv_handler", 1),
        ("dfl", "dfl", 0),
        ("dfl-blocked", "dfl", 1),
    ] {
        for place in ["rdtsc", "cpuid"] {
            expected.push(format!(
                "{state} {place} sigsegv={action} flags=0x10000000 usr2-in-mask=1 \
                 blocked={blocked}"
            ));
        }
        expected.push(format!(
            "{state} in-handler sigsegv={action} flags=0x10000000 usr2-in-mask=1 blocked=1"
        ));
        expected.push(format!(
            "{state} after-handler sigsegv={action} flags=0x10000000 usr2-in-mask=1 \
             blocked={blocked}"
        ));
    }
    expected
}

/// A guest's SIGSEGV state survives Reverie's rdtsc and cpuid traps, as it
/// does natively, where neither instruction faults
/// (<https://github.com/rrnewton/hermit/issues/4485>). Linux reports each
/// trap with `force_sig`, which resets a blocked or ignored SIGSEGV to
/// `SIG_DFL` and unblocks it. Six states go through a trapped rdtsc, a
/// trapped cpuid (where the CPU can fault it), a trapped rdtsc that is the
/// first instruction of a SIGUSR1 handler whose `sa_mask` blocks SIGSEGV (the
/// bit comes from the delivery, read through the handler's action at the
/// trap), and a trapped rdtsc after that handler's `rt_sigreturn`, with no
/// syscall between (the bit comes from the frame); the guest reads back the
/// handler, the flags, `sa_mask` and the mask bit. Before this, every ignored
/// or blocked row read `sigsegv=dfl ... blocked=0`
/// (`without_its_preconditions_a_trapped_rdtsc_resets_sigsegv`).
#[tokio::test(flavor = "current_thread")]
async fn sigsegv_state_survives_rdtsc_and_cpuid_traps() {
    let before = crate::task::SEGV_REPAIRS_FOR_TEST.with(|count| count.get());
    let queries = crate::task::SEGV_TRAP_QUERIES_FOR_TEST.with(|count| count.get());
    assert_segv_lines("segv_states", &kept_segv_states()).await;
    let made = crate::task::SEGV_REPAIRS_FOR_TEST.with(|count| count.get()) - before;
    assert!(made > 0, "no repair ran");
    // The ignored and caught-blocked rows read the action at the trap, so the
    // counter `a_trap_that_resets_nothing_takes_no_repair` reads counts.
    let made = crate::task::SEGV_TRAP_QUERIES_FOR_TEST.with(|count| count.get()) - queries;
    assert!(made > 0, "no query at a trap");
}

/// The negative control of `sigsegv_state_survives_rdtsc_and_cpuid_traps`:
/// without a serialized-execution contract, or with sigreturns not traced
/// (so a guest `rt_sigreturn` can change the mask unseen), Reverie keeps
/// nothing, and each trapped rdtsc leaves Linux's reset, as before: an
/// ignored or blocked SIGSEGV reads `SIG_DFL` and unblocked, and only an
/// unblocked handler or default survives.
#[tokio::test(flavor = "current_thread")]
async fn without_its_preconditions_a_trapped_rdtsc_resets_sigsegv() {
    let expected: Vec<String> = [
        ("ign", "dfl"),
        ("ign-blocked", "dfl"),
        ("handler", "segv_handler"),
        ("handler-blocked", "dfl"),
        ("dfl", "dfl"),
        ("dfl-blocked", "dfl"),
    ]
    .iter()
    .map(|(state, action)| {
        format!("{state} rdtsc sigsegv={action} flags=0x10000000 usr2-in-mask=1 blocked=0")
    })
    .collect();
    for (no_serialization_contract, sigreturns) in [(true, true), (false, false)] {
        let run = run_guest_options(
            "segv_states",
            GuestOptions {
                no_serialization_contract,
                sigreturns,
                ..Default::default()
            },
        )
        .await
        .expect("run segv_states without the keep's preconditions");
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        let rdtsc: Vec<String> = segv_lines(&run.report)
            .into_iter()
            .filter(|line| line.contains(" rdtsc sigsegv="))
            .collect();
        assert_eq!(rdtsc, expected, "{}", run.report);
    }
}

/// A SIGSEGV handler whose first instruction is a trapped rdtsc keeps its
/// handler and its blocked SIGSEGV, as natively: the delivery of the guest's
/// own SIGSEGV (`raise`) blocks SIGSEGV for the handler, and the trap's forced
/// SIGSEGV would reset the handler being run. Back from it, SIGSEGV is
/// unblocked again.
#[tokio::test(flavor = "current_thread")]
async fn a_sigsegv_handler_that_traps_keeps_its_handler_and_mask() {
    let expected = [
        "segv-handler in-handler sigsegv=other flags=0x10000000 usr2-in-mask=1 blocked=1",
        "segv-handler after-handler sigsegv=other flags=0x10000000 usr2-in-mask=1 blocked=0",
    ]
    .map(str::to_owned);
    assert_segv_lines("segv_in_segv_handler", &expected).await;
}

/// A SIGSEGV handler with `SA_NODEFER` runs with SIGSEGV unblocked, so its
/// trap resets nothing; one with `SA_RESETHAND` is reset to `SIG_DFL` by its
/// own delivery and runs with SIGSEGV blocked, so its trap unblocks SIGSEGV
/// and the default action stays. Both read as natively: the record follows
/// the one-shot reset, and the mask bit comes from the delivery.
#[tokio::test(flavor = "current_thread")]
async fn sigsegv_handlers_with_nodefer_or_resethand_trap_as_natively() {
    let expected = [
        "nodefer in-handler sigsegv=other flags=0x50000000 usr2-in-mask=1 blocked=0",
        "nodefer after-handler sigsegv=other flags=0x50000000 usr2-in-mask=1 blocked=0",
        "resethand in-handler sigsegv=dfl flags=0x90000000 usr2-in-mask=1 blocked=1",
        "resethand after-handler sigsegv=dfl flags=0x90000000 usr2-in-mask=1 blocked=0",
    ]
    .map(str::to_owned);
    assert_segv_lines("segv_handler_flags", &expected).await;
}

/// A handler that a mask-swapping wait lets run traps under the wait's
/// temporary mask, as natively. SIGSEGV is blocked, and `ppoll`'s empty
/// temporary mask lets a pending SIGUSR1 through: its handler, with an empty
/// `sa_mask`, runs with SIGSEGV unblocked, though the mask `ppoll` restores
/// (which `PTRACE_GETSIGMASK` reports while the restore is pending) blocks
/// it. Taking that mask for the handler's would block SIGSEGV in it. Back
/// from `ppoll`, the restored mask blocks SIGSEGV.
#[tokio::test(flavor = "current_thread")]
async fn a_handler_under_a_temporary_mask_traps_under_that_mask() {
    let expected = [
        "ppoll in-handler sigsegv=dfl flags=0x10000000 usr2-in-mask=1 blocked=0",
        "ppoll after sigsegv=dfl flags=0x10000000 usr2-in-mask=1 blocked=1",
    ]
    .map(str::to_owned);
    assert_segv_lines("segv_ppoll_handler", &expected).await;
}

/// A second thread's trap on the signal-action table it shares, a fork
/// child's on its copy, and traps after exec (an ignored SIGSEGV stays
/// ignored, a handler becomes `SIG_DFL` with no flags or mask, and the mask
/// is kept) and in a `clone3` child made with `CLONE_CLEAR_SIGHAND`, whose
/// copy of the actions is flushed: each keeps SIGSEGV's state as natively.
#[tokio::test(flavor = "current_thread")]
async fn sigsegv_state_survives_traps_in_threads_forks_execs_and_clones() {
    let ign = |tag: &str| format!("{tag} sigsegv=ign flags=0x10000000 usr2-in-mask=1 blocked=1");
    assert_segv_lines(
        "segv_thread",
        &[
            ign("thread rdtsc"),
            ign("thread main-after"),
            ign("thread main-rdtsc"),
        ],
    )
    .await;
    assert_segv_lines(
        "segv_fork",
        &[ign("fork child-rdtsc"), ign("fork parent-rdtsc")],
    )
    .await;
    assert_segv_lines(
        "segv_exec",
        &[
            "exec ign-blocked rdtsc sigsegv=ign flags=0 usr2-in-mask=0 blocked=1".to_owned(),
            "exec handler-blocked rdtsc sigsegv=dfl flags=0 usr2-in-mask=0 blocked=1".to_owned(),
        ],
    )
    .await;
    assert_segv_lines(
        "segv_clear_sighand",
        &[
            "clear-sighand child-rdtsc sigsegv=dfl flags=0 usr2-in-mask=0 blocked=1".to_owned(),
            "clear-sighand parent-rdtsc sigsegv=segv_handler flags=0x10000000 usr2-in-mask=1 \
             blocked=1"
                .to_owned(),
        ],
    )
    .await;
}

/// A signal handed to a resume from a stop that is not a signal-delivery
/// stop runs no handler, and so sets no handler mask: ptrace drops a SIGUSR1
/// passed on the resume of a seccomp stop
/// (`a_final_resume_signal_is_sent_only_from_a_syscall_exit_stop`), so the
/// trapped rdtsc right after the call runs with SIGSEGV unblocked, as
/// natively, though the SIGUSR1 handler's `sa_mask` blocks it. Taking the
/// signal as delivered would block SIGSEGV at the trap.
#[tokio::test(flavor = "current_thread")]
async fn a_signal_a_resume_drops_sets_no_handler_mask() {
    let expected =
        ["dropped after sigsegv=dfl flags=0x10000000 usr2-in-mask=1 blocked=0".to_owned()];
    assert_segv_lines("segv_resume_signal_dropped", &expected).await;
}

/// A table a thread Reverie does not trace may use has no known SIGSEGV
/// action. The guest ignores SIGSEGV, makes a thread sharing the actions that
/// spins without a syscall, and traps an rdtsc. With a traced thread the
/// ignored action is kept, as natively. With `CLONE_UNTRACED` the clone gives
/// no new-task event, so the table is marked (`note_segv_clone_result`) and
/// the trap leaves the reset `SIG_DFL`, as before this change: that thread's
/// own forced signals and one-shot deliveries could change the action unseen.
/// Run with tail injections, where the guest's clone runs from its own code
/// and the next stop must be the new-task event; an injected clone starts its
/// child on Reverie's private page, which an untraced child cannot leave.
#[tokio::test(flavor = "current_thread")]
async fn an_untraced_sharer_leaves_the_sigsegv_reset_as_before() {
    for (mode, expected) in [
        (
            "segv_sharer_t",
            "sharer traced rdtsc sigsegv=ign flags=0x10000000 usr2-in-mask=1 blocked=0",
        ),
        (
            "segv_sharer_u",
            "sharer untraced rdtsc sigsegv=dfl flags=0x10000000 usr2-in-mask=1 blocked=0",
        ),
    ] {
        let native = native_segv_lines(mode);
        assert_eq!(native.len(), 1, "{native:?}");
        assert!(native[0].contains("sigsegv=ign"), "{native:?}");
        let run = run_guest_options(
            mode,
            GuestOptions {
                tail: true,
                sigreturns: true,
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{mode}: {error}"));
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert_eq!(
            segv_lines(&run.report),
            [expected.to_owned()],
            "{}",
            run.report
        );
    }
}

/// A trap that resets nothing (SIGSEGV neither blocked nor ignored) costs no
/// repair: 400 trapped rdtscs under a handler and under `SIG_DFL` make none
/// (`SEGV_REPAIRS_FOR_TEST`) and no query (`SEGV_TRAP_QUERIES_FOR_TEST`),
/// and the state reads as natively. With injections, which keep the action
/// known from the guest's own rt_sigaction, the whole run's unstepped queries
/// are bounded too.
#[tokio::test(flavor = "current_thread")]
async fn a_trap_that_resets_nothing_takes_no_repair() {
    let before = crate::task::SEGV_REPAIRS_FOR_TEST.with(|count| count.get());
    let queries = crate::task::SEGV_TRAP_QUERIES_FOR_TEST.with(|count| count.get());
    let expected = [
        "quiet handler sigsegv=segv_handler flags=0x10000000 usr2-in-mask=1 blocked=0",
        "quiet dfl sigsegv=dfl flags=0x10000000 usr2-in-mask=1 blocked=0",
    ]
    .map(str::to_owned);
    assert_segv_lines("segv_quiet", &expected).await;
    let made = crate::task::SEGV_REPAIRS_FOR_TEST.with(|count| count.get()) - before;
    assert_eq!(made, 0);
    let made = crate::task::SEGV_TRAP_QUERIES_FOR_TEST.with(|count| count.get()) - queries;
    assert_eq!(made, 0);
    // With injections, a whole run makes at most three unstepped queries,
    // none at a trap: pre-init's, in the launcher before its exec, and one
    // after each of the mode's two rt_sigaction calls, which reads back the
    // action they installed (`learn_segv_action`). A learning loop that
    // repeated at every stop would exceed it.
    let unstepped = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get());
    let run = run_guest_options(
        "segv_quiet",
        GuestOptions {
            sigreturns: true,
            ..Default::default()
        },
    )
    .await
    .expect("run segv_quiet with injections");
    assert_eq!(segv_lines(&run.report), expected, "{}", run.report);
    let made = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get()) - unstepped;
    assert!(made <= 3, "{made} unstepped queries");
}

/// A caught, unblocked SIGTRAP needs no repair: no step can reset it, so a run
/// through every handler shape makes no unstepped injection
/// (`UNSTEPPED_INJECTIONS_FOR_TEST`) and keeps the handler.
#[tokio::test(flavor = "current_thread")]
async fn a_caught_unblocked_sigtrap_takes_no_repair_injection() {
    let before = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get());
    let run = run_guest("sigtrap_caught_unblocked", false).await;
    let made = crate::task::UNSTEPPED_INJECTIONS_FOR_TEST.with(|count| count.get()) - before;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    let lines: Vec<&str> = run
        .report
        .lines()
        .filter(|line| line.starts_with("caught "))
        .collect();
    let expected: Vec<String> = (0..6)
        .map(|shape| {
            format!(
                "caught shape={shape} sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=0"
            )
        })
        .collect();
    assert_eq!(lines, expected, "{}", run.report);
    assert_eq!(made, 0, "unstepped injections");
}

/// A phase-0 limit, pinned: a guest `int3` right after a wait that a handled
/// signal interrupted, with a caught, unblocked SIGTRAP in the wait's
/// temporary mask, meets the reset `SIG_DFL` and kills the child. The repair
/// is owed while the wait's mask restore is pending, and is written at the
/// thread's next syscall or timer event, which the `int3` precedes. Natively
/// the handler runs and the child exits 0, so this test must change when the
/// window closes (<https://github.com/rrnewton/hermit/issues/4409>).
#[tokio::test(flavor = "current_thread")]
async fn an_int3_right_after_an_interrupted_wait_still_meets_the_reset_action() {
    for run in run_both_configurations("sigtrap_int3_after_interrupted_wait").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("after-wait "))
            .collect();
        assert_eq!(
            lines,
            [
                "after-wait sigsuspend signaled=1 sig=5 exited=-1",
                "after-wait ppoll signaled=1 sig=5 exited=-1",
            ],
            "{}",
            run.report
        );
    }
}

/// A Tool that injects from its signal callback, then resumes the signal,
/// while the guest's SIGTRAP is default, ignored or caught
/// (<https://github.com/rrnewton/hermit/issues/4409>). The repair a reset owes
/// is never written inside the callback: its injections end at a
/// syscall-exit stop, from which the resumed signal would be sent anew, with
/// a made-up siginfo, and reported to the Tool again without end. The guest's
/// handler runs exactly once with the POSIX timer's own siginfo (`SI_TIMER`,
/// value 1234), each signal reaches the Tool exactly once, and SIGTRAP's
/// action is the guest's afterwards. SIGPROF's callback injects getpid;
/// SIGXCPU's brackets it with block-all `rt_sigprocmask` injections, which
/// reset even a caught SIGTRAP. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_signal_callback_injection_delivers_the_signal_once_and_keeps_sigtrap() {
    let mut expected = Vec::new();
    for signal in ["prof", "xcpu"] {
        for (state, action) in [("dfl", "dfl"), ("ign", "ign"), ("handler", "trap_handler")] {
            expected.push(format!(
                "callback {signal} {state} hits=1 code=-2 value=1234 sigtrap={action}"
            ));
        }
    }
    for run in run_both_configurations("sigtrap_signal_callback").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("callback "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
        let events = run.all_events();
        let reports = |name: &str| {
            events
                .iter()
                .filter(|event| event.starts_with(&format!("{name} ")))
                .count()
        };
        assert_eq!(reports("signal SIGPROF"), 3, "{events:#?}");
        assert_eq!(reports("signal SIGXCPU"), 3, "{events:#?}");
    }
}

/// Phase-0 limits, pinned: the reset `SIG_DFL` is also met by another thread
/// and by a guest handler after a signal-callback injection, not only by the
/// interrupted thread itself
/// (`an_int3_right_after_an_interrupted_wait_still_meets_the_reset_action`).
/// The repair is owed to the signal-action table, and a thread's read of the
/// action takes a syscall stop that writes it first; a delivery takes no
/// stop. So, with a caught, unblocked SIGTRAP:
/// - a sibling's `int3` while the interrupted thread's handler runs without a
///   syscall kills the child when SIGTRAP was in the wait's temporary mask,
///   and not otherwise;
/// - an `int3` in the guest's handler of a POSIX-timer signal whose Tool
///   callback injected block-all `rt_sigprocmask` calls (SIGXCPU) kills the
///   child, since the repair waits for a stop outside the callback; with only
///   a shielded `getpid` (SIGPROF) it does not.
///
/// Natively every child exits 0, so this test must change when the windows
/// close (<https://github.com/rrnewton/hermit/issues/4409>). Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn an_int3_in_another_thread_or_after_a_callback_injection_still_meets_the_reset_action() {
    for run in run_both_configurations("sigtrap_int3_in_the_other_windows").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("sibling ") || line.starts_with("callback "))
            .collect();
        assert_eq!(
            lines,
            [
                "sibling sigsuspend tmask=0 signaled=0 sig=0 exited=0",
                "sibling sigsuspend tmask=1 signaled=1 sig=5 exited=-1",
                "sibling ppoll tmask=0 signaled=0 sig=0 exited=0",
                "sibling ppoll tmask=1 signaled=1 sig=5 exited=-1",
                "callback prof signaled=0 sig=0 exited=0",
                "callback xcpu signaled=1 sig=5 exited=-1",
            ],
            "{}",
            run.report
        );
    }
}

/// Reverie's SIGTRAP repair page is the page after the trampoline
/// (0x71001000), mapped read-write and sealed at exec
/// (<https://github.com/rrnewton/hermit/issues/4409>): Reverie's private range
/// is the trampoline (`r-xp`) and that page (`rw-p`), sealed; the guest cannot
/// map over, unmap or reprotect it (a pinned difference from native, as for
/// the trampoline page), so a repair's writes never reach a guest page; a
/// repair leaves the guest's mappings as they were; and a forked child keeps
/// the seal, and its repairs too. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sigtrap_repair_never_writes_a_guest_page_over_reverie_scratch() {
    for run in run_both_configurations("sigtrap_scratch_overlay").await {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("overlay "))
            .collect();
        assert_eq!(
            lines,
            [
                "overlay maps 71000000-71001000 r-xp",
                "overlay maps 71001000-71002000 rw-p",
                "overlay parent noreplace=eexist fixed=eperm munmap=eperm mprotect=eperm sealed=1",
                "overlay repaired maps-same=1 sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=0",
                "overlay child noreplace=eexist fixed=eperm munmap=eperm mprotect=eperm sealed=1",
                "overlay child-repaired sigtrap=ign flags=0x50000000 usr2-in-mask=1 blocked=0",
            ],
            "{}",
            run.report
        );
    }
}

/// Builds `repair_page_elf_segment.S`, a static ELF with a read-write data
/// segment at 0x71001000, once per test binary directory, keyed by the
/// sources (FNV-1a).
fn repair_page_elf_segment_guest() -> &'static std::path::Path {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        let source = crate::tracer::tests::fixture("repair_page_elf_segment.S");
        let script = crate::tracer::tests::fixture("repair_page_elf_segment.ld");
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        let mut text = std::fs::read(&source).expect("read the ELF segment fixture source");
        text.extend(std::fs::read(&script).expect("read the ELF segment linker script"));
        let hash = text.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        let output = directory.join(format!("reverie-repair-page-elf-segment-{hash:016x}"));
        let staging = directory.join(format!(
            "reverie-repair-page-elf-segment-{hash:016x}.{}.tmp",
            std::process::id()
        ));
        let status = std::process::Command::new("cc")
            .args(["-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none"])
            .arg(format!("-Wl,-T,{}", script.display()))
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .expect("run cc");
        assert!(
            status.success(),
            "cc failed to build the ELF segment fixture"
        );
        std::fs::rename(&staging, &output).expect("publish the ELF segment fixture");
        output
    });
    &GUEST
}

/// A guest ELF segment loaded at 0x71001000, the page after the trampoline
/// where pre-init maps Reverie's sealed SIGTRAP repair page, keeps every
/// byte: pre-init maps the repair page with `MAP_FIXED_NOREPLACE`, so it never
/// replaces what the new image already has there, and the address space then
/// has no repair page (<https://github.com/rrnewton/hermit/issues/4409>). The
/// guest checks all 4096 bytes and exits 40 if any changed. Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_guest_elf_segment_at_the_repair_page_address_keeps_every_byte() {
    let guest = repair_page_elf_segment_guest();
    for tail in [false, true] {
        let tracer = TracerBuilder::<GuestTool>::new(Command::new(guest))
            .config(GuestConfig {
                tail,
                partial: false,
                sigreturns: false,
                serialized: true,
            })
            .spawn()
            .await
            .expect("spawn the ELF segment guest");
        let (status, _) = tokio::time::timeout(Duration::from_secs(60), tracer.wait())
            .await
            .expect("the ELF segment guest timed out")
            .expect("trace the ELF segment guest");
        assert_eq!(
            status,
            ExitStatus::Exited(0),
            "tail={tail}: exit 40 means a byte of the guest's segment changed"
        );
    }
}

/// A sibling's ordinary find-a-hole mapping (`mmap(NULL)`, `munmap`, then
/// `MAP_FIXED` or `MAP_FIXED_NOREPLACE` at that address) never meets a SIGTRAP
/// repair's page, which is at Reverie's reserved address, while another
/// thread's 4000 private injections each repair an ignored SIGTRAP: the
/// sibling's page is never lost or changed, and its NOREPLACE never fails.
/// In the inject configuration every read of SIGTRAP after a repair sees it
/// ignored; the tail configuration runs the sibling's own syscalls as stepped
/// injections, and a read while one is mid-step can see the reset, a phase-0
/// limit, so its count is not asserted
/// (<https://github.com/rrnewton/hermit/issues/4409>).
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_mapping_pages_never_meets_a_sigtrap_repair_page() {
    // 4000 repairs per run: 10 to 20 s quiet.
    let [inject, tail] =
        run_both_configurations_within("sigtrap_mmap_race", Duration::from_secs(240)).await;
    for (run, is_tail) in [(inject, false), (tail, true)] {
        let line = run
            .report
            .lines()
            .find(|line| line.starts_with("race "))
            .unwrap_or_else(|| panic!("no race line: {}", run.report));
        eprintln!("tail={is_tail} {line}");
        assert!(
            line.starts_with("race reserved=0 lost=0 changed=0 eexist=0 action-bad="),
            "{line}"
        );
        assert!(line.ends_with(" iters-nonzero=1"), "{line}");
        if !is_tail {
            assert!(line.contains(" action-bad=0 "), "{line}");
        }
    }
}

/// A sibling that tries to map over Reverie's sealed repair page with
/// `MAP_FIXED`, again and again, while another thread's private injections
/// repair an ignored SIGTRAP: the seal refuses every attempt (`EPERM`), so no
/// repair writes a sibling's page, and the sibling's pages elsewhere never
/// change (<https://github.com/rrnewton/hermit/issues/4409>). Both
/// configurations.
/// Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_can_never_map_over_the_sealed_repair_page() {
    for run in
        run_both_configurations_within("sigtrap_reserved_page_race", Duration::from_secs(240)).await
    {
        let line = run
            .report
            .lines()
            .find(|line| line.starts_with("race "))
            .unwrap_or_else(|| panic!("no race line: {}", run.report));
        assert!(
            line.starts_with("race reserved=1 lost=0 changed=0 eexist=0 action-bad="),
            "{line}"
        );
        assert!(line.ends_with(" iters-nonzero=1 refused=all"), "{line}");
    }
}

/// A guest's SIGTRAP state survives a precise timer's single-steps
/// (<https://github.com/rrnewton/hermit/issues/4409>). For each of five states
/// (ignored or caught, blocked or not, and default blocked) the timer fires
/// once in a branch loop it single-steps the end of, and the guest reads back
/// the handler, flags, `sa_mask` and mask bit it set, in every run. At least
/// one run must have stepped all five sequences
/// (`TIMER_SEQUENCES_STEPPED_FOR_TEST`).
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_timer_steps() {
    use std::sync::atomic::Ordering;
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let expected: Vec<String> = [
        ("ign-blocked", "ign", 1),
        ("ign", "ign", 0),
        ("handler-blocked", "trap_handler", 1),
        ("handler", "trap_handler", 0),
        ("dfl-blocked", "dfl", 1),
    ]
    .into_iter()
    .map(|(state, action, blocked)| {
        format!("timer {state} sigtrap={action} flags=0x50000000 usr2-in-mask=1 blocked={blocked}")
    })
    .collect();
    // Under load a timer can fire past its target and be delivered without
    // single-steps, so a run may step fewer than all five sequences. The
    // state must survive in every run; the runs are repeated until one has
    // stepped all five, so that each state is shown to survive real steps.
    const ATTEMPTS: usize = 4;
    for attempt in 1..=ATTEMPTS {
        let before = crate::task::TIMER_SEQUENCES_STEPPED_FOR_TEST.load(Ordering::SeqCst);
        let run = run_guest("sigtrap_timer", false).await;
        let stepped = crate::task::TIMER_SEQUENCES_STEPPED_FOR_TEST.load(Ordering::SeqCst) - before;
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        let timers = timer_events(&run);
        assert_eq!(timers.len(), 5, "{timers:#?}");
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| line.starts_with("timer "))
            .collect();
        assert_eq!(lines, expected, "{}", run.report);
        if stepped == 5 {
            return;
        }
        eprintln!(
            "attempt {attempt} of {ATTEMPTS}: {stepped} of 5 timer sequences stepped: {timers:#?}"
        );
    }
    panic!("no run in {ATTEMPTS} stepped all five timer sequences");
}

/// A caught, blocked SIGTRAP survives a timer step over a guest
/// `rt_sigreturn` whose frame blocks SIGTRAP: the step clears SIGTRAP from the
/// frame for its trap and blocks it again after
/// (<https://github.com/rrnewton/hermit/issues/4409>). The Tool sends SIGUSR1 at
/// each arming call, so the timer, 1 to 8 branches out, single-steps the
/// handler and its return; at least one step must have met such a frame
/// (`FRAME_SHIELDS_FOR_TEST`).
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_state_survives_a_timer_step_over_sigreturn() {
    use std::sync::atomic::Ordering;
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let before = crate::task::FRAME_SHIELDS_FOR_TEST.load(Ordering::SeqCst);
    let run = run_guest("sigtrap_sigreturn_timer", false).await;
    let shields = crate::task::FRAME_SHIELDS_FOR_TEST.load(Ordering::SeqCst) - before;
    assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
    eprintln!("sigreturn timer events: {:#?}", timer_events(&run));
    assert!(
        shields > 0,
        "no timer step met a SIGTRAP-blocking rt_sigreturn frame"
    );
    let expected: Vec<String> = (1..=8)
        .map(|k| {
            format!(
                "sigreturn k={k} sigtrap=trap_handler flags=0x50000000 usr2-in-mask=1 blocked=1"
            )
        })
        .collect();
    let lines: Vec<&str> = run
        .report
        .lines()
        .filter(|line| line.starts_with("sigreturn "))
        .collect();
    assert_eq!(lines, expected, "{}", run.report);
}

/// A timer single-step that reaches an untraced number (500) steps over it,
/// so it returns ENOSYS, and the timer fires once.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_step_over_an_untraced_number_returns_enosys_and_fires() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let ptrace = run_guest("timer_allow", false).await;
    assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
    assert_report_has(&ptrace, &["timer allow ret=-38 errno=38 "]);
    assert_eq!(timer_events(&ptrace).len(), 1, "{:#?}", ptrace.all_events());
}

/// A counting-phase timer armed at the site's getppid stays armed across an
/// untraced number (500) through a generic site, and across rt_sigreturn
/// from a signal handler that armed it, and fires exactly once, in the
/// branch loop after it, in both Tool configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_counting_timer_survives_an_untraced_number_and_a_handler_return() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    for (mode, line) in [
        (
            "timer_hop_unknown",
            "timer hop unknown ret=-38 getpid=1 bytes after 0f 05",
        ),
        (
            "timer_hop_sigreturn",
            "timer hop sigreturn getpid=1 bytes after 0f 05",
        ),
    ] {
        timer_mode_runs(mode, |runs| {
            for run in runs {
                assert_eq!(
                    timer_events(run).len(),
                    1,
                    "{mode}: {:#?}",
                    run.all_events()
                );
                assert_report_has(run, &[line]);
            }
        })
        .await;
    }
}

/// A Tool that observes sigreturns makes each handler return a stop that the
/// Tool does not see as an event, and the timer event fires where it fires
/// without the opt-in. Far from its target the stop keeps the event as an
/// injected-trap `rt_sigreturn` does; within the keep margin (10005
/// branches), where an injected-trap return cancels it, the stop requests it
/// again at the same target (`Timer::disregard_sigreturn_stop`).
/// `timer_far_sigreturn` arms its timer 30001 branches before the handler
/// returns, and `timer_hop_sigreturn` 3001: in each, the same single timer
/// event fires, at the same instruction and clock, as without the opt-in.
/// Only the number of single steps toward it may differ, which host timing
/// decides. `timer_hop_sigreturn_blocked` blocks the timer's signal across
/// the return, so the stop cannot request the event again and cancels it,
/// as before. Each handler return is reported, one per run.
#[tokio::test(flavor = "current_thread")]
async fn a_reported_handler_return_keeps_a_timer_at_its_target() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let observing = GuestOptions {
        sigreturns: true,
        ..Default::default()
    };
    let _serial = SIGRETURN_TESTS.lock().await;
    SIGRETURN_REPORTS.lock().unwrap().clear();
    // Each attempt's check takes the reports its two runs made (a retried
    // attempt's check takes its own): one handler return per run when
    // observing, none otherwise.
    let reports_per_attempt = |expected: usize| {
        let reports = std::mem::take(&mut *SIGRETURN_REPORTS.lock().unwrap());
        assert_eq!(reports.len(), expected, "{reports:?}");
    };
    let one_event = |line: &'static str, reports: usize| {
        move |runs: &[GuestRun; 2]| {
            reports_per_attempt(reports);
            for run in runs {
                assert_eq!(timer_events(run).len(), 1, "{:#?}", run.all_events());
                assert_report_has(run, &[line]);
            }
        }
    };
    let far = "timer far sigreturn getpid=1 bytes after 0f 05";
    let plain = timer_mode_runs("timer_far_sigreturn", one_event(far, 0)).await;
    let observed = timer_mode_runs_with("timer_far_sigreturn", observing, one_event(far, 2)).await;
    for (plain, observed) in plain.iter().zip(&observed) {
        assert_eq!(timer_events(plain), timer_events(observed));
    }
    let near = "timer hop sigreturn getpid=1 bytes after 0f 05";
    let plain = timer_mode_runs("timer_hop_sigreturn", one_event(near, 0)).await;
    let observed = timer_mode_runs_with("timer_hop_sigreturn", observing, one_event(near, 2)).await;
    // The instruction, clock and result register at the event, without the
    // count of single steps.
    let fired_at = |run: &GuestRun| -> Vec<String> {
        timer_events(run)
            .into_iter()
            .map(|event| event.split(" steps=").next().unwrap().to_owned())
            .collect()
    };
    for (plain, observed) in plain.iter().zip(&observed) {
        assert_eq!(
            fired_at(plain),
            fired_at(observed),
            "within the keep margin"
        );
    }
    // With the timer's signal blocked by the mask the frame installs, a
    // notification requested at the return could not arrive, so the stop
    // cancels the event as before, and the guest still runs to its end. The
    // stop's choice is not visible here: the next Tool-visible stop would
    // cancel a request it made anyway. `timer_notified_after_return`'s and
    // the timer's unit tests check the choice.
    let blocked = "timer hop sigreturn blocked getpid=1 bytes after 0f 05";
    timer_mode_runs_with("timer_hop_sigreturn_blocked", observing, |runs| {
        reports_per_attempt(2);
        for run in runs {
            assert_eq!(
                timer_events(run),
                Vec::<&String>::new(),
                "the frame blocks the timer's signal"
            );
            assert_report_has(run, &[blocked]);
        }
    })
    .await;
}

/// A handler that holds its timer's notification back past the target, by
/// blocking the timer's signal, returns to a mask that unblocks it. Without
/// the opt-in the late notification delivers the event after the return,
/// at a clock host timing decides, with a skid-overshoot witness. With it,
/// the reported return finds the Scheduled event past its target, records
/// the overshoot, and requests the event one branch after the return
/// (`Timer::disregard_sigreturn_stop`), so it still fires once rather than
/// being lost. Each run is witnessed once.
#[tokio::test(flavor = "current_thread")]
async fn a_reported_handler_return_past_a_held_back_timer_still_delivers_it() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let _serial = SIGRETURN_TESTS.lock().await;
    let line = "timer late sigreturn getpid=1 bytes after 0f 05";
    for sigreturns in [false, true] {
        for tail in [false, true] {
            SIGRETURN_REPORTS.lock().unwrap().clear();
            let _ = reverie::take_skid_overshoot_count();
            let options = GuestOptions {
                sigreturns,
                tail,
                ..Default::default()
            };
            let run = run_guest_options("timer_late_sigreturn", options)
                .await
                .expect("timer_late_sigreturn run");
            let witnesses = reverie::take_skid_overshoot_count();
            let reports = std::mem::take(&mut *SIGRETURN_REPORTS.lock().unwrap());
            assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
            assert_report_has(&run, &[line]);
            assert_eq!(
                timer_events(&run).len(),
                1,
                "sigreturns={sigreturns} tail={tail}: {:#?}",
                run.all_events()
            );
            assert_eq!(witnesses, 1, "sigreturns={sigreturns} tail={tail}");
            assert_eq!(reports.len(), usize::from(sigreturns), "{reports:?}");
        }
    }
}

/// Every Tool-visible stop cancels an armed counting-phase timer, both a
/// stop at the shared site and one at another site; only the last timer,
/// with no stop before its branch loop, fires, in both Tool configurations.
#[tokio::test(flavor = "current_thread")]
async fn every_tool_visible_stop_cancels_a_counting_timer() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    timer_mode_runs("timer_cancel", |runs| {
        for run in runs {
            assert_eq!(timer_events(run).len(), 1, "{:#?}", run.all_events());
            assert_report_has(run, &["timer cancel site=1 ordinary=1"]);
        }
    })
    .await;
}

/// With getuid unsubscribed, the guest's getuid through the shared site
/// returns its real uid without reaching the Tool, and a later getpid there
/// works, in both Tool configurations.
#[tokio::test(flavor = "current_thread")]
async fn an_unsubscribed_getuid_runs_without_the_tool() {
    for tail in [false, true] {
        let options = GuestOptions {
            tail,
            partial: true,
            ..Default::default()
        };
        let ptrace = run_guest_options("partial", options).await.unwrap();
        assert_report_has(
            &ptrace,
            &[
                "getuid ok=1",
                "getpid after pid=1",
                "partial site bytes 0f 05",
            ],
        );
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert!(
            !ptrace
                .all_events()
                .iter()
                .any(|e| e.starts_with("entry getuid")),
            "getuid is unsubscribed"
        );
    }
}

/// rt_sigreturn through the shared site, from a restorer the guest installed
/// with the raw rt_sigaction: the handler's edit of the frame's mask wins
/// (SIGUSR1 unblocked, SIGUSR2 blocked), the frame's registers are restored,
/// and the site works afterwards.
#[tokio::test(flavor = "current_thread")]
async fn rt_sigreturn_restores_the_frame_and_its_edited_mask() {
    let [inject, _] = run_both_configurations("sigreturn").await;
    eprintln!("sigreturn report:\n{}", inject.report);
    assert_report_has(
        &inject,
        &[
            "sigreturn 0: sig=10 code=-6 value=-1 ",
            "after sigreturn usr1-blocked=0 usr2-blocked=1",
            "getpid after sigreturn pid=1 rcx=tp_site_end r11=0x246",
            "after sigreturn site bytes 0f 05",
            "sigreturn again 0: sig=10 code=-6 value=-1 ",
        ],
    );
}

/// x86_64 335 (uretprobe) and 336 (uprobe), which seccomp passes through
/// without running the filter, run natively: 335 raises SIGILL and 336
/// returns -ENXIO, or both return -ENOSYS on a kernel without them.
#[tokio::test(flavor = "current_thread")]
async fn seccomp_bypassing_probe_numbers_run_natively() {
    for (mode, nr, probe_line) in [
        ("probe_uretprobe", 335, "probe nr=335 SIGILL code=128"),
        ("probe_uprobe", 336, "probe nr=336 ret=-6"),
    ] {
        let ptrace = run_guest(mode, false).await;
        eprintln!("{mode} report:\n{}", ptrace.report);
        let enosys = format!("probe nr={nr} ret=-38");
        if ptrace.report.lines().any(|line| line == enosys) {
            eprintln!("{mode}: this kernel lacks syscall {nr}");
        } else {
            assert_report_has(&ptrace, &[probe_line]);
        }
    }
}

/// A SIGSTOP the tracer sends to the thread (SI_TKILL) while a getpid at the
/// shared site is parked: the tracer suppresses it at its delivery stop,
/// after getpid returned, at the site's end, with the tracer's siginfo; the
/// call returns the pid in both Tool shapes.
#[tokio::test(flavor = "current_thread")]
async fn a_sigstop_from_the_tracer_is_delivered_after_the_call() {
    let [inject, _] = run_both_configurations("sigstop_hop").await;
    assert_report_has(
        &inject,
        &[
            "sigstop tail getpid returned pid=1",
            "sigstop inject getpid returned pid=1",
        ],
    );
    let stop = delivery_after_the_call(&inject, "SIGSTOP", libc::SI_TKILL, "tracer", "task#0", 39);
    let stops: Vec<&String> = inject.signals["task#0"]
        .iter()
        .filter(|signal| signal.starts_with("SIGSTOP "))
        .collect();
    assert_eq!(stops, [&stop, &stop]);
}

/// A SIGSTOP at the write's stop, then a SIGCONT at the hook's early point,
/// immediately before the write runs: the SIGCONT discards the pending
/// SIGSTOP, so there is no SIGSTOP delivery stop, and the SIGCONT is
/// delivered after the write.
#[tokio::test(flavor = "current_thread")]
async fn a_sigcont_before_the_call_discards_the_sigstop_at_the_early_point() {
    let [inject, _] = run_both_configurations("sigstop_cont_window").await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &inject,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4"),
                &format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    let cont = delivery_after_the_call(&inject, "SIGCONT", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        assert_eq!(inject.signals[child], std::slice::from_ref(&cont));
    }
}

/// SIGTSTP with a handler installed, sent at the write's stop or immediately
/// before the write runs, is handled after the write returned, never a stop:
/// one signal-delivery stop per child, after the write.
#[tokio::test(flavor = "current_thread")]
async fn a_handled_sigtstp_is_delivered_after_the_write() {
    let [inject, _] = run_both_configurations("sigtstp_handler").await;
    for tag in ["tool", "hook"] {
        assert_report_has(
            &inject,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=20 code=0 from-parent=1 rip=tp_site_end rax=4"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
            ],
        );
    }
    let tstp = delivery_after_the_call(&inject, "SIGTSTP", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        assert_eq!(inject.signals[child], std::slice::from_ref(&tstp));
    }
}

/// SIGKILL at the write's stop, immediately before the write runs, there
/// after a SIGSTOP, and from the tracer after a SIGSTOP: the child dies of
/// SIGKILL without the write landing and without any later output, and the
/// parent's SIGCHLD says so.
#[tokio::test(flavor = "current_thread")]
async fn a_sigkill_around_the_call_kills_the_child_before_the_write() {
    let [inject, _] = run_both_configurations("sigkill_hop").await;
    for (tag, notified) in [("entry", 1), ("hop", 1), ("stop-hop", 2), ("stop-kill", 1)] {
        assert_report_has(
            &inject,
            &[
                &format!(
                    "{tag} parent notified={notified} data=0 after=0 restarted=-1 waitpid signaled:9"
                ),
                &format!("{tag} parent SIGCHLD code=2 status=9 from-child=1"),
            ],
        );
    }
    assert!(!inject.report.contains(" child "), "{}", inject.report);
}

/// The guest reads the site's own bytes directly and through
/// `/proc/self/mem`, before and after making its page writable: always the
/// original `0f 05`, and the site works afterwards.
#[tokio::test(flavor = "current_thread")]
async fn the_guest_reads_its_own_syscall_bytes() {
    let ptrace = run_guest("text_residual", false).await;
    eprintln!("text report:\n{}", ptrace.report);
    assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "before direct 0f 05",
            "before procmem 0f 05",
            "after direct 0f 05",
            "after procmem 0f 05",
            "getpid after mprotect pid=1",
            "done",
        ],
    );
}

/// The lines of a fixture mode's report that begin with `prefix`, in both
/// configurations, each run with `deadline`.
async fn report_lines_within(mode: &str, prefix: &str, deadline: Duration) -> [Vec<String>; 2] {
    report_lines_with(
        mode,
        prefix,
        GuestOptions {
            deadline: Some(deadline),
            ..Default::default()
        },
    )
    .await
}

/// `report_lines_within` with `options` for each run, but its `tail`.
async fn report_lines_with(mode: &str, prefix: &str, options: GuestOptions) -> [Vec<String>; 2] {
    run_both_configurations_with(mode, options)
        .await
        .map(|run| {
            run.report
                .lines()
                .filter(|line| line.starts_with(prefix))
                .map(str::to_owned)
                .collect()
        })
}

/// A guest that keeps Reverie's sealed SIGTRAP repair page out of a fork's
/// copy (`MADV_DONTFORK`, which the seal allows on a read-write page), then
/// forks: the child has no repair page, so Reverie never writes 0x71001000
/// there, whether the child maps its own page there (unchanged) or nothing,
/// and the trace goes on; the child's repair is dropped, so SIGTRAP reads
/// `SIG_DFL` there, a phase-0 limit (natively it stays ignored)
/// (<https://github.com/rrnewton/hermit/issues/4409>). From the Claude
/// reviewer's witness W1 at rev 8. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_fork_without_the_repair_page_never_has_it_written() {
    for (mode, own, page, changed) in [
        ("sigtrap_rv_dontfork_own", 1, 1, 0),
        ("sigtrap_rv_dontfork_none", 0, 0, -1),
    ] {
        for lines in report_lines_within(mode, "rv-dontfork ", Duration::from_secs(60)).await {
            assert_eq!(
                lines,
                [
                    format!(
                        "rv-dontfork own={own} madvise=0 child-scratch-mapped=0 own-page={page} changed={changed} sigtrap=dfl flags=0x50000000 usr2-in-mask=1 blocked=0"
                    ),
                    String::from("rv-dontfork child-status=0"),
                ],
                "{mode}"
            );
        }
    }
}

/// A guest whose own seccomp filter kills, traps or refuses `mseal`, set
/// before an exec: Reverie sets up no repair page in an image whose thread has
/// filters of the guest's own, so it injects no `mseal`, and the exec'd image
/// runs and exits 0, as natively (<https://github.com/rrnewton/hermit/issues/4409>).
/// From the Claude reviewer's witness W2 at rev 8. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_guest_seccomp_filter_against_mseal_never_meets_one() {
    for (mode, action) in [
        ("sigtrap_rv_seccomp_exec_kill", "0x80000000"),
        ("sigtrap_rv_seccomp_exec_trap", "0x30000"),
        ("sigtrap_rv_seccomp_exec_errno", "0x50001"),
    ] {
        for lines in report_lines_within(mode, "rv-", Duration::from_secs(60)).await {
            assert_eq!(
                lines,
                [
                    String::from("rv-exec-hello"),
                    format!("rv-seccomp-exec action={action} exited=1 code=0 signaled=0 sig=-1"),
                ],
                "{mode}"
            );
        }
    }
}

/// A process sharing the address space but not the signal actions
/// (`CLONE_VM`) tries again and again to replace Reverie's sealed repair page
/// with `MAP_FIXED`, `mremap(MREMAP_FIXED)` and `shmat(SHM_REMAP)` while the
/// parent's 4000 private injections repair an ignored SIGTRAP: every attempt
/// is refused, and every read sees SIGTRAP ignored
/// (<https://github.com/rrnewton/hermit/issues/4409>). From the Claude
/// reviewer's witness W4 at rev 8. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn no_mapping_call_can_replace_the_sealed_repair_page() {
    for lines in report_lines_within(
        "sigtrap_rv_clonevm_replace",
        "rv-clonevm ",
        Duration::from_secs(240),
    )
    .await
    {
        assert_eq!(
            lines,
            [
                "rv-clonevm iters-nonzero=1 refused-all=1 mapped=0 changed=0 action-bad=0 child-status=0"
            ]
        );
    }
}

/// A phase-0 limit, pinned: a sibling's own `rt_sigaction(SIGTRAP,
/// SIG_DFL)` that lands while another thread's repair is in flight is taken
/// for the reset and overwritten with `SIG_IGN`, and stays overwritten after
/// every injection has finished. Only for a Tool that breaks the
/// serialization contract, as this one does by running guest threads at once
/// (`GuestConfig::serialized`); Hermit runs one thread at a time. Natively `persistent=0`, so this test must change when
/// the window closes (<https://github.com/rrnewton/hermit/issues/4409>). From
/// the Claude reviewer's witness W3b at rev 8. Both configurations; a lost
/// write is certain in the tail configuration, where the sibling's own
/// syscalls are stepped injections, and is then always persistent.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_sig_dfl_during_a_repair_is_lost_a_pinned_limit() {
    let [inject, tail] = report_lines_within(
        "sigtrap_rv_sibling_dfl_persist",
        "rv-sibling-dfl-persist ",
        Duration::from_secs(240),
    )
    .await;
    assert!(
        inject == ["rv-sibling-dfl-persist found=1 persistent=1"]
            || inject == ["rv-sibling-dfl-persist found=0 persistent=0"],
        "{inject:?}"
    );
    assert_eq!(tail, ["rv-sibling-dfl-persist found=1 persistent=1"]);
}

/// A sibling thread installs, with `SECCOMP_FILTER_FLAG_TSYNC`, a filter that
/// kills, traps or refuses `rt_sigaction` while the other thread's private
/// injections run with SIGTRAP ignored; neither thread calls `rt_sigaction`
/// after the install. Natively every child exits 0 for all three actions.
///
/// - **No serialization contract** (a plain Reverie Tool): Reverie makes no
///   SIGTRAP repair, so no injected `rt_sigaction` can meet the filter, and
///   every child exits 0, as natively. This is the oracle.
/// - **A declared contract that the test Tool breaks** (guest threads run at
///   once, and the guest installs a filter): the repair checks the thread's
///   filters before its injections, and the install can land between that
///   check and the repair's `rt_sigaction`, which a killing or trapping
///   filter then ends by SIGSYS. Pinned, to show what the contract excludes:
///   a kill is likely in the tail configuration, where every injection is
///   stepped and repaired, and is asserted there; a refusing filter only
///   drops the repair.
///
/// (<https://github.com/rrnewton/hermit/issues/4409>). From the Claude
/// reviewer's witness T1 at rev 10 and Codex's exit-0 requirement. Both
/// configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_sibling_tsync_filter_kills_no_guest_unless_the_contract_is_broken() {
    for no_serialization_contract in [true, false] {
        for (mode, action) in [
            ("sigtrap_tsync_filter_kill", "0x80000000"),
            ("sigtrap_tsync_filter_trap", "0x30000"),
            ("sigtrap_tsync_filter_errno", "0x50001"),
        ] {
            let options = GuestOptions {
                deadline: Some(Duration::from_secs(240)),
                no_serialization_contract,
                ..Default::default()
            };
            let [inject, tail] = report_lines_with(mode, "tsync-filter ", options).await;
            for (configuration, lines) in [("inject", &inject), ("tail", &tail)] {
                let what = format!(
                    "{mode} {configuration} contract={}",
                    !no_serialization_contract
                );
                let [line] = lines.as_slice() else {
                    panic!("{what}: {lines:?}");
                };
                eprintln!("{what}: {line}");
                let count = |key: &str| -> u32 {
                    line.split(' ')
                        .find_map(|field| field.strip_prefix(key))
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| panic!("{what}: no {key} in {line:?}"))
                };
                assert!(
                    line.starts_with(&format!("tsync-filter action={action} children=40 ")),
                    "{what}: {line}"
                );
                let (ok, sigsys) = (count("ok="), count("sigsys="));
                assert_eq!(count("other="), 0, "{what}: {line}");
                assert_eq!(ok + sigsys, 40, "{what}: {line}");
                if no_serialization_contract || mode == "sigtrap_tsync_filter_errno" {
                    assert_eq!(sigsys, 0, "{what}: {line}");
                } else if configuration == "tail" {
                    assert!(sigsys > 0, "{what}: {line}");
                }
            }
        }
    }
}

/// Reverie keeps an ignored SIGTRAP across a private injection's step only
/// for a Tool that declares a serialized-execution contract
/// (`Tool::enforces_serialized_execution`), as Hermit's does. For a plain
/// Reverie Tool the step's trap resets it, as at base
/// (<https://github.com/rrnewton/hermit/issues/4409>). Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn the_sigtrap_repair_runs_only_under_a_declared_serialization_contract() {
    for (no_serialization_contract, expected) in [
        (false, "preexec-filter sigign=1"),
        (true, "preexec-filter sigign=0"),
    ] {
        let options = GuestOptions {
            no_serialization_contract,
            ..Default::default()
        };
        for lines in
            report_lines_with("sigtrap_caller_preexec_filter", "preexec-filter ", options).await
        {
            assert_eq!(lines, [expected], "contract={}", !no_serialization_contract);
        }
    }
}

/// A seccomp filter that kills, traps or refuses `mseal`, which the caller
/// installs in a `pre_exec` callback: that callback runs before Reverie's own
/// stops the root, and so before Reverie's launch filter is loaded: at the
/// root's first stop the guest has the tracer's filters and the caller's, as
/// many as a guest without filters of its own has at an exec stop. Reverie
/// injects no `mseal` there or after the exec, and the guest exits 0, as
/// natively. Its repair is dropped under the
/// filter, so SIGTRAP keeps the step's reset (`sigign=0`), a phase-0 limit
/// (natively it stays ignored) (<https://github.com/rrnewton/hermit/issues/4409>).
/// From Codex's P2-1 at rev 9. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_caller_seccomp_filter_against_mseal_never_meets_one() {
    for action in [
        libc::SECCOMP_RET_KILL_PROCESS,
        libc::SECCOMP_RET_TRAP,
        libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ] {
        for tail in [false, true] {
            let options = GuestOptions {
                tail,
                caller_mseal_filter: Some(action),
                ..Default::default()
            };
            let run = run_guest_options("sigtrap_caller_preexec_filter", options)
                .await
                .unwrap_or_else(|error| {
                    panic!("caller filter {action:#x} tail={tail}: run failed: {error}")
                });
            assert_eq!(
                run.status,
                ExitStatus::Exited(0),
                "caller filter {action:#x} tail={tail}: {}",
                run.report
            );
            assert_eq!(
                run.report
                    .lines()
                    .filter(|line| line.starts_with("preexec-filter "))
                    .collect::<Vec<_>>(),
                ["preexec-filter sigign=0"],
                "caller filter {action:#x} tail={tail}: {}",
                run.report
            );
            assert!(run.report.ends_with("done\n"), "{}", run.report);
        }
    }
}

/// A guest whose own seccomp filter, installed after its last exec, kills,
/// traps or refuses `rt_sigaction`: a SIGTRAP repair's own `rt_sigaction`
/// never meets it, since Reverie writes no repair from a thread with filters
/// of the guest's own, and a repair call that fails drops the repair rather
/// than fail the trace. The child exits 0, as natively; its repair is dropped,
/// so SIGTRAP keeps the step's reset there (`sigign=0`), a phase-0 limit, as
/// at base (<https://github.com/rrnewton/hermit/issues/4409>). From the Claude
/// reviewer's witness N1 at rev 9. Both configurations.
#[tokio::test(flavor = "current_thread")]
async fn a_guest_seccomp_filter_against_rt_sigaction_never_meets_a_repair() {
    for (mode, action) in [
        ("sigtrap_rw9_filter_kill", "0x80000000"),
        ("sigtrap_rw9_filter_trap", "0x30000"),
        ("sigtrap_rw9_filter_errno", "0x50001"),
    ] {
        for lines in report_lines_within(mode, "rw9-", Duration::from_secs(60)).await {
            assert_eq!(
                lines,
                [
                    format!("rw9-filter-child action={action} sigign=0"),
                    format!("rw9-filter action={action} exited=1 code=0 signaled=0 sig=-1"),
                ],
                "{mode}"
            );
        }
    }
}
