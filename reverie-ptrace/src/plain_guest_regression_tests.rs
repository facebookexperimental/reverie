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
}

async fn run_guest_options(mode: &str, options: GuestOptions) -> Result<GuestRun, Error> {
    let report_path = tempfile_path(&format!("plain-guest-{mode}"));
    let mut command = Command::new(regression_guest());
    command.arg(mode).arg(&report_path);
    if let Some(order) = options.order {
        command.env("TP_ORDER", order);
    }
    let resumes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let tracer = TracerBuilder::<GuestTool>::new(command)
        .config(GuestConfig {
            tail: options.tail,
            partial: options.partial,
            sigreturns: options.sigreturns,
        })
        .backend_stats(BackendStatsRequest::ENABLED)
        .final_resume_signal_for_test(resume_recorder(resumes.clone()))
        .pre_syscall_for_test(park_hook())
        .spawn()
        .await?;
    let stats = tracer.backend_stats().expect("stats were requested");
    let result = tokio::time::timeout(Duration::from_secs(60), finish_run(tracer, &stats))
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

/// Each Tool handler shape single-steps a fixed number of times, so the
/// guest sees a fixed SIGTRAP disposition, mask and trap number after each:
/// a shape that single-steps resets SIGTRAP to its default and unblocks it,
/// and the last trap the SIGUSR1 frame records is the step's debug trap (1)
/// instead of the syscall's (13). In the fixture's order of the shapes
/// (exact inject, tail, emulate, private inject, two injects, two private
/// injects) the steps are 0, 0, 1, 2, 1 and 3.
#[tokio::test(flavor = "current_thread")]
async fn sigtrap_profile_follows_each_handler_shape() {
    let [inject, _] = run_both_configurations("sigtrap_profile").await;
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
        let (disposition, blocked, trapno) = if stepped {
            ("dfl", 0, 1)
        } else {
            ("ign", 1, 13)
        };
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
    let expected = [0, 0, 1, 2, 1, 3];
    let steps = steps_per_shape(&inject);
    eprintln!("steps per shape: {steps:?}");
    assert_eq!(steps, expected, "step profile");
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
