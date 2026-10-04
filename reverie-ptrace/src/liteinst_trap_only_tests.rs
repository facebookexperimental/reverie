/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Trap-only LiteInst with patching off must be observably plain ptrace.
//!
//! The stop sequence compared here is the tracer's run-loop waits (the stops
//! that `record_wait` sees). Stops consumed inside `inject`, `tail_inject` or
//! single-step paths are not recorded.

use std::collections::BTreeMap;
use std::sync::Mutex;

use reverie::Guest;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;

use super::*;
use crate::Ia32EmulationProbe;
use crate::Ia32EmulationUnavailable;
use crate::PtraceBackendStatsSnapshot;

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

/// Names a prebuilt parity guest for a re-executed namespace arm.
const PARITY_GUEST_ENV: &str = "REVERIE_TRAP_ONLY_PARITY_GUEST";

fn parity_guest() -> &'static std::path::Path {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        if let Some(prebuilt) = std::env::var_os(PARITY_GUEST_ENV) {
            return PathBuf::from(prebuilt);
        }
        // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
        // BUCK rule set. The compile-time value is a directory on the build
        // host and is missing on the test host when the binary was built
        // remotely.
        let source = std::env::var_os("CARGO_MANIFEST_DIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
            .join("tests/fixtures/trap_only_parity.c");
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
        let output = directory.join("reverie-trap-only-parity");
        let staging = directory.join(format!(
            "reverie-trap-only-parity.{}.tmp",
            std::process::id()
        ));
        let status = std::process::Command::new("cc")
            .args(["-O0", "-g"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .expect("invoke cc for the trap-only parity fixture");
        assert!(status.success(), "compile {}", source.display());
        std::fs::rename(&staging, &output).expect("publish the trap-only parity fixture");
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

async fn run_parity_guest(trap_only: bool, record_values: bool, identity: Identity) -> Observed {
    let mut builder = TracerBuilder::<RecordTool>::new(Command::new(parity_guest()))
        .config(record_values)
        .backend_stats(BackendStatsRequest::ENABLED);
    if trap_only {
        builder = builder.liteinst_trap_only(SitePatching::Off);
    }
    let tracer = builder.spawn().await.expect("spawn parity guest");
    let stats = tracer.backend_stats().expect("stats were requested");
    let handle = tracer.liteinst_trap_only();
    assert_eq!(handle.is_some(), trap_only);
    assert!(
        tracer.liteinst_instrumentation_stats().is_none(),
        "neither mode requested LiteInst patch statistics"
    );
    let (status, log) = tokio::time::timeout(Duration::from_secs(20), tracer.wait())
        .await
        .expect("parity guest timed out")
        .expect("parity guest run failed");
    if let Some(handle) = handle {
        assert_eq!(handle.patching(), SitePatching::Off);
        assert_eq!(handle.patched_sites(), 0, "patching off wrote a site");
        assert_eq!(
            handle.table_state(),
            crate::liteinst_trap_only::TableState::Patchable,
            "patching off changed its table state"
        );
    }
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

/// Checks that a plain-ptrace baseline covers the classes the preload hybrid
/// refuses, so that a comparison against it is not vacuous.
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

fn assert_same_run(trap_only: &Observed, ptrace: &Observed) {
    assert_eq!(trap_only.status, ptrace.status);
    assert_eq!(trap_only.root, ptrace.root, "root guest identity diverged");
    assert_eq!(trap_only.stops, ptrace.stops, "stop sequences diverged");
    assert_eq!(
        trap_only.tool_events, ptrace.tool_events,
        "Tool-visible events diverged"
    );
    assert_eq!(trap_only.counts, ptrace.counts, "stop counts diverged");
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_with_patching_off_matches_plain_ptrace_stop_for_stop() {
    let ptrace = run_parity_guest(false, false, Identity::Renamed).await;
    let trap_only = run_parity_guest(true, false, Identity::Renamed).await;
    assert_baseline_is_not_vacuous(&ptrace, false, "task#0", "task#1", "task#2");
    assert_same_run(&trap_only, &ptrace);
}

/// The same comparison with every syscall's return value recorded. PID values
/// are renamed consistently with task identity, because host PIDs differ
/// between runs; no other value is normalised (the tracer disables address
/// randomisation, so mapping addresses repeat).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_with_patching_off_matches_plain_ptrace_return_values() {
    let ptrace = run_parity_guest(false, true, Identity::Renamed).await;
    let trap_only = run_parity_guest(true, true, Identity::Renamed).await;
    assert_baseline_is_not_vacuous(&ptrace, true, "task#0", "task#1", "task#2");
    assert_same_run(&trap_only, &ptrace);
}

/// Selects the arm a re-executed namespace child runs.
const NAMESPACE_ARM_ENV: &str = "REVERIE_TRAP_ONLY_NAMESPACE_ARM";
const NAMESPACE_MARK: &str = "@@trap-only-namespace-arm@@ ";

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
        .env(PARITY_GUEST_ENV, parity_guest())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn /usr/bin/unshare");
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{arm} arm in a fresh PID namespace exceeded 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{arm} arm in a fresh PID namespace failed ({}):\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let record = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(NAMESPACE_MARK))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!record.is_empty(), "{arm} arm printed no record:\n{stdout}");
    record
}

/// Trap-only admission (including the IA-32 probe, which runs cold here) must
/// not consume a PID or otherwise perturb the guest. Each arm runs in its own
/// fresh PID namespace, so PID values are compared exactly: root, children,
/// getpid/fork/vfork/wait4 results, and every other syscall return value.
#[test]
fn trap_only_matches_plain_ptrace_pid_for_pid_in_a_fresh_pid_namespace() {
    if let Ok(arm) = std::env::var(NAMESPACE_ARM_ENV) {
        let trap_only = match arm.as_str() {
            "ptrace" => false,
            "trap-only" => true,
            other => panic!("unknown arm {other}"),
        };
        let observed = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_parity_guest(trap_only, true, Identity::Exact));
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
    let test_name =
        format!("{module}::trap_only_matches_plain_ptrace_pid_for_pid_in_a_fresh_pid_namespace");
    // Two plain-ptrace arms show that the exact comparison is repeatable
    // before it is used to judge the trap-only arm.
    let ptrace = run_arm_in_fresh_pid_namespace(&test_name, "ptrace");
    let ptrace_again = run_arm_in_fresh_pid_namespace(&test_name, "ptrace");
    let trap_only = run_arm_in_fresh_pid_namespace(&test_name, "trap-only");
    assert!(
        ptrace.contains("root: \"pid ") && ptrace.contains("\"syscall clone = pid "),
        "record lacks PID-bearing values: {ptrace}"
    );
    assert_eq!(
        ptrace_again, ptrace,
        "plain ptrace is not repeatable in a fresh namespace"
    );
    assert_eq!(
        trap_only, ptrace,
        "trap-only diverged from plain ptrace in a fresh PID namespace"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_refuses_launch_without_ia32_emulation() {
    let marker = tempfile_path("trap-only-refused");
    let mut command = Command::new(parity_guest());
    command.arg("touch").arg(&marker);
    let result = TracerBuilder::<RecordTool>::new(command)
        .liteinst_trap_only(SitePatching::Off)
        .liteinst_trap_only_ia32_probe_for_test(Ia32EmulationProbe::Unavailable(
            "forced unavailable by the test".into(),
        ))
        .spawn()
        .await;
    let error = match result {
        Ok(_) => panic!("trap-only launched without IA-32 syscall emulation"),
        Err(error) => error,
    };
    let Error::Tool(tool_error) = &error else {
        panic!("refusal must be a named Tool error, got {error:?}");
    };
    let refusal = tool_error
        .downcast_ref::<Ia32EmulationUnavailable>()
        .unwrap_or_else(|| panic!("refusal is not Ia32EmulationUnavailable: {error}"));
    assert_eq!(refusal.observation, "forced unavailable by the test");
    assert!(
        error
            .to_string()
            .contains("LiteInst trap-only launch refused"),
        "{error}"
    );
    assert!(
        !marker.exists(),
        "the guest ran even though the launch was refused"
    );

    // The same launch with an available probe runs the guest: the refusal
    // above is caused by the probe result, not by the command.
    let mut command = Command::new(parity_guest());
    command.arg("touch").arg(&marker);
    let (status, _) = TracerBuilder::<RecordTool>::new(command)
        .liteinst_trap_only(SitePatching::Off)
        .liteinst_trap_only_ia32_probe_for_test(Ia32EmulationProbe::Available)
        .spawn()
        .await
        .expect("available probe admits the launch")
        .wait()
        .await
        .expect("witness guest run");
    assert_eq!(status, ExitStatus::Exited(0));
    assert!(marker.exists(), "the admitted guest did not run");
    std::fs::remove_file(&marker).unwrap();
}

/// An IA-32 entry that changes rcx or r8-r11 cannot run a patched site, but
/// patching off never runs one: the launch is admitted and the guest runs.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_with_patching_off_runs_on_a_register_clobbering_entry() {
    let marker = tempfile_path("trap-only-clobbering-off");
    let mut command = Command::new(parity_guest());
    command.arg("touch").arg(&marker);
    let (status, _) = TracerBuilder::<RecordTool>::new(command)
        .liteinst_trap_only(SitePatching::Off)
        .liteinst_trap_only_ia32_probe_for_test(Ia32EmulationProbe::ClobbersRegisters(
            "int 0x80 getpid changed r8 from 0x5e171ce000000008 to 0x0".into(),
        ))
        .spawn()
        .await
        .expect("patching off is admitted on a register-clobbering entry")
        .wait()
        .await
        .expect("guest run");
    assert_eq!(status, ExitStatus::Exited(0));
    assert!(marker.exists(), "the admitted guest did not run");
    std::fs::remove_file(&marker).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_and_the_preload_runtime_are_mutually_exclusive() {
    let marker = tempfile_path("trap-only-exclusive");
    let mut command = Command::new(parity_guest());
    command.arg("touch").arg(&marker);
    let result = TracerBuilder::<RecordTool>::new(command)
        .liteinst_runtime("/nonexistent/preload.so", 1, 2, 3, 4, 5)
        .liteinst_trap_only(SitePatching::Off)
        .spawn()
        .await;
    let error = match result {
        Ok(_) => panic!("both LiteInst modes were accepted together"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("mutually exclusive"), "{error}");
    assert!(!marker.exists(), "the guest ran despite the refusal");
}

/// Site patching rewrites `syscall` into `int 0x80`, so a launch with it on
/// is refused when the IA-32 entry changes registers the x86_64 view needs,
/// before the guest is spawned.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_refuses_site_patching_on_a_register_clobbering_entry() {
    let marker = tempfile_path("trap-only-patching-clobber");
    let mut command = Command::new(parity_guest());
    command.arg("touch").arg(&marker);
    let result = TracerBuilder::<RecordTool>::new(command)
        .liteinst_trap_only(SitePatching::On)
        .liteinst_trap_only_ia32_probe_for_test(Ia32EmulationProbe::ClobbersRegisters(
            "int 0x80 changed r8 (test)".into(),
        ))
        .spawn()
        .await;
    let error = match result {
        Ok(_) => panic!("site patching launched on a register-clobbering entry"),
        Err(error) => error,
    };
    let Error::Tool(tool_error) = &error else {
        panic!("refusal must be a named Tool error, got {error:?}");
    };
    let refusal = tool_error
        .downcast_ref::<crate::liteinst_trap_only::Ia32EntryClobbersRegisters>()
        .unwrap_or_else(|| panic!("refusal is not Ia32EntryClobbersRegisters: {error}"));
    assert_eq!(refusal.patching, SitePatching::On);
    assert_eq!(
        error.to_string(),
        "LiteInst trap-only launch with site patching on refused: int 0x80 changed r8 (test)"
    );
    assert!(
        !marker.exists(),
        "the guest ran even though the launch was refused"
    );
}

#[test]
fn host_services_int_0x80() {
    // Trap-only parity depends on the real probe. A host without the IA-32
    // entry must fail this test loudly rather than skip the parity test.
    assert_eq!(crate::probe_ia32_emulation(), Ia32EmulationProbe::Available);
}

fn tempfile_path(label: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Fixed width: a guest that opens this path executes a number of
    // branches that depends on its length, and precise-timer clocks are
    // compared across runs.
    let path = std::env::temp_dir().join(format!(
        "reverie-{label}-{}-{serial:08}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[path = "liteinst_trap_only_p2_tests.rs"]
mod p2;
