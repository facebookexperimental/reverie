/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runtime-free (trap-only) LiteInst with patching off is plain ptrace.
//!
//! The fixtures are ones the preload hybrid refuses or fails closed on: a
//! static image and a vfork in a forked child. Trap-only loads nothing into the
//! guest, so both must run exactly as they do under plain ptrace.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::Mutex;
use std::time::Duration;

use reverie::BackendStatsSource;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_liteinst::LiteinstBackend;
use reverie_ptrace::TracerBuilder;

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

/// Records the Tool-visible syscall sequence of every task, and with `true`
/// each syscall's return value.
#[derive(Default)]
struct RecordTool;

#[reverie::tool]
impl Tool for RecordTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &bool) -> Subscription {
        Subscription::all_syscalls()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        if matches!(call.number(), Sysno::exit | Sysno::exit_group) {
            // Witness that nothing was loaded: the environment carries no
            // preload and no LiteInst object is mapped at exit. A failed read
            // is recorded as such, so it can never pass as "nothing loaded".
            let pid = guest.pid();
            let preload = match std::fs::read(format!("/proc/{pid}/environ")) {
                Ok(environ) => environ
                    .split(|byte| *byte == 0)
                    .any(|entry| entry.starts_with(b"LD_PRELOAD="))
                    .to_string(),
                Err(error) => format!("<environ unreadable: {error}>"),
            };
            let liteinst = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                Ok(maps) => maps.contains("reverie_liteinst").to_string(),
                Err(error) => format!("<maps unreadable: {error}>"),
            };
            guest
                .send_rpc(format!("preload={preload} liteinst-mapped={liteinst}"))
                .await;
        }
        // exit and a successful execve never return a value to the caller.
        let no_return = matches!(
            call.number(),
            Sysno::exit | Sysno::exit_group | Sysno::execve | Sysno::execveat
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
}

fn compile(name: &str, flags: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(flags)
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

/// Groups events per task; the interleaving of tasks is not deterministic.
fn per_task(trace: Vec<(Pid, String)>) -> Vec<Vec<String>> {
    let mut tasks = BTreeMap::<Pid, Vec<String>>::new();
    for (pid, event) in trace {
        tasks.entry(pid).or_default().push(event);
    }
    let mut sequences = tasks.into_values().collect::<Vec<_>>();
    sequences.sort();
    sequences
}

async fn under_ptrace(command: Command) -> (ExitStatus, Vec<Vec<String>>) {
    let (status, trace) = run_ptrace(command, false).await;
    (status, per_task(trace))
}

async fn under_trap_only(command: Command) -> (ExitStatus, Vec<Vec<String>>) {
    let (status, trace) = run_trap_only(command, false).await;
    (status, per_task(trace))
}

async fn run_ptrace(command: Command, record_values: bool) -> (ExitStatus, Vec<(Pid, String)>) {
    let (status, log) = tokio::time::timeout(Duration::from_secs(20), async {
        TracerBuilder::<RecordTool>::new(command)
            .config(record_values)
            .spawn()
            .await?
            .wait()
            .await
    })
    .await
    .expect("plain ptrace run timed out")
    .expect("plain ptrace run failed");
    (status, log.0.into_inner().unwrap())
}

async fn run_trap_only(command: Command, record_values: bool) -> (ExitStatus, Vec<(Pid, String)>) {
    let (status, log) = tokio::time::timeout(
        Duration::from_secs(20),
        LiteinstBackend::run_host_trap_only::<RecordTool>(command, record_values),
    )
    .await
    .expect("trap-only run timed out")
    .expect("trap-only run failed");
    (status, log.0.into_inner().unwrap())
}

fn assert_nothing_loaded(events: &[Vec<String>]) {
    let witnesses = events
        .concat()
        .into_iter()
        .filter(|event| event.starts_with("preload="))
        .collect::<Vec<_>>();
    assert!(!witnesses.is_empty(), "no exit witness was recorded");
    for witness in witnesses {
        assert_eq!(witness, "preload=false liteinst-mapped=false");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_runs_a_static_image_like_plain_ptrace() {
    let (_directory, binary) = compile(
        "hybrid_static_exit.c",
        &[
            "-std=gnu11",
            "-O0",
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-Wl,--build-id=none",
        ],
    );
    let scratch = tempfile::tempdir().unwrap();
    let command = |name: &str| {
        let mut command = Command::new(&binary);
        command.arg(scratch.path().join(name));
        command
    };

    let ptrace = under_ptrace(command("ptrace.pid")).await;
    let trap_only = under_trap_only(command("trap-only.pid")).await;

    assert_eq!(ptrace.0, ExitStatus::Exited(0));
    assert_eq!(
        ptrace.1,
        vec![vec![
            "syscall execve".to_owned(),
            "syscall openat".to_owned(),
            "syscall getpid".to_owned(),
            "syscall write".to_owned(),
            "syscall close".to_owned(),
            "preload=false liteinst-mapped=false".to_owned(),
            "syscall exit".to_owned(),
        ]],
        "unexpected plain-ptrace baseline"
    );
    assert_eq!(trap_only, ptrace, "trap-only diverged from plain ptrace");
    assert!(scratch.path().join("trap-only.pid").is_file());
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_runs_vfork_in_a_forked_child_like_plain_ptrace() {
    let (_directory, binary) = compile(
        "hybrid_fork_vfork.c",
        &["-std=gnu11", "-O0", "-fno-pie", "-no-pie"],
    );
    let scratch = tempfile::tempdir().unwrap();
    let command = |name: &str| {
        let mut command = Command::new(&binary);
        command
            .arg(format!("li-to-{name}"))
            .arg(scratch.path().join(name));
        command.stdout(reverie::process::Stdio::null());
        command
    };

    let ptrace = under_ptrace(command("ptrace")).await;
    let trap_only = under_trap_only(command("trap")).await;

    assert_eq!(ptrace.0, ExitStatus::Exited(0));
    assert_eq!(ptrace.1.len(), 3, "root, fork child, and vfork grandchild");
    assert!(
        ptrace
            .1
            .iter()
            .any(|task| task.iter().any(|event| event == "syscall vfork")),
        "baseline lacks the vfork: {:?}",
        ptrace.1
    );
    assert_nothing_loaded(&ptrace.1);
    assert_nothing_loaded(&trap_only.1);
    // The fixture names its process after argv[1], which differs per run;
    // prctl is still the same syscall in the same position.
    assert_eq!(trap_only, ptrace, "trap-only diverged from plain ptrace");
}

#[tokio::test(flavor = "current_thread")]
async fn trap_only_stats_report_no_patched_sites() {
    let (_directory, binary) = compile(
        "hybrid_static_exit.c",
        &[
            "-std=gnu11",
            "-O0",
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-Wl,--build-id=none",
        ],
    );
    let scratch = tempfile::tempdir().unwrap();
    let mut command = Command::new(&binary);
    command.arg(scratch.path().join("stats.pid"));
    let (status, _log, stats) = tokio::time::timeout(
        Duration::from_secs(20),
        LiteinstBackend::run_host_trap_only_and_stats::<RecordTool>(command, false),
    )
    .await
    .expect("trap-only stats run timed out")
    .expect("trap-only stats run failed");
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(stats.distinct_rips(), 0, "patching off patched a site");
    let snapshot = stats.backend_stats();
    assert_eq!(
        snapshot.dispatch_paths().total(),
        0,
        "a LiteInst dispatch path was counted with patching off: {:?}",
        snapshot.dispatch_paths().counts()
    );
    assert_eq!(
        snapshot.patch_decisions().total(),
        0,
        "a patch decision was counted with patching off: {:?}",
        snapshot.patch_decisions().counts()
    );
}

/// Selects the arm a re-executed namespace child runs.
const NAMESPACE_ARM_ENV: &str = "REVERIE_LITEINST_TRAP_ONLY_NAMESPACE_ARM";
const STATIC_FIXTURE_ENV: &str = "REVERIE_LITEINST_TRAP_ONLY_STATIC_FIXTURE";
const VFORK_FIXTURE_ENV: &str = "REVERIE_LITEINST_TRAP_ONLY_VFORK_FIXTURE";
const SCRATCH_ENV: &str = "REVERIE_LITEINST_TRAP_ONLY_SCRATCH";
const NAMESPACE_MARK: &str = "@@liteinst-trap-only-namespace-arm@@ ";
const NAMESPACE_TEST: &str = "trap_only_matches_plain_ptrace_pid_for_pid_in_a_fresh_pid_namespace";

/// Groups a trace per task, keeping each task's exact PID.
fn by_pid(trace: Vec<(Pid, String)>) -> BTreeMap<Pid, Vec<String>> {
    let mut tasks = BTreeMap::<Pid, Vec<String>>::new();
    for (pid, event) in trace {
        tasks.entry(pid).or_default().push(event);
    }
    tasks
}

/// Runs both fixtures under one arm, in this process's (fresh) namespace.
async fn namespace_arm(trap_only: bool) -> String {
    let path = |name: &str| PathBuf::from(std::env::var_os(name).unwrap());
    let scratch = path(SCRATCH_ENV);
    let mut static_command = Command::new(path(STATIC_FIXTURE_ENV));
    static_command.arg(scratch.join("static.pid"));
    let mut vfork_command = Command::new(path(VFORK_FIXTURE_ENV));
    vfork_command.arg("li-to-ns").arg(scratch.join("vfork.pid"));
    vfork_command.stdout(reverie::process::Stdio::null());
    let mut record = Vec::new();
    for command in [static_command, vfork_command] {
        let (status, trace) = if trap_only {
            run_trap_only(command, true).await
        } else {
            run_ptrace(command, true).await
        };
        record.push(format!("{status:?} {:?}", by_pid(trace)));
    }
    record.join("\n")
}

/// Runs one arm in a fresh user, PID and mount namespace with its own /proc,
/// the way Hermit runs the tracer, and returns the child's printed record.
fn run_arm_in_fresh_pid_namespace(
    arm: &str,
    static_fixture: &std::path::Path,
    vfork_fixture: &std::path::Path,
    scratch: &std::path::Path,
) -> String {
    for name in ["static.pid", "vfork.pid"] {
        let _ = std::fs::remove_file(scratch.join(name));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut child = ProcessCommand::new("/usr/bin/unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
            "--",
        ])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", NAMESPACE_TEST, "--nocapture", "--test-threads=1"])
        .env(NAMESPACE_ARM_ENV, arm)
        .env(STATIC_FIXTURE_ENV, static_fixture)
        .env(VFORK_FIXTURE_ENV, vfork_fixture)
        .env(SCRATCH_ENV, scratch)
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

/// Each arm runs in its own fresh PID namespace, so PIDs and every syscall
/// return value (getpid, clone, vfork, and the length of the PID the fixture
/// writes) are compared exactly, task by task.
#[test]
fn trap_only_matches_plain_ptrace_pid_for_pid_in_a_fresh_pid_namespace() {
    if let Ok(arm) = std::env::var(NAMESPACE_ARM_ENV) {
        let trap_only = match arm.as_str() {
            "ptrace" => false,
            "trap-only" => true,
            other => panic!("unknown arm {other}"),
        };
        let record = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(namespace_arm(trap_only));
        // libtest has already printed "test <name> ... " without a newline.
        println!();
        for line in record.lines() {
            println!("{NAMESPACE_MARK}{line}");
        }
        return;
    }
    let (_static_directory, static_fixture) = compile(
        "hybrid_static_exit.c",
        &[
            "-std=gnu11",
            "-O0",
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-Wl,--build-id=none",
        ],
    );
    let (_vfork_directory, vfork_fixture) = compile(
        "hybrid_fork_vfork.c",
        &["-std=gnu11", "-O0", "-fno-pie", "-no-pie"],
    );
    let scratch = tempfile::tempdir().unwrap();
    let run =
        |arm| run_arm_in_fresh_pid_namespace(arm, &static_fixture, &vfork_fixture, scratch.path());
    // Two plain-ptrace arms show that the exact comparison is repeatable
    // before it is used to judge the trap-only arm.
    let ptrace = run("ptrace");
    let ptrace_again = run("ptrace");
    let trap_only = run("trap-only");
    let lines = ptrace.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "one record per fixture: {ptrace}");
    for (line, required) in lines.iter().zip([
        &["Exited(0)", "\"syscall getpid = ", "\"syscall write = "][..],
        &["Exited(0)", "\"syscall clone = ", "\"syscall vfork = "][..],
    ]) {
        for needle in required {
            assert!(line.contains(needle), "baseline lacks {needle}: {line}");
        }
        assert!(
            line.contains("preload=false liteinst-mapped=false"),
            "baseline lacks the nothing-loaded witness: {line}"
        );
    }
    assert_eq!(
        ptrace_again, ptrace,
        "plain ptrace is not repeatable in a fresh namespace"
    );
    assert_eq!(
        trap_only, ptrace,
        "trap-only diverged from plain ptrace in a fresh PID namespace"
    );
}
