/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Plain ptrace runs a static image without libc, and a vfork in a forked
//! child after the session root has exited, with an exact record of every
//! task's Tool-visible syscalls, and repeats both PID for PID in a fresh PID
//! namespace. Each run also witnesses that nothing was preloaded into the
//! guest.
//!
//! These are the plain ptrace arms of the deleted trap-only LiteInst parity
//! tests, which compared each run with a run of that backend; the plain
//! assertions are kept as they were.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

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

/// The compiler flags of the static fixture.
const STATIC_FLAGS: [&str; 8] = [
    "-std=gnu11",
    "-O0",
    "-nostdlib",
    "-static",
    "-fno-stack-protector",
    "-fno-pie",
    "-no-pie",
    "-Wl,--build-id=none",
];

/// The compiler flags of the fork-then-vfork fixture.
const VFORK_FLAGS: [&str; 4] = ["-std=gnu11", "-O0", "-fno-pie", "-no-pie"];

/// The directory beside the test binary, where fixtures and scratch files of
/// this binary live.
fn binary_directory() -> PathBuf {
    std::env::current_exe()
        .expect("locate the test binary")
        .parent()
        .expect("the test binary has a directory")
        .to_path_buf()
}

/// The static fixture, compiled once per process (see `compile`).
fn static_fixture() -> &'static Path {
    static FIXTURE: LazyLock<PathBuf> =
        LazyLock::new(|| compile("plain_static_exit.c", &STATIC_FLAGS));
    &FIXTURE
}

/// The fork-then-vfork fixture, compiled once per process (see `compile`).
fn vfork_fixture() -> &'static Path {
    static FIXTURE: LazyLock<PathBuf> =
        LazyLock::new(|| compile("plain_fork_then_vfork.c", &VFORK_FLAGS));
    &FIXTURE
}

/// Compiles `tests/fixtures/<name>` with `flags` beside the test binary, as
/// `reverie-<stem>`, and returns its path. Each process compiles its own copy
/// once (the callers' `LazyLock`s), under a staging name of its own, and
/// renames it into place, so neither concurrent tests of this process nor
/// another process can write or rename a copy being compiled.
fn compile(name: &str, flags: &[&str]) -> PathBuf {
    // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the fbsource
    // BUCK rule set. The compile-time value is a directory on the build
    // host and is missing on the test host when the binary was built
    // remotely.
    let source = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("tests/fixtures")
        .join(name);
    let stem = name.trim_end_matches(".c").replace('_', "-");
    let output = binary_directory().join(format!("reverie-{stem}"));
    let staging = binary_directory().join(format!("reverie-{stem}.{}.tmp", std::process::id()));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(flags)
        .arg(&source)
        .arg("-o")
        .arg(&staging)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::rename(&staging, &output)
        .unwrap_or_else(|error| panic!("publish {}: {error}", output.display()));
    output
}

/// A scratch file path for this process, removed first if it exists.
fn scratch_path(label: &str) -> PathBuf {
    let path = binary_directory().join(format!(
        "reverie-static-vfork-{label}.{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
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

/// A static image without libc: exactly its seven records (execve, openat,
/// getpid, write, close, the nothing-loaded witness and exit), exit 0, and
/// the PID file it wrote.
#[tokio::test(flavor = "current_thread")]
async fn plain_ptrace_runs_a_static_image() {
    let binary = static_fixture();
    let pid_file = scratch_path("static.pid");
    let mut command = Command::new(binary);
    command.arg(&pid_file);

    let ptrace = under_ptrace(command).await;

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
    assert!(pid_file.is_file());
    let _ = std::fs::remove_file(&pid_file);
}

/// A forked child vforks after the session root has exited: the run exits
/// 0, three tasks are traced (root, fork child and vfork grandchild), one of
/// them makes the vfork, and each witnesses that nothing was loaded.
#[tokio::test(flavor = "current_thread")]
async fn plain_ptrace_traces_a_vfork_in_a_forked_child_after_the_root_exits() {
    let binary = vfork_fixture();
    let pid_file = scratch_path("vfork.pid");
    let mut command = Command::new(binary);
    command.arg("li-to-ptrace").arg(&pid_file);
    command.stdout(reverie::process::Stdio::null());

    let ptrace = under_ptrace(command).await;

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
    let _ = std::fs::remove_file(&pid_file);
}

/// Selects the arm a re-executed namespace child runs.
const NAMESPACE_ARM_ENV: &str = "REVERIE_PTRACE_STATIC_VFORK_NAMESPACE_ARM";
const STATIC_FIXTURE_ENV: &str = "REVERIE_PTRACE_STATIC_VFORK_STATIC_FIXTURE";
const VFORK_FIXTURE_ENV: &str = "REVERIE_PTRACE_STATIC_VFORK_VFORK_FIXTURE";
const SCRATCH_ENV: &str = "REVERIE_PTRACE_STATIC_VFORK_SCRATCH";
const NAMESPACE_MARK: &str = "@@ptrace-static-vfork-namespace-arm@@ ";
const NAMESPACE_TEST: &str =
    "plain_ptrace_repeats_both_fixtures_pid_for_pid_in_a_fresh_pid_namespace";

/// Groups a trace per task, keeping each task's exact PID.
fn by_pid(trace: Vec<(Pid, String)>) -> BTreeMap<Pid, Vec<String>> {
    let mut tasks = BTreeMap::<Pid, Vec<String>>::new();
    for (pid, event) in trace {
        tasks.entry(pid).or_default().push(event);
    }
    tasks
}

/// Runs both fixtures in this process's (fresh) namespace.
async fn namespace_arm() -> String {
    let path = |name: &str| PathBuf::from(std::env::var_os(name).unwrap());
    let scratch = path(SCRATCH_ENV);
    let mut static_command = Command::new(path(STATIC_FIXTURE_ENV));
    static_command.arg(scratch.join("static.pid"));
    let mut vfork_command = Command::new(path(VFORK_FIXTURE_ENV));
    vfork_command.arg("li-to-ns").arg(scratch.join("vfork.pid"));
    vfork_command.stdout(reverie::process::Stdio::null());
    let mut record = Vec::new();
    for command in [static_command, vfork_command] {
        let (status, trace) = run_ptrace(command, true).await;
        record.push(format!("{status:?} {:?}", by_pid(trace)));
    }
    record.join("\n")
}

/// Runs one arm in a fresh user, PID and mount namespace with its own /proc,
/// the way Hermit runs the tracer, and returns the child's printed record.
fn run_arm_in_fresh_pid_namespace(
    static_fixture: &Path,
    vfork_fixture: &Path,
    scratch: &Path,
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
        .env(NAMESPACE_ARM_ENV, "ptrace")
        .env(STATIC_FIXTURE_ENV, static_fixture)
        .env(VFORK_FIXTURE_ENV, vfork_fixture)
        .env(SCRATCH_ENV, scratch)
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
            panic!("ptrace arm in a fresh PID namespace exceeded 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        status.success(),
        "ptrace arm in a fresh PID namespace failed ({status}):\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&stderr)
    );
    let record = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(NAMESPACE_MARK))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !record.is_empty(),
        "ptrace arm printed no record:\n{stdout}"
    );
    record
}

/// Two plain ptrace runs of both fixtures, each in its own fresh PID
/// namespace, are exactly equal: exit status, and every task's PID and
/// syscall return values (getpid, clone, vfork, and the length of the PID the
/// fixture writes), task by task. Each record has the PID-bearing values and
/// the nothing-loaded witness.
#[test]
fn plain_ptrace_repeats_both_fixtures_pid_for_pid_in_a_fresh_pid_namespace() {
    if let Ok(arm) = std::env::var(NAMESPACE_ARM_ENV) {
        assert_eq!(arm, "ptrace", "unknown arm {arm}");
        let record = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(namespace_arm());
        // libtest has already printed "test <name> ... " without a newline.
        println!();
        for line in record.lines() {
            println!("{NAMESPACE_MARK}{line}");
        }
        return;
    }
    let static_fixture = static_fixture();
    let vfork_fixture = vfork_fixture();
    let scratch = scratch_path("namespace");
    std::fs::create_dir(&scratch).expect("create the namespace scratch directory");
    let run = || run_arm_in_fresh_pid_namespace(static_fixture, vfork_fixture, &scratch);
    let ptrace = run();
    let ptrace_again = run();
    for name in ["static.pid", "vfork.pid"] {
        let _ = std::fs::remove_file(scratch.join(name));
    }
    let _ = std::fs::remove_dir(&scratch);
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
}
