use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use reverie_liteinst::BuiltinTool;
use reverie_liteinst::COMPAT_EVENT_COOKIE_ENV;
use reverie_liteinst::COMPAT_EVENT_FD_ENV;
use reverie_liteinst::PreloadTool;
use reverie_liteinst::SPOOF_PID;
use reverie_liteinst::configure_command;
use reverie_liteinst::configure_command_builtin;

const TEST_EVENT_COOKIE: u64 = 7_915_913_731_959_187_131;
const TEST_EVENT_FD_ENV: &str = "REVERIE_LITEINST_TEST_EVENT_FD";

fn run_guest(program: &str, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-strace"))
        .env("REVERIE_LITEINST_PRELOAD", preload_path())
        .arg(program)
        .args(arguments)
        .output()
        .unwrap()
}

fn run_compat_guest(program: &str, arguments: &[&str]) -> Output {
    let mut command = Command::new(program);
    command.args(arguments);
    configure_command(&mut command, PreloadTool::Compatibility).unwrap();
    command.output().unwrap()
}

fn compile_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = Command::new(compiler)
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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared built-in guest harness.
fn run_builtin_guest(tool: BuiltinTool, program: &str, arguments: &[&str]) -> Output {
    let mut command = Command::new(program);
    command.args(arguments);
    configure_command_builtin(&mut command, tool).unwrap();
    command.output().unwrap()
}

fn run_compat_guest_with_event_pipe(program: &str, arguments: &[&str]) -> (Output, Vec<u8>) {
    let mut descriptors = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let inherited_write_fd = write_fd.as_raw_fd();

    let mut command = Command::new(program);
    command
        .args(arguments)
        .env(COMPAT_EVENT_FD_ENV, inherited_write_fd.to_string())
        .env(COMPAT_EVENT_COOKIE_ENV, TEST_EVENT_COOKIE.to_string())
        .env(TEST_EVENT_FD_ENV, inherited_write_fd.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_command(&mut command, PreloadTool::Compatibility).unwrap();
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited_write_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let reader = thread::spawn(move || {
        let mut events = Vec::new();
        File::from(read_fd).read_to_end(&mut events).unwrap();
        events
    });
    let child = command.spawn().unwrap();
    drop(write_fd);
    let output = child.wait_with_output().unwrap();
    let events = reader.join().unwrap();
    (output, events)
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
    .expect("cargo did not build the preload cdylib")
}

#[test]
fn strace_tool_observes_echo_syscalls() {
    let output = run_guest("/bin/echo", &["hello"]);
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"hello\n");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("[liteinst strace pid "));
    assert!(stderr.contains("syscall(1,"));
}

#[test]
fn first_sigsys_installs_a_hook_for_later_calls() {
    let output = run_guest(env!("CARGO_BIN_EXE_reverie-liteinst-trap-count-guest"), &[]);
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"calls=32 traps=1 hooks=32\n");
}

#[test]
fn compatibility_tool_emits_stable_events() {
    let first = run_compat_guest("/bin/echo", &["hello"]);
    let second = run_compat_guest("/bin/echo", &["hello"]);
    assert!(first.status.success(), "first status={:?}", first.status);
    assert!(second.status.success(), "second status={:?}", second.status);
    assert_eq!(first.stdout, b"hello\n");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);

    let events = String::from_utf8(first.stderr).unwrap();
    assert!(
        events.lines().all(|line| line
            .strip_prefix("reverie-liteinst: tool=compat syscall=")
            .is_some_and(|number| number.parse::<i64>().is_ok())),
        "unexpected events: {events}"
    );
    assert!(events.lines().count() > 1, "missing events: {events}");
}

#[test]
fn compatibility_event_fd_separates_guest_stderr() {
    let spoof = "reverie-liteinst: tool=compat syscall=999999\n";
    let (output, events) = run_compat_guest_with_event_pipe(
        "/bin/sh",
        &[
            "-c",
            "test -z \"$REVERIE_LITEINST_EVENT_FD\"; test -z \"$REVERIE_LITEINST_EVENT_COOKIE\"; printf 'reverie-liteinst: tool=compat syscall=999999\\n' >&2",
        ],
    );
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stderr, spoof.as_bytes());

    let events = String::from_utf8(events).unwrap();
    let prefix = format!("reverie-liteinst: tool=compat cookie={TEST_EVENT_COOKIE} pid=");
    assert!(
        events.lines().all(|line| {
            line.strip_prefix(&prefix)
                .and_then(|record| record.split_once(" syscall="))
                .is_some_and(|(pid, number)| {
                    pid.parse::<u32>().is_ok() && number.parse::<i64>().is_ok()
                })
        }),
        "unexpected events: {events}"
    );
    assert!(!events.contains("999999"), "guest stderr leaked: {events}");
    assert!(events.lines().count() > 1, "missing events: {events}");
}

#[test]
fn compatibility_event_fd_survives_guest_close() {
    let (output, events) = run_compat_guest_with_event_pipe(
        "/bin/sh",
        &[
            "-c",
            "eval \"exec ${REVERIE_LITEINST_TEST_EVENT_FD}>&-\"; printf 'channel-survived\\n'",
        ],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"channel-survived\n");
    let events = String::from_utf8(events).unwrap();
    assert!(
        events.contains(&format!(
            "reverie-liteinst: tool=compat cookie={TEST_EVENT_COOKIE} pid="
        )),
        "missing dedicated events: {events}"
    );
}

#[test]
fn compatibility_event_fd_rejects_guest_spoof_write() {
    let forged = format!(
        "reverie-liteinst: tool=compat cookie={TEST_EVENT_COOKIE} pid=999999 syscall=999999"
    );
    let script = format!(
        "eval \"printf '{forged}\\n' >&${{REVERIE_LITEINST_TEST_EVENT_FD}}\" 2>/dev/null; result=$?; test $result -ne 0; printf 'spoof-rejected\\n'"
    );
    let (output, events) = run_compat_guest_with_event_pipe("/bin/sh", &["-c", &script]);
    assert!(
        output.status.success(),
        "{output:?}; events={}",
        String::from_utf8_lossy(&events)
    );
    assert_eq!(output.stdout, b"spoof-rejected\n");
    let events = String::from_utf8(events).unwrap();
    assert!(
        !events.contains(&forged),
        "forged event was accepted: {events}"
    );
}

#[test]
fn compatibility_event_fd_backpressure_fails_without_hanging() {
    let mut descriptors = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let inherited_write_fd = write_fd.as_raw_fd();

    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "i=0; while [ \"$i\" -lt 100000 ]; do : > /dev/null; i=$((i + 1)); done",
        ])
        .env(COMPAT_EVENT_FD_ENV, inherited_write_fd.to_string())
        .env(COMPAT_EVENT_COOKIE_ENV, TEST_EVENT_COOKIE.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_command(&mut command, PreloadTool::Compatibility).unwrap();
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited_write_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().unwrap();
    drop(write_fd);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("dedicated event channel blocked on a full pipe");
        }
        thread::sleep(Duration::from_millis(10));
    };
    drop(read_fd);
    assert_eq!(status.code(), Some(121), "{status:?}");
}

#[test]
fn compatibility_event_fd_recovers_when_delayed_reader_drains() {
    let mut descriptors = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let inherited_write_fd = write_fd.as_raw_fd();
    assert_eq!(
        unsafe { libc::fcntl(inherited_write_fd, libc::F_SETPIPE_SZ, 4096) },
        4096
    );

    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "i=0; while [ \"$i\" -lt 1000 ]; do : > /dev/null; i=$((i + 1)); done",
        ])
        .env(COMPAT_EVENT_FD_ENV, inherited_write_fd.to_string())
        .env(COMPAT_EVENT_COOKIE_ENV, TEST_EVENT_COOKIE.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_command(&mut command, PreloadTool::Compatibility).unwrap();
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited_write_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().unwrap();
    drop(write_fd);
    thread::sleep(Duration::from_millis(250));
    let reader = thread::spawn(move || {
        let mut events = Vec::new();
        File::from(read_fd).read_to_end(&mut events).unwrap();
        events
    });
    let status = child.wait().unwrap();
    let events = reader.join().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(
        events.len() > 4096,
        "delayed reader did not drain a full pipe"
    );
}

#[test]
fn compatibility_tool_rejects_process_group_escape() {
    let (_directory, guest) = compile_fixture("compat_setsid.c");
    let output = run_compat_guest(guest.to_str().unwrap(), &[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"setsid-rejected\n");
}

#[test]
fn compatibility_event_fd_rejects_read_only_descriptor() {
    let mut descriptors = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let _write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let inherited_read_fd = read_fd.as_raw_fd();

    let mut command = Command::new("/bin/true");
    command
        .env(COMPAT_EVENT_FD_ENV, inherited_read_fd.to_string())
        .env(COMPAT_EVENT_COOKIE_ENV, TEST_EVENT_COOKIE.to_string());
    configure_command(&mut command, PreloadTool::Compatibility).unwrap();
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited_read_fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();

    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must name a writable descriptor"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fork_child_inherits_preload_instrumentation() {
    let output = run_guest(env!("CARGO_BIN_EXE_reverie-liteinst-fork-guest"), &[]);
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("fork child reached guest code"));
    assert!(stdout.contains("fork parent observed child"));

    let stderr = String::from_utf8(output.stderr).unwrap();
    let pids: BTreeSet<_> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("[liteinst strace pid "))
        .filter_map(|line| line.split(']').next())
        .collect();
    assert!(
        pids.len() >= 2,
        "expected trace records from parent and child, got {pids:?}:\n{stderr}"
    );
}

#[test]
fn compatibility_fork_reports_clone_only_from_parent() {
    assert_compatibility_fork_event(&[], libc::SYS_clone);
}

#[test]
fn compatibility_raw_fork_reports_once_before_child() {
    assert_compatibility_fork_event(&["--raw-fork"], libc::SYS_fork);
}

#[test]
fn unsafe_clone_is_rejected_in_compatibility_and_strace_modes() {
    let guest = env!("CARGO_BIN_EXE_reverie-liteinst-fork-guest");
    let compatibility = run_compat_guest(guest, &["--unsafe-clone"]);
    assert!(compatibility.status.success(), "{compatibility:?}");
    assert_eq!(
        compatibility.stdout,
        format!("unsafe clone rejected: {}\n", libc::EPERM).as_bytes()
    );

    let strace = run_guest(guest, &["--unsafe-clone"]);
    assert!(strace.status.success(), "{strace:?}");
    assert_eq!(
        strace.stdout,
        format!("unsafe clone rejected: {}\n", libc::ENOTSUP).as_bytes()
    );
}

fn assert_compatibility_fork_event(arguments: &[&str], syscall: i64) {
    let (output, events) = run_compat_guest_with_event_pipe(
        env!("CARGO_BIN_EXE_reverie-liteinst-fork-guest"),
        arguments,
    );
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let events = String::from_utf8(events).unwrap();
    let fork_suffix = format!(" syscall={syscall}");
    let lines: Vec<_> = events.lines().collect();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.ends_with(&fork_suffix))
            .count(),
        1,
        "successful fork must have one parent-owned compatibility event:\n{events}"
    );
    let clone_position = lines
        .iter()
        .position(|line| line.ends_with(&fork_suffix))
        .unwrap();
    let parent_pid = lines[clone_position]
        .split_once(" pid=")
        .unwrap()
        .1
        .split_once(" syscall=")
        .unwrap()
        .0;
    let child_position = lines
        .iter()
        .position(|line| {
            line.split_once(" pid=")
                .and_then(|(_, record)| record.split_once(" syscall="))
                .is_some_and(|(pid, _)| pid != parent_pid)
        })
        .expect("child instrumentation event is missing");
    assert!(
        clone_position < child_position,
        "clone marker must precede child activity:\n{events}"
    );
    let pids: BTreeSet<_> = lines
        .iter()
        .filter_map(|line| line.split_once(" pid=")?.1.split_once(" syscall="))
        .map(|(pid, _)| pid)
        .collect();
    assert!(
        pids.len() >= 2,
        "child instrumentation events are missing: {pids:?}\n{events}"
    );
}

#[test]
fn exec_fails_closed_before_runtime_is_replaced() {
    let output = run_guest(env!("CARGO_BIN_EXE_reverie-liteinst-exec-guest"), &[]);
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"exec rejected with ENOTSUP\n");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("syscall(59,"));
    assert!(stderr.contains("= -95"));
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared spoof-getpid built-in behavior test.
#[test]
fn spoof_getpid_builtin_mutates_getpid_result() {
    let output = run_builtin_guest(
        BuiltinTool::SpoofGetpid,
        env!("CARGO_BIN_EXE_reverie-liteinst-spoof-guest"),
        &[],
    );
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The shared built-in installs via reverie_preload::install_builtin and
    // rewrites the trapped getpid result: the LiteInst trap path MUTATED a
    // syscall return value, not merely observed it.
    assert_eq!(output.stdout, format!("getpid={SPOOF_PID}\n").as_bytes());
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared passthrough built-in behavior test.
#[test]
fn passthrough_builtin_preserves_getpid_result() {
    let output = run_builtin_guest(
        BuiltinTool::Passthrough,
        env!("CARGO_BIN_EXE_reverie-liteinst-spoof-guest"),
        &[],
    );
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let pid: i64 = stdout
        .strip_prefix("getpid=")
        .and_then(|value| value.trim_end().parse().ok())
        .unwrap_or_else(|| panic!("unexpected guest output: {stdout:?}"));
    // The passthrough built-in leaves the real result intact; a real PID is a
    // small positive value and never the spoof sentinel.
    assert!(pid > 0, "expected a real pid, got {pid}");
    assert_ne!(pid, SPOOF_PID, "passthrough must not spoof getpid");
}
