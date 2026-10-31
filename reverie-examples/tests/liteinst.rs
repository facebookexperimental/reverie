/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end checks for the exact example `Tool` types on LiteInst, with
//! Counter1 allocator coverage through the shared backend launcher.
//! DBT Counter1, Counter2, Strace, minimal Strace, ChromeTrace and ChunkyPrint
//! require their explicit caller producers for the same Cargo profile and
//! standard manifest layout.
//! The ChromeTrace, ChunkyPrint and minimal Strace negative controls also require
//! the basics-noop caller. The separate Counter1 local-Global case requires the no-argument
//! prototype producer `reverie-dbt/scripts/build-client.sh`, or `REVERIE_DBT_CLIENT`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV;

#[path = "../dbt_client.rs"]
mod dbt_client;

const TEST_STRADDLER_STALENESS_TICKS: &str = "20000";

fn preload() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    let profile = deps.parent().unwrap();
    [
        // `cargo test` refreshes the copy in `deps`; the profile-root copy can
        // belong to another worktree when both share one Cargo target directory.
        deps.join("libreverie_examples.so"),
        profile.join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build libreverie_examples.so")
}

fn run(tool: &str, extra: &[&str], guest: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        // The direct runtime has no ptrace fallback supervisor. Exercise its
        // concurrent WordPatch++ path explicitly; this test value is not a
        // production machine-calibration claim.
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .arg("--tool")
        .arg(tool)
        .arg("--preload")
        .arg(preload())
        .args(extra)
        .arg("--")
        .args(guest);
    output_with_timeout(&mut command)
}

fn output_with_timeout(command: &mut Command) -> Output {
    output_with_timeout_duration(command, Duration::from_secs(10))
}

fn output_with_timeout_duration(command: &mut Command, timeout: Duration) -> Output {
    output_with_timeout_observed(command, timeout, |_| Ok(()))
}

fn output_with_timeout_observed<G>(
    command: &mut Command,
    timeout: Duration,
    observe_spawn: impl FnOnce(libc::pid_t) -> std::io::Result<G>,
) -> Output {
    use std::io::Read as _;

    fn nonblocking(pipe: &impl AsRawFd) -> std::io::Result<()> {
        let flags = loop {
            let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
            if flags != -1 {
                break flags;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        };
        loop {
            if unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                != -1
            {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn read_pipe(
        pipe: &mut impl std::io::Read,
        bytes: &mut Vec<u8>,
        eof: &mut bool,
    ) -> std::io::Result<bool> {
        if *eof {
            return Ok(false);
        }
        // One bounded read per stream per turn keeps both streams and the
        // deadline moving, even when one writer produces data continuously.
        let mut buffer = [0; 8192];
        match pipe.read(&mut buffer) {
            Ok(0) => {
                *eof = true;
                Ok(false)
            }
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            // Retry next turn, without sleeping or mistaking interruption for EOF.
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(true),
            Err(error) => Err(error),
        }
    }

    fn drain_after_kill(
        pipe: &mut (impl std::io::Read + AsRawFd),
        bytes: &mut Vec<u8>,
    ) -> std::io::Result<()> {
        // No pipe can hold more than its capacity. Bound cleanup even if a
        // writer escaped the owned group; the parent endpoint is nonblocking.
        let capacity = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETPIPE_SZ) };
        if capacity == -1 {
            return Err(std::io::Error::last_os_error());
        }
        match pipe.take(capacity as u64).read_to_end(bytes) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + timeout;
    let process_group = child.id() as libc::pid_t;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_nonblocking = false;
    let mut stderr_nonblocking = false;
    let mut leader_owned = true;
    let mut observer = None;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> std::io::Result<()> {
            observer = Some(observe_spawn(process_group)?);
            let stdout = stdout
                .as_mut()
                .ok_or_else(|| std::io::Error::other("missing captured stdout"))?;
            let stderr = stderr
                .as_mut()
                .ok_or_else(|| std::io::Error::other("missing captured stderr"))?;
            nonblocking(stdout)?;
            stdout_nonblocking = true;
            nonblocking(stderr)?;
            stderr_nonblocking = true;
            let mut exited = false;
            let mut stdout_eof = false;
            let mut stderr_eof = false;
            loop {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "example output deadline expired",
                    ));
                }
                if !exited {
                    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    let waited = unsafe {
                        libc::waitid(
                            libc::P_PID,
                            child.id(),
                            &mut info,
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                        )
                    };
                    if waited == -1 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() == std::io::ErrorKind::Interrupted {
                            continue;
                        }
                        if error.raw_os_error() == Some(libc::ECHILD) {
                            // A foreign reaper invalidates our PID/PGID ownership.
                            // Refuse capture without signalling a reusable identity.
                            leader_owned = false;
                        }
                        return Err(error);
                    }
                    exited = unsafe { info.si_pid() } != 0;
                }
                let stdout_progress = read_pipe(stdout, &mut stdout_bytes, &mut stdout_eof)?;
                let stderr_progress = read_pipe(stderr, &mut stderr_bytes, &mut stderr_eof)?;
                if exited && stdout_eof && stderr_eof {
                    return Ok(());
                }
                if !stdout_progress && !stderr_progress {
                    std::thread::sleep(
                        Duration::from_millis(10)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }));
    let failed = !matches!(&result, Ok(Ok(())));
    let mut cleanup_errors = Vec::new();
    if failed && leader_owned {
        // WNOWAIT retains the leader's identity until this point, including
        // when an exited leader has a descendant holding either writer open.
        if unsafe { libc::kill(-process_group, libc::SIGKILL) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup_errors.push(error);
            }
        }
        if let Err(error) = child.kill()
            && error.raw_os_error() != Some(libc::ESRCH)
        {
            cleanup_errors.push(error);
        }
    }
    // The private observer's nonpanicking guard stops and joins its watcher
    // while the leader is still unreaped. It must never signal after this
    // handoff. Neither observer joins nor the collector wait for pipe EOF here.
    drop(observer);
    let status = child.wait();
    if failed {
        if let Some(stdout) = stdout.as_mut().filter(|_| stdout_nonblocking)
            && let Err(error) = drain_after_kill(stdout, &mut stdout_bytes)
        {
            cleanup_errors.push(error);
        }
        if let Some(stderr) = stderr.as_mut().filter(|_| stderr_nonblocking)
            && let Err(error) = drain_after_kill(stderr, &mut stderr_bytes)
        {
            cleanup_errors.push(error);
        }
    }
    let result = result.unwrap_or_else(|panic| {
        let _ = writeln!(
            std::io::stderr(),
            "LiteInst example capture unwound: wait={status:?}; cleanup={cleanup_errors:?}; stdout={stdout_bytes:?}; stderr={stderr_bytes:?}"
        );
        std::panic::resume_unwind(panic)
    });
    let status = status.unwrap_or_else(|error| {
        panic!(
            "LiteInst example wait failed: {error}; capture={result:?}; cleanup={cleanup_errors:?}; stdout={stdout_bytes:?}; stderr={stderr_bytes:?}"
        )
    });
    let output = Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    };
    if let Err(error) = result {
        if error.kind() == std::io::ErrorKind::TimedOut {
            panic!("LiteInst example timed out: {output:?}; cleanup={cleanup_errors:?}");
        }
        panic!("LiteInst example capture failed: {error}; {output:?}; cleanup={cleanup_errors:?}");
    }
    output
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CaptureProcess {
    pid: i32,
    group: i32,
    start_time: u64,
}

fn capture_process(pid: i32) -> std::io::Result<(CaptureProcess, char)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or_else(|| std::io::Error::other("malformed process stat"))?
        .1
        .split_ascii_whitespace()
        .collect();
    let invalid = || std::io::Error::other("invalid process identity");
    Ok((
        CaptureProcess {
            pid,
            group: fields
                .get(2)
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?,
            start_time: fields
                .get(19)
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?,
        },
        fields
            .first()
            .and_then(|state| state.chars().next())
            .ok_or_else(invalid)?,
    ))
}

fn kill_capture_process(process: &CaptureProcess) -> std::io::Result<()> {
    use std::os::fd::FromRawFd as _;

    // A pidfd plus the recorded start time prevents emergency test cleanup
    // from signalling a different process after the helper has reaped a PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, process.pid, 0) };
    if fd == -1 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) };
    match capture_process(process.pid) {
        Ok((actual, _)) if actual == *process => {}
        Ok(_) => return Err(std::io::Error::other("capture process identity changed")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn capture_worker_prefix(test: &str) -> Vec<u8> {
    format!("\nrunning 1 test\ntest {test} ... ").into_bytes()
}

#[test]
fn output_with_timeout_drains_both_pipes() {
    const TEST: &str = "output_with_timeout_drains_both_pipes";
    const READY: &str = "REVERIE_TEST_CAPTURE_WRITER_READY";
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Ready {
        process: CaptureProcess,
        stdout_capacity: usize,
        stderr_capacity: usize,
    }

    if let Some(path) = std::env::var_os(READY) {
        let stdout_capacity = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETPIPE_SZ) };
        let stderr_capacity = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETPIPE_SZ) };
        assert!(stdout_capacity > 0 && stderr_capacity > 0);
        let ready = Ready {
            process: capture_process(std::process::id() as i32).unwrap().0,
            stdout_capacity: stdout_capacity as usize,
            stderr_capacity: stderr_capacity as usize,
        };
        // This file is independent of the two pipes being tested.
        std::fs::write(path, serde_json::to_vec(&ready).unwrap()).unwrap();
        std::io::stdout()
            .write_all(&vec![b'O'; ready.stdout_capacity + 4096])
            .unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stderr()
            .write_all(&vec![b'E'; ready.stderr_capacity + 4096])
            .unwrap();
        std::io::stderr().flush().unwrap();
        // Omit libtest's variable-duration result line from the exact bytes.
        std::process::exit(0);
    }

    let directory = tempfile::tempdir().unwrap();
    let ready_path = directory.path().join("writer-ready.json");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(READY, &ready_path);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output_with_timeout_duration(&mut command, Duration::from_secs(1))
    }));
    let raw = std::fs::read_to_string(&ready_path).unwrap();
    eprintln!("native writer readiness: {raw}");
    let ready: Ready = serde_json::from_str(&raw).unwrap();
    assert_eq!(ready.process.group, ready.process.pid);
    let waited = unsafe { libc::waitpid(ready.process.pid, std::ptr::null_mut(), libc::WNOHANG) };
    let wait_error = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(waited, -1);
    assert_eq!(wait_error, Some(libc::ECHILD));
    let output = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(output.status.success(), "{output:?}");
    let mut stdout = capture_worker_prefix(TEST);
    stdout.extend(std::iter::repeat_n(b'O', ready.stdout_capacity + 4096));
    assert_eq!(output.stdout, stdout);
    assert_eq!(output.stderr, vec![b'E'; ready.stderr_capacity + 4096]);
}

#[test]
fn output_with_timeout_cleans_up_live_pipe_holder() {
    const TEST: &str = "output_with_timeout_cleans_up_live_pipe_holder";
    const ROLE: &str = "REVERIE_TEST_CAPTURE_HOLDER_ROLE";
    const READY: &str = "REVERIE_TEST_CAPTURE_HOLDER_READY";
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Ready {
        leader: CaptureProcess,
        holder: CaptureProcess,
    }

    let role = std::env::var(ROLE).ok();
    if role.is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(ROLE, "owner");
        // This separate owner bound is below the external ten-second bound.
        let output = output_with_timeout_duration(&mut command, Duration::from_secs(5));
        eprintln!("native holder owner: {output:?}");
        assert!(output.status.success(), "{output:?}");
        return;
    }
    if role.as_deref() == Some("leader") {
        let path = std::env::var_os(READY).unwrap();
        std::io::stdout().write_all(b"holder-out\n").unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stderr().write_all(b"holder-err\n").unwrap();
        let leader = capture_process(std::process::id() as i32).unwrap().0;
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Only async-signal-safe operations after fork; retain the same
            // group and the captured writers until the helper kills us.
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        let published = (|| -> std::io::Result<()> {
            let holder = capture_process(child)?.0;
            if holder.group != leader.group {
                return Err(std::io::Error::other("holder escaped group"));
            }
            std::fs::write(
                path,
                serde_json::to_vec(&Ready { leader, holder }).map_err(std::io::Error::other)?,
            )
        })();
        if let Err(error) = published {
            // The parent still owns this unreaped child on every setup error.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::waitpid(child, std::ptr::null_mut(), 0);
            }
            panic!("holder readiness failed: {error}");
        }
        std::process::exit(7);
    }
    assert_eq!(role.as_deref(), Some("owner"));
    // Subreaper state is confined to this isolated process, never the parallel
    // libtest parent. It lets the owner prove that the holder was reaped.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let directory = tempfile::tempdir().unwrap();
    let owner_deadline = Instant::now() + Duration::from_secs(4);
    let ready_path = directory.path().join("holder-ready.json");
    type WatchOutcome = (bool, Option<Ready>, bool, std::io::Result<()>);
    struct Watcher<'a> {
        group: libc::pid_t,
        stop: std::sync::mpsc::Sender<()>,
        thread: Option<std::thread::JoinHandle<WatchOutcome>>,
        outcome: &'a mut Option<WatchOutcome>,
    }
    fn kill_owned_group(group: libc::pid_t) -> std::io::Result<()> {
        // Called only before the collector reaps its group leader.
        if unsafe { libc::kill(-group, libc::SIGKILL) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }
    impl Drop for Watcher<'_> {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            *self.outcome = Some(match self.thread.take().map(|thread| thread.join()) {
                Some(Ok(outcome)) => outcome,
                _ => {
                    // Even a watcher panic cannot bypass owned-group cleanup.
                    let cleanup = kill_owned_group(self.group);
                    (
                        true,
                        None,
                        false,
                        Err(std::io::Error::other(format!(
                            "capture watchdog failed; group cleanup={cleanup:?}"
                        ))),
                    )
                }
            });
        }
    }
    let mut watch_outcome = None;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(ROLE, "leader")
        .env(READY, &ready_path);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        output_with_timeout_observed(&mut command, Duration::from_secs(1), |group| {
            let (finished, stop) = std::sync::mpsc::channel();
            let watcher = std::thread::Builder::new().spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut ready = Err(std::io::Error::other("missing holder readiness"));
                let mut live = false;
                let forced = loop {
                    if ready.is_err() {
                        ready = (|| -> std::io::Result<Ready> {
                            let bytes = std::fs::read(&ready_path)?;
                            let value: Ready =
                                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
                            let leader = capture_process(group)?.0;
                            let (holder, state) = capture_process(value.holder.pid)?;
                            if value.leader != leader
                                || leader.group != group
                                || holder != value.holder
                                || holder.group != group
                            {
                                return Err(std::io::Error::other(
                                    "holder readiness differs from the spawned group",
                                ));
                            }
                            live = state != 'Z' && state != 'X';
                            Ok(value)
                        })();
                    }
                    if Instant::now() >= deadline {
                        break true;
                    }
                    match stop.recv_timeout(Duration::from_millis(1)) {
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            break false;
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    }
                };
                let (ready, mut observation) = match ready {
                    Ok(value) => (Some(value), Ok(())),
                    Err(error) => (None, Err(error)),
                };
                if forced || observation.is_err() {
                    // Authority comes from spawn, never the readiness file.
                    // Missing readiness remains an error even if cleanup works.
                    if let Err(error) = kill_owned_group(group) {
                        observation = Err(std::io::Error::other(format!(
                            "holder observation={observation:?}; group cleanup={error}"
                        )));
                    }
                }
                (forced, ready, live, observation)
            })?;
            Ok(Watcher {
                group,
                stop: finished,
                thread: Some(watcher),
                outcome: &mut watch_outcome,
            })
        })
    }));
    let (forced, ready, live, watchdog_cleanup) = watch_outcome.unwrap_or_else(|| {
        (
            false,
            None,
            false,
            Err(std::io::Error::other("capture watchdog was not installed")),
        )
    });
    let observed = (|| -> std::io::Result<_> {
        let ready = ready
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing holder readiness"))?;
        let leader_wait =
            unsafe { libc::waitpid(ready.leader.pid, std::ptr::null_mut(), libc::WNOHANG) };
        let leader_error = std::io::Error::last_os_error().raw_os_error();
        let mut status = 0;
        let holder_wait = loop {
            let waited = unsafe { libc::waitpid(ready.holder.pid, &mut status, libc::WNOHANG) };
            if waited != 0 {
                break waited;
            }
            if Instant::now() >= owner_deadline {
                return Err(std::io::Error::other("helper left its holder alive"));
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        Ok((leader_wait, leader_error, holder_wait, status))
    })();
    // Cleanup precedes all assertions, including readiness/observation errors.
    let cleanup = if let Some(value) = &ready {
        let holder = kill_capture_process(&value.holder);
        let leader = kill_capture_process(&value.leader);
        holder.and(leader)
    } else {
        Ok(())
    };
    let mut reaped = Vec::new();
    let reaping = loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            reaped.push((pid, status));
            continue;
        }
        if pid == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                break Ok(());
            }
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break Err(error);
        }
        if Instant::now() >= owner_deadline {
            break Err(std::io::Error::other("capture children were not reaped"));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    eprintln!(
        "native holder observation: forced={forced}, live={live}, ready={ready:?}, waited={observed:?}, reaped={reaped:?}"
    );
    watchdog_cleanup.unwrap();
    cleanup.unwrap();
    reaping.unwrap();
    assert!(
        !forced,
        "owner watchdog intervened instead of helper cleanup"
    );
    assert!(live, "no live holder observed before the helper deadline");
    let ready = ready.unwrap();
    let (leader_wait, leader_error, holder_wait, status) = observed.unwrap();
    assert_eq!(leader_wait, -1);
    assert_eq!(leader_error, Some(libc::ECHILD));
    assert_eq!(holder_wait, ready.holder.pid, "helper left a live holder");
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert!(match capture_process(ready.holder.pid) {
        Ok((actual, state)) => actual != ready.holder || state == 'Z' || state == 'X',
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    });
    let panic = result.expect_err("helper returned normally despite a live pipe holder");
    let panic = panic
        .downcast_ref::<String>()
        .expect("timeout panic must retain its output");
    assert!(panic.starts_with("LiteInst example timed out: "), "{panic}");
    assert!(panic.contains("unix_wait_status(1792)"), "{panic}");
    let mut stdout = capture_worker_prefix(TEST);
    stdout.extend_from_slice(b"holder-out\n");
    assert!(
        panic.contains(&format!(
            "stdout: {:?}",
            std::str::from_utf8(&stdout).unwrap()
        )),
        "{panic}"
    );
    assert!(panic.contains("stderr: \"holder-err\\n\""), "{panic}");
}

#[test]
fn launcher_does_not_activate_the_guest_constructor() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .env("REVERIE_LITEINST_COORDINATOR", "/tmp/not-a-coordinator")
        .env("REVERIE_LITEINST_EXAMPLE_TOOL", "noop")
        .arg("--help");
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.starts_with(b"Usage:"), "{output:?}");
}

#[test]
fn launcher_exposes_the_complete_ptrace_example_surface() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command.arg("--help");
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).unwrap();
    for tool in [
        "chaos",
        "chrome-trace",
        "chunky-print",
        "counter1",
        "counter2",
        "debug",
        "noop",
        "strace",
        "strace-minimal",
    ] {
        assert!(help.contains(tool), "missing {tool:?} from help:\n{help}");
    }
}

#[test]
fn exact_noop_tool_preserves_output_and_hides_control_environment() {
    let output = run(
        "noop",
        &[],
        &[
            "/bin/sh",
            "-c",
            "test -z \"$REVERIE_LITEINST_EXAMPLE_TOOL\" && test -z \"$REVERIE_LITEINST_COORDINATOR\" && printf hello",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_user_coordinator_environment() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .env("REVERIE_LITEINST_COORDINATOR", "guest-value")
        .arg("--tool")
        .arg("noop")
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("check-coordinator-environment");
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"coordinator-environment-preserved\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_raw_environment_entries() {
    let output = run(
        "noop",
        &[],
        &[env!("CARGO_BIN_EXE_reverie-liteinst-env-guest")],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"raw-environment-ok\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_preserves_unrelated_inherited_descriptor() {
    let inherited = File::open("/dev/null").unwrap();
    let inherited_fd = inherited.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-examples"));
    command
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .arg("--tool")
        .arg("noop")
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("check-fd-198");
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(inherited_fd, 198) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"fd-198-preserved\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn exact_noop_tool_repeatedly_runs_fast_guest() {
    for attempt in 0..50 {
        let output = run("noop", &[], &["/bin/true"]);
        assert!(output.status.success(), "attempt {attempt}: {output:?}");
        assert!(output.stdout.is_empty(), "attempt {attempt}: {output:?}");
        assert!(output.stderr.is_empty(), "attempt {attempt}: {output:?}");
    }
}

#[test]
fn exact_counter1_tool_reports_a_nonzero_total() {
    let output = run("counter1", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let total = stderr
        .lines()
        .find_map(|line| line.strip_prefix(" [counter tool] Total system calls in process tree: "))
        .expect("counter1 summary is missing")
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator() {
    let output = run(
        "counter1",
        &[],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-allocator",
        ],
    );

    assert_counter1_allocator_output(
        &output,
        " [counter tool] Total system calls in process tree: ",
    );
}

fn assert_counter1_allocator_output(output: &Output, summary_prefix: &str) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"allocator-growth-ok\n");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let total = stderr
        .lines()
        .find_map(|line| line.strip_prefix(summary_prefix))
        .expect("counter1 summary is missing")
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
}

fn assert_one_counter1_allocator_summary(output: &Output) {
    let prefix = "counter1-global syscalls=";
    assert_counter1_allocator_output(output, prefix);
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count(),
        1,
        "{stderr}"
    );
}

fn counter1_allocator_on(backend: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
    command
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .arg("--backend")
        .arg(backend)
        .arg("--preload")
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_ptrace() {
    counter1_allocator_on("ptrace");
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_dbt() {
    counter1_allocator_on("dbt");
}

#[test]
fn exact_counter1_tool_does_not_reenter_the_guest_allocator_on_in_guest_trap() {
    counter1_allocator_on("in-guest-trap");
}

#[test]
fn exact_counter1_tool_reports_its_local_global_without_a_coordinator() {
    let client = dbt_client::find(Some(Path::new(env!("CARGO_BIN_EXE_counter1")))).expect(
        "build the DBT client with reverie-dbt/scripts/build-client.sh or set REVERIE_DBT_CLIENT",
    );
    // The documented exact-mode flag selects the same Tool with a local GlobalState.
    // Use the native launch shape from reverie-dbt/scripts/test-example-tools.sh.
    let mut command = Command::new(reverie_dbt::bundled_drrun_path());
    command
        .env_remove(reverie_dbt::TOOL_ENV)
        .env_remove(reverie_dbt::sync_rpc::RPC_SOCKET_ENV)
        .env("HERMIT_DBT_COUNTER1_EXACT", "1")
        .args(["-quiet", "-disable_rseq", "-stack_size", "2M", "-c"])
        .arg(client)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn dbt_counter1_explicit_caller_selection_bypasses_prototype_client() {
    let manifest = Path::new(env!("CARGO_BIN_EXE_counter1"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter1/manifest.json");
    // A valid, current pair is a prerequisite; a missing caller cannot prove
    // that the CLI selected the actual shared Tool through the caller owner.
    reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing_prototype = directory.path().join("missing-prototype-client.so");
    assert!(!missing_prototype.exists());
    let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
    command
        .env("REVERIE_DBT_CALLER_ARTIFACT", &manifest)
        .env("REVERIE_DBT_CLIENT", &missing_prototype)
        .env(
            STRADDLER_STALENESS_TICKS_ENV,
            TEST_STRADDLER_STALENESS_TICKS,
        )
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-allocator");
    assert_one_counter1_allocator_summary(&output_with_timeout(&mut command));
}

#[test]
fn dbt_counter1_bad_override_never_uses_the_valid_default_pair() {
    let default = Path::new(env!("CARGO_BIN_EXE_counter1"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter1/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let malformed = directory.path().join("malformed.json");
    std::fs::write(&malformed, b"{}").unwrap();
    for path in [directory.path().join("absent.json"), malformed] {
        for via_environment in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_counter1"));
            command
                .env_remove("REVERIE_DBT_CALLER_ARTIFACT")
                .args(["--backend", "dbt"]);
            if via_environment {
                command.env("REVERIE_DBT_CALLER_ARTIFACT", &path);
            } else {
                command.arg("--dbt-artifact").arg(&path);
            }
            command
                .arg("--")
                .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
                .arg("exercise-allocator");
            let output = output_with_timeout(&mut command);
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("cannot load DBT caller artifact"),
                "{output:?}"
            );
        }
    }
}

#[test]
fn exact_counter2_tool_reports_process_and_thread_totals() {
    let output = run("counter2", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let summary = stderr
        .lines()
        .find_map(|line| line.strip_prefix(" [counter tool] Total system calls in process tree: "))
        .expect("counter2 summary is missing");
    let total = summary
        .split_once(',')
        .expect("counter2 total is not followed by process details")
        .0
        .parse::<u64>()
        .unwrap();
    assert!(total > 0, "{stderr}");
    assert!(
        summary.ends_with("from 1 processes, 1 thread(s)."),
        "{stderr}"
    );
}

fn counter2_reports_exit_after_echo_closes_stdio(backend: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_counter2"));
    command.args(["--backend", backend, "--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    assert_counter2_report(&output);
}

fn assert_counter2_report(output: &Output) {
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let reports = stderr
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            line.strip_prefix("counter2-local thread=")
                .map(|report| (index, report))
        })
        .collect::<Vec<_>>();
    assert_eq!(reports.len(), 1, "{stderr}");
    let (tid, count) = reports[0]
        .1
        .split_once(" syscalls=")
        .expect("counter2 thread report has no syscall count");
    assert!(tid.parse::<i32>().unwrap() > 0, "{stderr}");
    let count = count.parse::<u64>().unwrap();
    assert!(count > 0, "{stderr}");

    let summaries = stderr
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            line.strip_prefix(" [counter tool] Total system calls in process tree: ")
                .map(|summary| (index, summary))
        })
        .collect::<Vec<_>>();
    assert_eq!(summaries.len(), 1, "{stderr}");
    let (total, details) = summaries[0]
        .1
        .split_once(", from ")
        .expect("counter2 total has no process details");
    assert_eq!(details, "1 processes, 1 thread(s).", "{stderr}");
    assert_eq!(total.parse::<u64>().unwrap(), count, "{stderr}");
    assert!(reports[0].0 < summaries[0].0, "{stderr}");
}

#[test]
fn ptrace_counter2_reports_exit_after_echo_closes_stdio() {
    counter2_reports_exit_after_echo_closes_stdio("ptrace");
}

#[test]
fn dbt_counter2_reports_exit_after_echo_closes_stdio() {
    counter2_reports_exit_after_echo_closes_stdio("dbt");
}

#[test]
fn dbt_counter2_bad_override_never_uses_the_valid_default_pair() {
    let default = Path::new(env!("CARGO_BIN_EXE_counter2"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter2/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let malformed = directory.path().join("malformed.json");
    std::fs::write(&malformed, b"{}").unwrap();
    for path in [directory.path().join("missing.json"), malformed] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_counter2"));
        command.env("REVERIE_DBT_CALLER_ARTIFACT", &path).args([
            "--backend",
            "dbt",
            "--",
            "/bin/echo",
            "hello",
        ]);
        let output = output_with_timeout(&mut command);
        assert!(!output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("cannot load DBT caller artifact"),
            "{stderr}"
        );
        assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
        assert!(!stderr.contains("counter2-local thread="), "{stderr}");
    }
}

fn assert_counter2_environment(output: &Output, expected: &BTreeMap<OsString, OsString>) {
    assert!(output.status.success(), "{output:?}");
    assert_counter2_report(output);
    assert_eq!(
        output.stdout.last(),
        Some(&0),
        "environment has no final NUL: {output:?}"
    );
    let mut actual = BTreeMap::new();
    for record in output.stdout[..output.stdout.len() - 1].split(|byte| *byte == 0) {
        let separator = record
            .iter()
            .position(|byte| *byte == b'=')
            .expect("environment entry has no '='");
        assert!(separator > 0, "environment entry has an empty key");
        let key = OsStr::from_bytes(&record[..separator]).to_os_string();
        let value = OsStr::from_bytes(&record[separator + 1..]).to_os_string();
        assert!(
            actual.insert(key, value).is_none(),
            "duplicate environment entry: {output:?}"
        );
    }
    // Compare every entry; in particular do not filter sanitizer additions or
    // private runtime controls out of an unexpected actual environment.
    assert_eq!(
        &actual, expected,
        "captured environment differs: {output:?}"
    );
}

fn counter2_captured_environment_controls(backend: &str) {
    let env_image = std::fs::canonicalize("/usr/bin/env").unwrap();
    let echo_image = std::fs::canonicalize("/bin/echo").unwrap();
    let env_metadata = std::fs::metadata(&env_image).unwrap();
    let echo_metadata = std::fs::metadata(&echo_image).unwrap();
    let env_bytes = std::fs::read(&env_image).unwrap();
    let echo_bytes = std::fs::read(&echo_image).unwrap();
    // Foreign argv0 must not select another applet of one multicall image.
    assert_ne!(env_image, echo_image, "env/echo fixture is a shared image");
    assert_ne!(
        (env_metadata.dev(), env_metadata.ino()),
        (echo_metadata.dev(), echo_metadata.ino())
    );
    assert!(env_bytes.starts_with(b"\x7fELF") && echo_bytes.starts_with(b"\x7fELF"));
    assert_ne!(
        env_bytes, echo_bytes,
        "env/echo fixture has identical image bytes"
    );
    eprintln!(
        "counter2 environment fixtures: env={env_image:?} dev={} ino={} bytes={}; echo={echo_image:?} dev={} ino={} bytes={}",
        env_metadata.dev(),
        env_metadata.ino(),
        env_bytes.len(),
        echo_metadata.dev(),
        echo_metadata.ino(),
        echo_bytes.len(),
    );
    let directory = tempfile::tempdir().unwrap();
    let host_bin = directory.path().join("host-bin");
    let guest_bin = directory.path().join("guest-bin");
    std::fs::create_dir(&host_bin).unwrap();
    std::fs::create_dir(&guest_bin).unwrap();
    for (link, target) in [
        (host_bin.join("probe"), &echo_image),
        (guest_bin.join("probe"), &env_image),
        (directory.path().join("echo"), &env_image),
    ] {
        std::os::unix::fs::symlink(target, &link).unwrap();
        assert_eq!(std::fs::canonicalize(&link).unwrap(), *target);
    }
    let program = Path::new(env!("CARGO_BIN_EXE_counter2"));
    assert!(program.is_absolute());
    let manifest = program
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/counter2/manifest.json");
    if backend == "dbt" {
        // An absent or stale producer is a setup failure, never a skipped case.
        reverie_dbt::CallerArtifact::load(&manifest).unwrap();
    }
    let controller = BTreeMap::from([
        (OsString::from("PATH"), OsString::from("/bin:/usr/bin")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (
            OsString::from("REVERIE_TEST_CONTROLLER_ONLY"),
            OsString::from("public-sentinel"),
        ),
        (
            OsString::from("REVERIE_TEST_OBSERVATION_PATH"),
            OsString::from("/unused-public-observation"),
        ),
        (
            OsString::from("REVERIE_TEST_VALUE"),
            OsString::from("controller-value"),
        ),
        (
            OsString::from("REVERIE_TEST_BYTES"),
            OsStr::from_bytes(b"public-\xff-value").to_os_string(),
        ),
    ]);
    for case in [
        "clear",
        "inherit",
        "override",
        "explicit-path",
        "absent-path",
    ] {
        let mut environment = controller.clone();
        let mut expected = environment.clone();
        let mut options: Vec<OsString> = Vec::new();
        let guest = match case {
            "clear" | "explicit-path" => {
                let path = if case == "clear" {
                    OsString::from("/bin/:/usr/bin")
                } else {
                    environment.insert("PATH".into(), host_bin.as_os_str().to_os_string());
                    guest_bin.as_os_str().to_os_string()
                };
                expected = BTreeMap::from([
                    (OsString::from("PATH"), path.clone()),
                    (OsString::from("LC_ALL"), OsString::from("C")),
                    (
                        OsString::from("REVERIE_TEST_VALUE"),
                        OsString::from("guest-clear"),
                    ),
                ]);
                options.extend(
                    [
                        "--no-host-envs",
                        "--env",
                        "LC_ALL=C",
                        "--env",
                        "REVERIE_TEST_VALUE=guest-clear",
                    ]
                    .map(OsString::from),
                );
                if case == "explicit-path" {
                    let mut entry = OsString::from("PATH=");
                    entry.push(path);
                    options.extend([OsString::from("--env"), entry]);
                    "probe"
                } else {
                    "/usr/bin/env"
                }
            }
            "inherit" => "/usr/bin/env",
            "override" => {
                options.extend(["--env", "REVERIE_TEST_VALUE=guest-override"].map(OsString::from));
                expected.insert("REVERIE_TEST_VALUE".into(), "guest-override".into());
                "/usr/bin/env"
            }
            "absent-path" => {
                environment.remove(OsStr::new("PATH"));
                expected.remove(OsStr::new("PATH"));
                // No --no-host-envs: its documented minimal PATH would hide
                // the distinction between shared cwd lookup and _CS_PATH.
                "echo"
            }
            _ => unreachable!(),
        };
        if backend == "ptrace" {
            // Existing TracerBuilder::spawn -> turn_off_leak_check policy.
            // The controller has none of these keys; UBSAN stays absent.
            expected.insert("ASAN_OPTIONS".into(), "detect_leaks=0".into());
            expected.insert("LSAN_OPTIONS".into(), "detect_leaks=0".into());
        }
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(&environment)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .args(["--backend", backend]);
        if backend == "dbt" {
            command.arg("--dbt-artifact").arg(&manifest);
        }
        command.args(&options).args(["--", guest, "-0"]);
        eprintln!("counter2 environment {backend}/{case}: begin");
        let output = output_with_timeout(&mut command);
        eprintln!(
            "counter2 environment {backend}/{case}: status={:?} stdout={:?} stderr={:?}",
            output.status, output.stdout, output.stderr,
        );
        assert_counter2_environment(&output, &expected);
        eprintln!("counter2 environment {backend}/{case}: exact-result-accepted");
        // A failure stops here; later cases have no begin/result record and
        // must be reported UNRUN. env output itself makes no cwd claim.
    }
}

#[test]
fn ptrace_counter2_captured_environment_controls() {
    counter2_captured_environment_controls("ptrace");
}

#[test]
fn dbt_counter2_captured_environment_controls() {
    counter2_captured_environment_controls("dbt");
}

#[test]
fn exact_chaos_tool_limits_reads_after_skip() {
    let output = run(
        "chaos",
        &["--skip", "32", "--no-interrupt"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-read",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("read("), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

#[test]
fn exact_chaos_skip_suppresses_intervention_before_boundary() {
    let output = run(
        "chaos",
        &["--skip", "18446744073709551615", "--no-interrupt"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-full-read",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-four\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("SKIPPED"), "{stderr}");
    assert!(!stderr.contains(" = -512"), "{stderr}");
}

#[test]
fn exact_chaos_tool_interrupts_then_limits_retry() {
    let output = run(
        "chaos",
        &["--skip", "32"],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "exercise-chaos-interrupt",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-interrupt-then-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" = -4"), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

#[test]
fn chaos_options_require_the_chaos_tool() {
    for skip in ["0", "1"] {
        let output = run("noop", &["--skip", skip], &["/bin/true"]);
        assert!(!output.status.success(), "skip={skip}: {output:?}");
        assert!(output.stdout.is_empty(), "skip={skip}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("chaos options are only valid with --tool chaos"),
            "skip={skip}: {stderr}"
        );
    }
}

#[test]
fn exact_chunky_print_delays_buffered_write_behind_later_alias_write() {
    let output = run(
        "chunky-print",
        &[],
        &[
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "chunky-alias-order",
        ],
    );

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.len(), 16 * 8, "{stdout}");
    let mut observed_buffering = false;
    for index in 0..16 {
        let buffered = format!("B{index:02};");
        let pass_through = format!("P{index:02};");
        assert_eq!(stdout.matches(&buffered).count(), 1, "{stdout}");
        assert_eq!(stdout.matches(&pass_through).count(), 1, "{stdout}");
        let buffered_at = stdout.find(&buffered).unwrap();
        let pass_through_at = stdout.find(&pass_through).unwrap();
        observed_buffering |= pass_through_at < buffered_at;
    }
    assert!(observed_buffering, "output was pure pass-through: {stdout}");
}

fn assert_chunky_print_guest_bytes(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(stdout.len(), 16 * 8, "{stdout}");
    for index in 0..16 {
        for kind in ['B', 'P'] {
            let token = format!("{kind}{index:02};");
            assert_eq!(stdout.matches(&token).count(), 1, "{stdout}");
        }
    }
}

fn assert_chunky_print_buffering(output: Output) -> String {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.len(), 16 * 8, "{stdout}");
    let mut observed_buffering = false;
    for index in 0..16 {
        let buffered = format!("B{index:02};");
        let pass_through = format!("P{index:02};");
        assert_eq!(stdout.matches(&buffered).count(), 1, "{stdout}");
        assert_eq!(stdout.matches(&pass_through).count(), 1, "{stdout}");
        let buffered_at = stdout.find(&buffered).unwrap();
        let pass_through_at = stdout.find(&pass_through).unwrap();
        observed_buffering |= pass_through_at < buffered_at;
    }
    assert!(observed_buffering, "output was pure pass-through: {stdout}");
    stdout
}

fn assert_chunky_print_causal_order(stdout: &str) {
    for index in 0..15 {
        let pass_through = format!("P{index:02};");
        let later_buffered = format!("B{:02};", index + 1);
        // This alias write completes before the guest can issue the next
        // buffered write, regardless of which syscall closes an epoch.
        assert!(
            stdout.find(&pass_through).unwrap() < stdout.find(&later_buffered).unwrap(),
            "completed alias write {pass_through} followed later {later_buffered}: {stdout}"
        );
    }
}

fn chunky_print_preserves_buffering_and_causal_order(backend: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chunky_print"));
    command
        .args(["--backend", backend, "--preload"])
        .arg(preload())
        .arg("--")
        .args([
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "chunky-alias-order",
        ]);
    let output = output_with_timeout(&mut command);
    eprintln!("{backend} ChunkyPrint child: {output:?}");
    assert_chunky_print_guest_bytes(&output);
    let stdout = assert_chunky_print_buffering(output);
    assert_chunky_print_causal_order(&stdout);
}

#[test]
fn ptrace_chunky_print_preserves_buffering_and_causal_order() {
    chunky_print_preserves_buffering_and_causal_order("ptrace");
}

#[test]
fn dbt_chunky_print_preserves_buffering_and_causal_order() {
    chunky_print_preserves_buffering_and_causal_order("dbt");
}

#[test]
fn dbt_chunky_print_oracle_requires_actual_tool() {
    let noop = Path::new(env!("CARGO_BIN_EXE_chunky_print"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/basics-noop/manifest.json");
    reverie_dbt::CallerArtifact::load(&noop).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_chunky_print"));
    command
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--dbt-artifact")
        .arg(noop)
        .arg("--")
        .args([
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "chunky-alias-order",
        ]);
    let output = output_with_timeout(&mut command);
    eprintln!("ChunkyPrint Noop child: {output:?}");
    // A successful real Noop guest with every token is required before the
    // unchanged buffering oracle's rejection can demonstrate sensitivity.
    assert_chunky_print_guest_bytes(&output);
    assert!(std::panic::catch_unwind(|| assert_chunky_print_buffering(output)).is_err());
}

#[test]
fn dbt_chunky_print_missing_artifact_refuses() {
    let default = Path::new(env!("CARGO_BIN_EXE_chunky_print"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/chunky-print/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_chunky_print"));
    command
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--dbt-artifact")
        .arg(&missing)
        .arg("--")
        .args([
            env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"),
            "chunky-alias-order",
        ]);
    let output = output_with_timeout(&mut command);
    eprintln!("ChunkyPrint missing-artifact child: {output:?}");
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot load DBT caller artifact"),
        "{stderr}"
    );
    assert!(stderr.contains(missing.to_str().unwrap()), "{stderr}");
}

#[test]
fn chrome_trace_output_requires_the_chrome_trace_tool() {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-liteinst-invalid-chrome-trace-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let output = run(
        "noop",
        &["--out", trace_path.to_str().unwrap()],
        &["/bin/true"],
    );

    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--out is only valid with --tool chrome-trace"),
        "{stderr}"
    );
    assert!(!trace_path.exists(), "unexpected artifact: {trace_path:?}");
}

#[test]
fn exact_chrome_trace_tool_writes_process_and_syscall_events() {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-liteinst-chrome-trace-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let output = run(
        "chrome-trace",
        &["--out", trace_path.to_str().unwrap()],
        &["/bin/echo", "hello"],
    );

    assert_chrome_trace_guest_output(&output);

    let trace = std::fs::read(&trace_path).unwrap();
    std::fs::remove_file(&trace_path).unwrap();
    let trace: serde_json::Value = serde_json::from_slice(&trace).unwrap();
    assert_chrome_trace_events(&trace);
}

fn assert_chrome_trace_guest_output(output: &Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

fn assert_chrome_trace_events(trace: &serde_json::Value) {
    let events = trace
        .as_array()
        .expect("chrome trace is not an event array");
    assert!(
        events
            .iter()
            .any(|event| event["cat"] == "process" && event["ph"] == "B"),
        "{trace}"
    );
    assert!(
        events.iter().any(|event| {
            event["cat"] == "syscall"
                && event["name"] == "write"
                && event["args"]["pretty"]
                    .as_str()
                    .is_some_and(|pretty| pretty.starts_with("write(1,"))
                && event["args"]["result"] == "Ok(6)"
        }),
        "{trace}"
    );
}

fn chrome_trace_command(backend: &str, trace_path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chrome_trace"));
    command
        .arg("--backend")
        .arg(backend)
        .arg("--preload")
        .arg(preload())
        .arg("--out")
        .arg(trace_path);
    command
}

fn chrome_trace_writes_process_and_syscall_events(backend: &str, identity: &str) {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-chrome-trace-{identity}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let mut command = chrome_trace_command(backend, &trace_path);
    command.args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);

    assert_chrome_trace_guest_output(&output);
    let trace = std::fs::read(&trace_path).unwrap();
    let trace: serde_json::Value = serde_json::from_slice(&trace).unwrap();
    assert_chrome_trace_events(&trace);
    // Keep the identity-owned trace on failure for diagnosis.
    std::fs::remove_file(&trace_path).unwrap();
}

#[test]
fn ptrace_chrome_trace_tool_writes_process_and_syscall_events() {
    chrome_trace_writes_process_and_syscall_events(
        "ptrace",
        "ptrace_chrome_trace_tool_writes_process_and_syscall_events",
    );
}

#[test]
fn dbt_chrome_trace_tool_writes_process_and_syscall_events() {
    chrome_trace_writes_process_and_syscall_events(
        "dbt",
        "dbt_chrome_trace_tool_writes_process_and_syscall_events",
    );
}

fn chrome_trace_preserves_stdin_and_writes_events(backend: &str, identity: &str) {
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-chrome-trace-{identity}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    // The standard pipe descriptors are close-on-exec. Close the writer before
    // spawning so the guest sees EOF after exactly these six bytes.
    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(b"hello\n").unwrap();
    drop(writer);
    let mut command = chrome_trace_command(backend, &trace_path);
    command.stdin(reader).args(["--", "/bin/cat"]);
    let output = output_with_timeout(&mut command);
    eprintln!("Chrome trace cat output: {output:?}");

    assert_chrome_trace_guest_output(&output);
    let trace = std::fs::read(&trace_path).unwrap();
    let trace: serde_json::Value = serde_json::from_slice(&trace).unwrap();
    assert_chrome_trace_events(&trace);
    // Keep the identity-owned trace on failure for diagnosis.
    std::fs::remove_file(&trace_path).unwrap();
}

#[test]
fn ptrace_chrome_trace_preserves_stdin_and_writes_events() {
    chrome_trace_preserves_stdin_and_writes_events(
        "ptrace",
        "ptrace_chrome_trace_preserves_stdin_and_writes_events",
    );
}

#[test]
fn dbt_chrome_trace_preserves_stdin_and_writes_events() {
    chrome_trace_preserves_stdin_and_writes_events(
        "dbt",
        "dbt_chrome_trace_preserves_stdin_and_writes_events",
    );
}

#[test]
fn dbt_chrome_trace_oracle_requires_actual_tool() {
    let noop = Path::new(env!("CARGO_BIN_EXE_chrome_trace"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/basics-noop/manifest.json");
    reverie_dbt::CallerArtifact::load(&noop).unwrap();
    let trace_path = std::env::temp_dir().join(format!(
        "reverie-chrome-trace-dbt_chrome_trace_oracle_requires_actual_tool-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let mut command = chrome_trace_command("dbt", &trace_path);
    command
        .arg("--dbt-artifact")
        .arg(noop)
        .args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);
    eprintln!("Chrome trace Noop output: {output:?}");
    // The real Noop Tool must run the guest successfully before it can expose
    // the event oracle's sensitivity. A caller setup refusal is not evidence.
    assert_chrome_trace_guest_output(&output);
    let trace = std::fs::read(&trace_path).unwrap();
    let trace: serde_json::Value = serde_json::from_slice(&trace).unwrap();
    eprintln!("Chrome trace Noop events: {trace}");
    assert!(trace.as_array().unwrap().is_empty(), "{trace}");
    assert!(std::panic::catch_unwind(|| assert_chrome_trace_events(&trace)).is_err());
    std::fs::remove_file(&trace_path).unwrap();
}

#[test]
fn dbt_chrome_trace_missing_artifact_refuses() {
    let default = Path::new(env!("CARGO_BIN_EXE_chrome_trace"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/chrome-trace/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.json");
    let trace_path = directory.path().join(format!(
        "dbt_chrome_trace_missing_artifact_refuses-{}.json",
        std::process::id()
    ));
    let mut command = chrome_trace_command("dbt", &trace_path);
    command
        .arg("--dbt-artifact")
        .arg(&missing)
        .args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);
    eprintln!("Chrome trace missing-artifact output: {output:?}");
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot load DBT caller artifact"),
        "{stderr}"
    );
    assert!(stderr.contains(missing.to_str().unwrap()), "{stderr}");
    assert!(!trace_path.exists(), "unexpected artifact: {trace_path:?}");
}

#[test]
fn exact_strace_tool_observes_filtered_write() {
    let output = run("strace", &["--trace", "write"], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = 6"), "{stderr}");
}

fn run_dbt_strace(extra: &[&str], guest: &[&str]) -> Output {
    run_strace("dbt", extra, guest)
}

fn run_strace(backend: &str, extra: &[&str], guest: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strace"));
    command
        .arg("--backend")
        .arg(backend)
        .args(extra)
        .arg("--")
        .args(guest);
    output_with_timeout(&mut command)
}

#[test]
fn dbt_exact_strace_tool_observes_filtered_write() {
    let output = run_dbt_strace(&["--trace", "write"], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = 6"), "{stderr}");
}

#[test]
fn dbt_strace_reports_exit_after_echo_closes_stdio() {
    strace_reports_exit_after_echo_closes_stdio("dbt");
}

#[test]
fn ptrace_strace_reports_exit_after_echo_closes_stdio() {
    strace_reports_exit_after_echo_closes_stdio("ptrace");
}

fn strace_reports_exit_after_echo_closes_stdio(backend: &str) {
    // GNU echo closes stdout and stderr before exit. Keep the original write
    // oracle above unchanged, and also require the consuming Tool diagnostics
    // to survive those application descriptor closes through controller RPC.
    let output = run_strace(backend, &["--trace", "write"], &["/bin/echo", "hello"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let lines: Vec<_> = stderr.lines().collect();
    let write = lines
        .iter()
        .position(|line| line.contains("write(1,") && line.ends_with(" = 6"))
        .expect("missing completed write diagnostic");
    let threads: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("Thread "))
        .collect();
    let processes: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("Process "))
        .collect();
    assert_eq!(threads.len(), 1, "{stderr}");
    assert_eq!(processes.len(), 1, "{stderr}");
    assert!(
        threads[0].1.ends_with(" exited with status Exited(0)"),
        "{stderr}"
    );
    assert!(
        processes[0].1.ends_with(" exited with status Exited(0)"),
        "{stderr}"
    );
    assert!(
        write < threads[0].0 && threads[0].0 < processes[0].0,
        "{stderr}"
    );
}

#[test]
fn exact_strace_minimal_tool_observes_write() {
    let output = run("strace-minimal", &[], &["/bin/echo", "hello"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = ?"), "{stderr}");
}

fn assert_strace_minimal_write(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = ?"), "{stderr}");
}

fn strace_minimal_tool_observes_write(backend: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_strace_minimal"));
    command
        .args(["--backend", backend, "--preload"])
        .arg(preload())
        .args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);
    eprintln!("strace-minimal {backend} child output: {output:?}");

    assert_strace_minimal_write(output);
}

#[test]
fn ptrace_strace_minimal_tool_observes_write() {
    strace_minimal_tool_observes_write("ptrace");
}

#[test]
fn dbt_strace_minimal_tool_observes_write() {
    strace_minimal_tool_observes_write("dbt");
}

#[test]
fn dbt_strace_minimal_oracle_requires_actual_tool() {
    let noop = Path::new(env!("CARGO_BIN_EXE_strace_minimal"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/basics-noop/manifest.json");
    reverie_dbt::CallerArtifact::load(&noop).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_strace_minimal"));
    command
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--dbt-artifact")
        .arg(noop)
        .args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);
    eprintln!("strace-minimal Noop child output: {output:?}");
    // Successful execution of the real Noop guest is required before missing
    // diagnostics can demonstrate the unchanged full oracle's sensitivity.
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hello\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(std::panic::catch_unwind(|| assert_strace_minimal_write(output)).is_err());
}

#[test]
fn dbt_strace_minimal_missing_artifact_refuses() {
    let default = Path::new(env!("CARGO_BIN_EXE_strace_minimal"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/strace-minimal/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_strace_minimal"));
    command
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--dbt-artifact")
        .arg(&missing)
        .args(["--", "/bin/echo", "hello"]);
    let output = output_with_timeout(&mut command);
    eprintln!("strace-minimal missing-artifact child output: {output:?}");
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot load DBT caller artifact"),
        "{stderr}"
    );
    assert!(stderr.contains(missing.to_str().unwrap()), "{stderr}");
    assert!(
        stderr.contains("run reverie-dbt/scripts/build-client.sh --caller-manifest reverie-examples/strace-minimal-dbt-runtime/Cargo.toml"),
        "{stderr}"
    );
}

#[test]
fn debug_port_requires_debug_selector() {
    let output = run("noop", &["--port", "0"], &["/bin/true"]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--port is only valid with --tool debug"),
        "{stderr}"
    );
}

#[test]
fn exact_strace_tool_observes_thread_and_process_exit() {
    let output = run("strace", &["--trace", "write"], &["/bin/true"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Thread "), "{stderr}");
    assert!(stderr.contains("Process "), "{stderr}");
    assert_eq!(stderr.matches("exited with status Exited(0)").count(), 2);
}

#[test]
fn dbt_exact_strace_tool_observes_thread_and_process_exit() {
    let output = run_dbt_strace(&["--trace", "write"], &["/bin/true"]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Thread "), "{stderr}");
    assert!(stderr.contains("Process "), "{stderr}");
    assert_eq!(stderr.matches("exited with status Exited(0)").count(), 2);
}

#[test]
fn dbt_strace_bad_override_never_uses_the_valid_default_pair() {
    // Require the real production prerequisite: a failed fallback to another
    // absent artifact would not establish this negative control.
    let default = Path::new(env!("CARGO_BIN_EXE_strace"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/strace/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let malformed = directory.path().join("malformed.json");
    std::fs::write(&malformed, b"{}").unwrap();
    let mut valid: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&default).unwrap()).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let inputs = valid["inputs"].as_array().unwrap();
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "reverie-examples/strace/config.rs",
        "reverie-examples/strace/filter.rs",
        "reverie-examples/strace/global_state.rs",
        "reverie-examples/strace/tool.rs",
        "reverie-examples/strace-dbt-runtime/Cargo.toml",
        "reverie-examples/strace-dbt-runtime/Cargo.lock",
        "reverie-examples/strace-dbt-runtime/build.rs",
        "reverie-examples/strace-dbt-runtime/src/lib.rs",
        "reverie-dbt/build.rs",
        "reverie-dbt/native/client.c",
        "reverie-dbt/native/CMakeLists.txt",
        "reverie-dbt/scripts/build-client.sh",
        "reverie-dbt/scripts/build-caller.rs",
    ] {
        let required = workspace.join(relative).canonicalize().unwrap();
        assert!(
            inputs
                .iter()
                .any(|input| { Path::new(input["path"].as_str().unwrap()) == required }),
            "missing declared input {relative}"
        );
    }
    for marker in [
        ".reverie-dbt-install.provenance",
        ".reverie-dbt-install.sha256",
    ] {
        assert!(
            inputs
                .iter()
                .any(|input| { Path::new(input["path"].as_str().unwrap()).ends_with(marker) }),
            "missing SDK input {marker}"
        );
    }
    for image in ["runtime", "client"] {
        valid[image]["path"] = serde_json::json!(
            default
                .parent()
                .unwrap()
                .join(valid[image]["path"].as_str().unwrap())
        );
    }
    let copied = directory.path().join("valid.json");
    std::fs::write(&copied, serde_json::to_vec(&valid).unwrap()).unwrap();
    reverie_dbt::CallerArtifact::load(&copied).unwrap();
    let mut bad_paths = vec![directory.path().join("absent.json"), malformed];
    for (label, pointer) in [
        ("stale-runtime", "/runtime/sha256"),
        ("stale-client", "/client/sha256"),
        ("stale-source", "/inputs/0/sha256"),
    ] {
        let mut stale = valid.clone();
        let digest = stale.pointer_mut(pointer).unwrap();
        let mut changed = digest.as_str().unwrap().as_bytes().to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        *digest = serde_json::Value::String(String::from_utf8(changed).unwrap());
        let path = directory.path().join(format!("{label}.json"));
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        bad_paths.push(path);
    }
    for path in bad_paths {
        for via_environment in [false, true] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_strace"));
            command.args(["--backend", "dbt"]);
            if via_environment {
                command.env("REVERIE_DBT_CALLER_ARTIFACT", &path);
            } else {
                command.arg("--dbt-artifact").arg(&path);
            }
            command.args(["--trace", "write", "--", "/bin/echo", "hello"]);
            let output = output_with_timeout(&mut command);
            assert!(!output.status.success(), "{output:?}");
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(!output.stderr.is_empty(), "{output:?}");
        }
    }
}

fn run_public_chaos(backend: &str, extra: &[&str], mode: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chaos"));
    command
        .args(["--backend", backend, "--preload"])
        .arg(preload())
        .args(extra)
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg(mode);
    let output = output_with_timeout(&mut command);
    eprintln!(
        "chaos {backend} {mode} child status: {:?}; stdout bytes: {:?}; stderr bytes: {:?}",
        output.status, output.stdout, output.stderr
    );
    output
}

fn assert_chaos_limits_reads_after_skip(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("read("), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

fn assert_chaos_skip_suppresses_intervention(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-four\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("SKIPPED"), "{stderr}");
    assert!(!stderr.contains(" = -512"), "{stderr}");
}

fn assert_chaos_interrupts_then_limits_retry(output: Output) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-interrupt-then-one\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(" = -4"), "{stderr}");
    assert!(stderr.contains(", 1) = 1"), "{stderr}");
}

fn chaos_tool_limits_reads_after_skip(backend: &str) {
    let output = run_public_chaos(
        backend,
        &["--skip", "32", "--no-interrupt"],
        "exercise-chaos-read",
    );
    assert_chaos_limits_reads_after_skip(output);
}

fn chaos_skip_suppresses_intervention_before_boundary(backend: &str) {
    let output = run_public_chaos(
        backend,
        &["--skip", "18446744073709551615", "--no-interrupt"],
        "exercise-chaos-full-read",
    );
    assert_chaos_skip_suppresses_intervention(output);
}

fn chaos_raw_interrupt_guest() -> PathBuf {
    const SOURCE: &str = include_str!("fixtures/chaos-raw-interrupt.S");
    static GUEST: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let directory = GUEST.get_or_init(|| {
        let checked_source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chaos-raw-interrupt.S");
        assert_eq!(std::fs::read_to_string(checked_source).unwrap(), SOURCE);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(root).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("chaos-raw-interrupt-")
            .tempdir_in(root)
            .unwrap();
        let source = directory.path().join("guest.S");
        std::fs::write(&source, SOURCE).unwrap();
        // Follow caller_lifecycle_live's native fixture: compilation precedes
        // the guest's ten-second bound, within the enclosing test deadline.
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let mut command = Command::new(compiler);
        command
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(directory.path().join("guest"))
            .arg(&source);
        eprintln!(
            "chaos raw compiler: {command:?}; source bytes: {:?}",
            SOURCE.as_bytes()
        );
        let output = command.output().unwrap();
        eprintln!("chaos raw compiler output: {output:?}");
        assert!(output.status.success(), "guest compiler failed: {output:?}");
        directory
    });
    directory.path().join("guest")
}

fn chaos_raw_interrupts_then_limits_retry(backend: &str) {
    let guest = chaos_raw_interrupt_guest();
    // Retain the exact compiled image, not just the checked-in assembly. The
    // evidence reader can hash these bytes even after the temporary path goes.
    let image = std::fs::read(&guest).unwrap();
    eprintln!("chaos raw guest path: {guest:?}; image bytes: {image:?}");
    let mut command = Command::new(env!("CARGO_BIN_EXE_chaos"));
    command
        .args(["--backend", backend, "--preload"])
        .arg(preload())
        .args(["--skip", "32", "--"])
        .arg(&guest);
    let output = output_with_timeout(&mut command);
    eprintln!(
        "chaos {backend} raw-interrupt child status: {:?}; stdout bytes: {:?}; stderr bytes: {:?}",
        output.status, output.stdout, output.stderr
    );
    assert_eq!(std::fs::read(&guest).unwrap(), image, "guest image changed");
    assert_chaos_interrupts_then_limits_retry(output);
}

#[test]
fn ptrace_chaos_tool_limits_reads_after_skip() {
    chaos_tool_limits_reads_after_skip("ptrace");
}

#[test]
fn dbt_chaos_tool_limits_reads_after_skip() {
    chaos_tool_limits_reads_after_skip("dbt");
}

#[test]
fn ptrace_chaos_skip_suppresses_intervention_before_boundary() {
    chaos_skip_suppresses_intervention_before_boundary("ptrace");
}

#[test]
fn dbt_chaos_skip_suppresses_intervention_before_boundary() {
    chaos_skip_suppresses_intervention_before_boundary("dbt");
}

#[test]
fn ptrace_chaos_raw_interrupts_then_limits_retry() {
    chaos_raw_interrupts_then_limits_retry("ptrace");
}

#[test]
fn dbt_chaos_raw_interrupts_then_limits_retry() {
    chaos_raw_interrupts_then_limits_retry("dbt");
}

#[test]
fn dbt_chaos_skip_oracle_requires_skip_configuration() {
    let output = run_public_chaos(
        "dbt",
        &["--skip", "0", "--no-read", "--no-interrupt"],
        "exercise-chaos-full-read",
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"chaos-read-four\n");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(stderr.contains("read("), "{stderr}");
    assert!(stderr.contains(", 4) = 4"), "{stderr}");
    assert!(!stderr.contains("SKIPPED"), "{stderr}");
    assert!(!stderr.contains(" = -512"), "{stderr}");
    // Every other predicate of the same full positive oracle already holds.
    assert!(
        std::panic::catch_unwind(|| assert_chaos_skip_suppresses_intervention(output)).is_err()
    );
}

#[test]
fn dbt_chaos_missing_artifact_refuses() {
    let default = Path::new(env!("CARGO_BIN_EXE_chaos"))
        .parent()
        .unwrap()
        .join("reverie-dbt-callers/chaos/manifest.json");
    reverie_dbt::CallerArtifact::load(&default).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_chaos"));
    command
        .args(["--backend", "dbt", "--preload"])
        .arg(preload())
        .arg("--dbt-artifact")
        .arg(&missing)
        .args(["--skip", "32", "--no-interrupt", "--"])
        .arg(env!("CARGO_BIN_EXE_reverie-liteinst-env-guest"))
        .arg("exercise-chaos-read");
    let output = output_with_timeout(&mut command);
    eprintln!(
        "chaos missing-artifact child status: {:?}; stdout bytes: {:?}; stderr bytes: {:?}",
        output.status, output.stdout, output.stderr
    );
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("cannot load DBT caller artifact"),
        "{stderr}"
    );
    assert!(stderr.contains(missing.to_str().unwrap()), "{stderr}");
    assert!(
        stderr.contains("run reverie-dbt/scripts/build-client.sh --caller-manifest reverie-examples/chaos-dbt-runtime/Cargo.toml"),
        "{stderr}"
    );
}
