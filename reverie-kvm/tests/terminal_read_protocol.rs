/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! One default Cargo case runs the complete native C aggregate, without KVM or
//! Rust FFI. The embedded inputs cannot drift after Cargo builds this test.
//! Complete equal exported attribute bytes are compared independently of LSM
//! inventory spelling; only `capability,bpf,ima` authorizes paired READ-EINVAL.
//! Readable, valid, stable securityfs inventory remains mandatory. The native
//! diagnostic explicitly selects the non-PIE x86-64 ABI; unsupported PLT layouts
//! still fail. Independent ELF association remains an external qualification.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::fs::{self};
use std::io::Write;
use std::io::{self};
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

const HELPER: &[u8] = include_bytes!("../src/terminal_read.c");
const HEADER: &[u8] = include_bytes!("../src/terminal_read.h");
const PROTOCOL: &[u8] = include_bytes!("terminal_read_protocol.c");
const STREAM_CAP: usize = 2 * 1024 * 1024;
const WALL_LIMIT: Duration = Duration::from_secs(30);
// The payload is killed at its deadline. Retirement has its own finite grace;
// failure to prove retirement fails the test and retains its private directory.
const RETIRE_LIMIT: Duration = Duration::from_secs(5);
const C_FLAGS: &[&str] = &[
    "-DRVK_READ_TEST",
    "-std=c11",
    "-pthread",
    "-fexceptions",
    "-fno-pie",
    "-no-pie",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-UNDEBUG",
];
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct PrivateTree {
    path: PathBuf,
    retain: Arc<AtomicBool>,
}

impl PrivateTree {
    fn new() -> io::Result<Self> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for _ in 0..32 {
            let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "reverie-terminal-read-{}-{stamp}-{serial}",
                std::process::id()
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        retain: Arc::new(AtomicBool::new(false)),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "could not exclusively create protocol temporary directory",
        ))
    }

    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path.join(name))?;
        file.write_all(bytes)
    }

    fn remove(&mut self) -> io::Result<()> {
        if self.retain.load(Ordering::Relaxed) {
            return Err(io::Error::other(format!(
                "owned group retirement unproved; retained {}",
                self.path.display()
            )));
        }
        if !self.path.as_os_str().is_empty() {
            fs::remove_dir_all(&self.path)?;
            self.path.clear();
        }
        Ok(())
    }
}

impl Drop for PrivateTree {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            let _ = writeln!(
                io::stderr(),
                "protocol temporary-directory cleanup: {error}"
            );
        }
    }
}

// This integration-test executable contains exactly one test. Subreaping is
// confined to it and restored on every return/unwind; we never wait for an
// unrelated child. It makes the deliberately forked native children observable
// even when their immediate parent dies during a wrapper failure.
struct Subreaper {
    saved: libc::c_int,
    restored: bool,
}

impl Subreaper {
    fn new() -> io::Result<Self> {
        let mut old = 0;
        // SAFETY: old is writable; these prctl operations take the documented
        // scalar/pointer arguments and affect only this test process.
        unsafe {
            if libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut old) != 0
                || libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            saved: old,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.restored {
            // SAFETY: restore this process's saved scalar prctl setting.
            if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.saved) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for Subreaper {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            let _ = writeln!(
                io::stderr(),
                "restore child subreaper during unwind: {error}"
            );
        }
    }
}

struct Capture {
    fd: Option<OwnedFd>,
    nonblocking: bool,
    bytes: Vec<u8>,
    overflow: bool,
}

impl Capture {
    fn new(fd: Option<OwnedFd>) -> Self {
        Self {
            fd,
            nonblocking: false,
            bytes: Vec::new(),
            overflow: false,
        }
    }

    fn configure(&mut self) -> io::Result<()> {
        let fd = self
            .fd
            .as_ref()
            .ok_or_else(|| io::Error::other("missing child pipe"))?
            .as_raw_fd();
        // SAFETY: fd remains owned by this capture. Preserve its existing flags.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.nonblocking = true;
        Ok(())
    }

    fn drain(&mut self) -> io::Result<()> {
        if !self.nonblocking {
            return Ok(());
        }
        let Some(fd) = self.fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return Ok(());
        };
        // Limit work per stream per iteration so a writer cannot starve the
        // other pipe, wait observation, or deadline check.
        for _ in 0..16 {
            let mut buffer = [0_u8; 8192];
            // SAFETY: buffer is writable and fd is an owned nonblocking pipe.
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count == 0 {
                self.fd.take();
                break;
            }
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    break;
                }
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let count = count as usize;
            let retained = count.min(STREAM_CAP - self.bytes.len());
            self.bytes.extend_from_slice(&buffer[..retained]);
            if retained != count && !self.overflow {
                self.overflow = true;
                return Err(io::Error::other(
                    "child stream exceeded 2 MiB; transcript is incomplete",
                ));
            }
        }
        Ok(())
    }
}

struct StageOwner {
    child: Option<Child>,
    pid: libc::pid_t,
    stdout: Capture,
    stderr: Capture,
    retain: Arc<AtomicBool>,
    status: Option<ExitStatus>,
    descendants: Vec<(libc::pid_t, u64, libc::c_int)>,
    retired: bool,
    signaling_allowed: bool,
    cleanup_returned: bool,
}

fn process_start(pid: libc::pid_t) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(')')
        .ok_or_else(|| io::Error::other("malformed process stat"))?
        .1;
    let start: u64 = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("missing process start time"))?
        .parse()
        .map_err(io::Error::other)?;
    if start == 0 {
        return Err(io::Error::other("zero process start time"));
    }
    Ok(start)
}

impl StageOwner {
    fn spawn(command: &mut Command, tree: &PrivateTree) -> io::Result<Self> {
        command
            .current_dir(&tree.path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("TMPDIR", tree.path.join("tmp"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the post-fork closure uses only async-signal-safe syscalls and
        // constructs an errno error on failure. No allocation/locks are used.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for (resource, limit) in [
                    (libc::RLIMIT_CPU, 30),
                    (libc::RLIMIT_AS, 1024 * 1024 * 1024),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let limits = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &limits) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let pid = child.id() as libc::pid_t;
        let stdout = Capture::new(child.stdout.take().map(Into::into));
        let stderr = Capture::new(child.stderr.take().map(Into::into));
        Ok(Self {
            child: Some(child),
            pid,
            stdout,
            stderr,
            retain: tree.retain.clone(),
            status: None,
            descendants: Vec::new(),
            retired: false,
            signaling_allowed: true,
            cleanup_returned: false,
        })
    }

    fn exited_without_reaping(&self) -> io::Result<bool> {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: info is initialized/writable. WNOWAIT is essential: retaining
        // this exact child prevents PID/PGID reuse until all signaling ends.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid succeeded and info was zero initialized for WNOHANG.
        Ok(unsafe { info.assume_init().si_pid() } != 0)
    }

    fn drain(&mut self) -> io::Result<()> {
        let left = self.stdout.drain();
        let right = self.stderr.drain();
        left.and(right)
    }

    fn poll_pipes(&self) -> io::Result<()> {
        let mut descriptors = [libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        }; 2];
        for (descriptor, capture) in descriptors.iter_mut().zip([&self.stdout, &self.stderr]) {
            if let Some(fd) = &capture.fd {
                descriptor.fd = fd.as_raw_fd();
            }
        }
        // One nonblocking poll loop drains both streams; no reader thread can
        // remain stuck on a pipe held open by a grandchild.
        // SAFETY: descriptors is a writable array of the stated size.
        if unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, 10) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }

    fn retire(&mut self) -> Vec<String> {
        if self.retired {
            return Vec::new();
        }
        let mut errors = Vec::new();
        if !self.signaling_allowed {
            self.retain.store(true, Ordering::Relaxed);
            self.cleanup_returned = true;
            return vec![
                "leader ownership was relinquished; refusing numeric PID/PGID signaling".into(),
            ];
        }
        let deadline = Instant::now() + RETIRE_LIMIT;
        let authenticated = match self.exited_without_reaping() {
            Ok(_) => true,
            Err(error) => {
                errors.push(format!(
                    "authenticate unreaped leader {}: {error}",
                    self.pid
                ));
                false
            }
        };
        if authenticated {
            // SAFETY: the unreaped leader still reserves this PGID. This is the
            // one group signal; irrevocably disarm before consuming ANY status.
            let result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
            self.signaling_allowed = false;
            if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                errors.push(format!(
                    "kill owned group {}: {}",
                    self.pid,
                    io::Error::last_os_error()
                ));
            }
        } else {
            self.signaling_allowed = false;
        }
        // /proc/TID/children is optional (CONFIG_PROC_CHILDREN). Kernel waits
        // include adopted children across our threads; __WALL also includes
        // non-SIGCHLD clone children. No task scan or waitpid(-1) is needed.
        // The leader may be reaped first now that all signaling is disarmed.
        // With trusted group-preserving descendants, every remaining subtree
        // has a direct child here: reparenting precedes exit notification.
        // Thus only ECHILD, after the leader is consumed, proves retirement.
        // Stages are sequential; unrelated external PGID reuse is not waitable.
        if authenticated {
            loop {
                if Instant::now() >= deadline {
                    errors.push("owned group retirement exceeded 5s grace".into());
                    break;
                }
                let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                // SAFETY: initialized output; WNOWAIT pins each returned child for
                // generation observation before its exact-PID consuming wait.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PGID,
                        self.pid as libc::id_t,
                        info.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                    )
                };
                if result != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ECHILD) && self.status.is_some() {
                        self.retired = true;
                    } else {
                        errors.push(format!(
                            "wait owned group {} (leader consumed={}): {error}",
                            self.pid,
                            self.status.is_some()
                        ));
                    }
                    break;
                }
                // SAFETY: successful waitid initialized this zeroed siginfo.
                let pid = unsafe { info.assume_init().si_pid() };
                if pid == self.pid {
                    if self.status.is_some() {
                        errors.push("owned leader was reported twice".into());
                        break;
                    }
                    match self.child.as_mut().unwrap().wait() {
                        Ok(status) => self.status = Some(status),
                        Err(error) => {
                            errors.push(format!("reap owned leader: {error}"));
                            break;
                        }
                    }
                } else if pid != 0 {
                    // SAFETY: query the still-unreaped child returned by P_PGID.
                    if unsafe { libc::getpgid(pid) } != self.pid {
                        errors.push(format!(
                            "waitable child {pid} no longer identifies owned group {}",
                            self.pid
                        ));
                        break;
                    }
                    let start = match process_start(pid) {
                        Ok(start) => start,
                        Err(error) => {
                            errors.push(format!("identify owned descendant {pid}: {error}"));
                            break;
                        }
                    };
                    let mut status = 0;
                    // SAFETY: consume only this exact waitable owned child, using
                    // the same clone-child accounting as the observing group wait.
                    let reaped =
                        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
                    if reaped != pid {
                        errors.push(format!(
                            "reap owned descendant {pid}: result={reaped} error={}",
                            io::Error::last_os_error()
                        ));
                        break;
                    }
                    self.descendants.push((pid, start, status));
                }
                if let Err(error) = self.drain() {
                    errors.push(format!("retirement stream read: {error}"));
                }
                if Instant::now() >= deadline {
                    errors.push("owned group retirement exceeded 5s grace".into());
                    break;
                }
                if let Err(error) = self.poll_pipes() {
                    errors.push(format!("retirement poll: {error}"));
                    break;
                }
            }
        }
        if self.retired {
            // A failed nonblocking setup already failed the stage. Closing an
            // unconfigured read end is safe now that every writer has retired.
            for capture in [&mut self.stdout, &mut self.stderr] {
                if !capture.nonblocking {
                    capture.fd.take();
                }
            }
            while self.stdout.fd.is_some() || self.stderr.fd.is_some() {
                if let Err(error) = self.drain() {
                    errors.push(format!("final stream read: {error}"));
                }
                if Instant::now() >= deadline {
                    errors.push("pipe EOF missing after owned group retirement".into());
                    break;
                }
                if let Err(error) = self.poll_pipes() {
                    errors.push(format!("final stream poll: {error}"));
                    break;
                }
            }
        }
        if Instant::now() >= deadline
            && !errors
                .iter()
                .any(|error| error == "owned group retirement exceeded 5s grace")
        {
            errors.push("owned group retirement exceeded 5s grace".into());
        }
        if !self.retired || !errors.is_empty() {
            // Preserve evidence when ownership, pipe EOF, or cleanup cannot be
            // proved. The primary monitor failure remains in StageReport.
            self.retain.store(true, Ordering::Relaxed);
        }
        self.cleanup_returned = true;
        errors
    }
}

impl Drop for StageOwner {
    fn drop(&mut self) {
        // An explicit failed retirement already used its bounded grace and
        // retained the evidence. Unexpected unwind still gets one attempt.
        if !self.retired && !self.cleanup_returned {
            for error in self.retire() {
                let _ = writeln!(io::stderr(), "protocol stage unwind cleanup: {error}");
            }
        }
    }
}

#[derive(Clone)]
struct StageReport {
    name: &'static str,
    leader: libc::pid_t,
    invocation: String,
    status: Option<ExitStatus>,
    primary: Option<String>,
    cleanup: Vec<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    retired: bool,
    descendants: usize,
    reaped_descendants: Vec<(libc::pid_t, u64, libc::c_int)>,
    timed_out: bool,
    monitor_failed: bool,
    stdout_overflow: bool,
    stderr_overflow: bool,
}

impl StageReport {
    fn diagnostic(&self) -> String {
        format!(
            "stage={} invocation={} status={:?} primary={:?} cleanup={:?} retired={} descendants={} monitor_failed={} overflow={}/{}\nstdout:\n{}\nstderr:\n{}",
            self.name,
            self.invocation,
            self.status,
            self.primary,
            self.cleanup,
            self.retired,
            self.descendants,
            self.monitor_failed,
            self.stdout_overflow,
            self.stderr_overflow,
            String::from_utf8_lossy(&self.stdout),
            String::from_utf8_lossy(&self.stderr)
        )
    }

    fn require_success(&self) -> Result<(), String> {
        if self.primary.is_none()
            && self.cleanup.is_empty()
            && self.retired
            && self.status.is_some_and(|status| status.success())
        {
            Ok(())
        } else {
            Err(self.diagnostic())
        }
    }
}

fn run_stage(
    tree: &PrivateTree,
    name: &'static str,
    command: &mut Command,
    timeout_control: bool,
) -> StageReport {
    let started = Instant::now();
    let mut report = StageReport {
        name,
        leader: 0,
        invocation: format!("{command:?}"),
        status: None,
        primary: None,
        cleanup: Vec::new(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        retired: false,
        descendants: 0,
        reaped_descendants: Vec::new(),
        timed_out: false,
        monitor_failed: false,
        stdout_overflow: false,
        stderr_overflow: false,
    };
    let mut owner = match StageOwner::spawn(command, tree) {
        Ok(owner) => owner,
        Err(error) => {
            report.primary = Some(format!("spawn: {error}"));
            report.monitor_failed = true;
            return report;
        }
    };
    report.leader = owner.pid;
    let mut deadline = started
        + if timeout_control {
            Duration::from_secs(5)
        } else {
            WALL_LIMIT
        };
    let mut armed = false;
    if let Err(error) = owner
        .stdout
        .configure()
        .and_then(|()| owner.stderr.configure())
    {
        report.primary = Some(format!("configure pipes: {error}"));
    }
    let start = if report.primary.is_none() {
        match process_start(owner.pid) {
            Ok(start) => Some(start),
            Err(error) => {
                report.primary = Some(format!("identify unreaped leader: {error}"));
                None
            }
        }
    } else {
        None
    };
    while report.primary.is_none() {
        if let Err(error) = owner.drain() {
            report.primary = Some(format!("capture: {error}"));
            break;
        }
        if timeout_control && !armed {
            let text = String::from_utf8_lossy(&owner.stdout.bytes);
            if text
                .lines()
                .any(|line| line.starts_with("WRAPPER_TIMEOUT_PARENT "))
                && text
                    .lines()
                    .any(|line| line.starts_with("WRAPPER_TIMEOUT_CHILD "))
            {
                let observed = Instant::now();
                if observed >= deadline {
                    report.primary = Some(
                        "timeout control did not publish both live processes within 5s".into(),
                    );
                    break;
                }
                armed = true;
                deadline = observed + Duration::from_millis(100);
            }
        }
        let exited = match owner.exited_without_reaping() {
            Ok(exited) => exited,
            Err(error) => {
                report.primary = Some(format!("waitid WNOWAIT: {error}"));
                break;
            }
        };
        // Completion observed after the deadline does not excuse the wall
        // bound, even if scheduling delayed this monitor's next observation.
        if Instant::now() >= deadline {
            report.timed_out = !timeout_control || armed;
            report.primary = Some(if timeout_control && !armed {
                "timeout control did not publish both live processes within 5s".into()
            } else {
                "payload wall deadline exceeded".into()
            });
            break;
        }
        if exited {
            break;
        }
        if let Err(error) = owner.poll_pipes() {
            report.primary = Some(format!("poll pipes: {error}"));
        }
    }
    report.monitor_failed = report.primary.is_some();
    report.cleanup = owner.retire();
    report.status = owner.status;
    report.retired = owner.retired;
    report.descendants = owner.descendants.len();
    report.reaped_descendants = std::mem::take(&mut owner.descendants);
    report.stdout_overflow = owner.stdout.overflow;
    report.stderr_overflow = owner.stderr.overflow;
    report.stdout = std::mem::take(&mut owner.stdout.bytes);
    report.stderr = std::mem::take(&mut owner.stderr.bytes);
    if report.primary.is_none() && !report.cleanup.is_empty() {
        report.primary = report.cleanup.first().cloned();
    }
    if report.primary.is_none() && !report.status.is_some_and(|status| status.success()) {
        report.primary = Some(format!(
            "child did not exit successfully: {:?}",
            report.status
        ));
    }
    // Keep test-runner output outside retirement; a blocked output consumer
    // must not stall cleanup while the process-group leader is still owned.
    for (pid, start, status) in &report.reaped_descendants {
        println!(
            "C_PROTOCOL_REAPED pgid={} pid={pid} start={start} raw_status={status}",
            owner.pid
        );
    }
    println!(
        "C_PROTOCOL_STAGE name={name} pid={} pgid={} start={start:?} code={:?} signal={:?} retired={} descendants={} timed_out={} monitor_failed={} stdout_overflow={} stderr_overflow={} stdout_bytes={} stderr_bytes={} cleanup_errors={} wall_ms={} invocation={}",
        owner.pid,
        owner.pid,
        report.status.and_then(|status| status.code()),
        report.status.and_then(|status| status.signal()),
        report.retired,
        report.descendants,
        report.timed_out,
        report.monitor_failed,
        report.stdout_overflow,
        report.stderr_overflow,
        report.stdout.len(),
        report.stderr.len(),
        report.cleanup.len(),
        started.elapsed().as_millis(),
        report.invocation
    );
    report
}

const PASS_BEFORE_CONTEXT: &[&str] = &[
    "PASS terminal-before-start: no pthread/read/join",
    "PASS terminal-during-create: latched through handle publication",
    "PASS terminal-before-handle-publication: queued public cancellation",
    "PASS early-completion: no send window; one physical join",
    "PASS normal-zero: outcome is not retirement; one join before release",
    "PASS pre-public-read: sticky cancellation; no fabricated result",
    "PASS inside-kernel: exact staging args, unchanged flags, alias reuse",
    "PASS public-return-before-disable: real EAGAIN retained on late cancel",
    "PASS delayed-sender: drain before join; fresh sends refused through retirement",
    "PASS queued-inotify: actual EINVAL and retained event",
    "PASS create-error: typed no-thread failure, no fallback read",
    "PASS injected-cancel-error: real event completion; first error retained",
    "PASS wake-before-wait: no lost wake or invented terminal outcome",
];
fn context_pass(decision: AttributeDecision) -> String {
    format!(
        "PASS inherited-context-v2: matching credentials/namespaces/mask; new thread has disabled altstack; attribute={}; read/join/ownership/restoration verified",
        decision.name()
    )
}
const JOIN_PASS: &str =
    "PASS injected-join-error: first failure and ownership retained until process exit";
const AGGREGATE_PASS: &str =
    "PASS all C protocol controls; injected retirement failure contained by process exit";

fn complete_protocol(stdout: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(stdout)
        .map_err(|error| format!("non-UTF8 protocol transcript: {error}"))?;
    let actual: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("PASS"))
        .collect();
    let context = context_pass(live_observations(text)?.decision);
    let expected: Vec<_> = PASS_BEFORE_CONTEXT
        .iter()
        .copied()
        .chain([context.as_str(), JOIN_PASS, AGGREGATE_PASS])
        .collect();
    if actual != expected {
        return Err(format!(
            "incomplete, reordered or unexpected internal PASS records: {actual:?}"
        ));
    }
    context_completion(text, "live", false)
}

fn exact_record(text: &str, expected: &str) -> Result<(), String> {
    if text.lines().filter(|line| *line == expected).count() != 1 {
        return Err(format!(
            "missing/duplicated context qualification: {expected}"
        ));
    }
    Ok(())
}

fn one_record<'a>(text: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut records = text.lines().filter(|line| line.starts_with(prefix));
    match (records.next(), records.next()) {
        (Some(record), None) => Ok(record),
        _ => Err(format!("missing/duplicated context observation: {prefix}")),
    }
}

fn record_field<'a>(record: &'a str, key: &str) -> Result<&'a str, String> {
    let mut values = record.split_whitespace().filter_map(|field| {
        field
            .split_once('=')
            .filter(|(name, _)| *name == key)
            .map(|(_, value)| value)
    });
    match (values.next(), values.next()) {
        (Some(value), None) => Ok(value),
        _ => Err(format!("missing/duplicated field {key}: {record}")),
    }
}

fn field_is(record: &str, key: &str, expected: &str) -> Result<(), String> {
    if record_field(record, key)? != expected {
        return Err(format!("expected {key}={expected}: {record}"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AttributeExpected<'a> {
    Value(&'a [u8]),
    Empty,
    ReadError(i32, bool), // errno; explicitly synthetic open=100
    Missing,
    Truncated,
}

fn attribute_record(
    record: &str,
    identity: (libc::pid_t, u64),
    expected: AttributeExpected<'_>,
) -> Result<(), String> {
    field_is(record, "tid", &identity.0.to_string())?;
    field_is(record, "start", &identity.1.to_string())?;
    if !matches!(expected, AttributeExpected::Missing) {
        let open: i32 = record_field(record, "open")?
            .parse()
            .map_err(|_| format!("invalid open result: {record}"))?;
        if open < 0 {
            return Err(format!("unexpected fixture open failure: {record}"));
        }
        field_is(record, "close", "0")?;
    }
    // errno is checked only for failed calls. Successful open/read/close may
    // leave any recorded errno; EOF/kind/length/all bytes remain exact.
    let (kind, reads, last_read, eof, bytes) = match expected {
        AttributeExpected::Value(bytes) => ("0", "2", "0", "1", bytes.to_vec()),
        AttributeExpected::Empty => ("0", "1", "0", "1", Vec::new()),
        AttributeExpected::ReadError(errno, synthetic) => {
            if synthetic {
                field_is(record, "open", "100")?;
            }
            field_is(record, "read_errno", &errno.to_string())?;
            ("2", "1", "-1", "0", Vec::new())
        }
        AttributeExpected::Missing => {
            field_is(record, "path", "/proc/self/task/0/attr/current")?;
            field_is(record, "open", "-1")?;
            field_is(record, "open_errno", "2")?;
            field_is(record, "close", "-2")?;
            ("1", "0", "-2", "0", Vec::new())
        }
        AttributeExpected::Truncated => ("4", "1", "4095", "0", vec![b'x'; 4095]),
    };
    for (key, value) in [
        ("kind", kind),
        ("reads", reads),
        ("last_read", last_read),
        ("eof", eof),
    ] {
        field_is(record, key, value)?;
    }
    field_is(record, "length", &bytes.len().to_string())?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    field_is(record, "bytes_hex", &hex)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttributeObservation {
    kind: u32,
    open: i32,
    reads: usize,
    last_read: i64,
    read_errno: i32,
    close: i32,
    eof: bool,
    bytes: Vec<u8>,
}

impl AttributeObservation {
    fn complete(&self) -> bool {
        self.kind == 0
            && self.open >= 0
            && self.reads >= 1
            && self.last_read == 0
            && self.eof
            && self.bytes.len() < 4095
            && self.close == 0
    }

    fn initial_einval(&self) -> bool {
        self.kind == 2
            && self.open >= 0
            && self.reads == 1
            && self.last_read == -1
            && self.read_errno == libc::EINVAL
            && self.bytes.is_empty()
            && !self.eof
            && self.close == 0
    }

    fn single_exported_value(&self) -> bool {
        self.complete() && self.reads == 2 && !self.bytes.is_empty()
    }
}

fn number<T: std::str::FromStr>(record: &str, key: &str) -> Result<T, String> {
    record_field(record, key)?
        .parse()
        .map_err(|_| format!("invalid numeric {key}: {record}"))
}

fn observed_attribute(
    record: &str,
    identity: (libc::pid_t, u64),
) -> Result<AttributeObservation, String> {
    if identity.0 <= 0 || identity.1 == 0 {
        return Err("invalid observed task identity".into());
    }
    field_is(record, "tid", &identity.0.to_string())?;
    field_is(record, "start", &identity.1.to_string())?;
    // Successful calls may leave arbitrary errno values; retain typed fields
    // without mistaking those diagnostic values for operation failures.
    let _: i32 = number(record, "open_errno")?;
    let _: i32 = number(record, "close_errno")?;
    let length: usize = number(record, "length")?;
    let encoded = record_field(record, "bytes_hex")?.as_bytes();
    if length > 4095 || encoded.len() != length * 2 {
        return Err("attribute byte length does not match its complete hex record".into());
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid attribute hex byte".to_string()),
    };
    let bytes = encoded
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect::<Result<Vec<_>, String>>()?;
    let eof = match record_field(record, "eof")? {
        "0" => false,
        "1" => true,
        _ => return Err("invalid attribute EOF flag".into()),
    };
    Ok(AttributeObservation {
        kind: number(record, "kind")?,
        open: number(record, "open")?,
        reads: number(record, "reads")?,
        last_read: number(record, "last_read")?,
        read_errno: number(record, "read_errno")?,
        close: number(record, "close")?,
        eof,
        bytes,
    })
}

// Bind each summary to its actual read records. The classifier separately
// requires one nonempty positive read and one EOF: getprocattr regenerates its
// value on every read, so concatenated positive chunks cannot prove one value.
fn actual_read_sequence(
    text: &str,
    origin: &str,
    identity: (libc::pid_t, u64),
    path: &str,
    observation: &AttributeObservation,
) -> Result<(), String> {
    let mut offset = 0;
    let mut count = 0;
    let prefix = format!("CONTEXT_ATTRIBUTE_READ origin={origin} ");
    for record in text.lines().filter(|line| line.starts_with(&prefix)) {
        if number::<libc::pid_t>(record, "tid")? != identity.0 {
            continue;
        }
        field_is(record, "start", &identity.1.to_string())?;
        field_is(record, "path", path)?;
        count += 1;
        let result: i64 = number(record, "return")?;
        let error: i32 = number(record, "errno")?;
        if number::<usize>(record, "index")? != count
            || number::<usize>(record, "offset")? != offset
            || count > observation.reads
            || result < -1
            || result > (4095 - offset) as i64
            || (count < observation.reads && result <= 0)
        {
            return Err("inconsistent actual attribute read sequence".into());
        }
        if result > 0 {
            offset += result as usize;
        }
        if count == observation.reads
            && (result != observation.last_read || error != observation.read_errno)
        {
            return Err("actual final read disagrees with attribute summary".into());
        }
    }
    if count != observation.reads || offset != observation.bytes.len() {
        return Err("missing actual attribute reads or byte count".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryProfile {
    KnownUnavailable,
    ExportedBytes,
}

fn inventory_profile(
    before: &AttributeObservation,
    after: &AttributeObservation,
) -> Result<InventoryProfile, String> {
    if !before.complete() || !after.complete() || before.reads != 2 || after.reads != 2 {
        return Err("provider inventory query incomplete".into());
    }
    for observation in [before, after] {
        let mut seen = Vec::new();
        for name in observation.bytes.split(|byte| *byte == b',') {
            if name.is_empty()
                || !name[0].is_ascii_lowercase()
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
                || seen.contains(&name)
            {
                return Err("malformed provider inventory".into());
            }
            seen.push(name);
        }
    }
    if before.bytes != after.bytes {
        return Err("changing provider inventory".into());
    }
    Ok(if before.bytes == b"capability,bpf,ima" {
        InventoryProfile::KnownUnavailable
    } else {
        InventoryProfile::ExportedBytes
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttributeDecision {
    Equal,
    Unavailable,
}

impl AttributeDecision {
    fn name(self) -> &'static str {
        match self {
            Self::Equal => "exact-label-bytes",
            Self::Unavailable => "unavailable-label",
        }
    }
}

fn attribute_decision(
    left: &AttributeObservation,
    right: &AttributeObservation,
    profile: InventoryProfile,
) -> Result<AttributeDecision, String> {
    // proc_pid_attr_read regenerates the selected getprocattr result per read.
    // Compare one nonempty exported value each, not all LSM state or policy.
    if left.single_exported_value() && right.single_exported_value() && left.bytes == right.bytes {
        Ok(AttributeDecision::Equal)
    } else if profile == InventoryProfile::KnownUnavailable
        && left.initial_einval()
        && right.initial_einval()
    {
        Ok(AttributeDecision::Unavailable)
    } else {
        Err(
            "attribute pair is neither equal nonempty single-read bytes nor qualified paired READ-EINVAL"
                .into(),
        )
    }
}

struct LiveContext {
    identities: [(libc::pid_t, u64); 2],
    attributes: [AttributeObservation; 2],
    profile: InventoryProfile,
    decision: AttributeDecision,
}

fn provider_decision_record(
    text: &str,
    origin: &str,
    mode: &str,
    profile: InventoryProfile,
) -> Result<(), String> {
    let (profile, reason) = match profile {
        InventoryProfile::KnownUnavailable => ("observed-unavailable", "recognized"),
        InventoryProfile::ExportedBytes => ("exported-bytes-only", "valid"),
    };
    let expected = format!(
        "CONTEXT_PROVIDER_DECISION origin={origin} profile={profile} reason={reason} mode={mode}"
    );
    if one_record(text, &format!("CONTEXT_PROVIDER_DECISION origin={origin} "))? != expected {
        return Err("provider decision disagrees with typed observations".into());
    }
    Ok(())
}

fn live_decision_records(text: &str, mode: &str, live: &LiveContext) -> Result<(), String> {
    provider_decision_record(text, "actual-live-inventory", mode, live.profile)?;
    let expected = format!(
        "CONTEXT_ATTRIBUTE_DECISION origin=actual-live-query decision={} mode={mode}",
        live.decision.name()
    );
    if one_record(text, "CONTEXT_ATTRIBUTE_DECISION origin=actual-live-query ")? != expected {
        return Err("attribute decision disagrees with typed observations".into());
    }
    Ok(())
}

fn live_observations(text: &str) -> Result<LiveContext, String> {
    let identity = one_record(text, "CONTEXT_IDENTITY ")?;
    let mut identities = [(0, 0); 2];
    for (index, role) in ["creator", "helper"].iter().enumerate() {
        let (pid, start) = record_field(identity, role)?
            .split_once('/')
            .ok_or_else(|| "invalid task identity".to_string())?;
        identities[index] = (
            pid.parse().map_err(|_| "invalid task pid")?,
            start.parse().map_err(|_| "invalid task generation")?,
        );
        if identities[index].0 <= 0 || identities[index].1 == 0 {
            return Err("invalid task identity".into());
        }
    }
    if identities[0].0 == identities[1].0 {
        return Err("creator/helper identity aliased".into());
    }
    // Every actual read event belongs to the declared pair (or the creator for
    // inventory). An extra task's record cannot disappear in per-task filtering.
    for origin in [
        "actual-task-query",
        "actual-provider-before",
        "actual-provider-after",
    ] {
        let prefix = format!("CONTEXT_ATTRIBUTE_READ origin={origin} ");
        for record in text.lines().filter(|line| line.starts_with(&prefix)) {
            let observed = (
                number::<libc::pid_t>(record, "tid")?,
                number::<u64>(record, "start")?,
            );
            if !identities.contains(&observed)
                || (origin != "actual-task-query" && observed != identities[0])
            {
                return Err("actual read record has an unbound task identity".into());
            }
        }
    }
    let actual: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("CONTEXT_ATTRIBUTE origin=actual-live-query "))
        .collect();
    if actual.len() != 2 {
        return Err("both actual task attribute records are required".into());
    }
    let mut attributes = Vec::new();
    for (record, identity) in actual.into_iter().zip(identities) {
        let path = format!("/proc/self/task/{}/attr/current", identity.0);
        field_is(record, "path", &path)?;
        let observation = observed_attribute(record, identity)?;
        actual_read_sequence(text, "actual-task-query", identity, &path, &observation)?;
        attributes.push(observation);
    }
    let mut inventories = Vec::new();
    for origin in ["actual-provider-before", "actual-provider-after"] {
        let record = one_record(text, &format!("CONTEXT_ATTRIBUTE origin={origin} "))?;
        field_is(record, "path", "/sys/kernel/security/lsm")?;
        let observation = observed_attribute(record, identities[0])?;
        actual_read_sequence(
            text,
            origin,
            identities[0],
            "/sys/kernel/security/lsm",
            &observation,
        )?;
        inventories.push(observation);
    }
    let profile = inventory_profile(&inventories[0], &inventories[1])?;
    let decision = attribute_decision(&attributes[0], &attributes[1], profile)?;
    Ok(LiveContext {
        identities,
        attributes: attributes
            .try_into()
            .map_err(|_| "missing actual attribute pair")?,
        profile,
        decision,
    })
}

const PLT_DECODER_CONTROL: &str = "CONTEXT_READ_PLT_DECODER legacy=1 endbr64=1 signed=1 malformed_rejected=1 truncated_rejected=1 overflow_rejected=1 stability_bytes=1 stability_length=1";

fn read_plt_records(text: &str) -> Result<(), String> {
    let mut observations = Vec::new();
    for phase in ["before-read", "after-join"] {
        let record = one_record(text, &format!("CONTEXT_READ_PLT phase={phase} "))?;
        let encoded = record_field(record, "plt_hex")?;
        let (length, prefix) = match encoded.len() {
            12 => (6, "ff25"),
            20 => (10, "f30f1efaff25"),
            _ => return Err("unsupported or incomplete live read PLT bytes".into()),
        };
        if encoded.len() != length * 2
            || !encoded.starts_with(prefix)
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("unsupported or incomplete live read PLT bytes".into());
        }
        let dispatch = one_record(text, &format!("CONTEXT_READ_DISPATCH phase={phase} "))?;
        for field in ["callable", "plt_hex"] {
            field_is(dispatch, field, record_field(record, field)?)?;
        }
        observations.push((record_field(record, "callable")?, length, encoded));
    }
    if observations[0] != observations[1] {
        return Err("live read PLT address, length or bytes changed between observations".into());
    }
    Ok(())
}

fn context_completion(text: &str, mode: &str, context_only: bool) -> Result<(), String> {
    let live = live_observations(text)?;
    exact_record(
        text,
        &format!(
            "CONTEXT_CONTROL mode={mode} context_only={}",
            u8::from(context_only)
        ),
    )?;
    live_decision_records(text, mode, &live)?;
    exact_record(text, PLT_DECODER_CONTROL)?;
    read_plt_records(text)?;
    for exact in [
        "CONTEXT_READ_DISPATCH_STABLE callable=1 plt_bytes=1 slot=1 target=1 public_symbol=1 dso=1",
        "CONTEXT_RETIREMENT physical_joins=1 cancel_sends=0 destroyed=1 owner_closed_fd=1",
    ] {
        exact_record(text, exact)?;
    }
    for prefix in [
        "CONTEXT_ATTRIBUTE origin=actual-provider-before ",
        "CONTEXT_ATTRIBUTE origin=actual-provider-after ",
        "CONTEXT_IDENTITY ",
        "CONTEXT_ALTSTACK ",
        "CONTEXT_READ_BINDING ",
        "CONTEXT_READ_PLT phase=before-read ",
        "CONTEXT_READ_PLT phase=after-join ",
        "CONTEXT_READ_GOT phase=before-read ",
        "CONTEXT_READ_GOT phase=after-join ",
        "CONTEXT_READ_DISPATCH phase=before-read ",
        "CONTEXT_READ_DISPATCH phase=after-join ",
        "CONTEXT_ENDPOINT ",
        "CONTEXT_RESTORATION mask_exact=1 altstack_exact=1 ",
    ] {
        one_record(text, prefix)?;
    }
    let outcomes: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("CONTEXT_READ_OUTCOME "))
        .collect();
    if outcomes.len() != 1
        || !outcomes[0].starts_with("CONTEXT_READ_OUTCOME outcome=1 result=0 read_errno=")
        || !outcomes[0].ends_with(" terminal=0 error_phase=0 error_number=0")
    {
        return Err("missing exact normal read/control outcome".into());
    }
    if text
        .lines()
        .filter(|line| line.starts_with("CONTEXT_ATTRIBUTE origin=actual-live-query "))
        .count()
        != 2
    {
        return Err("both actual task attribute records are required".into());
    }
    if text.lines().any(|line| {
        line.starts_with("UNEXPECTED_ACCEPTANCE")
            || line.starts_with("CONTEXT_ERROR")
            || line.starts_with("CONTEXT_REJECT")
            || line.contains(" decision=rejected ")
    }) {
        return Err("protocol transcript contains a rejected observation".into());
    }
    Ok(())
}

const SYNTHETIC_LABEL_PASS: &str =
    "PASS synthetic-label-classifier: equal length and all bytes including NUL suffix";
const SYNTHETIC_NONLEGACY_PASS: &str = "PASS synthetic-nonlegacy-label-classifier: stable valid inventory; equal exported bytes including NUL suffix";
const CONTEXT_MODES: &[(&str, &str)] = &[
    ("context-equal-labels", "equal-labels"),
    ("context-equal-labels-nonlegacy", "equal-labels-nonlegacy"),
    ("context-empty-labels", "empty-labels"),
    ("context-mask-mismatch", "mask-mismatch"),
    ("context-query-asymmetry", "query-asymmetry"),
    ("context-query-errors", "query-errors"),
    ("context-missing-task", "missing-task"),
    ("context-truncated-label", "truncated-label"),
    ("context-label-mismatch", "label-mismatch"),
    ("context-label-length", "label-length"),
    ("context-unqualified-provider", "unqualified-provider"),
    ("context-query-eperm", "query-eperm"),
    ("context-inventory-malformed", "inventory-malformed"),
    ("context-inventory-unknown", "inventory-unknown"),
    ("context-inventory-changing", "inventory-changing"),
    ("context-inventory-missing", "inventory-missing"),
    ("context-inventory-truncated", "inventory-truncated"),
];

fn fixture_observations(text: &str, mode: &str, live: &LiveContext) -> Result<(), String> {
    use AttributeExpected::*;
    let identities = live.identities;
    let (left, right) = match mode {
        "equal-labels" | "equal-labels-nonlegacy" => (Value(b"a\0x"), Value(b"a\0x")),
        "empty-labels" => (Empty, Empty),
        "missing-task" => (Value(b"a\0x"), Missing),
        "label-mismatch" => (Value(b"a\0x"), Value(b"a\0y")),
        "label-length" => (Value(b"a\0x"), Value(b"a\0x\0")),
        "query-asymmetry" => (Value(b"a\0x"), ReadError(libc::EINVAL, true)),
        "query-errors" => (ReadError(libc::EINVAL, true), ReadError(libc::EACCES, true)),
        "query-eperm" => (ReadError(libc::EPERM, true), ReadError(libc::EPERM, true)),
        "unqualified-provider" => (ReadError(libc::EINVAL, true), ReadError(libc::EINVAL, true)),
        "truncated-label" => (Value(b"a\0x"), Truncated),
        "inventory-malformed" => (Value(b"capability,,bpf,ima"), Value(b"capability,,bpf,ima")),
        "inventory-unknown" => (
            Value(b"capability,bpf,ima,fixture_unknown"),
            Value(b"capability,bpf,ima,fixture_unknown"),
        ),
        "inventory-changing" => (Value(b"capability,bpf,ima"), Value(b"capability,ima,bpf")),
        "inventory-missing" => (Value(b"capability,bpf,ima"), Missing),
        "inventory-truncated" => (Value(b"capability,bpf,ima"), Truncated),
        _ => return Err(format!("unknown fixture mode {mode}")),
    };
    let inventory = mode.starts_with("inventory-");
    let origins = if inventory {
        ["inventory-fixture-before", "inventory-fixture-after"]
    } else {
        ["classifier-fixture-creator", "classifier-fixture-helper"]
    };
    for (index, (origin, expected)) in origins.into_iter().zip([left, right]).enumerate() {
        let identity = if matches!(expected, Missing) {
            (0, 0)
        } else {
            identities[if inventory { 0 } else { index }]
        };
        attribute_record(
            one_record(text, &format!("CONTEXT_ATTRIBUTE origin={origin} "))?,
            identity,
            expected,
        )?;
    }
    Ok(())
}

fn fixture_inventory(
    text: &str,
    mode: &str,
    identities: [(libc::pid_t, u64); 2],
) -> Result<InventoryProfile, String> {
    // All fixture premises are synthetic and independent of the live host's
    // attribute branch. These inventories traverse the real C classifier.
    let bytes: &[u8] = if matches!(mode, "equal-labels-nonlegacy" | "unqualified-provider") {
        b"capability,bpf,ima,fixture_unknown"
    } else {
        b"capability,bpf,ima"
    };
    let mut inventories = Vec::new();
    for (origin, identity) in [
        "classifier-fixture-provider-before",
        "classifier-fixture-provider-after",
    ]
    .into_iter()
    .zip(identities)
    {
        let record = one_record(text, &format!("CONTEXT_ATTRIBUTE origin={origin} "))?;
        attribute_record(record, identity, AttributeExpected::Value(bytes))?;
        inventories.push(observed_attribute(record, identity)?);
    }
    let profile = inventory_profile(&inventories[0], &inventories[1])?;
    provider_decision_record(text, "classifier-fixture-inventory", mode, profile)?;
    Ok(profile)
}

fn require_context_mode(report: &StageReport, mode: &str) -> Result<(), String> {
    let text = std::str::from_utf8(&report.stdout).map_err(|error| error.to_string())?;
    let stderr = std::str::from_utf8(&report.stderr).map_err(|error| error.to_string())?;
    let live = live_observations(text)?;
    let identities = live.identities;
    if identities[0].0 != report.leader {
        return Err("actual creator is not this owned stage leader".into());
    }
    exact_record(text, &format!("CONTEXT_CONTROL mode={mode} context_only=1"))?;
    if text
        .lines()
        .chain(stderr.lines())
        .any(|line| line.starts_with("UNEXPECTED_ACCEPTANCE"))
    {
        return Err(format!("unexpected classifier acceptance in {mode}"));
    }
    let origin = if mode == "mask-mismatch" {
        "actual-helper-SIGUSR1-unblock"
    } else if mode.starts_with("inventory-") {
        "inventory-fixture"
    } else {
        "classifier-fixture"
    };
    let fault = format!("CONTEXT_TEST_FAULT mode={mode} origin={origin}");
    if one_record(text, "CONTEXT_TEST_FAULT ")? != fault {
        return Err(format!("wrong fault origin for {mode}"));
    }
    let passes: Vec<_> = text
        .lines()
        .chain(stderr.lines())
        .filter(|line| line.starts_with("PASS"))
        .collect();
    if mode == "equal-labels" || mode == "equal-labels-nonlegacy" {
        report.require_success()?;
        let synthetic = if mode == "equal-labels" {
            SYNTHETIC_LABEL_PASS
        } else {
            SYNTHETIC_NONLEGACY_PASS
        };
        let completion = context_pass(live.decision);
        if !stderr.is_empty() || passes != [synthetic, completion.as_str()] {
            return Err(report.diagnostic());
        }
        fixture_observations(text, mode, &live)?;
        exact_record(
            text,
            &format!(
                "CONTEXT_ATTRIBUTE_DECISION origin=classifier-fixture decision=exact-label-bytes mode={mode}"
            ),
        )?;
        let profile = fixture_inventory(text, mode, identities)?;
        let left = observed_attribute(
            one_record(text, "CONTEXT_ATTRIBUTE origin=classifier-fixture-creator ")?,
            identities[0],
        )?;
        let right = observed_attribute(
            one_record(text, "CONTEXT_ATTRIBUTE origin=classifier-fixture-helper ")?,
            identities[1],
        )?;
        if attribute_decision(&left, &right, profile)? != AttributeDecision::Equal {
            return Err("fixture did not exercise exported-byte equality".into());
        }
        // Synthetic acceptance never relabels the independent live observation.
        return context_completion(text, mode, true);
    }
    if report.monitor_failed
        || !report.retired
        || !report.cleanup.is_empty()
        || report.status.and_then(|status| status.signal()) != Some(libc::SIGABRT)
        || !passes.is_empty()
    {
        return Err(report.diagnostic());
    }
    if text.lines().any(|line| {
        [
            "CONTEXT_READ_",
            "CONTEXT_RETIREMENT ",
            "CONTEXT_RESTORATION ",
        ]
        .iter()
        .any(|prefix| line.starts_with(prefix))
    }) {
        return Err(format!(
            "negative {mode} claimed read/completion/retirement"
        ));
    }
    if mode == "mask-mismatch" {
        exact_record(
            text,
            "CONTEXT_REJECT reason=signal-mask signal=10 creator=1 helper=0",
        )?;
        let assertion = "Assertion `sigismember(&test_mask, signal) == sigismember(&child_context.mask, signal)' failed.";
        if stderr.lines().count() != 1
            || !stderr.starts_with("terminal-read-protocol: ")
            || !stderr.contains(": inherited_context: Assertion ")
            || !stderr.trim_end_matches('\n').ends_with(assertion)
            || stderr.contains("CONTEXT_ERROR")
        {
            return Err(report.diagnostic());
        }
        return Ok(());
    }
    fixture_observations(text, mode, &live)?;
    live_decision_records(text, mode, &live)?;
    let operation = if mode.starts_with("inventory-") {
        if mode == "inventory-unknown" {
            provider_decision_record(
                text,
                "inventory-fixture",
                mode,
                InventoryProfile::ExportedBytes,
            )?;
            for (origin, identity) in ["inventory-fixture-creator", "inventory-fixture-helper"]
                .into_iter()
                .zip(identities)
            {
                attribute_record(
                    one_record(text, &format!("CONTEXT_ATTRIBUTE origin={origin} "))?,
                    identity,
                    AttributeExpected::ReadError(libc::EINVAL, true),
                )?;
            }
            exact_record(
                text,
                "CONTEXT_ATTRIBUTE_DECISION origin=inventory-fixture decision=rejected mode=inventory-unknown",
            )?;
        } else {
            let reason = match mode {
                "inventory-malformed" => "malformed",
                "inventory-changing" => "changing",
                "inventory-missing" | "inventory-truncated" => "query-error",
                _ => return Err(format!("unknown inventory mode {mode}")),
            };
            exact_record(
                text,
                &format!(
                    "CONTEXT_PROVIDER_DECISION origin=inventory-fixture profile=unclassified reason={reason} mode={mode}"
                ),
            )?;
        }
        "provider-inventory-oracle"
    } else {
        fixture_inventory(text, mode, identities)?;
        exact_record(
            text,
            &format!(
                "CONTEXT_ATTRIBUTE_DECISION origin=classifier-fixture decision=rejected mode={mode}"
            ),
        )?;
        "attribute-oracle"
    };
    if stderr
        != format!("CONTEXT_ERROR operation={operation} path={mode} errno=71 (Protocol error)\n")
    {
        return Err(report.diagnostic());
    }
    Ok(())
}

fn context_modes(tree: &PrivateTree) -> Result<(), String> {
    for &(stage, mode) in CONTEXT_MODES {
        let report = run_stage(
            tree,
            stage,
            Command::new(tree.path.join("terminal-read-protocol"))
                .arg("--context-mode")
                .arg(mode),
            false,
        );
        println!("C_PROTOCOL_CONTEXT_STDOUT_BEGIN mode={mode}");
        print!("{}", String::from_utf8_lossy(&report.stdout));
        println!("C_PROTOCOL_CONTEXT_STDOUT_END mode={mode}");
        println!("C_PROTOCOL_CONTEXT_STDERR_BEGIN mode={mode}");
        print!("{}", String::from_utf8_lossy(&report.stderr));
        println!("C_PROTOCOL_CONTEXT_STDERR_END mode={mode}");
        require_context_mode(&report, mode)
            .map_err(|error| format!("{error}\n{}", report.diagnostic()))?;
        if mode == "mask-mismatch" {
            let mut malformed = report.clone();
            malformed.stderr = [b"PASS:".as_slice(), report.stderr.as_slice()].concat();
            if require_context_mode(&malformed, mode).is_ok() {
                return Err("mask assertion with a stderr PASS prefix was accepted".into());
            }
        }
    }
    println!("C_PROTOCOL_CONTEXT_CONTROLS positive=2 rejected=15 stderr_pass_prefix=rejected");
    Ok(())
}

// In-process controls only; not a second #[test] or a subprocess.
// All records below are synthetic, including fields named actual-* so the real
// parser is exercised. No generated record is printed as a live observation.
fn typed_context_controls() -> Result<(), String> {
    fn rejected<T>(name: &str, result: Result<T, String>, expected: &str) -> Result<(), String> {
        match result {
            Err(error) if error == expected => Ok(()),
            Err(error) => Err(format!(
                "synthetic {name}: expected {expected:?}, got {error:?}"
            )),
            Ok(_) => Err(format!("synthetic {name}: invalid observation accepted")),
        }
    }
    fn query(
        id: (libc::pid_t, u64),
        origin: &str,
        read_origin: &str,
        path: &str,
        chunks: &[&[u8]],
    ) -> String {
        let (tid, start) = id;
        let mut text = String::new();
        let mut bytes = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            text.push_str(&format!("CONTEXT_ATTRIBUTE_READ origin={read_origin} tid={tid} start={start} path={path} index={} return={} errno=17 offset={}\n", index + 1, chunk.len(), bytes.len()));
            bytes.extend_from_slice(chunk);
        }
        text.push_str(&format!("CONTEXT_ATTRIBUTE_READ origin={read_origin} tid={tid} start={start} path={path} index={} return=0 errno=17 offset={}\n", chunks.len() + 1, bytes.len()));
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        text.push_str(&format!("CONTEXT_ATTRIBUTE origin={origin} tid={tid} start={start} path={path} kind=0 open=9 open_errno=17 reads={} last_read=0 read_errno=17 close=0 close_errno=17 eof=1 length={} bytes_hex={hex}\n", chunks.len() + 1, bytes.len()));
        text
    }
    fn transcript(left: &[&[u8]], right: &[&[u8]]) -> String {
        let inventory: &[u8] = b"capability,bpf,ima,fixture_unknown";
        let mut text = "CONTEXT_IDENTITY creator=101/1001 helper=102/1002\n".to_string();
        text.push_str(&query(
            (101, 1001),
            "actual-provider-before",
            "actual-provider-before",
            "/sys/kernel/security/lsm",
            &[inventory],
        ));
        text.push_str(&query(
            (101, 1001),
            "actual-live-query",
            "actual-task-query",
            "/proc/self/task/101/attr/current",
            left,
        ));
        text.push_str(&query(
            (102, 1002),
            "actual-live-query",
            "actual-task-query",
            "/proc/self/task/102/attr/current",
            right,
        ));
        text.push_str(&query(
            (101, 1001),
            "actual-provider-after",
            "actual-provider-after",
            "/sys/kernel/security/lsm",
            &[inventory],
        ));
        text
    }
    let text = transcript(&[b"a\0x"], &[b"a\0x"]);
    let live = live_observations(&text)?;
    if live.profile != InventoryProfile::ExportedBytes
        || live.decision != AttributeDecision::Equal
        || live.attributes[0].bytes != b"a\0x"
    {
        return Err("synthetic nonempty single-read nonlegacy bytes positive rejected".into());
    }
    let label = live.attributes[0].clone();
    let inv = observed_attribute(
        one_record(&text, "CONTEXT_ATTRIBUTE origin=actual-provider-before ")?,
        (101, 1001),
    )?;
    let mut known_inventory = inv.clone();
    known_inventory.bytes = b"capability,bpf,ima".to_vec();
    let known_profile = inventory_profile(&known_inventory, &known_inventory)?;
    if known_profile != InventoryProfile::KnownUnavailable
        || attribute_decision(&label, &label, known_profile)? != AttributeDecision::Equal
    {
        return Err("synthetic known-inventory successful bytes positive rejected".into());
    }
    const PAIR_ERROR: &str = "attribute pair is neither equal nonempty single-read bytes nor qualified paired READ-EINVAL";
    rejected(
        "empty exported pair",
        live_observations(&transcript(&[], &[])),
        PAIR_ERROR,
    )?;
    rejected(
        "split exported value",
        live_observations(&transcript(&[b"a", b"\0x"], &[b"a\0x"])),
        PAIR_ERROR,
    )?;
    rejected(
        "extra positive chunks on both tasks",
        live_observations(&transcript(&[b"a", b"\0", b"x"], &[b"a", b"\0", b"x"])),
        PAIR_ERROR,
    )?;
    let mut einval = label.clone();
    einval.kind = 2;
    einval.reads = 1;
    einval.last_read = -1;
    einval.read_errno = libc::EINVAL;
    einval.eof = false;
    einval.bytes.clear();
    if attribute_decision(&einval, &einval, InventoryProfile::KnownUnavailable)?
        != AttributeDecision::Unavailable
    {
        return Err("synthetic known paired EINVAL positive rejected".into());
    }
    rejected(
        "nonlegacy paired EINVAL",
        attribute_decision(&einval, &einval, live.profile),
        PAIR_ERROR,
    )?;
    rejected(
        "success/error asymmetry",
        attribute_decision(&label, &einval, live.profile),
        PAIR_ERROR,
    )?;
    let mut partial = einval.clone();
    partial.reads = 2;
    partial.bytes.push(b'a');
    rejected(
        "partial data then EINVAL",
        attribute_decision(&partial, &partial, InventoryProfile::KnownUnavailable),
        PAIR_ERROR,
    )?;
    let mut eperm = einval.clone();
    eperm.read_errno = libc::EPERM;
    rejected(
        "known paired EPERM",
        attribute_decision(&eperm, &eperm, InventoryProfile::KnownUnavailable),
        PAIR_ERROR,
    )?;
    let mut wrong = label.clone();
    wrong.bytes[2] = b'y';
    rejected(
        "post-NUL mismatch",
        attribute_decision(&label, &wrong, live.profile),
        PAIR_ERROR,
    )?;
    wrong = label.clone();
    wrong.bytes.push(0);
    rejected(
        "length mismatch",
        attribute_decision(&label, &wrong, live.profile),
        PAIR_ERROR,
    )?;
    wrong = label.clone();
    wrong.eof = false;
    rejected(
        "missing EOF",
        attribute_decision(&label, &wrong, live.profile),
        PAIR_ERROR,
    )?;
    wrong = label.clone();
    wrong.close = -1;
    rejected(
        "close failure",
        attribute_decision(&label, &wrong, live.profile),
        PAIR_ERROR,
    )?;
    wrong = label.clone();
    wrong.kind = 4;
    wrong.eof = false;
    wrong.reads = 1;
    wrong.last_read = 4095;
    wrong.bytes = vec![b'x'; 4095];
    rejected(
        "truncated bytes",
        attribute_decision(&label, &wrong, live.profile),
        PAIR_ERROR,
    )?;
    for bytes in [
        b"capability,,bpf".as_slice(),
        b"capability,bpf,bpf",
        b"capability,bpf\n",
    ] {
        let mut malformed = inv.clone();
        malformed.bytes = bytes.to_vec();
        rejected(
            "malformed inventory",
            inventory_profile(&malformed, &malformed),
            "malformed provider inventory",
        )?;
    }
    let mut empty_inventory = inv.clone();
    empty_inventory.bytes.clear();
    empty_inventory.reads = 1;
    rejected(
        "empty EOF inventory",
        inventory_profile(&empty_inventory, &empty_inventory),
        "provider inventory query incomplete",
    )?;
    let mut split_inventory = inv.clone();
    split_inventory.reads = 3;
    rejected(
        "split inventory",
        inventory_profile(&split_inventory, &split_inventory),
        "provider inventory query incomplete",
    )?;
    let mut incomplete = inv.clone();
    incomplete.eof = false;
    rejected(
        "incomplete inventory",
        inventory_profile(&incomplete, &inv),
        "provider inventory query incomplete",
    )?;
    rejected(
        "truncated inventory",
        inventory_profile(&wrong, &inv),
        "provider inventory query incomplete",
    )?;
    let mut missing = inv.clone();
    missing.kind = 1;
    missing.open = -1;
    missing.reads = 0;
    missing.last_read = -2;
    missing.close = -2;
    missing.eof = false;
    missing.bytes.clear();
    rejected(
        "missing inventory",
        inventory_profile(&missing, &inv),
        "provider inventory query incomplete",
    )?;
    let mut changed = inv.clone();
    changed.bytes = b"capability,ima,bpf".to_vec();
    rejected(
        "changing inventory",
        inventory_profile(&inv, &changed),
        "changing provider inventory",
    )?;
    for (name, altered, error) in [
        (
            "malformed hex",
            text.replace("bytes_hex=610078", "bytes_hex=61007z"),
            "invalid attribute hex byte",
        ),
        (
            "hex length",
            text.replace("length=3 bytes_hex=610078", "length=4 bytes_hex=610078"),
            "attribute byte length does not match its complete hex record",
        ),
        (
            "invalid EOF",
            text.replacen("eof=1", "eof=2", 1),
            "invalid attribute EOF flag",
        ),
        (
            "read offset",
            text.replacen(
                "index=2 return=0 errno=17 offset=3\n",
                "index=2 return=0 errno=17 offset=0\n",
                1,
            ),
            "inconsistent actual attribute read sequence",
        ),
        (
            "read index",
            text.replacen(
                "index=1 return=3 errno=17 offset=0\n",
                "index=4 return=3 errno=17 offset=0\n",
                1,
            ),
            "inconsistent actual attribute read sequence",
        ),
        (
            "last-read summary",
            text.replacen(
                "path=/proc/self/task/101/attr/current index=2 return=0 errno=17",
                "path=/proc/self/task/101/attr/current index=2 return=0 errno=22",
                1,
            ),
            "actual final read disagrees with attribute summary",
        ),
        (
            "first-read length disagrees with summary",
            text.replacen(
                "index=1 return=3 errno=17 offset=0",
                "index=1 return=2 errno=17 offset=0",
                1,
            )
            .replacen(
                "index=2 return=0 errno=17 offset=3\n",
                "index=2 return=0 errno=17 offset=2\n",
                1,
            ),
            "missing actual attribute reads or byte count",
        ),
        (
            "undeclared third positive read",
            format!(
                "{text}CONTEXT_ATTRIBUTE_READ origin=actual-task-query tid=101 start=1001 path=/proc/self/task/101/attr/current index=3 return=1 errno=17 offset=3\n"
            ),
            "inconsistent actual attribute read sequence",
        ),
        (
            "aliased tasks",
            text.replace("helper=102/1002", "helper=101/1002"),
            "creator/helper identity aliased",
        ),
        (
            "missing task",
            text.replace("creator=101/1001", "creator=0/0"),
            "invalid task identity",
        ),
    ] {
        rejected(name, live_observations(&altered), error)?;
    }
    let missing_read = text
        .lines()
        .filter(|line| {
            !(line.starts_with("CONTEXT_ATTRIBUTE_READ origin=actual-task-query tid=101 ")
                && line.contains(" index=2 "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    rejected(
        "missing final read",
        live_observations(&missing_read),
        "missing actual attribute reads or byte count",
    )?;
    let missing_query = text
        .lines()
        .filter(|line| !line.starts_with("CONTEXT_ATTRIBUTE origin=actual-live-query tid=102 "))
        .collect::<Vec<_>>()
        .join("\n");
    rejected(
        "missing second query",
        live_observations(&missing_query),
        "both actual task attribute records are required",
    )?;
    let unbound = format!(
        "{text}CONTEXT_ATTRIBUTE_READ origin=actual-task-query tid=103 start=1003 path=/proc/self/task/103/attr/current index=1 return=0 errno=0 offset=0\n"
    );
    rejected(
        "unbound read",
        live_observations(&unbound),
        "actual read record has an unbound task identity",
    )?;
    let provider = "CONTEXT_PROVIDER_DECISION origin=actual-live-inventory profile=exported-bytes-only reason=valid mode=synthetic\n";
    let equal = "CONTEXT_ATTRIBUTE_DECISION origin=actual-live-query decision=exact-label-bytes mode=synthetic\n";
    let unavailable = "CONTEXT_ATTRIBUTE_DECISION origin=actual-live-query decision=unavailable-label mode=synthetic\n";
    live_decision_records(&format!("{provider}{equal}"), "synthetic", &live)?;
    rejected(
        "wrong attribute decision",
        live_decision_records(&format!("{provider}{unavailable}"), "synthetic", &live),
        "attribute decision disagrees with typed observations",
    )?;
    rejected(
        "contradictory attribute decisions",
        live_decision_records(
            &format!("{provider}{equal}{unavailable}"),
            "synthetic",
            &live,
        ),
        "missing/duplicated context observation: CONTEXT_ATTRIBUTE_DECISION origin=actual-live-query ",
    )?;
    let known = "CONTEXT_PROVIDER_DECISION origin=actual-live-inventory profile=observed-unavailable reason=recognized mode=synthetic\n";
    rejected(
        "wrong provider decision",
        provider_decision_record(known, "actual-live-inventory", "synthetic", live.profile),
        "provider decision disagrees with typed observations",
    )?;
    rejected(
        "contradictory provider decisions",
        provider_decision_record(
            &format!("{provider}{known}"),
            "actual-live-inventory",
            "synthetic",
            live.profile,
        ),
        "missing/duplicated context observation: CONTEXT_PROVIDER_DECISION origin=actual-live-inventory ",
    )?;
    println!(
        "C_PROTOCOL_TYPED_CONTEXT_CONTROLS origin=synthetic nonlegacy_bytes=accepted empty=rejected split_reads=rejected extra_positive_reads=rejected first_read_length=rejected paired_einval=qualified_only invalid_observations=rejected"
    );
    Ok(())
}

const WRAPPER_FIXTURE: &[u8] = br#"
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static unsigned long long start_time(pid_t pid) {
  char path[64], data[4096];
  int n = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
  assert(n > 0 && (size_t)n < sizeof(path));
  FILE *file = fopen(path, "r");
  assert(file != NULL);
  assert(fgets(data, sizeof(data), file) != NULL);
  assert(feof(file) || fgetc(file) == EOF);
  assert(!ferror(file));
  assert(fclose(file) == 0);
  char *cursor = strrchr(data, ')');
  assert(cursor != NULL && cursor[1] == ' ');
  cursor += 2;
  for (int field = 3; field < 22; ++field) {
    cursor = strchr(cursor, ' ');
    assert(cursor != NULL);
    ++cursor;
  }
  char *end;
  errno = 0;
  unsigned long long start = strtoull(cursor, &end, 10);
  assert(errno == 0 && end != cursor && *end == ' ' && start > 0);
  return start;
}
int main(int argc, char **argv) {
  assert(argc == 2);
  if (strcmp(argv[1], "incomplete") == 0) {
    puts("PASS terminal-before-start: no pthread/read/join");
    return 0;
  }
  if (strcmp(argv[1], "abort") == 0) { abort(); }
  if (strcmp(argv[1], "overflow") == 0) {
    char bytes[8192];
    memset(bytes, 'x', sizeof(bytes));
    for (;;) {
      ssize_t n = write(STDOUT_FILENO, bytes, sizeof(bytes));
      assert(n > 0);
    }
  }
  if (strcmp(argv[1], "retirement-order") == 0) {
    pid_t exited = fork();
    assert(exited >= 0);
    if (exited == 0) { _exit(7); }
    siginfo_t info = {0};
    assert(waitid(P_PID, (id_t)exited, &info, WEXITED | WNOWAIT) == 0);
    assert(info.si_pid == exited && info.si_code == CLD_EXITED && info.si_status == 7);
    unsigned long long exited_start = start_time(exited);
    int ready[2];
    assert(pipe(ready) == 0);
    pid_t live = fork();
    assert(live >= 0);
    if (live == 0) {
      assert(close(ready[0]) == 0);
      assert(write(ready[1], "r", 1) == 1);
      assert(close(ready[1]) == 0);
      for (;;) { pause(); }
    }
    assert(close(ready[1]) == 0);
    char byte;
    assert(read(ready[0], &byte, 1) == 1 && byte == 'r');
    assert(close(ready[0]) == 0);
    unsigned long long live_start = start_time(live);
    printf("WRAPPER_RETIREMENT_READY leader=%ld exited=%ld/%llu live=%ld/%llu exited_code=7\n",
           (long)getpid(), (long)exited, exited_start, (long)live, live_start);
    assert(fflush(stdout) == 0);
    return 0;
  }
  assert(strcmp(argv[1], "timeout") == 0);
  pid_t child = fork();
  assert(child >= 0);
  if (child == 0) {
    printf("WRAPPER_TIMEOUT_CHILD pid=%ld parent=%ld\n", (long)getpid(), (long)getppid());
  } else {
    printf("WRAPPER_TIMEOUT_PARENT pid=%ld child=%ld\n", (long)getpid(), (long)child);
  }
  assert(fflush(stdout) == 0);
  for (;;) { pause(); }
}
"#;

fn require_retirement_order(report: &StageReport) -> Result<(), String> {
    report.require_success()?;
    let text = std::str::from_utf8(&report.stdout).map_err(|error| error.to_string())?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() != 5
        || fields[0] != "WRAPPER_RETIREMENT_READY"
        || fields[1] != format!("leader={}", report.leader)
        || fields[4] != "exited_code=7"
        || !report.stderr.is_empty()
        || report.descendants != 2
    {
        return Err(report.diagnostic());
    }
    let identity = |field: &str, prefix: &str| -> Result<(libc::pid_t, u64), String> {
        let (pid, start) = field
            .strip_prefix(prefix)
            .and_then(|value| value.split_once('/'))
            .ok_or_else(|| report.diagnostic())?;
        let pid = pid
            .parse::<libc::pid_t>()
            .map_err(|_| report.diagnostic())?;
        let start = start.parse::<u64>().map_err(|_| report.diagnostic())?;
        if pid <= 0 || start == 0 || pid == report.leader {
            return Err(report.diagnostic());
        }
        Ok((pid, start))
    };
    let exited = identity(fields[2], "exited=")?;
    let live = identity(fields[3], "live=")?;
    if exited.0 == live.0 {
        return Err(report.diagnostic());
    }
    let mut expected = vec![
        (exited.0, exited.1, 7 << 8),
        (live.0, live.1, libc::SIGKILL),
    ];
    let mut actual = report.reaped_descendants.clone();
    expected.sort_unstable();
    actual.sort_unstable();
    if actual != expected {
        return Err(report.diagnostic());
    }
    Ok(())
}

fn compile_command(tree: &PrivateTree, sources: &[&str], output: &str) -> Command {
    let mut command = Command::new("/usr/bin/cc");
    command.args(C_FLAGS);
    for source in sources {
        command.arg(tree.path.join(source));
    }
    command.arg("-ldl").arg("-o").arg(tree.path.join(output));
    command
}

fn exercise(tree: &PrivateTree) -> Result<(), String> {
    for directory in ["src", "tests", "tmp"] {
        DirBuilder::new()
            .mode(0o700)
            .create(tree.path.join(directory))
            .map_err(|error| error.to_string())?;
    }
    for (path, bytes) in [
        ("src/terminal_read.c", HELPER),
        ("src/terminal_read.h", HEADER),
        ("tests/terminal_read_protocol.c", PROTOCOL),
        ("wrapper.c", WRAPPER_FIXTURE),
        (
            "compiler-error.c",
            b"#error RVK_EXPECTED_COMPILER_FAILURE\n".as_slice(),
        ),
    ] {
        tree.write(path, bytes).map_err(|error| error.to_string())?;
    }
    println!(
        "C_PROTOCOL_EMBEDDED helper_bytes={} header_bytes={} protocol_bytes={}",
        HELPER.len(),
        HEADER.len(),
        PROTOCOL.len()
    );
    run_stage(
        tree,
        "compile-protocol",
        &mut compile_command(
            tree,
            &["src/terminal_read.c", "tests/terminal_read_protocol.c"],
            "terminal-read-protocol",
        ),
        false,
    )
    .require_success()?;
    let protocol = run_stage(
        tree,
        "complete-protocol",
        &mut Command::new(tree.path.join("terminal-read-protocol")),
        false,
    );
    protocol.require_success()?;
    if !protocol.stderr.is_empty() {
        return Err(protocol.diagnostic());
    }
    complete_protocol(&protocol.stdout)
        .map_err(|error| format!("{error}\n{}", protocol.diagnostic()))?;
    println!("C_PROTOCOL_NATIVE_TRANSCRIPT_BEGIN");
    print!("{}", String::from_utf8_lossy(&protocol.stdout));
    println!("C_PROTOCOL_NATIVE_TRANSCRIPT_END");
    typed_context_controls()?;
    context_modes(tree)?;

    // These controls exercise this very subprocess owner and parser without
    // modifying or suppressing any source-under-test assertion.
    run_stage(
        tree,
        "compile-wrapper-controls",
        &mut compile_command(tree, &["wrapper.c"], "wrapper"),
        false,
    )
    .require_success()?;
    let compiler_error = run_stage(
        tree,
        "expected-compiler-error",
        &mut compile_command(tree, &["compiler-error.c"], "must-not-build"),
        false,
    );
    if compiler_error.status.and_then(|status| status.code()) != Some(1)
        || compiler_error.monitor_failed
        || !compiler_error.retired
        || !compiler_error.cleanup.is_empty()
        || !String::from_utf8_lossy(&compiler_error.stderr)
            .contains("RVK_EXPECTED_COMPILER_FAILURE")
    {
        return Err(compiler_error.diagnostic());
    }
    let incomplete = run_stage(
        tree,
        "expected-incomplete-aggregate",
        Command::new(tree.path.join("wrapper")).arg("incomplete"),
        false,
    );
    incomplete.require_success()?;
    if incomplete.stdout != format!("{}\n", PASS_BEFORE_CONTEXT[0]).as_bytes()
        || !incomplete.stderr.is_empty()
    {
        return Err(incomplete.diagnostic());
    }
    if complete_protocol(&incomplete.stdout).is_ok() {
        return Err("incomplete child transcript was accepted".into());
    }
    let aborted = run_stage(
        tree,
        "expected-aborted-aggregate",
        Command::new(tree.path.join("wrapper")).arg("abort"),
        false,
    );
    if aborted.status.and_then(|status| status.signal()) != Some(libc::SIGABRT)
        || aborted.monitor_failed
        || !aborted.retired
        || !aborted.cleanup.is_empty()
    {
        return Err(aborted.diagnostic());
    }
    let timeout = run_stage(
        tree,
        "expected-timeout-descendant",
        Command::new(tree.path.join("wrapper")).arg("timeout"),
        true,
    );
    if !timeout.timed_out
        || !timeout.retired
        || !timeout.cleanup.is_empty()
        || timeout.descendants != 1
        || timeout.status.and_then(|status| status.signal()) != Some(libc::SIGKILL)
    {
        return Err(timeout.diagnostic());
    }
    let overflow = run_stage(
        tree,
        "expected-output-overflow",
        Command::new(tree.path.join("wrapper")).arg("overflow"),
        false,
    );
    if overflow.primary.as_deref()
        != Some("capture: child stream exceeded 2 MiB; transcript is incomplete")
        || !overflow.monitor_failed
        || !overflow.stdout_overflow
        || overflow.stderr_overflow
        || overflow.stdout.len() != STREAM_CAP
        || !overflow.stderr.is_empty()
        || !overflow.retired
        || !overflow.cleanup.is_empty()
        || overflow.status.and_then(|status| status.signal()) != Some(libc::SIGKILL)
    {
        return Err(overflow.diagnostic());
    }
    let retirement = run_stage(
        tree,
        "expected-disarmed-group-retirement",
        Command::new(tree.path.join("wrapper")).arg("retirement-order"),
        false,
    );
    require_retirement_order(&retirement)?;
    print!("{}", String::from_utf8_lossy(&retirement.stdout));
    let transcript = std::str::from_utf8(&protocol.stdout).unwrap();
    for (name, replacement) in [
        ("missing", String::new()),
        (
            "altered",
            PLT_DECODER_CONTROL.replace("endbr64=1", "endbr64=0"),
        ),
    ] {
        let altered = transcript.replacen(PLT_DECODER_CONTROL, &replacement, 1);
        if !complete_protocol(altered.as_bytes()).is_err_and(|error| {
            error == format!("missing/duplicated context qualification: {PLT_DECODER_CONTROL}")
        }) {
            return Err(format!("{name} decoder control record was not rejected"));
        }
    }
    // Mutate the actual successful observation, keeping each phase's two
    // records coherent. Only the before/after byte-and-length proof can reject
    // the valid alternate layout or changed displacement below.
    let after_plt = one_record(transcript, "CONTEXT_READ_PLT phase=after-join ")?;
    let after_dispatch = one_record(transcript, "CONTEXT_READ_DISPATCH phase=after-join ")?;
    let encoded = record_field(after_plt, "plt_hex")?;
    let length = encoded.len() / 2;
    let mut changed = encoded.as_bytes().to_vec();
    let last = changed.last_mut().ok_or("missing live PLT bytes")?;
    *last = if *last == b'0' { b'1' } else { b'0' };
    let changed = String::from_utf8(changed).unwrap();
    let other_form = if length == 6 {
        format!("f30f1efa{encoded}")
    } else {
        encoded[8..].to_string()
    };
    for (name, new_bytes) in [("changed-byte", changed), ("changed-length", other_form)] {
        let change_record = |record: &str| {
            record.replacen(
                &format!("plt_hex={encoded}"),
                &format!("plt_hex={new_bytes}"),
                1,
            )
        };
        let altered = transcript
            .replacen(after_plt, &change_record(after_plt), 1)
            .replacen(after_dispatch, &change_record(after_dispatch), 1);
        if !complete_protocol(altered.as_bytes()).is_err_and(|error| {
            error == "live read PLT address, length or bytes changed between observations"
        }) {
            return Err(format!(
                "{name} PLT stability control was not rejected by its proof"
            ));
        }
    }
    let truncated = transcript.replacen(
        after_plt,
        &after_plt.replacen(
            &format!("plt_hex={encoded}"),
            &format!("plt_hex={}", &encoded[..encoded.len() - 2]),
            1,
        ),
        1,
    );
    if !complete_protocol(truncated.as_bytes())
        .is_err_and(|error| error == "unsupported or incomplete live read PLT bytes")
    {
        return Err("truncated live PLT record was not rejected by its proof".into());
    }
    println!(
        "C_PROTOCOL_PLT_CONTROLS missing_decoder=rejected altered_decoder=rejected changed_byte=rejected changed_length=rejected truncated=rejected"
    );
    let completion = context_pass(live_observations(transcript)?.decision);
    let reordered = transcript
        .replacen(PASS_BEFORE_CONTEXT[0], "WRAPPER_SWAP", 1)
        .replacen(PASS_BEFORE_CONTEXT[1], PASS_BEFORE_CONTEXT[0], 1)
        .replacen("WRAPPER_SWAP", PASS_BEFORE_CONTEXT[1], 1);
    for (name, altered) in [
        ("unexpected", format!("{transcript}\nPASS unexpected\n")),
        (
            "duplicate",
            format!("{transcript}\n{}\n", PASS_BEFORE_CONTEXT[0]),
        ),
        ("reordered", reordered),
        ("missing-context", transcript.replacen(&completion, "", 1)),
        ("pass-colon", format!("{transcript}\nPASS:unexpected\n")),
        ("pass-tab", format!("{transcript}\nPASS\tunexpected\n")),
        ("pass-bare", format!("{transcript}\nPASS\n")),
    ] {
        if complete_protocol(altered.as_bytes()).is_ok() {
            return Err(format!("{name} PASS record control was accepted"));
        }
    }
    println!(
        "C_PROTOCOL_WRAPPER_CONTROLS incomplete=rejected abort=rejected compiler_error=rejected timeout=rejected descendant_retired=1 output_overflow=rejected unexpected=rejected duplicate=rejected reordered=rejected missing_context=rejected pass_colon=rejected pass_tab=rejected pass_bare=rejected disarmed_group_retired=2"
    );
    Ok(())
}

#[test]
fn c_terminal_read_protocol_preserves_lifetime_and_context() {
    let mut subreaper = Subreaper::new().expect("enable isolated test-process child subreaper");
    let mut tree = PrivateTree::new().expect("create exclusive native protocol directory");
    let mut errors = Vec::new();
    if let Err(primary) = exercise(&tree) {
        errors.push(primary);
    }
    if let Err(error) = tree.remove() {
        errors.push(format!("temporary-directory cleanup: {error}"));
    }
    if let Err(error) = subreaper.restore() {
        errors.push(format!("restore child subreaper: {error}"));
    }
    if !errors.is_empty() {
        panic!("{}", errors.join("\nadditional cleanup: "));
    }
}
