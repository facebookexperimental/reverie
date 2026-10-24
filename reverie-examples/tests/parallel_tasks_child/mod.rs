/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Test-only ownership for the parallel workload's tracer and tracees.
//!
//! This follows safeptrace's bounded-subprocess test helper: observe exit with a
//! pidfd, drain both pipes while waiting, and retain the unreaped process-group
//! leader through cleanup. The group-membership check follows the DBT launcher.
//! The fixed workload creates threads but never leaves this process group;
//! Reverie also installs EXITKILL on its tracees. This is not an arbitrary
//! daemon or group-escaping command runner.

use std::fs;
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const CHILD_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const CAPTURE_LIMIT: usize = 64 * 1024;

struct Capture<R> {
    pipe: R,
    bytes: Vec<u8>,
    eof: bool,
    overflow: bool,
}

impl<R: Read + AsRawFd> Capture<R> {
    fn new(pipe: R) -> io::Result<Self> {
        // SAFETY: the descriptor belongs to this pipe and remains open.
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pipe,
            bytes: Vec::new(),
            eof: false,
            overflow: false,
        })
    }

    fn drain_once(&mut self) -> io::Result<()> {
        // One bounded read per pipe per poll prevents a noisy writer from
        // starving the other pipe or the deadline check.
        let mut buffer = [0; 8192];
        match self.pipe.read(&mut buffer) {
            Ok(0) => self.eof = true,
            Ok(count) => {
                let keep = count.min(CAPTURE_LIMIT - self.bytes.len());
                self.bytes.extend_from_slice(&buffer[..keep]);
                self.overflow |= keep < count;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

struct OwnedGroup {
    child: Child,
    pidfd: Option<OwnedFd>,
    reaped: bool,
    cleanup_deadline: Option<Instant>,
}

impl OwnedGroup {
    fn spawn(command: &mut Command) -> io::Result<Self> {
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut group = Self {
            child,
            pidfd: None,
            reaped: false,
            cleanup_deadline: None,
        };
        // The owned, unreaped child pins its PID even if it exits before open.
        // SAFETY: pidfd_open takes a PID and zero flags, with no pointer operand.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, group.child.id(), 0) } as i32;
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pidfd_open returned a new owned descriptor.
        group.pidfd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(group)
    }

    fn exited(&self) -> io::Result<bool> {
        if let Some(pidfd) = &self.pidfd {
            let mut pollfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd names one valid descriptor and writable record.
            let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            return Ok(result == 1 && pollfd.revents & libc::POLLIN != 0);
        }

        // Only setup-error cleanup needs this fallback. WNOWAIT preserves the
        // process-group anchor just as the normal pidfd observation does.
        // SAFETY: waitid receives a zero-initialized writable siginfo record.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn retire(&mut self) -> io::Result<ExitStatus> {
        // Error unwinding may enter Drop after an explicit cleanup refusal.
        // Preserve the original cleanup deadline in that case.
        let deadline = *self
            .cleanup_deadline
            .get_or_insert_with(|| Instant::now() + CLEANUP_TIMEOUT);
        let group = i32::try_from(self.child.id()).expect("child PID fits pid_t");
        // SAFETY: process_group(0) created this group; its unreaped leader
        // still pins the PID/PGID. No group signal is sent after reaping.
        let killed = unsafe { libc::kill(-group, libc::SIGKILL) };
        if killed == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        loop {
            let live = live_group_threads(group)?;
            if self.exited()? && live.is_empty() {
                return self.reap_retired();
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "parallel_tasks cleanup unverified for group {group}; live TIDs={live:?}"
                    ),
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    // Call only after observing leader exit and no live group members. Keep
    // natural retirement separate from cleanup that had to send SIGKILL.
    fn reap_retired(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if !self.reaped
            && let Err(error) = self.retire()
        {
            eprintln!("parallel_tasks owned-child cleanup failed: {error}");
        }
    }
}

fn read_stat(path: &std::path::Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(stat) => Ok(Some(stat)),
        // procfs can open stat before a task is released and then return ESRCH
        // from the read. Both errors mean this entry has disappeared.
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn stat_fields(stat: &[u8]) -> io::Result<(&str, i32)> {
    // comm can contain arbitrary bytes, spaces and parentheses. Only the
    // kernel's numeric/state suffix is text that this check needs to parse.
    let name_end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| io::Error::other("malformed process stat name"))?;
    let tail = std::str::from_utf8(&stat[name_end + 1..])
        .map_err(|_| io::Error::other("malformed process stat fields"))?;
    let mut fields = tail.split_ascii_whitespace();
    let state = fields
        .next()
        .ok_or_else(|| io::Error::other("missing process state"))?;
    let group = fields
        .nth(1)
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| io::Error::other("missing process group"))?;
    Ok((state, group))
}

fn live_group_threads(group: i32) -> io::Result<Vec<u32>> {
    let mut live = Vec::new();
    for process in fs::read_dir("/proc")? {
        let process = process?;
        if process
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .is_err()
        {
            continue;
        }
        let Some(stat) = read_stat(&process.path().join("stat"))? else {
            continue;
        };
        if stat_fields(&stat)?.1 != group {
            continue;
        }
        let tasks = match fs::read_dir(process.path().join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        // A group leader can be a zombie while another thread is alive.
        for task in tasks {
            let task = match task {
                Ok(task) => task,
                // The directory may lose its task after read_dir succeeds.
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            };
            let Some(stat) = read_stat(&task.path().join("stat"))? else {
                continue;
            };
            let (state, _) = stat_fields(&stat)?;
            if !matches!(state, "Z" | "X") {
                let tid = task
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| io::Error::other("invalid task ID"))?;
                live.push(tid);
            }
        }
    }
    Ok(live)
}

pub(super) fn output(command: &mut Command) -> io::Result<Output> {
    let mut group = OwnedGroup::spawn(command)?;
    let mut stdout = Capture::new(group.child.stdout.take().expect("piped stdout"))?;
    let mut stderr = Capture::new(group.child.stderr.take().expect("piped stderr"))?;
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let process_group = i32::try_from(group.child.id()).expect("child PID fits pid_t");
    let timed_out = loop {
        stdout.drain_once()?;
        stderr.drain_once()?;
        if group.exited()?
            && live_group_threads(process_group)?.is_empty()
            && stdout.eof
            && stderr.eof
        {
            break false;
        }
        if Instant::now() >= deadline {
            break true;
        }
        thread::sleep(POLL_INTERVAL);
    };
    // This result is deliberately distinct from timeout detection. Neither
    // SIGKILL delivery nor ESRCH alone establishes that the tracees retired.
    // A successful leader that leaves descendants or pipe writers behind is
    // still a failure: never turn cleanup intervention into a passing result.
    let retirement = if timed_out {
        group.retire()
    } else {
        group.reap_retired()
    };
    let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
    while !stdout.eof || !stderr.eof {
        stdout.drain_once()?;
        stderr.drain_once()?;
        if Instant::now() >= drain_deadline {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    if timed_out
        || retirement.is_err()
        || !stdout.eof
        || !stderr.eof
        || stdout.overflow
        || stderr.overflow
    {
        return Err(io::Error::other(format!(
            "parallel_tasks did not finish cleanly; possible thread serialization; \
             deadline={CHILD_TIMEOUT:?}, timed_out={timed_out}, retirement={retirement:?}, \
             stdout_eof={}, stderr_eof={}, stdout_overflow={}, stderr_overflow={}\nstdout:\n{}\nstderr:\n{}",
            stdout.eof,
            stderr.eof,
            stdout.overflow,
            stderr.overflow,
            String::from_utf8_lossy(&stdout.bytes),
            String::from_utf8_lossy(&stderr.bytes),
        )));
    }
    Ok(Output {
        status: retirement?,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}
