// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Dormant-seize exec supervisor skeleton.
//!
//! The child self-stops before its initial exec without calling
//! `PTRACE_TRACEME`; the parent seizes it with `EXITKILL`,
//! `TRACEEXEC`, and `TRACESYSGOOD`, resumes it, drains only the
//! initial exec syscall return, and detaches. No runtime image is
//! mapped and no successor is armed:
//! after detach the new image runs unsupervised. This proves only
//! the launch/event/detach plumbing and its cost floor.

use std::time::Duration;
use std::time::Instant;

use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::Options;
use safeptrace::Running;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::Wait;

use super::ChildOwner;
use super::CleanupReceipt;
use super::CleanupState;
use super::LaunchFailure;
use super::Result;
use super::child::PreparedExec;
use super::trace;

/// Whether the dormant supervisor participates in a launch at all.
/// The default keeps every existing launch path unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SupervisorMode {
    /// No seize, no supervisor thread obligation; spawn refuses.
    #[default]
    Disabled,
    /// Seize before the initial exec, catch that exec event, detach.
    DormantSeize,
}

/// Completed detached run: the observed exec, its terminal status,
/// measured spawn-to-after-detach interval, and confirmed cleanup
/// observations.
#[derive(Debug)]
pub struct SupervisorOutcome {
    /// Actual child identity.
    pub pid: safeptrace::Pid,
    /// Former tid reported by the kernel exec event.
    pub former_tid: safeptrace::Pid,
    /// Actual terminal status from the retained physical wait.
    pub status: ExitStatus,
    /// Spawn-entry to just-after-detach interval. It includes fork,
    /// seize, the initial exec event, its one-exit drain, and detach;
    /// it is not a seize-only latency sample.
    pub spawn_to_after_detach: Duration,
    /// Spawn-entry to confirmed terminal wait interval.
    pub total: Duration,
    /// Cleanup observations, including confirmed retirement.
    pub cleanup: CleanupState,
}

/// A detached child whose exec event was caught. Retains the physical
/// owner until [`DetachedSupervisor::wait`] (or drop, which retires
/// through the owner's bounded best-effort cleanup).
#[must_use = "retain the detached supervisor through terminal wait or cancellation"]
pub struct DetachedSupervisor<'fd> {
    pid: safeptrace::Pid,
    former_tid: safeptrace::Pid,
    spawn_to_after_detach: Duration,
    started: Instant,
    owner: ChildOwner<'fd>,
    running: Option<Running>,
    receipt: CleanupReceipt,
}

impl std::fmt::Debug for DetachedSupervisor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetachedSupervisor")
            .field("pid", &self.pid)
            .field("former_tid", &self.former_tid)
            .field("spawn_to_after_detach", &self.spawn_to_after_detach)
            .field("owner", &self.owner)
            .field("detached", &self.running.is_some())
            .field("cleanup", &self.receipt.snapshot())
            .finish()
    }
}

impl<'fd> DetachedSupervisor<'fd> {
    /// The actual child identity.
    pub fn pid(&self) -> safeptrace::Pid {
        self.pid
    }

    /// Former tid from the caught kernel exec event.
    pub fn former_tid(&self) -> safeptrace::Pid {
        self.former_tid
    }

    /// Same-generation shared signal/observation handle; it cannot wait here.
    pub fn cancellation_handle(&self) -> safeptrace::TerminalCleanup {
        self.owner.cancellation_handle()
    }

    /// Take the original child's parent pipe endpoints once. Captured
    /// streams must be drained concurrently with the wait below.
    pub fn take_parent_stdio(&mut self) -> Option<reverie::process::ParentStdio> {
        self.owner._request.take_parent_stdio()
    }

    /// Wait for this same detached generation on the original ptracer.
    pub fn wait(mut self) -> std::result::Result<SupervisorOutcome, Box<DetachedWaitFailure<'fd>>> {
        let running = self.running.take().expect("detached running state");
        match self.owner.wait(running) {
            Ok(status) => Ok(SupervisorOutcome {
                pid: self.pid,
                former_tid: self.former_tid,
                status,
                spawn_to_after_detach: self.spawn_to_after_detach,
                total: self.started.elapsed(),
                cleanup: self.receipt.snapshot(),
            }),
            Err(failure) => Err(Box::new(DetachedWaitFailure {
                failure,
                pid: self.pid,
            })),
        }
    }
}

/// A detached wait that did not complete. The retained launch failure
/// keeps any unresolved physical owner for retry; this wrapper only
/// names the child whose detached wait failed.
#[derive(Debug)]
pub struct DetachedWaitFailure<'fd> {
    /// The retained launch failure from the physical owner.
    pub failure: LaunchFailure<'fd>,
    /// The detached child whose terminal wait failed.
    pub pid: safeptrace::Pid,
}

impl std::fmt::Display for DetachedWaitFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exec supervisor detached wait for {:?}: {}",
            self.pid, self.failure
        )
    }
}
impl std::error::Error for DetachedWaitFailure<'_> {}

/// The handshake signal is the child's own `tgkill(SIGSTOP)`: its
/// siginfo must name that exact cause and sender. Anything else is an
/// unrelated stop signal whose provenance this supervisor may not
/// claim, suppress, or forward on trust.
#[allow(unsafe_code)]
fn require_owned_handshake_sigstop(task: &Stopped, pid: safeptrace::Pid) -> Result<()> {
    let info = task.getsiginfo()?;
    // SAFETY: this is the just-read Linux siginfo for the current stop.
    let sender = unsafe { info.si_pid() };
    if info.si_signo != libc::SIGSTOP || info.si_code != libc::SI_TKILL || sender != pid.as_raw() {
        return Err(format!(
            "exec supervisor encountered unowned SIGSTOP before exec: si_code={}, sender={sender}",
            info.si_code
        )
        .into());
    }
    Ok(())
}

/// Wait for the child's handshake stop after seize. A group stop
/// leaves the signal-delivery phase outstanding; a signal-delivery
/// stop is accepted only if its siginfo proves it is the child's
/// own handshake. Every other pre-exec stop fails closed rather
/// than being silently forwarded or dropped. Bounded only by the
/// caller's external deadline, like every synchronous exec-stop wait.
fn wait_initial_stop(running: Running, pid: safeptrace::Pid) -> Result<(Stopped, bool)> {
    match trace::wait(running)? {
        Wait::Stopped(task, event) => match event {
            Event::Stop => Ok((task, true)),
            Event::Signal(Signal::SIGSTOP) => {
                require_owned_handshake_sigstop(&task, pid)?;
                Ok((task, false))
            }
            Event::Signal(signal) => Err(format!(
                "exec supervisor encountered unexpected signal before exec: {signal:?}"
            )
            .into()),
            Event::RawSignal(raw) => Err(format!(
                "exec supervisor encountered unexpected raw signal before exec: {raw}"
            )
            .into()),
            Event::Exec(_) => {
                Err("exec supervisor received an exec event before its seize stop".into())
            }
            other_event => Err(format!(
                "exec supervisor encountered unexpected stop before exec: {other_event:?}"
            )
            .into()),
        },
        other => Err(format!("exec supervisor expected its seize stop, got {other:?}").into()),
    }
}

/// Wait for the genuine exec event, verify it names this child and the
/// launcher's own `execve`, then detach. The new image runs unarmed.
/// Consume the seize stop, resume suppressed, and detach at the
/// exec event. Runs entirely on the original ptracer thread.
fn catch_initial_exec(
    owner: &mut ChildOwner<'_>,
    running: Running,
    pid: safeptrace::Pid,
    started: Instant,
    before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
) -> Result<(Running, safeptrace::Pid, Duration)> {
    owner._thread = Some(owner.generation.ptracer_thread_guard()?);
    let (initial, group_stop) = wait_initial_stop(running, pid)?;
    before_initial_resume(pid);
    // A group stop (Event::Stop) is not cleared by suppressing the
    // signal: restart with SIGCONT so no job-control stop remains
    // pending across the exec. A signal-delivery stop is suppressed.
    let running = if group_stop {
        initial.resume(Some(Signal::SIGCONT))?
    } else {
        initial.resume(None)?
    };
    let (running, former) = wait_exec_detach(running, pid, group_stop)?;
    Ok((running, former, started.elapsed()))
}

fn wait_exec_detach(
    mut running: Running,
    pid: safeptrace::Pid,
    mut handshake_signal_pending: bool,
) -> Result<(Running, safeptrace::Pid)> {
    loop {
        match trace::wait(running)? {
            Wait::Stopped(task, Event::Exec(former)) => {
                if former != pid {
                    return Err(format!(
                        "exec supervisor expected exec of {pid:?}, got former {former:?}"
                    )
                    .into());
                }
                let at_event = task.getregs()?;
                if at_event.orig_rax != libc::SYS_execve as u64 {
                    return Err("exec supervisor exec event did not originate in execve".into());
                }
                // Drain only the exec syscall return, like ExecStop,
                // so detach leaves the new image at its entry with no
                // in-flight syscall or pending handshake stop.
                let (task, event) = trace::stopped(task.syscall(None)?, "supervisor exec drain")?;
                let info = task.getsyscallinfo()?;
                let entry = task.getregs()?;
                if !matches!(
                    info.operation,
                    safeptrace::SyscallInfoOp::Exit {
                        return_value: 0,
                        is_error: false
                    }
                ) || entry.rip != at_event.rip
                    || entry.rsp != at_event.rsp
                {
                    return Err(format!(
                        "exec supervisor exec return did not drain: event={event:?} info={info:?}"
                    )
                    .into());
                }
                // Detach with SIGCONT so any residual group-stop state
                // from the handshake cannot park the detached guest.
                let running = task.detach(Some(Signal::SIGCONT))?;
                return Ok((running, former));
            }
            Wait::Stopped(task, Event::Signal(Signal::SIGSTOP)) => {
                // Only the one still-pending handshake signal may be
                // suppressed here, and only if siginfo proves the
                // child sent it to itself. A fresh SIGSTOP from any
                // other sender is somebody else's process control and
                // must fail this launch closed, not be swallowed.
                if !handshake_signal_pending {
                    return Err(
                        "exec supervisor encountered unowned SIGSTOP before exec: no handshake signal was pending"
                            .into(),
                    );
                }
                require_owned_handshake_sigstop(&task, pid)?;
                handshake_signal_pending = false;
                running = task.resume(None)?;
            }
            Wait::Stopped(_task, Event::Signal(signal)) => {
                return Err(format!(
                    "exec supervisor encountered unexpected signal before exec: {signal:?}"
                )
                .into());
            }
            Wait::Stopped(_task, Event::RawSignal(raw)) => {
                return Err(format!(
                    "exec supervisor encountered unexpected raw signal before exec: {raw}"
                )
                .into());
            }
            Wait::Stopped(_task, other_event) => {
                return Err(format!(
                    "exec supervisor encountered unexpected stop before exec: {other_event:?}"
                )
                .into());
            }
            other => {
                return Err(format!(
                    "exec supervisor child reached {other:?} before an exec event"
                )
                .into());
            }
        }
    }
}

/// Dormant-seize supervisor entry point. See module docs.
pub struct Supervisor;

impl Supervisor {
    /// Clone one owned child, seize it before its initial exec, catch
    /// that exec event, and detach. Caller must retain an external
    /// physical deadline for synchronous waits. With
    /// [`SupervisorMode::Disabled`] (the default) this refuses before
    /// any child is created; the receipt is left unclaimed.
    pub fn spawn<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        mode: SupervisorMode,
    ) -> std::result::Result<DetachedSupervisor<'fd>, LaunchFailure<'fd>> {
        Self::spawn_inner(request, receipt, mode, &mut |_| {})
    }

    fn spawn_inner<'fd>(
        mut request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        mode: SupervisorMode,
        before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
    ) -> std::result::Result<DetachedSupervisor<'fd>, LaunchFailure<'fd>> {
        if mode == SupervisorMode::Disabled {
            return Err(LaunchFailure {
                error: "exec supervisor is disabled".into(),
                receipt,
                owner: None,
                pending: None,
                parent_stdio: None,
            });
        }
        let started = Instant::now();
        if !receipt.claim() {
            return Err(LaunchFailure {
                error: "exec supervisor cleanup receipt already used".into(),
                receipt,
                owner: None,
                pending: None,
                parent_stdio: None,
            });
        }
        request = request.with_supervisor_seize();
        let mut pending = match request.fork(receipt.clone()) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(LaunchFailure {
                    error: format!("loader_clone_pidfd_refused: {error}").into(),
                    receipt,
                    owner: None,
                    pending: None,
                    parent_stdio: None,
                });
            }
        };
        #[cfg(feature = "loader-private-runtime")]
        let birth_pidfd = match pending.duplicate_birth_pidfd() {
            Ok(fd) => fd,
            Err(error) => {
                let parent_stdio = request.take_parent_stdio();
                pending.retire();
                let deferred = pending.is_owned().then(|| Box::new((pending, request)));
                return Err(LaunchFailure {
                    error: format!("exec_stop_birth_pidfd_retention_failed: {error}").into(),
                    receipt,
                    owner: None,
                    pending: deferred,
                    parent_stdio,
                });
            }
        };
        let pid = pending.pid();
        let running = match Running::seize_on_ptracer_thread(
            pid,
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXEC
                | Options::PTRACE_O_TRACESYSGOOD,
        ) {
            Ok(running) => running,
            Err(error) => {
                let parent_stdio = request.take_parent_stdio();
                pending.retire();
                let deferred = pending.is_owned().then(|| Box::new((pending, request)));
                return Err(LaunchFailure {
                    error: error.into(),
                    receipt,
                    owner: None,
                    pending: deferred,
                    parent_stdio,
                });
            }
        };
        let cleanup = running.terminal_cleanup_on_ptracer_thread();
        let generation = running.generation();
        // No fallible operation between installing the original
        // generation's cleanup owner and disarming the atomic
        // pre-registration pidfd owner (same invariant as ExecStop).
        let mut owner = ChildOwner {
            cleanup,
            generation,
            #[cfg(feature = "loader-private-runtime")]
            birth_pidfd,
            _thread: None,
            _request: request,
            receipt: receipt.clone(),
            complete: false,
        };
        pending.transfer_to_ptracer();
        let result = catch_initial_exec(&mut owner, running, pid, started, before_initial_resume);
        match result {
            Ok((running, former_tid, spawn_to_after_detach)) => Ok(DetachedSupervisor {
                pid,
                former_tid,
                spawn_to_after_detach,
                started,
                owner,
                running: Some(running),
                receipt,
            }),
            Err(error) => {
                let parent_stdio = owner._request.take_parent_stdio();
                let deferred = owner.cancel().err();
                Err(LaunchFailure {
                    error,
                    receipt,
                    owner: deferred,
                    pending: None,
                    parent_stdio,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::*;

    fn request(program: &str, arguments: &[&str]) -> PreparedExec<'static> {
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        PreparedExec::new(Path::new(program), &arguments, &[], None, Vec::new()).unwrap()
    }

    #[test]
    fn supervisor_disabled_refuses_before_fork() {
        let receipt = CleanupReceipt::default();
        let failure = Supervisor::spawn(
            request("/bin/true", &["true"]),
            receipt.clone(),
            SupervisorMode::Disabled,
        )
        .unwrap_err();
        assert!(failure.error.to_string().contains("disabled"));
        assert!(!receipt.snapshot().child_created);
    }

    #[test]
    fn supervisor_catches_initial_exec_and_detaches() {
        let detached = Supervisor::spawn(
            request("/bin/true", &["true"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
        )
        .unwrap();
        assert_eq!(detached.former_tid(), detached.pid());
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert_eq!(outcome.former_tid, outcome.pid);
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn supervisor_guest_runs_unarmed_after_detach() {
        // The shell's own exec is the caught initial exec; its later
        // exec to /bin/false happens after detach, unsupervised.
        let detached = Supervisor::spawn(
            request("/bin/sh", &["sh", "-c", "exec /bin/false"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
        )
        .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(1));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn supervisor_missing_program_fails_before_exec_event() {
        let failure = Supervisor::spawn(
            request("/nonexistent-s2a-supervisor-target", &["absent"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
        )
        .unwrap_err();
        assert!(
            failure.error.to_string().contains("before an exec event"),
            "unexpected failure: {}",
            failure.error
        );
    }

    #[test]
    fn supervisor_parent_origin_sigstop_after_handshake_is_not_swallowed() {
        let mut injected_pid = None;
        let failure = Supervisor::spawn_inner(
            request("/bin/true", &["true"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
            &mut |pid| {
                injected_pid = Some(pid);
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid.as_raw()),
                    nix::sys::signal::Signal::SIGSTOP,
                )
                .unwrap();
            },
        )
        .unwrap_err();
        let pid = injected_pid.expect("initial-resume hook ran");
        assert!(
            failure.error.to_string().contains("unowned SIGSTOP"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }
}
