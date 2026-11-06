// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Dormant-seize exec supervisor.
//!
//! The child self-stops before its initial exec without calling
//! `PTRACE_TRACEME`; the parent seizes it with `EXITKILL`,
//! `TRACEEXEC`, and `TRACESYSGOOD` and resumes it. Two modes share
//! that seize and the initial-handshake discipline:
//!
//! * [`Supervisor::spawn`] drains only the initial exec syscall
//!   return and detaches. No runtime image is mapped and no
//!   successor is armed: after detach the new image runs
//!   unsupervised. This proves only the launch/event/detach
//!   plumbing and its cost floor.
//! * [`Supervisor::spawn_watched`] stays seized while the guest
//!   runs. Every caught exec event is drained and captured exactly
//!   like the first-image exec stop and handed to the caller as a
//!   [`SuccessorStop`]. The caller's hook re-runs whatever
//!   stopped-image work its policy requires (map, filter, handover,
//!   admission) and returns the stop; the supervisor then restores
//!   the exact original entry context and either resumes the guest
//!   still seized for the next exec or detaches it through the
//!   production release transition. This module keeps no admission
//!   or ticket state of its own: successor admission belongs
//!   entirely to the caller's hook.
//!
//! While watched, guest signal deliveries are forwarded unchanged
//! and group stops are resumed with `SIGCONT` (a supervised guest
//! is not job-controlled). Only the initial pre-exec window keeps
//! the stricter handshake ownership proof. The watched path
//! follows one thread-group leader: an exec event whose former
//! tid is not the watched leader fails closed; fork-following and
//! thread supervision are not part of this module.

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
use super::EntryContext;
use super::ExecBoundary;
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

/// Consume the seize stop and resume toward the initial exec. A group
/// stop leaves the child's handshake signal still to be delivered;
/// the returned flag says that one owned signal may still be
/// suppressed before the first exec. Runs entirely on the original
/// ptracer thread.
fn consume_handshake(
    owner: &mut ChildOwner<'_>,
    running: Running,
    pid: safeptrace::Pid,
    before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
) -> Result<(Running, bool)> {
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
    Ok((running, group_stop))
}

/// Wait for the genuine exec event, verify it names this child and the
/// launcher's own `execve`, then detach. The new image runs unarmed.
fn catch_initial_exec(
    owner: &mut ChildOwner<'_>,
    running: Running,
    pid: safeptrace::Pid,
    started: Instant,
    before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
) -> Result<(Running, safeptrace::Pid, Duration)> {
    let (running, group_stop) = consume_handshake(owner, running, pid, before_initial_resume)?;
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
                // Drain only the exec syscall return, like ExecStop,
                // so detach leaves the new image at its entry with no
                // in-flight syscall or pending handshake stop. The
                // captured context is discarded: this mode detaches
                // without touching the new image.
                let (task, _context, _boundary) = super::drain_and_capture(task, former)?;
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

/// Assemble a launch failure from a retained owner: preserve any
/// parent stdio, cancel, and keep an unconfirmed owner for retry.
fn launch_failure<'fd>(
    mut owner: ChildOwner<'fd>,
    receipt: CleanupReceipt,
    error: Box<dyn std::error::Error>,
) -> LaunchFailure<'fd> {
    let parent_stdio = owner._request.take_parent_stdio();
    let deferred = owner.cancel().err();
    LaunchFailure {
        error,
        receipt,
        owner: deferred,
        pending: None,
        parent_stdio,
    }
}

/// Claim the receipt, clone one owned child and seize it before its
/// initial exec. Shared by the detached and watched entry points.
fn seize_child<'fd>(
    mut request: PreparedExec<'fd>,
    receipt: CleanupReceipt,
) -> std::result::Result<
    (
        ChildOwner<'fd>,
        Running,
        safeptrace::Pid,
        Instant,
        CleanupReceipt,
    ),
    LaunchFailure<'fd>,
> {
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
        Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_TRACESYSGOOD,
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
    let owner = ChildOwner {
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
    Ok((owner, running, pid, started, receipt))
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
        request: PreparedExec<'fd>,
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
        let (mut owner, running, pid, started, receipt) = seize_child(request, receipt)?;
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
            Err(error) => Err(launch_failure(owner, receipt, error)),
        }
    }

    /// Clone one owned child, seize it before its initial exec, and
    /// stay seized while it runs. Each [`WatchedSupervisor::wait_next`]
    /// returns the next caught exec as a [`SuccessorStop`] (drained
    /// and captured before any guest instruction of the new image)
    /// or the terminal outcome. Caller must retain an external
    /// physical deadline for synchronous waits.
    pub fn spawn_watched<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
    ) -> std::result::Result<WatchedSupervisor<'fd>, LaunchFailure<'fd>> {
        Self::spawn_watched_inner(request, receipt, &mut |_| {})
    }

    fn spawn_watched_inner<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
    ) -> std::result::Result<WatchedSupervisor<'fd>, LaunchFailure<'fd>> {
        let (mut owner, running, pid, started, receipt) = seize_child(request, receipt)?;
        match consume_handshake(&mut owner, running, pid, before_initial_resume) {
            Ok((running, handshake_signal_pending)) => Ok(WatchedSupervisor {
                pid,
                started,
                owner,
                running: Some(running),
                receipt,
                pre_first_exec: true,
                handshake_signal_pending,
                execs_seen: 0,
            }),
            Err(error) => Err(launch_failure(owner, receipt, error)),
        }
    }
}

/// Terminal outcome of a watched run: actual status from the retained
/// physical wait, how many exec events were caught, and confirmed
/// cleanup observations.
#[derive(Debug)]
pub struct WatchedOutcome {
    /// Actual child identity.
    pub pid: safeptrace::Pid,
    /// Actual terminal status from the retained physical wait.
    pub status: ExitStatus,
    /// Exec events caught and handed out as successor stops.
    pub execs_seen: u64,
    /// Spawn-entry to confirmed terminal wait interval.
    pub total: Duration,
    /// Cleanup observations, including confirmed retirement.
    pub cleanup: CleanupState,
}

/// One step of a watched run: the next caught exec stop, or the end.
#[derive(Debug)]
pub enum WatchedStep<'fd> {
    /// An exec event was caught, drained and captured; no guest
    /// instruction of the new image has run. Boxed because the stop
    /// carries the full captured entry context and physical owner.
    Exec(Box<SuccessorStop<'fd>>),
    /// The watched child terminated and retirement was recorded
    /// from the actual terminal wait.
    Finished(WatchedOutcome),
}

enum NextExec {
    Exec(Stopped),
    Finished(ExitStatus),
}

/// Drive the seized guest until its next exec event or terminal
/// exit. Before the first exec, only the one siginfo-proven owned
/// handshake signal may be suppressed; afterwards guest signal
/// deliveries are forwarded unchanged and group stops are resumed
/// with `SIGCONT`.
fn wait_watched(
    mut running: Running,
    pid: safeptrace::Pid,
    pre_first_exec: bool,
    handshake_signal_pending: &mut bool,
) -> Result<NextExec> {
    loop {
        match trace::wait(running)? {
            Wait::Exited(_, status) => return Ok(NextExec::Finished(status)),
            Wait::Stopped(task, Event::Exec(former)) => {
                if former != pid {
                    return Err(format!(
                        "exec supervisor expected exec of {pid:?}, got former {former:?}"
                    )
                    .into());
                }
                return Ok(NextExec::Exec(task));
            }
            Wait::Stopped(task, Event::Signal(Signal::SIGSTOP)) if pre_first_exec => {
                // Same ownership proof as the detached path: only the
                // child's own still-pending handshake signal may be
                // suppressed here. Any other pre-exec SIGSTOP is
                // somebody else's process control and fails closed.
                if !*handshake_signal_pending {
                    return Err(
                        "exec supervisor encountered unowned SIGSTOP before exec: no handshake signal was pending"
                            .into(),
                    );
                }
                require_owned_handshake_sigstop(&task, pid)?;
                *handshake_signal_pending = false;
                running = task.resume(None)?;
            }
            Wait::Stopped(task, Event::Signal(signal)) => {
                running = task.resume(Some(signal))?;
            }
            Wait::Stopped(task, Event::RawSignal(raw)) => {
                running = task.resume_raw(raw)?;
            }
            Wait::Stopped(task, Event::Stop) => {
                running = task.resume(Some(Signal::SIGCONT))?;
            }
            Wait::Stopped(_task, other_event) => {
                return Err(format!(
                    "exec supervisor encountered unexpected stop while watched: {other_event:?}"
                )
                .into());
            }
        }
    }
}

/// A seized, running guest under exec watch. Retains the physical
/// owner until [`WatchedSupervisor::wait_next`] reports the terminal
/// outcome (or drop, which retires through the owner's bounded
/// best-effort cleanup; `EXITKILL` covers supervisor death).
#[must_use = "retain the watched supervisor through its terminal outcome or cancellation"]
pub struct WatchedSupervisor<'fd> {
    pid: safeptrace::Pid,
    started: Instant,
    owner: ChildOwner<'fd>,
    running: Option<Running>,
    receipt: CleanupReceipt,
    pre_first_exec: bool,
    handshake_signal_pending: bool,
    execs_seen: u64,
}

impl std::fmt::Debug for WatchedSupervisor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchedSupervisor")
            .field("pid", &self.pid)
            .field("execs_seen", &self.execs_seen)
            .field("owner", &self.owner)
            .field("seized", &self.running.is_some())
            .field("cleanup", &self.receipt.snapshot())
            .finish()
    }
}

impl<'fd> WatchedSupervisor<'fd> {
    /// The actual child identity.
    pub fn pid(&self) -> safeptrace::Pid {
        self.pid
    }

    /// Same-generation shared signal/observation handle; it cannot wait here.
    pub fn cancellation_handle(&self) -> safeptrace::TerminalCleanup {
        self.owner.cancellation_handle()
    }

    /// Take the original child's parent pipe endpoints once. Captured
    /// streams must be drained concurrently with the waits below.
    pub fn take_parent_stdio(&mut self) -> Option<reverie::process::ParentStdio> {
        self.owner._request.take_parent_stdio()
    }

    /// Run the guest until its next exec event or terminal exit, on
    /// the original ptracer thread. A caught exec is drained and
    /// captured before this returns, so the successor stop sits at
    /// the new image's kernel entry with no guest progress.
    pub fn wait_next(mut self) -> std::result::Result<WatchedStep<'fd>, LaunchFailure<'fd>> {
        let running = self.running.take().expect("watched running state");
        let Self {
            pid,
            started,
            mut owner,
            receipt,
            pre_first_exec,
            mut handshake_signal_pending,
            execs_seen,
            ..
        } = self;
        let next = wait_watched(running, pid, pre_first_exec, &mut handshake_signal_pending);
        match next {
            Ok(NextExec::Finished(status)) => {
                owner.record_detached_terminal(status);
                Ok(WatchedStep::Finished(WatchedOutcome {
                    pid,
                    status,
                    execs_seen,
                    total: started.elapsed(),
                    cleanup: receipt.snapshot(),
                }))
            }
            Ok(NextExec::Exec(task)) => match super::drain_and_capture(task, pid) {
                Ok((task, context, boundary)) => Ok(WatchedStep::Exec(Box::new(SuccessorStop {
                    task,
                    context,
                    boundary,
                    owner,
                    receipt,
                    pid,
                    started,
                    execs_seen: execs_seen + 1,
                }))),
                Err(error) => Err(launch_failure(owner, receipt, error)),
            },
            Err(error) => Err(launch_failure(owner, receipt, error)),
        }
    }

    /// Cancel while seized, before any terminal outcome.
    pub fn cancel(self) -> std::result::Result<CleanupState, Box<ChildOwner<'fd>>> {
        self.owner.cancel()
    }
}

/// One caught successor exec, stopped at the new image's kernel
/// entry with the exec return drained and the original entry
/// context captured. The caller's hook performs the stopped-image
/// re-arm work (map, filter, handover, admission) and returns the
/// stop; only then does the supervisor restore the entry context
/// and let the guest run.
#[must_use = "retain the successor stop through re-arm, release, or cancellation"]
pub struct SuccessorStop<'fd> {
    task: Stopped,
    context: EntryContext,
    boundary: ExecBoundary,
    owner: ChildOwner<'fd>,
    receipt: CleanupReceipt,
    pid: safeptrace::Pid,
    started: Instant,
    execs_seen: u64,
}

impl std::fmt::Debug for SuccessorStop<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuccessorStop")
            .field("pid", &self.pid)
            .field("former_tid", &self.boundary.former_tid)
            .field("execs_seen", &self.execs_seen)
            .field("owner", &self.owner)
            .field("cleanup", &self.receipt.snapshot())
            .finish()
    }
}

impl<'fd> SuccessorStop<'fd> {
    /// The actual child identity.
    pub fn pid(&self) -> safeptrace::Pid {
        self.pid
    }

    /// Former tid from the caught kernel exec event.
    pub fn former_tid(&self) -> safeptrace::Pid {
        self.boundary.former_tid
    }

    /// Inspect the successor's original entry and initial stack.
    pub fn entry(&self) -> &EntryContext {
        &self.context
    }

    /// Inspect the exact exec boundary observations.
    pub fn boundary(&self) -> &ExecBoundary {
        &self.boundary
    }

    /// Same-generation shared signal/observation handle; it cannot wait here.
    pub fn cancellation_handle(&self) -> safeptrace::TerminalCleanup {
        self.owner.cancellation_handle()
    }

    /// Take the original child's parent pipe endpoints once, before
    /// releasing guest execution.
    pub fn take_parent_stdio(&mut self) -> Option<reverie::process::ParentStdio> {
        self.owner._request.take_parent_stdio()
    }

    /// Run the caller's re-arm hook on the stopped successor, restore
    /// the exact original entry context, and resume the guest still
    /// seized for the next exec. The hook owns mapping, filter
    /// installation, handover, admission and every readiness check;
    /// this transition proves only that the hook returned the stop
    /// and the original context (unchanged guest stack included)
    /// restored exactly. Any hook or restore error fails the launch
    /// closed with the child cancelled.
    pub fn rearm_and_resume<F>(
        self,
        hook: F,
    ) -> std::result::Result<WatchedSupervisor<'fd>, LaunchFailure<'fd>>
    where
        F: FnOnce(Stopped, &EntryContext, &ExecBoundary) -> Result<Stopped>,
    {
        let Self {
            task,
            context,
            boundary,
            owner,
            receipt,
            pid,
            started,
            execs_seen,
        } = self;
        let result = hook(task, &context, &boundary).and_then(|task| {
            context.restore(&task)?;
            Ok(task.resume(None)?)
        });
        match result {
            Ok(running) => Ok(WatchedSupervisor {
                pid,
                started,
                owner,
                running: Some(running),
                receipt,
                pre_first_exec: false,
                handshake_signal_pending: false,
                execs_seen,
            }),
            Err(error) => Err(launch_failure(owner, receipt, error)),
        }
    }

    /// Run the caller's re-arm hook, then take the production
    /// release transition: restore the exact original entry context
    /// and detach at the kernel entry. The guest runs unsupervised
    /// afterwards; retain the result through its terminal wait.
    pub fn release_detached<F>(
        self,
        hook: F,
    ) -> std::result::Result<DetachedSupervisor<'fd>, LaunchFailure<'fd>>
    where
        F: FnOnce(Stopped, &EntryContext, &ExecBoundary) -> Result<Stopped>,
    {
        let Self {
            task,
            context,
            boundary,
            owner,
            receipt,
            pid,
            started,
            execs_seen: _,
        } = self;
        let former_tid = boundary.former_tid;
        // Detach with SIGCONT, like the dormant path, so any residual
        // group-stop state from the seize handshake cannot park the
        // released guest.
        let result = hook(task, &context, &boundary)
            .and_then(|task| super::release_restored(task, &context, Some(Signal::SIGCONT)));
        match result {
            Ok(running) => Ok(DetachedSupervisor {
                pid,
                former_tid,
                spawn_to_after_detach: started.elapsed(),
                started,
                owner,
                running: Some(running),
                receipt,
            }),
            Err(error) => Err(launch_failure(owner, receipt, error)),
        }
    }

    /// Cancel while the successor is stopped, before any release.
    pub fn cancel(self) -> std::result::Result<CleanupState, Box<ChildOwner<'fd>>> {
        self.owner.cancel()
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

    #[test]
    fn watched_supervisor_rearms_each_successor_exec() {
        let mut watched = Supervisor::spawn_watched(
            request("/bin/sh", &["sh", "-c", "exec /bin/true"]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched_pid = watched.pid();
        let mut execs = 0u64;
        let outcome = loop {
            match watched.wait_next().unwrap() {
                WatchedStep::Exec(stop) => {
                    execs += 1;
                    assert_eq!(stop.pid(), watched_pid);
                    assert_eq!(stop.former_tid(), watched_pid);
                    assert_eq!(stop.entry().regs().rip, stop.boundary().exit_regs.rip);
                    watched = stop
                        .rearm_and_resume(|task, _entry, _boundary| Ok(task))
                        .unwrap();
                }
                WatchedStep::Finished(outcome) => break outcome,
            }
        };
        assert_eq!(execs, 2);
        assert_eq!(outcome.execs_seen, 2);
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_supervisor_hook_error_fails_closed() {
        let watched =
            Supervisor::spawn_watched(request("/bin/true", &["true"]), CleanupReceipt::default())
                .unwrap();
        let pid = watched.pid();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected an exec stop, got terminal {outcome:?}")
            }
        };
        let failure = stop
            .rearm_and_resume(|_task, _entry, _boundary| Err("test hook refusal".into()))
            .unwrap_err();
        assert!(
            failure.error.to_string().contains("test hook refusal"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }

    #[test]
    fn watched_supervisor_restore_overrides_hook_register_mutation() {
        let mut watched =
            Supervisor::spawn_watched(request("/bin/true", &["true"]), CleanupReceipt::default())
                .unwrap();
        let outcome = loop {
            match watched.wait_next().unwrap() {
                WatchedStep::Exec(stop) => {
                    watched = stop
                        .rearm_and_resume(|task, _entry, _boundary| {
                            let mut regs = task.getregs()?;
                            regs.rip = 0x4141_4141;
                            task.setregs(&regs)?;
                            Ok(task)
                        })
                        .unwrap();
                }
                WatchedStep::Finished(outcome) => break outcome,
            }
        };
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_supervisor_forwards_guest_signal() {
        let mut watched = Supervisor::spawn_watched(
            request("/bin/sh", &["sh", "-c", "kill -TERM $$"]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = loop {
            match watched.wait_next().unwrap() {
                WatchedStep::Exec(stop) => {
                    watched = stop
                        .rearm_and_resume(|task, _entry, _boundary| Ok(task))
                        .unwrap();
                }
                WatchedStep::Finished(outcome) => break outcome,
            }
        };
        assert_eq!(outcome.execs_seen, 1);
        assert!(
            matches!(outcome.status, ExitStatus::Signaled(Signal::SIGTERM, _)),
            "unexpected status: {:?}",
            outcome.status
        );
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn successor_stop_release_detached_runs_unupervised() {
        let watched = Supervisor::spawn_watched(
            request("/bin/sh", &["sh", "-c", "exec /bin/false"]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected an exec stop, got terminal {outcome:?}")
            }
        };
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(1));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn initial_exec_stop_release_runs_guest() {
        use super::super::ExecStop;

        let stop =
            ExecStop::spawn(request("/bin/true", &["true"]), CleanupReceipt::default()).unwrap();
        let (running, owner) = stop.release(|task, _entry| Ok(task)).unwrap();
        assert_eq!(owner.wait(running).unwrap(), ExitStatus::Exited(0));
    }

    #[test]
    fn initial_exec_stop_release_hook_error_fails_closed() {
        use super::super::ExecStop;

        let receipt = CleanupReceipt::default();
        let stop = ExecStop::spawn(request("/bin/true", &["true"]), receipt.clone()).unwrap();
        let pid = stop.pid();
        let failure = stop
            .release(|_task, _entry| Err("test hook refusal".into()))
            .unwrap_err();
        assert!(
            failure.error.to_string().contains("test hook refusal"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }
}
