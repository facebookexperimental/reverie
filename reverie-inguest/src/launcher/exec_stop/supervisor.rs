// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Dormant-seize exec supervisor.
//!
//! The child self-stops before its initial exec without calling
//! `PTRACE_TRACEME`; the parent seizes it with `EXITKILL`,
//! `TRACEEXEC`, and `TRACESYSGOOD` (watched mode adds `TRACEFORK`
//! and `TRACEVFORK`, and each driven fork child also gets
//! `TRACEEXIT`) and resumes it. Two modes share that seize and the
//! initial-handshake discipline:
//!
//! * [`Supervisor::spawn`] drains only the initial exec syscall
//!   return and detaches. No runtime image is mapped and no
//!   successor is armed: after detach the new image runs
//!   unsupervised. This proves only the launch/event/detach
//!   plumbing and its cost floor.
//! * [`Supervisor::spawn_watched`] stays seized while the guest
//!   runs. Every exec event caught on the leader's traced thread is
//!   drained and captured exactly like the first-image exec stop and
//!   handed to the caller as a [`SuccessorStop`] (a fork child's
//!   exec is refused instead; see below). The caller's hook re-runs whatever
//!   stopped-image work its policy requires (map, filter, handover,
//!   admission) and returns the stop; the supervisor then restores
//!   the exact original entry context and either resumes the guest
//!   still seized for the next exec or detaches it through the
//!   production release transition. This module keeps no admission
//!   or ticket state of its own: successor admission belongs
//!   entirely to the caller's hook.
//!
//! Stop policy: the watched leader is not job-controlled. While
//! watched, its signal deliveries are forwarded unchanged and a
//! group stop is continued at once: the supervisor sends its own
//! real `SIGCONT` while still seized, consumes the notify trap,
//! and forwards that SIGCONT delivery. The leader therefore
//! ordinarily observes a SIGCONT from the supervisor pid
//! (including a handler, if installed; if a foreign SIGCONT is
//! already pending, standard-signal merging may preserve that
//! sender instead), queued stop signals are flushed by that
//! generation, and the stop lasts zero guest-visible time. A
//! job-control continuer's SIGCONT can therefore become a second
//! delivery (an extra handler run or EINTR), and a leader that
//! keeps stopping itself spins through stop/continue cycles
//! instead of remaining stopped. Only the initial pre-exec
//! window keeps the stricter handshake ownership proof. After
//! `release_detached`, the detached wait is terminal-only: a
//! guest that then stops itself is reported as an unexpected
//! post-detach stop and cancelled.
//!
//! Fork children keep native job control. Their signal
//! deliveries are forwarded unchanged; a group stop is parked
//! with `PTRACE_LISTEN`, so the child stays stopped until a
//! guest continuer's `SIGCONT` (or `SIGKILL`) arrives, and that
//! delivery is then forwarded. A fork child's exec is refused
//! by name (`exec_supervisor_fork_child_exec_refused`): no
//! caller re-arm hook exists for fork children yet, so this
//! module does not re-arm new leaders and does not satisfy a
//! fork-tree successor-arming acceptance on its own. A fork
//! child's traced main thread is detached at its exit stop, so
//! its zombie is reaped natively by the guest parent; a main
//! thread that exits while sibling threads keep running
//! therefore neither holds up the leader's outcome nor stays
//! traced. Exit-only fork and vfork children are observed to
//! exit unchanged.
//!
//! Scope limits: seized descendants get `EPERM` if they try to
//! ptrace (guest debuggers and tracers do not work inside the
//! watched tree); forks from untraced non-leader threads are
//! not followed; `clone` children whose exit signal is not
//! `SIGCHLD` are not followed (`PTRACE_O_TRACECLONE` is not
//! requested); an auto-attached child whose fork event is
//! never reported (for example its parent is killed before the
//! event stop) is never driven, because there is no
//! `wait(-1)` discovery; and children are not driven while the
//! caller holds a [`SuccessorStop`]. An exec from a non-leader
//! thread of the watched leader is not observed and leaves no record
//! (as on `main`). The same exec inside a fork child is refused by
//! name (`exec_supervisor_fork_child_exec_refused`) before its new
//! image runs: de_thread kills the child's traced main thread and must
//! wait for it, and that thread is then held at its exit stop. When that
//! main thread was killed (`PF_SIGNALED`, `SIGKILL` pending, or
//! unreadable evidence), it is released only once the group is shown
//! to hold no waiting exec: `Threads: 1` in `/proc/<pid>/status`, or a
//! complete task listing whose every sibling is gone or dying. A sibling
//! seen in an execve/execveat entry of any host ABI (native, x32, ia32)
//! refuses at once; anything else unresolved after 1 s refuses then.
//! A refusal kills the whole group before the main thread is released.
//! Not caught: when the main thread exited on its own, a sibling exec
//! still before de_thread that one pass does not see in exec (it starts
//! after its read, its syscall file is unreadable, it is ia32 `execve`
//! with an unreadable entry instruction, or the listing skipped it);
//! that exec's own kill ejects a still-held main thread, and the new
//! image runs unarmed and unsupervised. A sibling seen inside an execve
//! that will fail gets a healthy group refused and killed. The check
//! reads `/proc` by the child's pid, so `/proc` must belong to the
//! supervisor's pid namespace.
//!
//! A fork child's exit stop is released through one check
//! (`settle_exit_stop`) in the wait loop and in teardown detach; the
//! bounded kill of a child that could not be detached detaches a
//! killed child at its exit stop directly.
//!
//! Teardown: on leader exit, release, error, cancellation and
//! drop, the supervisor detaches every driven child, including
//! children met while detaching. Where the leader is still
//! running (cancellation, drop, or an error while it runs), it is
//! first interrupted and drained to its next stop, adopting the
//! child of a fork it had not yet reported, before it is killed.
//! A child stopped at a fork-child exec event when teardown
//! begins is detached there, and that new image runs unarmed. A
//! child that does not reach a ptrace stop within 2 s is killed
//! (process-directed) and reaped within 2 s more, and the failure
//! is reported as `exec_supervisor_fork_child_undrivable`; the
//! leader's quiesce has the same bound
//! (`exec_supervisor_leader_quiesce_timeout`). Healthy tasks hit
//! these bounds in killable or uninterruptible waits that ignore
//! `PTRACE_INTERRUPT`: a task blocked in `vfork` until its vfork
//! child execs or exits, and a task in D-state I/O. Each failed
//! child costs up to 4 s. A teardown failure is reported without
//! replacing the guest's outcome: leader exit still returns the
//! leader's actual status, and every path records the first
//! failure as `CleanupState::child_detach_error`.

use std::task::Context;
use std::task::Poll;
use std::task::Waker;
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

/// A real SIGCONT sent to clear the handshake group stop flushes
/// every queued stop signal at generation time. Refuse first if any
/// stop signal is already queued when peeked, so the clear claims
/// none of those. This does not close the peek-to-kill window: a
/// stop signal queued after the peek can still be flushed by the
/// clearing SIGCONT and leave no trace.
#[allow(unsafe_code)]
fn refuse_pending_stop_signal(task: &Stopped) -> Result<()> {
    for flags in [None, Some(safeptrace::PeekSigInfoFlags::SHARED)] {
        for info in task.peeksiginfo_all(flags)? {
            if matches!(
                info.si_signo,
                libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
            ) {
                // SAFETY: this is a queued Linux siginfo just returned
                // by PTRACE_PEEKSIGINFO for the current stop.
                let sender = unsafe { info.si_pid() };
                return Err(format!(
                    "exec supervisor encountered unowned SIGSTOP before exec: pending stop signal {} si_code={}, sender={sender}",
                    info.si_signo, info.si_code
                )
                .into());
            }
        }
    }
    Ok(())
}

/// The SIGCONT used to clear a handshake group stop is this
/// supervisor process's own `kill`: its delivery stop must name
/// that exact sender and cause before it may be suppressed.
#[allow(unsafe_code)]
fn require_owned_sigcont(task: &Stopped) -> Result<()> {
    let info = task.getsiginfo()?;
    // SAFETY: this is the just-read Linux siginfo for the current stop.
    let sender = unsafe { info.si_pid() };
    if info.si_signo != libc::SIGCONT
        || info.si_code != libc::SI_USER
        || sender != std::process::id() as i32
    {
        return Err(format!(
            "exec supervisor encountered unowned SIGCONT before exec: si_code={}, sender={sender}",
            info.si_code
        )
        .into());
    }
    Ok(())
}

/// Send this supervisor process's real SIGCONT to a seized child.
/// Generating it (not injecting it on a ptrace resume) is what
/// clears the kernel's hidden natural-parent group-stop report.
fn send_own_sigcont(pid: safeptrace::Pid) -> Result<()> {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid.as_raw()),
        nix::sys::signal::Signal::SIGCONT,
    )?;
    Ok(())
}

/// The first stop after sending the clearing SIGCONT is the ptrace
/// trap notification for that generation, not a fresh group stop:
/// its siginfo must be the child's own PTRACE_EVENT_STOP trap.
#[allow(unsafe_code)]
fn require_group_stop_clear_trap(task: &Stopped, pid: safeptrace::Pid) -> Result<()> {
    let info = task.getsiginfo()?;
    // SAFETY: this is the just-read Linux siginfo for the current stop.
    let sender = unsafe { info.si_pid() };
    let expected = libc::SIGTRAP | (libc::PTRACE_EVENT_STOP << 8);
    if info.si_signo != libc::SIGTRAP || info.si_code != expected || sender != pid.as_raw() {
        return Err(format!(
            "exec supervisor encountered unexpected group-stop clear trap: si_signo={}, si_code={}, sender={sender}",
            info.si_signo, info.si_code
        )
        .into());
    }
    Ok(())
}

/// Classify a PTRACE_EVENT_STOP trap by its siginfo. A SIGCONT
/// notify trap names SIGTRAP; a genuine group stop names its stop
/// signal in both the signal number and the low byte of the code.
/// The stopped child is the sender of the trap siginfo in both
/// cases. Returns the validated signal number.
#[allow(unsafe_code)]
fn classify_group_stop_trap(
    task: &Stopped,
    pid: safeptrace::Pid,
    refusal: &'static str,
) -> Result<i32> {
    let info = task.getsiginfo()?;
    // SAFETY: this is the just-read Linux siginfo for the current stop.
    let sender = unsafe { info.si_pid() };
    if !matches!(
        info.si_signo,
        libc::SIGTRAP | libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
    ) || info.si_code != info.si_signo | (libc::PTRACE_EVENT_STOP << 8)
        || sender != pid.as_raw()
    {
        return Err(format!(
            "{refusal}: si_signo={}, si_code={}, sender={sender}",
            info.si_signo, info.si_code
        )
        .into());
    }
    Ok(info.si_signo)
}

/// Wait for the child's handshake stop after seize. A group stop
/// has already consumed the handshake signal; no signal-delivery
/// phase remains outstanding. A signal-delivery stop is accepted
/// only if its siginfo proves it is the child's own handshake.
/// Every other pre-exec stop fails closed rather than being
/// silently forwarded or dropped. Bounded only by the caller's
/// external deadline, like every synchronous exec-stop wait.
fn wait_initial_stop(running: Running, pid: safeptrace::Pid) -> Result<(Stopped, bool)> {
    match trace::wait(running)? {
        Wait::Stopped(task, event) => match event {
            Event::Stop => {
                let signo = classify_group_stop_trap(
                    &task,
                    pid,
                    "exec supervisor encountered unexpected handshake group stop",
                )?;
                if signo != libc::SIGSTOP {
                    return Err(format!(
                        "exec supervisor encountered unexpected handshake group stop: si_signo={signo}"
                    )
                    .into());
                }
                Ok((task, true))
            }
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

/// Consume the seize stop and resume toward the initial exec. A
/// handshake that completed as a group stop consumed its SIGSTOP,
/// but the natural parent's group-stop report remains hidden while
/// seized and would become a stale stopped status after detach.
/// Send this supervisor's own real SIGCONT while still seized so
/// the kernel clears that report at generation time; the returned
/// flag says its trap/delivery stops must still be consumed before
/// the first exec. A signal-delivery handshake stop is simply
/// suppressed. Runs entirely on the original ptracer thread.
fn consume_handshake(
    owner: &mut ChildOwner<'_>,
    running: Running,
    pid: safeptrace::Pid,
    before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
) -> Result<(Running, bool)> {
    owner._thread = Some(owner.generation.ptracer_thread_guard()?);
    let (initial, group_stop) = wait_initial_stop(running, pid)?;
    before_initial_resume(pid);
    let running = if group_stop {
        refuse_pending_stop_signal(&initial)?;
        send_own_sigcont(pid)?;
        initial.resume(None)?
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
    mut group_stop_clear_pending: bool,
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
                // in-flight syscall. A group-stop handshake was
                // already cleared by a real SIGCONT while seized, so
                // no stale natural-parent stop remains for the
                // detached wait. The captured context is discarded:
                // this mode detaches without touching the new image.
                let (task, _context, _boundary) = super::drain_and_capture(task, former)?;
                let running = task.detach(Some(Signal::SIGCONT))?;
                return Ok((running, former));
            }
            Wait::Stopped(task, Event::Stop) if group_stop_clear_pending => {
                require_group_stop_clear_trap(&task, pid)?;
                running = task.resume(None)?;
            }
            Wait::Stopped(task, Event::Signal(Signal::SIGCONT)) if group_stop_clear_pending => {
                require_owned_sigcont(&task)?;
                group_stop_clear_pending = false;
                running = task.resume(None)?;
            }
            Wait::Stopped(task, Event::Signal(Signal::SIGSTOP)) => {
                // No handshake signal-delivery phase remains: a group
                // stop consumed the child's SIGSTOP and a
                // signal-delivery handshake was suppressed at the
                // seize stop. Preserve the ownership proof so a
                // SIGSTOP from any other sender is named unowned,
                // then fail closed rather than swallow either kind.
                require_owned_handshake_sigstop(&task, pid)?;
                return Err(
                    "exec supervisor encountered SIGSTOP before exec: no handshake signal was pending"
                        .into(),
                );
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

/// Seize options for the supervisor. Fork following is watched-only:
/// the dormant path detaches at the first exec and must not
/// auto-attach children it would never drive.
fn supervisor_options(follow_forks: bool) -> Options {
    let base =
        Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_TRACESYSGOOD;
    if follow_forks {
        base | Options::PTRACE_O_TRACEFORK | Options::PTRACE_O_TRACEVFORK
    } else {
        base
    }
}

/// Options installed on each driven fork child at its first stop:
/// the watched options plus `PTRACE_O_TRACEEXIT`. A child's traced
/// main thread is detached at its exit stop, so its zombie is never
/// left traced: a zombie group leader whose sibling threads still
/// run can be neither stopped nor detached, and only this ptracer
/// thread could otherwise reap it for the guest parent.
fn fork_child_options() -> Options {
    supervisor_options(true) | Options::PTRACE_O_TRACEEXIT
}

/// One auto-attached fork child being driven by the watched
/// supervisor. Its wait is polled, never blocked on, so the leader
/// and every sibling keep making progress.
struct ChildWait {
    driver: safeptrace::PtracerWaitDriver,
    /// The child's exit-stop claim. safeptrace publishes an exit stop
    /// to its exit future, never to an ordinary wait, so each child is
    /// polled here too, to be detached at that stop. `None` once the
    /// epoch ended without a stop (for example after `SIGKILL`), and
    /// for a child that is only being settled.
    exit: Option<safeptrace::PtracerExitDriver>,
    initialized: bool,
}

impl ChildWait {
    /// A newly auto-attached child, still in its initial stop.
    fn new(running: Running) -> Self {
        let exit = Some(running.exit_event_on_ptracer_thread().into_driver());
        Self {
            driver: leader_wait(running),
            exit,
            initialized: false,
        }
    }

    /// A child that is only being driven to its terminal status.
    fn settling(driver: safeptrace::PtracerWaitDriver, initialized: bool) -> Self {
        Self {
            driver,
            exit: None,
            initialized,
        }
    }

    /// Poll this child's exit-stop claim once. `Some(task)` is the
    /// child stopped at its exit stop; the claim is spent either way
    /// once it resolves.
    fn poll_exit_stop(&mut self) -> Option<Stopped> {
        let exit = self.exit.as_mut()?;
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        match exit.poll_on_ptracer_thread(&mut cx) {
            Poll::Pending => None,
            Poll::Ready(claimed) => {
                self.exit = None;
                claimed.ok()
            }
        }
    }
}

/// A fork child's traced main thread at its exit stop, after
/// [`settle_exit_stop`].
struct ExitStopOutcome {
    /// The wait to settle when the child was killed out of the stop
    /// and is still attached; `None` once it is detached.
    dying: Option<safeptrace::PtracerWaitDriver>,
    /// The named refusal when a sibling thread was execing.
    refusal: Option<String>,
}

/// How long a killed main thread is held at its exit stop while its
/// group drains, before the release is refused.
const EXIT_STOP_DRAIN_BOUND: Duration = Duration::from_secs(1);

/// `PF_EXITING` and `PF_SIGNALED` from the kernel's task flags, as shown
/// in field 9 of `/proc/<pid>/task/<tid>/stat` (readable even when the
/// child is non-dumpable).
const PF_EXITING: u64 = 0x4;
const PF_SIGNALED: u64 = 0x400;

/// One read of a `/proc` file of a task.
enum ProcRead {
    Text(String),
    /// ENOENT/ESRCH: the task is released.
    Gone,
    /// Any other error (EACCES/EPERM for a non-dumpable child).
    Unreadable,
}

fn read_proc(path: &std::path::Path) -> ProcRead {
    match std::fs::read_to_string(path) {
        Ok(text) => ProcRead::Text(text),
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOENT | libc::ESRCH) => ProcRead::Gone,
            _ => ProcRead::Unreadable,
        },
    }
}

/// What one read of a sibling's `/proc/.../syscall` showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyscallRead {
    Gone,
    /// Inside an execve/execveat entry (see [`is_exec_entry`]).
    Exec,
    /// In another syscall, outside one, or "running".
    Other,
    Unreadable,
}

/// The syscall ABI a blocked task entered through, from the two
/// instruction bytes before its saved user `pc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryAbi {
    /// `syscall` (x86_64 native, or x32 with `__X32_SYSCALL_BIT`).
    Native,
    /// `int $0x80`, or the ia32 vDSO's landing pad after `sysenter` or
    /// `syscall`, which is preceded by `int $0x80`.
    Ia32,
    /// The bytes could not be read or are neither.
    Unknown,
}

/// Whether syscall `nr`, entered through `abi`, is execve or execveat in
/// any ABI the host accepts. On x86_64: native 59/322, x32
/// `0x40000000|520` and `0x40000000|545`, and ia32 11/358. For an
/// unknown entry the native and x32 numbers and 358 (unused natively)
/// still count; ia32 11 is native `munmap`, so it counts only for a
/// known ia32 entry. Elsewhere only the native numbers count.
#[cfg(target_arch = "x86_64")]
fn is_exec_entry(nr: i64, abi: EntryAbi) -> bool {
    const X32: i64 = 0x4000_0000;
    match abi {
        EntryAbi::Ia32 => nr == 11 || nr == 358,
        EntryAbi::Native => matches!(nr, 59 | 322) || matches!(nr ^ X32, 520 | 545),
        EntryAbi::Unknown => matches!(nr, 59 | 322 | 358) || matches!(nr ^ X32, 520 | 545),
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn is_exec_entry(nr: i64, _abi: EntryAbi) -> bool {
    nr == libc::SYS_execve || nr == libc::SYS_execveat
}

/// The entry ABI of the task whose `/proc/.../syscall` fields are
/// `fields`, read from `mem` (the same `ptrace` access check as the
/// syscall file).
#[cfg(target_arch = "x86_64")]
fn entry_abi(fields: &[&str], mem: &std::path::Path) -> EntryAbi {
    use std::os::unix::fs::FileExt;
    let Some(pc) = fields
        .get(8)
        .and_then(|pc| u64::from_str_radix(pc.trim_start_matches("0x"), 16).ok())
        .and_then(|pc| pc.checked_sub(2))
    else {
        return EntryAbi::Unknown;
    };
    let mut bytes = [0u8; 2];
    match std::fs::File::open(mem).and_then(|file| file.read_exact_at(&mut bytes, pc)) {
        Ok(()) => match bytes {
            [0x0f, 0x05] => EntryAbi::Native,
            [0xcd, 0x80] | [0x0f, 0x34] => EntryAbi::Ia32,
            _ => EntryAbi::Unknown,
        },
        Err(_) => EntryAbi::Unknown,
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn entry_abi(_fields: &[&str], _mem: &std::path::Path) -> EntryAbi {
    EntryAbi::Native
}

#[cfg(test)]
thread_local! {
    /// Test-only: every sibling syscall read shows "running", so no
    /// sibling is ever seen in exec.
    static FORCE_SIBLING_SYSCALL_RUNNING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only: drop the last entry of every task listing, as an
    /// incomplete `/proc/<pid>/task` walk would.
    static DROP_LAST_LISTED_TASK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// One read (no re-read) of the syscall file in the task directory `dir`.
fn read_sibling_syscall(dir: &std::path::Path) -> SyscallRead {
    #[cfg(test)]
    if FORCE_SIBLING_SYSCALL_RUNNING.with(std::cell::Cell::get) {
        return SyscallRead::Other;
    }
    let text = match read_proc(&dir.join("syscall")) {
        ProcRead::Text(text) => text,
        ProcRead::Gone => return SyscallRead::Gone,
        ProcRead::Unreadable => return SyscallRead::Unreadable,
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    match fields.first().map(|nr| nr.parse::<i64>()) {
        Some(Ok(nr)) if is_exec_entry(nr, entry_abi(&fields, &dir.join("mem"))) => {
            SyscallRead::Exec
        }
        // Another syscall, "running", or not a number.
        _ => SyscallRead::Other,
    }
}

/// Task flags from field 9 of a `/proc/.../stat` text (after the
/// parenthesized command name, which may itself contain spaces).
fn task_flags(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(6)?.parse().ok()
}

/// Whether a `/proc/.../status` text shows `SIGKILL` pending (`SigPnd`
/// or `ShdPnd`).
fn sigkill_pending(status: &str) -> bool {
    status
        .lines()
        .filter_map(|line| {
            line.strip_prefix("SigPnd:")
                .or_else(|| line.strip_prefix("ShdPnd:"))
        })
        .filter_map(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .any(|mask| mask & (1 << (libc::SIGKILL - 1)) != 0)
}

/// `Threads:` from a `/proc/<pid>/status` text.
fn status_threads(status: &str) -> Option<usize> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
}

/// What one pass of the exit-stop check found for one sibling thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SiblingFinding {
    /// Its `/proc` entry is gone (ENOENT/ESRCH on any read).
    Gone,
    /// Shown leaving: `SIGKILL` pending, or `PF_EXITING` or
    /// `PF_SIGNALED` in its flags. A thread waiting in de_thread has
    /// none of these (if it is killed, its exec is abandoned).
    Dying,
    /// In an execve/execveat entry and not shown leaving.
    Exec,
    /// Alive with no death evidence and not shown in exec: unreadable,
    /// running, or in another syscall.
    Live,
}

/// Examine one sibling. `status` is read before `stat`: Linux removes
/// `SIGKILL` from pending before it sets `PF_SIGNALED`, so in the other
/// order a dying thread could show neither.
fn examine_sibling(dir: &std::path::Path) -> SiblingFinding {
    match read_proc(&dir.join("status")) {
        ProcRead::Gone => return SiblingFinding::Gone,
        ProcRead::Text(status) if sigkill_pending(&status) => return SiblingFinding::Dying,
        ProcRead::Text(_) | ProcRead::Unreadable => {}
    }
    match read_proc(&dir.join("stat")) {
        ProcRead::Gone => return SiblingFinding::Gone,
        ProcRead::Text(stat)
            if task_flags(&stat).is_some_and(|flags| flags & (PF_EXITING | PF_SIGNALED) != 0) =>
        {
            return SiblingFinding::Dying;
        }
        ProcRead::Text(_) | ProcRead::Unreadable => {}
    }
    match read_sibling_syscall(dir) {
        SyscallRead::Gone => SiblingFinding::Gone,
        SyscallRead::Exec => SiblingFinding::Exec,
        SyscallRead::Other | SyscallRead::Unreadable => SiblingFinding::Live,
    }
}

/// One pass over a fork child's threads.
#[derive(Debug, PartialEq, Eq)]
struct ThreadsPass {
    /// `Threads:` of the child, read before the listing.
    threads: Option<usize>,
    /// The finding for every listed sibling.
    siblings: Vec<SiblingFinding>,
    /// The task directory and every entry of it were read without error.
    listed_ok: bool,
}

impl ThreadsPass {
    /// Whether the listing shows every thread of the group. Once the
    /// main thread was killed, every thread was sent `SIGKILL` and no
    /// new one can be created (`copy_process` refuses with a fatal
    /// signal pending), so the group only shrinks: a sibling listed
    /// after `threads` was read was counted in it, and a listing as long
    /// as `threads` (with the held main thread) is the whole group.
    fn complete(&self) -> bool {
        self.listed_ok && self.threads == Some(self.siblings.len() + 1)
    }

    fn describe(&self) -> String {
        let count = |finding| self.siblings.iter().filter(|s| **s == finding).count();
        format!(
            "Threads: {:?}; {} siblings listed ({} gone, {} dying, {} live), listing {}",
            self.threads,
            self.siblings.len(),
            count(SiblingFinding::Gone),
            count(SiblingFinding::Dying),
            count(SiblingFinding::Live),
            if self.complete() {
                "complete"
            } else {
                "incomplete"
            }
        )
    }
}

/// What one pass decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PassVerdict {
    Release,
    RefuseExec,
    /// Look again; at the drain bound this refuses.
    Undecided,
}

/// Decide one pass at a fork child's exit stop, with its main thread
/// held there. A non-leader exec's de_thread kills the main thread and
/// then waits, alive and in the group, until the held main thread is
/// released. So once the main thread was killed:
/// - `Threads: 1` (only the held main thread) proves no exec is waiting:
///   release.
/// - A complete listing in which every sibling is gone or dying proves
///   it too: release.
/// - A sibling in exec refuses at once.
/// - Anything else (a live sibling, an incomplete listing, an
///   unreadable count) is undecided, and refused at the drain bound.
///
/// A main thread that was not killed cannot be waited on by any exec:
/// the pass refuses only for a sibling seen in exec (one still before
/// de_thread) and otherwise releases.
fn pass_verdict(main_killed: bool, pass: &ThreadsPass) -> PassVerdict {
    if main_killed && pass.threads == Some(1) {
        return PassVerdict::Release;
    }
    if pass.siblings.contains(&SiblingFinding::Exec) {
        return PassVerdict::RefuseExec;
    }
    if !main_killed
        || (pass.complete()
            && pass
                .siblings
                .iter()
                .all(|s| matches!(s, SiblingFinding::Gone | SiblingFinding::Dying)))
    {
        return PassVerdict::Release;
    }
    PassVerdict::Undecided
}

/// Whether the held main thread whose task directory is `main` was
/// killed: `SIGKILL` pending or `PF_SIGNALED`. Evidence that cannot be
/// read counts as killed.
fn main_thread_killed(main: &std::path::Path) -> bool {
    let ProcRead::Text(status) = read_proc(&main.join("status")) else {
        return true;
    };
    let ProcRead::Text(stat) = read_proc(&main.join("stat")) else {
        return true;
    };
    sigkill_pending(&status) || task_flags(&stat).is_none_or(|flags| flags & PF_SIGNALED != 0)
}

/// One pass over the threads of fork child `pid`, whose main thread the
/// caller holds at its exit stop (so `pid` still names this child). The
/// listing is skipped once a killed main thread is alone.
fn threads_pass(pid: safeptrace::Pid, main_killed: bool) -> ThreadsPass {
    let threads = match read_proc(std::path::Path::new(&format!(
        "/proc/{}/status",
        pid.as_raw()
    ))) {
        ProcRead::Text(status) => status_threads(&status),
        ProcRead::Gone | ProcRead::Unreadable => None,
    };
    let mut pass = ThreadsPass {
        threads,
        siblings: Vec::new(),
        listed_ok: true,
    };
    if main_killed && threads == Some(1) {
        return pass;
    }
    let mut dirs = Vec::new();
    match std::fs::read_dir(format!("/proc/{}/task", pid.as_raw())) {
        Err(_) => pass.listed_ok = false,
        Ok(tasks) => {
            for task in tasks {
                let Ok(task) = task else {
                    pass.listed_ok = false;
                    continue;
                };
                match task.file_name().to_string_lossy().parse::<i32>() {
                    Ok(tid) if tid == pid.as_raw() => {}
                    Ok(_) => dirs.push(task.path()),
                    Err(_) => pass.listed_ok = false,
                }
            }
        }
    }
    #[cfg(test)]
    if DROP_LAST_LISTED_TASK.with(std::cell::Cell::get) {
        dirs.pop();
    }
    pass.siblings = dirs.iter().map(|dir| examine_sibling(dir)).collect();
    pass
}

/// The refusal reason for releasing fork child `pid`'s main thread from
/// its exit stop, or `None` to release it (see [`pass_verdict`]).
fn exit_stop_refusal(pid: safeptrace::Pid) -> Option<String> {
    let main_killed = main_thread_killed(std::path::Path::new(&format!(
        "/proc/{0}/task/{0}",
        pid.as_raw()
    )));
    let deadline = Instant::now() + EXIT_STOP_DRAIN_BOUND;
    loop {
        let pass = threads_pass(pid, main_killed);
        match pass_verdict(main_killed, &pass) {
            PassVerdict::Release => return None,
            PassVerdict::RefuseExec => return Some("exec from a non-leader thread".to_owned()),
            PassVerdict::Undecided if Instant::now() >= deadline => {
                return Some(format!(
                    "a live non-leader thread that could not be ruled out of exec after its main thread was killed ({} after {EXIT_STOP_DRAIN_BOUND:?})",
                    pass.describe()
                ));
            }
            PassVerdict::Undecided => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

/// Kill the fork child's whole group: through its retained descriptor,
/// process-directed, or else by number (the held, unreaped main thread
/// pins `pid`).
fn kill_child_group(task: &Stopped) -> std::result::Result<(), String> {
    let pid = task.pid();
    match task.terminal_cleanup().request_process_sigkill() {
        Ok(()) => Ok(()),
        Err(descriptor) => nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        )
        .map_err(|number| format!("descriptor kill: {descriptor}; numeric kill: {number}")),
    }
}

/// Release a fork child's main thread from its exit stop.
///
/// A non-leader exec's de_thread kills the old main thread and then
/// waits for it, so while this held main thread stays at its exit stop
/// the new image cannot run. [`exit_stop_refusal`] decides whether the
/// release is refused (see [`pass_verdict`]); if so, the whole group is
/// killed first and the refusal is named, and if that kill cannot be
/// sent, the main thread is not released at all and the error says so.
/// Then the main thread is detached at its exit stop: nothing of it is
/// left to supervise, and its zombie is never traced, so the guest
/// parent reaps it natively.
///
/// Once the main thread was killed, no exec waiting on it is released:
/// the release needs `Threads: 1` or a complete listing of gone or
/// dying siblings, and otherwise is refused at the drain bound. That
/// bound also refuses a group exit whose siblings neither finish nor
/// show death evidence in a complete listing within it.
///
/// Not caught, when the main thread exited on its own (not killed, so
/// no exec can be waiting on it): a sibling exec still before
/// de_thread that the single pass does not see in exec, because it
/// starts after its read, its syscall file is unreadable (non-dumpable
/// child), it is ia32 `execve` (11) whose entry instruction could not
/// be read, or the listing skipped it. That exec's own kill later
/// ejects a still-held main thread, and the new image runs unarmed and
/// unsupervised. Conversely, a sibling seen inside an execve that will
/// fail gets a healthy group killed.
fn settle_exit_stop(task: Stopped) -> Result<ExitStopOutcome> {
    let pid = task.pid();
    let refusal = if let Some(seen) = exit_stop_refusal(pid) {
        if let Err(error) = kill_child_group(&task) {
            // Keep the main thread held: releasing it would let a
            // waiting exec run.
            return Err(format!(
                "exec_supervisor_fork_child_exec_refused: fork child {pid:?} {seen}; the group kill could not be sent ({error}), so its main thread stays held at its exit stop"
            )
            .into());
        }
        Some(format!(
            "exec_supervisor_fork_child_exec_refused: fork child {pid:?} {seen}; it has no caller re-arm hook, so its group was killed before the main thread was released"
        ))
    } else {
        None
    };
    let dying = detach_at_exit_stop(task)?;
    Ok(ExitStopOutcome { dying, refusal })
}

#[cfg(test)]
thread_local! {
    /// Test-only: SIGKILL a fork child immediately before teardown or
    /// exit-stop detach, so the ESRCH arms run deterministically.
    static KILL_BEFORE_CHILD_DETACH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
#[allow(unsafe_code)]
fn before_child_detach(pid: safeptrace::Pid) {
    if KILL_BEFORE_CHILD_DETACH.with(std::cell::Cell::get) {
        // Thread-directed, so the stopped thread itself has a fatal
        // signal pending and PTRACE_DETACH fails with ESRCH; then
        // process-directed, so a live sibling takes it and the group
        // exit ends an exit stop. The tracee is attached and unreaped,
        // so its number is pinned.
        // SAFETY: tgkill reads only its scalar arguments.
        let sent =
            unsafe { libc::syscall(libc::SYS_tgkill, pid.as_raw(), pid.as_raw(), libc::SIGKILL) };
        assert_eq!(sent, 0, "test tgkill of a traced fork child");
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        )
        .expect("test kill of a traced fork child");
    }
}

#[cfg(not(test))]
fn before_child_detach(_pid: safeptrace::Pid) {}

#[cfg(test)]
thread_local! {
    /// Test-only: pause right after an exit-stop detach, so a kill that
    /// came after the detach (instead of before it) would be too late.
    static DELAY_AFTER_EXIT_STOP_DETACH: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn after_exit_stop_detach() {
    if let Some(delay) = DELAY_AFTER_EXIT_STOP_DETACH.with(std::cell::Cell::get) {
        std::thread::sleep(delay);
    }
}

#[cfg(not(test))]
fn after_exit_stop_detach() {}

/// Detach a fork child at its exit stop. Returns the wait to settle
/// instead when the child was killed out of that stop and is still
/// attached.
fn detach_at_exit_stop(task: Stopped) -> Result<Option<safeptrace::PtracerWaitDriver>> {
    before_child_detach(task.pid());
    let detached = task.detach(None);
    after_exit_stop_detach();
    match detached {
        Ok(_running) => Ok(None),
        Err(safeptrace::Error::Died(zombie)) => {
            Ok(Some(zombie.wait_owned_on_ptracer_thread().into_driver()))
        }
        Err(error) => Err(error.into()),
    }
}

/// The retained ptracer-thread wait for one running tracee.
fn leader_wait(running: Running) -> safeptrace::PtracerWaitDriver {
    running.wait_owned_on_ptracer_thread().into_driver()
}

fn poll_driver(
    driver: &mut safeptrace::PtracerWaitDriver,
) -> Option<std::result::Result<Wait, safeptrace::OwnedWaitError>> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    match driver.poll_on_ptracer_thread(&mut cx) {
        Poll::Ready(result) => Some(result),
        Poll::Pending => None,
    }
}

/// What a watched run's teardown observed.
struct Teardown {
    /// The leader's actual terminal status, when it exited while being
    /// quiesced and its status was consumed here.
    leader_status: Option<ExitStatus>,
    /// The first failure, also recorded as
    /// [`CleanupState::child_detach_error`].
    error: Option<String>,
}

/// The watched leader's in-flight wait and the driven fork children
/// of a watched run. Every exit path (leader exit, release, error,
/// cancellation, drop of the supervisor or successor stop, and
/// unwinding) ends in [`ChildSet::teardown`], so no exit path
/// knowingly leaves a guest task seized by a supervisor that will
/// never wait it again.
struct ChildSet {
    /// The leader's wait while it runs: present in a
    /// [`WatchedSupervisor`], absent while the leader is held at a
    /// successor stop, consumed, or exited.
    leader: Option<safeptrace::PtracerWaitDriver>,
    children: Vec<ChildWait>,
    receipt: CleanupReceipt,
}

impl ChildSet {
    fn new(leader: Option<safeptrace::PtracerWaitDriver>, receipt: CleanupReceipt) -> Self {
        Self {
            leader,
            children: Vec::new(),
            receipt,
        }
    }

    /// Quiesce the leader if it is still running, adopting any fork it
    /// reports on the way, then detach every child (including children
    /// met while detaching), killing and reaping any child that cannot
    /// be detached. The leader itself is left for its owner to kill.
    /// The first failure is recorded in the cleanup receipt and also
    /// returned.
    fn teardown(&mut self) -> Teardown {
        let mut leader_status = None;
        let mut first_error = None;
        if let Some(leader) = self.leader.take() {
            match quiesce_leader(leader, &mut self.children) {
                Ok(status) => leader_status = status,
                Err(error) => first_error = Some(error.to_string()),
            }
        }
        if let Err(error) = detach_children(std::mem::take(&mut self.children))
            && first_error.is_none()
        {
            first_error = Some(error.to_string());
        }
        if let Some(error) = &first_error {
            self.receipt
                .borrow_mut()
                .child_detach_error
                .get_or_insert_with(|| error.clone());
        }
        Teardown {
            leader_status,
            error: first_error,
        }
    }

    /// Tear down after `primary` failed, appending any teardown failure
    /// instead of discarding either one.
    fn teardown_after(
        &mut self,
        primary: Box<dyn std::error::Error>,
    ) -> Box<dyn std::error::Error> {
        match self.teardown().error {
            None => primary,
            Some(error) => {
                format!("{primary}; exec supervisor fork-child detach also failed: {error}").into()
            }
        }
    }
}

impl Drop for ChildSet {
    fn drop(&mut self) {
        // The receipt carries any failure: a dropped supervisor or
        // successor stop has no other error channel.
        self.teardown();
    }
}

/// How long one fork child's detach, one failed child's kill, or the
/// leader's quiesce may take before it is reported instead of waited
/// on forever.
const CHILD_DETACH_TIMEOUT: Duration = Duration::from_secs(2);

/// `PTRACE_INTERRUPT` one seized tracee. A task that is already gone
/// needs no interrupt.
fn interrupt_task(pid: safeptrace::Pid) -> Result<()> {
    match Running::new_on_ptracer_thread(pid) {
        Ok(running) => match running.interrupt() {
            Ok(()) => Ok(()),
            Err(reverie::Errno::ESRCH | reverie::Errno::ENOENT) => Ok(()),
            Err(error) => {
                Err(format!("exec supervisor interrupt failed for {pid:?}: {error}").into())
            }
        },
        Err(reverie::Errno::ESRCH | reverie::Errno::ENOENT) => Ok(()),
        Err(error) => {
            Err(format!("exec supervisor interrupt capture failed for {pid:?}: {error}").into())
        }
    }
}

/// Stop the running watched leader before it is killed. A fork's
/// child is auto-attached before the parent reports the fork event,
/// so killing a leader whose fork event is still pending would leave
/// that child seized in its initial stop with nobody to drive it.
/// After `PTRACE_INTERRUPT`, the leader's next stop is that pending
/// fork event if there is one (it precedes the interrupt trap), and
/// its child is adopted for detach. The stopped leader is left for
/// its owner's kill. Returns the leader's status if it exited
/// instead, and returns at once when the leader thread has already
/// exited (a zombie whose siblings still run cannot fork or stop; the
/// owner's process-directed kill ends it). Bounded: a leader blocked in a killable or
/// uninterruptible wait (for example `vfork` waiting for its child,
/// or D-state I/O) cannot stop, and is reported once the bound
/// passes; such a leader is not inside a fork.
fn quiesce_leader(
    mut leader: safeptrace::PtracerWaitDriver,
    children: &mut Vec<ChildWait>,
) -> Result<Option<ExitStatus>> {
    let Some(generation) = leader.generation() else {
        return Ok(None);
    };
    let pid = generation.pid();
    // An exited leader thread (a zombie whose siblings still run) can
    // neither fork nor stop; its owner's process-directed kill ends it.
    let cleanup = generation.terminal_cleanup();
    let leader_thread_exited = || matches!(cleanup.exit_effects_complete(), Ok(true));
    if leader_thread_exited() {
        return Ok(None);
    }
    interrupt_task(pid)?;
    let deadline = Instant::now() + CHILD_DETACH_TIMEOUT;
    loop {
        match poll_driver(&mut leader) {
            Some(Ok(Wait::Exited(_, status))) => return Ok(Some(status)),
            Some(Ok(Wait::Stopped(_leader_stop, Event::NewChild(_op, child)))) => {
                children.push(ChildWait::new(child));
                return Ok(None);
            }
            Some(Ok(Wait::Stopped(_leader_stop, _event))) => return Ok(None),
            Some(Err(safeptrace::OwnedWaitError::Completed)) => return Ok(None),
            // Dying: no fork can complete, and its owner settles it.
            Some(Err(safeptrace::OwnedWaitError::Died)) => return Ok(None),
            Some(Err(error)) => {
                return Err(format!(
                    "exec supervisor leader quiesce wait failed for {pid:?}: {error:?}"
                )
                .into());
            }
            None => {
                if leader_thread_exited() {
                    return Ok(None);
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "exec_supervisor_leader_quiesce_timeout: leader {pid:?} did not stop within {CHILD_DETACH_TIMEOUT:?} before its kill"
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// A child whose detach failed, with its retained kill descriptor. Its
/// [`ChildWait`] (exit claim included) is kept, because a killed child
/// still stops at its exit stop and that stop must be claimed too.
struct FailedChild {
    cleanup: safeptrace::TerminalCleanup,
    child: ChildWait,
}

/// Detach one driven fork child, taking ownership of any child its
/// stop carries. A signal-delivery stop detaches with its own signal
/// forwarded; event and trap stops detach with none. No `SIGCONT` is
/// ever injected here. A child whose detach fails is queued in
/// `failed` for the bounded kill in [`cancel_children`], so an error
/// can be reported without leaving that child seized.
fn detach_child(
    mut child: ChildWait,
    work: &mut Vec<ChildWait>,
    failed: &mut Vec<FailedChild>,
) -> Result<()> {
    let Some(generation) = child.driver.generation() else {
        return Ok(());
    };
    let result = match detach_child_inner(&mut child, generation.pid(), work) {
        // Settled, but refused: the child is already dead or detached
        // and needs no kill, only the report.
        Ok(Some(refusal)) => return Err(refusal.into()),
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    if result.is_err() {
        // A failure after the stop was consumed leaves a completed
        // driver; give the same entry a fresh wait to settle with.
        if child.driver.generation().is_none()
            && let Ok(running) = Running::new_on_ptracer_thread(generation.pid())
        {
            child.driver = leader_wait(running);
        }
        failed.push(FailedChild {
            cleanup: generation.terminal_cleanup(),
            child,
        });
    }
    result
}

/// Returns `Ok(Some(refusal))` when the child was settled but a
/// non-leader exec was refused at its exit stop.
fn detach_child_inner(
    child: &mut ChildWait,
    pid: safeptrace::Pid,
    work: &mut Vec<ChildWait>,
) -> Result<Option<String>> {
    let deadline = Instant::now() + CHILD_DETACH_TIMEOUT;
    let mut interrupted = false;
    let mut refusal = None;
    loop {
        if let Some(task) = child.poll_exit_stop() {
            match settle_exit_stop(task) {
                Ok(ExitStopOutcome {
                    dying: None,
                    refusal: refused,
                }) => return Ok(refused),
                Ok(ExitStopOutcome {
                    dying: Some(dying),
                    refusal: refused,
                }) => {
                    child.driver = dying;
                    interrupted = true;
                    refusal = refused;
                }
                Err(error) => {
                    return Err(format!(
                        "exec supervisor fork-child exit-stop detach failed for {pid:?}: {error}"
                    )
                    .into());
                }
            }
        }
        match poll_driver(&mut child.driver) {
            Some(Ok(Wait::Exited(_, _))) => return Ok(refusal),
            Some(Ok(Wait::Stopped(task, event))) => {
                before_child_detach(task.pid());
                let detached = match event {
                    Event::Signal(signal) => task.detach(Some(signal)),
                    Event::RawSignal(raw) => task.detach_raw(raw),
                    Event::NewChild(_op, grandchild) => {
                        work.push(ChildWait::new(grandchild));
                        task.detach(None)
                    }
                    // Every other stop, including a fork-child exec
                    // event that was still pending when teardown began
                    // (that new image then runs unarmed), detaches with
                    // no signal.
                    _ => task.detach(None),
                };
                match detached {
                    Ok(_running) => return Ok(refusal),
                    // ESRCH: the child left its stop because it is
                    // dying (a guest SIGKILL raced this detach). It is
                    // gone, but still attached: settle its terminal
                    // status, within the same bound, so no traced
                    // zombie is left behind.
                    Err(safeptrace::Error::Died(zombie)) => {
                        child.driver = zombie.wait_owned_on_ptracer_thread().into_driver();
                        interrupted = true;
                    }
                    Err(error) => {
                        return Err(format!(
                            "exec supervisor fork-child detach failed for {pid:?}: {error}"
                        )
                        .into());
                    }
                }
            }
            Some(Err(safeptrace::OwnedWaitError::Completed)) => return Ok(refusal),
            // Death observed while decoding: the driver still owns the
            // child, so keep polling it for the terminal status, within
            // the same bound.
            Some(Err(safeptrace::OwnedWaitError::Died)) => {
                interrupted = true;
                if Instant::now() >= deadline {
                    return Err(format!(
                        "exec_supervisor_fork_child_undrivable: dying fork child {pid:?} gave no terminal status within {CHILD_DETACH_TIMEOUT:?}"
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Some(Err(safeptrace::OwnedWaitError::Errno(reverie::Errno::ECHILD))) => {
                return Err(format!(
                    "exec_supervisor_fork_child_undrivable: fork child {pid:?} wait refused with ECHILD during detach"
                )
                .into());
            }
            Some(Err(error)) => {
                return Err(format!(
                    "exec supervisor fork-child detach wait failed for {pid:?}: {error:?}"
                )
                .into());
            }
            None => {
                if !interrupted {
                    interrupted = true;
                    interrupt_task(pid)?;
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "exec_supervisor_fork_child_undrivable: fork-child detach timed out for {pid:?} after {CHILD_DETACH_TIMEOUT:?}"
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Detach every driven fork child, including any child met while
/// detaching. Every child is attempted even after a failure; children
/// that could not be detached are then killed and reaped (bounded),
/// children met while killing them are detached in turn, and the
/// first error is returned.
fn detach_children(children: Vec<ChildWait>) -> Result<()> {
    let mut work = children;
    let mut first_error: Option<Box<dyn std::error::Error>> = None;
    while !work.is_empty() {
        let mut failed = Vec::new();
        while let Some(child) = work.pop() {
            if let Err(error) = detach_child(child, &mut work, &mut failed)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        work = cancel_children(failed);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Kill one fork child that could not be detached, process-directed
/// through its retained descriptor (a thread-directed kill would be
/// absorbed by an exited main thread whose siblings still run), and
/// drive it to a terminal state, bounded, so it is not left a traced
/// zombie. Delivery stops forward their own signal (including the
/// requested `SIGKILL`); a child it reports forking on the way is
/// returned in `adopted` for detach, not killed.
fn cancel_child(failed: FailedChild, adopted: &mut Vec<ChildWait>) {
    // An undelivered kill is observed by the bounded wait below.
    let _ = failed.cleanup.request_process_sigkill();
    let mut child = failed.child;
    let deadline = Instant::now() + CHILD_DETACH_TIMEOUT;
    loop {
        // The killed child stops at its exit stop: detach there, so its
        // zombie is reaped by the guest parent, not left traced.
        if let Some(task) = child.poll_exit_stop() {
            match detach_at_exit_stop(task) {
                Ok(None) => break,
                Ok(Some(dying)) => child.driver = dying,
                Err(_) => break,
            }
        }
        match poll_driver(&mut child.driver) {
            Some(Ok(Wait::Exited(_, _))) => break,
            Some(Ok(Wait::Stopped(task, event))) => {
                let resumed = match event {
                    Event::NewChild(_op, grandchild) => {
                        adopted.push(ChildWait::new(grandchild));
                        task.resume(None)
                    }
                    Event::Signal(signal) => task.resume(Some(signal)),
                    Event::RawSignal(raw) => task.resume_raw(raw),
                    _ => task.resume(None),
                };
                child.driver = match resumed {
                    Ok(running) => leader_wait(running),
                    Err(safeptrace::Error::Died(zombie)) => {
                        zombie.wait_owned_on_ptracer_thread().into_driver()
                    }
                    Err(_) => break,
                };
            }
            // Dying: keep polling the same owner for its terminal status.
            Some(Err(safeptrace::OwnedWaitError::Died)) => {}
            Some(Err(_)) => break,
            None => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }
}

/// Kill and settle every failed child; returns the children they were
/// seen forking, which still need a detach.
fn cancel_children(children: Vec<FailedChild>) -> Vec<ChildWait> {
    let mut adopted = Vec::new();
    for child in children {
        cancel_child(child, &mut adopted);
    }
    adopted
}

/// Claim the receipt, clone one owned child and seize it before its
/// initial exec. Shared by the detached and watched entry points.
fn seize_child<'fd>(
    mut request: PreparedExec<'fd>,
    receipt: CleanupReceipt,
    follow_forks: bool,
    before_seize: &mut dyn FnMut(safeptrace::Pid),
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
    before_seize(pid);
    let running = match Running::seize_on_ptracer_thread(pid, supervisor_options(follow_forks)) {
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
        Self::spawn_inner(request, receipt, mode, &mut |_| {}, &mut |_| {})
    }

    fn spawn_inner<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        mode: SupervisorMode,
        before_seize: &mut dyn FnMut(safeptrace::Pid),
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
        let (mut owner, running, pid, started, receipt) =
            seize_child(request, receipt, false, before_seize)?;
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
        Self::spawn_watched_inner(request, receipt, &mut |_| {}, &mut |_| {})
    }

    fn spawn_watched_inner<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
        before_seize: &mut dyn FnMut(safeptrace::Pid),
        before_initial_resume: &mut dyn FnMut(safeptrace::Pid),
    ) -> std::result::Result<WatchedSupervisor<'fd>, LaunchFailure<'fd>> {
        let (mut owner, running, pid, started, receipt) =
            seize_child(request, receipt, true, before_seize)?;
        match consume_handshake(&mut owner, running, pid, before_initial_resume) {
            Ok((running, group_stop_clear_pending)) => Ok(WatchedSupervisor {
                pid,
                started,
                children: ChildSet::new(Some(leader_wait(running)), receipt.clone()),
                owner,
                receipt,
                pre_first_exec: true,
                group_stop_clear_pending,
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

/// A driven fork child's state after one of its stops.
enum ChildNext {
    /// Resumed (or parked listening); keep driving it.
    Running(Running),
    /// It is dying and still attached: settle its terminal status.
    Dying(safeptrace::PtracerWaitDriver),
    /// Detached at its exit stop; nothing is left to drive.
    Detached,
    /// Refused by name and killed. Its own resumed wait, if the resume
    /// succeeded, is kept for teardown to settle; no fresh capture is
    /// made (one could be refused once the child is gone).
    Refused(Option<safeptrace::PtracerWaitDriver>, String),
}

/// Drive one stopped fork child to its next running state. Its
/// first stop is the auto-attach initial stop: install the fork-child
/// options and suppress it. Signals forward, group stops are parked
/// in the kernel listening state (native job control: the child stays
/// stopped until a guest continuer), and nested forks are captured as
/// new driven children. A fork child's exec is refused by name: no
/// caller re-arm hook exists for fork children yet, and running one
/// unarmed would escape supervision. When the child's traced main
/// thread reaches its exit stop it is detached there, so the guest
/// parent reaps it natively and an exited main thread whose siblings
/// still run never stays traced.
fn handle_child_stop(
    task: Stopped,
    event: Event,
    child: &mut ChildWait,
    new_children: &mut Vec<ChildWait>,
) -> Result<ChildNext> {
    let pid = task.pid();
    let cleanup = task.terminal_cleanup();
    let result = handle_child_stop_inner(task, event, &mut child.initialized, new_children);
    if result.is_err() {
        // The stopped capability was consumed by the failing
        // operation. Kill the exact generation (process-directed) and
        // give this same entry, whose exit claim the killed child's
        // exit stop needs, a fresh wait, so the caller's teardown can
        // still settle it (and any child captured above).
        let _ = cleanup.request_process_sigkill();
        if let Ok(running) = Running::new_on_ptracer_thread(pid) {
            child.driver = leader_wait(running);
        }
    }
    result
}

fn handle_child_stop_inner(
    task: Stopped,
    event: Event,
    initialized: &mut bool,
    new_children: &mut Vec<ChildWait>,
) -> Result<ChildNext> {
    if !*initialized {
        task.setoptions(fork_child_options())?;
        *initialized = true;
        if matches!(event, Event::Stop | Event::Signal(Signal::SIGSTOP)) {
            return Ok(ChildNext::Running(task.resume(None)?));
        }
    }
    let running = match event {
        Event::Exec(_former) => {
            // No caller hook contract exists for fork-child execs:
            // kill this child and fail the launch closed by name
            // rather than run its new image unarmed.
            if let Err(error) = kill_child_group(&task) {
                // Not resumed: resuming would run the new image.
                return Ok(ChildNext::Refused(
                    None,
                    format!(
                        "exec_supervisor_fork_child_exec_refused: fork-child execs have no caller re-arm hook; the kill could not be sent ({error}), so the child stays held at its exec stop"
                    ),
                ));
            }
            let resumed = match task.resume(None) {
                Ok(running) => Some(leader_wait(running)),
                // The kill already took it out of the stop: settle the
                // still-attached zombie through its own wait.
                Err(safeptrace::Error::Died(zombie)) => {
                    Some(zombie.wait_owned_on_ptracer_thread().into_driver())
                }
                Err(_) => None,
            };
            return Ok(ChildNext::Refused(
                resumed,
                "exec_supervisor_fork_child_exec_refused: fork-child execs have no caller re-arm hook"
                    .to_owned(),
            ));
        }
        // Exit stops normally arrive through the child's exit claim
        // (`ChildWait::poll_exit_stop`); one reported here is handled
        // the same way.
        Event::Exit => {
            let outcome = settle_exit_stop(task)?;
            return Ok(match (outcome.dying, outcome.refusal) {
                (dying, Some(refusal)) => ChildNext::Refused(dying, refusal),
                (None, None) => ChildNext::Detached,
                (Some(dying), None) => ChildNext::Dying(dying),
            });
        }
        Event::NewChild(_op, child) => {
            new_children.push(ChildWait::new(child));
            task.resume(None)?
        }
        Event::VforkDone => task.resume(None)?,
        Event::Signal(signal) => task.resume(Some(signal))?,
        Event::RawSignal(raw) => task.resume_raw(raw)?,
        Event::Stop => {
            let pid = task.pid();
            let signo = classify_group_stop_trap(
                &task,
                pid,
                "exec supervisor encountered unexpected fork-child stop trap",
            )?;
            if signo == libc::SIGTRAP {
                task.resume(None)?
            } else {
                // Native job control: park the child in the kernel
                // listening state instead of continuing it. It
                // re-traps only when a guest continuer's SIGCONT
                // (or SIGKILL) actually continues it.
                task.listen()?
            }
        }
        Event::Seccomp | Event::Syscall => task.resume(None)?,
    };
    Ok(ChildNext::Running(running))
}

/// Drive the seized guest until its next exec event or terminal
/// exit. Before the first exec, only this supervisor's own
/// group-stop-clearing SIGCONT trap/delivery may be suppressed;
/// any other pre-exec SIGCONT notify trap is resumed and its
/// delivery is forwarded.
/// Afterwards guest signal deliveries are forwarded unchanged; a
/// guest group stop is continued at once with this supervisor's
/// real `SIGCONT`, whose delivery is forwarded. The stop lasts
/// zero guest-visible time and the guest observes a SIGCONT from
/// the supervisor pid. On error the whole tree is torn down
/// (leader quiesced, children detached) before the error returns,
/// with any leader status consumed on the way.
fn wait_watched(
    pid: safeptrace::Pid,
    pre_first_exec: bool,
    group_stop_clear_pending: &mut bool,
    children: &mut ChildSet,
) -> std::result::Result<NextExec, (Box<dyn std::error::Error>, Option<ExitStatus>)> {
    match wait_watched_inner(pid, pre_first_exec, group_stop_clear_pending, children) {
        Ok(next) => Ok(next),
        Err(error) => {
            let teardown = children.teardown();
            let error = match teardown.error {
                None => error,
                Some(detach) => {
                    format!("{error}; exec supervisor fork-child detach also failed: {detach}")
                        .into()
                }
            };
            Err((error, teardown.leader_status))
        }
    }
}

fn wait_watched_inner(
    pid: safeptrace::Pid,
    pre_first_exec: bool,
    group_stop_clear_pending: &mut bool,
    children: &mut ChildSet,
) -> Result<NextExec> {
    loop {
        let mut progressed = false;
        let mut index = 0;
        while index < children.children.len() {
            if let Some(task) = children.children[index].poll_exit_stop() {
                progressed = true;
                let outcome = settle_exit_stop(task)?;
                let detached = match outcome.dying {
                    None => {
                        children.children.remove(index);
                        true
                    }
                    Some(dying) => {
                        children.children[index].driver = dying;
                        false
                    }
                };
                if let Some(refusal) = outcome.refusal {
                    return Err(refusal.into());
                }
                if detached {
                    continue;
                }
            }
            match poll_driver(&mut children.children[index].driver) {
                Some(Ok(Wait::Exited(_, _))) => {
                    children.children.remove(index);
                    progressed = true;
                }
                Some(Ok(Wait::Stopped(task, event))) => {
                    progressed = true;
                    let mut new_children = Vec::new();
                    let next = handle_child_stop(
                        task,
                        event,
                        &mut children.children[index],
                        &mut new_children,
                    );
                    let initialized = children.children[index].initialized;
                    match next {
                        Ok(ChildNext::Running(next)) => {
                            children.children[index].driver = leader_wait(next);
                            index += 1;
                        }
                        Ok(ChildNext::Dying(driver)) => {
                            children.children[index] = ChildWait::settling(driver, initialized);
                            index += 1;
                        }
                        Ok(ChildNext::Detached) => {
                            children.children.remove(index);
                        }
                        Ok(ChildNext::Refused(resumed, refusal)) => {
                            if let Some(driver) = resumed {
                                children.children[index].driver = driver;
                            }
                            children.children.extend(new_children);
                            return Err(refusal.into());
                        }
                        Err(error) => {
                            // Keep any child captured by the failing
                            // call (and its recovery driver) owned by
                            // the set the error path tears down.
                            children.children.extend(new_children);
                            return Err(error);
                        }
                    }
                    children.children.extend(new_children);
                }
                Some(Err(safeptrace::OwnedWaitError::Died)) => {
                    return Err(
                        "exec_supervisor_fork_child_undrivable: fork child died without a terminal status"
                            .into(),
                    );
                }
                Some(Err(safeptrace::OwnedWaitError::Errno(reverie::Errno::ECHILD))) => {
                    return Err(
                        "exec_supervisor_fork_child_undrivable: fork child wait refused with ECHILD"
                            .into(),
                    );
                }
                Some(Err(error)) => {
                    return Err(format!("exec supervisor fork-child wait failed: {error:?}").into());
                }
                None => index += 1,
            }
        }
        let leader = children
            .leader
            .as_mut()
            .ok_or("exec supervisor watched leader has no running wait")?;
        if let Some(waited) = poll_driver(leader) {
            progressed = true;
            // A refused poll keeps the driver for teardown's quiesce;
            // a completed one transfers the leader's state to `waited`.
            let waited = waited?;
            children.leader = None;
            match waited {
                Wait::Exited(_, status) => {
                    // The leader's actual status is kept even when a
                    // child cannot be detached: that failure is
                    // recorded in the cleanup receipt the outcome
                    // carries (`CleanupState::child_detach_error`).
                    children.teardown();
                    return Ok(NextExec::Finished(status));
                }
                Wait::Stopped(task, Event::Exec(former)) => {
                    if former != pid {
                        return Err(format!(
                            "exec supervisor expected exec of {pid:?}, got former {former:?}"
                        )
                        .into());
                    }
                    return Ok(NextExec::Exec(task));
                }
                Wait::Stopped(task, Event::NewChild(_op, child)) => {
                    children.children.push(ChildWait::new(child));
                    children.leader = Some(leader_wait(task.resume(None)?));
                }
                Wait::Stopped(task, Event::Stop) if pre_first_exec && *group_stop_clear_pending => {
                    require_group_stop_clear_trap(&task, pid)?;
                    children.leader = Some(leader_wait(task.resume(None)?));
                }
                Wait::Stopped(task, Event::Signal(Signal::SIGCONT))
                    if pre_first_exec && *group_stop_clear_pending =>
                {
                    require_owned_sigcont(&task)?;
                    *group_stop_clear_pending = false;
                    children.leader = Some(leader_wait(task.resume(None)?));
                }
                Wait::Stopped(task, Event::Signal(Signal::SIGSTOP)) if pre_first_exec => {
                    require_owned_handshake_sigstop(&task, pid)?;
                    return Err(
                        "exec supervisor encountered SIGSTOP before exec: no handshake signal was pending"
                            .into(),
                    );
                }
                Wait::Stopped(task, Event::Signal(signal)) => {
                    children.leader = Some(leader_wait(task.resume(Some(signal))?));
                }
                Wait::Stopped(task, Event::RawSignal(raw)) => {
                    children.leader = Some(leader_wait(task.resume_raw(raw)?));
                }
                Wait::Stopped(task, Event::Stop) => {
                    // Classify by siginfo, with no pending flag: every
                    // SIGCONT to a seized task arms a SIGTRAP notify
                    // trap, whether or not the guest was stopped, and a
                    // SIGCONT delivery need not reach the traced leader.
                    let signo = classify_group_stop_trap(
                        &task,
                        pid,
                        "exec supervisor encountered unexpected watched stop trap",
                    )?;
                    if signo == libc::SIGTRAP {
                        // SIGCONT notify trap. This loop never
                        // interrupts the running leader: only teardown
                        // does (`quiesce_leader`), and it consumes its
                        // own trap and never resumes the leader.
                        children.leader = Some(leader_wait(task.resume(None)?));
                        continue;
                    }
                    if pre_first_exec {
                        return Err(
                            "exec supervisor encountered unexpected group stop before exec".into(),
                        );
                    }
                    // A signal injected on the group-stop resume would be
                    // ignored and leave the natural-parent stop report
                    // for after detach. Generate a real SIGCONT instead;
                    // its notify trap is consumed above and its delivery
                    // reaches the general signal arm.
                    send_own_sigcont(pid)?;
                    children.leader = Some(leader_wait(task.resume(None)?));
                }
                Wait::Stopped(_task, other_event) => {
                    return Err(format!(
                        "exec supervisor encountered unexpected stop while watched: {other_event:?}"
                    )
                    .into());
                }
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A seized, running guest under exec watch. Retains the physical
/// owner until [`WatchedSupervisor::wait_next`] reports the terminal
/// outcome (or drop: the leader is quiesced and the driven fork
/// children detached, then the owner retires through its bounded
/// best-effort cleanup; `EXITKILL` covers supervisor death).
#[must_use = "retain the watched supervisor through its terminal outcome or cancellation"]
pub struct WatchedSupervisor<'fd> {
    pid: safeptrace::Pid,
    started: Instant,
    // Declared before `owner`: fields drop in order, so the leader's
    // pending fork is adopted and the children are detached before
    // the owner kills the leader.
    children: ChildSet,
    owner: ChildOwner<'fd>,
    receipt: CleanupReceipt,
    pre_first_exec: bool,
    group_stop_clear_pending: bool,
    execs_seen: u64,
}

impl std::fmt::Debug for WatchedSupervisor<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchedSupervisor")
            .field("pid", &self.pid)
            .field("execs_seen", &self.execs_seen)
            .field("children", &self.children.children.len())
            .field("owner", &self.owner)
            .field("running", &self.children.leader.is_some())
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
    pub fn wait_next(self) -> std::result::Result<WatchedStep<'fd>, LaunchFailure<'fd>> {
        let Self {
            pid,
            started,
            mut owner,
            receipt,
            pre_first_exec,
            mut group_stop_clear_pending,
            execs_seen,
            mut children,
        } = self;
        let next = wait_watched(
            pid,
            pre_first_exec,
            &mut group_stop_clear_pending,
            &mut children,
        );
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
                    children,
                }))),
                Err(error) => {
                    let error = children.teardown_after(error);
                    Err(launch_failure(owner, receipt, error))
                }
            },
            Err((error, leader_status)) => {
                if let Some(status) = leader_status {
                    owner.record_detached_terminal(status);
                }
                Err(launch_failure(owner, receipt, error))
            }
        }
    }

    /// Cancel while seized, before any terminal outcome. The running
    /// leader is first interrupted and stopped, adopting a fork it had
    /// not yet reported; the driven fork children are then detached
    /// (killed and reaped only if a detach fails); the leader is then
    /// cancelled. A teardown failure is reported in the returned (or
    /// retained) cleanup state as
    /// [`CleanupState::child_detach_error`].
    pub fn cancel(mut self) -> std::result::Result<CleanupState, Box<ChildOwner<'fd>>> {
        if let Some(status) = self.children.teardown().leader_status {
            self.owner.record_detached_terminal(status);
        }
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
    // Declared before `owner`, as in `WatchedSupervisor`.
    children: ChildSet,
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
            .field("children", &self.children.children.len())
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

    /// Duplicate this held birth's original kernel pidfd for
    /// coordinator admission, exactly as
    /// [`super::InitialExecStop::duplicate_birth_pidfd`] does for a
    /// first image. This conveys descriptor identity only, never
    /// wait ownership or permission to resume.
    #[cfg(feature = "loader-private-runtime")]
    pub fn duplicate_birth_pidfd(&self) -> Result<std::os::fd::OwnedFd> {
        self.owner.duplicate_birth_pidfd(&self.task)
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
            mut children,
        } = self;
        let result = hook(task, &context, &boundary).and_then(|task| {
            context.restore(&task)?;
            Ok(task.resume(None)?)
        });
        match result {
            Ok(running) => {
                children.leader = Some(leader_wait(running));
                Ok(WatchedSupervisor {
                    pid,
                    started,
                    children,
                    owner,
                    receipt,
                    pre_first_exec: false,
                    group_stop_clear_pending: false,
                    execs_seen,
                })
            }
            Err(error) => {
                let error = children.teardown_after(error);
                Err(launch_failure(owner, receipt, error))
            }
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
            mut children,
        } = self;
        if let Some(error) = children.teardown().error {
            return Err(launch_failure(owner, receipt, error.into()));
        }
        let former_tid = boundary.former_tid;
        // Detach with SIGCONT, like the dormant path. Group stops
        // encountered while watched were already cleared while
        // seized, so this detach signal is not what clears their
        // natural-parent reports. It flushes a stop signal queued
        // while this successor stop was held; if the guest blocks
        // SIGCONT, the detach SIGCONT stays pending in the new image.
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
    /// Driven fork children are detached first (killed and reaped
    /// only if a detach fails); the leader is then cancelled. A
    /// teardown failure is reported in the returned (or retained)
    /// cleanup state as [`CleanupState::child_detach_error`].
    pub fn cancel(mut self) -> std::result::Result<CleanupState, Box<ChildOwner<'fd>>> {
        self.children.teardown();
        self.owner.cancel()
    }

    /// Read the successor's original input bytes from this actual
    /// stopped generation, exactly as
    /// [`super::InitialExecStop::capture_initial_inputs`] does for a
    /// first image. No resume capability escapes.
    pub fn capture_initial_inputs(&self) -> Result<super::initial_inputs::CapturedInitialInputs> {
        super::initial_inputs::capture_initial_inputs_parts(&self.task, &self.context, &self.owner)
    }

    /// Assemble copied original inputs for this successor stop,
    /// exactly as [`super::InitialExecStop::prepare_copied_inputs`]
    /// does for a first image. Returns no handoff or entry
    /// capability.
    #[cfg(feature = "loader-private-runtime")]
    pub fn prepare_copied_inputs(
        &self,
        captured: &super::initial_inputs::CapturedInitialInputs,
        image: &reverie_loader::image::ValidatedImage<'_>,
        request: &super::CopiedInputRequest,
    ) -> Result<super::CopiedInitialData> {
        super::input_data::prepare_copied_inputs_parts(
            &self.task,
            &self.context,
            &self.owner,
            captured,
            image,
            request,
        )
    }

    /// Crate-private decomposition into stopped-image parts. The
    /// public hook surface always keeps the stop whole; only the
    /// physical-preparation entry in this crate may split it, and
    /// the parts are rechecked against each other there.
    #[cfg(feature = "loader-private-runtime")]
    pub(crate) fn into_parts(
        mut self,
    ) -> (
        Stopped,
        EntryContext,
        ExecBoundary,
        ChildOwner<'fd>,
        Result<()>,
    ) {
        // The prepared-mapping path owns only the leader stop; fork
        // children of the old image are detached here rather than
        // left seized with nobody left to wait them. The detach
        // result travels with the parts so the preparation entry
        // can fail with it instead of discarding it.
        let detach = match self.children.teardown().error {
            None => Ok(()),
            Some(error) => Err(error.into()),
        };
        (self.task, self.context, self.boundary, self.owner, detach)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::OnceLock;

    use super::*;

    fn request(program: &str, arguments: &[&str]) -> PreparedExec<'static> {
        let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
        PreparedExec::new(Path::new(program), &arguments, &[], None, Vec::new()).unwrap()
    }

    fn fork_guest() -> &'static Path {
        static GUEST: OnceLock<PathBuf> = OnceLock::new();
        GUEST.get_or_init(|| {
            let directory = std::env::temp_dir().join(format!(
                "reverie-supervisor-fork-guest-{}",
                std::process::id()
            ));
            fs::create_dir_all(&directory).unwrap();
            let source = directory.join("guest.c");
            let program = directory.join("guest");
            fs::write(&source, FORK_GUEST_C).unwrap();
            let output = std::process::Command::new("cc")
                .args([
                    "-std=gnu11",
                    "-O1",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pthread",
                ])
                .arg(&source)
                .arg("-o")
                .arg(&program)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fork guest cc failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            program
        })
    }

    fn fork_request(mode: &str, extra: &[&Path]) -> PreparedExec<'static> {
        let program = fork_guest();
        let mut arguments = vec![program.as_os_str().to_owned(), OsString::from(mode)];
        arguments.extend(extra.iter().map(|path| path.as_os_str().to_owned()));
        PreparedExec::new(program, &arguments, &[], None, Vec::new()).unwrap()
    }

    fn supervisor_test_file(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-supervisor-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[allow(unsafe_code)]
    fn current_tid() -> i32 {
        // SAFETY: gettid takes no arguments and cannot fail for the
        // calling thread.
        unsafe { libc::syscall(libc::SYS_gettid) as i32 }
    }

    fn traced_by_current_thread() -> Vec<i32> {
        let tid = current_tid();
        let mut traced = Vec::new();
        for entry in fs::read_dir("/proc").unwrap() {
            let Ok(entry) = entry else { continue };
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:")
                    && rest.trim().parse::<i32>() == Ok(tid)
                {
                    traced.push(pid);
                }
            }
        }
        traced
    }

    fn assert_no_traced_by_current_thread(context: &str) {
        let traced = traced_by_current_thread();
        let described: Vec<String> = traced
            .iter()
            .map(|pid| {
                let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                let field = |name: &str| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix(name))
                        .map_or("?", str::trim)
                        .to_owned()
                };
                format!(
                    "{pid} {} {} ppid={} threads={}",
                    field("Name:"),
                    field("State:"),
                    field("PPid:"),
                    field("Threads:")
                )
            })
            .collect();
        assert!(
            traced.is_empty(),
            "{context}: tasks still traced by supervisor thread {}: {described:?}",
            current_tid()
        );
    }

    fn watched_next_exec(watched: WatchedSupervisor<'_>) -> Box<SuccessorStop<'_>> {
        match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected an exec stop, got terminal {outcome:?}")
            }
        }
    }

    fn rearm_ok(stop: Box<SuccessorStop<'_>>) -> WatchedSupervisor<'_> {
        stop.rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap()
    }

    /// A background child's marker is written immediately before its
    /// `_exit(0)`, so finding it proves the child survived teardown
    /// (neither killed nor left stopped) and ran to a clean exit.
    fn wait_for_marker(path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if fs::read_to_string(path).is_ok_and(|text| text == "exit=0\n") {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    /// Start the grandchild-at-detach guest and hold its leader's
    /// successor stop until the fork child (not driven while the stop is
    /// held) has forked: its fork event and the grandchild's initial stop
    /// are then both waiting for the teardown detach.
    fn grandchild_held_at_release() -> Box<SuccessorStop<'static>> {
        let pid_file = supervisor_test_file("grandchild.pid");
        let watched = Supervisor::spawn_watched(
            fork_request("grandchild-at-detach", &[&pid_file]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let child = fs::read_to_string(&pid_file).unwrap().trim().to_owned();
        let _ = fs::remove_file(&pid_file);
        let deadline = Instant::now() + Duration::from_secs(5);
        let forked = loop {
            let found = fs::read_dir("/proc").unwrap().flatten().any(|entry| {
                fs::read_to_string(entry.path().join("status")).is_ok_and(|status| {
                    status
                        .lines()
                        .any(|line| line.strip_prefix("PPid:").map(str::trim) == Some(&child))
                })
            });
            if found || Instant::now() >= deadline {
                break found;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(forked, "fork child {child} did not fork its grandchild");
        stop
    }

    fn assert_child_survived(marker: &Path, context: &str) {
        assert!(
            wait_for_marker(marker, Duration::from_secs(5)),
            "{context}: background child did not survive teardown and exit 0 (no marker at {})",
            marker.display()
        );
        let _ = fs::remove_file(marker);
    }

    /// Run one whole supervision on a fresh thread (its own ptracer
    /// thread) and fail, rather than hang, if it does not finish in
    /// time.
    fn run_bounded<T: Send + 'static>(
        timeout: Duration,
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(body());
        });
        receiver.recv_timeout(timeout).unwrap_or_else(|error| {
            panic!("supervision did not finish within {timeout:?}: {error}")
        })
    }

    const FORK_GUEST_C: &str = r#"
#define _DEFAULT_SOURCE 1
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int write_text(const char *path, const char *text) {
  FILE *file = fopen(path, "w");
  if (!file) return -1;
  int ok = fputs(text, file) >= 0;
  if (fclose(file) != 0) ok = 0;
  return ok ? 0 : -1;
}

static void close_output(void) {
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

static int wait_status(pid_t pid) {
  int status = 0;
  if (waitpid(pid, &status, 0) != pid) return -1;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -2;
}

static int state_of(pid_t pid) {
  char path[64];
  char buffer[4096];
  snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
  FILE *file = fopen(path, "r");
  if (!file) return '?';
  size_t count = fread(buffer, 1, sizeof(buffer) - 1, file);
  fclose(file);
  buffer[count] = '\0';
  char *state = strstr(buffer, "\nState:");
  if (!state) return '?';
  state += strlen("\nState:");
  while (*state == ' ' || *state == '\t') state++;
  return *state ? *state : '?';
}

static int stop_child(void) {
  pid_t pid = fork();
  if (pid == 0) {
    kill(getpid(), SIGSTOP);
    _exit(5);
  }
  if (pid < 0) return 9;
  usleep(200000);
  int state = state_of(pid);
  kill(pid, SIGCONT);
  int status = wait_status(pid);
  return (state == 'T' || state == 't') && status == 5 ? 7 : 9;
}

static int stop_child_leader_exit(const char *pid_path) {
  pid_t pid = fork();
  if (pid == 0) {
    char text[64];
    snprintf(text, sizeof(text), "%d\n", (int)getpid());
    if (write_text(pid_path, text) != 0) _exit(10);
    close_output();
    kill(getpid(), SIGSTOP);
    _exit(5);
  }
  if (pid < 0) return 9;
  usleep(200000);
  return 7;
}

/* A background child that records its own pid, sleeps, and writes
 * its marker immediately before _exit(0): a marker proves it was
 * neither killed nor left stopped by the supervisor's teardown. */
static pid_t marker_sleeper(const char *pid_path, const char *marker,
                            useconds_t delay) {
  pid_t pid = fork();
  if (pid == 0) {
    char text[64];
    close_output();
    if (pid_path) {
      snprintf(text, sizeof(text), "%d\n", (int)getpid());
      if (write_text(pid_path, text) != 0) _exit(10);
    }
    usleep(delay);
    if (write_text(marker, "exit=0\n") != 0) _exit(10);
    _exit(0);
  }
  return pid;
}

static int sleep_child_exec_leader(const char *pid_path, const char *marker) {
  if (marker_sleeper(pid_path, marker, 700000) < 0) return 9;
  /* The pid file proves the child is running (its initial stop was
   * driven) before the caller may hold the leader's exec stop. */
  for (int i = 0; i < 400 && access(pid_path, F_OK) != 0; i++) usleep(5000);
  execl("/bin/true", "true", (char *)NULL);
  return 111;
}

static int fork_loop(int exec_child) {
  if (exec_child) {
    pid_t pid = fork();
    if (pid == 0) {
      usleep(20000);
      execl("/bin/true", "true", (char *)NULL);
      _exit(111);
    }
    if (pid < 0) return 9;
  }
  for (;;) {
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    if (pid < 0) return 9;
    if (wait_status(pid) != 0) return 9;
  }
}

static int nested_fork(void) {
  pid_t pid = fork();
  if (pid == 0) {
    pid_t grandchild = fork();
    if (grandchild == 0) _exit(6);
    if (grandchild < 0) _exit(10);
    _exit(wait_status(grandchild) == 6 ? 0 : 10);
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}

static void *finish_after_leader_thread_exit(void *marker) {
  usleep(2500000);
  if (write_text((const char *)marker, "exit=0\n") != 0) _exit(10);
  _exit(0);
}

/* The fork child's main (traced) thread exits while a sibling keeps
 * running; the guest leader exits 7 long before that sibling ends. */
static int zombie_leader_child(const char *marker) {
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (pthread_create(&thread, NULL, finish_after_leader_thread_exit,
                       (void *)marker) != 0)
      _exit(10);
    pthread_exit(NULL);
  }
  if (pid < 0) return 9;
  usleep(100000);
  return 7;
}

static int sleep_leader_exec_true(void) {
  usleep(300000);
  execl("/bin/true", "true", (char *)NULL);
  return 111;
}

static int grandchild_at_detach(const char *pid_path) {
  pid_t pid = fork();
  if (pid == 0) {
    char text[64];
    close_output();
    snprintf(text, sizeof(text), "%d\n", (int)getpid());
    if (write_text(pid_path, text) != 0) _exit(10);
    usleep(300000);
    pid_t grandchild = fork();
    if (grandchild == 0) {
      usleep(800000);
      _exit(6);
    }
    if (grandchild < 0) _exit(10);
    _exit(wait_status(grandchild) == 6 ? 0 : 10);
  }
  if (pid < 0) return 9;
  /* The pid file proves the child is running before the caller may
   * hold the leader's exec stop. */
  for (int i = 0; i < 400 && access(pid_path, F_OK) != 0; i++) usleep(5000);
  execl("/bin/true", "true", (char *)NULL);
  return 111;
}

static volatile sig_atomic_t usr1_count;
static volatile sig_atomic_t cont_count;
static void on_usr1(int signal) { (void)signal; usr1_count++; }
static void on_cont(int signal) { (void)signal; cont_count++; }

static int signal_child(const char *pid_path, const char *result_path) {
  pid_t pid = fork();
  if (pid == 0) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = on_usr1;
    if (sigaction(SIGUSR1, &action, NULL) != 0) _exit(10);
    action.sa_handler = on_cont;
    if (sigaction(SIGCONT, &action, NULL) != 0) _exit(10);
    char text[64];
    snprintf(text, sizeof(text), "%d\n", (int)getpid());
    if (write_text(pid_path, text) != 0) _exit(10);
    while (!usr1_count && !cont_count) pause();
    snprintf(text, sizeof(text), "usr1=%d cont=%d\n", (int)usr1_count,
             (int)cont_count);
    if (write_text(result_path, text) != 0) _exit(10);
    _exit(0);
  }
  if (pid < 0) return 9;
  for (int i = 0; i < 200 && access(pid_path, F_OK) != 0; i++) usleep(5000);
  execl("/bin/true", "true", (char *)NULL);
  return 111;
}

static const char *exec_marker;

static void *exec_marker_writer(void *unused) {
  (void)unused;
  execl("/bin/sh", "sh", "-c", ": > \"$0\"", exec_marker, (char *)NULL);
  _exit(112);
}

/* A fork child whose non-leader thread execs an image that writes a
 * marker: a marker proves the new image ran. Optionally the child is
 * made non-dumpable first, which hides its /proc syscall files. */
static int thread_exec_child_marker(const char *marker, int nondumpable) {
  exec_marker = marker;
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (nondumpable && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(13);
    if (pthread_create(&thread, NULL, exec_marker_writer, NULL) != 0) _exit(10);
    if (pthread_join(thread, NULL) != 0) _exit(11);
    _exit(12);
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}

#if defined(__x86_64__)
/* The exec'ing thread enters execve through the ia32 entry (int $0x80,
 * nr 11), so its /proc syscall file shows 11, not 59. ia32 takes 32-bit
 * pointers, so the strings and argv live in a MAP_32BIT page. */
static void *exec_marker_writer_int80(void *unused) {
  (void)unused;
  char *low = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
  if (low == MAP_FAILED) _exit(114);
  const char *strs[4] = {"/bin/sh", "-c", ": > \"$0\"", exec_marker};
  uint32_t *argv32 = (uint32_t *)(void *)low;
  char *p = low + 64;
  for (int i = 0; i < 4; i++) {
    size_t n = strlen(strs[i]) + 1;
    memcpy(p, strs[i], n);
    argv32[i] = (uint32_t)(uintptr_t)p;
    p += n;
  }
  argv32[4] = 0;
  long ret;
  __asm__ volatile("int $0x80"
                   : "=a"(ret)
                   : "a"(11L), "b"((long)argv32[0]), "c"((long)(uintptr_t)argv32),
                     "d"(0L)
                   : "memory", "r8", "r9", "r10", "r11");
  (void)ret;
  _exit(113);
}

static int thread_exec_child_marker_int80(const char *marker) {
  exec_marker = marker;
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (pthread_create(&thread, NULL, exec_marker_writer_int80, NULL) != 0)
      _exit(10);
    if (pthread_join(thread, NULL) != 0) _exit(11);
    _exit(12);
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}
#endif

static void *park_forever(void *unused) {
  (void)unused;
  for (;;) pause();
  return NULL;
}

static int park_threads(int count) {
  pthread_attr_t attr;
  pthread_t thread;
  if (pthread_attr_init(&attr) != 0) return -1;
  /* 65536 is below the thread-stack minimum on aarch64 (128 KiB), where
   * setstacksize fails EINVAL and no thread is created; use the larger
   * of the two so the parked threads exist on both architectures. */
  long min_stack = sysconf(_SC_THREAD_STACK_MIN);
  size_t stack_size = 65536;
  if (min_stack > (long)stack_size) stack_size = (size_t)min_stack;
  if (pthread_attr_setstacksize(&attr, stack_size) != 0) return -1;
  for (int i = 0; i < count; i++)
    if (pthread_create(&thread, &attr, park_forever, NULL) != 0) return -1;
  return 0;
}

/* A fork child with `count` parked threads, then a last thread that
 * execs the marker image: de_thread kills the parked threads while
 * /proc/<pid>/task is walked, so walks can come up short. */
static int many_thread_exec_child_marker(const char *marker, int count) {
  exec_marker = marker;
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (park_threads(count) != 0) _exit(14);
    if (pthread_create(&thread, NULL, exec_marker_writer, NULL) != 0) _exit(10);
    if (pthread_join(thread, NULL) != 0) _exit(11);
    _exit(12);
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}

static int count_tasks(void) {
  DIR *dir = opendir("/proc/self/task");
  if (!dir) return -1;
  int count = 0;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL)
    if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') count++;
  closedir(dir);
  return count;
}

/* Park `count` threads, prove they exist by counting
 * /proc/self/task, and record the count in the marker. */
static int park_count(const char *marker, int count) {
  if (park_threads(count) != 0) return 14;
  int tasks = count_tasks();
  char text[32];
  snprintf(text, sizeof(text), "tasks=%d\n", tasks);
  if (write_text(marker, text) != 0) return 10;
  return tasks == count + 1 ? 7 : 9;
}

static void *exit_group_zero(void *unused) {
  (void)unused;
  usleep(20000);
  exit(0);
}

/* Control: a non-dumpable fork child with `count` parked threads, one
 * of which calls exit(0) (exit_group). Its main thread is killed
 * (PF_SIGNALED) with no exec anywhere. */
static int many_thread_exit_group_nondumpable(int count) {
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(13);
    if (park_threads(count) != 0) _exit(14);
    if (pthread_create(&thread, NULL, exit_group_zero, NULL) != 0) _exit(10);
    for (;;) pause();
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}

static void *busy_then_marker(void *marker) {
  struct timespec start, now;
  clock_gettime(CLOCK_MONOTONIC, &start);
  do {
    clock_gettime(CLOCK_MONOTONIC, &now);
  } while ((now.tv_sec - start.tv_sec) * 1000000000L +
               (now.tv_nsec - start.tv_nsec) <
           400000000L);
  if (write_text((const char *)marker, "exit=0\n") != 0) _exit(10);
  _exit(0);
}

/* Control: a non-dumpable fork child's main thread exits on its own
 * while a sibling spins (shown "running", syscall file unreadable),
 * then the sibling writes its marker and exits 0. */
static int busy_sibling_main_exit(const char *marker) {
  pid_t pid = fork();
  if (pid == 0) {
    pthread_t thread;
    close_output();
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(13);
    if (pthread_create(&thread, NULL, busy_then_marker, (void *)marker) != 0)
      _exit(10);
    pthread_exit(NULL);
  }
  if (pid < 0) return 9;
  usleep(100000);
  return 7;
}

static void *marker_after_leader_exit(void *marker) {
  usleep(3000000);
  if (write_text((const char *)marker, "exit=0\n") != 0) _exit(10);
  _exit(0);
}

/* The guest leader's own traced main thread exits while a sibling
 * sleeps 3 s and then writes its marker. */
static int leader_pthread_exit(const char *marker) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, marker_after_leader_exit,
                     (void *)marker) != 0)
    return 10;
  pthread_exit(NULL);
}

/* A healthy background child, then a child blocked in vfork while
 * its vfork child sleeps past the teardown bound; the leader then
 * execs so the caller holds its successor stop. Teardown takes the
 * newest child first, so it meets the blocked child (and fails on
 * it) before the healthy one. */
static pid_t vfork_blocked_child(void) {
  pid_t pid = fork();
  if (pid == 0) {
    close_output();
    pid_t inner = vfork();
    if (inner == 0) {
      struct timespec delay = {3, 0};
      nanosleep(&delay, NULL);
      _exit(0);
    }
    _exit(inner < 0 ? 10 : 0);
  }
  return pid;
}

static int vfork_wait_child_with_sleeper(const char *marker) {
  if (marker_sleeper(NULL, marker, 700000) < 0) return 9;
  if (vfork_blocked_child() < 0) return 9;
  usleep(300000);
  execl("/bin/true", "true", (char *)NULL);
  return 111;
}

/* The same blocked child, but the leader simply exits 7 at 300 ms. */
static int vfork_wait_child_leader_exit(void) {
  if (vfork_blocked_child() < 0) return 9;
  usleep(300000);
  return 7;
}

static int vfork_exit(void) {
  pid_t pid = vfork();
  if (pid == 0) _exit(5);
  if (pid < 0) return 9;
  return wait_status(pid) == 5 ? 7 : 9;
}

static int vfork_exec(void) {
  pid_t pid = vfork();
  if (pid == 0) {
    execl("/bin/true", "true", (char *)NULL);
    _exit(111);
  }
  if (pid < 0) return 9;
  return wait_status(pid) == 0 ? 7 : 9;
}

int main(int argc, char **argv) {
  if (argc < 2) return 2;
  if (strcmp(argv[1], "stop-child") == 0) return stop_child();
  if (strcmp(argv[1], "stop-child-leader-exit") == 0 && argc == 3)
    return stop_child_leader_exit(argv[2]);
  if (strcmp(argv[1], "sleep-child-exec-leader") == 0 && argc == 4)
    return sleep_child_exec_leader(argv[2], argv[3]);
  if (strcmp(argv[1], "fork-loop") == 0) return fork_loop(0);
  if (strcmp(argv[1], "fork-loop-exec-child") == 0) return fork_loop(1);
  if (strcmp(argv[1], "nested-fork") == 0) return nested_fork();
  if (strcmp(argv[1], "zombie-leader-child") == 0 && argc == 3)
    return zombie_leader_child(argv[2]);
  if (strcmp(argv[1], "vfork-wait-child-with-sleeper") == 0 && argc == 3)
    return vfork_wait_child_with_sleeper(argv[2]);
  if (strcmp(argv[1], "vfork-wait-child-leader-exit") == 0)
    return vfork_wait_child_leader_exit();
  if (strcmp(argv[1], "sleep-leader-exec-true") == 0)
    return sleep_leader_exec_true();
  if (strcmp(argv[1], "grandchild-at-detach") == 0 && argc == 3)
    return grandchild_at_detach(argv[2]);
  if (strcmp(argv[1], "signal-child") == 0 && argc == 4)
    return signal_child(argv[2], argv[3]);
  if (strcmp(argv[1], "thread-exec-child-marker") == 0 && argc == 3)
    return thread_exec_child_marker(argv[2], 0);
  if (strcmp(argv[1], "thread-exec-child-marker-nondumpable") == 0 && argc == 3)
    return thread_exec_child_marker(argv[2], 1);
#if defined(__x86_64__)
  if (strcmp(argv[1], "thread-exec-child-marker-int80") == 0 && argc == 3)
    return thread_exec_child_marker_int80(argv[2]);
#endif
  if (strcmp(argv[1], "many-thread-exec-child-marker") == 0 && argc == 4)
    return many_thread_exec_child_marker(argv[2], atoi(argv[3]));
  if (strcmp(argv[1], "park-count") == 0 && argc == 4)
    return park_count(argv[2], atoi(argv[3]));
  if (strcmp(argv[1], "many-thread-exit-group-nondumpable") == 0 && argc == 3)
    return many_thread_exit_group_nondumpable(atoi(argv[2]));
  if (strcmp(argv[1], "busy-sibling-main-exit") == 0 && argc == 3)
    return busy_sibling_main_exit(argv[2]);
  if (strcmp(argv[1], "leader-pthread-exit") == 0 && argc == 3)
    return leader_pthread_exit(argv[2]);
  if (strcmp(argv[1], "vfork-exit") == 0) return vfork_exit();
  if (strcmp(argv[1], "vfork-exec") == 0) return vfork_exec();
  return 2;
}
"#;

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
            &mut |_| {},
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

    #[allow(unsafe_code)]
    fn sigqueue_sigcont(pid: safeptrace::Pid) {
        let value = libc::sigval {
            sival_ptr: std::ptr::null_mut(),
        };
        assert_eq!(
            unsafe { libc::sigqueue(pid.as_raw(), libc::SIGCONT, value) },
            0
        );
    }

    #[test]
    fn supervisor_foreign_sigcont_during_group_stop_clear_is_refused() {
        let _guard = super::super::forked_child_test_guard();
        let mut injected_pid = None;
        let failure = Supervisor::spawn_inner(
            request("/bin/true", &["true"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
            &mut |_| std::thread::sleep(Duration::from_millis(100)),
            &mut |pid| {
                injected_pid = Some(pid);
                let pid_arg = pid.as_raw().to_string();
                assert!(
                    std::process::Command::new("/bin/kill")
                        .args(["-CONT", &pid_arg])
                        .status()
                        .unwrap()
                        .success()
                );
            },
        )
        .unwrap_err();
        let pid = injected_pid.expect("initial-resume hook ran");
        assert!(
            failure.error.to_string().contains("unowned SIGCONT"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }

    #[test]
    fn watched_foreign_sigcont_during_group_stop_clear_is_refused() {
        let _guard = super::super::forked_child_test_guard();
        let watched = Supervisor::spawn_watched_inner(
            request("/bin/true", &["true"]),
            CleanupReceipt::default(),
            &mut |_| std::thread::sleep(Duration::from_millis(100)),
            &mut |pid| {
                let pid_arg = pid.as_raw().to_string();
                assert!(
                    std::process::Command::new("/bin/kill")
                        .args(["-CONT", &pid_arg])
                        .status()
                        .unwrap()
                        .success()
                );
            },
        )
        .unwrap();
        let pid = watched.pid();
        let failure = watched.wait_next().unwrap_err();
        assert!(
            failure.error.to_string().contains("unowned SIGCONT"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }

    #[test]
    fn supervisor_sigqueue_sigcont_during_group_stop_clear_is_refused() {
        let _guard = super::super::forked_child_test_guard();
        let mut injected_pid = None;
        let failure = Supervisor::spawn_inner(
            request("/bin/true", &["true"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
            &mut |_| std::thread::sleep(Duration::from_millis(100)),
            &mut |pid| {
                injected_pid = Some(pid);
                sigqueue_sigcont(pid);
            },
        )
        .unwrap_err();
        let pid = injected_pid.expect("initial-resume hook ran");
        assert!(
            failure.error.to_string().contains("unowned SIGCONT"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert!(!Path::new(&format!("/proc/{}", pid.as_raw())).exists());
    }

    #[allow(unsafe_code)]
    fn pin_current_and_child(pid: safeptrace::Pid) {
        let cpu = nix::sched::sched_getcpu().unwrap();
        let mut set = nix::sched::CpuSet::new();
        set.set(cpu).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set).unwrap();
        nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(pid.as_raw()), &set).unwrap();
        // Keep the detached parent ahead of the woken child on that one
        // CPU long enough for its first wait to observe kernel state
        // before the child can process the detach SIGCONT.
        assert_eq!(
            unsafe { libc::setpriority(libc::PRIO_PROCESS, pid.as_raw().try_into().unwrap(), 19,) },
            0
        );
    }

    #[test]
    fn supervisor_group_stop_handshake_detached_wait_reaps_running_guest() {
        let _guard = super::super::forked_child_test_guard();
        // Delaying seize until after the child's self-SIGSTOP forces
        // the pre-seize group-stop handshake. The detached guest then
        // sleeps long enough that a stale group-stop wait report, if
        // one remained for the natural parent, would be collected
        // before its exit rather than racing it.
        let detached = Supervisor::spawn_inner(
            request("/bin/sh", &["sh", "-c", "exec sleep 0.2"]),
            CleanupReceipt::default(),
            SupervisorMode::DormantSeize,
            &mut |_| std::thread::sleep(Duration::from_millis(100)),
            &mut pin_current_and_child,
        )
        .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_group_stop_release_detached_wait_reaps_running_guest() {
        let _guard = super::super::forked_child_test_guard();
        let watched = Supervisor::spawn_watched_inner(
            request("/bin/sh", &["sh", "-c", "exec sleep 0.2"]),
            CleanupReceipt::default(),
            &mut |_| std::thread::sleep(Duration::from_millis(100)),
            &mut pin_current_and_child,
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
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_guest_group_stop_release_detached_reaps_running_guest() {
        // The guest stops itself after the first exec, while still
        // seized. Its group stop must be cleared before release, or
        // the detached wait can collect the stale SIGSTOP report
        // ahead of the detach SIGCONT and kill the running sleep.
        // Pinning plus nice 19 makes that ordering deterministic.
        let watched = Supervisor::spawn_watched_inner(
            request("/bin/sh", &["sh", "-c", "kill -STOP $$; exec sleep 0.2"]),
            CleanupReceipt::default(),
            &mut |_| {},
            &mut pin_current_and_child,
        )
        .unwrap();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected the shell exec stop, got terminal {outcome:?}")
            }
        };
        let watched = stop
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected the sleep exec stop, got terminal {outcome:?}")
            }
        };
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    fn rearm_until_finished(mut watched: WatchedSupervisor<'_>) -> WatchedOutcome {
        loop {
            match watched.wait_next().unwrap() {
                WatchedStep::Exec(stop) => {
                    watched = stop
                        .rearm_and_resume(|task, _entry, _boundary| Ok(task))
                        .unwrap();
                }
                WatchedStep::Finished(outcome) => return outcome,
            }
        }
    }

    #[test]
    fn watched_guest_self_sigcont_runs_to_completion() {
        let watched = Supervisor::spawn_watched(
            request("/bin/sh", &["sh", "-c", "kill -CONT $$; exec /bin/true"]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_foreign_tstp_then_cont_runs_to_completion() {
        // Leader-only guest: a shell's external `sleep` would be
        // a fork-child exec, which this successor refuses by
        // name; the behavior under test is the leader's foreign
        // TSTP/CONT handling.
        let watched = Supervisor::spawn_watched(
            fork_request("sleep-leader-exec-true", &[]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected the guest exec stop, got terminal {outcome:?}")
            }
        };
        let watched = stop
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let pid = watched.pid().as_raw().to_string();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            assert!(
                std::process::Command::new("/bin/kill")
                    .args(["-TSTP", &pid])
                    .status()
                    .unwrap()
                    .success()
            );
            std::thread::sleep(Duration::from_millis(20));
            assert!(
                std::process::Command::new("/bin/kill")
                    .args(["-CONT", &pid])
                    .status()
                    .unwrap()
                    .success()
            );
        });
        let outcome = rearm_until_finished(watched);
        sender.join().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_blocked_sigcont_two_stops_run_to_completion() {
        assert!(
            Path::new("/usr/bin/perl").exists(),
            "blocked SIGCONT guest requires /usr/bin/perl (perl-interpreter)"
        );
        assert!(
            std::process::Command::new("/usr/bin/perl")
                .args(["-MPOSIX=:signal_h,sigprocmask", "-e", "1"])
                .status()
                .is_ok_and(|status| status.success()),
            "blocked SIGCONT guest requires perl POSIX (perl-POSIX)"
        );
        // A single-threaded perl guest blocks SIGCONT process-wide
        // for its only thread, stops itself twice, then execs from
        // the traced leader. Both execs must be observed; a libtest
        // guest would block SIGCONT only on a non-leader thread and
        // its final exec would escape through de_thread.
        let perl = concat!(
            "use POSIX qw(:signal_h sigprocmask); ",
            "my $set = POSIX::SigSet->new(); ",
            "$set->addset(SIGCONT); ",
            "sigprocmask(SIG_BLOCK, $set) or die $!; ",
            "kill STOP => $$ or die $!; ",
            "kill STOP => $$ or die $!; ",
            "exec '/bin/true' or die $!;"
        );
        let watched = Supervisor::spawn_watched(
            request("/usr/bin/perl", &["perl", "-e", perl]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert_eq!(outcome.execs_seen, 2);
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_guest_sees_forwarded_sigcont_handler() {
        let watched = Supervisor::spawn_watched(
            request(
                "/bin/sh",
                &[
                    "sh",
                    "-c",
                    "trap 'exit 7' CONT; kill -STOP $$; sleep 0.3; exit 0",
                ],
            ),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_fork_child_group_stop_stays_stopped_until_guest_continues() {
        // The C guest's leader forks a child that stops itself and
        // then exits without exec. Native job control: it must
        // still read stopped after the parent's sleep, and only
        // the guest parent's SIGCONT continues it. The guest
        // checks the state itself and exits 9 if the supervisor
        // auto-continued the child.
        let watched =
            Supervisor::spawn_watched(fork_request("stop-child", &[]), CleanupReceipt::default())
                .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_leader_exit_detaches_listening_fork_child_still_stopped() {
        // The fork child is parked in LISTEN when its leader
        // exits. Detach must leave it untraced but still in its
        // native group stop; only the test's later SIGCONT (a
        // guest-side continuer from the child's new parent
        // chain) lets it exit.
        let pid_file = supervisor_test_file("stop-child.pid");
        let watched = Supervisor::spawn_watched(
            fork_request("stop-child-leader-exit", &[&pid_file]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        assert_no_traced_by_current_thread("leader exit with listening child");
        let child_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let status = fs::read_to_string(format!("/proc/{child_pid}/status")).unwrap();
        let state = status
            .lines()
            .find(|line| line.starts_with("State:"))
            .expect("child state");
        assert!(
            state.contains("(stopped)"),
            "detached listening child must stay stopped, got {state}"
        );
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child_pid),
            nix::sys::signal::Signal::SIGCONT,
        )
        .unwrap();
        for _ in 0..200 {
            if !Path::new(&format!("/proc/{child_pid}")).exists() {
                let _ = fs::remove_file(&pid_file);
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("continued fork child {child_pid} did not exit");
    }

    #[test]
    fn watched_sh_chain_fork_child_exec_is_refused_by_name() {
        // No caller re-arm hook exists for fork-child execs yet, so
        // the inner shell's exec fails the launch closed by name
        // instead of running its new image unarmed.
        let watched = Supervisor::spawn_watched(
            request(
                "/bin/sh",
                &["sh", "-c", "sh -c 'sh -c \"exec /bin/true\"'; exit 7"],
            ),
            CleanupReceipt::default(),
        )
        .unwrap();
        let stop = match watched.wait_next().unwrap() {
            WatchedStep::Exec(stop) => stop,
            WatchedStep::Finished(outcome) => {
                panic!("expected the shell exec stop, got terminal {outcome:?}")
            }
        };
        let watched = stop
            .rearm_and_resume(|task, _entry, _boundary| Ok(task))
            .unwrap();
        let failure = watched.wait_next().unwrap_err();
        assert!(
            failure
                .error
                .to_string()
                .contains("exec_supervisor_fork_child_exec_refused"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
    }

    #[test]
    fn watched_exit_only_vfork_child_is_unchanged() {
        // The C guest vforks from its traced leader (main) thread.
        // Dropping the NewChild capture leaves the vfork child in
        // its initial stop and the parent blocked in vfork, so
        // this test hangs under that mutant.
        let watched =
            Supervisor::spawn_watched(fork_request("vfork-exit", &[]), CleanupReceipt::default())
                .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
    }

    #[test]
    fn watched_vfork_child_exec_is_refused_by_name() {
        // A vfork child's exec is a fork-child exec: with no
        // per-child re-arm hook it fails closed by name rather
        // than running the new image unarmed.
        let watched =
            Supervisor::spawn_watched(fork_request("vfork-exec", &[]), CleanupReceipt::default())
                .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let failure = watched.wait_next().unwrap_err();
        assert!(
            failure
                .error
                .to_string()
                .contains("exec_supervisor_fork_child_exec_refused"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert_no_traced_by_current_thread("vfork-exec refusal");
    }

    #[test]
    fn watched_release_detached_forwards_in_flight_sigusr1_to_fork_child() {
        // While the leader successor stop is held, a SIGUSR1 is in
        // flight to the fork child. Detaching that child during
        // release must forward its own signal, not replace it
        // with a supervisor-invented SIGCONT: the child records
        // usr1=1 cont=0 (the old detach recorded usr1=0 cont=1).
        let pid_file = supervisor_test_file("signal-child.pid");
        let result_file = supervisor_test_file("signal-child.result");
        let watched = Supervisor::spawn_watched(
            fork_request("signal-child", &[&pid_file, &result_file]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let child_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child_pid),
            nix::sys::signal::Signal::SIGUSR1,
        )
        .unwrap();
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        assert_no_traced_by_current_thread("release_detached signal child");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
        let mut result = String::new();
        for _ in 0..200 {
            if let Ok(text) = fs::read_to_string(&result_file) {
                result = text;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(result.trim(), "usr1=1 cont=0");
        let _ = fs::remove_file(&pid_file);
        let _ = fs::remove_file(&result_file);
    }

    #[test]
    fn watched_release_detached_detaches_grandchild_met_while_detaching() {
        // The direct child forks a grandchild while the caller
        // holds the leader successor stop, so the grandchild is
        // first met by the detach worklist during release. It
        // must be taken over and detached too, not dropped in
        // its initial tracing stop.
        let stop = grandchild_held_at_release();
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        assert_no_traced_by_current_thread("release_detached grandchild");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
    }

    fn sleep_child_request(marker: &Path, pid_file: &Path) -> PreparedExec<'static> {
        fork_request("sleep-child-exec-leader", &[pid_file, marker])
    }

    #[test]
    fn watched_hook_error_detaches_fork_children() {
        let marker = supervisor_test_file("hook-error.marker");
        let pid_file = supervisor_test_file("hook-error.pid");
        let watched = Supervisor::spawn_watched(
            sleep_child_request(&marker, &pid_file),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let failure = stop
            .rearm_and_resume(|_task, _entry, _boundary| Err("test hook refusal".into()))
            .unwrap_err();
        assert!(
            failure.error.to_string().contains("test hook refusal"),
            "unexpected failure: {}",
            failure.error
        );
        assert!(failure.cleanup().confirmed);
        assert_no_traced_by_current_thread("hook error");
        assert_child_survived(&marker, "hook error");
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn watched_drop_successor_stop_detaches_fork_children() {
        let marker = supervisor_test_file("drop-stop.marker");
        let pid_file = supervisor_test_file("drop-stop.pid");
        let watched = Supervisor::spawn_watched(
            sleep_child_request(&marker, &pid_file),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        drop(stop);
        assert_no_traced_by_current_thread("drop successor stop");
        assert_child_survived(&marker, "drop successor stop");
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn watched_drop_supervisor_detaches_fork_children() {
        // Both leader execs are driven first, so the sleeping fork
        // child is already captured when the supervisor is dropped.
        // The racing drop right after the first re-arm is covered by
        // the next test and by the fork-loop teardown tests.
        let marker = supervisor_test_file("drop-watched.marker");
        let pid_file = supervisor_test_file("drop-watched.pid");
        let watched = Supervisor::spawn_watched(
            sleep_child_request(&marker, &pid_file),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let watched = rearm_ok(watched_next_exec(watched));
        drop(watched);
        assert_no_traced_by_current_thread("drop watched supervisor");
        assert_child_survived(&marker, "drop watched supervisor");
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn watched_release_detaches_child_parked_at_exit_stop() {
        // The caller holds the successor stop past the background
        // child's exit, so that child is parked, unclaimed, at its
        // exit stop when release detaches it. It must be detached
        // there (no timeout, no error), its zombie left to the guest
        // side, and its marker shows it ran to exit 0.
        let marker = supervisor_test_file("exit-stop.marker");
        let pid_file = supervisor_test_file("exit-stop.pid");
        let watched = Supervisor::spawn_watched(
            sleep_child_request(&marker, &pid_file),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        assert!(wait_for_marker(&marker, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_no_traced_by_current_thread("release with child at exit stop");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert_eq!(outcome.cleanup.child_detach_error, None);
        let _ = fs::remove_file(&marker);
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn watched_release_detaches_exiting_child_whose_kill_is_dropped() {
        // The background child exits through `_exit` (exit_group) while
        // the successor stop is held and parks at its exit stop. A
        // guest-side SIGKILL sent then is dropped by the kernel (the
        // group is already exiting), so the child stays at that stop
        // and release simply detaches it there: no failure and nothing
        // left traced. The kill-before-detach ESRCH arms are covered by
        // the test-hook tests below.
        let marker = supervisor_test_file("killed-exit.marker");
        let pid_file = supervisor_test_file("killed-exit.pid");
        let watched = Supervisor::spawn_watched(
            sleep_child_request(&marker, &pid_file),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        assert!(wait_for_marker(&marker, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(100));
        let child_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(child_pid),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        assert_no_traced_by_current_thread("release with child killed at exit stop");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert_eq!(outcome.cleanup.child_detach_error, None);
        let _ = fs::remove_file(&marker);
        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn watched_drop_right_after_rearm_leaves_nothing_traced() {
        // Dropped right after the first re-arm. In practice the drop
        // lands before the leader's fork (review measurement: no fork
        // seen in 50 of 50 rounds), so this is a no-leak smoke check of
        // that ordering, plus survival if a child was forked after all.
        // The fork-loop teardown tests are the deterministic coverage
        // of adopting a pending fork.
        for round in 0..5 {
            let marker = supervisor_test_file("drop-race.marker");
            let pid_file = supervisor_test_file("drop-race.pid");
            let watched = Supervisor::spawn_watched(
                sleep_child_request(&marker, &pid_file),
                CleanupReceipt::default(),
            )
            .unwrap();
            let watched = rearm_ok(watched_next_exec(watched));
            drop(watched);
            assert_no_traced_by_current_thread(&format!("drop race round {round}"));
            // A forked child writes its pid file at once; give it a
            // moment, then require its marker if it exists at all.
            std::thread::sleep(Duration::from_millis(200));
            if pid_file.exists() {
                assert_child_survived(&marker, &format!("drop race round {round}"));
            }
            let _ = fs::remove_file(&marker);
            let _ = fs::remove_file(&pid_file);
        }
    }

    fn fork_loop_teardown(mode: &str, cancel: bool) {
        // The leader forks in a tight loop and nobody drives it after
        // the re-arm, so 30 ms later it sits at (or is about to
        // report) a fork event whose auto-attached child is in its
        // initial stop. Teardown must adopt that child before killing
        // the leader, or the child stays traced forever.
        for round in 0..3 {
            let receipt = CleanupReceipt::default();
            let watched =
                Supervisor::spawn_watched(fork_request(mode, &[]), receipt.clone()).unwrap();
            let watched = rearm_ok(watched_next_exec(watched));
            std::thread::sleep(Duration::from_millis(30));
            if cancel {
                let cleanup = watched.cancel().unwrap();
                assert!(cleanup.confirmed);
                assert_eq!(cleanup.child_detach_error, None);
            } else {
                drop(watched);
                let cleanup = receipt.snapshot();
                assert!(cleanup.confirmed);
                assert_eq!(cleanup.child_detach_error, None);
            }
            assert_no_traced_by_current_thread(&format!(
                "{mode} {} round {round}",
                if cancel { "cancel" } else { "drop" }
            ));
        }
    }

    #[test]
    fn watched_cancel_adopts_pending_leader_fork() {
        fork_loop_teardown("fork-loop", true);
    }

    #[test]
    fn watched_drop_adopts_pending_leader_fork() {
        fork_loop_teardown("fork-loop", false);
    }

    #[test]
    fn watched_wait_error_adopts_pending_leader_fork() {
        // A fork child's exec is refused while the leader keeps
        // forking: the wait error path must also adopt the leader's
        // pending fork before the launch failure kills the leader.
        for round in 0..8 {
            let watched = Supervisor::spawn_watched(
                fork_request("fork-loop-exec-child", &[]),
                CleanupReceipt::default(),
            )
            .unwrap();
            let watched = rearm_ok(watched_next_exec(watched));
            let failure = watched.wait_next().unwrap_err();
            assert!(
                failure
                    .error
                    .to_string()
                    .contains("exec_supervisor_fork_child_exec_refused"),
                "round {round}: unexpected failure: {}",
                failure.error
            );
            assert!(failure.cleanup().confirmed);
            // The refused child is settled through its own wait, so no
            // teardown failure may be recorded for it.
            assert_eq!(
                failure.cleanup().child_detach_error,
                None,
                "round {round}: refused child reported as a detach failure"
            );
            assert_no_traced_by_current_thread(&format!("wait error round {round}"));
        }
    }

    #[test]
    fn watched_nested_fork_in_fork_child_is_driven() {
        // The fork child forks a grandchild and waits for it. The
        // grandchild is first met as the child's own fork event; if
        // that capture is dropped, the grandchild sits in its
        // initial stop and the whole tree hangs.
        let status = run_bounded(Duration::from_secs(20), || {
            let watched = Supervisor::spawn_watched(
                fork_request("nested-fork", &[]),
                CleanupReceipt::default(),
            )
            .unwrap();
            let outcome = rearm_until_finished(watched);
            assert!(outcome.cleanup.confirmed);
            assert_no_traced_by_current_thread("nested fork");
            outcome.status
        });
        assert_eq!(status, ExitStatus::Exited(7));
    }

    #[test]
    fn watched_zombie_leader_fork_child_keeps_leader_status() {
        // The fork child's traced main thread pthread_exits while a
        // sibling runs 2.5 s; the guest leader exits 7 at 100 ms
        // (natively 7). The leader's status must be kept, the run
        // must not wait for or kill the sibling, and the child must
        // end untraced and exit 0 on its own.
        let marker = supervisor_test_file("zombie-leader.marker");
        let started = Instant::now();
        let watched = Supervisor::spawn_watched(
            fork_request("zombie-leader-child", &[&marker]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        let elapsed = started.elapsed();
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        assert_eq!(outcome.cleanup.child_detach_error, None);
        assert!(
            elapsed < Duration::from_millis(1500),
            "leader exit waited for the fork child's sibling: {elapsed:?}"
        );
        assert_no_traced_by_current_thread("zombie leader fork child");
        assert_child_survived(&marker, "zombie leader fork child");
    }

    #[test]
    fn watched_teardown_kills_and_reaps_child_it_cannot_detach() {
        // A child blocked in vfork (its vfork child sleeps 3 s) cannot
        // reach a ptrace stop within the bound. Release must report it
        // by name, kill it and reap it rather than leave it traced,
        // and still go on to detach the healthy sleeper, which
        // teardown meets only after the failed child.
        let marker = supervisor_test_file("vfork-wait.marker");
        let watched = Supervisor::spawn_watched(
            fork_request("vfork-wait-child-with-sleeper", &[&marker]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let started = Instant::now();
        let failure = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap_err();
        let elapsed = started.elapsed();
        let report = failure.error.to_string();
        assert!(
            report.contains("exec_supervisor_fork_child_undrivable")
                && report.contains("timed out"),
            "unexpected failure: {report}"
        );
        assert!(failure.cleanup().confirmed);
        assert_eq!(
            failure.cleanup().child_detach_error.as_deref(),
            Some(report.as_str())
        );
        assert!(elapsed < Duration::from_secs(5), "release took {elapsed:?}");
        assert_no_traced_by_current_thread("vfork-blocked child");
        assert_child_survived(&marker, "vfork-blocked child");
    }

    #[test]
    fn watched_leader_exit_keeps_status_when_a_child_cannot_be_detached() {
        // The leader exits 7 while a child is blocked in vfork past the
        // detach bound. The run must still finish with the leader's
        // actual status, report the child by name beside it, and kill
        // and reap that child rather than leave it traced.
        let started = Instant::now();
        let watched = Supervisor::spawn_watched(
            fork_request("vfork-wait-child-leader-exit", &[]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        let elapsed = started.elapsed();
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        let report = outcome
            .cleanup
            .child_detach_error
            .expect("the child that could not be detached is reported");
        assert!(
            report.contains("exec_supervisor_fork_child_undrivable")
                && report.contains("timed out"),
            "unexpected report: {report}"
        );
        assert!(elapsed < Duration::from_secs(6), "run took {elapsed:?}");
        assert_no_traced_by_current_thread("leader exit with undetachable child");
    }

    #[test]
    fn watched_successor_cancel_reports_child_detach_failure() {
        // Cancel has no error channel for a child it could not detach:
        // the failure must be surfaced in the returned cleanup state,
        // not discarded, and the child still killed and reaped.
        let marker = supervisor_test_file("cancel-report.marker");
        let watched = Supervisor::spawn_watched(
            fork_request("vfork-wait-child-with-sleeper", &[&marker]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let cleanup = stop.cancel().unwrap();
        assert!(cleanup.confirmed);
        let report = cleanup
            .child_detach_error
            .expect("cancel must report the child it could not detach");
        assert!(
            report.contains("exec_supervisor_fork_child_undrivable")
                && report.contains("timed out"),
            "unexpected report: {report}"
        );
        assert_no_traced_by_current_thread("cancel with undetachable child");
        assert_child_survived(&marker, "cancel with undetachable child");
    }

    #[test]
    fn watched_release_settles_child_killed_out_of_its_stop() {
        // While the successor stop is held nobody drives the fork
        // child: a SIGUSR1 parks it in a signal-delivery stop, then a
        // guest-side SIGKILL takes it out of that stop to die. Release
        // must settle that child (its terminal status, or ESRCH from a
        // detach that raced the kill), not fail or leave a traced
        // zombie. Measured here, the notifier reports the terminal
        // status first.
        let pid_file = supervisor_test_file("killed-child.pid");
        let result_file = supervisor_test_file("killed-child.result");
        let watched = Supervisor::spawn_watched(
            fork_request("signal-child", &[&pid_file, &result_file]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let stop = watched_next_exec(watched);
        let child_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let child = nix::unistd::Pid::from_raw(child_pid);
        nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGUSR1).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let detached = stop
            .release_detached(|task, _entry, _boundary| Ok(task))
            .unwrap();
        assert_no_traced_by_current_thread("release with killed child");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert!(outcome.cleanup.confirmed);
        assert!(
            !result_file.exists(),
            "the killed child must not have run its handler"
        );
        let _ = fs::remove_file(&pid_file);
    }

    /// Test-only hook scopes for the exit-stop check.
    struct HookScope(fn(bool));

    impl HookScope {
        fn force_sibling_syscall_running() -> Self {
            fn set(on: bool) {
                super::FORCE_SIBLING_SYSCALL_RUNNING.with(|hook| hook.set(on));
            }
            set(true);
            Self(set)
        }

        fn drop_last_listed_task() -> Self {
            fn set(on: bool) {
                super::DROP_LAST_LISTED_TASK.with(|hook| hook.set(on));
            }
            set(true);
            Self(set)
        }

        fn delay_after_exit_stop_detach() -> Self {
            fn set(on: bool) {
                super::DELAY_AFTER_EXIT_STOP_DETACH
                    .with(|hook| hook.set(on.then_some(Duration::from_millis(300))));
            }
            set(true);
            Self(set)
        }
    }

    impl Drop for HookScope {
        fn drop(&mut self) {
            (self.0)(false);
        }
    }

    /// Which exit-stop refusal must fire.
    #[derive(Clone, Copy, Debug)]
    enum RefusalPath {
        /// A sibling was seen in an exec entry.
        ExecSeen,
        /// Nothing proved the group free of a waiting exec within the
        /// drain bound.
        NotRuledOut,
        /// Either; the many-thread walk decides which.
        Either,
    }

    /// Whether this test process can read a non-dumpable task's `/proc`
    /// syscall file (`CAP_SYS_PTRACE` in its effective set, as root
    /// has). Then the non-dumpable exec is seen in exec rather than
    /// left unresolved.
    fn reads_nondumpable_syscalls() -> bool {
        const CAP_SYS_PTRACE: u32 = 19;
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .is_some_and(|mask| mask & (1 << CAP_SYS_PTRACE) != 0)
    }

    #[derive(Clone, Copy, Default)]
    struct Hooks {
        force_running: bool,
        drop_last_listed: bool,
    }

    impl Hooks {
        fn scopes(self) -> (Option<HookScope>, Option<HookScope>) {
            (
                self.force_running
                    .then(HookScope::force_sibling_syscall_running),
                self.drop_last_listed.then(HookScope::drop_last_listed_task),
            )
        }
    }

    /// A fork child's non-leader (untraced) thread execs an image that
    /// would write the marker (the first argument after the mode).
    /// de_thread kills the child's traced main thread, which is held at
    /// its exit stop; the check there must kill the group and name the
    /// refusal through `path`, so the image never runs. Natively the
    /// guest exits 7. Every case runs with a 300 ms pause after the
    /// exit-stop detach, so a kill sent after the detach instead of
    /// before it would let the image write its marker.
    fn assert_nonleader_exec_refused(mode: &str, extra: &[&str], hooks: Hooks, path: RefusalPath) {
        let marker = supervisor_test_file("thread-exec.marker");
        let mut args: Vec<&Path> = vec![&marker];
        args.extend(extra.iter().map(Path::new));
        let _delay = HookScope::delay_after_exit_stop_detach();
        let _hooks = hooks.scopes();
        let started = Instant::now();
        let watched =
            Supervisor::spawn_watched(fork_request(mode, &args), CleanupReceipt::default())
                .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        let failure = watched.wait_next().unwrap_err();
        let elapsed = started.elapsed();
        let report = failure.error.to_string();
        assert!(
            report.contains("exec_supervisor_fork_child_exec_refused")
                && report.contains("non-leader thread")
                && report.contains("its group was killed"),
            "{mode}: unexpected failure: {report}"
        );
        let exec_seen = report.contains("exec from a non-leader thread");
        let not_ruled_out = report.contains("could not be ruled out of exec");
        assert!(
            match path {
                RefusalPath::ExecSeen => exec_seen && !not_ruled_out,
                RefusalPath::NotRuledOut => not_ruled_out && !exec_seen,
                RefusalPath::Either => exec_seen != not_ruled_out,
            },
            "{mode}: expected the {path:?} refusal: {report}"
        );
        assert!(failure.cleanup().confirmed);
        assert_eq!(failure.cleanup().child_detach_error, None);
        assert!(
            elapsed < Duration::from_secs(5),
            "{mode}: refusal took {elapsed:?}"
        );
        assert_no_traced_by_current_thread(mode);
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !marker.exists(),
            "{mode}: the refused exec's new image ran (marker {})",
            marker.display()
        );
    }

    #[test]
    fn watched_fork_child_nonleader_thread_exec_is_refused_before_image_runs() {
        // Control for a main thread exiting beside a running, not
        // execing, sibling: the zombie-leader and busy-sibling tests.
        assert_nonleader_exec_refused(
            "thread-exec-child-marker",
            &[],
            Hooks::default(),
            RefusalPath::ExecSeen,
        );
    }

    #[test]
    fn watched_nondumpable_fork_child_nonleader_exec_is_refused_before_image_runs() {
        // A non-dumpable child's /proc syscall files are unreadable
        // without CAP_SYS_PTRACE: the killed main thread plus a live
        // sibling that never drains must still refuse, never fail open.
        let path = if reads_nondumpable_syscalls() {
            RefusalPath::ExecSeen
        } else {
            RefusalPath::NotRuledOut
        };
        assert_nonleader_exec_refused(
            "thread-exec-child-marker-nondumpable",
            &[],
            Hooks::default(),
            path,
        );
    }

    #[test]
    fn watched_nonleader_exec_is_refused_when_sibling_never_shows_exec() {
        // Every sibling syscall read shows "running": the exec is never
        // seen, and its thread keeps the group from draining.
        assert_nonleader_exec_refused(
            "thread-exec-child-marker",
            &[],
            Hooks {
                force_running: true,
                ..Hooks::default()
            },
            RefusalPath::NotRuledOut,
        );
    }

    #[test]
    fn watched_nonleader_exec_is_refused_when_listing_is_short() {
        // Every task listing drops its last entry, the exec'ing thread:
        // the short listing must not be taken as a drained group.
        assert_nonleader_exec_refused(
            "thread-exec-child-marker",
            &[],
            Hooks {
                drop_last_listed: true,
                ..Hooks::default()
            },
            RefusalPath::NotRuledOut,
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn watched_int80_nonleader_exec_is_refused_before_image_runs() {
        // The ia32 entry: /proc shows execve as 11 (native munmap); the
        // int $0x80 instruction before its pc marks it as exec.
        assert_nonleader_exec_refused(
            "thread-exec-child-marker-int80",
            &[],
            Hooks::default(),
            RefusalPath::ExecSeen,
        );
    }

    #[test]
    fn watched_many_thread_nonleader_exec_is_refused_before_image_runs() {
        // 2000 parked threads are killed while /proc/<pid>/task is
        // walked, so walks come up short; the exec'ing thread is last.
        assert_nonleader_exec_refused(
            "many-thread-exec-child-marker",
            &["2000"],
            Hooks::default(),
            RefusalPath::Either,
        );
    }

    fn assert_many_thread_exit_group_released(hooks: Hooks) {
        // Control: a non-dumpable child with 2000 parked threads, one of
        // which calls exit(0). Its main thread is killed but no thread
        // execs, so nothing is refused: the leader's 7, no failure,
        // nothing traced. The hooks show that neither a short listing
        // nor syscall reads decide this release.
        let _hooks = hooks.scopes();
        let watched = Supervisor::spawn_watched(
            fork_request("many-thread-exit-group-nondumpable", &[Path::new("2000")]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        assert_eq!(outcome.cleanup.child_detach_error, None);
        assert_no_traced_by_current_thread("many-thread exit group");
    }

    #[test]
    fn watched_nondumpable_many_thread_exit_group_is_not_refused() {
        assert_many_thread_exit_group_released(Hooks::default());
    }

    #[test]
    fn watched_many_thread_exit_group_with_short_listing_is_not_refused() {
        assert_many_thread_exit_group_released(Hooks {
            drop_last_listed: true,
            ..Hooks::default()
        });
    }

    #[test]
    fn watched_many_thread_exit_group_with_running_siblings_is_not_refused() {
        assert_many_thread_exit_group_released(Hooks {
            force_running: true,
            ..Hooks::default()
        });
    }

    fn assert_busy_sibling_main_exit_released(force_running: bool) {
        // Control: the non-dumpable child's main thread exits on its own
        // while a sibling spins (unreadable, "running"). That main
        // thread was not killed, so nothing is refused: the leader's 7,
        // no failure, nothing traced, and the sibling runs on to exit 0.
        let marker = supervisor_test_file("busy-sibling.marker");
        let _hooks = Hooks {
            force_running,
            ..Hooks::default()
        }
        .scopes();
        let watched = Supervisor::spawn_watched(
            fork_request("busy-sibling-main-exit", &[&marker]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = rearm_until_finished(watched);
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        assert_eq!(outcome.cleanup.child_detach_error, None);
        assert_no_traced_by_current_thread("busy sibling main exit");
        assert_child_survived(&marker, "busy sibling main exit");
    }

    #[test]
    fn watched_main_exit_beside_busy_unreadable_sibling_is_not_refused() {
        assert_busy_sibling_main_exit_released(false);
    }

    #[test]
    fn watched_main_exit_beside_running_sibling_is_not_refused() {
        assert_busy_sibling_main_exit_released(true);
    }

    #[test]
    fn exit_stop_pass_releases_a_killed_main_thread_only_on_proof() {
        use super::PassVerdict::*;
        use super::SiblingFinding::*;
        let pass = |threads: Option<usize>, siblings: &[super::SiblingFinding], listed_ok| {
            super::ThreadsPass {
                threads,
                siblings: siblings.to_vec(),
                listed_ok,
            }
        };
        let verdict = super::pass_verdict;
        // Killed main thread: drained, or a complete listing of gone or
        // dying siblings, releases.
        assert_eq!(verdict(true, &pass(Some(1), &[], true)), Release);
        assert_eq!(verdict(true, &pass(Some(1), &[], false)), Release);
        assert_eq!(verdict(true, &pass(Some(3), &[Gone, Dying], true)), Release);
        // A sibling in exec refuses.
        assert_eq!(
            verdict(true, &pass(Some(3), &[Dying, Exec], true)),
            RefuseExec
        );
        assert_eq!(
            verdict(false, &pass(Some(3), &[Live, Exec], true)),
            RefuseExec
        );
        // Anything unproven waits for the drain bound.
        assert_eq!(
            verdict(true, &pass(Some(3), &[Dying, Live], true)),
            Undecided
        );
        assert_eq!(verdict(true, &pass(Some(3), &[Dying], true)), Undecided);
        assert_eq!(verdict(true, &pass(Some(2), &[Dying], false)), Undecided);
        assert_eq!(verdict(true, &pass(None, &[Dying], true)), Undecided);
        assert_eq!(verdict(true, &pass(None, &[], true)), Undecided);
        // A main thread that exited on its own is released beside any
        // sibling not seen in exec.
        assert_eq!(verdict(false, &pass(Some(2), &[Live], true)), Release);
        assert_eq!(verdict(false, &pass(None, &[], false)), Release);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn exec_entry_counts_every_x86_64_abi() {
        use super::EntryAbi::*;
        let exec = super::is_exec_entry;
        for abi in [Native, Unknown] {
            assert!(exec(59, abi) && exec(322, abi));
            assert!(exec(0x4000_0000 | 520, abi) && exec(0x4000_0000 | 545, abi));
            assert!(!exec(11, abi), "native 11 is munmap");
            assert!(!exec(0x4000_0000 | 59, abi), "x32 59 is not exec");
        }
        assert!(
            exec(358, Unknown) && !exec(358, Native),
            "358 is unused natively"
        );
        assert!(exec(11, Ia32) && exec(358, Ia32));
        assert!(!exec(59, Ia32) && !exec(322, Ia32));
        assert!(!exec(1, Native) && !exec(-1, Unknown));
    }

    /// A fake `/proc/<pid>/task/<tid>` directory holding `files`.
    fn fake_task_dir(files: &[(&str, &[u8])]) -> PathBuf {
        let dir = supervisor_test_file("task");
        fs::create_dir(&dir).unwrap();
        for (name, bytes) in files {
            fs::write(dir.join(name), bytes).unwrap();
        }
        dir
    }

    const STATUS_CLEAR: &[u8] =
        b"Threads:\t3\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n";
    const STATUS_SIGKILL: &[u8] =
        b"Threads:\t3\nSigPnd:\t0000000000000100\nShdPnd:\t0000000000000000\n";
    // Flags 0x400040: neither PF_EXITING nor PF_SIGNALED.
    const STAT_CLEAR: &[u8] = b"7 (sh) S 1 7 7 0 -1 4194368 0 0";
    // Flags 0x400448, caught live by review: PF_SIGNALED without
    // PF_EXITING, after SIGKILL left pending.
    const STAT_SIGNALED: &[u8] = b"7 (sh) S 1 7 7 0 -1 4195400 0 0";
    const STAT_EXITING: &[u8] = b"7 (sh) S 1 7 7 0 -1 4194372 0 0";

    #[test]
    fn exit_stop_sibling_evidence() {
        use super::SiblingFinding::*;
        let examine = |files: &[(&str, &[u8])]| {
            let dir = fake_task_dir(files);
            let finding = super::examine_sibling(&dir);
            fs::remove_dir_all(&dir).unwrap();
            finding
        };
        let blocked = b"7 0x0 0x0 0x0 0x0 0x0 0x0 0x7ffd0000 0x100";
        // Gone: the directory, or any file read, is ENOENT.
        let missing = supervisor_test_file("no-task");
        assert_eq!(super::examine_sibling(&missing), Gone);
        assert_eq!(examine(&[("stat", STAT_CLEAR), ("syscall", blocked)]), Gone);
        assert_eq!(
            examine(&[("status", STATUS_CLEAR), ("syscall", blocked)]),
            Gone
        );
        assert_eq!(
            examine(&[("status", STATUS_CLEAR), ("stat", STAT_CLEAR)]),
            Gone
        );
        // Dying: SIGKILL pending, PF_SIGNALED or PF_EXITING; this wins
        // over an exec number.
        // The host's execve number (59 on x86_64, 221 on aarch64): a
        // literal 59 is a different syscall on aarch64 and never Exec.
        let in_execve: &'static [u8] = format!(
            "{} 0x0 0x0 0x0 0x0 0x0 0x0 0x7ffd0000 0x100",
            libc::SYS_execve
        )
        .leak()
        .as_bytes();
        assert_eq!(
            examine(&[
                ("status", STATUS_SIGKILL),
                ("stat", STAT_CLEAR),
                ("syscall", in_execve)
            ]),
            Dying
        );
        assert_eq!(
            examine(&[
                ("status", STATUS_CLEAR),
                ("stat", STAT_SIGNALED),
                ("syscall", in_execve)
            ]),
            Dying
        );
        assert_eq!(
            examine(&[
                ("status", STATUS_CLEAR),
                ("stat", STAT_EXITING),
                ("syscall", in_execve)
            ]),
            Dying
        );
        // Exec, by number and entry instruction.
        let live = [("status", STATUS_CLEAR), ("stat", STAT_CLEAR)];
        let with = |syscall: &'static [u8], mem: Option<&'static [u8]>| {
            let mut files: Vec<(&str, &[u8])> = live.to_vec();
            files.push(("syscall", syscall));
            if let Some(mem) = mem {
                files.push(("mem", mem));
            }
            examine(&files)
        };
        let mut syscall_insn = vec![0u8; 0x100];
        syscall_insn[0xfe..].copy_from_slice(&[0x0f, 0x05]);
        let syscall_insn: &'static [u8] = syscall_insn.leak();
        let mut int80_insn = vec![0u8; 0x100];
        int80_insn[0xfe..].copy_from_slice(&[0xcd, 0x80]);
        let int80_insn: &'static [u8] = int80_insn.leak();
        let in_11 = b"11 0x0 0x0 0x0 0x0 0x0 0x0 0x7ffd0000 0x100";
        assert_eq!(with(in_execve, Some(syscall_insn)), Exec);
        assert_eq!(with(in_execve, None), Exec);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(with(in_11, Some(int80_insn)), Exec);
            assert_eq!(with(in_11, Some(syscall_insn)), Live, "native 11 is munmap");
            assert_eq!(with(in_11, None), Live, "unknown entry");
        }
        // Live: unreadable, running, or another syscall.
        assert_eq!(with(b"running", None), Live);
        assert_eq!(with(blocked, None), Live);
        assert_eq!(examine(&live), Gone, "no syscall file");
    }

    #[test]
    fn sibling_exec_check_uses_the_host_execve_number() {
        // The Exec classification must key on the host's execve
        // numbers, not another architecture's: 59 is execve only on
        // x86_64; on aarch64 it is pipe2 (semtimedop is 192 there).
        assert!(super::is_exec_entry(
            libc::SYS_execve,
            super::EntryAbi::Native
        ));
        assert!(super::is_exec_entry(
            libc::SYS_execveat,
            super::EntryAbi::Native
        ));
        assert!(!super::is_exec_entry(
            libc::SYS_read,
            super::EntryAbi::Native
        ));
        // Literal pins, independent of libc's table, so a binding
        // regression cannot silently re-key the classification.
        #[cfg(target_arch = "aarch64")]
        {
            // Compile-checked only here: this arm is type-checked by
            // the aarch64 cargo check, not natively executed.
            assert!(super::is_exec_entry(221, super::EntryAbi::Native));
            assert!(super::is_exec_entry(281, super::EntryAbi::Native));
            assert!(!super::is_exec_entry(59, super::EntryAbi::Native));
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert!(super::is_exec_entry(59, super::EntryAbi::Native));
            assert!(super::is_exec_entry(322, super::EntryAbi::Native));
        }
    }

    #[test]
    fn parked_threads_really_exist() {
        // The many-thread fixtures are only meaningful if the 2000
        // parked threads were actually created (on aarch64 a 64 KiB
        // stack request used to fail EINVAL and create none). The
        // guest counts /proc/self/task and records it in the marker.
        let marker = supervisor_test_file("park-count.marker");
        let output = std::process::Command::new(fork_guest())
            .arg("park-count")
            .arg(&marker)
            .arg("2000")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(7),
            "park-count guest failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(&marker).unwrap().trim(), "tasks=2001");
    }

    #[test]
    fn exit_stop_main_thread_evidence() {
        let killed = |files: &[(&str, &[u8])]| {
            let dir = fake_task_dir(files);
            let killed = super::main_thread_killed(&dir);
            fs::remove_dir_all(&dir).unwrap();
            killed
        };
        assert!(!killed(&[("status", STATUS_CLEAR), ("stat", STAT_CLEAR)]));
        assert!(!killed(&[("status", STATUS_CLEAR), ("stat", STAT_EXITING)]));
        assert!(killed(&[("status", STATUS_SIGKILL), ("stat", STAT_CLEAR)]));
        assert!(killed(&[("status", STATUS_CLEAR), ("stat", STAT_SIGNALED)]));
        // Unreadable evidence counts as killed.
        assert!(killed(&[("stat", STAT_CLEAR)]));
        assert!(killed(&[("status", STATUS_CLEAR)]));
        assert!(killed(&[("status", STATUS_CLEAR), ("stat", b"garbage")]));
    }

    #[test]
    fn proc_text_parsers() {
        let stat = "42 (a (b) c) S 1 42 42 0 -1 4194624 0 0";
        assert_eq!(super::task_flags(stat), Some(4194624));
        let status =
            "Name:\tx\nThreads:\t2\nSigPnd:\t0000000000000100\nShdPnd:\t0000000000000000\n";
        assert_eq!(super::status_threads(status), Some(2));
        assert!(super::sigkill_pending(status));
        assert!(!super::sigkill_pending(
            "SigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n"
        ));
    }

    fn exited_leader_thread_teardown(cancel: bool) {
        // The guest leader's own traced main thread pthread_exits while
        // a sibling sleeps 3 s before writing a marker. Teardown must
        // not wait for the zombie leader thread to stop (no 2 s quiesce
        // timeout, no recorded failure), and the leader's kill must be
        // process-directed so the sibling dies too: terminal SIGKILL and
        // no marker.
        let marker = supervisor_test_file("leader-pthread-exit.marker");
        let receipt = CleanupReceipt::default();
        let watched = Supervisor::spawn_watched(
            fork_request("leader-pthread-exit", &[&marker]),
            receipt.clone(),
        )
        .unwrap();
        let watched = rearm_ok(watched_next_exec(watched));
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let cleanup = if cancel {
            watched.cancel().unwrap()
        } else {
            drop(watched);
            receipt.snapshot()
        };
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "teardown took {elapsed:?}"
        );
        assert!(cleanup.confirmed);
        assert_eq!(cleanup.child_detach_error, None);
        assert!(
            matches!(
                cleanup.terminal_status,
                Some(ExitStatus::Signaled(Signal::SIGKILL, _))
            ),
            "unexpected terminal status {:?}",
            cleanup.terminal_status
        );
        assert_no_traced_by_current_thread("exited leader thread");
        std::thread::sleep(Duration::from_millis(3300));
        assert!(!marker.exists(), "the leader's sibling survived its kill");
    }

    #[test]
    fn watched_cancel_with_exited_leader_thread_kills_group_promptly() {
        exited_leader_thread_teardown(true);
    }

    #[test]
    fn watched_drop_with_exited_leader_thread_kills_group_promptly() {
        exited_leader_thread_teardown(false);
    }

    /// Enable the test-only SIGKILL-before-detach hook for one scope.
    struct KillBeforeDetach;

    impl KillBeforeDetach {
        fn enable() -> Self {
            super::KILL_BEFORE_CHILD_DETACH.with(|hook| hook.set(true));
            Self
        }
    }

    impl Drop for KillBeforeDetach {
        fn drop(&mut self) {
            super::KILL_BEFORE_CHILD_DETACH.with(|hook| hook.set(false));
        }
    }

    #[test]
    fn watched_release_settles_children_killed_just_before_detach() {
        // While the successor stop is held, the fork child forks a
        // grandchild, so release meets the child at its fork event and
        // the grandchild in its unconsumed initial stop. The hook kills
        // each just before PTRACE_DETACH (ESRCH for a task killed out
        // of its initial stop). Gone but still attached, each must be
        // settled: release succeeds, nothing is recorded, nothing stays
        // traced.
        let stop = grandchild_held_at_release();
        let detached = {
            let _hook = KillBeforeDetach::enable();
            stop.release_detached(|task, _entry, _boundary| Ok(task))
                .unwrap()
        };
        assert_no_traced_by_current_thread("kill before ordinary detach");
        let outcome = detached.wait().unwrap();
        assert_eq!(outcome.status, ExitStatus::Exited(0));
        assert_eq!(outcome.cleanup.child_detach_error, None);
    }

    #[test]
    fn watched_settles_child_killed_at_exit_stop_just_before_detach() {
        // The fork child's main thread pthread_exits beside a running
        // sibling and reaches its exit stop; the hook then kills the
        // group (the live sibling takes the SIGKILL, which ends the
        // exit stop) before PTRACE_DETACH, which fails with ESRCH. The
        // still-attached child must be settled: the leader's status is
        // kept, nothing is recorded, nothing stays traced.
        let marker = supervisor_test_file("hook-exit.marker");
        let watched = Supervisor::spawn_watched(
            fork_request("zombie-leader-child", &[&marker]),
            CleanupReceipt::default(),
        )
        .unwrap();
        let outcome = {
            let _hook = KillBeforeDetach::enable();
            rearm_until_finished(watched)
        };
        assert_eq!(outcome.status, ExitStatus::Exited(7));
        assert!(outcome.cleanup.confirmed);
        assert_eq!(outcome.cleanup.child_detach_error, None);
        assert_no_traced_by_current_thread("kill before exit-stop detach");
        assert!(!wait_for_marker(&marker, Duration::from_secs(3)));
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
                    assert_eq!(
                        super::super::arch::instruction_pointer(stop.entry().regs()),
                        super::super::arch::instruction_pointer(&stop.boundary().exit_regs)
                    );
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
                            super::super::arch::set_instruction_pointer(&mut regs, 0x4141_4141);
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

    /// Preparation-re-run witness (W9 mechanical half): full physical
    /// preparation — reserve, map, filter-last, transcript-checked —
    /// run on a first image and again on a self-exec successor,
    /// cancel-terminated. This is NOT successor arming: no image
    /// entry runs, no relay is installed, no Ready or admission is
    /// claimed, and the guest is never released after preparation.
    #[cfg(all(feature = "loader-private-runtime", feature = "stage1a-probe"))]
    #[allow(unsafe_code)]
    mod preparation_rerun {
        use std::fs::File;
        use std::os::fd::AsFd;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;

        use nix::fcntl::FcntlArg;
        use nix::fcntl::SealFlag;
        use nix::fcntl::fcntl;
        use nix::sys::memfd::MFdFlags;
        use nix::sys::memfd::memfd_create;
        use reverie_loader::artifact::RUNTIME_WINDOW;
        use reverie_loader::artifact::TOOL_REGION;
        use reverie_loader::handoff;
        use reverie_loader::handoff::Extent;
        use reverie_loader::handoff::View;
        use reverie_loader::image::Image;
        use reverie_loader::image::Policy;
        use reverie_loader::image::ValidatedImage;

        use super::*;
        use crate::launcher::exec_stop::CopiedInputRequest;
        use crate::launcher::exec_stop::physical::Preparation;
        use crate::launcher::exec_stop::register_words;

        const PAGE: u64 = 4096;
        const INERT_PACKET: &[u8] = b"PREPARATION_ONLY_NOT_HLIINIT1";

        fn synthetic_runtime() -> Vec<u8> {
            let base = RUNTIME_WINDOW.start;
            let mut gate = vec![0x90_u8; 4096];
            for offset in [0x80_usize, 0x90, 0xa0, 0xb0, 0x200] {
                gate[offset..offset + 2].copy_from_slice(&[0x0f, 0x05]);
            }
            let mut bytes = vec![0; 16384];
            bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
            bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
            bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
            bytes[24..32].copy_from_slice(&(base + 4096).to_le_bytes());
            bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
            bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
            bytes[56..58].copy_from_slice(&7_u16.to_le_bytes());
            for (i, (kind, flags, offset, address, file, memory, align)) in [
                (1_u32, 4_u32, 0_u64, base, 4096_u64, 4096_u64, 4096_u64),
                (1, 5, 4096, base + 4096, 4096, 4096, 4096),
                (1, 6, 8192, base + 8192, 512, 4096, 4096),
                (7, 4, 8192, base + 8192, 16, 80, 8),
                (0x6474_e551, 6, 0, 0, 0, 8 * 1024 * 1024, 0),
                (6, 4, 64, base + 64, 392, 392, 8),
                (1, 4, 12288, base + 12288, 4096, 4096, 4096),
            ]
            .into_iter()
            .enumerate()
            {
                let at = 64 + i * 56;
                bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
                bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
                for (relative, value) in [
                    (8, offset),
                    (16, address),
                    (32, file),
                    (40, memory),
                    (48, align),
                ] {
                    bytes[at + relative..at + relative + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
            for (i, word) in [
                u64::from_le_bytes(*b"HLMLAY01"),
                1,
                96,
                handoff::VERSION,
                handoff::HEADER_BYTES as u64,
                handoff::MAX_BYTES as u64,
                64,
                16,
                128,
                8,
                base + 4096,
                base + 4096 + 0x7c,
            ]
            .into_iter()
            .enumerate()
            {
                bytes[512 + i * 8..520 + i * 8].copy_from_slice(&word.to_le_bytes());
            }
            bytes[1024..1034].copy_from_slice(b"/dev/null\0");
            bytes[4096..8192].copy_from_slice(&gate);
            bytes[12288..16384].copy_from_slice(&gate);
            bytes
        }

        fn descriptor_words(runtime: &[u8]) -> [u64; 12] {
            let mut words = [0_u64; 12];
            for (i, word) in words.iter_mut().enumerate() {
                *word = u64::from_le_bytes(runtime[512 + i * 8..520 + i * 8].try_into().unwrap());
            }
            words
        }

        fn memfd(bytes: &[u8], seal: bool) -> std::io::Result<File> {
            let mut file = File::from(
                memfd_create(
                    c"preparation-rerun-witness",
                    MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING,
                )
                .map_err(std::io::Error::from)?,
            );
            std::io::Write::write_all(&mut file, bytes)?;
            if seal {
                seal_file(&file)?;
            }
            Ok(file)
        }

        fn seal_file(file: &File) -> std::io::Result<()> {
            fcntl(
                file,
                FcntlArg::F_ADD_SEALS(
                    SealFlag::F_SEAL_WRITE
                        | SealFlag::F_SEAL_GROW
                        | SealFlag::F_SEAL_SHRINK
                        | SealFlag::F_SEAL_SEAL,
                ),
            )
            .map_err(std::io::Error::from)?;
            Ok(())
        }

        fn validated(runtime: &[u8]) -> ValidatedImage<'_> {
            let parsed = Image::parse(runtime).expect("synthetic runtime parses");
            let image = parsed
                .validate(&Policy {
                    window: RUNTIME_WINDOW,
                    allow_tls: true,
                })
                .expect("synthetic runtime validates");
            image
                .private_runtime_metadata()
                .expect("synthetic runtime metadata");
            image
        }

        fn exact_rx<'a>(
            image: &ValidatedImage<'a>,
            address: u64,
            length: usize,
        ) -> Result<&'a [u8]> {
            let end = address
                .checked_add(length as u64)
                .ok_or("RX span overflow")?;
            for load in image.segments() {
                let initialized = image
                    .mapped_file_bytes(load)
                    .map_err(|e| format!("RX load: {e:?}"))?;
                if load.permissions.read
                    && load.permissions.execute
                    && !load.permissions.write
                    && load.memory.start <= address
                    && end
                        <= load
                            .memory
                            .start
                            .checked_add(load.file.end - load.file.start)
                            .ok_or("RX end overflow")?
                {
                    let at = usize::try_from(address - load.memory.start)?;
                    return initialized
                        .get(at..at + length)
                        .ok_or_else(|| "RX file bounds".into());
                }
            }
            Err("outside initialized RX bytes".into())
        }

        fn aligned(value: u64, alignment: u64) -> u64 {
            assert!(alignment.is_power_of_two());
            (value + alignment - 1) & !(alignment - 1)
        }

        fn payload_words(
            data: &crate::launcher::exec_stop::CopiedInitialData,
            address: u64,
            count: u64,
        ) -> Result<Vec<u64>> {
            let start = usize::try_from(address - data.address())?;
            let length = usize::try_from(count * 8)?;
            Ok(data.bytes()[start..start + length]
                .as_chunks::<8>()
                .0
                .iter()
                .map(|row| u64::from_le_bytes(*row))
                .collect())
        }

        fn payload_bytes(
            data: &crate::launcher::exec_stop::CopiedInitialData,
            address: u64,
            length: u64,
        ) -> Result<&[u8]> {
            let start = usize::try_from(address - data.address())?;
            let end = start + usize::try_from(length)?;
            data.bytes()
                .get(start..end)
                .ok_or_else(|| "copied bytes bounds".into())
        }

        struct Geometry {
            roles: [Extent; 5],
            free_band: Extent,
            control: u64,
            relay: u64,
            filter_scratch: u64,
            copied_address: u64,
            copied_capacity: usize,
        }

        fn geometry(descriptor: &[u64; 12]) -> Geometry {
            let free_band = crate::guest::tool_region::scalar_free_band();
            let base = free_band.start;
            let roles = core::array::from_fn(|i| Extent {
                start: base + i as u64 * 0x10000,
                end: base + i as u64 * 0x10000 + 0x8000,
            });
            let control = roles[4].start + PAGE;
            let relay = aligned(control + descriptor[6], descriptor[9]);
            let address = roles[3].start + PAGE;
            let copied_address = address + 2 * PAGE;
            let copied_capacity = usize::try_from(roles[3].end - PAGE - copied_address).unwrap();
            Geometry {
                roles,
                free_band,
                control,
                relay,
                filter_scratch: roles[4].start + 8192,
                copied_address,
                copied_capacity,
            }
        }

        struct WireContext {
            pid: u64,
            regs: [u64; 27],
            mask: u64,
            input_fd: u64,
            pkru: u32,
        }

        // Happy-path numeric wire only, adapted from the probe's
        // preparation-only wire. It is deliberately not an admission
        // or execution-eligible handoff producer.
        fn build_wire(
            image: &ValidatedImage<'_>,
            descriptor: &[u64; 12],
            geometry: &Geometry,
            data: &crate::launcher::exec_stop::CopiedInitialData,
            context: &WireContext,
        ) -> Result<Vec<u8>> {
            let roles = &geometry.roles;
            let gate = descriptor[10];
            let address = roles[3].start + PAGE;
            let length = usize::try_from(roles[3].end - address - PAGE)?;
            assert!(length <= handoff::MAX_BYTES && length >= 3 * PAGE as usize);
            let mut bytes = vec![0; length];
            let at = usize::try_from(data.address() - address)?;
            bytes[at..at + data.bytes().len()].copy_from_slice(data.bytes());
            let metadata = data.image_metadata();
            let handler = gate + 0x100;
            assert_eq!(exact_rx(image, handler, 16)?.len(), 16);
            let dev_null = RUNTIME_WINDOW.start + 1024;
            let mut code = Vec::new();
            for load in image.segments() {
                if load.permissions.read && load.permissions.execute && !load.permissions.write {
                    code.push(handoff::Code {
                        start: load.memory.start,
                        end: load.memory.start + (load.file.end - load.file.start),
                    });
                }
            }
            let mut sites = Vec::new();
            for (offset, number, operation) in [
                (0x80_u64, 158_u64, 1_u64),
                (0x90, 218, 2),
                (0xa0, 7, 3),
                (0xb0, 2, 4),
            ] {
                let ip = gate + offset;
                assert_eq!(exact_rx(image, ip, 2)?, [0x0f, 0x05]);
                sites.push(handoff::SiteRecord {
                    syscall_ip: ip,
                    return_ip: ip + 2,
                    number,
                    operation,
                });
            }
            sites.sort_unstable_by_key(|site| site.return_ip);
            let tool_init = [gate + 0x202];
            assert_eq!(exact_rx(image, gate + 0x200, 2)?, [0x0f, 0x05]);
            let maps = data.planned_maps().to_vec();
            let locations = data.locations();
            let env = payload_words(data, locations.envp, locations.envp_words)?;
            let aux = payload_words(data, locations.raw_aux, locations.raw_aux_words)?;
            let name = payload_bytes(data, locations.program_name, locations.program_name_bytes)?;
            let tls = &metadata.tls;
            let backing = data.tls_geometry().backing();
            let mut header = handoff::Header {
                prefix: [
                    handoff::MAGIC,
                    handoff::VERSION,
                    length as u64,
                    handoff::HEADER_BYTES as u64,
                    0,
                    0,
                    0,
                    0,
                ],
                binding: [[0; 4]; 5],
                roles: *roles,
                registers: context.regs,
                scalars: [
                    context.pid,
                    geometry.control,
                    data.control_bytes(),
                    geometry.relay,
                    data.relay_bytes(),
                    context.input_fd,
                    u64::from(context.pkru),
                    context.mask,
                    data.tls_geometry().pthread().start as u64,
                    handler,
                    RUNTIME_WINDOW.start + 12288,
                    PAGE,
                    metadata.gnu_stack_bytes,
                    dev_null,
                    0,
                    0,
                ],
                tables: std::array::from_fn(|_| handoff::Table {
                    offset: 0,
                    count: 0,
                    stride: 0,
                }),
                tls: [
                    metadata.program_headers.start,
                    56,
                    u64::from(metadata.program_header_count),
                    tls.address,
                    tls.file_bytes,
                    tls.memory_bytes,
                    tls.alignment,
                    backing.start as u64,
                    backing.bytes as u64,
                    tls.load.memory.start,
                    tls.load.memory.end - tls.load.memory.start,
                    tls.load.file.end - tls.load.file.start,
                ],
            };
            let mut cursor = handoff::HEADER_BYTES as u64;
            for (index, count, stride) in [
                (0, maps.len(), 32_u64),
                (1, code.len(), 16),
                (2, sites.len(), 32),
                (3, INERT_PACKET.len(), 1),
                (7, 10, 1),
                (8, tool_init.len(), 8),
            ] {
                cursor = aligned(cursor, 8);
                header.tables[index] = handoff::Table {
                    offset: cursor,
                    count: count as u64,
                    stride,
                };
                cursor += count as u64 * stride;
            }
            assert!(cursor <= at as u64, "metadata overlaps copied payload");
            for (index, location, count, stride) in [
                (4, locations.envp, locations.envp_words, 8_u64),
                (5, locations.raw_aux, locations.raw_aux_words, 8),
                (6, locations.program_name, locations.program_name_bytes, 1),
            ] {
                header.tables[index] = handoff::Table {
                    offset: location - address,
                    count,
                    stride,
                };
            }
            let tables = handoff::TableData {
                maps: &maps,
                code: &code,
                sites: &sites,
                packet: INERT_PACKET,
                env: &env,
                aux: &aux,
                program_name: name,
                dev_null: b"/dev/null\0",
                tool_init: &tool_init,
            };
            handoff::serialize(&header, &tables, address, &mut bytes)
                .map_err(|e| format!("wire serialize: {e:?}"))?;
            reverie_loader::mapped_inputs::ProductionMappedInputs::validate_at(
                &bytes,
                address,
                reverie_loader::mapped_inputs::ConsumerLayout {
                    free_band: geometry.free_band,
                    region: Extent {
                        start: TOOL_REGION.start,
                        end: TOOL_REGION.end,
                    },
                    control_bytes: descriptor[6],
                    relay_bytes: descriptor[8],
                    control_align: descriptor[7],
                    relay_align: descriptor[9],
                },
            )
            .map_err(|e| format!("wire validate_at: {e:?}"))?;
            View::parse(&bytes, address).map_err(|e| format!("wire parse: {e:?}"))?;
            Ok(bytes)
        }

        fn watched_guest<'fd>(
            runtime_file: &'fd File,
            handoff_file: &'fd File,
            input_file: &'fd File,
        ) -> WatchedSupervisor<'fd> {
            let args: Vec<OsString> = ["sh", "-c", "exec /bin/sh -c true"]
                .iter()
                .map(OsString::from)
                .collect();
            let request = PreparedExec::new(
                Path::new("/bin/sh"),
                &args,
                &[],
                None,
                vec![
                    runtime_file.as_fd(),
                    handoff_file.as_fd(),
                    input_file.as_fd(),
                ],
            )
            .unwrap();
            Supervisor::spawn_watched(request, CleanupReceipt::default()).unwrap()
        }

        fn next_exec(watched: WatchedSupervisor<'_>) -> SuccessorStop<'_> {
            match watched.wait_next().unwrap() {
                WatchedStep::Exec(stop) => *stop,
                WatchedStep::Finished(outcome) => {
                    panic!("expected an exec stop, got terminal {outcome:?}")
                }
            }
        }

        fn status_u64(status: &str, key: &str) -> u64 {
            status
                .lines()
                .find(|line| line.starts_with(key))
                .and_then(|line| line[key.len()..].trim().parse().ok())
                .unwrap_or_else(|| panic!("status key {key} missing"))
        }

        // Full physical preparation on this stop, then cancel. The
        // guest is never released after preparation.
        fn prepare_and_cancel<'fd>(
            stop: SuccessorStop<'fd>,
            runtime: &[u8],
            descriptor: &[u64; 12],
            geometry: &Geometry,
            runtime_file: &'fd File,
            handoff_file: &'fd File,
            input_file: &'fd File,
        ) {
            let original_regs = register_words(stop.entry().regs());
            let original_mask = stop.entry().signal_mask();
            let original_entry = trace::read(&stop.task, stop.entry().regs().rip, 16).unwrap();
            let image = validated(runtime);
            let captured = stop.capture_initial_inputs().unwrap();
            let copied = stop
                .prepare_copied_inputs(
                    &captured,
                    &image,
                    &CopiedInputRequest {
                        roles: geometry.roles,
                        free_band: geometry.free_band,
                        layout_address: RUNTIME_WINDOW.start + 512,
                        copied_address: geometry.copied_address,
                        copied_capacity: geometry.copied_capacity,
                        control_address: geometry.control,
                        relay_address: geometry.relay,
                        filter_scratch: geometry.filter_scratch,
                    },
                )
                .unwrap();
            // SAFETY: EntryContext owns the complete unchanged real
            // ptrace XSAVE capture for this held generation (same
            // obligation the probe documents for this read).
            let pkru = unsafe { stop.entry().xstate().pkru() }.expect("stopped PKRU");
            let wire = build_wire(
                &image,
                descriptor,
                geometry,
                &copied,
                &WireContext {
                    pid: stop.pid().as_raw() as u64,
                    regs: original_regs,
                    mask: original_mask,
                    input_fd: input_file.as_raw_fd() as u64,
                    pkru,
                },
            )
            .unwrap();
            let role_bytes = geometry.roles[3].end - geometry.roles[3].start - 2 * PAGE;
            assert_eq!(role_bytes, (wire.len() as u64).div_ceil(PAGE) * PAGE);
            handoff_file.write_all_at(&wire, 0).unwrap();
            handoff_file.set_len(role_bytes).unwrap();
            seal_file(handoff_file).unwrap();
            let preparation = Preparation {
                runtime_fd: runtime_file.as_fd(),
                runtime_bytes: runtime,
                layout_address: RUNTIME_WINDOW.start + 512,
                handoff_fd: handoff_file.as_fd(),
                handoff_bytes: &wire,
                handoff_address: geometry.roles[3].start + PAGE,
                input_fd: input_file.as_fd(),
                free_band: geometry.free_band,
                filter_scratch: geometry.filter_scratch,
            };
            // SAFETY: original ptracer thread, inherited immutable
            // descriptors retained by the launch request, genuine
            // captured context of this stop, outer test bounds. No
            // image/guest entry is called; preparation only.
            let prepared = match unsafe { stop.prepare_mapping(preparation) } {
                Ok(prepared) => prepared,
                Err(failure) => panic!(
                    "preparation refused: {} cleanup={:?}",
                    failure.error,
                    failure.cleanup()
                ),
            };
            let observed = prepared.diagnostic_observation().unwrap();
            assert_eq!(observed.registers, original_regs);
            assert_eq!(observed.signal_mask, original_mask);
            assert!(observed.xstate_exact);
            assert!(observed.stack_exact);
            assert_eq!(observed.entry_bytes, original_entry);
            assert!(observed.runtime_contents_exact);
            assert!(observed.handoff_exact);
            assert_eq!(status_u64(&observed.status, "Seccomp:"), 2);
            assert_eq!(status_u64(&observed.status, "NoNewPrivs:"), 1);
            let cancelled = match prepared.cancel() {
                Ok(cancelled) => cancelled,
                Err(retained) => panic!("preparation cancel unconfirmed: {:?}", retained.cleanup()),
            };
            assert!(cancelled.cleanup.confirmed);
            assert_eq!(cancelled.filter_bytes.len(), 23 * 8);
            let last = cancelled.injected_calls.last().expect("injected calls");
            assert_eq!(last.0, libc::SYS_seccomp as u64);
            assert_eq!(last.2, 0);
            assert!(
                cancelled
                    .injected_calls
                    .iter()
                    .any(|call| call.0 == libc::SYS_mmap as u64),
                "preparation transcript must contain real mappings"
            );
        }

        #[test]
        fn preparation_rerun_first_image() {
            let runtime = synthetic_runtime();
            let descriptor = descriptor_words(&runtime);
            let geometry = geometry(&descriptor);
            let runtime_file = memfd(&runtime, true).unwrap();
            let handoff_file = memfd(&[], false).unwrap();
            let input_file = memfd(INERT_PACKET, true).unwrap();
            let watched = watched_guest(&runtime_file, &handoff_file, &input_file);
            let stop = next_exec(watched);
            prepare_and_cancel(
                stop,
                &runtime,
                &descriptor,
                &geometry,
                &runtime_file,
                &handoff_file,
                &input_file,
            );
        }

        #[test]
        fn preparation_rerun_self_exec_successor() {
            let runtime = synthetic_runtime();
            let descriptor = descriptor_words(&runtime);
            let geometry = geometry(&descriptor);
            let runtime_file = memfd(&runtime, true).unwrap();
            let handoff_file = memfd(&[], false).unwrap();
            let input_file = memfd(INERT_PACKET, true).unwrap();
            let mut watched = watched_guest(&runtime_file, &handoff_file, &input_file);
            // Release the first image UNPREPARED so it can self-exec;
            // a prepared image has no release transition in this
            // slice (cancel-only), which is the named residual gap
            // for a one-lineage prepared->exec->prepared chain.
            let first = next_exec(watched);
            let pid = first.pid();
            watched = first
                .rearm_and_resume(|task, _entry, _boundary| Ok(task))
                .unwrap();
            let successor = next_exec(watched);
            assert_eq!(successor.pid(), pid);
            assert_eq!(successor.former_tid(), pid);
            prepare_and_cancel(
                successor,
                &runtime,
                &descriptor,
                &geometry,
                &runtime_file,
                &handoff_file,
                &input_file,
            );
        }

        #[test]
        fn release_after_ready_mismatch_returns_unspent_mapping() {
            use crate::launcher::exec_stop::physical::VerifiedReady;

            let runtime = synthetic_runtime();
            let descriptor = descriptor_words(&runtime);
            let geometry = geometry(&descriptor);
            let runtime_file = memfd(&runtime, true).unwrap();
            let handoff_file = memfd(&[], false).unwrap();
            let input_file = memfd(INERT_PACKET, true).unwrap();
            let watched = watched_guest(&runtime_file, &handoff_file, &input_file);
            let stop = next_exec(watched);
            let pid = stop.pid();
            let original_regs = register_words(stop.entry().regs());
            let original_mask = stop.entry().signal_mask();
            let image = validated(&runtime);
            let captured = stop.capture_initial_inputs().unwrap();
            let copied = stop
                .prepare_copied_inputs(
                    &captured,
                    &image,
                    &CopiedInputRequest {
                        roles: geometry.roles,
                        free_band: geometry.free_band,
                        layout_address: RUNTIME_WINDOW.start + 512,
                        copied_address: geometry.copied_address,
                        copied_capacity: geometry.copied_capacity,
                        control_address: geometry.control,
                        relay_address: geometry.relay,
                        filter_scratch: geometry.filter_scratch,
                    },
                )
                .unwrap();
            // SAFETY: same held-generation XSAVE read as the
            // preparation witnesses above.
            let pkru = unsafe { stop.entry().xstate().pkru() }.expect("stopped PKRU");
            let wire = build_wire(
                &image,
                &descriptor,
                &geometry,
                &copied,
                &WireContext {
                    pid: pid.as_raw() as u64,
                    regs: original_regs,
                    mask: original_mask,
                    input_fd: input_file.as_raw_fd() as u64,
                    pkru,
                },
            )
            .unwrap();
            let role_bytes = geometry.roles[3].end - geometry.roles[3].start - 2 * PAGE;
            handoff_file.write_all_at(&wire, 0).unwrap();
            handoff_file.set_len(role_bytes).unwrap();
            seal_file(&handoff_file).unwrap();
            let preparation = Preparation {
                runtime_fd: runtime_file.as_fd(),
                runtime_bytes: &runtime,
                layout_address: RUNTIME_WINDOW.start + 512,
                handoff_fd: handoff_file.as_fd(),
                handoff_bytes: &wire,
                handoff_address: geometry.roles[3].start + PAGE,
                input_fd: input_file.as_fd(),
                free_band: geometry.free_band,
                filter_scratch: geometry.filter_scratch,
            };
            // SAFETY: original ptracer thread, inherited immutable
            // descriptors, genuine captured context, as in
            // prepare_and_cancel. Preparation only; the mismatched
            // release below refuses before any restore or entry.
            let mut prepared = match unsafe { stop.prepare_mapping(preparation) } {
                Ok(prepared) => prepared,
                Err(failure) => panic!(
                    "preparation refused: {} cleanup={:?}",
                    failure.error,
                    failure.cleanup()
                ),
            };
            // Name an exact initialized stop, then present a token for
            // another pid naming that same stop. Only the release
            // call site's owner-pid argument can refuse this; passing
            // the token's own pid would wrongly proceed to restore.
            let terminal = RUNTIME_WINDOW.start + 8192;
            let reserved = 1_u64 << (libc::SIGSYS - 1);
            prepared.set_initialized_stop_for_test(Some((terminal, reserved)));
            let wrong = VerifiedReady::for_test(
                safeptrace::Pid::from_raw(pid.as_raw() + 1),
                terminal,
                reserved,
            );
            let tokio = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            // SAFETY: the token names the exact recorded stop but
            // another child, so release must refuse at its recheck
            // before any physical change.
            let failure = tokio.block_on(async {
                match unsafe {
                    prepared
                        .release_after_ready(
                            wrong,
                            std::time::Instant::now() + std::time::Duration::from_secs(30),
                        )
                        .await
                } {
                    Ok(_) => panic!("mismatched release unexpectedly detached"),
                    Err(failure) => failure,
                }
            });
            assert!(
                failure
                    .error
                    .to_string()
                    .contains("mapped_ready_token_mismatch"),
                "unexpected release refusal: {}",
                failure.error
            );
            let mut mapping = failure.into_mapping();
            assert_eq!(
                mapping.handover_flags_for_test(),
                (false, false),
                "mismatch must leave failed and handover_started unset"
            );
            // Keep the stop-mismatch case as well: present a token
            // for the correct pid after clearing the recorded stop.
            // Only the call site's initialized-stop argument can
            // refuse this; passing the token's own stop would proceed.
            mapping.set_initialized_stop_for_test(None);
            let wrong_stop = VerifiedReady::for_test(pid, terminal, reserved);
            // SAFETY: the token names this child but no recorded
            // initialized stop remains, so release must refuse at its
            // recheck before any physical change.
            let failure = tokio.block_on(async {
                match unsafe {
                    mapping
                        .release_after_ready(
                            wrong_stop,
                            std::time::Instant::now() + std::time::Duration::from_secs(30),
                        )
                        .await
                } {
                    Ok(_) => panic!("stop-mismatched release unexpectedly detached"),
                    Err(failure) => failure,
                }
            });
            assert!(
                failure
                    .error
                    .to_string()
                    .contains("mapped_ready_token_mismatch"),
                "unexpected release refusal: {}",
                failure.error
            );
            let mapping = failure.into_mapping();
            assert_eq!(
                mapping.handover_flags_for_test(),
                (false, false),
                "mismatch must leave failed and handover_started unset"
            );
            let observed = mapping.diagnostic_observation().unwrap();
            assert_eq!(observed.registers, original_regs);
            assert!(observed.xstate_exact);
            let cancelled = match mapping.cancel() {
                Ok(cancelled) => cancelled,
                Err(retained) => panic!("cancel unconfirmed: {:?}", retained.cleanup()),
            };
            assert!(cancelled.cleanup.confirmed);
        }

        #[test]
        fn preparation_parts_refuse_foreign_context() {
            use crate::launcher::exec_stop::physical::prepare_mapping_parts;

            let runtime = synthetic_runtime();
            let descriptor = descriptor_words(&runtime);
            let geometry = geometry(&descriptor);
            let runtime_file = memfd(&runtime, true).unwrap();
            let handoff_file = memfd(&[], false).unwrap();
            let input_file = memfd(INERT_PACKET, true).unwrap();
            let watched_a = watched_guest(&runtime_file, &handoff_file, &input_file);
            let stop_a = next_exec(watched_a);
            let runtime_file_b = memfd(&runtime, true).unwrap();
            let handoff_file_b = memfd(&[], false).unwrap();
            let input_file_b = memfd(INERT_PACKET, true).unwrap();
            let watched_b = watched_guest(&runtime_file_b, &handoff_file_b, &input_file_b);
            let stop_b = next_exec(watched_b);
            let (task_a, _context_a, boundary_a, owner_a, detach_a) = stop_a.into_parts();
            let (task_b, context_b, _boundary_b, owner_b, detach_b) = stop_b.into_parts();
            detach_a.unwrap();
            detach_b.unwrap();
            let preparation = Preparation {
                runtime_fd: runtime_file.as_fd(),
                runtime_bytes: &runtime,
                layout_address: RUNTIME_WINDOW.start + 512,
                handoff_fd: handoff_file.as_fd(),
                handoff_bytes: &[],
                handoff_address: geometry.roles[3].start + PAGE,
                input_fd: input_file.as_fd(),
                free_band: geometry.free_band,
                filter_scratch: geometry.filter_scratch,
            };
            // SAFETY: same obligations as the happy witness; the
            // deliberately foreign pairing must refuse before any
            // child mutation, which is the fence under test.
            let failure = match unsafe {
                prepare_mapping_parts(task_a, context_b, boundary_a, owner_a, preparation)
            } {
                Ok(_) => panic!("foreign parts unexpectedly prepared"),
                Err(failure) => failure,
            };
            assert!(
                failure
                    .error
                    .to_string()
                    .contains("mapped_preparation_foreign_parts"),
                "unexpected refusal: {}",
                failure.error
            );
            assert!(failure.cleanup().confirmed);
            drop(task_b);
            let cancelled = owner_b.cancel().unwrap();
            assert!(cancelled.confirmed);
        }
    }
}
