/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg(target_os = "linux")]

//! A safe ptrace API. This API forces correct usage of ptrace in that it is
//! not possible to call ptrace on a process not in a stopped state.
#[cfg(feature = "memory")]
mod memory;
#[cfg(feature = "notifier")]
mod notifier;
mod regs;
mod waitid;

use core::mem::MaybeUninit;
use std::fmt;

use nix::sys::ptrace;
// Re-exports so that nothing else needs to depend on `nix`.
pub use nix::sys::ptrace::Options;
pub use nix::sys::signal::Signal;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
pub use reverie_process::ExitStatus;
pub use reverie_process::Pid;
pub use syscalls::Errno;
use syscalls::Sysno;
use thiserror::Error;

#[cfg(feature = "notifier")]
pub use crate::notifier::ProcStatError;
#[cfg(feature = "notifier")]
pub use crate::notifier::StopObservationError;
#[cfg(feature = "notifier")]
pub use crate::notifier::StopObservationSample;
#[cfg(feature = "notifier")]
pub use crate::notifier::StopSiginfo;
#[cfg(feature = "notifier")]
pub use crate::notifier::StoppedObservation;
#[cfg(feature = "notifier")]
pub use crate::notifier::SupersededStopRefusal;
#[cfg(feature = "notifier")]
pub use crate::notifier::TerminalCleanup;
pub use crate::regs::*;
use crate::waitid::IdType;
use crate::waitid::waitid;

/// Immutable generation token carried through every typed tracee state.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct TraceeToken {
    #[cfg(feature = "notifier")]
    event: notifier::EventHandle,
}

impl TraceeToken {
    fn new() -> Self {
        Self {
            #[cfg(feature = "notifier")]
            event: notifier::EventHandle::new(),
        }
    }

    fn current_or_new(pid: Pid) -> Result<Self, Errno> {
        #[cfg(not(feature = "notifier"))]
        let _ = pid;
        Ok(Self {
            #[cfg(feature = "notifier")]
            event: notifier::EventHandle::current_or_new(pid)?,
        })
    }

    /// The generation that `pid` names now, shared with every other
    /// capability for it as `current_or_new` shares it, or a fresh token if
    /// the task's identity cannot be captured. A fresh token is bound to no
    /// generation, so its requests are not held off by the TID gate that the
    /// task's reaper marks.
    fn current_or_fresh(pid: Pid) -> Self {
        Self::current_or_new(pid).unwrap_or_else(|_| Self::new())
    }

    fn current_or_error(pid: Pid) -> Self {
        #[cfg(not(feature = "notifier"))]
        let _ = pid;
        Self {
            #[cfg(feature = "notifier")]
            event: notifier::EventHandle::current_or_error(pid),
        }
    }

    #[cfg(feature = "notifier")]
    fn from_event(event: notifier::EventHandle) -> Self {
        Self { event }
    }

    #[cfg(feature = "notifier")]
    fn event(&self) -> &notifier::EventHandle {
        &self.event
    }

    /// Runs one numeric request on this generation's TID.
    ///
    /// Under the notifier, a fatal signal can end the stop that a capability
    /// names, and the generation's reaper can then release the TID for reuse
    /// while the capability is still held. Once that reap has marked this
    /// generation's gate, the request fails with `ESRCH` without reaching the
    /// kernel, so it does not name a replacement task. A reap that marks no
    /// gate lets the request through: a generation whose identity was never
    /// captured, a bulk wait, or an order in
    /// <https://github.com/rrnewton/reverie/issues/860>. Without the notifier
    /// the request always runs.
    fn on_held_tid<T>(&self, request: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
        #[cfg(feature = "notifier")]
        let Some(_held) = self.event.hold_tid() else {
            return Err(Errno::ESRCH);
        };
        request()
    }
}

fn nix_errno(err: nix::Error) -> Errno {
    Errno::new(err as i32)
}

#[cfg(target_arch = "x86_64")]
const NT_X86_XSTATE: i32 = 0x202;

/// An error that occurred during tracing.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    /// A low-level errno.
    #[error(transparent)]
    Errno(#[from] Errno),

    /// The tracee died unexpectedly. This should be handled gracefully by
    /// reaping the zombie.
    #[error("tracee {0} is a zombie")]
    Died(Zombie),
}

impl From<nix::errno::Errno> for Error {
    fn from(err: nix::errno::Errno) -> Self {
        Self::Errno(Errno::new(err as i32))
    }
}

#[cfg(feature = "notifier")]
pub use notifier::OwnedWaitError;
#[cfg(feature = "notifier")]
pub use notifier::OwnedWaitFuture;

/// Represents an invalid state. Useful for errors.
#[derive(Debug, Eq, PartialEq)]
struct InvalidState(pub TryWait);

impl From<InvalidState> for TryWait {
    fn from(error: InvalidState) -> TryWait {
        error.0
    }
}

impl fmt::Display for InvalidState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "got unexpected status {}", self.0)
    }
}

impl std::error::Error for InvalidState {}

/// Indicates how a child was created (i.e., via `fork`, `vfork`, or `clone`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ChildOp {
    /// Stop before return from `fork(2)` or `clone(2)` with the exit signal set
    /// to `SIGCHLD`.
    Fork,

    /// Stop before return from `vfork(2)` or `clone(2)` with the `CLONE_VFORK`
    /// flag. When the tracee is continued after this stop, it will wait for
    /// child to exit/exec before continuing its execution (in other words, the
    /// usual behavior on `vfork(2)`).
    Vfork,

    /// Stop before return from `clone(2)`.
    Clone,
}

/// A stop event. Documentation is from `ptrace(2)`.
#[derive(Debug, Eq, PartialEq)]
pub enum Event {
    /// Stop event after a new child has been created (i.e., via `fork`, `vfork`,
    /// or `clone`).
    NewChild(ChildOp, Running),

    /// Stop before return from `execve(2)`. Since Linux 3.0,
    /// `PTRACE_GETEVENTMSG` returns the former thread ID.
    Exec(Pid),

    /// Stop before return from `vfork(2)` or `clone(2)` with the `CLONE_VFORK`
    /// flag, but after the child unblocked this tracee by exiting or execing.
    VforkDone,

    /// Stop before exit (including death from `exit_group(2)`), signal death, or
    /// exit caused by `execve(2)` in a multithreaded process.
    /// `PTRACE_GETEVENTMSG` returns the exit status. Registers can be examined
    /// (unlike when "real" exit happens). The tracee is still alive; it needs to
    /// be `PTRACE_CONT`ed or `PTRACE_DETACH`ed to finish exiting.
    Exit,

    /// Stop triggered by a `seccomp(2)` rule on tracee syscall entry when
    /// `PTRACE_O_TRACESECCOMP` has been set by the tracer. The seccomp event
    /// message data (from the `SECCOMP_RET_DATA` portion of the seccomp filter
    /// rule) can be retrieved with `PTRACE_GETEVENTMSG`. The semantics of this
    /// stop are described in detail in a separate section below.
    Seccomp,

    /// Stop induced by PTRACE_INTERRUPT command, or group-stop, or initial
    /// ptrace-stop when a new child is attached (only if attached using
    /// PTRACE_SEIZE).
    Stop,

    /// The tracee was stopped by execution of a system call.
    Syscall,

    /// The tracee was stopped by delivery of a signal.
    Signal(Signal),
}

impl Event {
    /// Converts a raw i32 to a ptrace event and gets any associated data.
    fn from_ptrace_event(task: &Stopped, event: i32) -> Result<Self, Error> {
        // Note that there is no danger in calling ptrace here because the
        // process is guaranteed to be in a ptrace-stop state when this function
        // is called.
        match event {
            libc::PTRACE_EVENT_FORK => {
                // Get the pid of the child immediately since we almost always
                // want that.
                let child_pid = Pid::from_raw(task.getevent()? as i32);
                #[cfg(all(test, feature = "notifier"))]
                notifier::register_new_child_for_test_cleanup(task.1.event(), child_pid)?;
                Ok(Self::NewChild(
                    ChildOp::Fork,
                    Running::from_current_or_new(child_pid)?,
                ))
            }
            libc::PTRACE_EVENT_VFORK => {
                // Get the pid of the child immediately since we almost always
                // want that.
                let child_pid = Pid::from_raw(task.getevent()? as i32);
                #[cfg(all(test, feature = "notifier"))]
                notifier::register_new_child_for_test_cleanup(task.1.event(), child_pid)?;
                Ok(Self::NewChild(
                    ChildOp::Vfork,
                    Running::from_current_or_new(child_pid)?,
                ))
            }
            libc::PTRACE_EVENT_CLONE => {
                // Get the pid of the child immediately since we almost always
                // want that.
                let child_pid = Pid::from_raw(task.getevent()? as i32);
                #[cfg(all(test, feature = "notifier"))]
                notifier::register_new_child_for_test_cleanup(task.1.event(), child_pid)?;
                Ok(Self::NewChild(
                    ChildOp::Clone,
                    Running::from_current_or_new(child_pid)?,
                ))
            }
            libc::PTRACE_EVENT_EXEC => {
                // The event arrives under the current leader TID. GETEVENTMSG
                // identifies the executing thread's former TID; it is not a
                // newly allocated PID or a terminal status for that thread.
                let former_tid = Pid::from_raw(task.getevent()? as i32);
                // Only a task in its exec stop reports that message. A fatal
                // signal takes a tracee out of any stop without a tracer
                // request, into its exit stop, whose message is the exit
                // code. PTRACE_GETSIGINFO after GETEVENTMSG confirms the task
                // was still in its exec stop when the message was read: the
                // task never returns to an exec stop once it has left it, so
                // an exec-stop si_code here proves the message above is the
                // former TID. Any other si_code, or ESRCH, is a death under
                // ptrace: this status names a stop the tracee has left.
                let siginfo = task.getsiginfo()?;
                if siginfo.si_code != libc::SIGTRAP | (libc::PTRACE_EVENT_EXEC << 8) {
                    return Err(Error::Died(Zombie::from_token(task.0, task.1.clone())));
                }
                Ok(Self::Exec(former_tid))
            }
            libc::PTRACE_EVENT_VFORK_DONE => Ok(Self::VforkDone),
            libc::PTRACE_EVENT_EXIT => {
                // Note that we can get the exit status here using `getevent`,
                // but that's almost never what we want to do. It is better to
                // get that during the final exit event.
                Ok(Self::Exit)
            }
            libc::PTRACE_EVENT_SECCOMP => Ok(Self::Seccomp),
            libc::PTRACE_EVENT_STOP => Ok(Self::Stop),
            _ => unreachable!("unknown ptrace event {:#x}", event),
        }
    }
}

/// Helper function for waiting on one or more processes. Returns `None` if
/// `WaitPidFlag::WNOHANG` was specified and the process is still running.
fn wait(id: IdType, flags: WaitPidFlag) -> Result<Option<WaitStatus>, Errno> {
    loop {
        let result = waitid(id, flags).map(|status| {
            if status == WaitStatus::StillAlive {
                None
            } else {
                Some(status)
            }
        });

        if result == Err(Errno::EINTR) {
            continue;
        }

        return result;
    }
}

/// The result of a non-blocking wait. A process can be in one of three main
/// states: running, ptrace-stopped, or exited.
///
/// Both `Clone` and `Copy` are intentionally not implemented. This is to enforce
/// type safety.
#[derive(Debug, Eq, PartialEq)]
pub enum TryWait {
    /// The process is in either a stopped state or an exited state.
    Wait(Wait),

    /// The process is in a running state and thus can only be waited on.
    ///
    /// When the process is successfully waited on, it transitions to a waited
    /// state.
    Running(Running),
}

impl TryWait {
    /// Returns the PID for this attempted wait.
    pub fn pid(&self) -> Pid {
        match self {
            Self::Wait(wait) => wait.pid(),
            Self::Running(running) => running.pid(),
        }
    }

    /// Returns true if we're in a running state. Note that this may not reflect
    /// the real *current* state that we may not yet have observed.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    /// Returns true if we're in a stopped state. Note that this may not reflect
    /// the real *current* state that we may not yet have observed.
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Wait(Wait::Stopped(_, _)))
    }

    /// Assumes the process is in a stopped state. Panics if it isn't.
    pub fn assume_stopped(self) -> (Stopped, Event) {
        match self {
            Self::Wait(Wait::Stopped(stopped, event)) => (stopped, event),
            status => panic!("{:?}", InvalidState(status)),
        }
    }

    /// Assumes the process is in a running state. Panics if it isn't.
    pub fn assume_running(self) -> Running {
        match self {
            Self::Running(running) => running,
            status => panic!("{:?}", InvalidState(status)),
        }
    }

    /// Assumes the process is in an exited state. Panics if it isn't.
    pub fn assume_exited(self) -> (Pid, ExitStatus) {
        match self {
            Self::Wait(Wait::Exited(pid, exit_status)) => (pid, exit_status),
            status => panic!("{:?}", InvalidState(status)),
        }
    }
}

impl fmt::Display for TryWait {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Wait(wait) => write!(f, "{}", wait),
            Self::Running(running) => write!(f, "pid {} is running", running.pid()),
        }
    }
}

impl From<Running> for TryWait {
    fn from(status: Running) -> Self {
        Self::Running(status)
    }
}

impl From<Wait> for TryWait {
    fn from(wait: Wait) -> Self {
        Self::Wait(wait)
    }
}

/// The result of a blocking wait. A process in this state is guaranteed to not
/// be in a running state.
///
/// Both `Clone` and `Copy` are intentionally not implemented. This is to enforce
/// type safety.
#[derive(Debug, Eq, PartialEq)]
pub enum Wait {
    /// The process is in a stopped state and thus only operations that can be
    /// done during a stopped state are allowed (i.e., ptrace operations).
    ///
    /// When the process is resumed, it transitions to a running state.
    Stopped(Stopped, Event),

    /// The process has exited with an exit status.
    Exited(Pid, ExitStatus),
}

impl Wait {
    /// Returns the PID for this state.
    pub fn pid(&self) -> Pid {
        match self {
            Self::Stopped(stopped, _) => stopped.pid(),
            Self::Exited(pid, _exit_status) => *pid,
        }
    }

    /// Assumes the process is in a stopped state. Panics if it isn't.
    pub fn assume_stopped(self) -> (Stopped, Event) {
        match self {
            Self::Stopped(stopped, event) => (stopped, event),
            state => panic!("{:?}", InvalidState(state.into())),
        }
    }

    /// Assumes the process is in an exited state. Panics if it isn't.
    pub fn assume_exited(self) -> (Pid, ExitStatus) {
        match self {
            Self::Exited(pid, exit_status) => (pid, exit_status),
            state => panic!("{:?}", InvalidState(state.into())),
        }
    }

    /// Converts a raw `i32` status to this type.
    ///
    /// Preconditions:
    /// The process must not be in a running state.
    pub fn from_raw(pid: Pid, status: i32) -> Result<Self, Error> {
        let token = if libc::WIFSTOPPED(status) {
            TraceeToken::current_or_fresh(pid)
        } else {
            TraceeToken::new()
        };
        Self::from_raw_with_token(pid, status, token)
    }

    fn from_raw_with_token(pid: Pid, status: i32, token: TraceeToken) -> Result<Self, Error> {
        Ok(if libc::WIFEXITED(status) {
            Wait::Exited(pid, ExitStatus::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            let sig = Signal::try_from(libc::WTERMSIG(status)).map_err(|_| Errno::EINVAL)?;
            Wait::Exited(pid, ExitStatus::Signaled(sig, libc::WCOREDUMP(status)))
        } else if libc::WIFSTOPPED(status) {
            let task = Stopped::from_token(pid, token);

            let event = if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
                Event::Syscall
            } else if (status >> 16) == 0 {
                let sig = Signal::try_from(libc::WSTOPSIG(status)).map_err(|_| Errno::EINVAL)?;
                Event::Signal(sig)
            } else {
                let sig = Signal::try_from(libc::WSTOPSIG(status)).map_err(|_| Errno::EINVAL)?;

                let event = status >> 16;

                // PTRACE_EVENT_STOP is not guaranteed to return the correct
                // signal, so we ignore it here.
                debug_assert!(event == libc::PTRACE_EVENT_STOP || sig == Signal::SIGTRAP);

                let event = Event::from_ptrace_event(&task, event)?;
                #[cfg(all(test, feature = "notifier"))]
                if matches!(event, Event::NewChild(..)) {
                    notifier::pause_sync_new_child_decode(task.1.event());
                }
                event
            };

            Wait::Stopped(task, event)
        } else if libc::WIFCONTINUED(status) {
            // TODO: Handle continued status.
            unimplemented!("Continued status not yet handled")
        } else {
            panic!("PID {} got unexpected status: {:#x}", pid, status)
        })
    }
}

impl TryFrom<WaitStatus> for Wait {
    type Error = Error;

    /// Converts a `WaitStatus` to this type.
    ///
    /// Preconditions:
    /// The process must not be in a `StillAlive` state.
    fn try_from(wait_status: WaitStatus) -> Result<Self, Error> {
        let token = match wait_status {
            WaitStatus::Stopped(pid, _)
            | WaitStatus::PtraceEvent(pid, ..)
            | WaitStatus::PtraceSyscall(pid) => TraceeToken::current_or_fresh(pid.into()),
            _ => TraceeToken::new(),
        };
        Self::from_wait_status_with_token(wait_status, token)
    }
}

impl Wait {
    fn from_wait_status_with_token(
        wait_status: WaitStatus,
        token: TraceeToken,
    ) -> Result<Self, Error> {
        Ok(match wait_status {
            WaitStatus::Exited(pid, code) => Self::Exited(pid.into(), ExitStatus::Exited(code)),
            WaitStatus::Signaled(pid, sig, coredump) => {
                Self::Exited(pid.into(), ExitStatus::Signaled(sig, coredump))
            }
            WaitStatus::Stopped(pid, sig) => {
                let event = Event::Signal(sig);
                Self::Stopped(Stopped::from_token(pid.into(), token), event)
            }
            WaitStatus::PtraceEvent(pid, sig, event) => {
                // PTRACE_EVENT_STOP is not guaranteed to return the correct
                // signal, so we ignore it here.
                debug_assert!(event == libc::PTRACE_EVENT_STOP || sig == Signal::SIGTRAP);
                let task = Stopped::from_token(pid.into(), token);
                let event = Event::from_ptrace_event(&task, event)?;
                Self::Stopped(task, event)
            }
            WaitStatus::PtraceSyscall(pid) => {
                let event = Event::Syscall;
                Self::Stopped(Stopped::from_token(pid.into(), token), event)
            }
            WaitStatus::Continued(_pid) => {
                // Not possible because we aren't using WaitPidFlag::WCONTINUED
                // anywhere.
                unreachable!("unexpected WaitStatus::Continued");
            }
            WaitStatus::StillAlive => {
                // The precondition of this function forbids this.
                unreachable!("precondition violated with WaitStatus::StillAlive");
            }
        })
    }
}

impl fmt::Display for Wait {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Stopped(stopped, event) => {
                write!(f, "pid {} stopped ({:?})", stopped.pid(), event)
            }
            Self::Exited(pid, exit_status) => write!(f, "pid {} exited ({:?})", pid, exit_status),
        }
    }
}

// libc crate doesn't provide this struct
#[repr(C)]
struct ptrace_peeksiginfo_args {
    off: u64,
    flags: u32,
    nr: u32,
}

bitflags::bitflags! {
    /// Flags for ptrace peeksiginfo
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct PeekSigInfoFlags: u32 {
        /// dumping signals from the process-wide signal queue. signals are
        /// read from the per-thread queue of the specified thread if this
        /// flag is not set.
        const SHARED = 1;
    }
}

/// The tracee generation a [`Stopped`] capability is bound to. It grants no
/// ptrace operation by itself.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct TraceeGeneration(Pid, TraceeToken);

impl TraceeGeneration {
    /// Returns the process ID of the tracee.
    pub fn pid(&self) -> Pid {
        self.0
    }

    /// Creates a stopped state for this generation. Like
    /// [`Stopped::new_unchecked`], the caller must independently know that the
    /// tracee is stopped. Unlike it, with the `notifier` feature and once this
    /// generation's identity has been captured, requests through the result
    /// are refused once the notifier or [`Running::wait`] reaps this
    /// generation, even if another task has reused the TID. Without that
    /// feature, or for a generation whose identity could not be captured,
    /// requests go to the numeric TID unchecked. A reap through [`wait_all`],
    /// [`try_wait_all`] or [`wait_group`], and the registration orders in
    /// <https://github.com/rrnewton/reverie/issues/860>, do not refuse them yet.
    pub fn assume_stopped(&self) -> Stopped {
        Stopped::from_token(self.0, self.1.clone())
    }
}

/// A process that is in a stopped state and allows ptrace operations to be
/// performed.
#[derive(Hash, Eq, PartialEq)]
pub struct Stopped(Pid, TraceeToken, ExitStopMark);

impl fmt::Debug for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Stopped")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

/// Marks the one [`Stopped`] minted by an exit future for a published
/// `PTRACE_EVENT_EXIT` stop, with the exit epoch that publication belongs to.
/// It is not part of the value's identity: equality and hashing ignore it.
#[derive(Clone, Copy, Default)]
#[cfg_attr(not(feature = "notifier"), allow(dead_code))]
struct ExitStopMark(Option<usize>);

impl PartialEq for ExitStopMark {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ExitStopMark {}

impl std::hash::Hash for ExitStopMark {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}

impl Stopped {
    /// Helper for converting from the Errno type.
    ///
    /// # Why is this needed?
    ///
    /// According to ptrace(2), any ptrace operation may return ESRCH
    /// ("No such process") for one of three reasons:
    ///  1. The process was observed to be in a stopped state and died
    ///     unexpectedly.
    ///  2. The process is not currently being traced by the caller.
    ///  3. The process is not in a stopped state.
    ///
    /// Since we know that reasons (2) and (3) only occur due to
    /// programmer errors that this API is designed to prevent, we can
    /// safely assume that this ESRCH means the tracee has died
    /// unexpectedly while in a stopped state.
    ///
    /// For more information, please see the "Death under ptrace" section
    /// in `man 2 ptrace`.
    ///
    /// On the capability for a published exit stop, ESRCH also retires the
    /// statuses queued before that exit stop (see
    /// [`Stopped::retire_statuses_before_exit_stop`]). That relies on the
    /// same assumption as the mapping to `Died` above: every ptrace request
    /// for this tracee comes from its one tracer thread, so reason (2), which
    /// the kernel also reports to a thread that is not the tracer, does not
    /// apply. The kernel also returns ESRCH when it cannot freeze the stop
    /// because a fatal signal is pending; the tracee is then being killed out
    /// of the exit stop, so the queued stops ahead of it are still dead.
    fn map_err(&self, err: Errno) -> Error {
        if err == Errno::ESRCH {
            self.retire_statuses_before_exit_stop();
            Error::Died(Zombie::from_token(self.0, self.1.clone()))
        } else {
            Error::Errno(err)
        }
    }

    /// Returns a future that is notified when the next exit stop occurs. This
    /// is received asynchronously regardless of what the process was doing at
    /// the time. This is useful for canceling futures when a process enters a
    /// `PTRACE_EVENT_EXIT` (such as when one thread calls `exit_group` and
    /// causes all other threads to suddenly exit).
    ///
    /// Exactly one future for this immutable tracee generation can claim the
    /// exit stop and return a [`Stopped`] capability. Duplicate or re-polled
    /// futures return [`Errno::EALREADY`]. An unclaimed capability also expires
    /// before terminal publication or cancellation cleanup advances the
    /// tracee.
    #[cfg(feature = "notifier")]
    pub fn exit_event(&self) -> notifier::ExitFuture {
        notifier::ExitFuture::new(self.0, &self.1)
    }

    /// Returns a generation-bound terminal cleanup acknowledgment.
    ///
    /// This is primarily useful with [`Stopped::new_unchecked`] during
    /// cancellation after the caller has independently validated that the TID
    /// still names the expected ptrace generation.
    #[cfg(feature = "notifier")]
    pub fn terminal_cleanup(&self) -> TerminalCleanup {
        TerminalCleanup::new(self.0, &self.1)
    }

    /// Retain a read-only observer for this actual token and its current exec epoch.
    /// It cannot resume, wait, or mint another owning capability, and makes no
    /// new PID/proc capture. Use it only while the original current stop remains
    /// under this caller's execution-control ownership.
    #[cfg(feature = "notifier")]
    pub fn observation(&self) -> StoppedObservation {
        StoppedObservation::new(self.0, &self.1)
    }

    /// Creates a new stopped state. This is useful when we know the process is
    /// in a stopped state already.
    ///
    /// Using this method is unsound because there is no check to verify that the
    /// pid really is in a stopped state. It is better to arrive at a stopped
    /// state via other methods such as `Running::wait`.
    pub fn new_unchecked(pid: Pid) -> Self {
        Self::from_token(pid, TraceeToken::current_or_error(pid))
    }

    /// Creates an unchecked stopped state joined to the currently registered
    /// proc generation for `pid`.
    ///
    /// Like [`Stopped::new_unchecked`], the caller must independently prove
    /// that the exact TID is stopped. Unlike that constructor, generation
    /// capture/read failures are returned rather than creating an unbound
    /// notifier state.
    #[cfg(feature = "notifier")]
    pub fn try_new_current_unchecked(pid: Pid) -> Result<Self, Errno> {
        Ok(Self::from_token(pid, TraceeToken::current_or_new(pid)?))
    }

    fn from_token(pid: Pid, token: TraceeToken) -> Self {
        Self(pid, token, ExitStopMark(None))
    }

    /// The capability for the `PTRACE_EVENT_EXIT` stop published in exit
    /// `epoch`. See [`Stopped::retire_statuses_before_exit_stop`] for when the
    /// statuses queued before that exit stop are retired.
    #[cfg(feature = "notifier")]
    fn from_exit_token(pid: Pid, token: TraceeToken, epoch: usize) -> Self {
        Self(pid, token, ExitStopMark(Some(epoch)))
    }

    /// On the capability for a published exit stop, retires the statuses the
    /// notifier queued before that exit stop. The tracee had already left
    /// each of those stops when it entered the exit stop, so none of them
    /// names a stop it can still be in.
    ///
    /// This runs on every terminal disposition of the capability: a ptrace
    /// request that moves the tracee out of the exit stop, and an ESRCH from
    /// any request on it (resume, step, GETEVENTMSG, ...), which means the
    /// tracee is no longer in the exit stop. Statuses queued after the exit
    /// stop, such as the Exec or the terminal wait status, are never removed.
    /// A mark from an earlier exit epoch retires nothing, so a stale
    /// capability cannot remove the prefix of a later exit stop. Does nothing
    /// on any other capability.
    fn retire_statuses_before_exit_stop(&self) {
        #[cfg(feature = "notifier")]
        if let Some(epoch) = self.2.0 {
            self.1.event().retire_statuses_before_exit_stop(epoch);
        }
    }

    /// On the capability for a published exit stop, refuses the stop when a
    /// fork, vfork or clone stop was queued before it.
    ///
    /// Such a stop names a live child only through its event message. The
    /// tracee left it for the exit stop, whose message (the exit status) has
    /// replaced the child's PID: decoding it now would read the exit status
    /// as a PID, and once this exit stop is resumed the read fails with
    /// ESRCH and the child is never captured. The refusal names the queued
    /// status instead. This makes no ptrace request and changes no queue; a
    /// prefix holding such a stop is also never retired (see
    /// [`Stopped::retire_statuses_before_exit_stop`]). Always succeeds on any
    /// other capability.
    #[cfg(feature = "notifier")]
    pub fn superseded_new_child(&self) -> Result<(), SupersededStopRefusal> {
        match self.2.0 {
            Some(epoch) => self.1.event().superseded_new_child(epoch),
            None => Ok(()),
        }
    }

    /// Converts this capability into the running state after a successful
    /// ptrace request moved the tracee out of its stop.
    fn into_running(self) -> Running {
        self.retire_statuses_before_exit_stop();
        Running::from_token(self.0, self.1)
    }

    /// Returns the generation this capability is bound to, so a caller that
    /// later rebuilds an unchecked capability for this tracee keeps the
    /// generation's TID gate instead of joining whatever task holds the TID
    /// by then.
    pub fn generation(&self) -> TraceeGeneration {
        TraceeGeneration(self.0, self.1.clone())
    }

    /// Returns the process ID of the tracee.
    pub fn pid(&self) -> Pid {
        self.0
    }

    /// Sets the ptracer options.
    pub fn setoptions(&self, options: ptrace::Options) -> Result<(), Error> {
        self.1
            .on_held_tid(|| ptrace::setoptions(self.0.into(), options).map_err(nix_errno))
            .map_err(|err| self.map_err(err))
    }

    /// Gets a set of registers.
    ///
    /// `which` corresponds to one of:
    ///  * `libc::NT_PRSTATUS` for the general registers.
    ///  * `libc::NT_PRFPREG` for the floating point registers.
    ///
    /// There are others, but we don't use them.
    fn getregset<T>(&self, which: i32) -> Result<T, Error> {
        let mut regs = MaybeUninit::<T>::uninit();

        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: core::mem::size_of_val(&regs),
        };

        self.1
            .on_held_tid(|| unsafe {
                syscalls::syscall!(
                    Sysno::ptrace,
                    // PTRACE_GETREGS isn't available on aarch64, so we must use
                    // PTRACE_GETREGSET instead.
                    libc::PTRACE_GETREGSET,
                    self.0.as_raw(),
                    which,
                    &mut iov as *mut _
                )
            })
            .map_err(|err| self.map_err(err))?;

        // PTRACE_GETREGSET modifies the length to the real length of the
        // registers, but we should already know the exact number of registers
        // for this architecture.
        debug_assert_eq!(iov.iov_len, core::mem::size_of_val(&regs));

        Ok(unsafe { regs.assume_init() })
    }

    fn setregset<T>(&self, which: i32, regs: &T) -> Result<(), Error> {
        let iov = libc::iovec {
            iov_base: regs as *const _ as *mut _,
            iov_len: core::mem::size_of::<T>(),
        };

        self.1
            .on_held_tid(|| unsafe {
                syscalls::syscall!(
                    Sysno::ptrace,
                    // PTRACE_SETREGS isn't available on aarch64, so we must use
                    // PTRACE_SETREGSET instead.
                    libc::PTRACE_SETREGSET,
                    self.0.as_raw(),
                    which,
                    &iov as *const _
                )
            })
            .map_err(|err| self.map_err(err))?;

        Ok(())
    }

    /// Gets the current state of the general purpose registers.
    pub fn getregs(&self) -> Result<Regs, Error> {
        self.getregset(libc::NT_PRSTATUS)
    }

    /// Sets the general purpose registers.
    pub fn setregs(&self, regs: &Regs) -> Result<(), Error> {
        self.setregset(libc::NT_PRSTATUS, regs)
    }

    /// Gets the floating point registers.
    pub fn getfpregs(&self) -> Result<FpRegs, Error> {
        self.getregset(libc::NT_PRFPREG)
    }

    /// Sets the floating point registers.
    pub fn setfpregs(&self, regs: &FpRegs) -> Result<(), Error> {
        self.setregset(libc::NT_PRFPREG, regs)
    }

    /// Gets the complete variable-length x86 XSAVE state for the tracee.
    // TODO-HUMAN-REVIEW(PR-270): Review complete ptrace XSTATE preservation API.
    #[cfg(target_arch = "x86_64")]
    pub fn getxstate(&self) -> Result<XState, Error> {
        // CPUID.(EAX=0xD,ECX=0):ECX reports the maximum XSAVE area for all
        // processor-supported user components. The kernel returns the exact
        // active regset length through iov_len.
        let maximum = core::arch::x86_64::__cpuid_count(0x0d, 0).ecx as usize;
        let mut bytes = vec![0_u8; maximum.max(4096)];
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        self.1
            .on_held_tid(|| unsafe {
                syscalls::syscall!(
                    Sysno::ptrace,
                    libc::PTRACE_GETREGSET,
                    self.0.as_raw(),
                    NT_X86_XSTATE,
                    &mut iov as *mut _
                )
            })
            .map_err(|err| self.map_err(err))?;
        if iov.iov_len > bytes.len() {
            return Err(Error::Errno(Errno::EOVERFLOW));
        }
        bytes.truncate(iov.iov_len);
        Ok(XState(bytes))
    }

    /// Restores a complete x86 XSAVE state previously returned by
    /// [`Stopped::getxstate`].
    // TODO-HUMAN-REVIEW(PR-270): Review complete ptrace XSTATE preservation API.
    #[cfg(target_arch = "x86_64")]
    pub fn setxstate(&self, state: &XState) -> Result<(), Error> {
        let iov = libc::iovec {
            iov_base: state.0.as_ptr() as *mut libc::c_void,
            iov_len: state.0.len(),
        };
        self.1
            .on_held_tid(|| unsafe {
                syscalls::syscall!(
                    Sysno::ptrace,
                    libc::PTRACE_SETREGSET,
                    self.0.as_raw(),
                    NT_X86_XSTATE,
                    &iov as *const _
                )
            })
            .map_err(|err| self.map_err(err))?;
        Ok(())
    }

    /// Resumes the process and transitions it back to a running state.
    pub fn resume<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        self.1
            .on_held_tid(|| ptrace::cont(self.0.into(), sig).map_err(nix_errno))
            .map_err(|err| self.map_err(err))?;
        Ok(self.into_running())
    }

    /// Attempts to resume while retaining the original capability on error.
    ///
    /// The error arm returns the same generation-bound value, not a new value
    /// constructed from its numeric PID. This retains ownership; it does not
    /// guarantee that the kernel state is unchanged after every ptrace error.
    /// The refusal is a non-owning errno, including ESRCH: no second Zombie
    /// capability escapes beside the retained Stopped. An errno alone does not
    /// acknowledge terminal status or guarantee the same physical kernel stop.
    /// Callers must use their original event owner before another transition.
    pub fn resume_retaining<T: Into<Option<Signal>>>(
        self,
        sig: T,
    ) -> Result<Running, (Self, Errno)> {
        let result = self
            .1
            .on_held_tid(|| ptrace::cont(self.0.into(), sig).map_err(nix_errno));
        self.finish_retained_resume(result)
    }

    /// Transfers the original capability into a retained notifier wait.
    ///
    /// This performs no resume and constructs no replacement running or stopped
    /// value. Use it when an external lifecycle transition may have superseded
    /// this stop, such as an actual ESRCH from [`Stopped::resume_retaining`].
    /// The error is not an exit acknowledgement: only this same generation's
    /// actual next event settles the wait. If the task remains stopped, this
    /// future can remain pending; the caller must retain its ownership and
    /// arrange any necessary termination through its existing supervisor.
    /// Registration/decoding refusals obey [`Running::wait_owned`]'s retry
    /// contract and never return a second owning capability.
    #[cfg(feature = "notifier")]
    pub fn wait_owned(self) -> notifier::OwnedWaitFuture {
        notifier::OwnedWaitFuture::from_stopped(self)
    }

    pub(crate) fn finish_retained_resume(
        self,
        result: Result<(), Errno>,
    ) -> Result<Running, (Self, Errno)> {
        match result {
            Ok(()) => Ok(self.into_running()),
            Err(error) => {
                if error == Errno::ESRCH {
                    // The retained value keeps its ownership role, but the
                    // tracee has left the exit stop this capability names.
                    self.retire_statuses_before_exit_stop();
                }
                Err((self, error))
            }
        }
    }

    /// Advances the execution of the process by a single step optionally
    /// delivering a signal specified by `sig`.
    pub fn step<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        self.1
            .on_held_tid(|| ptrace::step(self.0.into(), sig).map_err(nix_errno))
            .map_err(|err| self.map_err(err))?;
        Ok(self.into_running())
    }

    /// Like `step`, but arranges for the tracee to be stopped at the next
    /// entry to or exit from a system call.
    pub fn syscall<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        self.1
            .on_held_tid(|| ptrace::syscall(self.0.into(), sig).map_err(nix_errno))
            .map_err(|err| self.map_err(err))?;
        Ok(self.into_running())
    }

    /// Sets the syscall to be executed. Only available on `aarch64`.
    ///
    /// Normally, on x86_64, the register `orig_rax` should be set instead to
    /// modify the syscall number, which typically involves 3 ptrace calls:
    ///  1. getregs to get the current registers.
    ///  2. setregs to change `orig_rax` to set the syscall number.
    ///  3. setregs again to restore the original registers after the syscall
    ///     has been executed.
    ///
    /// `set_syscall` on `aarch64` has the advantage of only requiring a single
    /// ptrace call.
    #[cfg(target_arch = "aarch64")]
    pub fn set_syscall(&self, nr: i32) -> Result<(), Error> {
        const NT_ARM_SYSTEM_CALL: i32 = 0x404;
        self.setregset(NT_ARM_SYSTEM_CALL, &nr)
    }

    /// Gets info about the signal that caused the process to be stopped.
    pub fn getsiginfo(&self) -> Result<libc::siginfo_t, Error> {
        self.1
            .on_held_tid(|| ptrace::getsiginfo(self.0.into()).map_err(nix_errno))
            .map_err(|err| self.map_err(err))
    }

    /// Returns [`Error::Died`] if this tracee has left the stop this
    /// capability names and is now in its `PTRACE_EVENT_EXIT` stop, or if
    /// the probe itself reports its death. Returns `None` otherwise.
    ///
    /// A fatal signal takes a tracee out of any ptrace stop without a tracer
    /// request. A request made while the tracee is on its way to its exit
    /// stop fails with `ESRCH`, because the tracee is not in a stop. Once it
    /// is in its exit stop, requests succeed again, so an ordinary probe made
    /// after that `ESRCH` sees a stopped, apparently live tracee.
    /// `PTRACE_GETSIGINFO` tells the two apart: in the exit stop, `si_code`
    /// is `SIGTRAP | (PTRACE_EVENT_EXIT << 8)`.
    ///
    /// Call this only on the capability for a stop other than the exit stop,
    /// after a request on it failed with `ESRCH`. Holding such a stop, the
    /// tracer has not resumed the tracee, so a tracee found in its exit stop
    /// was taken there by a fatal signal and the held stop is dead.
    pub fn died_into_exit_stop(&self) -> Option<Error> {
        match self.getsiginfo() {
            Ok(siginfo)
                if siginfo.si_signo == libc::SIGTRAP
                    && siginfo.si_code == libc::SIGTRAP | (libc::PTRACE_EVENT_EXIT << 8) =>
            {
                Some(self.map_err(Errno::ESRCH))
            }
            Err(died @ Error::Died(_)) => Some(died),
            _ => None,
        }
    }

    /// Sets info about the singal that caused the process to be stopped.
    pub fn setsiginfo(&self, siginfo: &libc::siginfo_t) -> Result<(), Error> {
        self.1
            .on_held_tid(|| ptrace::setsiginfo(self.0.into(), siginfo).map_err(nix_errno))
            .map_err(|err| self.map_err(err))
    }

    /// Gets the tracee's blocked signal mask (`PTRACE_GETSIGMASK`). Bit `n - 1`
    /// is set when signal `n` is blocked.
    pub fn getsigmask(&self) -> Result<u64, Error> {
        let mut mask: u64 = 0;
        self.1
            .on_held_tid(|| {
                Errno::result(unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETSIGMASK,
                        self.0.as_raw(),
                        core::mem::size_of::<u64>(),
                        &mut mask as *mut u64,
                    )
                })
            })
            .map_err(|err| self.map_err(err))?;
        Ok(mask)
    }

    /// Sets the tracee's blocked signal mask (`PTRACE_SETSIGMASK`). The kernel
    /// ignores the `SIGKILL` and `SIGSTOP` bits. Like any ptrace mask write, it
    /// also clears the tracee's pending restore of a mask saved by a
    /// mask-swapping syscall such as `ppoll` or `rt_sigsuspend`.
    pub fn setsigmask(&self, mask: u64) -> Result<(), Error> {
        self.1
            .on_held_tid(|| {
                Errno::result(unsafe {
                    libc::ptrace(
                        libc::PTRACE_SETSIGMASK,
                        self.0.as_raw(),
                        core::mem::size_of::<u64>(),
                        &mask as *const u64,
                    )
                })
            })
            .map_err(|err| self.map_err(err))?;
        Ok(())
    }

    /// Like `getsiginfo`, but do not remove the signal info from an internal
    /// queue.
    pub fn peeksiginfo<T: Into<Option<PeekSigInfoFlags>>>(
        &self,
        flags: T,
    ) -> Result<Vec<libc::siginfo_t>, Error> {
        const SIGNAL_MAX: usize = 8 * core::mem::size_of::<u64>();
        let mut data = MaybeUninit::<[libc::siginfo_t; SIGNAL_MAX]>::zeroed();
        let mut siginfo_args = ptrace_peeksiginfo_args {
            off: 0,
            flags: flags.into().map_or(0, |x| x.bits()),
            nr: SIGNAL_MAX as u32,
        };
        let count = self
            .1
            .on_held_tid(|| {
                Errno::result(unsafe {
                    libc::ptrace(
                        libc::PTRACE_PEEKSIGINFO,
                        self.0.as_raw(),
                        &mut siginfo_args as *mut _,
                        data.as_mut_ptr() as *const _ as *const libc::c_void,
                    )
                })
            })
            .map_err(|err| self.map_err(err))?;
        Ok(unsafe { data.assume_init() }[0..count as usize].to_vec())
    }

    /// Like `peeksiginfo`, but returns the whole queue rather than at most its
    /// first 64 entries.
    ///
    /// The kernel copies at least one entry per call if one exists at the
    /// offset, may stop early when the tracer has a signal pending, and
    /// returns 0 only past the end of the queue, so this reads until it gets 0.
    /// Real-time signals queue one entry each, so a queue can exceed 64 entries.
    pub fn peeksiginfo_all<T: Into<Option<PeekSigInfoFlags>>>(
        &self,
        flags: T,
    ) -> Result<Vec<libc::siginfo_t>, Error> {
        const CHUNK: usize = 64;
        let flags = flags.into().map_or(0, |x| x.bits());
        let mut data = MaybeUninit::<[libc::siginfo_t; CHUNK]>::zeroed();
        let mut all = Vec::new();
        loop {
            let mut siginfo_args = ptrace_peeksiginfo_args {
                off: all.len() as u64,
                flags,
                nr: CHUNK as u32,
            };
            let count = self
                .1
                .on_held_tid(|| {
                    Errno::result(unsafe {
                        libc::ptrace(
                            libc::PTRACE_PEEKSIGINFO,
                            self.0.as_raw(),
                            &mut siginfo_args as *mut _,
                            data.as_mut_ptr() as *const _ as *const libc::c_void,
                        )
                    })
                })
                .map_err(|err| self.map_err(err))? as usize;
            if count == 0 {
                return Ok(all);
            }
            // SAFETY: zero-initialized, and the kernel wrote the first `count`.
            all.extend_from_slice(&unsafe { data.assume_init_ref() }[..count]);
        }
    }

    /// Retrieve a message about the ptrace event that just happened.
    ///
    /// It shouldn't be necessary to call this in most cases because `Event`
    /// provides the necessary context for certain ptrace events.
    pub fn getevent(&self) -> Result<i64, Error> {
        self.1
            .on_held_tid(|| ptrace::getevent(self.0.into()).map_err(nix_errno))
            .map_err(|err| self.map_err(err))
    }

    /// Detaches from and then resumes the stopped tracee.
    pub fn detach<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        self.1
            .on_held_tid(|| ptrace::detach(self.0.into(), sig).map_err(nix_errno))
            .map_err(|err| self.map_err(err))?;
        Ok(self.into_running())
    }
}

/// Waits for any child processes to change state, blocking until the next event.
/// This is equivalent to `waitpid(-1)`.
///
/// Reaping a child here does not close its capabilities' TID gates, so a
/// gate that nothing else closed lets them reach a task that reuses its TID
/// (<https://github.com/rrnewton/reverie/issues/860>).
pub fn wait_all() -> Result<Option<Wait>, Error> {
    let result = wait(IdType::All, WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED)
        .map_err(Error::from)
        .and_then(|status| {
            // Unwrap is OK because the process cannot be left in a running
            // state without WNOHANG.
            Wait::try_from(status.unwrap())
        });

    match result {
        Ok(state) => Ok(Some(state)),
        Err(Error::Errno(Errno::ECHILD)) => {
            // waitpid(-1) only returns ECHILD when there are no more children
            // to wait for. Returning `None` here makes it easy to write a while
            // loop that terminates when there are no more children left.
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Like `wait_all`, but immediately returns `Ok(None)` if no state transition
/// will occur.
///
/// This is the non-blocking version of `wait_all`.
pub fn try_wait_all() -> Result<Option<Wait>, Error> {
    wait(
        IdType::All,
        WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED | WaitPidFlag::WNOHANG,
    )?
    .map(Wait::try_from)
    .transpose()
}

/// Waits for any child in a process group to change state, blocking until the
/// next event.
///
/// Reaping a child here does not close its capabilities' TID gates, so a
/// gate that nothing else closed lets them reach a task that reuses its TID
/// (<https://github.com/rrnewton/reverie/issues/860>).
pub fn wait_group(pid: Pid) -> Result<Option<Wait>, Error> {
    let result = wait(
        IdType::Pgid(pid.into()),
        WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED,
    )
    .map_err(Error::from)
    .and_then(|status| {
        // Unwrap is OK because the process cannot be left in a running
        // state without WNOHANG.
        Wait::try_from(status.unwrap())
    });

    match result {
        Ok(state) => Ok(Some(state)),
        Err(Error::Errno(Errno::ECHILD)) => {
            // This only returns ECHILD when there are no more children to wait
            // for. Returning `None` here makes it easy to write a while loop
            // that terminates when there are no more children left.
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Blocks until a state change is ready to consume, but does not consume it.
/// Returns the pid that has the pending state change. Returns `Ok(None)` if
/// there are no child processes to wait on.
///
/// This is useful for deciding which processes to consume events for.
///
/// # Examples
///
/// ```ignore
/// while let Some(process) = peek_all()? {
///     match process.wait()? {
///         Wait::Stopped(tracee, _event) => {
///             tracee.resume(None)?;
///         }
///         Wait::Exited(pid, exit_status) => {
///             println!("pid {} exited ({})", pid, exit_status);
///         }
///     }
/// }
/// ```
pub fn peek_all() -> Result<Option<Running>, Errno> {
    let result = wait(
        IdType::All,
        WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED | WaitPidFlag::WNOWAIT,
    )
    .map(|state| {
        // Unwrap is OK because the process cannot be in a running state without
        // WNOHANG.
        state.unwrap()
    });

    match result {
        Ok(status) => Ok(status.pid().map(|pid| Running::new(pid.into()))),
        Err(Errno::ECHILD) => {
            // waitpid(-1) only returns ECHILD when there are no more children
            // to wait for. Returning `None` here makes it easy to write a while
            // loop that terminates when there are no more children left.
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Returns a process that is ready to change state. If there are no child
/// processes ready to change, returns immediately.
///
/// This is the non-blocking version of `peek_all`.
pub fn try_peek_all() -> Result<Option<Running>, Errno> {
    let next = wait(
        IdType::All,
        WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
    )?;

    Ok(next.and_then(|state| state.pid().map(|pid| Running::new(pid.into()))))
}

/// A running child.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Running(Pid, TraceeToken);

impl Running {
    /// Creates a new running process. This is generally the entry point for a
    /// new process as soon as it is created.
    ///
    /// The state shares the generation that other states for the same live
    /// task already carry. With the `notifier` feature, once that
    /// generation's identity has been captured, a numeric request through any
    /// of them stops reaching the TID once the notifier or [`Running::wait`]
    /// reaps that task, except in the orders listed in
    /// <https://github.com/rrnewton/reverie/issues/860>. If the identity
    /// cannot be captured, the state gets a fresh generation that no reap
    /// gates.
    pub fn new(pid: Pid) -> Self {
        Self::from_token(pid, TraceeToken::current_or_fresh(pid))
    }

    fn from_token(pid: Pid, token: TraceeToken) -> Self {
        Self(pid, token)
    }

    fn from_current_or_new(pid: Pid) -> Result<Self, Errno> {
        Ok(Self::from_token(pid, TraceeToken::current_or_new(pid)?))
    }

    /// Attaches to a running process. The process becomes a tracee and a SIGSTOP
    /// is sent to it. By the time this function ends, the tracee may not yet
    /// have actually stopped. Thus, the tracee is still considered to be in a
    /// running state and needs to be waited upon to observe the SIGSTOP.
    pub fn attach(pid: Pid) -> Result<Self, Errno> {
        ptrace::attach(pid.into()).map_err(|err| Errno::new(err as i32))?;
        Ok(Self::new(pid))
    }

    /// Similar to attach, but does not stop the process. This also affects the
    /// events that are later delivered. Upon clone, fork, or vfork, an
    /// `Event::Stop` is delivered instead of `Event::Signal(Signal::SIGSTOP)`.
    ///
    /// Unlike other modes, a seized process can also accept interrupts.
    pub fn seize(pid: Pid, options: Options) -> Result<Self, Errno> {
        ptrace::seize(pid.into(), options).map_err(|err| Errno::new(err as i32))?;
        Ok(Self::new(pid))
    }

    /// Interrupts the running process, even if it is in the middle of a syscall.
    /// The next time the process is waited on, the process transitions to a
    /// stopped state and `Event::Stop` is returned.
    ///
    /// # Limitations
    ///
    /// This only works for processes being traced via `Running::seize`.
    pub fn interrupt(&self) -> Result<(), Errno> {
        // nix doesn't provide `ptrace::interrupt` yet, so we need to roll our
        // own.
        self.1.on_held_tid(|| {
            Errno::result(unsafe {
                libc::ptrace(
                    libc::PTRACE_INTERRUPT,
                    self.0.as_raw(),
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                )
            })
            .map(drop)
        })
    }

    /// Returns the pid of the running process.
    pub fn pid(&self) -> Pid {
        self.0
    }

    /// Blocks until a state change occurs. This may transition the process to
    /// either a stopped state or exited state, but never a running state.
    pub fn wait(self) -> Result<Wait, Error> {
        let pid = self.0;
        let token = self.1;
        #[cfg(feature = "notifier")]
        {
            notifier::wait_sync(pid, token)
        }
        #[cfg(not(feature = "notifier"))]
        {
            wait(
                IdType::Pid(pid.into()),
                WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED,
            )
            .map_err(Error::from)
            .and_then(|status| {
                // Unwrap is OK because the process cannot be in a running state without
                // WNOHANG.
                Wait::from_wait_status_with_token(status.unwrap(), token)
            })
        }
    }

    /// Like `wait`, but filters out events we don't care about by resuming the
    /// tracee when encountering them. This is useful for skipping past spurious
    /// events until a point we know the tracee must stop.
    #[cfg(feature = "notifier")]
    pub async fn wait_until<F>(mut self, mut pred: F) -> Result<Wait, Error>
    where
        F: FnMut(&Event) -> bool,
    {
        loop {
            match self.next_state().await? {
                Wait::Stopped(stopped, event) => {
                    if pred(&event) {
                        break Ok(Wait::Stopped(stopped, event));
                    } else if let Event::Signal(sig) = event {
                        self = stopped.resume(Some(sig))?;
                    } else {
                        self = stopped.resume(None)?;
                    }
                }
                task => break Ok(task),
            }
        }
    }

    /// Waits until we receive a specific stop signal. Useful for skipping past
    /// spurious signals.
    #[cfg(feature = "notifier")]
    pub async fn wait_for_signal(self, sig: Signal) -> Result<Wait, Error> {
        self.wait_until(|event| event == &Event::Signal(sig)).await
    }

    /// Waits for the next exit stop to occur. This is received asynchronously
    /// regardless of what the process was doing at the time. This is useful for
    /// canceling futures when a process enters a `PTRACE_EVENT_EXIT` (such as
    /// when one thread calls `exit_group` and causes all other threads to
    /// suddenly exit).
    ///
    /// Exactly one future for this immutable tracee generation can claim the
    /// exit stop and return a [`Stopped`] capability. Duplicate or re-polled
    /// futures return [`Errno::EALREADY`]. An unclaimed capability also expires
    /// before terminal publication or cancellation cleanup advances the
    /// tracee.
    #[cfg(feature = "notifier")]
    pub fn exit_event(&self) -> notifier::ExitFuture {
        notifier::ExitFuture::new(self.0, &self.1)
    }

    /// Registers this process with the async notifier and returns a bounded
    /// synchronous acknowledgment handle for terminal cleanup.
    #[cfg(feature = "notifier")]
    pub fn terminal_cleanup(&self) -> TerminalCleanup {
        TerminalCleanup::new(self.0, &self.1)
    }

    /// Transfers this generation into an owned notifier wait.
    ///
    /// Unlike the convenience async wrapper, this future retains its original
    /// generation after a returned error. It may be polled again after the
    /// caller has handled a registration or status-decoding refusal. An error
    /// does not prove exit. Its [`OwnedWaitError`] contains no second owning
    /// Zombie. After a successful state return this future releases its old
    /// owner and every subsequent poll returns `OwnedWaitError::Completed`.
    #[cfg(feature = "notifier")]
    pub fn wait_owned(self) -> notifier::OwnedWaitFuture {
        notifier::OwnedWaitFuture::new(self)
    }

    /// Like `wait`, but wait asynchronously for the next state change.
    ///
    /// NOTE: This call should not be mixed with [`Running::wait`]!! Once
    /// [`Running::next_state`] is called once, [`Running::wait`] should never
    /// be called again for that PID. This is because a notifier thread takes
    /// over and calls `wait` in a continuous loop.
    #[cfg(feature = "notifier")]
    pub async fn next_state(self) -> Result<Wait, Error> {
        notifier::WaitFuture::new(self).await
    }
}

/// A process that is no longer running, but hasn't yet fully exited. The only
/// thing zombie can do is exit.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Zombie(Running);

impl Zombie {
    /// Creates a new instance.
    fn from_token(pid: Pid, token: TraceeToken) -> Self {
        Zombie(Running::from_token(pid, token))
    }

    /// Returns the PID of the zombie.
    pub fn pid(&self) -> Pid {
        self.0.pid()
    }

    /// Transfers the original generation into a retained notifier wait.
    ///
    /// The same retry contract as [`Running::wait_owned`] applies. A subsequent
    /// stop still requires its actual stopped capability to be continued; this
    /// method does not manufacture or acknowledge terminal status.
    #[cfg(feature = "notifier")]
    pub fn wait_owned(self) -> notifier::OwnedWaitFuture {
        self.0.wait_owned()
    }

    /// Reaps the zombie by waiting for it to fully exit.
    #[cfg(feature = "notifier")]
    pub async fn reap(self) -> Result<ExitStatus, Error> {
        // The tracee may not be fully dead yet. It is still possible for it to
        // still enter an `Event::Exit` state by waiting on it. For more info,
        // see the "BUGS" section in `man 2 ptrace`.
        let mut next_state = self.0.next_state().await;

        loop {
            match next_state {
                Ok(wait) => match wait {
                    Wait::Stopped(stopped, event) => {
                        if let Event::Exit = event {
                            next_state = match stopped.resume(None) {
                                Ok(task) => task.next_state().await,
                                Err(err) => Err(err),
                            };
                        } else {
                            panic!("Task {:?} unexpected stop event {:?}", stopped, event)
                        }
                    }
                    Wait::Exited(_pid, exit_status) => break Ok(exit_status),
                },
                Err(Error::Died(zombie)) => next_state = zombie.0.next_state().await,
                Err(error) => break Err(error),
            }
        }
    }
}

impl fmt::Display for Zombie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.pid())
    }
}

/// Sets up this process to be traced by its parent and raises a SIGSTOP.
pub fn traceme_and_stop() -> Result<(), Errno> {
    ptrace::traceme()
        .and_then(|()| nix::sys::signal::raise(Signal::SIGSTOP))
        .map_err(|e| Errno::new(e as i32))?;
    Ok(())
}

/// These tests are meant to test this API but also to show how ptrace works.
#[cfg(test)]
mod test {
    use std::io;
    use std::os::fd::BorrowedFd;
    use std::thread;

    use nix::sys::signal;
    use nix::sys::signal::Signal;
    use nix::unistd::ForkResult;
    use nix::unistd::fork;
    // Make sure tokio is referenced in all configurations.
    use tokio as _;

    use super::*;

    // Traces a closure in a forked process. The forked process starts in a
    // stopped state so that ptrace options may be set.
    fn trace<F>(f: F, options: Options) -> Result<(Pid, Stopped), Error>
    where
        F: FnOnce() -> i32,
    {
        match unsafe { fork() }? {
            ForkResult::Parent { child, .. } => {
                let mut running = Running::seize(child.into(), options)?;

                // Keep consuming events until we reach a SIGSTOP or group stop.
                let stopped = loop {
                    match running.wait()? {
                        Wait::Stopped(stopped, event) => {
                            if event == Event::Signal(Signal::SIGSTOP) || event == Event::Stop {
                                break stopped;
                            } else if let Event::Signal(sig) = event {
                                running = stopped.resume(Some(sig))?;
                            } else {
                                running = stopped.resume(None)?;
                            }
                        }
                        task => panic!("Got unexpected exit: {:?}", task),
                    }
                };

                Ok((stopped.pid(), stopped))
            }
            ForkResult::Child => {
                // Create a new process group so we can wait on this process and
                // every child more efficiently.
                let _ = unsafe { libc::setpgid(0, 0) };

                // Suppress core dumps for testing purposes.
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let _ = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };

                // PTRACE_SEIZE is inherently racey, so we stop the child
                // process here.
                signal::raise(Signal::SIGSTOP).unwrap();

                // Run the child when the process is resumed.
                let exit_code = f();

                // Note: We can't use the normal exit function here because we
                // don't want to call atexit handlers since `execve` was never
                // called. `_exit` diverges (`-> !`), so there is nothing to bind.
                unsafe { ::libc::_exit(exit_code) };
            }
        }
    }

    #[test]
    fn basic() -> Result<(), Box<dyn std::error::Error + 'static>> {
        // Do nothing but exit.
        let (pid, tracee) = trace(|| 42, Options::empty())?;
        assert_eq!(
            tracee.resume(None)?.wait()?,
            Wait::Exited(pid, ExitStatus::Exited(42))
        );

        Ok(())
    }

    #[test]
    fn stop_on_exit() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (pid, tracee) = trace(
            || 42,
            Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEEXIT,
        )?;

        let running = tracee.resume(None)?;
        let (stopped, event) = running.wait()?.assume_stopped();

        // The tracee has stopped just before exiting. Resuming or detaching now
        // will let the process exit.
        assert_eq!(event, Event::Exit);

        assert_eq!(
            stopped.resume(None)?.wait()?,
            Wait::Exited(pid, ExitStatus::Exited(42))
        );

        Ok(())
    }

    #[test]
    #[cfg(not(sanitized))]
    fn serialized_threads() -> Result<(), Box<dyn std::error::Error + 'static>> {
        const THREAD_COUNT: usize = 8;

        let (pid, tracee) = trace(
            move || {
                // Create a handful of threads that do nothing but exit. They
                // are raw pthreads: see `spawn_tracee_thread`.
                extern "C" fn exit_at_once(_: *mut libc::c_void) -> *mut libc::c_void {
                    std::ptr::null_mut()
                }
                let threads = (0..THREAD_COUNT)
                    .map(|_| spawn_tracee_thread(exit_at_once, std::ptr::null_mut()))
                    .collect::<Vec<_>>();

                for t in threads {
                    assert_eq!(unsafe { libc::pthread_join(t, std::ptr::null_mut()) }, 0);
                }

                42
            },
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACECLONE,
        )?;

        let mut parent = tracee.resume(None)?;

        // We should observe threads getting created.
        for _ in 0..THREAD_COUNT {
            let (stopped, event) = parent.wait()?.assume_stopped();

            let child = match event {
                Event::NewChild(ChildOp::Clone, child) => child,
                e => panic!("Expected clone event, got {:?}", e),
            };

            // Should be at a group stop.
            let (child, event) = child.wait()?.assume_stopped();
            assert_eq!(event, Event::Stop);

            // Resume the child.
            let child = child.resume(None)?;

            // Wait for it to exit.
            let (child, event) = child.wait()?.assume_stopped();
            assert_eq!(event, Event::Exit);

            // Resume one last time to let it fully exit.
            let (_child_pid, exit_status) = child.resume(None)?.wait()?.assume_exited();
            assert_eq!(exit_status, ExitStatus::Exited(0));

            // Resume the parent.
            parent = stopped.resume(None)?;
        }

        // ptrace stop just before fully exiting.
        let (parent, event) = parent.wait()?.assume_stopped();
        assert_eq!(event, Event::Exit);

        // Fully exited.
        let parent = parent.resume(None)?;
        assert_eq!(parent.wait()?, Wait::Exited(pid, ExitStatus::Exited(42)));

        Ok(())
    }

    /// Starts a thread in a tracee forked by [`trace`] with a raw
    /// `pthread_create`.
    ///
    /// The test harness is multithreaded, and `fork` copies only the calling
    /// thread. A lock another harness thread held at the fork stays held in
    /// the child forever. `std::thread::spawn` takes such a lock (the thread
    /// info lock of std's stack overflow handler), so a tracee that uses it
    /// can block before its first clone. `pthread_create` needs no lock that
    /// glibc does not reset in the child of a fork.
    #[cfg(not(sanitized))]
    fn spawn_tracee_thread(
        start: extern "C" fn(*mut libc::c_void) -> *mut libc::c_void,
        arg: *mut libc::c_void,
    ) -> libc::pthread_t {
        let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
        let rc = unsafe { libc::pthread_create(thread.as_mut_ptr(), std::ptr::null(), start, arg) };
        assert_eq!(rc, 0, "pthread_create in a tracee failed");
        unsafe { thread.assume_init() }
    }

    #[cfg(not(sanitized))]
    fn group_exit(thread_count: usize) -> Result<(), Box<dyn std::error::Error + 'static>> {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let (parent_pid, tracee) = trace(
            move || {
                let counter = Arc::new(AtomicUsize::new(0));

                // Create a handful of threads that sleep forever. They are
                // raw pthreads: see `spawn_tracee_thread`.
                extern "C" fn count_and_sleep(counter: *mut libc::c_void) -> *mut libc::c_void {
                    // SAFETY: `counter` comes from `Arc::into_raw` below and
                    // owns one strong count, which this thread never drops:
                    // it sleeps until exit_group ends the process.
                    let counter = unsafe { &*(counter as *const AtomicUsize) };
                    counter.fetch_add(1, Ordering::Relaxed);
                    unsafe { libc::sleep(Duration::from_mins(1).as_secs() as libc::c_uint) };
                    std::ptr::null_mut()
                }
                let _threads = (0..thread_count)
                    .map(|_i| {
                        let counter = Arc::into_raw(counter.clone()) as *mut libc::c_void;
                        spawn_tracee_thread(count_and_sleep, counter)
                    })
                    .collect::<Vec<_>>();

                // Wait for each of the threads to actually get initialized.
                while counter.load(Ordering::Relaxed) != thread_count {
                    thread::yield_now();
                }

                // All threads should be alive at this point. SYS_exit_group
                // should force all threads to exit.
                let _ = unsafe { libc::syscall(libc::SYS_exit_group, 42) };

                unreachable!()
            },
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACECLONE,
        )?;

        tracee.resume(None)?;

        let mut exited = Vec::new();

        // Keep consuming events until everything has exited.
        while let Some(wait) = wait_group(parent_pid)? {
            match wait {
                Wait::Stopped(tracee, _event) => {
                    tracee.resume(None)?;
                }
                Wait::Exited(pid, exit_status) => {
                    exited.push((pid, exit_status));
                }
            }
        }

        // The parent should have exited last.
        assert_eq!(exited.pop(), Some((parent_pid, ExitStatus::Exited(42))));

        // The only things left should be the threads that were spawned.
        assert_eq!(exited.len(), thread_count);

        // All others should have exited with the same exit status.
        for (_pid, exit_status) in exited {
            assert_eq!(exit_status, ExitStatus::Exited(42));
        }

        Ok(())
    }

    /// Tests that we receive an exit for all threads in the right order even
    /// when the main thread calls `exit_group`.
    #[test]
    #[cfg(not(sanitized))]
    fn group_exit_stress() {
        // Test a variety of thread counts. Super-high thread counts makes
        // ptrace very slow, so we keep this to a relatively low number.
        for i in 0..100 {
            group_exit(i / 2).unwrap();
        }
    }

    /// Tests that trying to trace from another thread does not work.
    #[test]
    fn trace_from_another_thread() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (pid, tracee) = trace(|| 42, Options::empty()).unwrap();

        // Try resuming from another thread, which should fail. The process
        // didn't actually die; this is just how ESRCH is interpreted.
        let error = thread::spawn(move || tracee.resume(None))
            .join()
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, Error::Died(zombie) if zombie.pid() == pid));

        assert_eq!(
            Stopped::new_unchecked(pid).resume(None)?.wait()?,
            Wait::Exited(pid, ExitStatus::Exited(42))
        );

        Ok(())
    }

    #[test]
    fn trace_killed_by_signal() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (pid, tracee) = trace(
            || {
                signal::raise(Signal::SIGILL).unwrap();
                unreachable!()
            },
            Options::PTRACE_O_EXITKILL,
        )?;

        let running = tracee.resume(None)?;

        let (stopped, event) = running.wait()?.assume_stopped();

        // The tracee has stopped just before exiting. Resuming or detaching now
        // will let the process exit.
        assert_eq!(event, Event::Signal(Signal::SIGILL));

        assert_eq!(
            stopped.resume(Some(Signal::SIGILL))?.wait()?,
            Wait::Exited(pid, ExitStatus::Signaled(Signal::SIGILL, true))
        );

        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[tokio::test]
    async fn notifier_basic() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (pid, tracee) = trace(|| 42, Options::empty())?;
        assert_eq!(
            tracee.resume(None)?.next_state().await?,
            Wait::Exited(pid, ExitStatus::Exited(42))
        );

        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[tokio::test]
    async fn notifier_generation_preserves_exit_and_signal_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let (pid, tracee) = trace(|| 42, Options::empty())?;
        let token = tracee.1.clone();
        let stale_running = Running::from_token(pid, token.clone());
        let stale_zombie = Zombie::from_token(pid, token);
        let expected = ExitStatus::Exited(42);

        assert_eq!(
            tracee.resume(None)?.next_state().await?,
            Wait::Exited(pid, expected)
        );
        assert_eq!(
            stale_running.next_state().await?,
            Wait::Exited(pid, expected),
            "old Running rebound after terminal registry removal"
        );
        assert_eq!(stale_zombie.reap().await?, expected);
        assert_eq!(
            Running::new(pid).next_state().await,
            Err(Error::Errno(Errno::ECHILD)),
            "fresh generation inherited stale terminal status"
        );

        let (pid, tracee) = trace(
            || {
                signal::raise(Signal::SIGILL).unwrap();
                unreachable!()
            },
            Options::PTRACE_O_EXITKILL,
        )?;
        let token = tracee.1.clone();
        let stale_running = Running::from_token(pid, token.clone());
        let stale_zombie = Zombie::from_token(pid, token);
        let expected = ExitStatus::Signaled(Signal::SIGILL, true);
        let (stopped, event) = tracee.resume(None)?.next_state().await?.assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGILL));

        assert_eq!(
            stopped.resume(Some(Signal::SIGILL))?.next_state().await?,
            Wait::Exited(pid, expected)
        );
        assert_eq!(
            stale_running.next_state().await?,
            Wait::Exited(pid, expected),
            "old Running lost the terminating signal"
        );
        assert_eq!(stale_zombie.reap().await?, expected);
        assert_eq!(
            Running::new(pid).next_state().await,
            Err(Error::Errno(Errno::ECHILD))
        );

        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[tokio::test(flavor = "current_thread")]
    async fn owned_wait_clone_parent_decode_refusal_retains_same_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        for injected in [Errno::EMFILE, Errno::EIO] {
            let (pid, tracee) = trace(
                || {
                    let flags = libc::CLONE_PARENT | libc::SIGCHLD;
                    let result = unsafe {
                        libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize)
                    };
                    if result == 0 {
                        unsafe { libc::_exit(0) };
                    }
                    i32::from(result == -1)
                },
                Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEFORK,
            )?;
            let running = tracee.resume_retaining(None).map_err(|(_, error)| error)?;
            let cleanup = running.terminal_cleanup();
            let mut owner = running.wait_owned();

            notifier::inject_capture_error_for_current_thread(injected);
            assert_eq!(
                tokio::time::timeout(
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    &mut owner
                )
                .await?,
                Err(OwnedWaitError::Errno(injected)),
                "first CLONE_PARENT decode did not surface the injected capture error"
            );

            let (parent, event) = tokio::time::timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
                &mut owner,
            )
            .await??
            .assume_stopped();
            assert_eq!(parent.pid(), pid);
            assert!(parent.terminal_cleanup().same_generation(&cleanup));
            assert!(matches!((&mut owner).await, Err(OwnedWaitError::Completed)));
            let child = match event {
                Event::NewChild(ChildOp::Fork, child) => child,
                event => panic!("retry lost the CLONE_PARENT event: {event:?}"),
            };
            let (child, event) = tokio::time::timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
                child.wait_owned(),
            )
            .await??
            .assume_stopped();
            assert!(matches!(
                event,
                Event::Stop | Event::Signal(Signal::SIGSTOP)
            ));
            assert_eq!(
                tokio::time::timeout(
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    child.resume(None)?.wait_owned()
                )
                .await??
                .assume_exited()
                .1,
                ExitStatus::Exited(0)
            );
            assert_eq!(
                tokio::time::timeout(
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    parent.resume(None)?.wait_owned()
                )
                .await??
                .assume_exited()
                .1,
                ExitStatus::Exited(0)
            );
        }
        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[tokio::test(flavor = "current_thread")]
    async fn notifier_clone_parent_decode_error_preserves_fifo_front()
    -> Result<(), Box<dyn std::error::Error>> {
        for injected in [Errno::EMFILE, Errno::EIO] {
            let (pid, tracee) = trace(
                || {
                    let flags = libc::CLONE_PARENT | libc::SIGCHLD;
                    let result = unsafe {
                        libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize)
                    };
                    if result == 0 {
                        unsafe { libc::_exit(0) };
                    }
                    i32::from(result == -1)
                },
                Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEFORK,
            )?;
            let token = tracee.1.clone();
            let running = tracee.resume(None)?;
            let retry = Running::from_token(pid, token);
            let _cleanup = running.terminal_cleanup();

            notifier::inject_capture_error_for_current_thread(injected);
            assert_eq!(
                running.next_state().await,
                Err(Error::Errno(injected)),
                "first CLONE_PARENT decode did not surface the injected capture error"
            );

            let (parent, event) = retry.next_state().await?.assume_stopped();
            let child = match event {
                Event::NewChild(ChildOp::Fork, child) => child,
                event => panic!("retry lost the CLONE_PARENT event: {event:?}"),
            };
            let (child, event) = child.next_state().await?.assume_stopped();
            assert!(matches!(
                event,
                Event::Stop | Event::Signal(Signal::SIGSTOP)
            ));
            assert_eq!(
                child.resume(None)?.next_state().await?.assume_exited().1,
                ExitStatus::Exited(0)
            );
            assert_eq!(
                parent.resume(None)?.next_state().await?.assume_exited().1,
                ExitStatus::Exited(0)
            );
        }
        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[test]
    fn synchronous_clone_parent_decode_error_preserves_fifo_front()
    -> Result<(), Box<dyn std::error::Error>> {
        for injected in [Errno::EMFILE, Errno::EIO] {
            let (pid, tracee) = trace(
                || {
                    let flags = libc::CLONE_PARENT | libc::SIGCHLD;
                    let result = unsafe {
                        libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize)
                    };
                    if result == 0 {
                        unsafe { libc::_exit(0) };
                    }
                    i32::from(result == -1)
                },
                Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEFORK,
            )?;
            let token = tracee.1.clone();
            let running = tracee.resume(None)?;
            let retry = Running::from_token(pid, token);

            notifier::inject_sync_decode_capture_error(pid, injected);
            assert_eq!(
                running.wait(),
                Err(Error::Errno(injected)),
                "first synchronous CLONE_PARENT decode did not surface the injected error"
            );

            let (parent, event) = retry.wait()?.assume_stopped();
            let child = match event {
                Event::NewChild(ChildOp::Fork, child) => child,
                event => panic!("synchronous retry lost the CLONE_PARENT event: {event:?}"),
            };
            let (child, event) = child.wait()?.assume_stopped();
            assert!(matches!(
                event,
                Event::Stop | Event::Signal(Signal::SIGSTOP)
            ));
            assert_eq!(
                child.resume(None)?.wait()?.assume_exited().1,
                ExitStatus::Exited(0)
            );
            assert_eq!(
                parent.resume(None)?.wait()?.assume_exited().1,
                ExitStatus::Exited(0)
            );
        }
        Ok(())
    }

    #[cfg(feature = "notifier")]
    #[cfg(not(sanitized))]
    #[tokio::test]
    async fn late_waits_after_terminal_reap_return_echild() -> Result<(), Box<dyn std::error::Error>>
    {
        let (pid, tracee) = trace(|| 42, Options::empty())?;
        assert_eq!(
            tracee.resume(None)?.next_state().await?,
            Wait::Exited(pid, ExitStatus::Exited(42))
        );

        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                Running::new(pid).next_state(),
            )
            .await
            .expect("late next_state hung after terminal reap"),
            Err(Error::Errno(Errno::ECHILD))
        );
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                Running::new(pid).exit_event(),
            )
            .await
            .expect("late exit_event hung after terminal reap"),
            Err(Error::Errno(Errno::ECHILD))
        );

        Ok(())
    }

    // kernel_sigset_t used by naked syscall
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct KernelSigset(u64);

    impl From<&[Signal]> for KernelSigset {
        fn from(signals: &[Signal]) -> Self {
            let mut set: u64 = 0;
            for &sig in signals {
                set |= 1u64 << (sig as usize - 1);
            }
            KernelSigset(set)
        }
    }

    #[unsafe(no_mangle)]
    extern "C" fn sigalrm_handler(
        _sig: i32,
        _siginfo: *mut libc::siginfo_t,
        _ucontext: *const libc::c_void,
    ) {
        nix::unistd::write(unsafe { BorrowedFd::borrow_raw(2) }, b"caught SIGALRM!").unwrap();
    }

    #[allow(dead_code)]
    unsafe fn install_sigalrm_handler() -> i32 {
        unsafe {
            let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
            sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO | libc::SA_NODEFER;
            sa.sa_sigaction = sigalrm_handler as *const () as _;

            libc::sigaction(libc::SIGALRM, &sa as *const _, std::ptr::null_mut())
        }
    }

    #[allow(dead_code)]
    // unblock signal(s) and set its handler to SIG_DFL
    unsafe fn unblock_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        unsafe {
            let set = KernelSigset::from(signals);
            let mut oldset = MaybeUninit::<u64>::uninit();

            if libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_UNBLOCK,
                &set as *const _,
                oldset.as_mut_ptr(),
                8,
            ) != 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(KernelSigset(oldset.assume_init()))
            }
        }
    }

    #[allow(dead_code)]
    unsafe fn block_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        unsafe {
            let set = KernelSigset::from(signals);
            let mut oldset = MaybeUninit::<u64>::uninit();

            if libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                &set as *const _,
                oldset.as_mut_ptr(),
                8,
            ) != 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(KernelSigset(oldset.assume_init()))
            }
        }
    }

    /// The calling thread's blocked-signal mask, as the kernel reports it.
    fn own_sigmask() -> u64 {
        let mut mask = 0u64;
        let ret = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                std::ptr::null::<u64>(),
                &mut mask as *mut u64,
                8,
            )
        };
        assert_eq!(ret, 0);
        mask
    }

    /// Stops the calling thread with a raw `tgkill(getpid(), gettid(),
    /// SIGSTOP)`, so no userspace mask save and restore wraps the stop. libc
    /// `raise()` in glibc 2.26 to 2.33, and in musl, blocks signals around its
    /// tgkill and restores the saved mask afterwards; that restore would run
    /// after the tracer's PTRACE_SETSIGMASK at this stop and overwrite it.
    fn stop_self_with_raw_tgkill() {
        let ret = unsafe {
            let pid = libc::syscall(libc::SYS_getpid);
            let tid = libc::syscall(libc::SYS_gettid);
            libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSTOP)
        };
        assert_eq!(ret, 0);
    }

    /// Waits for the tracee's next stop, which must be a signal-delivery stop
    /// for `signal`.
    fn expect_signal_stop(running: Running, signal: Signal) -> Stopped {
        match running.wait().unwrap() {
            Wait::Stopped(stopped, Event::Signal(got)) if got == signal => stopped,
            other => panic!("expected a {signal:?} delivery stop, got {other:?}"),
        }
    }

    /// PTRACE_GETSIGMASK reads the mask the tracee set itself, and
    /// PTRACE_SETSIGMASK replaces it (minus SIGKILL and SIGSTOP, which the
    /// kernel never blocks) as the tracee then observes.
    #[cfg(not(sanitized))]
    #[test]
    fn getsigmask_and_setsigmask_read_and_replace_the_tracee_mask()
    -> Result<(), Box<dyn std::error::Error + 'static>> {
        let replacement = KernelSigset::from(&[Signal::SIGUSR1, Signal::SIGALRM][..]).0;
        let unblockable = KernelSigset::from(&[Signal::SIGKILL, Signal::SIGSTOP][..]).0;
        let (pid, tracee) = trace(
            move || {
                unsafe { block_signals(&[Signal::SIGUSR1, Signal::SIGUSR2]) }.unwrap();
                stop_self_with_raw_tgkill();
                if own_sigmask() == replacement { 0 } else { 1 }
            },
            Options::PTRACE_O_EXITKILL,
        )?;
        let stopped = expect_signal_stop(tracee.resume(None)?, Signal::SIGSTOP);
        let blocked = KernelSigset::from(&[Signal::SIGUSR1, Signal::SIGUSR2][..]).0;
        let mask = stopped.getsigmask()?;
        assert_eq!(mask & blocked, blocked, "mask {mask:#x}");
        stopped.setsigmask(replacement | unblockable)?;
        assert_eq!(stopped.getsigmask()?, replacement);
        // Suppress the SIGSTOP; the tracee checks its own mask and exits.
        assert_eq!(
            stopped.resume(None)?.wait()?,
            Wait::Exited(pid, ExitStatus::Exited(0))
        );
        Ok(())
    }

    static SIGUSR1_HANDLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    extern "C" fn note_sigusr1(_signal: libc::c_int) {
        SIGUSR1_HANDLED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A mask set by the tracer holds a signal sent meanwhile pending (no
    /// delivery stop, no handler), and restoring the saved mask releases it
    /// to an ordinary delivery stop and the handler.
    #[cfg(not(sanitized))]
    #[test]
    fn setsigmask_holds_a_signal_pending_until_the_mask_is_restored()
    -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (pid, tracee) = trace(
            || {
                let mut action: libc::sigaction = unsafe { MaybeUninit::zeroed().assume_init() };
                action.sa_sigaction = note_sigusr1 as *const () as usize;
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) },
                    0
                );
                unsafe { unblock_signals(&[Signal::SIGUSR1]) }.unwrap();
                stop_self_with_raw_tgkill();
                // The tracer blocked everything and sent SIGUSR1.
                let mut pending = 0u64;
                unsafe { libc::syscall(libc::SYS_rt_sigpending, &mut pending as *mut u64, 8) };
                let usr1 = KernelSigset::from(&[Signal::SIGUSR1][..]).0;
                if pending & usr1 == 0 {
                    return 2;
                }
                if SIGUSR1_HANDLED.load(std::sync::atomic::Ordering::SeqCst) {
                    return 3;
                }
                stop_self_with_raw_tgkill();
                // The tracer restored the mask: SIGUSR1 has been handled.
                if SIGUSR1_HANDLED.load(std::sync::atomic::Ordering::SeqCst) {
                    0
                } else {
                    4
                }
            },
            Options::PTRACE_O_EXITKILL,
        )?;
        let stopped = expect_signal_stop(tracee.resume(None)?, Signal::SIGSTOP);
        let saved = stopped.getsigmask()?;
        stopped.setsigmask(!0)?;
        signal::kill(pid.into(), Signal::SIGUSR1)?;
        // SIGUSR1 is blocked: the next stop is the second SIGSTOP.
        let stopped = expect_signal_stop(stopped.resume(None)?, Signal::SIGSTOP);
        stopped.setsigmask(saved)?;
        assert_eq!(stopped.getsigmask()?, saved);
        let stopped = expect_signal_stop(stopped.resume(None)?, Signal::SIGUSR1);
        assert_eq!(
            stopped.resume(Some(Signal::SIGUSR1))?.wait()?,
            Wait::Exited(pid, ExitStatus::Exited(0))
        );
        Ok(())
    }

    #[cfg(not(sanitized))]
    #[test]
    fn peeksiginfo_returns_pending_siginfo() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (parent_pid, tracee) = trace(
            move || {
                let _ = unsafe {
                    block_signals(&[Signal::SIGALRM, Signal::SIGVTALRM, Signal::SIGPROF])
                };
                assert!(signal::raise(Signal::SIGALRM).is_ok());
                assert!(signal::raise(Signal::SIGVTALRM).is_ok());
                assert!(signal::raise(Signal::SIGPROF).is_ok());

                // All threads should be alive at this point. SYS_exit_group
                // should force all threads to exit.
                let _ = unsafe { libc::syscall(libc::SYS_exit_group, 0) };

                unreachable!()
            },
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACECLONE,
        )?;

        tracee.resume(None)?;

        let mut exited = Vec::new();

        // Keep consuming events until everything has exited.
        while let Some(wait) = wait_group(parent_pid)? {
            match wait {
                Wait::Stopped(tracee, Event::Exit) => {
                    let pending: Vec<_> = tracee
                        .peeksiginfo(None)?
                        .iter()
                        .map(|&si| Signal::try_from(si.si_signo).unwrap())
                        .collect();
                    assert_eq!(
                        pending,
                        [Signal::SIGALRM, Signal::SIGVTALRM, Signal::SIGPROF]
                    );
                    // do a second peek here to demostrate peek doesn't
                    // *pop* pending signals.
                    let pending: Vec<_> = tracee
                        .peeksiginfo(None)?
                        .iter()
                        .map(|&si| Signal::try_from(si.si_signo).unwrap())
                        .collect();
                    assert_eq!(
                        pending,
                        [Signal::SIGALRM, Signal::SIGVTALRM, Signal::SIGPROF]
                    );
                    tracee.resume(None)?;
                }
                Wait::Stopped(tracee, _event) => {
                    tracee.resume(None)?;
                }
                Wait::Exited(pid, exit_status) => {
                    exited.push((pid, exit_status));
                }
            }
        }

        // The parent should have exited last
        assert_eq!(exited.pop(), Some((parent_pid, ExitStatus::Exited(0))));

        Ok(())
    }

    #[cfg(not(sanitized))]
    #[test]
    fn peeksiginfo_all_returns_the_whole_queue() -> Result<(), Box<dyn std::error::Error + 'static>>
    {
        // Real-time signals queue one entry each, so this exceeds one 64-entry
        // read twice over.
        const QUEUED: usize = 150;
        let (parent_pid, tracee) = trace(
            move || {
                let rt = libc::SIGRTMIN();
                unsafe {
                    let mut set: libc::sigset_t = core::mem::zeroed();
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, rt);
                    libc::sigaddset(&mut set, libc::SIGALRM);
                    assert_eq!(
                        libc::sigprocmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()),
                        0
                    );
                    for _ in 0..QUEUED {
                        assert_eq!(
                            libc::syscall(libc::SYS_tgkill, libc::getpid(), libc::gettid(), rt),
                            0
                        );
                    }
                    assert_eq!(
                        libc::syscall(
                            libc::SYS_tgkill,
                            libc::getpid(),
                            libc::gettid(),
                            libc::SIGALRM
                        ),
                        0
                    );
                    libc::syscall(libc::SYS_exit_group, 0);
                }
                unreachable!()
            },
            Options::PTRACE_O_EXITKILL | Options::PTRACE_O_TRACEEXIT,
        )?;

        tracee.resume(None)?;

        let mut peeked = false;
        while let Some(wait) = wait_group(parent_pid)? {
            match wait {
                Wait::Stopped(tracee, Event::Exit) => {
                    let signos = |v: Vec<libc::siginfo_t>| -> Vec<i32> {
                        v.iter().map(|si| si.si_signo).collect()
                    };
                    let mut expected = vec![libc::SIGRTMIN(); QUEUED];
                    expected.push(libc::SIGALRM);
                    assert_eq!(signos(tracee.peeksiginfo(None)?), expected[..64]);
                    assert_eq!(signos(tracee.peeksiginfo_all(None)?), expected);
                    peeked = true;
                    tracee.resume(None)?;
                }
                Wait::Stopped(tracee, _event) => {
                    tracee.resume(None)?;
                }
                Wait::Exited(_, exit_status) => {
                    assert_eq!(exit_status, ExitStatus::Exited(0));
                }
            }
        }
        assert!(peeked, "the tracee never reached its exit stop");

        Ok(())
    }

    #[cfg(not(sanitized))]
    #[test]
    fn getsiginfo_should_success() -> Result<(), Box<dyn std::error::Error + 'static>> {
        let (parent_pid, tracee) = trace(
            move || {
                let _ = unsafe { unblock_signals(&[Signal::SIGALRM]) };
                let _ = unsafe { block_signals(&[Signal::SIGVTALRM, Signal::SIGPROF]) };
                assert_eq!(unsafe { install_sigalrm_handler() }, 0);
                assert!(signal::raise(Signal::SIGALRM).is_ok());

                // All threads should be alive at this point. SYS_exit_group
                // should force all threads to exit.
                let _ = unsafe { libc::syscall(libc::SYS_exit_group, 0) };

                unreachable!()
            },
            Options::PTRACE_O_EXITKILL
                | Options::PTRACE_O_TRACEEXIT
                | ptrace::Options::PTRACE_O_TRACECLONE,
        )?;

        tracee.resume(None)?;

        let mut exited = Vec::new();

        // Keep consuming events until everything has exited.
        while let Some(wait) = wait_group(parent_pid)? {
            match wait {
                Wait::Stopped(tracee, Event::Signal(Signal::SIGALRM)) => {
                    let siginfo = tracee.getsiginfo()?;
                    assert_eq!(siginfo.si_signo, Signal::SIGALRM as i32);
                    tracee.resume(Signal::SIGALRM)?;
                }
                Wait::Stopped(tracee, Event::Signal(other_signal)) => {
                    tracee.resume(other_signal)?;
                }
                Wait::Stopped(tracee, _event) => {
                    tracee.resume(None)?;
                }
                Wait::Exited(pid, exit_status) => {
                    exited.push((pid, exit_status));
                }
            }
        }

        // The parent should have exited last
        assert_eq!(exited.pop(), Some((parent_pid, ExitStatus::Exited(0))));

        Ok(())
    }
}
