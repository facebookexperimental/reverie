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

pub use crate::regs::*;
use crate::waitid::waitid;
use crate::waitid::IdType;

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
                Ok(Self::NewChild(ChildOp::Fork, Running(child_pid)))
            }
            libc::PTRACE_EVENT_VFORK => {
                // Get the pid of the child immediately since we almost always
                // want that.
                let child_pid = Pid::from_raw(task.getevent()? as i32);
                Ok(Self::NewChild(ChildOp::Vfork, Running(child_pid)))
            }
            libc::PTRACE_EVENT_CLONE => {
                // Get the pid of the child immediately since we almost always
                // want that.
                let child_pid = Pid::from_raw(task.getevent()? as i32);
                Ok(Self::NewChild(ChildOp::Clone, Running(child_pid)))
            }
            libc::PTRACE_EVENT_EXEC => {
                // Get the pid of the thread group leader that this call to exec
                // is replacing. This is not necessarily equal to `pid` since
                // another thread besides the main thread can call `exec`. This
                // information is necessary to track the "death" of a process.
                let new_pid = Pid::from_raw(task.getevent()? as i32);
                Ok(Self::Exec(new_pid))
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
            status => Err(InvalidState(status)).unwrap(),
        }
    }

    /// Assumes the process is in a running state. Panics if it isn't.
    pub fn assume_running(self) -> Running {
        match self {
            Self::Running(running) => running,
            status => Err(InvalidState(status)).unwrap(),
        }
    }

    /// Assumes the process is in an exited state. Panics if it isn't.
    pub fn assume_exited(self) -> (Pid, ExitStatus) {
        match self {
            Self::Wait(Wait::Exited(pid, exit_status)) => (pid, exit_status),
            status => Err(InvalidState(status)).unwrap(),
        }
    }
}

impl fmt::Display for TryWait {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Wait(wait) => write!(f, "{}", wait),
            Self::Running(Running(pid)) => write!(f, "pid {} is running", pid),
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
            Self::Stopped(Stopped(pid), _) => *pid,
            Self::Exited(pid, _exit_status) => *pid,
        }
    }

    /// Assumes the process is in a stopped state. Panics if it isn't.
    pub fn assume_stopped(self) -> (Stopped, Event) {
        match self {
            Self::Stopped(stopped, event) => (stopped, event),
            state => Err(InvalidState(state.into())).unwrap(),
        }
    }

    /// Assumes the process is in an exited state. Panics if it isn't.
    pub fn assume_exited(self) -> (Pid, ExitStatus) {
        match self {
            Self::Exited(pid, exit_status) => (pid, exit_status),
            state => Err(InvalidState(state.into())).unwrap(),
        }
    }

    /// Converts a raw `i32` status to this type.
    ///
    /// Preconditions:
    /// The process must not be in a running state.
    pub fn from_raw(pid: Pid, status: i32) -> Result<Self, Error> {
        Ok(if libc::WIFEXITED(status) {
            Wait::Exited(pid, ExitStatus::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            let sig = Signal::try_from(libc::WTERMSIG(status)).map_err(|_| Errno::EINVAL)?;
            Wait::Exited(pid, ExitStatus::Signaled(sig, libc::WCOREDUMP(status)))
        } else if libc::WIFSTOPPED(status) {
            let task = Stopped(pid);

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

                Event::from_ptrace_event(&task, event)?
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
        Ok(match wait_status {
            WaitStatus::Exited(pid, code) => Self::Exited(pid.into(), ExitStatus::Exited(code)),
            WaitStatus::Signaled(pid, sig, coredump) => {
                Self::Exited(pid.into(), ExitStatus::Signaled(sig, coredump))
            }
            WaitStatus::Stopped(pid, sig) => {
                let event = Event::Signal(sig);
                Self::Stopped(Stopped(pid.into()), event)
            }
            WaitStatus::PtraceEvent(pid, sig, event) => {
                // PTRACE_EVENT_STOP is not guaranteed to return the correct
                // signal, so we ignore it here.
                debug_assert!(event == libc::PTRACE_EVENT_STOP || sig == Signal::SIGTRAP);
                let task = Stopped(pid.into());
                let event = Event::from_ptrace_event(&task, event)?;
                Self::Stopped(task, event)
            }
            WaitStatus::PtraceSyscall(pid) => {
                let event = Event::Syscall;
                Self::Stopped(Stopped(pid.into()), event)
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
    pub struct PeekSigInfoFlags: u32 {
        /// dumping signals from the process-wide signal queue. signals are
        /// read from the per-thread queue of the specified thread if this
        /// flag is not set.
        const SHARED = 1;
    }
}

/// A process that is in a stopped state and allows ptrace operations to be
/// performed.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Stopped(Pid);

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
    fn map_err(&self, err: Errno) -> Error {
        if err == Errno::ESRCH {
            Error::Died(Zombie::new(self.0))
        } else {
            Error::Errno(err)
        }
    }

    // Helper for converting from the nix::Error type.
    fn map_nix_err(&self, err: nix::Error) -> Error {
        self.map_err(Errno::new(err as i32))
    }

    /// Returns a future that is notified when the next exit stop occurs. This
    /// is received asynchronously regardless of what the process was doing at
    /// the time. This is useful for canceling futures when a process enters a
    /// `PTRACE_EVENT_EXIT` (such as when one thread calls `exit_group` and
    /// causes all other threads to suddenly exit).
    #[cfg(feature = "notifier")]
    pub fn exit_event(&self) -> notifier::ExitFuture {
        notifier::ExitFuture(self.0)
    }

    /// Creates a new stopped state. This is useful when we know the process is
    /// in a stopped state already.
    ///
    /// Using this method is unsound because there is no check to verify that the
    /// pid really is in a stopped state. It is better to arrive at a stopped
    /// state via other methods such as `Running::wait`.
    pub fn new_unchecked(pid: Pid) -> Self {
        Stopped(pid)
    }

    /// Returns the process ID of the tracee.
    pub fn pid(&self) -> Pid {
        self.0
    }

    /// Sets the ptracer options.
    pub fn setoptions(&self, options: ptrace::Options) -> Result<(), Error> {
        ptrace::setoptions(self.0.into(), options).map_err(|err| self.map_nix_err(err))
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

        unsafe {
            syscalls::syscall!(
                Sysno::ptrace,
                // PTRACE_GETREGS isn't available on aarch64, so we must use
                // PTRACE_GETREGSET instead.
                libc::PTRACE_GETREGSET,
                self.0.as_raw(),
                which,
                &mut iov as *mut _
            )
        }
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

        unsafe {
            syscalls::syscall!(
                Sysno::ptrace,
                // PTRACE_SETREGS isn't available on aarch64, so we must use
                // PTRACE_SETREGSET instead.
                libc::PTRACE_SETREGSET,
                self.0.as_raw(),
                which,
                &iov as *const _
            )
        }
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

    /// Resumes the process and transitions it back to a running state.
    pub fn resume<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        ptrace::cont(self.0.into(), sig).map_err(|err| self.map_nix_err(err))?;
        Ok(Running::new(self.0))
    }

    /// Advances the execution of the process by a single step optionally
    /// delivering a signal specified by `sig`.
    pub fn step<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        ptrace::step(self.0.into(), sig).map_err(|err| self.map_nix_err(err))?;
        Ok(Running::new(self.0))
    }

    /// Like `step`, but arranges for the tracee to be stopped at the next
    /// entry to or exit from a system call.
    pub fn syscall<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        ptrace::syscall(self.0.into(), sig).map_err(|err| self.map_nix_err(err))?;
        Ok(Running::new(self.0))
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
        ptrace::getsiginfo(self.0.into()).map_err(|err| self.map_nix_err(err))
    }

    /// Sets info about the singal that caused the process to be stopped.
    pub fn setsiginfo(&self, siginfo: &libc::siginfo_t) -> Result<(), Error> {
        ptrace::setsiginfo(self.0.into(), siginfo).map_err(|err| self.map_nix_err(err))
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
        let count = Errno::result(unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKSIGINFO,
                self.0.as_raw(),
                &mut siginfo_args as *mut _,
                data.as_mut_ptr() as *const _ as *const libc::c_void,
            )
        })
        .map_err(|err| self.map_err(err))?;
        Ok(unsafe { data.assume_init() }[0..count as usize].to_vec())
    }

    /// Retrieve a message about the ptrace event that just happened.
    ///
    /// It shouldn't be necessary to call this in most cases because `Event`
    /// provides the necessary context for certain ptrace events.
    pub fn getevent(&self) -> Result<i64, Error> {
        ptrace::getevent(self.0.into()).map_err(|err| self.map_nix_err(err))
    }

    /// Detaches from and then resumes the stopped tracee.
    pub fn detach<T: Into<Option<Signal>>>(self, sig: T) -> Result<Running, Error> {
        ptrace::detach(self.0.into(), sig).map_err(|err| self.map_nix_err(err))?;
        Ok(Running::new(self.0))
    }
}

/// Waits for any child processes to change state, blocking until the next event.
/// This is equivalent to `waitpid(-1)`.
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
        Ok(status) => Ok(status.pid().map(|pid| Running(pid.into()))),
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

    Ok(next.and_then(|state| state.pid().map(|pid| Running(pid.into()))))
}

/// A running child.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Running(Pid);

impl Running {
    /// Creates a new running process. This is generally the entry point for a
    /// new process as soon as it is created.
    pub fn new(pid: Pid) -> Self {
        Running(pid)
    }

    /// Attaches to a running process. The process becomes a tracee and a SIGSTOP
    /// is sent to it. By the time this function ends, the tracee may not yet
    /// have actually stopped. Thus, the tracee is still considered to be in a
    /// running state and needs to be waited upon to observe the SIGSTOP.
    pub fn attach(pid: Pid) -> Result<Self, Errno> {
        ptrace::attach(pid.into()).map_err(|err| Errno::new(err as i32))?;
        Ok(Running(pid))
    }

    /// Similar to attach, but does not stop the process. This also affects the
    /// events that are later delivered. Upon clone, fork, or vfork, an
    /// `Event::Stop` is delivered instead of `Event::Signal(Signal::SIGSTOP)`.
    ///
    /// Unlike other modes, a seized process can also accept interrupts.
    pub fn seize(pid: Pid, options: Options) -> Result<Self, Errno> {
        ptrace::seize(pid.into(), options).map_err(|err| Errno::new(err as i32))?;
        Ok(Running(pid))
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
        Errno::result(unsafe {
            libc::ptrace(
                libc::PTRACE_INTERRUPT,
                self.0.as_raw(),
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        })
        .map(drop)
    }

    /// Returns the pid of the running process.
    pub fn pid(&self) -> Pid {
        self.0
    }

    /// Blocks until a state change occurs. This may transition the process to
    /// either a stopped state or exited state, but never a running state.
    pub fn wait(self) -> Result<Wait, Error> {
        wait(
            IdType::Pid(self.0.into()),
            WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED,
        )
        .map_err(Error::from)
        .and_then(|status| {
            // Unwrap is OK because the process cannot be in a running state without
            // WNOHANG.
            Wait::try_from(status.unwrap())
        })
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
    #[cfg(feature = "notifier")]
    pub fn exit_event(&self) -> notifier::ExitFuture {
        notifier::ExitFuture(self.0)
    }

    /// Like `wait`, but wait asynchronously for the next state change.
    ///
    /// NOTE: This call should not be mixed with [`Running::wait`]!! Once
    /// [`Running::next_state`] is called once, [`Running::wait`] should never
    /// be called again for that PID. This is because a notifier thread takes
    /// over and calls `wait` in a continuous loop.
    #[cfg(feature = "notifier")]
    pub async fn next_state(self) -> Result<Wait, Error> {
        notifier::WaitFuture(self).await
    }
}

/// A process that is no longer running, but hasn't yet fully exited. The only
/// thing zombie can do is exit.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct Zombie(Running);

impl Zombie {
    /// Creates a new instance.
    fn new(pid: Pid) -> Self {
        Zombie(Running(pid))
    }

    /// Returns the PID of the zombie.
    pub fn pid(&self) -> Pid {
        self.0.pid()
    }

    /// Reaps the zombie by waiting for it to fully exit.
    #[cfg(feature = "notifier")]
    pub async fn reap(self) -> ExitStatus {
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
                    Wait::Exited(_pid, exit_status) => break exit_status,
                },
                Err(Error::Died(zombie)) => next_state = zombie.0.next_state().await,
                Err(Error::Errno(Errno::ECHILD)) => break ExitStatus::Exited(1),
                other => panic!(
                    "Got unexpected result when awaiting final death {:?}",
                    other
                ),
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
    use std::thread;

    use nix::sys::signal;
    use nix::sys::signal::Signal;
    use nix::unistd::fork;
    use nix::unistd::ForkResult;
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
                // called.
                let _ = unsafe { ::libc::_exit(exit_code) };
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
                // Create a handful of threads that do nothing but exit.
                let threads = (0..THREAD_COUNT)
                    .map(|i| thread::spawn(move || i))
                    .collect::<Vec<_>>();

                for t in threads {
                    t.join().unwrap();
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

    #[cfg(not(sanitized))]
    fn group_exit(thread_count: usize) -> Result<(), Box<dyn std::error::Error + 'static>> {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;
        use std::time::Duration;

        let (parent_pid, tracee) = trace(
            move || {
                let counter = Arc::new(AtomicUsize::new(0));

                // Create a handful of threads that sleep forever.
                let _threads = (0..thread_count)
                    .map(|_i| {
                        let counter = counter.clone();

                        thread::spawn(move || {
                            counter.fetch_add(1, Ordering::Relaxed);
                            thread::sleep(Duration::from_secs(60));
                        })
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

        assert_eq!(
            // Try resuming from another thread, which should fail.
            thread::spawn(move || tracee.resume(None)).join().unwrap(),
            // The process didn't actually die, this is just how ESRCH was
            // interpretted.
            Err(Error::Died(Zombie::new(pid)))
        );

        assert_eq!(
            Stopped(pid).resume(None)?.wait()?,
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

    #[no_mangle]
    extern "C" fn sigalrm_handler(
        _sig: i32,
        _siginfo: *mut libc::siginfo_t,
        _ucontext: *const libc::c_void,
    ) {
        nix::unistd::write(2, b"caught SIGALRM!").unwrap();
    }

    #[allow(dead_code)]
    unsafe fn install_sigalrm_handler() -> i32 {
        let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO | libc::SA_NODEFER;
        sa.sa_sigaction = sigalrm_handler as _;

        libc::sigaction(libc::SIGALRM, &sa as *const _, std::ptr::null_mut())
    }

    #[allow(dead_code)]
    // unblock signal(s) and set its handler to SIG_DFL
    unsafe fn unblock_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
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

    #[allow(dead_code)]
    unsafe fn block_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
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
