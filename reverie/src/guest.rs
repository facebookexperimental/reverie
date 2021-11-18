/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! Guest (i.e. thread) structure and traits

use async_trait::async_trait;
use reverie_syscalls::{Errno, MemoryAccess, SyscallInfo};

use crate::auxv::Auxv;
use crate::error::Error;
use crate::stack::Stack;
use crate::timer::TimerSchedule;
use crate::tool::{GlobalRPC, GlobalTool, Tool};
use crate::Pid;

/// A representation of a guest task (thread).
#[async_trait]
pub trait Guest<T: Tool>: Send + GlobalRPC<T::GlobalState> {
    /// Access to guest memory
    type Memory: MemoryAccess + Send;

    /// Access to guest stack
    type Stack: Send + Stack;

    /// Thread ID of the guest task.
    fn tid(&self) -> Pid;

    /// Process ID of the process containing the guest task.
    fn pid(&self) -> Pid;

    /// Process ID of the parent process. Returns `None` if this is the root of
    /// the traced process tree. A return value of `None` does not necessarily
    /// mean it is the root process in the system.
    fn ppid(&self) -> Option<Pid>;

    /// Returns true if this thread is the thread group leader (i.e., the main
    /// thread).
    fn is_main_thread(&self) -> bool {
        self.tid() == self.pid()
    }

    /// Returns true if this is considered the root process of the traced task
    /// tree (i.e., if `getppid()` returns `None`).
    fn is_root_process(&self) -> bool {
        self.ppid().is_none()
    }

    /// Returns true if this is considered the root thread of the traced task
    /// tree (i.e., if `getppid()` returns `None` and `is_main_thread` returns
    /// true).
    fn is_root_thread(&self) -> bool {
        self.is_root_process() && self.is_main_thread()
    }

    /// Reads and returns the auxv table for this process.
    fn auxv(&self) -> Auxv {
        Auxv::new(self.pid()).expect("failed to read auxv table")
    }

    /// Returns a representation of the address space associated with this guest
    /// thread.
    fn memory(&self) -> Self::Memory;

    /// Returns a mutable reference to thread state.
    fn thread_state_mut(&mut self) -> &mut T::ThreadState;

    /// Returns an immutable reference to thread state.
    fn thread_state(&self) -> &T::ThreadState;

    /// Returns the current stack pointer with this guest thread.
    async fn stack(&mut self) -> Self::Stack;

    /// Task is trying to become a daemon. The tracer may choose to kill all
    /// remaining tasks when daemons are the only ones left.
    async fn daemonize(&mut self);

    /// Inject a system call into the guest and wait for the return value. This
    /// function dirties the register file while its executing, but restores at
    /// the end.
    ///
    /// Preconditions: the guest is in a stopped state and Reverie is currently
    /// running a handler on that guest thread's behalf.
    ///
    /// Postconditions: the register file is the same as before the call to this
    /// function. However, any side effects, including to guest memory, persist
    /// after the injected call.
    ///
    /// # Caveats
    ///
    /// A few syscalls are special and behave differently from the rest:
    ///  - `exit` or `exit_group` will never return when injected. Since these
    ///    syscalls will cause the current thread or process to exit, no code that
    ///    comes after can be executed.
    ///  - `execve` will never return when *successfully* injected. If you wish to
    ///    handle successful calls to `execve`, use [`Tool::handle_post_exec`].
    ///    Failed calls to `execve` will still return, however. Thus, it is safe to
    ///    use [`Result::unwrap_err`] on the result of the `inject`.
    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno>;

    /// Similar to [`Guest::inject`], except that it never returns. Since it does
    /// not return to the caller, the syscall return value cannot be altered or
    /// inspected. This method exists as an optimization for the `ptrace`
    /// backend, so that we can avoid interrupting the guest if we don't care
    /// about the syscall return value.
    ///
    /// # Caveats
    ///
    /// This method comes with a major footgun. Any code written after
    /// `tail_inject` will never be executed:
    ///
    /// ```no_run
    /// use reverie::*;
    /// use reverie::syscalls::*;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Debug, Serialize, Deserialize, Default, Clone)]
    /// struct MyTool;
    ///
    /// #[reverie::tool]
    /// impl Tool for MyTool {
    ///     /// Count of successful syscalls.
    ///     type ThreadState = u64;
    ///
    ///     async fn handle_syscall_event<T: Guest<Self>>(
    ///         &self,
    ///         guest: &mut T,
    ///         syscall: Syscall,
    ///     ) -> Result<i64, Error> {
    ///         let ret = match syscall {
    ///             Syscall::Open(syscall) => guest.tail_inject(syscall).await,
    ///             _ => guest.inject(syscall).await?,
    ///         };
    ///
    ///         // This is never called if we got the `open` syscall above!!
    ///         *guest.thread_state_mut() += 1;
    ///
    ///         Ok(ret)
    ///     }
    /// }
    /// ```
    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> !;

    /// Like [`Guest::inject`], but will retry the syscall if `EINTR` or
    /// `ERESTARTSYS` are returned.
    ///
    /// This is useful if we need to inject a syscall other than the one
    /// currently being handled in `handle_syscall_event`. If we don't retry
    /// interrupted syscalls, we could end up running the real syscall more than
    /// once.
    async fn inject_with_retry<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        loop {
            match self.inject(syscall).await {
                Ok(x) => return Ok(x),
                Err(Errno::EINTR) | Err(Errno::ERESTARTSYS) => continue,
                Err(other) => return Err(other),
            }
        }
    }

    /// Converts this `Guest<T>` such that it implements `Guest<U>`. This is
    /// useful when forwarding callbacks to a "child" tool.
    fn into_guest(&mut self) -> IntoGuest<Self, T> {
        IntoGuest::new(self)
    }

    /// Request that a single timer event occur in the future according to
    /// `sched`.
    ///
    /// There is only a single timer, so repeatedly setting a timer event delays
    /// the delivery of the single timer event that will eventually fire.
    ///
    /// Timer events are cancelled by the delivery of other event types. If
    /// receiving timer events is critical, your tool must override all event
    /// listeners and reschedule your timer within them.
    ///
    /// This requests a non-deterministic timer event, which will occur after _at
    /// least_ `sched` has elapsed, but no guarantees are made for delivery. As a
    /// result, the event will likely have much less overhead than one set with
    /// [`Guest::set_timer_precise`].
    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), Error>;

    /// Request that a single timer event occur in the future according to
    /// `sched`.
    ///
    /// Functions identically to [`Guest::set_timer`], except that the resulting
    /// event will be delivered _exactly_ when `sched` has elapsed. This results
    /// in a far higher overhead to deliver an event.
    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), Error>;

    /// Read a thread-local monotonic clock which is never reset. The starting
    /// value, resolution, and semantics of the ticks are
    /// implementation-specific.
    fn read_clock(&mut self) -> Result<u64, Error>;
}

/// Wraps a `Guest<T>` such that it implements `Guest<U>`.
///
/// # Limitations
///
/// `T` and `U` must have the same global state. This limitation may be removed
/// in the future.
pub struct IntoGuest<'a, G: ?Sized, U> {
    inner: &'a mut G,
    _phantom: core::marker::PhantomData<U>,
}

impl<'a, G: ?Sized, U> IntoGuest<'a, G, U> {
    /// Creates a new `IntoGuest`.
    pub fn new(guest: &'a mut G) -> Self {
        Self {
            inner: guest,
            _phantom: core::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<'a, G, U> GlobalRPC<U::GlobalState> for IntoGuest<'a, G, U>
where
    G: Guest<U> + ?Sized,
    U: Tool,
{
    async fn send_rpc(
        &self,
        message: <U::GlobalState as GlobalTool>::Request,
    ) -> Result<<U::GlobalState as GlobalTool>::Response, Error> {
        self.inner.send_rpc(message).await
    }

    fn config(&self) -> &<U::GlobalState as GlobalTool>::Config {
        self.inner.config()
    }
}

#[async_trait]
impl<'a, G, U, L> Guest<L> for IntoGuest<'a, G, U>
where
    G: Guest<U> + ?Sized,
    L: Tool<GlobalState = U::GlobalState>,
    U: Tool + AsMut<L>,
    U::ThreadState: AsRef<L::ThreadState> + AsMut<L::ThreadState>,
{
    type Memory = G::Memory;
    type Stack = G::Stack;

    fn tid(&self) -> Pid {
        self.inner.tid()
    }

    fn pid(&self) -> Pid {
        self.inner.pid()
    }

    fn ppid(&self) -> Option<Pid> {
        self.inner.ppid()
    }

    fn is_main_thread(&self) -> bool {
        self.inner.is_main_thread()
    }

    fn is_root_process(&self) -> bool {
        self.inner.is_root_process()
    }

    fn is_root_thread(&self) -> bool {
        self.inner.is_root_thread()
    }

    fn memory(&self) -> Self::Memory {
        self.inner.memory()
    }

    fn thread_state_mut(&mut self) -> &mut L::ThreadState {
        self.inner.thread_state_mut().as_mut()
    }

    fn thread_state(&self) -> &L::ThreadState {
        self.inner.thread_state().as_ref()
    }

    async fn stack(&mut self) -> Self::Stack {
        self.inner.stack().await
    }

    async fn daemonize(&mut self) {
        self.inner.daemonize().await
    }

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        self.inner.inject(syscall).await
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> ! {
        #![allow(unreachable_code)]
        self.inner.tail_inject(syscall).await
    }

    fn set_timer(&mut self, sched: TimerSchedule) -> Result<(), Error> {
        self.inner.set_timer(sched)
    }

    fn set_timer_precise(&mut self, sched: TimerSchedule) -> Result<(), Error> {
        self.inner.set_timer_precise(sched)
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        self.inner.read_clock()
    }
}
