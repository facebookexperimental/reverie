/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The API that a Reverie tool (client) should implement.
//!
//! Reverie tools consist of two portions: the global and local (per-guest
//! thread) instrumentation, though in some backends these will execute in the
//! same process.

use async_trait::async_trait;
use reverie_syscalls::Syscall;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Errno;
use crate::error::Error;
use crate::guest::Guest;
#[cfg(target_arch = "x86_64")]
use crate::rdtsc::Rdtsc;
#[cfg(target_arch = "x86_64")]
use crate::rdtsc::RdtscResult;
use crate::ExitStatus;
use crate::Pid;
use crate::Signal;
use crate::Subscription;
use crate::Tid;

/// The global half of a complete Reverie tool.
///
/// One global instance of this type will exist at runtime (singleton). This
/// global state is shared by the tool across the whole process tree being
/// instrumented.
#[async_trait]
pub trait GlobalTool: Send + Sync + Default {
    /// The message to send to the global tool.
    type Request: Serialize + DeserializeOwned + Send = ();

    /// The result of sending the message.
    type Response: Serialize + DeserializeOwned + Send = ();

    /// Static, read-only configuration data that is available everywhere the
    /// tool runs code.
    type Config: Serialize + DeserializeOwned + Send + Sync + Clone + Default = ();

    /// Initialize the tool, allocating the global state.
    async fn init_global_state(_cfg: &Self::Config) -> Self {
        Default::default()
    }

    /// Receive a (potentially) inter-process upcall on the global state object.
    /// This intended to be IPC, inter-process communication, in some backends,
    /// and a local method call in others, but never truly a communication
    /// between different machines.
    ///
    /// It receives a shared reference to the global state object, which must
    /// manage its own synchronization.
    async fn receive_rpc(&self, _from: Tid, _message: Self::Request) -> Self::Response;
}

#[async_trait]
impl GlobalTool for () {
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _from: Tid, _message: ()) {}
}

/// A trait that every Reverie *tool* must implement. The primary function of the
/// tool specifies how syscalls and signals are handled.
///
/// The type that a `Tool` is implemented for represents the process-level state.
/// That is, one runtime instance of this type will be created for each guest
/// process. This type is in turn a factory for *thread level states*, which are
/// allocated dynamically upon guest thread creation. Instances of the thread
/// state are also managed by Reverie.
///
/// # Example
///
/// Here is an example of a tool that simply counts the number of syscalls
/// intercepted for each thread:
/// ```
/// use reverie::syscalls::*;
/// use reverie::*;
/// use serde::{Deserialize, Serialize};
///
/// /// Our process-level state.
/// #[derive(Debug, Serialize, Deserialize, Default, Clone)]
/// struct MyTool;
///
/// #[reverie::tool]
/// impl Tool for MyTool {
///     /// Count of syscalls.
///     type ThreadState = u64;
///
///     async fn handle_syscall_event<T: Guest<Self>>(
///         &self,
///         guest: &mut T,
///         syscall: Syscall,
///     ) -> Result<i64, Error> {
///         *guest.thread_state_mut() += 1;
///
///         // Inject the syscall. If we don't do this, the syscall will be
///         // supressed.
///         let ret = guest.inject(syscall).await?;
///
///         Ok(ret)
///     }
/// }
/// ```
#[async_trait]
pub trait Tool: Serialize + DeserializeOwned + Send + Sync + Default {
    /// The type of the global half that goes along with this Local tool. By
    /// including this type, the Tool is actually a complete specification for an
    /// instrumentation tool.
    type GlobalState: GlobalTool = ();

    /// Tool-state specific to each guest thread. If unset, this defaults to the
    /// unit type `()`, indicating that the tool does not have thread-level
    /// state.
    ///
    /// Both thread-local and process-local state may have to be migrated between
    /// address spaces by a Reverie backend. Hence the `ThreadState` type must
    /// implement [`Serialize`] and [`DeserializeOwned`].
    ///
    /// The thread-local storage must be in a good, consistent state when each
    /// handler returns, and also when handlers yield.
    ///
    /// [`Serialize`]: serde::Serialize
    /// [`DeserializeOwned`]: serde::de::DeserializeOwned
    type ThreadState: Serialize + DeserializeOwned + Default + Send + Sync = ();

    /// A common constructor that initializes state when a process is created,
    /// including the guest's initial, root process. Of course, every process
    /// includes at least one thread, but the process level state is allocated
    /// before thread level-state for the process's main thread is allocated.
    ///
    /// For now this method assumes access to the global state, but that may
    /// change.
    fn new(_pid: Pid, _cfg: &<Self::GlobalState as GlobalTool>::Config) -> Self {
        Default::default()
    }

    /// Events the tool subscribes to. This is only called *once* for the entire
    /// tree. By default, all syscalls are traced (but CPUID/RDTSC instructions
    /// are not).
    fn subscriptions(_cfg: &<Self::GlobalState as GlobalTool>::Config) -> Subscription {
        Subscription::all_syscalls()
    }

    /// A guest process creates additional threads, which need their tool state
    /// initialized. This method returns a newly-allocated thread state. This
    /// method necessarily runs before the first instruction of a newly created
    /// guest thread.
    ///
    /// If the parent thread is running a handler which injects a fork, this
    /// callback executes on behalf of the child and may observe the parent's
    /// thread-local state just this one time. It is important to know WHEN that
    /// view into the parent's thread-state occurs. We currently guarantee that
    /// this is *immediately* upon the `.inject()` call that creates the child
    /// thread. Any later point of execution for `init_thread_state` could delay
    /// the creation of the child arbitrarily long, waiting for the parent to
    /// relinquish its hold on its own thread-local state.
    ///
    /// The parent Tid always refers to the thread-ID that called
    /// fork/clone/vfork in order to create the new guest thread. Access to the
    /// parent's state allows the child state to be defined in terms of modifying
    /// the parent's, such as tracking the depth in a tree of threads.
    ///
    /// # Arguments
    ///
    /// * `&self`: a handle on the process-level state.
    /// * `child`: the new child thread's ID.
    /// * `parent`: A tuple of the parent thread ID and a snapshot of the
    ///    parent's thread-local state. This is `None` if the current thread is the
    ///    root of the guest process tree.
    fn init_thread_state(
        &self,
        _child: Tid,
        _parent: Option<(Tid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        Default::default()
    }

    /// Similar to `handle_syscall_event`, except this traps the first
    /// instruction executed by a new thread. Typical uses of this method include
    /// delaying thread execution or running initialization actions (injections
    /// or rpcs).
    ///
    /// Both this callback and `init_thread_state` run once for every newly
    /// created thread. The important difference is that this callback is
    /// guaranteed to run independently from the parent. It does not view the
    /// parents state, and this handler runs in its own asynchronous task.
    /// Blocking this task on an `.await` will not interfere with the progress of
    /// the parent thread.
    ///
    /// # Arguments
    ///
    ///  * `&self`: The process-level state for this thread.
    ///  * `guest`: A handle to the guest thread.
    async fn handle_thread_start<T: Guest<Self>>(&self, _guest: &mut T) -> Result<(), Error> {
        Ok(())
    }

    /// Called upon a *successful* execve. In `handle_syscall_event`, after
    /// injecting `execve`, it is not possible to run code after a successful
    /// `execve` because it never returns.
    ///
    /// NOTE: Thread and process state are unchanged across this execve boundary.
    /// Thus, this can be useful for doing something like counting the number of
    /// times a process successfully calls `execve`.
    async fn handle_post_exec<T: Guest<Self>>(&self, _guest: &mut T) -> Result<(), Errno> {
        Ok(())
    }

    /// The tool receives an event from the guest, via the Reverie program
    /// instrumentation. A Reverie syscall handler fires in the moment *before* a
    /// guest syscall executes (like a "prehook").
    ///
    /// After the event is trapped, control transfers to `handle_syscall_event`
    /// which is put in temporary control of the guest thread. Via `guest`, we
    /// can directly access the thread/process local state, and we can also
    /// remotely access (1) the global state and (2) the memory/registers of the
    /// guest thread it controls.
    ///
    /// NOTE: Only syscalls we have subscribed to [`Tool::subscriptions`] will
    /// have this handler invoked.
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        c: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(c).await
    }

    /// CPUID is trapped, the tool should implement this function to return
    /// `[eax, ebx, ecx, edx]`.
    ///
    /// NOTE:
    ///  * This is never called by default unless cpuid events are subscribed
    ///    to.
    ///  * This is only available on x86_64.
    #[cfg(target_arch = "x86_64")]
    async fn handle_cpuid_event<T: Guest<Self>>(
        &self,
        _guest: &mut T,
        eax: u32,
        ecx: u32,
    ) -> Result<raw_cpuid::CpuIdResult, Errno> {
        Ok(raw_cpuid::cpuid!(eax, ecx))
    }

    /// rdtsc/rdtscp is trapped, the tool should implement this function to
    /// return the counter.
    ///
    /// NOTE:
    ///  * This is never called by default unless rdtsc events are subscribed
    ///    to.
    ///  * This is only available on x86_64.
    #[cfg(target_arch = "x86_64")]
    async fn handle_rdtsc_event<T: Guest<Self>>(
        &self,
        _guest: &mut T,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        Ok(RdtscResult::new(request))
    }

    /// Handles a guest's signal before it is delivered to guest.
    ///
    /// # Return value
    ///  - `Some(sig)`: The signal `sig` will be delivered to guest.
    ///  - `None`: The signal is supressed and never delivered to the guest.
    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        _guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        Ok(Some(signal))
    }

    /// Handles a timer event generated by a call to `Guest::set_timer`
    async fn handle_timer_event<T: Guest<Self>>(&self, _guest: &mut T) {}

    /// Called when a thread will exit shortly or has exited. That means there
    /// will be no more intercepted events on this thread.
    ///
    /// Serves as a "destructor" for the thread state, and thus takes it by move.
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Tid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called when a process will exit shortly or has exited. That means there
    /// will be no more intercepted events on from any thread within this
    /// process.
    ///
    /// Serves as a "destructor" for the process state (`self`), and thus takes
    /// it by move.
    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        _global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A "noop" tool that doesn't do anything.
impl Tool for () {
    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}

/// A handle to send messages to the global state (potentially a remote,
/// inter-process communication).
#[async_trait]
pub trait GlobalRPC<G: GlobalTool>: Sync {
    /// Send an RPC message to wherever the global state is stored, synchronously
    /// blocks the current thread until a response is received.
    async fn send_rpc(&self, message: G::Request) -> G::Response;

    /// Return the read-only tool configuration
    fn config(&self) -> &G::Config;
}
