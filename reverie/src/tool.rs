/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ExitStatus;
use crate::Pid;
use crate::Signal;
use crate::SignalEvent;
use crate::Subscription;
use crate::Tid;
use crate::error::Errno;
use crate::error::Error;
use crate::guest::Guest;
#[cfg(target_arch = "x86_64")]
use crate::rdtsc::Rdtsc;
#[cfg(target_arch = "x86_64")]
use crate::rdtsc::RdtscResult;

/// Who owns a guest thread: the single axis that governs *both* how the thread
/// executes *and* who owns its thread-synchronization primitives (`futex`,
/// `CLONE_CHILD_CLEARTID`).
///
/// These two concerns must never disagree. If a thread executes under the Tool
/// (registered in the Tool's scheduler) while its `futex` is serviced by the
/// host — or vice versa — a `pthread_join` deadlocks: the joiner's `FUTEX_WAIT`
/// waits in one domain while the exiting thread's `CLEARTID` wake fires in the
/// other, so the wake never reaches the waiter. Collapsing both concerns onto
/// this single enum makes that split-brain state *unrepresentable*: a thread is
/// either wholly `Tool`-owned or wholly `Host`-owned, never half of each.
///
/// A backend that runs child threads (e.g. the KVM backend, where each guest
/// thread runs on its own vCPU) selects the ownership for a tool's threads from
/// [`Tool::thread_ownership`] and uses the *same* value to decide (a) whether to
/// drive the thread through the Tool loop and (b) whether its `futex` routes to
/// the Tool. Backends that do not run child threads (e.g. ptrace, which already
/// routes every subscribed `futex` to the Tool) may ignore this value.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    serde::Deserialize
)]
pub enum ThreadOwnership {
    /// The Tool owns the thread: it is driven through the Tool loop (so the Tool
    /// observes every one of its syscalls and schedules it) and its `futex` /
    /// `CLEARTID` synchronization is serviced by the Tool. This is the safe,
    /// "follow children" default — it matches the golden ptrace backend, where
    /// the Tool (Detcore) owns every futex and no thread synchronization touches
    /// the host. Determinism can only be guaranteed for `Tool`-owned threads.
    #[default]
    Tool,
    /// The host owns the thread: it runs uninstrumented on the backend's direct
    /// execution personality and its `futex` / `CLEARTID` synchronization uses
    /// real host futex words.
    ///
    /// This is the `unmonitored_` opt-out. It is internally consistent (host
    /// execution + host futex, so it does not by itself deadlock a join), but it
    /// is a determinism/coverage hazard, **not** a correctness shortcut:
    ///
    /// * The Tool never sees the thread's syscalls, so it cannot sanitize,
    ///   record, or schedule them — determinism is **not** guaranteed for it or
    ///   for anything ordered against it.
    /// * Mixing `Host`-owned threads into a tool that expects to schedule the
    ///   whole thread group (e.g. Detcore) breaks that tool's model.
    ///
    /// It is deliberately not named `unsafe_`: it cannot cause undefined
    /// behavior, only nondeterminism and missed instrumentation.
    Host,
}

impl ThreadOwnership {
    /// Whether a thread with this ownership executes under the Tool loop (as
    /// opposed to the backend's direct host execution personality).
    pub fn executes_on_tool(self) -> bool {
        matches!(self, ThreadOwnership::Tool)
    }

    /// Whether a thread with this ownership executes on the backend's direct
    /// host execution personality (as opposed to the Tool loop). The exact
    /// inverse of [`Self::executes_on_tool`].
    pub fn executes_on_host(self) -> bool {
        matches!(self, ThreadOwnership::Host)
    }

    /// Whether the thread's `futex` / `CLEARTID` synchronization is serviced by
    /// the host rather than the Tool. This is the exact inverse of
    /// [`Self::executes_on_tool`]; the two are derived from the same value so
    /// execution and synchronization ownership can never disagree.
    pub fn futex_is_host_owned(self) -> bool {
        matches!(self, ThreadOwnership::Host)
    }
}

/// The global half of a complete Reverie tool.
///
/// One global instance of this type will exist at runtime (singleton). This
/// global state is shared by the tool across the whole process tree being
/// instrumented.
#[async_trait]
pub trait GlobalTool: Send + Sync + Default {
    /// The message to send to the global tool.
    type Request: Serialize + DeserializeOwned + Send;

    /// The result of sending the message.
    type Response: Serialize + DeserializeOwned + Send;

    /// Static, read-only configuration data that is available everywhere the
    /// tool runs code.
    type Config: Serialize + DeserializeOwned + Send + Sync + Clone + Default;

    /// Initialize the tool, allocating the global state.
    async fn init_global_state(_cfg: &Self::Config) -> Self {
        Default::default()
    }

    /// Install one run-scoped backend capability before the first guest hook.
    /// The default preserves backend-owned selection. A Tool that requires
    /// controlled process signals must reject missing capabilities here.
    fn install_backend_signal_control(
        &self,
        _control: Option<crate::BackendSignalControl>,
    ) -> Result<crate::BackendSignalControlMode, Error> {
        Ok(crate::BackendSignalControlMode::Unchanged)
    }

    /// Authorize the current real user-return boundary. The backend calls
    /// this outside signal locks; host callback arrival is not authorization.
    fn authorize_backend_signal_boundary(
        &self,
        _task: crate::SignalTaskIdentity,
    ) -> Result<Option<crate::SignalDeliveryPermit>, Error> {
        Ok(None)
    }

    /// Consume a real signal boundary before user entry. This hook must retain
    /// ownership across cancellation; it is not an ordinary grant or syscall.
    async fn on_backend_signal_boundary(
        &self,
        _receipt: crate::SignalBoundaryReceipt,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Reports final process cleanup after the leader has joined every guest
    /// thread and released their descriptor references, including its own.
    /// Only a backend offering `BackendSignalControl` sends this callback. A
    /// Tool may retain a fence awaiting it only with that capability installed
    /// in `ToolControlled` mode; a backend offering that mode must complete the
    /// callback after successful process retirement. A terminal boundary receipt
    /// can establish this fence and must remain able to cancel peer RPCs.
    /// The fence then keeps other processes from observing host-timed EOF.
    ///
    /// There need not be a preceding terminal boundary receipt: synchronous
    /// hardware faults can terminate a process without a delivery permit.
    /// Consumers must distinguish an exact known process with no outstanding
    /// controlled boundary from an early callback for a still-pending boundary.
    /// This notification alone does not order an otherwise unfenced exit.
    ///
    /// KVM emits this once from a successfully retired process leader, before
    /// its consuming hooks or joins of independent child processes. It is not
    /// a child-wait publication or an ordinary scheduling request. The callback
    /// must settle its exact process generation synchronously and must not wait
    /// for guest progress. A backend failure ends the run instead of emitting
    /// a successful retirement notification.
    fn on_backend_process_retired(&self, _event: BackendProcessRetirement) -> Result<(), Error> {
        Ok(())
    }

    /// Receive a (potentially) inter-process upcall on the global state object.
    /// This intended to be IPC, inter-process communication, in some backends,
    /// and a local method call in others, but never truly a communication
    /// between different machines.
    ///
    /// It receives a shared reference to the global state object, which must
    /// manage its own synchronization.
    ///
    /// On a fatal KVM or ordinary-ptrace run failure, an in-flight Tool callback and its inline
    /// RPC future may be dropped at any await point. RPC implementations must
    /// leave shared state safe for concurrent consuming cleanup when dropped;
    /// a normal response is not manufactured to complete the abandoned RPC.
    /// The terminal transition in `report_backend_failure` must also make
    /// cleanup possible for requests that were admitted but did not complete.
    async fn receive_rpc(&self, _from: Tid, _message: Self::Request) -> Self::Response;

    /// Reports a fatal backend failure before cleanup can wait on another Tool
    /// callback. This is a failed run, not a guest exit, signal, or RPC reply.
    /// Implementations must finish their terminal transition synchronously,
    /// including making concurrent consuming cleanup safe, before returning.
    /// Complete that transition before waking any failure subscriber. Several
    /// workers may report distinct errors in one run, so this method must be
    /// idempotent and preserve the first terminal cause. It must not wait for
    /// Tool callbacks or physical worker joins that depend on that transition.
    fn report_backend_failure(&self, _event: BackendFailure) {}

    /// Waits until this run cannot continue faithfully. Each call must subscribe
    /// independently: multiple Tool callbacks and the scheduler may be waiting.
    /// The default preserves Tools that do not own a scheduler.
    /// Returning allows the backend to drop in-flight callbacks, including
    /// `receive_rpc`, and proceed to consuming exit hooks. Shared state must
    /// already support that cleanup; returning is not an ordinary RPC reply.
    /// The ptrace backend polls the returned future again only after the waker
    /// it was last polled with fires, so a pending future must arrange that
    /// wake rather than rely on being polled again for another reason.
    async fn wait_for_backend_failure(&self) {
        std::future::pending::<()>().await
    }

    /// Reports that a backend observed a child transition and committed its
    /// waitability for the parent process.
    ///
    /// Backends that model child lifecycle outside the host kernel should
    /// invoke this at that boundary rather than inferring state from signal
    /// delivery. Backends whose host kernel owns child waitability may retain
    /// the default no-op.
    ///
    /// KVM polls this callback through its first suspension before making the
    /// status visible to a parent wait. A Tool-controlled signal scheduler must
    /// commit its publication or suppression decision in that synchronous
    /// prefix: it must neither reach an `.await` nor otherwise block on parent
    /// progress. The backend may already be holding a concurrent parent wait
    /// across the whole prefix, so waiting for that parent would deadlock.
    /// Work after that admission point may await parent progress; the backend
    /// retains and finishes the same pinned future after publishing waitability.
    /// If that synchronous prefix makes a concurrent parent runnable, the
    /// backend fences its wait until publication completes; the parent cannot
    /// observe the callback decision while still receiving a no-child-ready
    /// result.
    ///
    /// No callback is emitted when the exact parent generation is already
    /// terminal. Such a child is run-teardown state rather than a new waitable
    /// transition, and the backend auto-reaps its status. A terminal transitive
    /// ancestor does not suppress a child event while the direct parent remains
    /// logically live; that parent retains its exact wait semantics.
    /// For a live parent, callback admission only controls when waitability is
    /// exposed. It does not reap the backend status: a Tool-controlled wait must
    /// still be injected into the Guest before Tool shadow state is consumed.
    async fn on_backend_child_wait_event(
        &self,
        _event: BackendChildWaitEvent,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// Final descriptor cleanup and worker joins for one exact process lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendProcessRetirement {
    /// Process identity retained after its last live task has retired.
    pub process: crate::SignalProcessId,
    /// Authoritative process status after all guest threads have exited.
    pub status: ExitStatus,
}

/// The location of a fatal backend failure. The backend retains its typed cause;
/// this notification only ends dependent waits and must not invent guest status.
/// Host-side ordinary-ptrace capture failures use the run root's PID/TID with
/// a `ptrace stdout capture` or `ptrace stderr capture` phase. Those locations
/// identify the host run owner, not an inferred guest writer or guest failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendFailure {
    /// Guest process owning the failed operation.
    pub pid: Pid,
    /// Guest thread owning the failed operation.
    pub tid: Tid,
    /// Backend operation that failed.
    pub phase: &'static str,
}

/// A child state and waitability decision observed by an execution backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendChildWaitState {
    /// The child terminated with this exit status.
    Exited {
        /// The terminal status reported by the backend.
        status: ExitStatus,
        /// Whether the parent may consume this status with a wait syscall.
        /// Explicit `SIGCHLD` ignore and `SA_NOCLDWAIT` make this false.
        waitable: bool,
        /// Virtual child uid reported through `siginfo_t`.
        uid: u32,
        /// Child user CPU time in signed Linux clock ticks.
        user_ticks: i64,
        /// Child system CPU time in signed Linux clock ticks.
        system_ticks: i64,
    },
    /// The child entered a job-control stop for this signal number.
    Stopped(i32),
    /// A previously stopped child resumed.
    Continued,
}

/// A backend-observed child waitability decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendChildWaitEvent {
    /// Exact process lifetime whose wait syscalls may observe the transition.
    pub parent: crate::SignalProcessId,
    /// Exact child process lifetime that changed state.
    pub child: crate::SignalProcessId,
    /// The observed child state and whether it remains waitable.
    pub state: BackendChildWaitState,
}

impl BackendChildWaitEvent {
    /// Returns the complete terminal publication payload when the receiving
    /// parent remains inside the traced process tree.
    pub fn child_exit_completion(self) -> Option<crate::ChildExitCompletion> {
        let BackendChildWaitState::Exited {
            status,
            waitable,
            uid,
            user_ticks,
            system_ticks,
        } = self.state
        else {
            return None;
        };
        Some(crate::ChildExitCompletion {
            parent: self.parent,
            child: self.child,
            status,
            waitable,
            uid,
            user_ticks,
            system_ticks,
        })
    }
}

#[async_trait]
impl GlobalTool for () {
    type Request = ();
    type Response = ();
    type Config = ();

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
/// During fatal KVM run cleanup, asynchronous event callbacks may be dropped
/// at any await point. Their thread state is then passed to `on_exit_thread`
/// even if the start callback was never entered or did not finish. Exit hooks
/// must consume partially initialized state without requiring guest execution
/// or a normal response from an abandoned callback. This contract covers
/// returned runtime errors; arbitrary panic unwinding is not guaranteed to
/// invoke consuming hooks.
///
/// The ordinary ptrace backend owns execution-control state and wait statuses.
/// Tools must use Guest/backend APIs for resumes, stepping, detach/attach,
/// tracing options, wait/reap, and mutations of registers or signal information
/// (including PTRACE_SETSIGINFO). Raw operations outside those APIs invalidate
/// its current-stop ownership contract. Read-only ptrace/memory observations
/// are permitted; supported Guest injection can replace the current stop.
///
/// For ordinary non-syscall Errno-only callbacks, the return type erases causal
/// provenance. If a same-generation observation justifies yielding to the
/// original lifecycle owner, the callback's errno is retained as a diagnostic
/// while that owner supplies actual exit or exec status. A live callback error
/// remains fatal; an actually received Error::Tool or Error::Io is always fatal.
/// This is cancellation/death precedence, not attribution of an errno to a
/// memory access. The ptrace completion API exposes these records; successful
/// legacy waits project them away. No host timeout is used to choose death.
///
/// # Example
///
/// Here is an example of a tool that simply counts the number of syscalls
/// intercepted for each thread:
/// ```
/// use reverie::syscalls::*;
/// use reverie::*;
///
/// /// Our process-level state.
/// #[derive(Debug, Default, Clone)]
/// struct MyTool;
///
/// #[reverie::tool]
/// impl Tool for MyTool {
///     /// The global state type.
///     type GlobalState = ();
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
pub trait Tool: Send + Sync + Default {
    /// The type of the global half that goes along with this Local tool. By
    /// including this type, the Tool is actually a complete specification for an
    /// instrumentation tool.
    type GlobalState: GlobalTool;

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
    type ThreadState: Serialize + DeserializeOwned + Default + Send + Sync;

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

    /// How this tool's guest threads (children created via `CLONE_THREAD`) are
    /// owned. See [`ThreadOwnership`]. Called once per tree, like
    /// [`Tool::subscriptions`].
    ///
    /// The default is [`ThreadOwnership::Tool`] — the tool follows its children:
    /// every guest thread is driven through the Tool loop and its `futex`
    /// synchronization is serviced by the Tool. This is what a determinizing
    /// tool such as Detcore needs (it owns every futex and schedules every
    /// thread, matching the golden ptrace backend), and it is the safe default
    /// for any tool. Override it to return [`ThreadOwnership::Host`] only to opt
    /// a tool's child threads *out* of instrumentation, accepting the
    /// determinism/coverage hazard documented on that variant.
    ///
    /// Only backends that themselves run child threads (e.g. KVM) consult this;
    /// backends like ptrace that already route every subscribed `futex` to the
    /// Tool ignore it.
    fn thread_ownership(_cfg: &<Self::GlobalState as GlobalTool>::Config) -> ThreadOwnership {
        ThreadOwnership::Tool
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
    /// `init_thread_state` runs once for every constructed thread state. This
    /// callback runs once when that thread is allowed to start; cancellation
    /// before admission can consume the state without entering this callback.
    /// Fatal run failure may also drop it before completion. This callback is
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

    /// Enables acknowledgment of real KVM pending removals before thread start.
    /// Other Tools retain their existing pending-state behavior by default.
    /// The static-ELF runner requires effective [`ThreadOwnership::Tool`],
    /// including caller overrides, and rejects an incompatible Host choice
    /// before initializing GlobalState or consuming/executing the installed ELF.
    fn observe_signal_dequeues(_config: &<Self::GlobalState as GlobalTool>::Config) -> bool {
        false
    }

    /// Acknowledges one irreversible pending removal before any later Tool/guest work.
    /// The backend retains the journal entry until this returns success. An error
    /// is terminal; it is never a rollback or an ordinary guest syscall errno.
    /// Notifications are process-wide FIFO, but each runs on its removing Guest.
    /// Another owner can wait here before posting its next Tool scheduler request.
    /// An opted-in Tool must complete this acknowledgment without requiring that
    /// waiting owner to make progress or relinquish its scheduler token. FIFO
    /// sequencing alone does not establish deterministic event membership.
    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _dequeue: crate::SignalDequeue,
    ) -> Result<(), Errno> {
        Ok(())
    }

    /// Handles a structured guest signal immediately before a virtual backend
    /// delivers it.
    ///
    /// The default is a compatibility bridge to [`Self::handle_signal_event`]
    /// for signal numbers represented by [`Signal`]. It preserves the complete
    /// event when the legacy hook keeps it and preserves suppression when that
    /// hook drops it. Legacy signal-number replacement and raw real-time signal
    /// numbers are rejected with `ENOSYS`, because neither path can produce
    /// coherent replacement `siginfo_t`; a structured override must do that
    /// rather than silently losing information in the legacy enum.
    async fn handle_structured_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let signal = Signal::try_from(event.signal()).map_err(|_| Errno::ENOSYS)?;
        match self.handle_signal_event(guest, signal).await? {
            None => Ok(None),
            Some(replacement) if replacement as i32 == event.signal() => Ok(Some(event)),
            // Linux's ptrace reinjection path clears the old siginfo and
            // synthesizes SI_USER with the tracer parent's credentials when a
            // tracer changes the signal number. A virtual backend has no
            // faithful guest-visible identity for that host tracer. Refuse the
            // lossy legacy replacement; a structured-hook override can return
            // a new SignalEvent with coherent replacement metadata.
            Some(_) => Err(Errno::ENOSYS),
        }
    }

    /// Handles a timer event generated by a call to `Guest::set_timer`
    async fn handle_timer_event<T: Guest<Self>>(&self, _guest: &mut T) {}

    /// Called when a thread will exit shortly or has exited. That means there
    /// will be no more intercepted events on this thread.
    ///
    /// Serves as a "destructor" for the thread state, and thus takes it by move.
    /// KVM cleanup consumes each constructed state once on returned runtime
    /// errors or cancellation, including states whose `handle_thread_start`
    /// was never entered or completed. No further guest event is started to
    /// perform this cleanup. Panic unwinding may bypass the hook.
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
    /// On KVM this also consumes a constructed process cancelled before its
    /// initial thread starts, after the thread states have been consumed. It
    /// must support cleanup after fatal failure without ordinary guest RPC
    /// progress. Panic unwinding may bypass the hook.
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
    type GlobalState = ();
    type ThreadState = ();

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
