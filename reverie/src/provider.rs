/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The provider-neutral interface of the Linux syscall provider under a
//! Reverie backend's `Guest::inject`: [`LinuxProvider`] and
//! [`ProviderOutcome`], the raw [`SyscallRequest`] it executes, and the memory
//! interfaces a provider uses ([`GuestMemoryAccess`] and [`AddressSpace`]).
//!
//! This module is part of Reverie's core, next to [`Tool`](crate::Tool),
//! [`Guest`](crate::Guest) and [`Backend`](crate::Backend). It was step U6a
//! of the provider seam (<https://github.com/rrnewton/hermit/issues/4485>,
//! epic <https://github.com/rrnewton/hermit/issues/4492>) as its own crate,
//! reverie-linux-provider, which now only re-exports this module. It names no
//! backend: reverie-kvm implements the memory traits for its guest arena and
//! fixes the associated types; reverie-kvm's syscall executor and the
//! crate-private `HostLinux` providers of reverie-ptrace, reverie-inguest and
//! reverie-dbt implement [`LinuxProvider`].
//!
//! Being in core does not yet make it part of every backend's contract. Four
//! backend implementations call it. In reverie-kvm the syscall executor is the
//! provider. In reverie-ptrace the provider is the host kernel: a
//! crate-private `HostLinux` runs each injected call in the stopped tracee.
//! In reverie-inguest, the runtime LiteInst and in-guest-trap share, the
//! provider is also the host kernel: the final forward of a call `InGuest`
//! has admitted runs through a crate-private `HostLinux`, which issues the
//! call on the guest thread itself through the runtime's trusted syscall
//! gate. Plain fork, native exec, `pkey_alloc`, the `brk(0)` probe and the
//! `close_range` split that protect the runtime's mappings and descriptors,
//! and the syscalls of the runtime's virtual signal calls still reach Linux
//! directly from the backend. Its `SuccessorImageGuest`, the feature-gated
//! `Guest` of a native exec's successor image, does not route through the
//! provider yet. In reverie-dbt, returning calls that pass backend admission
//! reach a private `HostLinux` through the existing full native invoker on the
//! issuing task. The invocation keeps its exact purpose, native ownership,
//! descriptor/lifecycle bookkeeping and interruption receipt. Tool-requested
//! `close_range` fragments in admission, deferred tail execution, native
//! copied-child/lifecycle paths and coordinator transport calls remain outside
//! that provider route. SaBRe does not route `Guest::inject` through it yet,
//! and [`Backend`](crate::Backend) does not carry a provider. The remaining
//! routes are later steps, tracked in
//! <https://github.com/rrnewton/hermit/issues/4485>.
//!
//! # Rules every provider is held to
//!
//! - **One provider per run.** The provider owns the run's Linux state: the
//!   file-descriptor table, the memory map and the task table. Calls are never
//!   routed per syscall to different providers, because that would split this
//!   state. The backend may reach the provider through a short-lived handle per
//!   guest callback, which is why the methods take `&mut self`; the handle is
//!   only a view of the one provider.
//! - **Concurrency.** [`LinuxProvider::execute`] runs on the issuing task's
//!   host thread. The provider must not assume that no other task executes
//!   at the same time. Calls are serialised only under a Tool that
//!   sequentialises guest threads, and only while the issuing task holds its
//!   scheduler turn; even then, a call the Tool classifies as external
//!   blocking (a blocking read, `rt_sigsuspend`) is injected in the
//!   background, off the run queue, and overlaps other tasks' turns and
//!   their `execute` calls. A Tool that does not sequentialise injects from
//!   every task's own thread concurrently, and threads the backend runs
//!   outside the Tool execute at any time. Provider state shared between
//!   tasks is therefore protected against concurrent guest tasks, Tool-owned
//!   tasks and host-owned workers alike, with a lock order the implementation
//!   documents. A provider may block the host thread, as a blocking read or a
//!   futex wait does, but must not hold backend admission across the block.
//! - **Error model.** A Linux error is an ordinary result: `-errno`. A broken
//!   backend or provider invariant is an `Err` that ends the run and is never
//!   encoded as an errno. A request the provider does not implement is
//!   answered with the errno Linux gives for a missing feature (normally
//!   `ENOSYS`) and records a typed refusal, which the backend reads through
//!   [`LinuxProvider::take_unsupported_refusal`] and reports loudly; the
//!   errno alone is not the report. This is the contract providers are held
//!   to; an implementation that does not yet meet it documents its
//!   deviation on its impl.
//! - **Determinism.** A result is a deterministic function of the provider's
//!   state, the request, the guest memory it reads and host-file contents.
//!   The provider must not read host time, host randomness or other
//!   host-varying state to produce a guest-visible value, and must not invent
//!   or sanitise values for determinism: time, randomness, credentials,
//!   `/proc` content and pid numbering belong to the Tool (Detcore). If a
//!   provider needs a fixed value to be faithful, such as its own pid
//!   numbering, the Tool supplies it through configuration.

mod memory;
mod request;

pub use memory::Access;
pub use memory::AddressSpace;
pub use memory::Discarded;
pub use memory::GuestMemoryAccess;
pub use memory::LentOperand;
pub use memory::LentOperandMut;
pub use memory::MapError;
pub use memory::RangeState;
pub use memory::UserLayout;
pub use request::SyscallRequest;

/// What one executed syscall produced.
///
/// Effects are already committed to the provider's state when the outcome is
/// returned.
///
/// `Plan` is the provider's own description of a process action the backend
/// must carry out ([`LinuxProvider::Plan`]).
///
/// [`ProviderOutcome::Cancelled`] and [`ProviderOutcome::ThreadGroupExited`]
/// produce no syscall result at all: the call never returns to the issuing
/// task. [`ProviderOutcome::Interrupted`] produces none either: the call did
/// not run. The remaining outcome, an exit, is added in a later step. Until then
/// an implementation reports it to its backend outside this trait, after
/// `execute` returns `Return` with the call's raw result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutcome<Plan> {
    /// The raw Linux result: a nonnegative value, or `-errno` for a Linux
    /// error.
    Return(i64),
    /// A blocking call was cancelled because the issuing task was retired
    /// or cancelled (for example a read of inherited standard input). There is
    /// no result. The backend must neither fabricate one nor resume the
    /// Tool's handler, and it ends the issuing task's handler without a
    /// result.
    Cancelled,
    /// The call observed that the issuing task's thread group has already
    /// exited with `status`, an exit the provider committed before or during
    /// the call (for example a child wait interrupted by a sibling's
    /// `exit_group`). There is no result. The backend ends the handler and
    /// reports the group exit with this status.
    ThreadGroupExited {
        /// The committed thread-group exit status.
        status: crate::ExitStatus,
    },
    /// The call succeeded with `result` and the provider staged a process
    /// action that the backend must carry out before the call completes: a
    /// child created by `fork`, `vfork`, `clone` or `clone3`, or an exec.
    /// `result` is always a successful (nonnegative) result, and the call's
    /// final result is what the backend's completion reports. A plan that
    /// fully describes the action is carried out at most once. A plan that
    /// is only a token for an action the provider keeps staged may be
    /// deferred or dropped without completing the action, which then stays
    /// with the provider, and the provider may let the backend complete an
    /// action for which it issued no token (for example one staged by an
    /// earlier call).
    Process {
        /// The raw successful result the provider computed.
        result: i64,
        /// The provider's description of the process action.
        plan: Plan,
    },
    /// The call succeeded with `result` and set the issuing task's FS or GS
    /// segment base to `base` (`arch_prctl(ARCH_SET_FS)` or `ARCH_SET_GS`).
    /// The provider's own record of the base is already updated. The backend
    /// makes the task's CPU state use `base` before the task next runs in user
    /// mode. Until then a later base set for the same register of the same
    /// task replaces this one, and an exec of the task discards it.
    SegmentBase {
        /// The raw successful result the provider computed.
        result: i64,
        /// Which segment register's base was set.
        register: SegmentRegister,
        /// The new base address.
        base: u64,
    },
    /// A signal stopped the call before it ran. The call had no effect and
    /// there is no result. The backend may run the call again, or report
    /// the interruption to the Tool as `ERESTARTSYS`, which is what
    /// [`Guest::inject`](crate::Guest::inject) documents for a call that a
    /// signal stopped before it ran.
    ///
    /// A call that ran and returned `-EINTR` or `-ERESTARTSYS` is a
    /// [`ProviderOutcome::Return`], not this. Only a provider whose kernel is
    /// the host kernel produces it, where the guest task itself runs the call
    /// and a signal can stop the task before the syscall instruction.
    Interrupted,
}

/// A segment register whose base a task can set
/// ([`ProviderOutcome::SegmentBase`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentRegister {
    /// The FS register, which x86-64 Linux uses for thread-local storage.
    Fs,
    /// The GS register.
    Gs,
}

/// Executes Linux syscalls on behalf of guest tasks: the provider-neutral core
/// of the kernel under `Guest::inject`.
///
/// See the module documentation for the rules every method is held to (one
/// provider per run, concurrency, the error model and the determinism
/// obligations). This trait is not generic over the Tool: creating Tool state
/// for a new child is backend work.
///
/// [`LinuxProvider::execute`] is an `async` method, so an implementation is
/// written inside a `#[reverie::provider]` block (an alias of
/// `async_trait`, as `#[reverie::tool]` is):
///
/// ```ignore
/// #[reverie::provider]
/// impl LinuxProvider for MyProvider {
///     type Context = MyContext;
///     type Plan = MyPlan;
///     type Error = MyError;
///
///     async fn execute(
///         &mut self,
///         task: reverie::Tid,
///         request: &SyscallRequest,
///         cx: &mut MyContext,
///     ) -> Result<ProviderOutcome<MyPlan>, MyError> {
///         // ...
///     }
/// }
/// ```
///
/// The trait stays dyn-compatible: a backend may call it through
/// `&mut dyn LinuxProvider<Context = _, Plan = _, Error = _>`.
#[async_trait::async_trait]
pub trait LinuxProvider: Send + Sync {
    /// The backend's per-call context: what the provider needs from the
    /// backend to execute one call as the issuing task. The backend lends it
    /// for exactly one [`LinuxProvider::execute`] call, as `&mut` so that the
    /// provider may drive it. A provider never keeps it past the call.
    ///
    /// In reverie-kvm it is the guest memory arena. In reverie-ptrace, whose
    /// provider is the host kernel, it is the backend's handle on the
    /// stopped guest task: the tracee, which also owns its stop-wait. In
    /// reverie-inguest, whose provider is also the host kernel, it is a token
    /// for the runtime's trusted syscall gate on the calling guest thread,
    /// built only after the backend's admission filters have run.
    ///
    /// It must be [`Send`] because [`LinuxProvider::execute`]'s future holds
    /// `&mut Self::Context` and must itself be `Send` (see the method's
    /// documentation).
    type Context: ?Sized + Send;
    /// The provider's plan for a process action (a child or an exec) that the
    /// backend carries out, returned in [`ProviderOutcome::Process`]: either
    /// a full description, or a token for an action the provider keeps
    /// staged until the backend completes it. Its shape is the provider's
    /// own, because what a provider needs the backend to do differs between
    /// kernels. It is [`Send`] because the backend holds it across awaits in
    /// a `Send` future.
    type Plan: Send;
    /// A broken backend or provider invariant that ends the run.
    type Error;

    /// Executes `request` as the issuing task and returns its outcome.
    ///
    /// `task` is the issuing task, named by the guest tid the Tool sees
    /// through `Guest::tid`. A provider bound to a single task checks it and
    /// returns `Err` if it names a different task, which is a broken backend
    /// invariant. A provider that keys per-task state by tid uses it to find
    /// that state. Translating pids belongs to the Tool, not to the provider.
    ///
    /// The request's arguments are guest values, exactly as the guest or the
    /// Tool issued them: guest addresses and guest file descriptors. `cx` is
    /// the backend's per-call context ([`LinuxProvider::Context`]), through
    /// which the provider reaches the call's guest operands.
    ///
    /// Called only from the backend's injection path, after the backend's own
    /// admission checks, on the issuing task's host thread (see the module
    /// documentation's concurrency rule for what may run at the same time).
    ///
    /// The method is `async` because a provider whose kernel is the host
    /// kernel may have to wait for the guest task itself to run the call, as
    /// the ptrace backend waits for a tracee stop. The returned future is
    /// [`Send`], because the backend awaits it inside `Guest::inject`, whose
    /// future is `Send` ([`Guest`](crate::Guest) is a `Send` trait with `Send`
    /// futures). The future holds `&mut Self::Context`, so
    /// [`LinuxProvider::Context`] must be [`Send`]. This is unlike
    /// [`Backend::run`](crate::Backend::run), whose future need not be
    /// `Send`. The backend polls the future on the issuing task's host
    /// thread. A provider that never awaits completes on the first
    /// poll, so making the method `async` adds no suspension point to it. A
    /// provider that does await must assume the backend can drop the future at
    /// any of its await points, and must not leave its own state half
    /// committed across one.
    ///
    /// - `Ok(ProviderOutcome::Return(-errno))` is a Linux error and is
    ///   returned to the Tool as that errno.
    /// - `Ok(ProviderOutcome::Process { result, plan })` is a successful call
    ///   whose process action the backend carries out before the call
    ///   completes.
    /// - `Ok(ProviderOutcome::SegmentBase { .. })` is a successful call that
    ///   set a segment base the backend must apply.
    /// - `Ok(ProviderOutcome::Cancelled)` and
    ///   `Ok(ProviderOutcome::ThreadGroupExited { .. })` produce no syscall
    ///   result; see [`ProviderOutcome`].
    /// - `Ok(ProviderOutcome::Interrupted)` is a call that did not run: a
    ///   signal stopped it first.
    /// - `Err` is a broken invariant that ends the run; the backend must not
    ///   turn it into a guest-visible errno.
    /// - A request the provider does not implement is answered as the module
    ///   documentation's error model says, with a typed refusal recorded for
    ///   [`LinuxProvider::take_unsupported_refusal`].
    async fn execute(
        &mut self,
        task: crate::Tid,
        request: &SyscallRequest,
        cx: &mut Self::Context,
    ) -> Result<ProviderOutcome<Self::Plan>, Self::Error>;

    /// Takes the typed refusal recorded by the last [`LinuxProvider::execute`],
    /// when the provider declined that request as an operation it does not
    /// implement, and clears it.
    ///
    /// The backend reads it immediately after a successful `execute`, so a
    /// refusal always describes the request that produced it; a provider
    /// discards any refusal left by an earlier syscall when `execute` begins.
    /// Under the error model, `None` means the request was implemented,
    /// whatever its result. The refusal exists so that unsupported behaviour
    /// is reported loudly instead of passing as a plausible Linux errno.
    fn take_unsupported_refusal(&mut self) -> Option<crate::UnsupportedRefusal> {
        None
    }
}
