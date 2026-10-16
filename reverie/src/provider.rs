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
//! fixes the associated types, and today's syscall executor implements
//! [`LinuxProvider`].
//!
//! Being in core does not yet make it part of every backend's contract.
//! reverie-kvm is still its only implementer and its only caller; the other
//! backends (ptrace, DBT, in-guest/LiteInst and SaBRe) do not route
//! `Guest::inject` through it yet, and [`Backend`](crate::Backend) does not
//! carry a provider. Those are later steps, tracked in
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
/// Only [`ProviderOutcome::Return`] exists so far. The remaining outcomes (a
/// segment-base effect for `arch_prctl(ARCH_SET_FS/GS)`, a child created by
/// `fork`/`vfork`/`clone`/`clone3`, an exec, and an exit) are added in a later
/// step; until then an implementation reports them to its backend outside this
/// trait, after `execute` returns `Return` with the call's raw result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    /// The raw Linux result: a nonnegative value, or `-errno` for a Linux
    /// error.
    Return(i64),
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
///     type Memory = MyMemory;
///     type Error = MyError;
///
///     async fn execute(
///         &mut self,
///         request: &SyscallRequest,
///         memory: &MyMemory,
///     ) -> Result<ProviderOutcome, MyError> {
///         // ...
///     }
/// }
/// ```
///
/// The trait stays dyn-compatible: a backend may call it through
/// `&mut dyn LinuxProvider<Memory = _, Error = _>`.
#[async_trait::async_trait]
pub trait LinuxProvider: Send + Sync {
    /// The issuing task's guest memory as the backend hands it to the
    /// provider for one call.
    ///
    /// It is [`Sync`] because [`LinuxProvider::execute`]'s future holds a
    /// shared reference to it and must itself be [`Send`].
    type Memory: ?Sized + Sync;
    /// A broken backend or provider invariant that ends the run.
    type Error;

    /// Executes `request` as the issuing task and returns its outcome.
    ///
    /// The request's arguments are guest values, exactly as the guest or the
    /// Tool issued them: guest addresses and guest file descriptors. `memory`
    /// is the issuing task's guest memory, through which the provider reads
    /// and writes the call's guest operands.
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
    /// futures). That is why [`LinuxProvider::Memory`] must be [`Sync`]: the
    /// future holds `&Self::Memory`. This is unlike
    /// [`Backend::run`](crate::Backend::run), whose future need not be `Send`. The backend polls the future on the issuing
    /// task's host thread. A provider that never awaits completes on the first
    /// poll, so making the method `async` adds no suspension point to it. A
    /// provider that does await must assume the backend can drop the future at
    /// any of its await points, and must not leave its own state half
    /// committed across one.
    ///
    /// - `Ok(ProviderOutcome::Return(-errno))` is a Linux error and is
    ///   returned to the Tool as that errno.
    /// - `Err` is a broken invariant that ends the run; the backend must not
    ///   turn it into a guest-visible errno. Until [`ProviderOutcome`] carries
    ///   exits and interruptions, two errors are dispositions rather than
    ///   failures: a thread-group exit the provider already committed, and a
    ///   blocking read that was cancelled and must produce no syscall result
    ///   (in reverie-kvm, `Error::ChildWaitGroupExit` and
    ///   `Error::TerminalReadCancelled`).
    /// - A request the provider does not implement is answered as the module
    ///   documentation's error model says, with a typed refusal recorded for
    ///   [`LinuxProvider::take_unsupported_refusal`].
    async fn execute(
        &mut self,
        request: &SyscallRequest,
        memory: &Self::Memory,
    ) -> Result<ProviderOutcome, Self::Error>;

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
