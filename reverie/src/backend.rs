/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The API that a Reverie *backend* (as opposed to a *tool*) must implement.
//!
//! A Reverie program has two halves:
//!
//!  * A [`Tool`] (see [`crate::tool`]) says *what* to do when the guest hits a
//!    trappable event -- a syscall, a signal, a `cpuid`/`rdtsc`, a thread
//!    start, an exit, and so on. Tool authors are the primary audience of this
//!    library.
//!  * A **backend** says *how* those events are trapped and how the tool's code
//!    is actually run against a live guest process tree. The backend owns
//!    process supervision: spawning the guest, intercepting its syscalls,
//!    routing each event to the tool, hosting the tool's global state, and
//!    tearing everything down.
//!
//! [`reverie-ptrace`][reverie_ptrace] is the reference backend. It uses
//! `ptrace` + `seccomp` to trap events from *outside* the guest, keeping all
//! tool state centralized in the tracer's address space. A future backend might
//! instead rewrite the guest's binary and run handlers *inside* the guest with
//! near-function-call overhead -- but from the tool's point of view nothing
//! changes, because both backends honor the same contract.
//!
//! # Why this trait exists
//!
//! Historically the backend contract was *implicit*: the only way to learn what
//! a backend had to provide was to read `reverie-ptrace`'s `TracerBuilder` /
//! `Tracer` types and notice which pieces of the [`Tool`]/[`GlobalTool`]
//! lifecycle they drove. That left "what does it mean to implement a Reverie
//! backend?" as folklore, and led to partial building blocks (e.g. a bare VM or
//! binary-rewriter) being mistaken for full backends when they could not, in
//! fact, host an arbitrary [`Tool`].
//!
//! The [`Backend`] trait makes the minimal contract explicit and machine
//! checked. It is intentionally small -- a real backend will usually expose a
//! richer, backend-specific builder as well (see the "Beyond the minimal
//! contract" section below) -- but every backend must at least be able to
//! satisfy [`Backend::run`].
//!
//! [reverie_ptrace]: https://docs.rs/reverie-ptrace

use async_trait::async_trait;

use crate::Error;
use crate::ExitStatus;
use crate::GlobalTool;
use crate::Tool;
use crate::process::Command;

/// A Reverie backend: a swappable implementation of process supervision and
/// event interception, equivalent in role to `reverie-ptrace`.
///
/// Implementing this trait is a promise that the backend can host an
/// **arbitrary** tool `T: `[`Tool`] -- the tool type is a generic parameter of
/// [`run`](Backend::run), never hard-coded -- and drive the complete tool
/// lifecycle against a real guest process tree.
///
/// # The contract
///
/// A conforming backend must, given a [`Command`] and the tool's static
/// configuration:
///
/// 1. **Initialize global state.** Call
///    [`GlobalTool::init_global_state`] once for the whole guest tree and keep
///    the resulting singleton reachable for the duration of the run. Every
///    place the tool can send an RPC
///    (see [`GlobalRPC`](crate::GlobalRPC)) must reach *this* instance.
/// 2. **Compute subscriptions.** Call [`Tool::subscriptions`] once and only
///    trap the event streams the tool asked for. Delivering unsubscribed events
///    -- or dropping subscribed ones -- is a contract violation.
/// 3. **Spawn and supervise the guest.** Start `command` as the root guest
///    process and manage its whole process/thread tree (`fork`/`clone`/`vfork`
///    and `execve`), including stdio.
/// 4. **Allocate per-process and per-thread state.** Call [`Tool::new`] for
///    each new process and [`Tool::init_thread_state`] for each new thread, at
///    the points documented on those methods.
/// 5. **Route every subscribed event to the tool.** Drive
///    [`Tool::handle_syscall_event`], [`Tool::handle_signal_event`],
///    [`Tool::handle_thread_start`], [`Tool::handle_post_exec`],
///    [`Tool::handle_timer_event`], and (on x86-64, when subscribed)
///    [`Tool::handle_cpuid_event`] / [`Tool::handle_rdtsc_event`]. Each handler
///    is given a [`Guest`](crate::Guest) handle through which the tool inspects
///    and mutates the guest and talks to global state.
/// 6. **Run destructors.** Call [`Tool::on_exit_thread`] and
///    [`Tool::on_exit_process`] as threads and processes wind down.
/// 7. **Return the result.** When the root guest exits, yield the guest's
///    [`ExitStatus`] together with the (now uniquely owned) global state so the
///    caller can read out whatever the tool accumulated.
///
/// The associated `GlobalState` a backend must return is exactly
/// [`T::GlobalState`](Tool::GlobalState); returning `(ExitStatus,
/// T::GlobalState)` is what lets a caller do useful work with the tool after
/// the guest is gone (counting syscalls, collecting a trace, etc.).
///
/// # Example implementation
///
/// A thin backend that simply delegates to a lower-level tracer (this is
/// essentially what `reverie-ptrace`'s `PtraceBackend` does):
///
/// ```ignore
/// use reverie::{Backend, Error, ExitStatus, GlobalTool, Tool};
/// use reverie::process::Command;
///
/// struct MyBackend;
///
/// #[reverie::backend(?Send)]
/// impl Backend for MyBackend {
///     async fn run<T: Tool + 'static>(
///         command: Command,
///         config: <T::GlobalState as GlobalTool>::Config,
///     ) -> Result<(ExitStatus, T::GlobalState), Error> {
///         // `init_global_state`, `subscriptions`, spawning, event routing, and
///         // teardown all happen inside the tracer, which honors the contract
///         // above.
///         let tracer = SomeTracer::<T>::new(command).config(config).spawn().await?;
///         tracer.wait().await
///     }
/// }
/// ```
///
/// # Beyond the minimal contract
///
/// [`run`](Backend::run) is deliberately the *smallest* useful entry point: run
/// a command under a tool and hand back the result. Real backends typically
/// layer extra, backend-specific capabilities on top -- for example
/// `reverie-ptrace` additionally offers output capture, a GDB server, and
/// spawning a *function* (rather than a `Command`) under instrumentation. Those
/// live on the backend's own builder type; this trait only fixes the common
/// denominator every backend shares so that tools -- and readers -- have one
/// explicit definition of "what a Reverie backend is".
///
/// [`Guest`]: crate::Guest
///
/// # A note on `Send`
///
/// The returned future is **not** required to be [`Send`]. The reference
/// `ptrace` backend is inherently single-threaded -- all ptrace operations for
/// a guest must happen on one thread -- so requiring `Send` would exclude it.
/// Drive [`run`](Backend::run) on a current-thread (`LocalSet`) executor.
#[async_trait(?Send)]
pub trait Backend {
    /// Run `command` as the root of a guest process tree, instrumented by the
    /// tool `T`, and drive it to completion.
    ///
    /// This performs the whole lifecycle described in the [trait
    /// documentation](Backend): it initializes `T`'s global state from `config`,
    /// computes the tool's subscriptions, spawns and supervises the guest,
    /// routes every subscribed event to `T`'s handlers, and runs the tool's
    /// exit destructors.
    ///
    /// On success it returns the root guest's [`ExitStatus`] together with the
    /// tool's final [`GlobalState`](Tool::GlobalState), which is uniquely owned
    /// by the caller once the guest tree has fully exited.
    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static;
}
