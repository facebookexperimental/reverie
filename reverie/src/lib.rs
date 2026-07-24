/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie is a user space system-call interception framework for Linux. It can
//! be used to intercept, modify, or elide a syscall before the kernel executes
//! it.
//!
//! Reverie consists of a family of crates:
//!  - `reverie` (this one): Primarily provides the [`Tool`] trait interface
//!    that Reverie tools must implement to intercept syscalls. It also defines
//!    the [`Backend`] trait, which is the contract a *backend* implementation
//!    must satisfy in order to run an arbitrary tool.
//!  - `reverie-ptrace`: The backend that uses ptrace to intercept syscalls.
//!    This is currently the only non-experimental backend and is the reference
//!    implementation of the [`Backend`] contract. In the future, we may have a
//!    backend that uses binary rewriting to intercept syscalls within the guest
//!    process.
//!  - `reverie-syscalls`: Provides typed syscalls, which provide safer and more
//!    ergonomic access to the arguments of a syscall. Also provides pretty
//!    printing of syscalls and their arguments.
//!
//! The rest of the `reverie-*` crates are used in service to the above crates.
//!
//! # Tools and backends
//!
//! There are two sides to every Reverie program:
//!  - A [`Tool`] decides *what* to do when the guest hits a trappable event.
//!    This is what most users write; see the [`Tool`] trait for the full
//!    handler API.
//!  - A [`Backend`] decides *how* those events are trapped and how the tool is
//!    run against a live guest process tree (spawning, syscall interception,
//!    hosting global state, teardown). `reverie-ptrace` is the reference
//!    backend; the [`Backend`] trait spells out exactly what any alternative
//!    backend must provide.
//!
//! For examples of usage, please see the [`reverie-examples`][] folder.
//!
//! See also [`README.md`][] for a high-level overview of Reverie.
//!
//! [`reverie-examples`]: https://github.com/facebookexperimental/reverie/tree/main/reverie-examples
//! [`README.md`]: https://github.com/facebookexperimental/reverie

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg(target_os = "linux")]

mod auxv;
mod backend;
mod backtrace;
mod error;
mod guest;
#[cfg(target_arch = "x86_64")]
mod rdtsc;
mod regs;
mod stack;
mod subscription;
mod timer;
mod tool;

pub use auxv::*;
pub use backend::*;
pub use backtrace::*;
pub use error::*;
pub use guest::*;
pub use process::ExitStatus;
pub use process::Pid;
#[cfg(target_arch = "x86_64")]
pub use rdtsc::*;
pub use regs::RegDisplay;
pub use regs::RegDisplayOptions;
pub use reverie_process as process;
pub use stack::*;
pub use subscription::*;
pub use timer::*;
pub use tool::*;

/// The identifier for a specific thread, corresponding to the output of gettid.
/// In many cases, Linux blurs the Pid/Tid distinction, but Reverie should
/// consistently use TIDs when referring to threads, and Pids when referring to
/// shared address spaces that (typically) correspond to processes.
///
/// This type is currently equivalent to [`Pid`], but relying on that equivalence
/// is deprecated. `Tid` may be a distinct newtype in the future.
pub type Tid = Pid;

/// Required for `impl Tool for MyTool` blocks.
///
/// NOTE: This is just an alias for `async_trait` for now, but may be extended in
/// the future to do more things (like derive syscall subscriptions).
pub use async_trait::async_trait as tool;
/// Required for `impl GlobalTool for MyGlobalTool` blocks.
///
/// NOTE: This is just an alias for `async_trait` for now, but may be extended in
/// the future to do more things (like deriving Request/Response types from
/// method names).
pub use async_trait::async_trait as global_tool;
/// Required for `impl Backend for MyBackend` blocks.
///
/// NOTE: This is just an alias for `async_trait` for now, but may be extended in
/// the future.
pub use async_trait::async_trait as backend;
// Reexport nix Signal type.
pub use nix::sys::signal::Signal;
/// CPUID result.
pub use raw_cpuid::CpuIdResult;
/// typed syscalls.
pub use reverie_syscalls as syscalls;

/// `Never` type is a stopgap for the unstable `!` type (i.e., the never type).
pub type Never = never_say_never::Never;
