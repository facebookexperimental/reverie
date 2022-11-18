/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![doc = include_str!("../../README.md")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![feature(never_type)]

mod auxv;
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
// Reexport nix Signal type.
pub use nix::sys::signal::Signal;
/// CPUID result.
pub use raw_cpuid::CpuIdResult;
/// typed syscalls.
pub use reverie_syscalls as syscalls;
