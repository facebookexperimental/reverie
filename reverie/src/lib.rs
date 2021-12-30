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

#![doc = include_str!("../../README.md")]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![feature(associated_type_defaults)]
#![feature(never_type)]

mod auxv;
mod backtrace;
mod error;
mod guest;
mod rdtsc;
mod stack;
mod subscription;
mod timer;
mod tool;

pub use auxv::*;
pub use backtrace::*;
pub use error::*;
pub use guest::*;
pub use rdtsc::*;
pub use stack::*;
pub use subscription::*;
pub use timer::*;
pub use tool::*;

pub use reverie_process as process;

pub use process::ExitStatus;
pub use process::Pid;

/// The identifier for a specific thread, corresponding to the output of gettid.
/// In many cases, Linux blurs the Pid/Tid distinction, but Reverie should
/// consistently use TIDs when referring to threads, and Pids when referring to
/// shared address spaces that (typically) correspond to processes.
///
/// This type is currently equivalent to [`Pid`], but relying on that equivalence
/// is deprecated. `Tid` may be a distinct newtype in the future.
pub type Tid = Pid;

/// typed syscalls.
pub use reverie_syscalls as syscalls;

/// CPUID result.
pub use raw_cpuid::CpuIdResult;

// Reexport nix Signal type.
pub use nix::sys::signal::Signal;

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
