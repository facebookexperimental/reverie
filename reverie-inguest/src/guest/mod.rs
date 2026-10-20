/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The half of the runtime that runs inside the guest process, shared by the
//! in-guest backends: the syscall event every trap and hook path builds and
//! the register context they save, the allocator that keeps Tool callbacks
//! off libc's heap, the synchronous coordinator RPC handle an in-guest Tool
//! sends its global requests through, the Tool host that runs the Tool, and
//! the fallback continuation that runs a trapped call in ordinary context,
//! and the RCB clock that measures the guest's own progress.
//! The rest of the trap path and the launcher move here in the following
//! steps of the in-guest plan (<https://github.com/rrnewton/hermit/issues/3520>, step C3).

pub mod alloc;
#[cfg(feature = "rcb-clock")]
pub mod clock;
pub mod context;
pub mod continuation;
pub mod event;
#[cfg(feature = "exec-private-init")]
pub mod exec_private;
#[cfg(feature = "coordinator-rpc")]
pub mod host;
pub mod installed_stack;
#[cfg(feature = "coordinator-rpc")]
pub mod installed_tool;
pub mod instruction;
#[cfg(feature = "exec-native-injection")]
pub mod native_exec;
#[cfg(feature = "exec-native-injection")]
pub mod native_exec_arguments;
#[cfg(any(feature = "exec-native-injection", feature = "loader-private-runtime"))]
pub mod native_exec_fds;
#[cfg(feature = "exec-native-injection")]
pub mod native_exec_mappings;
#[cfg(feature = "coordinator-rpc")]
pub mod patcher;
pub mod protect;
pub mod restorer;
#[cfg(feature = "coordinator-rpc")]
pub mod rpc;
#[cfg(feature = "coordinator-rpc")]
pub mod runtime_seam;
pub mod sigalrm;
pub mod signal;
pub mod support;
#[cfg(all(feature = "coordinator-rpc", feature = "rcb-clock"))]
pub mod tool_install;
pub mod tool_region;
pub mod trap_dispatch;
