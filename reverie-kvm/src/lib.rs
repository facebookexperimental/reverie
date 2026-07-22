/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Minimal x86-64 KVM primitives for experimenting with a Reverie backend.
//!
//! This crate currently handles a single real-mode vCPU and a version-zero
//! syscall transport. It intentionally does not claim to provide Linux process
//! semantics; see the crate README for the remaining execution-runtime work.

#![cfg(target_arch = "x86_64")]

mod error;
mod memory;
mod runtime;
mod syscall;
mod vm;

pub use error::Error;
pub use memory::GuestMemory;
pub use runtime::KvmStack;
pub use runtime::KvmStackGuard;
pub use runtime::SyscallExecutor;
pub use syscall::SyscallRequest;
pub use vm::KvmBackend;
pub use vm::VMCALL_SYSCALL_TRANSPORT;

/// Result type used by the KVM backend prototype.
pub type Result<T> = std::result::Result<T, Error>;
