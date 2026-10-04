/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Minimal x86-64 KVM primitives for experimenting with a Reverie backend.
//!
//! The crate supports the original real-mode transport probes and a bare
//! long-mode process personality for fixed-address static ELF executables. The
//! latter implements only a bounded, single-process subset of Linux semantics;
//! see the crate README for its explicit limits.
//!
//! The embedding process must reserve Linux real-time signal 64 exclusively
//! for this backend. First vCPU entry installs a process-wide handler that is
//! not restored when a backend is dropped. Existing or later signal ownership
//! conflicts cause entry errors; these checks do not make concurrent use by
//! another library safe. SIGURG remains the separate worker-cancellation signal.
//! See the crate README for the complete host signal requirements.

#![cfg(target_arch = "x86_64")]
#![cfg_attr(test, feature(thread_spawn_hook))]

mod bootstrap;
mod clock;
mod cpuid;
mod cpuid_instruction;
mod elf;
mod entry;
mod error;
mod executor;
mod failure;
mod fdinfo;
mod memory;
mod proc_mounts;
mod runtime;
mod signal;
mod stats;
mod syscall;
mod terminal_read;
mod timestamp;
mod tools;
mod vm;

pub use cpuid::CpuidPolicy;
pub use error::Error;
pub use memory::GuestMemory;
pub use reverie::syscalls::Syscall;
pub use reverie::syscalls::SyscallInfo;
pub use reverie::syscalls::Sysno;
pub use runtime::KvmStack;
pub use runtime::KvmStackGuard;
pub use runtime::SyscallExecutor;
pub use runtime::ToolRunCompletion;
#[cfg(feature = "native-test-support")]
pub use runtime::native_test_support;
pub use stats::KvmBackendStats;
pub use stats::KvmExitReason;
pub use syscall::SyscallRequest;
pub use tools::CounterTool;
pub use tools::HierarchicalCounter;
pub use tools::HierarchicalCounterTool;
pub use tools::HierarchicalTotals;
pub use tools::StraceEntry;
pub use tools::StraceLog;
pub use tools::StraceTool;
pub use tools::SyscallCounter;
pub use vm::KvmBackend;
pub use vm::VMCALL_SYSCALL_TRANSPORT;

/// Result type used by the KVM backend prototype.
pub type Result<T> = std::result::Result<T, Error>;
