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
//! another library safe. A thread that arms a preemption timer also reserves
//! SIGSTKFLT, which the timer uses only to end `KVM_RUN`: the thread keeps it
//! blocked outside `KVM_RUN`, so it interrupts no host call. SIGURG remains the
//! separate worker-cancellation signal. See the crate README for the complete
//! host signal requirements.

#![cfg(target_arch = "x86_64")]
#![cfg_attr(test, feature(thread_spawn_hook))]

mod clock;
mod cpuid_instruction;
mod entry_driver;
mod preemption_timer;
mod runtime;
mod stats;
mod step_filter;
mod timestamp;
mod tools;
mod vm;

#[cfg(test)]
#[path = "entry_cleanup_tests.rs"]
mod entry_cleanup_tests;

#[cfg(test)]
#[path = "linuxemu_tests.rs"]
mod linuxemu_tests;

#[cfg(test)]
#[path = "../../reverie-linuxemu/tests/support/broker_library_tests.rs"]
#[expect(
    dead_code,
    reason = "this crate's tests use only the cleanup fixture of the shared adapter"
)]
mod broker_library_tests;

// LinuxEmu (reverie-linuxemu) and the machine it runs on (reverie-kvm-core),
// under the names they had when they were modules of this crate.
pub use memory::GuestMemory;
pub use reverie::syscalls::Syscall;
pub use reverie::syscalls::SyscallInfo;
pub use reverie::syscalls::Sysno;
pub use reverie_kvm_core::Error;
use reverie_kvm_core::bootstrap;
use reverie_kvm_core::entry;
use reverie_kvm_core::error_ext as error;
use reverie_kvm_core::failure;
use reverie_kvm_core::memory;
use reverie_kvm_core::syscall;
use reverie_linuxemu::elf;
use reverie_linuxemu::executor;
pub use reverie_linuxemu::native_exit_broker;
use reverie_linuxemu::provider;
use reverie_linuxemu::signal;
#[cfg(test)]
use reverie_linuxemu::terminal_cleanup;
use reverie_linuxemu::terminal_read;
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
