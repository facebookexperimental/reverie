/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! LinuxEmu: the Linux syscall emulation that Reverie's KVM backend runs its
//! guests on, in the manner of gVisor's Sentry.
//!
//! LinuxEmu models Linux: tasks and thread groups, the fd table and file
//! descriptions, signals, memory mappings, ELF loading and exec, and the
//! syscalls over them. The machine underneath it (guest memory and page
//! tables, the entry gate, failure ownership) is `reverie-kvm-core`, and
//! `reverie-kvm` runs the vCPUs and drives the Tool.
//!
//! Its modules and the gVisor Sentry packages (`pkg/sentry/...`) they
//! correspond to:
//!
//! - [`credentials`]: the credentials a guest starts with and their change at
//!   exec (`kernel/auth`).
//! - [`executor`]: syscall dispatch and the per-syscall handlers
//!   (`syscalls/linux`), with the process lifecycle (`kernel/task_*`), the fd
//!   table (`kernel/fd_table`), pipes, epoll, inotify and the other file
//!   descriptions (`kernel/pipe`, `vfs`, `fsimpl/*`).
//! - [`elf`]: the ELF loader (`loader`) and the per-task state it creates.
//! - [`signal`]: the signal ABI and per-thread and per-process signal state
//!   (`arch/signal_amd64`, `kernel/task_signals`, `kernel/pending_signals`).
//! - [`fdinfo`]: `/proc/<pid>/fdinfo` rendering (`fsimpl/proc`).
//! - [`provider`]: the `reverie::provider` interface as LinuxEmu answers it.
//! - [`terminal_read`] and [`terminal_cleanup`]: reads from a host terminal and
//!   their cleanup (`kernel/tty`, `fsimpl/devpts`).
//! - [`native_exit_broker`]: the host-side broker that completes native exits.
//!
//! It is an internal building block of reverie-kvm; it is not part of
//! Reverie's `Tool`, `Guest` or backend contract.

#![cfg(target_arch = "x86_64")]

pub mod credentials;
pub mod elf;
pub mod executor;
pub mod fdinfo;
pub mod native_exit_broker;
pub mod provider;
pub mod signal;
pub mod terminal_cleanup;
pub mod terminal_read;

#[cfg(test)]
mod bootstrap_tests;

#[cfg(test)]
#[path = "../tests/support/broker_library_tests.rs"]
mod broker_library_tests;

#[cfg(test)]
#[path = "../tests/support/broker_library_selftests.rs"]
mod broker_library_selftests;

// The machine LinuxEmu runs on, under the names it had before LinuxEmu was its
// own crate.
pub use reverie_kvm_core::Error;
pub use reverie_kvm_core::GuestMemory;
pub use reverie_kvm_core::Result;
pub use reverie_kvm_core::SyscallRequest;
#[cfg(test)]
use reverie_kvm_core::alias_failure;
use reverie_kvm_core::bootstrap;
use reverie_kvm_core::entry;
use reverie_kvm_core::error_ext as error;
use reverie_kvm_core::failure;
use reverie_kvm_core::memory;
use reverie_kvm_core::provider_memory;
