/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The lower layer of Reverie's KVM backend: the machine that LinuxEmu
//! (`reverie-linuxemu`) emulates Linux on.
//!
//! - [`memory`]: the guest arena, its page tables and the guest memory map.
//! - [`bootstrap`]: long-mode setup, descriptor tables and the syscall
//!   trampoline.
//! - [`syscall`]: the guest's syscall frame ([`SyscallRequest`]).
//! - [`entry`]: the entry gate between vCPU entries and memory operations.
//! - [`failure`]: run-failure ownership.
//! - [`provider_memory`]: the `reverie::provider` guest-memory traits over
//!   [`GuestMemory`].
//! - [`error`], [`error_ext`] and [`layout`]: the backend's error type and the
//!   fixed guest address map.
//!
//! It is an internal building block of reverie-kvm, which re-exports [`Error`],
//! [`GuestMemory`] and [`SyscallRequest`] unchanged; it is not part of
//! Reverie's `Tool`, `Guest` or backend contract.

#![cfg(target_arch = "x86_64")]

pub mod bootstrap;
pub mod entry;
pub mod error;
pub mod error_ext;
pub mod failure;
pub mod layout;
pub mod memory;
pub mod provider_memory;
pub mod syscall;

#[cfg(any(test, feature = "test-support"))]
#[path = "../tests/support/alias_failure.rs"]
pub mod alias_failure;

pub use error::Error;
pub use memory::GuestMemory;
pub use syscall::SyscallRequest;

pub type Result<T> = std::result::Result<T, Error>;
