/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use thiserror::Error;

/// Errors produced by the KVM backend prototype.
#[derive(Debug, Error)]
pub enum Error {
    /// A KVM ioctl or vCPU operation failed.
    #[error("KVM operation failed: {0}")]
    Kvm(#[from] kvm_ioctls::Error),

    /// The guest-memory mapping could not be created.
    #[error("failed to allocate guest memory: {0}")]
    MemoryMapping(#[source] std::io::Error),

    /// Guest memory must be non-empty and page aligned.
    #[error("invalid guest memory layout: base={guest_base:#x}, size={size:#x}")]
    InvalidMemoryLayout {
        /// First guest-physical address in the mapping.
        guest_base: u64,
        /// Mapping size in bytes.
        size: usize,
    },

    /// A guest-memory access fell outside the registered mapping.
    #[error(
        "guest memory access is out of bounds: address={address:#x}, length={length:#x}, mapping={guest_base:#x}..{guest_end:#x}"
    )]
    InvalidGuestAddress {
        /// First byte requested by the caller.
        address: u64,
        /// Requested number of bytes.
        length: usize,
        /// First guest-physical address in the mapping.
        guest_base: u64,
        /// Address immediately after the mapping.
        guest_end: u64,
    },

    /// The host kernel cannot forward the selected hypercall to userspace.
    #[error("KVM userspace hypercall exits are not supported")]
    HypercallExitUnsupported,

    /// The virtual CPU exposes neither the Intel nor AMD hypercall instruction.
    #[error("the virtual CPU exposes neither vmcall nor vmmcall")]
    HypercallInstructionUnsupported,

    /// The guest used a hypercall number other than the syscall transport.
    #[error("unexpected guest hypercall number {0}")]
    UnexpectedHypercall(u64),

    /// The vCPU stopped for an event this prototype does not handle.
    #[error("unexpected vCPU exit: {0}")]
    UnexpectedVcpuExit(String),
}
