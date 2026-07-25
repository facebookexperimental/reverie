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
    /// A host filesystem operation failed while preparing the guest.
    #[error("host filesystem operation failed: {0}")]
    HostIo(#[from] std::io::Error),

    /// A post-exec tool hook rejected the new guest image.
    #[error("Reverie post-exec hook failed: {0}")]
    PostExec(reverie::syscalls::Errno),

    /// A shared Reverie tool callback failed.
    #[error("Reverie tool failed: {0}")]
    Reverie(#[source] reverie::Error),

    /// A KVM ioctl or vCPU operation failed.
    #[error("KVM operation failed: {0}")]
    Kvm(#[from] kvm_ioctls::Error),

    /// The guest-memory mapping could not be created.
    #[error("failed to allocate guest memory: {0}")]
    MemoryMapping(#[source] std::io::Error),

    /// The ELF image could not be parsed.
    #[error("failed to parse ELF image: {0}")]
    ElfParse(#[from] goblin::error::Error),

    /// The ELF image cannot run in the minimal KVM process personality.
    #[error("unsupported ELF image: {0}")]
    UnsupportedElf(String),

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

    /// The transport frame named a number outside the architecture syscall table.
    #[error("invalid x86-64 syscall number {0}")]
    InvalidSyscallNumber(u64),

    /// Syscall frames must use addresses accepted by KVM's hypercall ABI.
    #[error("invalid syscall frame address {0:#x}")]
    InvalidSyscallFrameAddress(u64),

    /// The host kernel cannot forward the selected hypercall to userspace.
    #[error("KVM userspace hypercall exits are not supported")]
    HypercallExitUnsupported,

    /// The virtual CPU exposes neither the Intel nor AMD hypercall instruction.
    #[error("the virtual CPU exposes neither vmcall nor vmmcall")]
    HypercallInstructionUnsupported,

    /// The guest used a hypercall number other than the syscall transport.
    #[error("unexpected guest hypercall number {0}")]
    UnexpectedHypercall(u64),

    /// The fixed long-mode bootstrap layout does not fit in guest memory.
    #[error("guest memory is too small for the long-mode bootstrap")]
    LongModeMemoryTooSmall,

    /// No static ELF has been installed on this backend.
    #[error("no static ELF is installed")]
    StaticElfNotInstalled,

    /// KVM accepted only part of the long-mode MSR table.
    #[error("KVM installed {actual} of {expected} long-mode MSRs")]
    IncompleteMsrSetup {
        /// Number of MSRs supplied.
        expected: usize,
        /// Number of MSRs accepted.
        actual: usize,
    },

    /// The guest raised an x86 exception while running a loaded ELF image.
    #[error("guest exception vector {vector} at {instruction_pointer:#x} (CR2={fault_address:#x})")]
    GuestException {
        /// Architectural exception vector.
        vector: u8,
        /// Guest instruction pointer saved by the exception frame.
        instruction_pointer: u64,
        /// Guest CR2 value, meaningful for page faults.
        fault_address: u64,
    },

    /// The vCPU stopped for an event this prototype does not handle.
    #[error("unexpected vCPU exit: {0}")]
    UnexpectedVcpuExit(String),
}
