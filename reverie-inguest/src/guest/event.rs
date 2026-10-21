/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The syscall event that every trap and hook path builds.

/// How a guest syscall reached the runtime.
#[derive(Clone, Copy)]
pub enum SyscallDispatch {
    /// Through the seccomp `SIGSYS` trap.
    Trap,
    /// Through a patched site's installed hook; also every CPUID, RDTSC or
    /// RDTSCP instruction event, however it arrived (including through the
    /// fallback continuation for an instruction that could not be patched).
    InstalledHook,
    /// Through the in-guest fallback continuation.
    Fallback,
}

/// One guest syscall as the runtime sees it: its number and arguments, where
/// it came from, the protection-key value to run it under, and the result the
/// guest will see.
///
/// The Tool host also builds one, as a placeholder, for a CPUID, RDTSC or
/// RDTSCP instruction event: then `number` is -1, `args` are zero, `result`
/// is unused, and the instruction's inputs and outputs are the registers in
/// `context`.
#[derive(Clone, Copy)]
pub struct SyscallEvent {
    /// The syscall number (-1 for an instruction event).
    pub number: i64,
    /// The six argument registers (zero for an instruction event).
    pub args: [u64; 6],
    /// The guest address the call belongs to. For `InstalledHook` and
    /// `Fallback` events it is the address of the syscall instruction itself
    /// (or of the CPUID, RDTSC or RDTSCP instruction, for an instruction
    /// event). For `Trap` events it is the address the `SIGSYS` frame resumes
    /// at, just past the two-byte `syscall` instruction.
    pub instruction_pointer: u64,
    /// The value returned to the guest (a negative errno on failure); unused
    /// for an instruction event.
    pub result: i64,
    /// The dispatch path's register context, as an address.
    pub context: usize,
    /// How the call reached the runtime.
    pub dispatch: SyscallDispatch,
    /// The guest's PKRU value to run the call under, when it is not the runtime's.
    pub guest_pkru: Option<u32>,
}

impl SyscallEvent {
    /// Forward only this guest operation. Runtime-private syscall buffers must
    /// retain caller access and continue to use the ordinary raw gate.
    ///
    /// # Safety
    ///
    /// Issues the guest's syscall with its own arguments through the trusted
    /// gate; the caller must be on a guest syscall path.
    pub unsafe fn forward(&mut self) -> i64 {
        let result = unsafe {
            crate::trap::physical_guest_syscall6(self.number, self.args, self.guest_pkru)
        };
        // Permission effects survive negative errno and later Tool result
        // transformation. Private injection never calls this operation.
        self.guest_pkru = result.pkru;
        result.result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// The instruction an instruction event is for.
pub enum InstructionEventKind {
    /// `cpuid`.
    Cpuid,
    /// `rdtsc`.
    Rdtsc,
    /// `rdtscp`.
    Rdtscp,
}

impl InstructionEventKind {
    /// Length of the only encoding the runtime recognizes for this kind.
    pub const fn encoded_len(self) -> u64 {
        match self {
            Self::Cpuid | Self::Rdtsc => 2,
            Self::Rdtscp => 3,
        }
    }
}
