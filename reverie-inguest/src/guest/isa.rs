/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The one architecture seam for the in-guest runtime.
//!
//! Division of responsibility: `crate::arch` owns the seccomp ABI
//! (audit architecture, rt_sigreturn number, runtime page size),
//! `trap::frame` owns the kernel signal-frame layout, and this
//! trait owns register/instruction/continuation facts. Facts live
//! in exactly one of those homes.
//!
//! Generic guest code names only [`Isa`] (through [`NativeIsa`]): the
//! register-context layout, the syscall ABI over that layout, conversion
//! to and from the signal frame's saved state and the ptrace-shaped
//! `user_regs_struct`, and the restart snapshot a signal-at-entry
//! delivery restores. The two implementations are the only places new
//! architecture facts may land; their module bodies carry their own
//! target cfg, and the alias below is the single selection site.

use std::io;

use super::event::InstructionEventKind;
use super::event::InstructionSubscriptions;
use crate::trap::frame::FrameError;
use crate::trap::frame::SignalFrame;

mod aarch64;
mod x86_64;

/// The instruction-set architecture this runtime was compiled for.
#[cfg(target_arch = "x86_64")]
pub type NativeIsa = x86_64::X86_64;
/// The instruction-set architecture this runtime was compiled for.
#[cfg(target_arch = "aarch64")]
pub type NativeIsa = aarch64::Aarch64;

/// Which faulting-instruction controls this architecture can admit.
/// Admission still requires the runtime preflight on capable
/// architectures; an incapable architecture refuses by name.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InstructionCapabilities {
    /// CPUID faulting can be admitted.
    pub cpuid: bool,
    /// RDTSC/RDTSCP faulting can be admitted.
    pub rdtsc: bool,
}

/// A Tool-produced result for one intercepted instruction, in the
/// architecture-neutral shape the Tool callbacks return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionResult {
    /// The four CPUID output registers.
    Cpuid {
        eax: u32,
        ebx: u32,
        ecx: u32,
        edx: u32,
    },
    /// A timestamp-counter value and its auxiliary word, when the
    /// instruction kind carries one.
    Tsc { value: u64, aux: Option<u32> },
}

/// Every per-architecture fact the shared in-guest runtime consumes.
///
/// Implementations are zero-sized markers; every operation is an
/// associated function on the marker type, so call sites write
/// `NativeIsa::syscall_site(resume)` and never name a register, an
/// instruction length, or a frame layout themselves.
pub trait Isa: Copy + Send + Sync + 'static {
    /// The saved register block a hook or the fallback continuation
    /// hands to ordinary-context dispatch. Its layout is this
    /// architecture's own: x86-64 keeps the 176-byte LiteInst
    /// `HookContext` block; aarch64 carries x0-x30 and PSTATE.
    type RegisterContext: Default + Send + Sync + 'static;
    /// The owned signal-frame image this architecture captures into
    /// (the selected `trap::frame` implementation's saved state).
    type SavedState;
    /// The register values a signal-at-entry delivery must restore so
    /// the interrupted syscall re-issues exactly as first trapped:
    /// the registers ordinary dispatch may have written over.
    type RestartSnapshot: Copy + Send + Sync + 'static;

    /// Length of this architecture's syscall instruction, in bytes.
    const SYSCALL_LEN: u64;
    /// This architecture's syscall instruction encoding.
    const SYSCALL_INSN: &'static [u8];

    /// The address of a trapped syscall instruction, given the
    /// address its `SIGSYS` frame resumes at (just past it).
    fn syscall_site(resume_address: u64) -> u64 {
        resume_address.saturating_sub(Self::SYSCALL_LEN)
    }

    /// The syscall number in a saved register context.
    fn syscall_number(context: &Self::RegisterContext) -> i64;
    /// The six syscall argument registers in a saved register context.
    fn syscall_args(context: &Self::RegisterContext) -> [u64; 6];
    /// Writes a syscall result into a saved register context,
    /// including this architecture's syscall-instruction clobbers
    /// (x86-64's RCX/R11; aarch64 has none beyond the result register).
    fn finish_syscall(context: &mut Self::RegisterContext, result: i64);
    /// The displaced instruction's address in a saved register context.
    fn instruction_pointer(context: &Self::RegisterContext) -> u64;
    /// Replaces the displaced instruction's address.
    fn set_instruction_pointer(context: &mut Self::RegisterContext, value: u64);
    /// The application stack pointer in a saved register context.
    fn stack_pointer(context: &Self::RegisterContext) -> u64;

    /// Builds the ordinary-context register block for the trapped
    /// instruction at `instruction` from its captured frame image.
    /// The block carries no saved extended state.
    fn context_from_saved(saved: &Self::SavedState, instruction: u64) -> Self::RegisterContext;
    /// Writes a dispatched register block back into the captured
    /// frame image, resuming `length` bytes past the block's
    /// instruction pointer.
    fn commit_context(
        saved: &mut Self::SavedState,
        context: &Self::RegisterContext,
        length: u64,
    ) -> Result<(), FrameError>;

    /// Captures the registers a signal-at-entry restart restores.
    fn restart_snapshot(context: &Self::RegisterContext) -> Self::RestartSnapshot;
    /// Restores a snapshot taken by [`Self::restart_snapshot`].
    fn restore_restart_snapshot(
        context: &mut Self::RegisterContext,
        snapshot: Self::RestartSnapshot,
    );

    /// The ptrace-shaped register view of a saved register context.
    fn user_regs_from_context(context: &Self::RegisterContext) -> libc::user_regs_struct;
    /// The ptrace-shaped register view of a bare syscall event
    /// (no saved context): number, arguments and instruction only.
    fn user_regs_from_event(
        number: i64,
        args: [u64; 6],
        instruction_pointer: u64,
    ) -> libc::user_regs_struct;
    /// The syscall number and arguments a ptrace-shaped register
    /// view asks to run.
    fn event_from_user_regs(regs: &libc::user_regs_struct) -> (i64, [u64; 6]);
    /// Applies a ptrace-shaped register view to a saved register
    /// context. The context's instruction pointer is the entry's
    /// own and is never taken from the view.
    fn apply_user_regs(context: &mut Self::RegisterContext, regs: &libc::user_regs_struct);

    /// Which faulting-instruction controls this architecture can
    /// admit at all. A capable architecture still probes the actual
    /// controls in [`Self::admit_instruction_subscriptions`].
    fn instruction_capabilities() -> InstructionCapabilities;
    /// Preflights the faulting controls `subscriptions` needs on
    /// this thread, restoring every previous setting. An
    /// architecture without the control fails with `Unsupported`
    /// naming it; empty subscriptions always succeed.
    fn admit_instruction_subscriptions(subscriptions: InstructionSubscriptions) -> io::Result<()>;
    /// Recognizes a faulting instruction encoding at the start of
    /// `bytes`, returning its kind and exact encoding.
    fn decode_instruction(bytes: &[u8]) -> Option<(InstructionEventKind, &'static [u8])>;
    /// Turns on this thread's faulting controls for `subscriptions`,
    /// which admission has already accepted.
    fn enable_instruction_faulting(subscriptions: InstructionSubscriptions) -> io::Result<()>;
    /// Lets `kind` execute natively on this thread (`enabled`), or
    /// makes it fault again.
    ///
    /// # Safety
    ///
    /// The caller must turn faulting back on (`enabled == false`)
    /// before guest code runs again on this thread, or the guest
    /// executes the instruction natively and the Tool never sees it.
    unsafe fn set_instruction_native(kind: InstructionEventKind, enabled: bool) -> io::Result<()>;
    /// Executes `kind` natively with `context`'s registers as input
    /// and writes its results back into `context`.
    ///
    /// # Safety
    ///
    /// Native execution of `kind` must be enabled on this thread;
    /// otherwise the private helper itself faults.
    unsafe fn execute_native_instruction(
        kind: InstructionEventKind,
        context: &mut Self::RegisterContext,
    );
    /// Executes `kind` natively with a kernel fault frame's
    /// registers as input, writes the results into the frame, and
    /// advances its resume address past the instruction.
    ///
    /// # Safety
    ///
    /// `context` must be a kernel fault frame for a `kind`
    /// instruction of `instruction_len` bytes, and native execution
    /// of `kind` must be enabled on this thread.
    unsafe fn execute_native_fault_instruction(
        kind: InstructionEventKind,
        context: &mut libc::ucontext_t,
        instruction_len: usize,
    );
    /// The faulting address in a kernel fault frame.
    fn fault_instruction_pointer(context: &libc::ucontext_t) -> u64;
    /// Replaces a kernel fault frame's resume address.
    fn set_fault_instruction_pointer(context: &mut libc::ucontext_t, value: u64);
    /// Sets a captured signal frame's resume address to a
    /// continuation entry the architecture prepared.
    fn set_frame_resume(frame: &mut SignalFrame<'_>, entry: u64);
    /// The CPUID leaf and subleaf a saved context asks for. Only
    /// reachable where CPUID events exist.
    fn cpuid_inputs(context: &Self::RegisterContext) -> (u32, u32);
    /// Writes a Tool-produced instruction result into a saved
    /// register context. Only reachable where instruction events
    /// exist.
    fn apply_instruction_result(
        context: &mut Self::RegisterContext,
        kind: InstructionEventKind,
        result: InstructionResult,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_syscall_site_uses_the_instruction_length() {
        assert_eq!(NativeIsa::SYSCALL_INSN.len() as u64, NativeIsa::SYSCALL_LEN);
        assert_eq!(
            NativeIsa::syscall_site(0x4000),
            0x4000 - NativeIsa::SYSCALL_LEN
        );
        assert_eq!(NativeIsa::syscall_site(1), 0);
    }

    #[test]
    fn default_context_is_zeroed_with_no_extended_state() {
        let mut context = <NativeIsa as Isa>::RegisterContext::default();
        assert!(context.extended_state_unavailable());
        assert_eq!(NativeIsa::instruction_pointer(&context), 0);
        assert_eq!(NativeIsa::stack_pointer(&context), 0);
        assert_eq!(NativeIsa::syscall_number(&context), 0);
        assert_eq!(NativeIsa::syscall_args(&context), [0; 6]);
        NativeIsa::set_instruction_pointer(&mut context, 0x1234);
        assert_eq!(NativeIsa::instruction_pointer(&context), 0x1234);
    }

    #[test]
    fn user_regs_event_round_trips_number_and_args() {
        let regs = NativeIsa::user_regs_from_event(7, [1, 2, 3, 4, 5, 6], 0x4000);
        assert_eq!(
            NativeIsa::event_from_user_regs(&regs),
            (7, [1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn instruction_admission_matches_capabilities() {
        assert!(
            NativeIsa::admit_instruction_subscriptions(InstructionSubscriptions::default()).is_ok()
        );
        let capabilities = NativeIsa::instruction_capabilities();
        if capabilities.cpuid {
            assert!(matches!(
                NativeIsa::decode_instruction(&[0x0f, 0xa2]),
                Some((InstructionEventKind::Cpuid, _))
            ));
        } else {
            assert_eq!(NativeIsa::decode_instruction(&[0x0f, 0xa2]), None);
            let error = NativeIsa::admit_instruction_subscriptions(InstructionSubscriptions {
                cpuid: true,
                rdtsc: false,
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
    }
}
