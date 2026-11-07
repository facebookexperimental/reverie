/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![cfg(target_arch = "aarch64")]

//! The aarch64 [`Isa`] implementation: the only aarch64 cfg site for
//! the guest runtime's architecture facts.

use std::io;

use super::InstructionCapabilities;
use super::InstructionResult;
use super::Isa;
use crate::guest::event::InstructionEventKind;
use crate::guest::instruction::InstructionSubscriptions;
use crate::trap::frame::FrameError;
use crate::trap::frame::SavedState;
use crate::trap::frame::SignalFrame;

/// The guest's general-purpose registers at a hooked or continued
/// instruction, saved by the continuation that entered the runtime.
/// This is aarch64's own layout — never an alias of the x86-64 block:
/// register-aware Tools see x0-x30 and PSTATE exactly.
#[repr(C)]
#[derive(Debug, Default)]
pub struct RegisterContext {
    /// Address of the displaced (continued) instruction.
    pub instruction_pointer: u64,
    /// Application SP at that instruction.
    pub stack_pointer: u64,
    /// Saved x0-x30, in sigcontext order.
    pub regs: [u64; 31],
    /// Saved PSTATE.
    pub pstate: u64,
    /// The saver's descriptor of the saved extended (FP/SVE) state;
    /// opaque here and never written. All zeros means no saved state,
    /// which is what [`Default`] gives.
    saved_extended_state: [u64; 4],
}

impl RegisterContext {
    /// Whether the context carries no saved extended state, as one
    /// built by the fallback continuation (or [`Default`]) does.
    pub fn extended_state_unavailable(&self) -> bool {
        self.saved_extended_state == [0; 4]
    }
}

const _: () = {
    assert!(core::mem::size_of::<RegisterContext>() == 304);
    assert!(core::mem::align_of::<RegisterContext>() == 8);
    assert!(core::mem::offset_of!(RegisterContext, regs) == 16);
    assert!(core::mem::offset_of!(RegisterContext, pstate) == 264);
};

/// The aarch64 instruction-set architecture marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64;

impl Isa for Aarch64 {
    type RegisterContext = RegisterContext;
    type SavedState = SavedState;
    /// The result register dispatch writes, plus the syscall-number
    /// register a register view may have replaced.
    type RestartSnapshot = (u64, u64);

    const SYSCALL_LEN: u64 = 4;
    const SYSCALL_INSN: &'static [u8] = &[0x01, 0x00, 0x00, 0xd4];

    fn audit_arch() -> u32 {
        crate::arch::FILTER_ABI_AARCH64.audit_arch
    }

    fn rt_sigreturn_nr() -> i64 {
        i64::from(crate::arch::FILTER_ABI_AARCH64.rt_sigreturn)
    }

    fn syscall_number(context: &RegisterContext) -> i64 {
        context.regs[8] as i64
    }

    fn syscall_args(context: &RegisterContext) -> [u64; 6] {
        context.regs[..6].try_into().unwrap()
    }

    fn finish_syscall(context: &mut RegisterContext, result: i64) {
        context.regs[0] = result as u64;
    }

    fn instruction_pointer(context: &RegisterContext) -> u64 {
        context.instruction_pointer
    }

    fn set_instruction_pointer(context: &mut RegisterContext, value: u64) {
        context.instruction_pointer = value;
    }

    fn stack_pointer(context: &RegisterContext) -> u64 {
        context.stack_pointer
    }

    fn context_from_saved(saved: &SavedState, instruction: u64) -> RegisterContext {
        let context = RegisterContext {
            instruction_pointer: instruction,
            stack_pointer: saved.sp,
            regs: saved.registers,
            pstate: saved.pstate,
            saved_extended_state: [0; 4],
        };
        debug_assert!(context.extended_state_unavailable());
        context
    }

    fn commit_context(
        saved: &mut SavedState,
        context: &RegisterContext,
        length: u64,
    ) -> Result<(), FrameError> {
        saved.registers = context.regs;
        saved.sp = context.stack_pointer;
        saved.pstate = context.pstate;
        saved.pc = context
            .instruction_pointer
            .checked_add(length)
            .ok_or(FrameError)?;
        Ok(())
    }

    fn restart_snapshot(context: &RegisterContext) -> (u64, u64) {
        (context.regs[0], context.regs[8])
    }

    fn restore_restart_snapshot(context: &mut RegisterContext, snapshot: (u64, u64)) {
        (context.regs[0], context.regs[8]) = snapshot;
    }

    fn user_regs_from_context(context: &RegisterContext) -> libc::user_regs_struct {
        libc::user_regs_struct {
            regs: context.regs,
            sp: context.stack_pointer,
            pc: context.instruction_pointer,
            pstate: context.pstate,
        }
    }

    fn user_regs_from_event(
        number: i64,
        args: [u64; 6],
        instruction_pointer: u64,
    ) -> libc::user_regs_struct {
        let mut regs = libc::user_regs_struct {
            regs: [0; 31],
            sp: 0,
            pc: instruction_pointer,
            pstate: 0,
        };
        regs.regs[..6].copy_from_slice(&args);
        regs.regs[8] = number as u64;
        regs
    }

    fn event_from_user_regs(regs: &libc::user_regs_struct) -> (i64, [u64; 6]) {
        (regs.regs[8] as i64, regs.regs[..6].try_into().unwrap())
    }

    fn apply_user_regs(context: &mut RegisterContext, regs: &libc::user_regs_struct) {
        context.regs = regs.regs;
        context.stack_pointer = regs.sp;
        context.pstate = regs.pstate;
    }

    fn instruction_capabilities() -> InstructionCapabilities {
        // Linux/seccomp on aarch64 has no user-mode switch that
        // faults MRS counter/ID reads the way x86 faults CPUID and
        // RDTSC; seccomp sees only svc. Instruction subscriptions
        // are therefore refused by name, never approximated.
        InstructionCapabilities {
            cpuid: false,
            rdtsc: false,
        }
    }

    fn admit_instruction_subscriptions(subscriptions: InstructionSubscriptions) -> io::Result<()> {
        if subscriptions.cpuid || subscriptions.rdtsc {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "instruction faulting is unavailable on aarch64",
            ));
        }
        Ok(())
    }

    fn decode_instruction(_bytes: &[u8]) -> Option<(InstructionEventKind, &'static [u8])> {
        None
    }

    fn enable_instruction_faulting(subscriptions: InstructionSubscriptions) -> io::Result<()> {
        Self::admit_instruction_subscriptions(subscriptions)
    }

    unsafe fn set_instruction_native(
        _kind: InstructionEventKind,
        _enabled: bool,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "instruction faulting is unavailable on aarch64",
        ))
    }

    unsafe fn execute_native_instruction(
        _kind: InstructionEventKind,
        _context: &mut RegisterContext,
    ) {
        // Unreachable by construction: admission refuses every
        // instruction subscription, so no instruction event exists.
        crate::arch::trap_unreachable()
    }

    unsafe fn execute_native_fault_instruction(
        _kind: InstructionEventKind,
        _context: &mut libc::ucontext_t,
        _instruction_len: usize,
    ) {
        crate::arch::trap_unreachable()
    }

    fn fault_instruction_pointer(context: &libc::ucontext_t) -> u64 {
        context.uc_mcontext.pc
    }

    fn set_fault_instruction_pointer(context: &mut libc::ucontext_t, value: u64) {
        context.uc_mcontext.pc = value;
    }

    fn set_frame_resume(frame: &mut SignalFrame<'_>, entry: u64) {
        // Sigcontext order: x0-x30 (0..30), sp (31), pc (32), pstate (33).
        frame.set_register(32, entry as i64);
    }

    fn cpuid_inputs(_context: &RegisterContext) -> (u32, u32) {
        crate::arch::trap_unreachable()
    }

    fn apply_instruction_result(
        _context: &mut RegisterContext,
        _kind: InstructionEventKind,
        _result: InstructionResult,
    ) {
        crate::arch::trap_unreachable()
    }
}
