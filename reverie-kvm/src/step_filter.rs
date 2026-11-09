/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Which user instruction a precise timer event's single steps may step (see
//! `preemption_timer.rs`), decoded with iced-x86.
//!
//! The trap flag (TF) that a step sets is in the guest's real RFLAGS, so an
//! instruction that saves RFLAGS where the guest can read them, or loads
//! them, would see or drop it: PUSHF pushes it, POPF and IRETQ replace it, a
//! syscall's R11 and an exception or interrupt frame save it. This filter
//! names those instructions, the ones that leave user mode or may be
//! completed by KVM without an exit, and the ones the engine refuses, so that
//! no step ever runs them.

use iced_x86::Code;
use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Mnemonic;
use iced_x86::Register;

/// The longest x86-64 instruction.
pub(crate) const MAX_INSTRUCTION_BYTES: usize = 15;

/// The bytes of one instruction, in a buffer whose alignment keeps iced-x86
/// 1.21.0 from panicking: it panics on an instruction whose bytes end at a
/// multiple of 4 GiB of host memory
/// (<https://github.com/rrnewton/reverie/issues/858>), and the first
/// [`MAX_INSTRUCTION_BYTES`] bytes of a 16-byte aligned buffer never do.
#[repr(align(16))]
#[derive(Default)]
pub(crate) struct InstructionBytes(pub(crate) [u8; 16]);

/// How the engine runs the user instruction at RIP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepClass {
    /// Step it.
    Step,
    /// Run it unstepped to the next instruction, `length` bytes on, where a
    /// breakpoint takes the guest back: PUSHF and POPF, so that no image
    /// holds a step's TF and POPF reads its image once, itself; RDTSC,
    /// RDTSCP, CPUID, VMCALL and VMMCALL, which KVM may complete without an
    /// exit (an intercepted RDTSC or CPUID faults, and a stepped one's frame
    /// would carry TF); REP MOVS and REP STOS, whose iterations retire no
    /// conditional branch, so as not to step every iteration.
    RunOver { length: u64 },
    /// Run it unstepped: it leaves user mode with an exit of its own (the
    /// syscall's hypercall, or an exception stub's halt) before any further
    /// user instruction, or it cannot be decoded.
    Unstepped,
    /// Refuse it by name: IRETQ, which loads RFLAGS, CS and SS from memory
    /// another thread may change, and MOV SS or POP SS, which holds off the
    /// trap of the instruction after it.
    Refused(&'static str),
}

/// Classifies the instruction whose bytes `code` holds, fetched at `rip`.
pub(crate) fn classify(code: &[u8], rip: u64) -> StepClass {
    let code = &code[..code.len().min(MAX_INSTRUCTION_BYTES)];
    let instruction = Decoder::with_ip(64, code, rip, DecoderOptions::NONE).decode();
    if instruction.is_invalid() {
        return StepClass::Unstepped;
    }
    let run_over = StepClass::RunOver {
        length: instruction.len() as u64,
    };
    match instruction.mnemonic() {
        Mnemonic::Pushf
        | Mnemonic::Pushfq
        | Mnemonic::Popf
        | Mnemonic::Popfq
        | Mnemonic::Rdtsc
        | Mnemonic::Rdtscp
        | Mnemonic::Cpuid
        | Mnemonic::Vmcall
        | Mnemonic::Vmmcall => run_over,
        Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => StepClass::Refused("runs IRETQ"),
        Mnemonic::Syscall
        | Mnemonic::Sysenter
        | Mnemonic::Sysexit
        | Mnemonic::Sysret
        | Mnemonic::Int
        | Mnemonic::Int1
        | Mnemonic::Int3
        | Mnemonic::Into
        | Mnemonic::Ud0
        | Mnemonic::Ud1
        | Mnemonic::Ud2
        | Mnemonic::Hlt
        | Mnemonic::In
        | Mnemonic::Out
        | Mnemonic::Insb
        | Mnemonic::Insw
        | Mnemonic::Insd
        | Mnemonic::Outsb
        | Mnemonic::Outsw
        | Mnemonic::Outsd => StepClass::Unstepped,
        Mnemonic::Mov | Mnemonic::Pop if instruction.op0_register() == Register::SS => {
            StepClass::Refused("loads SS")
        }
        _ if instruction.has_rep_prefix()
            && matches!(
                instruction.code(),
                Code::Movsb_m8_m8
                    | Code::Movsw_m16_m16
                    | Code::Movsd_m32_m32
                    | Code::Movsq_m64_m64
                    | Code::Stosb_m8_AL
                    | Code::Stosw_m16_AX
                    | Code::Stosd_m32_EAX
                    | Code::Stosq_m64_RAX
            ) =>
        {
            run_over
        }
        _ => StepClass::Step,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_that_save_load_or_leave_with_rflags_are_not_stepped_plainly() {
        let rip = 0x40_1000;
        for (code, class) in [
            (&[0x90][..], StepClass::Step),                          // nop
            (&[0x75, 0xfe], StepClass::Step),                        // jnz .
            (&[0xe2, 0xfe], StepClass::Step),                        // loop .
            (&[0xe3, 0xfe], StepClass::Step),                        // jrcxz .
            (&[0xff, 0xc9], StepClass::Step),                        // dec ecx
            (&[0xa4], StepClass::Step),                              // movsb, once
            (&[0xf3, 0xa6], StepClass::Step),                        // repe cmpsb
            (&[0xf2, 0x0f, 0x10, 0xc1], StepClass::Step),            // movsd xmm0, xmm1
            (&[0x9c], StepClass::RunOver { length: 1 }),             // pushfq
            (&[0x66, 0x9c], StepClass::RunOver { length: 2 }),       // pushf
            (&[0x9d], StepClass::RunOver { length: 1 }),             // popfq
            (&[0x66, 0x9d], StepClass::RunOver { length: 2 }),       // popf
            (&[0x0f, 0x31], StepClass::RunOver { length: 2 }),       // rdtsc
            (&[0x0f, 0x01, 0xf9], StepClass::RunOver { length: 3 }), // rdtscp
            (&[0x0f, 0xa2], StepClass::RunOver { length: 2 }),       // cpuid
            (&[0x0f, 0x01, 0xc1], StepClass::RunOver { length: 3 }), // vmcall
            (&[0x0f, 0x01, 0xd9], StepClass::RunOver { length: 3 }), // vmmcall
            (&[0xf3, 0xa4], StepClass::RunOver { length: 2 }),       // rep movsb
            (&[0xf3, 0x48, 0xa5], StepClass::RunOver { length: 3 }), // rep movsq
            (&[0xf3, 0xaa], StepClass::RunOver { length: 2 }),       // rep stosb
            (&[0xf3, 0x48, 0xab], StepClass::RunOver { length: 3 }), // rep stosq
            (&[0x48, 0xcf], StepClass::Refused("runs IRETQ")),       // iretq
            (&[0x8e, 0xd0], StepClass::Refused("loads SS")),         // mov ss, ax
            (&[0x0f, 0x05], StepClass::Unstepped),                   // syscall
            (&[0xcd, 0x80], StepClass::Unstepped),                   // int 0x80
            (&[0xcc], StepClass::Unstepped),                         // int3
            (&[0xf1], StepClass::Unstepped),                         // int1
            (&[0x0f, 0x0b], StepClass::Unstepped),                   // ud2
            (&[0xf4], StepClass::Unstepped),                         // hlt
            (&[0xe4, 0x60], StepClass::Unstepped),                   // in al, 0x60
            (&[0xee], StepClass::Unstepped),                         // out dx, al
            (&[0x06], StepClass::Unstepped),                         // invalid in 64-bit mode
            (&[0x0f], StepClass::Unstepped),                         // truncated
        ] {
            assert_eq!(classify(code, rip), class, "{code:02x?}");
        }
    }
}
