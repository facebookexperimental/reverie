/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe's entry into the shared in-guest runtime: a rewritten syscall site's
//! trampoline frame becomes the runtime's saved [`RegisterContext`], the
//! shared saved-register entry handles it exactly as it handles a patched
//! LiteInst site or the SIGSYS continuation, and the result goes back into the
//! frame. This is the only part of SaBRe's syscall path that differs from the
//! other in-guest backends: who saved the registers.
//!
//! The instruction pointer the runtime sees is `fake_ret - 2`, the address of
//! the final two bytes (`0f 05`) of the displaced `syscall`. For a plain
//! `syscall` that is the instruction's start. For a prefixed one (for example
//! `48 0f 05`) it is inside the instruction, which is what the SIGSYS
//! continuation reports for the same site (`resume address - 2`), so the two
//! entries agree.
//!
//! Nothing calls `dispatch_rewritten_syscall` (feature `shared-entry`) yet. The
//! SaBRe switch (dev-hermit `ai_docs/2026-10-17-sabre-switch-design.md`, step
//! 5c) makes the loader's router call it once the plugin is the shared runtime.

use reverie_inguest::guest::context::RegisterContext;
#[cfg(feature = "shared-entry")]
use reverie_sabre_stats::SabreDispatchRoute;

use crate::ffi::syscall_stackframe;

// The frame layout the adapter relies on is the trampoline's push order
// (vendor/sabre/arch/x86_64/handle_syscall.S: RFLAGS via R11, RBP, RBX, RCX,
// RDX, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15, then the aligning RBP,
// below the two return slots the rewrite pushed).
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(syscall_stackframe, rbp_stackalign) == 0x00);
    assert!(offset_of!(syscall_stackframe, r15) == 0x08);
    assert!(offset_of!(syscall_stackframe, r14) == 0x10);
    assert!(offset_of!(syscall_stackframe, r13) == 0x18);
    assert!(offset_of!(syscall_stackframe, r12) == 0x20);
    assert!(offset_of!(syscall_stackframe, r11) == 0x28);
    assert!(offset_of!(syscall_stackframe, r10) == 0x30);
    assert!(offset_of!(syscall_stackframe, r9) == 0x38);
    assert!(offset_of!(syscall_stackframe, r8) == 0x40);
    assert!(offset_of!(syscall_stackframe, rdi) == 0x48);
    assert!(offset_of!(syscall_stackframe, rsi) == 0x50);
    assert!(offset_of!(syscall_stackframe, rdx) == 0x58);
    assert!(offset_of!(syscall_stackframe, rcx) == 0x60);
    assert!(offset_of!(syscall_stackframe, rbx) == 0x68);
    assert!(offset_of!(syscall_stackframe, rbp_prologue) == 0x70);
    assert!(offset_of!(syscall_stackframe, rflags) == 0x78);
    assert!(offset_of!(syscall_stackframe, fake_ret) == 0x80);
    assert!(offset_of!(syscall_stackframe, ret) == 0x88);
    assert!(core::mem::size_of::<syscall_stackframe>() == 0x90);
};

/// Width of the x86-64 `syscall` instruction the rewrite displaced.
const SYSCALL_INSTRUCTION_BYTES: u64 = 2;

/// The shared runtime's saved register context for the syscall `number` at a
/// rewritten site, from SaBRe's trampoline frame.
///
/// The frame holds the guest's general registers as the trampoline saved them
/// and the architectural return address after the displaced `syscall`
/// (`fake_ret`). The context's `instruction_pointer` is `fake_ret - 2`, the
/// address of that `syscall`'s final two bytes (its start, unless it is
/// prefixed), as for a patched LiteInst site and the SIGSYS continuation; the
/// shared entry then reports `rcx = instruction_pointer + 2` exactly as the
/// kernel would. RAX carries the syscall number. The frame
/// saves no extended (FPU/vector) state, so the context says so, as the
/// fallback continuation's does.
pub fn context_from_frame(frame: &syscall_stackframe, number: i64) -> RegisterContext {
    // Default leaves the extended-state descriptor "unavailable".
    let mut context = RegisterContext::default();
    context.instruction_pointer = (frame.fake_ret as u64).wrapping_sub(SYSCALL_INSTRUCTION_BYTES);
    context.stack_pointer = frame.guest_stack_pointer();
    context.r15 = frame.r15 as u64;
    context.r14 = frame.r14 as u64;
    context.r13 = frame.r13 as u64;
    context.r12 = frame.r12 as u64;
    context.r11 = frame.r11 as u64;
    context.r10 = frame.r10 as u64;
    context.r9 = frame.r9 as u64;
    context.r8 = frame.r8 as u64;
    context.rdi = frame.rdi as u64;
    context.rsi = frame.rsi as u64;
    context.rbp = frame.rbp_prologue as u64;
    context.rbx = frame.rbx as u64;
    context.rdx = frame.rdx as u64;
    context.rcx = frame.rcx as u64;
    context.rax = number as u64;
    context.rflags = frame.rflags;
    context
}

/// Whether `frame` is a genuine trampoline frame for the call `args`.
///
/// The loader's router is also entered from its SIGILL handler for a site
/// rewritten to the UD0 marker (and, until the switch, for the supervisor's
/// markers), with a stand-in frame in which only the return slot is real. The
/// router tells the two apart by its route
/// ([`reverie_sabre_stats::SabreDispatchRoute`]), and
/// `dispatch_rewritten_syscall` refuses any route but the trampoline's before
/// it reads the frame; this check is the second line of defence, against a
/// frame that does not match the router's arguments. On a
/// genuine frame the rewrite's own `LEA return(%rip),%rcx` and `PUSHFQ; POP
/// %r11` (vendor/sabre/arch/x86_64/rewriter.c) leave RCX equal to `fake_ret`
/// and R11 equal to the saved RFLAGS, and the saved argument registers are the
/// arguments the router received.
pub fn is_trampoline_frame(frame: &syscall_stackframe, args: [u64; 6]) -> bool {
    frame.rcx as u64 == frame.fake_ret as u64
        && frame.r11 as u64 == frame.rflags
        && [
            frame.rdi as u64,
            frame.rsi as u64,
            frame.rdx as u64,
            frame.r10 as u64,
            frame.r8 as u64,
            frame.r9 as u64,
        ] == args
}

/// A context change SaBRe's trampoline cannot carry back to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unrepresentable {
    /// The trampoline resumes the guest on the stack it saved; it cannot move it.
    StackPointer {
        /// Stack pointer the frame was saved with.
        saved: u64,
        /// Stack pointer the context asks for.
        requested: u64,
    },
    /// The trampoline resumes through its own continuation after the
    /// displaced instructions; it cannot resume anywhere else.
    InstructionPointer {
        /// Instruction pointer the frame was saved with.
        saved: u64,
        /// Instruction pointer the context asks for.
        requested: u64,
    },
}

/// Writes the shared entry's results back into SaBRe's trampoline frame and
/// returns the syscall's result, which the trampoline returns in RAX.
///
/// Every general register the trampoline restores takes the context's value,
/// RCX and R11 included (the shared entry sets them as the kernel's SYSRET
/// would), and so does RFLAGS. The context's stack and instruction pointers
/// must be the ones the frame was saved with (`saved`, as built by
/// [`context_from_frame`]); otherwise nothing is written and the change is
/// reported.
pub fn write_back(
    context: &RegisterContext,
    saved: &RegisterContext,
    frame: &mut syscall_stackframe,
) -> Result<i64, Unrepresentable> {
    if context.stack_pointer != saved.stack_pointer {
        return Err(Unrepresentable::StackPointer {
            saved: saved.stack_pointer,
            requested: context.stack_pointer,
        });
    }
    if context.instruction_pointer != saved.instruction_pointer {
        return Err(Unrepresentable::InstructionPointer {
            saved: saved.instruction_pointer,
            requested: context.instruction_pointer,
        });
    }
    frame.r15 = context.r15 as *mut libc::c_void;
    frame.r14 = context.r14 as *mut libc::c_void;
    frame.r13 = context.r13 as *mut libc::c_void;
    frame.r12 = context.r12 as *mut libc::c_void;
    frame.r11 = context.r11 as *mut libc::c_void;
    frame.r10 = context.r10 as *mut libc::c_void;
    frame.r9 = context.r9 as *mut libc::c_void;
    frame.r8 = context.r8 as *mut libc::c_void;
    frame.rdi = context.rdi as *mut libc::c_void;
    frame.rsi = context.rsi as *mut libc::c_void;
    frame.rbp_prologue = context.rbp as *mut libc::c_void;
    frame.rbx = context.rbx as *mut libc::c_void;
    frame.rdx = context.rdx as *mut libc::c_void;
    frame.rcx = context.rcx as *mut libc::c_void;
    frame.rflags = context.rflags;
    Ok(context.rax as i64)
}

/// Handles the syscall `number` from a rewritten site through the shared
/// runtime's saved-register entry and returns its result for the trampoline.
///
/// `route` is how the loader's router was entered and `args` are the arguments
/// it received. `process` and
/// `observe_nested_mapping` are the installed runtime's own callbacks, exactly
/// those its patched sites and SIGSYS continuation pass. A route other than
/// [`SabreDispatchRoute::Trampoline`] (checked before `frame` is read), a frame
/// that is not a genuine trampoline frame ([`is_trampoline_frame`]), or a
/// context change the trampoline cannot carry back ends the guest with a named
/// refusal (exit 122), written through the runtime's trusted syscall gate.
///
/// # Safety
///
/// When `route` is [`SabreDispatchRoute::Trampoline`], `frame` must be the live
/// trampoline frame of the genuine intercepted guest thread, valid for reads
/// and writes, after the shared runtime is installed and armed on it, and
/// `process`/`observe_nested_mapping` must belong to that installed runtime:
/// every obligation of
/// [`reverie_inguest::guest::installed_tool::dispatch_saved_syscall`] applies.
#[cfg(feature = "shared-entry")]
pub unsafe fn dispatch_rewritten_syscall(
    route: SabreDispatchRoute,
    frame: *mut syscall_stackframe,
    number: i64,
    args: [u64; 6],
    process: unsafe extern "C" fn(*mut core::ffi::c_void),
    observe_nested_mapping: fn(&reverie_inguest::guest::event::SyscallEvent),
) -> i64 {
    if route != SabreDispatchRoute::Trampoline {
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        unsafe { refuse(Refusal::NotTrampolineRoute) };
    }
    let (saved, mut context) = {
        // SAFETY: on the trampoline route the caller supplies this thread's
        // live trampoline frame; it is only read until it has passed the check.
        let frame = unsafe { &*frame };
        if !is_trampoline_frame(frame, args) {
            // SAFETY: refuse writes and exits through the runtime's trusted gate.
            unsafe { refuse(Refusal::NotTrampolineFrame) };
        }
        (
            context_from_frame(frame, number),
            context_from_frame(frame, number),
        )
    };
    // SAFETY: the caller's obligations are those of the shared entry; the
    // context lives on this stack for the synchronous call only.
    unsafe {
        reverie_inguest::guest::installed_tool::dispatch_saved_syscall(
            &mut context,
            Some(number),
            reverie_inguest::guest::event::SyscallDispatch::InstalledHook,
            None,
            process,
            observe_nested_mapping,
            None,
        )
    };
    // SAFETY: the frame passed the check above, and the shared reference used
    // for it has ended.
    let frame = unsafe { &mut *frame };
    match write_back(&context, &saved, frame) {
        Ok(result) => result,
        // SAFETY: refuse writes and exits through the runtime's trusted gate.
        Err(change) => unsafe { refuse(Refusal::Unrepresentable(change)) },
    }
}

#[cfg(feature = "shared-entry")]
enum Refusal {
    NotTrampolineRoute,
    NotTrampolineFrame,
    Unrepresentable(Unrepresentable),
}

#[cfg(feature = "shared-entry")]
unsafe fn refuse(refusal: Refusal) -> ! {
    let message: &[u8] = match refusal {
        Refusal::NotTrampolineRoute => {
            b"reverie-sabre: refused: a syscall from a UD0-marker site reached the shared runtime's entry, which only a rewritten site's trampoline may enter\n"
        }
        Refusal::NotTrampolineFrame => {
            b"reverie-sabre: refused: a syscall reached the shared runtime's entry without a genuine SaBRe trampoline frame for its arguments\n"
        }
        Refusal::Unrepresentable(Unrepresentable::StackPointer { .. }) => {
            b"reverie-sabre: refused: a Tool changed the stack pointer of a rewritten syscall, which SaBRe's trampoline cannot carry back to the guest\n"
        }
        Refusal::Unrepresentable(Unrepresentable::InstructionPointer { .. }) => {
            b"reverie-sabre: refused: a Tool changed the instruction pointer of a rewritten syscall, which SaBRe's trampoline cannot carry back to the guest\n"
        }
    };
    // SAFETY: the runtime's trusted gate issues the write and the exit; the
    // message is a static buffer.
    unsafe {
        let _ = reverie_inguest::trap::raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        );
        reverie_inguest::guest::support::exit_now(122)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARGS: [u64; 6] = [0xd1, 0x51, 0xd, 0x10, 0x8, 0x9];

    /// A frame as the trampoline saves it for getppid(): RCX is the return
    /// address and R11 the pre-syscall RFLAGS, as the rewrite leaves them, and
    /// every other slot holds a distinct value, so a swapped field shows.
    fn frame() -> Box<syscall_stackframe> {
        let p = |value: usize| value as *mut libc::c_void;
        Box::new(syscall_stackframe {
            rbp_stackalign: p(0x1000),
            r15: p(0x15),
            r14: p(0x14),
            r13: p(0x13),
            r12: p(0x12),
            r11: p(0x202),
            r10: p(0x10),
            r9: p(0x9),
            r8: p(0x8),
            rdi: p(0xd1),
            rsi: p(0x51),
            rdx: p(0xd),
            rcx: p(0x40_1236),
            rbx: p(0xb),
            rbp_prologue: p(0xbb),
            rflags: 0x202,
            fake_ret: p(0x40_1236),
            ret: p(0x7000_0000),
        })
    }

    #[test]
    fn context_takes_every_register_and_the_syscall_instruction_address() {
        let frame = frame();
        let context = context_from_frame(&frame, libc::SYS_getppid);
        assert_eq!(context.instruction_pointer, 0x40_1234);
        assert_eq!(context.stack_pointer, frame.guest_stack_pointer());
        assert_eq!(context.rax, libc::SYS_getppid as u64);
        assert_eq!(
            [
                context.r15,
                context.r14,
                context.r13,
                context.r12,
                context.r11,
                context.r10,
                context.r9,
                context.r8,
            ],
            [0x15, 0x14, 0x13, 0x12, 0x202, 0x10, 0x9, 0x8]
        );
        assert_eq!(
            [
                context.rdi,
                context.rsi,
                context.rdx,
                context.rcx,
                context.rbx,
                context.rbp
            ],
            [0xd1, 0x51, 0xd, 0x40_1236, 0xb, 0xbb]
        );
        assert_eq!(context.rflags, 0x202);
        assert!(context.extended_state_unavailable());
    }

    #[test]
    fn context_maps_every_slot_when_all_slots_differ() {
        // Unlike a genuine frame, RCX differs from fake_ret and R11 from
        // RFLAGS, so a context field read from the wrong one of those shows.
        let mut frame = frame();
        frame.rcx = 0xc0c0 as *mut libc::c_void;
        frame.r11 = 0x1111 as *mut libc::c_void;
        frame.rflags = 0x246;
        let context = context_from_frame(&frame, libc::SYS_getppid);
        assert_eq!(context.rcx, 0xc0c0);
        assert_eq!(context.r11, 0x1111);
        assert_eq!(context.rflags, 0x246);
        assert_eq!(context.instruction_pointer, 0x40_1234);
        assert_eq!(context.rbp, 0xbb);
        assert_eq!(context.stack_pointer, frame.guest_stack_pointer());
    }

    #[test]
    fn write_back_carries_every_register_and_leaves_the_trampoline_slots() {
        let mut frame = frame();
        let saved = context_from_frame(&frame, libc::SYS_getppid);
        let mut context = context_from_frame(&frame, libc::SYS_getppid);
        // A distinct new value in every field the trampoline restores.
        context.rax = 4242;
        context.r15 = 0x1015;
        context.r14 = 0x1014;
        context.r13 = 0x1013;
        context.r12 = 0x1012;
        context.r11 = 0x1011;
        context.r10 = 0x1010;
        context.r9 = 0x1009;
        context.r8 = 0x1008;
        context.rdi = 0x10d1;
        context.rsi = 0x1051;
        context.rdx = 0x100d;
        context.rcx = 0x100c;
        context.rbx = 0x100b;
        context.rbp = 0x10bb;
        context.rflags = 0x203;
        assert_eq!(write_back(&context, &saved, &mut frame), Ok(4242));
        assert_eq!(
            [
                frame.r15 as u64,
                frame.r14 as u64,
                frame.r13 as u64,
                frame.r12 as u64,
                frame.r11 as u64,
                frame.r10 as u64,
                frame.r9 as u64,
                frame.r8 as u64,
            ],
            [
                0x1015, 0x1014, 0x1013, 0x1012, 0x1011, 0x1010, 0x1009, 0x1008
            ]
        );
        assert_eq!(
            [
                frame.rdi as u64,
                frame.rsi as u64,
                frame.rdx as u64,
                frame.rcx as u64,
                frame.rbx as u64,
                frame.rbp_prologue as u64,
            ],
            [0x10d1, 0x1051, 0x100d, 0x100c, 0x100b, 0x10bb]
        );
        assert_eq!(frame.rflags, 0x203);
        // The trampoline's own slots stay untouched.
        assert_eq!(frame.rbp_stackalign as u64, 0x1000);
        assert_eq!(frame.fake_ret as u64, 0x40_1236);
        assert_eq!(frame.ret as u64, 0x7000_0000);
    }

    #[test]
    fn write_back_of_a_completed_syscall_gives_the_kernel_clobbers() {
        let mut frame = frame();
        let saved = context_from_frame(&frame, libc::SYS_getppid);
        let mut context = context_from_frame(&frame, libc::SYS_getppid);
        // What the shared entry leaves after a completed syscall.
        context.rax = 7;
        context.rcx = context.instruction_pointer + 2;
        context.r11 = context.rflags;
        assert_eq!(write_back(&context, &saved, &mut frame), Ok(7));
        assert_eq!(frame.rcx as u64, frame.fake_ret as u64);
        assert_eq!(frame.r11 as u64, frame.rflags);
    }

    #[test]
    fn write_back_refuses_a_moved_stack_or_instruction_and_writes_nothing() {
        let mut frame = frame();
        let saved = context_from_frame(&frame, libc::SYS_getppid);
        let mut context = context_from_frame(&frame, libc::SYS_getppid);
        context.rdi = 0x77;
        context.stack_pointer += 8;
        assert_eq!(
            write_back(&context, &saved, &mut frame),
            Err(Unrepresentable::StackPointer {
                saved: saved.stack_pointer,
                requested: saved.stack_pointer + 8,
            })
        );
        assert_eq!(frame.rdi as u64, 0xd1);

        let mut context = context_from_frame(&frame, libc::SYS_getppid);
        context.rdi = 0x77;
        context.instruction_pointer = 0x50_0000;
        assert_eq!(
            write_back(&context, &saved, &mut frame),
            Err(Unrepresentable::InstructionPointer {
                saved: 0x40_1234,
                requested: 0x50_0000,
            })
        );
        assert_eq!(frame.rdi as u64, 0xd1);
    }

    #[test]
    fn only_a_genuine_trampoline_frame_for_these_arguments_is_accepted() {
        let genuine = frame();
        assert!(is_trampoline_frame(&genuine, ARGS));

        // The SIGILL stand-in frame has only its return slot right.
        let mut rcx = frame();
        rcx.rcx = 0x1234 as *mut libc::c_void;
        assert!(!is_trampoline_frame(&rcx, ARGS));
        let mut r11 = frame();
        r11.r11 = 0x246 as *mut libc::c_void;
        assert!(!is_trampoline_frame(&r11, ARGS));
        for index in 0..6 {
            let mut args = ARGS;
            args[index] ^= 0x100;
            assert!(!is_trampoline_frame(&genuine, args), "argument {index}");
        }
    }
}
