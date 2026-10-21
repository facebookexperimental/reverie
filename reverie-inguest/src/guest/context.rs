/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The register context a hook or the fallback continuation saves for one
//! guest event.

/// The guest's general-purpose registers at a hooked or continued
/// instruction, saved by the trampoline or continuation that entered the
/// runtime. Its layout is fixed (176 bytes): it is the same block LiteInst's
/// trampolines (liteinst2's `HookContext`) and the fallback continuation save,
/// and the runtime reads and writes it through a pointer.
#[repr(C)]
#[derive(Debug, Default)]
pub struct RegisterContext {
    /// Address of the displaced (hooked or continued) instruction.
    pub instruction_pointer: u64,
    /// Application RSP at that instruction.
    pub stack_pointer: u64,
    /// Saved R15.
    pub r15: u64,
    /// Saved R14.
    pub r14: u64,
    /// Saved R13.
    pub r13: u64,
    /// Saved R12.
    pub r12: u64,
    /// Saved R11.
    pub r11: u64,
    /// Saved R10.
    pub r10: u64,
    /// Saved R9.
    pub r9: u64,
    /// Saved R8.
    pub r8: u64,
    /// Saved RDI.
    pub rdi: u64,
    /// Saved RSI.
    pub rsi: u64,
    /// Saved RBP.
    pub rbp: u64,
    /// Saved RBX.
    pub rbx: u64,
    /// Saved RDX.
    pub rdx: u64,
    /// Saved RCX.
    pub rcx: u64,
    /// Saved RAX.
    pub rax: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
    /// The saver's descriptor of the saved extended (FPU/vector) state;
    /// opaque here and never written. All zeros means no saved state (the
    /// trampolines' "unavailable" descriptor), which is what [`Default`]
    /// gives.
    saved_extended_state: [u64; 4],
}

impl RegisterContext {
    /// Whether the context carries no saved extended state, as one built by
    /// the fallback continuation (or [`Default`]) does.
    pub fn extended_state_unavailable(&self) -> bool {
        self.saved_extended_state == [0; 4]
    }
}

const _: () = {
    assert!(core::mem::size_of::<RegisterContext>() == 176);
    assert!(core::mem::align_of::<RegisterContext>() == 8);
    assert!(core::mem::offset_of!(RegisterContext, r11) == 48);
    assert!(core::mem::offset_of!(RegisterContext, rflags) == 136);
};
