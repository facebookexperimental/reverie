/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(target_arch = "x86_64")]
pub use libc::user_fpregs_struct as FpRegs;
pub use libc::user_regs_struct as Regs;

/// Variable-length x86 extended processor state returned by `NT_X86_XSTATE`.
///
/// This includes the legacy x87/SSE state plus every kernel-exposed XSAVE
/// component enabled for the tracee. The bytes are intentionally opaque: a
/// caller may save and restore them, but should not assume a fixed layout.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-270): Review public opaque XSTATE save/restore storage.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XState(pub(crate) Vec<u8>);

/// Floating point registers.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[allow(missing_docs)]
pub struct FpRegs {
    pub vregs: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    __reserved: [u32; 2],
}

#[cfg(target_arch = "x86_64")]
mod xstate_pkru;
#[cfg(target_arch = "x86_64")]
pub use xstate_pkru::XStatePkruError;

/// One breakpoint register pair of a thread's hardware breakpoints:
/// `struct user_hwdebug_state`'s `dbg_regs` entry
/// (arch/arm64/include/uapi/asm/ptrace.h).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
pub struct HwBreakpoint {
    /// The address of the instruction the breakpoint matches.
    pub addr: u64,
    /// The breakpoint control register (DBGBCR) value: bit 0 enables it.
    pub ctrl: u32,
    pad: u32,
}

#[cfg(target_arch = "aarch64")]
impl HwBreakpoint {
    /// An enabled breakpoint on the A64 instruction at `addr`, matched at
    /// EL0: byte address select 0b1111, privilege EL0, enabled.
    pub fn at(addr: u64) -> Self {
        Self {
            addr,
            ctrl: (0b1111 << 5) | (0b10 << 1) | 1,
            pad: 0,
        }
    }

    /// Whether the breakpoint is enabled.
    pub fn enabled(&self) -> bool {
        self.ctrl & 1 != 0
    }
}

/// A thread's hardware breakpoints, `NT_ARM_HW_BREAK`'s
/// `struct user_hwdebug_state`.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct HwBreakpoints {
    dbg_info: u32,
    pad: u32,
    /// The breakpoint registers. Only the first [`HwBreakpoints::slots`]
    /// exist in hardware.
    pub regs: [HwBreakpoint; 16],
}

#[cfg(target_arch = "aarch64")]
impl HwBreakpoints {
    /// How many breakpoint registers the hardware has: the low byte of
    /// `dbg_info`.
    pub fn slots(&self) -> usize {
        usize::from(self.dbg_info as u8).min(self.regs.len())
    }
}
