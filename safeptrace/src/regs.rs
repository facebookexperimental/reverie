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
