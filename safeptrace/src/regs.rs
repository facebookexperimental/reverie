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
