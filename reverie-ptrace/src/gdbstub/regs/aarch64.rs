/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::mem::MaybeUninit;

use serde::Deserialize;
use serde::Serialize;

use super::super::response::*;

/// GDB-specific definition of the general purpose registers. This is only
/// *slightly* different from `libc::user_regs_struct`.
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct GeneralRegs {
    // General purpose registers
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr_flags: u32,
}

/// GDB-specific definition of the FPU registers.
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct FpRegs {
    pub vregs: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

/// GDB-specific definition of the registers. This is only *slightly* different
/// from `libc::user_regs_struct`.
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct CoreRegs {
    // General purpose registers
    pub gpr: GeneralRegs,

    // FPU registers
    pub fpr: FpRegs,
}

impl From<libc::user_regs_struct> for GeneralRegs {
    fn from(regs: libc::user_regs_struct) -> Self {
        Self {
            x0: regs.regs[0],
            x1: regs.regs[1],
            x2: regs.regs[2],
            x3: regs.regs[3],
            x4: regs.regs[4],
            x5: regs.regs[5],
            x6: regs.regs[6],
            x7: regs.regs[7],
            x8: regs.regs[8],
            x9: regs.regs[9],
            x10: regs.regs[10],
            x11: regs.regs[11],
            x12: regs.regs[12],
            x13: regs.regs[13],
            x14: regs.regs[14],
            x15: regs.regs[15],
            x16: regs.regs[16],
            x17: regs.regs[17],
            x18: regs.regs[18],
            x19: regs.regs[19],
            x20: regs.regs[20],
            x21: regs.regs[21],
            x22: regs.regs[22],
            x23: regs.regs[23],
            x24: regs.regs[24],
            x25: regs.regs[25],
            x26: regs.regs[26],
            x27: regs.regs[27],
            x28: regs.regs[28],
            x29: regs.regs[29],
            x30: regs.regs[30],
            sp: regs.sp,
            pc: regs.pc,
            cpsr_flags: regs.pstate as u32,
        }
    }
}

impl From<GeneralRegs> for libc::user_regs_struct {
    fn from(regs: GeneralRegs) -> Self {
        let mut out = unsafe { MaybeUninit::<Self>::zeroed().assume_init() };
        out.regs[0] = regs.x0;
        out.regs[1] = regs.x1;
        out.regs[2] = regs.x2;
        out.regs[3] = regs.x3;
        out.regs[4] = regs.x4;
        out.regs[5] = regs.x5;
        out.regs[6] = regs.x6;
        out.regs[7] = regs.x7;
        out.regs[8] = regs.x8;
        out.regs[9] = regs.x9;
        out.regs[10] = regs.x10;
        out.regs[11] = regs.x11;
        out.regs[12] = regs.x12;
        out.regs[13] = regs.x13;
        out.regs[14] = regs.x14;
        out.regs[15] = regs.x15;
        out.regs[16] = regs.x16;
        out.regs[17] = regs.x17;
        out.regs[18] = regs.x18;
        out.regs[19] = regs.x19;
        out.regs[20] = regs.x20;
        out.regs[21] = regs.x21;
        out.regs[22] = regs.x22;
        out.regs[23] = regs.x23;
        out.regs[24] = regs.x24;
        out.regs[25] = regs.x25;
        out.regs[26] = regs.x26;
        out.regs[27] = regs.x27;
        out.regs[28] = regs.x28;
        out.regs[29] = regs.x29;
        out.regs[30] = regs.x30;
        out.sp = regs.sp;
        out.pc = regs.pc;
        out.pstate = regs.cpsr_flags as u64;
        out
    }
}

impl From<safeptrace::FpRegs> for FpRegs {
    fn from(regs: safeptrace::FpRegs) -> Self {
        Self {
            vregs: regs.vregs,
            fpsr: regs.fpsr,
            fpcr: regs.fpcr,
        }
    }
}

impl From<FpRegs> for safeptrace::FpRegs {
    fn from(regs: FpRegs) -> Self {
        let mut out = unsafe { MaybeUninit::<Self>::zeroed().assume_init() };
        out.vregs = regs.vregs;
        out.fpsr = regs.fpsr;
        out.fpcr = regs.fpcr;
        out
    }
}

impl CoreRegs {
    pub fn from_parts(gpr: libc::user_regs_struct, fpr: safeptrace::FpRegs) -> Self {
        Self {
            gpr: gpr.into(),
            fpr: fpr.into(),
        }
    }

    pub fn into_parts(self) -> (libc::user_regs_struct, safeptrace::FpRegs) {
        (self.gpr.into(), self.fpr.into())
    }
}

impl WriteResponse for ResponseAsHex<CoreRegs> {
    fn write_response(&self, f: &mut ResponseWriter) {
        let encoded: Vec<u8> = bincode::serialize(&self.0).unwrap();
        ResponseAsHex(encoded.as_slice()).write_response(f)
    }
}

impl WriteResponse for ResponseAsBinary<CoreRegs> {
    fn write_response(&self, f: &mut ResponseWriter) {
        let encoded: Vec<u8> = bincode::serialize(&self.0).unwrap();
        ResponseAsBinary(encoded.as_slice()).write_response(f)
    }
}
