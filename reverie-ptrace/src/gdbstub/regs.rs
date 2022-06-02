/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use serde::{Deserialize, Serialize};
use std::fmt;

use super::response::*;

#[repr(transparent)]
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
/// 80-bit FPU register, see gdb/64bit-core.xml
pub struct Fp80([u8; 10]);

// NB: st from `libc::user_fpregs_struct' has a different representation.
fn from_u32s(st: &[u32]) -> Fp80 {
    Fp80([
        (st[0] & 0xff) as u8,
        ((st[0] >> 8) & 0xff) as u8,
        ((st[0] >> 16) & 0xff) as u8,
        ((st[0] >> 24) & 0xff) as u8,
        (st[1] & 0xff) as u8,
        ((st[1] >> 8) & 0xff) as u8,
        ((st[1] >> 16) & 0xff) as u8,
        ((st[1] >> 24) & 0xff) as u8,
        (st[2] & 0xff) as u8,
        ((st[2] >> 8) & 0xff) as u8,
    ])
}

impl From<[u32; 4]> for Fp80 {
    fn from(v: [u32; 4]) -> Fp80 {
        from_u32s(&v)
    }
}

fn from_fp80(fp: &Fp80, u32s: &mut [u32]) {
    u32s[0] =
        fp.0[0] as u32 | (fp.0[1] as u32) << 8 | (fp.0[2] as u32) << 16 | (fp.0[3] as u32) << 24;
    u32s[1] =
        fp.0[4] as u32 | (fp.0[5] as u32) << 8 | (fp.0[6] as u32) << 16 | (fp.0[7] as u32) << 24;
    u32s[2] = fp.0[8] as u32 | (fp.0[9] as u32) << 8;
    u32s[3] = 0;
}

impl From<Fp80> for [u32; 4] {
    fn from(fp: Fp80) -> [u32; 4] {
        let mut res: [u32; 4] = [0; 4];
        from_fp80(&fp, &mut res);
        res
    }
}

#[repr(transparent)]
struct St([Fp80; 8]);

impl From<[u32; 32]> for St {
    fn from(st: [u32; 32]) -> Self {
        St([
            from_u32s(&st[0..]),
            from_u32s(&st[4..]),
            from_u32s(&st[8..]),
            from_u32s(&st[12..]),
            from_u32s(&st[16..]),
            from_u32s(&st[20..]),
            from_u32s(&st[24..]),
            from_u32s(&st[28..]),
        ])
    }
}

impl From<St> for [u32; 32] {
    fn from(st: St) -> [u32; 32] {
        let mut res: [u32; 32] = [0; 32];
        from_fp80(&st.0[0], &mut res[0..]);
        from_fp80(&st.0[1], &mut res[4..]);
        from_fp80(&st.0[2], &mut res[8..]);
        from_fp80(&st.0[3], &mut res[12..]);
        from_fp80(&st.0[4], &mut res[16..]);
        from_fp80(&st.0[5], &mut res[20..]);
        from_fp80(&st.0[6], &mut res[24..]);
        from_fp80(&st.0[7], &mut res[28..]);
        res
    }
}

#[repr(transparent)]
struct Xmm([u128; 16]);

impl From<[u32; 64]> for Xmm {
    fn from(xmm: [u32; 64]) -> Self {
        Xmm([
            (xmm[3] as u128) << 96
                | (xmm[2] as u128) << 64
                | (xmm[1] as u128) << 32
                | (xmm[0] as u128),
            (xmm[7] as u128) << 96
                | (xmm[6] as u128) << 64
                | (xmm[5] as u128) << 32
                | (xmm[4] as u128),
            (xmm[11] as u128) << 96
                | (xmm[10] as u128) << 64
                | (xmm[9] as u128) << 32
                | (xmm[8] as u128),
            (xmm[15] as u128) << 96
                | (xmm[14] as u128) << 64
                | (xmm[13] as u128) << 32
                | (xmm[12] as u128),
            (xmm[19] as u128) << 96
                | (xmm[18] as u128) << 64
                | (xmm[17] as u128) << 32
                | (xmm[16] as u128),
            (xmm[23] as u128) << 96
                | (xmm[22] as u128) << 64
                | (xmm[21] as u128) << 32
                | (xmm[20] as u128),
            (xmm[27] as u128) << 96
                | (xmm[26] as u128) << 64
                | (xmm[25] as u128) << 32
                | (xmm[24] as u128),
            (xmm[31] as u128) << 96
                | (xmm[30] as u128) << 64
                | (xmm[29] as u128) << 32
                | (xmm[28] as u128),
            (xmm[35] as u128) << 96
                | (xmm[34] as u128) << 64
                | (xmm[33] as u128) << 32
                | (xmm[32] as u128),
            (xmm[39] as u128) << 96
                | (xmm[38] as u128) << 64
                | (xmm[37] as u128) << 32
                | (xmm[36] as u128),
            (xmm[43] as u128) << 96
                | (xmm[42] as u128) << 64
                | (xmm[41] as u128) << 32
                | (xmm[40] as u128),
            (xmm[47] as u128) << 96
                | (xmm[46] as u128) << 64
                | (xmm[45] as u128) << 32
                | (xmm[44] as u128),
            (xmm[51] as u128) << 96
                | (xmm[50] as u128) << 64
                | (xmm[49] as u128) << 32
                | (xmm[48] as u128),
            (xmm[55] as u128) << 96
                | (xmm[54] as u128) << 64
                | (xmm[53] as u128) << 32
                | (xmm[52] as u128),
            (xmm[59] as u128) << 96
                | (xmm[58] as u128) << 64
                | (xmm[57] as u128) << 32
                | (xmm[56] as u128),
            (xmm[63] as u128) << 96
                | (xmm[62] as u128) << 64
                | (xmm[61] as u128) << 32
                | (xmm[60] as u128),
        ])
    }
}

fn u128_to_u32s(u: u128, u32s: &mut [u32]) {
    u32s[0] = u as u32;
    u32s[1] = (u >> 32) as u32;
    u32s[2] = (u >> 64) as u32;
    u32s[3] = (u >> 96) as u32;
}

impl From<Xmm> for [u32; 64] {
    fn from(xmm: Xmm) -> [u32; 64] {
        let mut res: [u32; 64] = [0; 64];
        u128_to_u32s(xmm.0[0], &mut res[0..]);
        u128_to_u32s(xmm.0[1], &mut res[4..]);
        u128_to_u32s(xmm.0[2], &mut res[8..]);
        u128_to_u32s(xmm.0[3], &mut res[12..]);
        u128_to_u32s(xmm.0[4], &mut res[16..]);
        u128_to_u32s(xmm.0[5], &mut res[20..]);
        u128_to_u32s(xmm.0[6], &mut res[24..]);
        u128_to_u32s(xmm.0[7], &mut res[28..]);
        u128_to_u32s(xmm.0[8], &mut res[32..]);
        u128_to_u32s(xmm.0[9], &mut res[36..]);
        u128_to_u32s(xmm.0[10], &mut res[40..]);
        u128_to_u32s(xmm.0[11], &mut res[44..]);
        u128_to_u32s(xmm.0[12], &mut res[48..]);
        u128_to_u32s(xmm.0[13], &mut res[52..]);
        u128_to_u32s(xmm.0[14], &mut res[56..]);
        u128_to_u32s(xmm.0[15], &mut res[60..]);
        res
    }
}

/// i387 regs, gdb layout.
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct X87Regs {
    /// fctrl
    pub fctrl: u32,
    /// fstat
    pub fstat: u32,
    /// ftag
    pub ftag: u32,
    /// fiseg
    pub fiseg: u32,
    /// fioff
    pub fioff: u32,
    /// foseg
    pub foseg: u32,
    /// fooff
    pub fooff: u32,
    /// fop
    pub fop: u32,
}

/// arm64 core/sse regs, see gdb/64bit-{core,sse}-linux.xml.
/// This is the same as: 64bit-core+64bit-sse+64bit-linux.
#[derive(Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct Amd64CoreRegs {
    /// general purpose regsiters
    /// rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8..r15
    pub regs: [u64; 16],
    /// rip aka instruction pointer
    pub rip: u64,
    /// eflags
    pub eflags: u32,
    /// cs, ss, ds, es, fs, gs
    pub segments: [u32; 6],
    /// 80-bit fpu regs
    pub st: [Fp80; 8],
    /// fpu control regs
    pub x87: X87Regs,
    /// SSE registers
    pub xmm: [u128; 16],
    /// Sse status/control
    pub mxcsr: u32,
    pub orig_rax: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

impl fmt::Debug for Amd64CoreRegs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Amd64CoreRegs")
            .field("rax", &self.regs[0])
            .field("rbx", &self.regs[1])
            .field("rcx", &self.regs[2])
            .field("rdx", &self.regs[3])
            .field("rsi", &self.regs[4])
            .field("rdi", &self.regs[5])
            .field("rbp", &self.regs[6])
            .field("rsp", &self.regs[7])
            .field("r8", &self.regs[8])
            .field("r9", &self.regs[9])
            .field("r10", &self.regs[10])
            .field("r11", &self.regs[11])
            .field("r12", &self.regs[12])
            .field("r13", &self.regs[13])
            .field("r14", &self.regs[14])
            .field("r15", &self.regs[15])
            .field("rip", &self.rip)
            .field("eflags", &self.eflags)
            .field("cs", &self.segments[0])
            .field("ss", &self.segments[1])
            .field("ds", &self.segments[2])
            .field("es", &self.segments[3])
            .field("fs", &self.segments[4])
            .field("gs", &self.segments[5])
            .field("st", &self.st)
            .field("x87", &self.x87)
            .field("xmm", &self.xmm)
            .field("mxcsr", &self.mxcsr)
            .field("orig_rax", &self.orig_rax)
            .field("fs_base", &self.fs_base)
            .field("gs_base", &self.gs_base)
            .finish()
    }
}

impl Amd64CoreRegs {
    /// create `Amd64CoreRegs` from user and fp regs.
    pub fn from(regs: libc::user_regs_struct, i387: libc::user_fpregs_struct) -> Self {
        Amd64CoreRegs {
            regs: [
                regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.rsp,
                regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15,
            ],
            rip: regs.rip,
            eflags: regs.eflags as u32,
            segments: [
                regs.cs as u32,
                regs.ss as u32,
                regs.ds as u32,
                regs.es as u32,
                regs.fs as u32,
                regs.fs as u32,
            ],
            st: St::from(i387.st_space).0,
            // NB: fpu/fxsave layout, see https://github.com/rr-debugger/rr/blob/master/src/ExtraRegisters.cc and
            // https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/user_64.h#L51
            x87: X87Regs {
                fctrl: i387.cwd as u32,                // 0, short
                fstat: i387.swd as u32,                // 2, short
                ftag: i387.ftw as u32,                 // 4, short
                fiseg: (i387.rip >> 32) as u32,        // 12,
                fioff: (i387.rip & 0xffffffff) as u32, // 8,
                foseg: (i387.rdp >> 32) as u32,        // 20,
                fooff: (i387.rdp & 0xffffffff) as u32, // 16,
                fop: i387.fop as u32,                  // 6, short
            },
            xmm: Xmm::from(i387.xmm_space).0,
            mxcsr: i387.mxcsr,
            orig_rax: regs.orig_rax,
            fs_base: regs.fs_base,
            gs_base: regs.gs_base,
        }
    }

    pub fn into_parts(self) -> (libc::user_regs_struct, libc::user_fpregs_struct) {
        // NB: `padding` is private so we cannot use struct literal syntax.
        let mut fpregs_intializer: libc::user_fpregs_struct =
            unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        fpregs_intializer.cwd = self.x87.fctrl as u16;
        fpregs_intializer.swd = self.x87.fstat as u16;
        fpregs_intializer.ftw = self.x87.ftag as u16;
        fpregs_intializer.fop = self.x87.fop as u16;
        fpregs_intializer.rip = self.x87.fioff as u64 | ((self.x87.fiseg as u64) << 32);
        fpregs_intializer.rdp = self.x87.fooff as u64 | ((self.x87.foseg as u64) << 32);
        fpregs_intializer.mxcsr = self.mxcsr;
        fpregs_intializer.mxcr_mask = 0xffff; // only bit 0-15 are valid.
        fpregs_intializer.st_space = St(self.st).into();
        fpregs_intializer.xmm_space = Xmm(self.xmm).into();
        (
            libc::user_regs_struct {
                rax: self.regs[0],
                rbx: self.regs[1],
                rcx: self.regs[2],
                rdx: self.regs[3],
                rsi: self.regs[4],
                rdi: self.regs[5],
                rbp: self.regs[6],
                rsp: self.regs[7],
                r8: self.regs[8],
                r9: self.regs[9],
                r10: self.regs[10],
                r11: self.regs[11],
                r12: self.regs[12],
                r13: self.regs[13],
                r14: self.regs[14],
                r15: self.regs[15],
                orig_rax: self.orig_rax,
                rip: self.rip,
                cs: self.segments[0] as u64,
                ss: self.segments[1] as u64,
                ds: self.segments[2] as u64,
                es: self.segments[3] as u64,
                fs: self.segments[4] as u64,
                gs: self.segments[5] as u64,
                eflags: self.eflags as u64,
                fs_base: self.fs_base,
                gs_base: self.gs_base,
            },
            fpregs_intializer,
        )
    }
}

impl WriteResponse for ResponseAsHex<Amd64CoreRegs> {
    fn write_response(&self, f: &mut ResponseWriter) {
        let encoded: Vec<u8> = bincode::serialize(&self.0).unwrap();
        ResponseAsHex(encoded.as_slice()).write_response(f)
    }
}

impl WriteResponse for ResponseAsBinary<Amd64CoreRegs> {
    fn write_response(&self, f: &mut ResponseWriter) {
        let encoded: Vec<u8> = bincode::serialize(&self.0).unwrap();
        ResponseAsBinary(encoded.as_slice()).write_response(f)
    }
}

/// amd64 avx regs
#[derive(Debug, Default, PartialEq, Clone, Deserialize, Serialize)]
pub struct Amd64ExtraRegs {
    /// avx registers
    pub ymm: [u128; 32],
    /// avx512 registers
    pub ymmh: [u128; 32],
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;

    #[test]
    fn fp80_sanity() {
        assert_eq!(mem::size_of::<Fp80>(), 10);
        let u32s: [u32; 4] = [0x12345678, 0x87654321, 0xabcd, 0];
        let fp80: Fp80 = Fp80::from(u32s);
        let u32s_1: [u32; 4] = fp80.into();
        assert_eq!(u32s, u32s_1);
    }

    #[test]
    fn st_sanity() {
        let u32s: [u32; 32] = [
            0x12345678, 0x87654321, 0xabcd, 0, 0x34127856, 0x56781234, 0xcdab, 0, 0x11223344,
            0x44332211, 0xcadb, 0, 0x55667788, 0xaabbccdd, 0x1423, 0, 0x44332211, 0x11223344,
            0x5678, 0, 0xaabbccdd, 0xddccbbaa, 0x1234, 0, 0xabcdabcd, 0xdeadbeef, 0x9876, 0,
            0xdeadbeef, 0xdcbadcba, 0xac12, 0,
        ];
        let st: St = St::from(u32s);
        let u32s_1: [u32; 32] = st.into();
        assert_eq!(u32s, u32s_1);
    }

    #[test]
    fn xmm_sanity() {
        let u32s: [u32; 64] = [
            0x12345678, 0x87654321, 0xaabbccdd, 0xddccbbaa, 0x34127856, 0x65872143, 0xbbaaddcc,
            0xccddaabb, 0xccddaabb, 0xbbaaddcc, 0x65872143, 0x34127856, 0xddccbbaa, 0xaabbccdd,
            0x87654321, 0x12345678, 0x12345678, 0x87654321, 0xaabbccdd, 0xddccbbaa, 0x34127856,
            0x65872143, 0xbbaaddcc, 0xccddaabb, 0xccddaabb, 0xbbaaddcc, 0x65872143, 0x34127856,
            0xddccbbaa, 0xaabbccdd, 0x87654321, 0x12345678, 0x12345678, 0x87654321, 0xaabbccdd,
            0xddccbbaa, 0x34127856, 0x65872143, 0xbbaaddcc, 0xccddaabb, 0xccddaabb, 0xbbaaddcc,
            0x65872143, 0x34127856, 0xddccbbaa, 0xaabbccdd, 0x87654321, 0x12345678, 0x12345678,
            0x87654321, 0xaabbccdd, 0xddccbbaa, 0x34127856, 0x65872143, 0xbbaaddcc, 0xccddaabb,
            0xccddaabb, 0xbbaaddcc, 0x65872143, 0x34127856, 0xddccbbaa, 0xaabbccdd, 0x87654321,
            0x12345678,
        ];
        let xmm: Xmm = Xmm::from(u32s);
        let u32s_1: [u32; 64] = xmm.into();
        assert_eq!(u32s, u32s_1);
    }

    #[test]
    fn amd64_core_regs_sanity() {
        const EXPECTED_SIZE: usize = 16 * 8 + 8 + 4 + 4 * 6 + 10 * 8 + 8 * 4 + 16 * 16 + 4 + 8 * 3; // 560.
        assert_eq!(mem::size_of::<Amd64CoreRegs>(), EXPECTED_SIZE);
        let core_regs: Amd64CoreRegs = Default::default();
        let encoded: Vec<u8> = bincode::serialize(&core_regs).unwrap();
        assert_eq!(encoded.len(), EXPECTED_SIZE);
    }

    #[test]
    fn amd64_core_regs_serde() {
        let core_regs: Amd64CoreRegs = Amd64CoreRegs {
            regs: [
                0x1c,
                0,
                0,
                0x7ffff7fe2f80,
                0x7ffff7ffe6c8,
                0x7ffff7ffe130,
                0,
                0x7fffffffdd20,
                0x4d,
                0x7ffff7f91860,
                0xc2,
                0,
                0x401040,
                0x7fffffffdd20,
                0,
                0,
            ],
            rip: 0x401040,
            eflags: 0x206,
            segments: [0x33, 0x2b, 0, 0, 0, 0],
            st: [
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                Fp80([0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ],
            x87: X87Regs {
                fctrl: 0x37f,
                fstat: 0,
                ftag: 0,
                fiseg: 0,
                fioff: 0,
                foseg: 0,
                fooff: 0,
                fop: 0,
            },
            xmm: [
                0xff000000,
                0x2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f,
                0xff000000000000,
                0xff0000000000000000ff000000ff0000,
                0,
                0,
                6,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
            mxcsr: 0x1f80,
            orig_rax: 0xffffffffffffffff,
            fs_base: 0x7ffff7fcd540,
            gs_base: 0,
        };
        let encoded: Vec<u8> = bincode::serialize(&core_regs).unwrap();
        // NB: keep this so that we can *visualize* how core regs are
        // serialized.
        let expected: Vec<u8> = vec![
            0x1c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x2f, 0xfe, 0xf7, 0xff, 0x7f, 0x0, 0x0, 0xc8,
            0xe6, 0xff, 0xf7, 0xff, 0x7f, 0x0, 0x0, 0x30, 0xe1, 0xff, 0xf7, 0xff, 0x7f, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0xdd, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0,
            0x4d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x60, 0x18, 0xf9, 0xf7, 0xff, 0x7f, 0x0, 0x0,
            0xc2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40,
            0x10, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0xdd, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x40, 0x10,
            0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x2, 0x0, 0x0, 0x33, 0x0, 0x0, 0x0, 0x2b, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7f, 0x3, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
            0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0xff,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x80, 0x1f, 0x0,
            0x0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x40, 0xd5, 0xfc, 0xf7, 0xff,
            0x7f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        assert_eq!(encoded, expected);
        let core_regs2 = bincode::deserialize(&encoded).unwrap();
        assert_eq!(core_regs, core_regs2);
    }
}
