/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Decoding for branch-to-branch steps toward a precise timer target on
//! aarch64, which has no block step.
//!
//! A run starts at a stop point or anywhere before one, and ends at the next
//! stop point: the first instruction, in straight-line order, that may change
//! the flow of control, trap, or touch an exclusive monitor (see [`classify`]).
//! Every instruction before it falls through to the next one, so a run that
//! a hardware breakpoint ends there retires no branch of its own. A run that
//! starts at a branch whose successors are known retires exactly that branch.

/// How many A64 instructions are decoded forward from an address, at most.
pub(crate) const STOP_WINDOW: usize = 64;

/// What a stop point is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// A branch whose successors its encoding gives: B, BL, B.cond, BC.cond,
    /// CBZ, CBNZ, TBZ and TBNZ. A conditional one also falls through.
    Direct { target: u64, conditional: bool },
    /// BR, BLR or RET, without pointer authentication: to the address in
    /// general register `reg`.
    Register { reg: u8 },
    /// Anything else that ends a run, to be single stepped: any other branch
    /// (pointer-authenticated, exception return), an exception-generating
    /// instruction (SVC, BRK and the others), a system instruction other than
    /// the few that run straight through ([`system_runs_straight`]), a
    /// load or store exclusive, and the reserved and unallocated groups.
    Other,
}

impl Stop {
    /// The addresses control can reach after the branch at `at` retires,
    /// given the general registers `x`; `None` for a stop point whose
    /// successors are not known.
    pub(crate) fn successors(self, at: u64, x: &[u64; 31]) -> Option<([u64; 2], usize)> {
        match self {
            Stop::Direct {
                target,
                conditional: false,
            } => Some(([target, target], 1)),
            Stop::Direct {
                target,
                conditional: true,
            } if target == at.wrapping_add(4) => Some(([target, target], 1)),
            Stop::Direct {
                target,
                conditional: true,
            } => Some(([at.wrapping_add(4), target], 2)),
            // Register 31 is not a general register here.
            Stop::Register { reg } => x.get(usize::from(reg)).map(|&to| ([to, to], 1)),
            Stop::Other => None,
        }
    }
}

/// Sign-extends the low `bits` bits of `value`.
fn sign_extend(value: u64, bits: u32) -> i64 {
    ((value << (64 - bits)) as i64) >> (64 - bits)
}

/// Whether the A64 instruction `insn` at `pc` is a stop point, and which.
/// `None` for an instruction that always falls through to the next one
/// without a branch, a trap or an exclusive access.
pub(crate) fn classify(insn: u32, pc: u64) -> Option<Stop> {
    let offset =
        |imm: u32, bits: u32| pc.wrapping_add_signed(sign_extend(u64::from(imm) << 2, bits + 2));
    // B, BL: imm26.
    if insn & 0x7c00_0000 == 0x1400_0000 {
        return Some(Stop::Direct {
            target: offset(insn & 0x03ff_ffff, 26),
            conditional: false,
        });
    }
    // B.cond, BC.cond: imm19.
    if insn & 0xff00_0000 == 0x5400_0000 {
        return Some(Stop::Direct {
            target: offset((insn >> 5) & 0x7_ffff, 19),
            conditional: true,
        });
    }
    // CBZ, CBNZ: imm19.
    if insn & 0x7e00_0000 == 0x3400_0000 {
        return Some(Stop::Direct {
            target: offset((insn >> 5) & 0x7_ffff, 19),
            conditional: true,
        });
    }
    // TBZ, TBNZ: imm14.
    if insn & 0x7e00_0000 == 0x3600_0000 {
        return Some(Stop::Direct {
            target: offset((insn >> 5) & 0x3fff, 14),
            conditional: true,
        });
    }
    // BR, BLR, RET without pointer authentication.
    if matches!(insn & 0xffff_fc1f, 0xd61f_0000 | 0xd63f_0000 | 0xd65f_0000) {
        let reg = ((insn >> 5) & 0x1f) as u8;
        return Some(if reg == 31 {
            Stop::Other
        } else {
            Stop::Register { reg }
        });
    }
    // Every other unconditional branch (register): the pointer-authenticated
    // ones, ERET and DRPS.
    if insn & 0xfe00_0000 == 0xd600_0000 {
        return Some(Stop::Other);
    }
    // Exception generation: SVC, HVC, SMC, BRK, HLT, DCPS.
    if insn & 0xff00_0000 == 0xd400_0000 {
        return Some(Stop::Other);
    }
    // System instructions: hints, barriers, MSR, MRS, SYS, SYSL.
    if insn & 0xffc0_0000 == 0xd500_0000 {
        return (!system_runs_straight(insn)).then_some(Stop::Other);
    }
    // Anything else in the branch, exception and system group: newer
    // compare-and-branch forms (CB<cc>, CBB, CBH), SYSP, MSRR, MRRS, and its
    // unallocated encodings.
    if (insn >> 26) & 0b111 == 0b101 {
        return Some(Stop::Other);
    }
    // Load and store exclusive (o2 == 0): LDXR, LDAXR, STXR, STLXR and the
    // pairs. A trap between a load exclusive and its store fails the store.
    if insn & 0x3f80_0000 == 0x0800_0000 {
        return Some(Stop::Other);
    }
    // The reserved group (UDF, and SME in later architectures) and the
    // unallocated ones.
    if matches!((insn >> 25) & 0xf, 0b0000 | 0b0001 | 0b0011) {
        return Some(Stop::Other);
    }
    None
}

/// The system instructions a run executes without stopping: hints other than
/// WFE and WFI (NOP, YIELD, the pointer-authentication and BTI hints), the
/// data barriers DMB and DSB, and the thread-pointer read `mrs xN, tpidr_el0`.
/// Any other system instruction (ISB, CLREX, an MSR, any other MRS, SYS) is a
/// stop point, single stepped as before.
fn system_runs_straight(insn: u32) -> bool {
    if insn & 0xffff_f01f == 0xd503_201f {
        return !matches!((insn >> 5) & 0x7f, 2 | 3);
    }
    matches!(insn & 0xffff_f0ff, 0xd503_30bf | 0xd503_309f) || insn & 0xffff_ffe0 == 0xd53b_d040
}

/// The first stop point at or after `pc` in `code`, the guest's code bytes
/// from `pc`, within [`STOP_WINDOW`] instructions; `None` if there is none,
/// or `pc` is not instruction aligned.
pub(crate) fn first_stop(pc: u64, code: &[u8]) -> Option<(u64, Stop)> {
    if !pc.is_multiple_of(4) {
        return None;
    }
    code.as_chunks::<4>()
        .0
        .iter()
        .take(STOP_WINDOW)
        .zip((pc..).step_by(4))
        .find_map(|(word, at)| classify(u32::from_le_bytes(*word), at).map(|stop| (at, stop)))
}

/// The first two breakpoint registers that are not enabled, given whether
/// each register the hardware has is (`enabled`); `None` with fewer than two
/// free. An enabled register belongs to someone else (a debugger of the
/// guest, or breakpoints the guest arms through `perf_event_open`) and is
/// never chosen.
pub(crate) fn free_slots(enabled: impl IntoIterator<Item = bool>) -> Option<[usize; 2]> {
    let mut free = enabled
        .into_iter()
        .enumerate()
        .filter_map(|(slot, on)| (!on).then_some(slot));
    Some([free.next()?, free.next()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(insns: &[u32]) -> Vec<u8> {
        insns.iter().flat_map(|insn| insn.to_le_bytes()).collect()
    }

    const NOP: u32 = 0xd503_201f;
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1

    #[test]
    fn branches_with_their_targets() {
        let pc = 0x1000;
        // b .+8
        assert_eq!(
            classify(0x1400_0002, pc),
            Some(Stop::Direct {
                target: 0x1008,
                conditional: false
            })
        );
        // bl .-4
        assert_eq!(
            classify(0x97ff_ffff, pc),
            Some(Stop::Direct {
                target: 0x0ffc,
                conditional: false
            })
        );
        // b.ne .-8
        assert_eq!(
            classify(0x54ff_ffc1, pc),
            Some(Stop::Direct {
                target: 0x0ff8,
                conditional: true
            })
        );
        // cbz x0, .+12
        assert_eq!(
            classify(0xb400_0060, pc),
            Some(Stop::Direct {
                target: 0x100c,
                conditional: true
            })
        );
        // cbnz w3, .+4
        assert_eq!(
            classify(0x3500_0023, pc),
            Some(Stop::Direct {
                target: 0x1004,
                conditional: true
            })
        );
        // tbz x0, #0, .+16
        assert_eq!(
            classify(0x3600_0080, pc),
            Some(Stop::Direct {
                target: 0x1010,
                conditional: true
            })
        );
        // tbnz x5, #33, .-4
        assert_eq!(
            classify(0xb70f_ffe5, pc),
            Some(Stop::Direct {
                target: 0x0ffc,
                conditional: true
            })
        );
        // br x16, blr x8, ret, ret x2
        assert_eq!(classify(0xd61f_0200, pc), Some(Stop::Register { reg: 16 }));
        assert_eq!(classify(0xd63f_0100, pc), Some(Stop::Register { reg: 8 }));
        assert_eq!(classify(0xd65f_03c0, pc), Some(Stop::Register { reg: 30 }));
        assert_eq!(classify(0xd65f_0040, pc), Some(Stop::Register { reg: 2 }));
    }

    #[test]
    fn other_stops() {
        let pc = 0x1000;
        for insn in [
            0xd65f_0bff, // retaa
            0xd69f_03e0, // eret
            0xd61f_0a1f, // braaz x16
            0xd400_0001, // svc #0
            0xd420_0000, // brk #0
            0x0000_0000, // udf #0
            0xd503_205f, // wfe
            0xd503_207f, // wfi
            0xd503_3fdf, // isb
            0xd503_3f5f, // clrex
            0xd51b_4200, // msr nzcv, x0
            0xd53b_e040, // mrs x0, cntvct_el0
            0xd50b_7520, // ic ivau, x0
            0xc85f_7c20, // ldxr x0, [x1]
            0xc85f_fc20, // ldaxr x0, [x1]
            0xc802_7c20, // stxr w2, x0, [x1]
            0xc822_8020, // stlxp w2, x0, x0, [x1]
            0x885f_7c20, // ldxr w0, [x1]
            0x7400_0000, // the FEAT_CMPBR compare-and-branch space
            0xf400_0000,
            0x7500_0000,
            0xd548_0000, // sysp
            0xd55c_0000, // mrrs/msrr space
            0x5500_0000, // unallocated: B.cond with bit 24 set
        ] {
            assert_eq!(classify(insn, pc), Some(Stop::Other), "{insn:#010x}");
        }
    }

    #[test]
    fn straight_line_instructions() {
        for insn in [
            NOP,
            ADD,
            0xd503_233f, // paciasp
            0xd503_23bf, // autiasp
            0xd503_245f, // bti c
            0xd503_3bbf, // dmb ish
            0xd503_3b9f, // dsb ish
            0xd53b_d040, // mrs x0, tpidr_el0
            0xf940_0020, // ldr x0, [x1]
            0xf900_0020, // str x0, [x1]
            0xc8df_fc20, // ldar x0, [x1]
            0xc89f_fc20, // stlr x0, [x1]
            0xf820_0020, // ldadd x0, x0, [x1]
            0xc8a0_7c20, // cas x0, x0, [x1]
            0xeb01_001f, // cmp x0, x1
            0x9a81_1000, // csel x0, x0, x1, ne
        ] {
            assert_eq!(classify(insn, 0x1000), None, "{insn:#010x}");
        }
    }

    #[test]
    fn the_first_stop_ends_the_run() {
        let code = bytes(&[ADD, NOP, ADD, 0x54ff_ffa1, ADD]);
        assert_eq!(
            first_stop(0x2000, &code),
            Some((
                0x200c,
                Stop::Direct {
                    target: 0x2000,
                    conditional: true
                }
            ))
        );
        // At a stop point, the run starts there.
        assert_eq!(
            first_stop(0x200c, &code[12..]).map(|(at, _)| at),
            Some(0x200c)
        );
        // None within the bytes read, or within the window.
        assert_eq!(first_stop(0x2000, &code[..12]), None);
        assert_eq!(first_stop(0x2000, &bytes(&[ADD; STOP_WINDOW + 1])), None);
        // A partial instruction is not one.
        assert_eq!(first_stop(0x2000, &code[..15]), None);
        assert_eq!(first_stop(0x2002, &code), None);
    }

    #[test]
    fn only_free_slots_are_chosen() {
        assert_eq!(free_slots([false; 6]), Some([0, 1]));
        assert_eq!(
            free_slots([true, false, true, false, false, true]),
            Some([1, 3])
        );
        assert_eq!(free_slots([true, true, true, true, true, false]), None);
        assert_eq!(free_slots([false]), None);
        assert_eq!(free_slots([]), None);
    }

    #[test]
    fn successors() {
        let mut x = [0u64; 31];
        x[30] = 0x4444;
        let b = Stop::Direct {
            target: 0x3000,
            conditional: false,
        };
        assert_eq!(b.successors(0x1000, &x), Some(([0x3000, 0x3000], 1)));
        let bne = Stop::Direct {
            target: 0x0ff0,
            conditional: true,
        };
        assert_eq!(bne.successors(0x1000, &x), Some(([0x1004, 0x0ff0], 2)));
        // A conditional branch to the next instruction has one successor.
        let next = Stop::Direct {
            target: 0x1004,
            conditional: true,
        };
        assert_eq!(next.successors(0x1000, &x), Some(([0x1004, 0x1004], 1)));
        assert_eq!(
            Stop::Register { reg: 30 }.successors(0x1000, &x),
            Some(([0x4444, 0x4444], 1))
        );
        assert_eq!(Stop::Other.successors(0x1000, &x), None);
    }
}
