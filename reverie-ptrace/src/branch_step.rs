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
//!
//! A load-exclusive and the code up to its store-exclusive run as one unit
//! (see [`exclusive_sequence`]): a stop between the two clears the exclusive
//! monitor, so a store reached by single steps fails on every attempt, and a
//! retry loop stepped that way would spin until the timer's target.

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

/// How many instructions from a load-exclusive its store-exclusive may lie,
/// at most, for the two to run as one unit (the window gdb's software single
/// step uses to step over such a sequence, `aarch64_software_single_step`).
pub(crate) const EXCLUSIVE_WINDOW: usize = 16;

/// Whether `insn` is a load exclusive (LDXR, LDAXR and their byte, halfword
/// and pair forms) or, with `load` false, a store exclusive (STXR, STLXR and
/// theirs). The load/store exclusive group with `o2` clear, less CASP, which
/// shares it in ARMv8.1 (`o1` set with a size below 64 bits).
fn is_exclusive(insn: u32, load: bool) -> bool {
    let o1 = insn & (1 << 21) != 0;
    let pair_size = insn >> 30 >= 2;
    insn & 0x3f80_0000 == 0x0800_0000 && (insn & (1 << 22) != 0) == load && (!o1 || pair_size)
}

/// A load-exclusive sequence that runs as one unit: from its load-exclusive
/// to a hardware breakpoint at one of `stops[..count]`, retiring exactly
/// `branches[i]` branches on the way to `stops[i]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExclusiveSequence {
    pub stops: [u64; 2],
    pub branches: [u64; 2],
    pub count: usize,
}

impl ExclusiveSequence {
    /// The most branches the unit retires, at any of its ends.
    pub(crate) fn most(&self) -> u64 {
        self.branches[..self.count]
            .iter()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

/// The sequence from the load-exclusive at `pc` to its store-exclusive, in
/// `code`, the guest's code bytes from `pc`; `None` if `pc` is not a load
/// exclusive or the sequence is not one that runs as a unit.
///
/// The store-exclusive is the first exclusive instruction after the load,
/// within [`EXCLUSIVE_WINDOW`] instructions. Between the two there may be
/// only instructions that fall through without a branch, trap or exclusive
/// access ([`classify`] gives `None`), and conditional branches with encoded
/// targets outside the sequence, as the comparison of a compare-and-swap
/// leaves it. So the unit executes no exception-generating instruction (SVC,
/// BRK, HVC, SMC), no system instruction other than those `classify` lets a
/// branch run execute, and no second exclusive access.
///
/// The unit ends at a breakpoint just after the store, having retired
/// every one of those branches, none taken, or at a breakpoint at the target
/// of the one it took, having retired the branches up to and including it:
/// each end is reached along one straight-line path, so with one exact count.
/// The ends lie outside `[pc, store]`, so no breakpoint stops the unit
/// between its load and its store; a branch back to the load-exclusive
/// itself is the retry edge, which belongs after the store, not inside. A
/// sequence is not a unit if two of its paths reach one address with
/// different counts, or it has more than two ends, the two breakpoint
/// registers a branch run uses.
pub(crate) fn exclusive_sequence(pc: u64, code: &[u8]) -> Option<ExclusiveSequence> {
    if !pc.is_multiple_of(4) {
        return None;
    }
    let words = code.as_chunks::<4>().0;
    let insn = |index: usize| words.get(index).map(|word| u32::from_le_bytes(*word));
    if !is_exclusive(insn(0)?, true) {
        return None;
    }
    // (target, branches retired on reaching it) of each conditional branch.
    let mut exits: Vec<(u64, u64)> = Vec::new();
    for index in 1..EXCLUSIVE_WINDOW {
        let at = pc + 4 * index as u64;
        let word = insn(index)?;
        if is_exclusive(word, false) {
            let end = at + 4;
            let mut ends = vec![(end, exits.len() as u64)];
            for &(target, branches) in &exits {
                if (pc..end).contains(&target) {
                    return None;
                }
                ends.push((target, branches));
            }
            ends.sort_unstable();
            ends.dedup();
            if ends.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return None;
            }
            return match ends[..] {
                [(stop, branches)] => Some(ExclusiveSequence {
                    stops: [stop, stop],
                    branches: [branches, branches],
                    count: 1,
                }),
                [(first, first_branches), (second, second_branches)] => Some(ExclusiveSequence {
                    stops: [first, second],
                    branches: [first_branches, second_branches],
                    count: 2,
                }),
                _ => None,
            };
        }
        match classify(word, at) {
            None => {}
            Some(Stop::Direct {
                target,
                conditional: true,
            }) => exits.push((target, exits.len() as u64 + 1)),
            Some(_) => return None,
        }
    }
    None
}

/// Whether the guest's code at `pc` holds a load-exclusive sequence that
/// runs as one unit ([`exclusive_sequence`]). `read` fills a buffer with the
/// code from an address and returns how many bytes it read. The first
/// instruction is read alone, and the rest of the window only if that is a
/// load-exclusive, which almost no stepped instruction is.
pub(crate) fn probe_exclusive_sequence(
    pc: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> usize,
) -> bool {
    if !pc.is_multiple_of(4) {
        return false;
    }
    let mut code = [0u8; 4 * EXCLUSIVE_WINDOW];
    let (first, rest) = code.split_first_chunk_mut::<4>().expect("a window");
    if read(pc, first) < 4 || !is_exclusive(u32::from_le_bytes(*first), true) {
        return false;
    }
    let len = 4 + read(pc.wrapping_add(4), rest);
    exclusive_sequence(pc, &code[..len]).is_some()
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

/// Registers that can be given back to the thread they were borrowed from,
/// at a ptrace stop of that thread.
pub(crate) trait GiveBack {
    /// A stop of the thread, where its registers can be written.
    type Stop;

    /// Writes the registers back as they were found, at `stop`.
    fn give_back(self, stop: &Self::Stop);
}

/// Registers that branch runs borrow from a thread for one approach to a
/// precise target (its hardware breakpoints on aarch64), and the stop where
/// they can be given back.
///
/// The approach gives them back itself on its ordinary returns, taking them
/// out of [`Borrowed::regs`]. Every other return, an error's `?` included,
/// drops the guard, which gives back whatever is still borrowed at the stop
/// the approach last knew the thread to be in: the one it started at, or the
/// last one a wait returned ([`Borrowed::stopped`]). Between a resuming
/// request and the wait that follows it ([`Borrowed::resumed`]) the thread
/// may be running, and nothing can be written: a return there (a failed
/// wait, or the approach's future dropped while it waits) leaves the
/// registers as they are, since the thread is at no stop this approach can
/// write at.
pub(crate) struct Borrowed<R: GiveBack> {
    regs: Option<R>,
    stop: Option<R::Stop>,
}

impl<R: GiveBack> Borrowed<R> {
    /// Nothing borrowed yet, from a thread at `stop`.
    pub(crate) fn new(stop: R::Stop) -> Self {
        Self {
            regs: None,
            stop: Some(stop),
        }
    }

    /// The borrowed registers: `None` until borrowed, and once given back.
    pub(crate) fn regs(&mut self) -> &mut Option<R> {
        &mut self.regs
    }

    /// A resuming request took effect: until a wait returns the thread's
    /// next stop, a return gives nothing back.
    pub(crate) fn resumed(&mut self) {
        self.stop = None;
    }

    /// A wait returned the thread at `stop`.
    pub(crate) fn stopped(&mut self, stop: R::Stop) {
        self.stop = Some(stop);
    }

    /// The thread no longer holds the registers (it execed, or exited), so
    /// they are dropped without a write.
    pub(crate) fn forget(&mut self) {
        self.regs = None;
    }
}

impl<R: GiveBack> Drop for Borrowed<R> {
    fn drop(&mut self) {
        if let (Some(regs), Some(stop)) = (self.regs.take(), self.stop.as_ref()) {
            regs.give_back(stop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(insns: &[u32]) -> Vec<u8> {
        insns.iter().flat_map(|insn| insn.to_le_bytes()).collect()
    }

    const NOP: u32 = 0xd503_201f;
    const ADD: u32 = 0x9100_0400; // add x0, x0, #1

    // Encodings checked against GNU as 2.35 (aarch64).
    const LDXR_W: u32 = 0x885f_7c20; // ldxr w0, [x1]
    const LDAXR_W: u32 = 0x885f_fc40; // ldaxr w0, [x2]
    const LDXP_X: u32 = 0xc87f_0440; // ldxp x0, x1, [x2]
    const LDXRB: u32 = 0x085f_7c20; // ldxrb w0, [x1]
    const LDAXRH: u32 = 0x485f_fc20; // ldaxrh w0, [x1]
    const STXR_W: u32 = 0x8811_7c41; // stxr w17, w1, [x2]
    const STLXR_W: u32 = 0x880f_fc31; // stlxr w15, w17, [x1]
    const STXP_X: u32 = 0xc823_0440; // stxp w3, x0, x1, [x2]
    const STLXRB: u32 = 0x0802_fc20; // stlxrb w2, w0, [x1]
    const STXRB: u32 = 0x0802_7c20; // stxrb w2, w0, [x1]
    const LDXRH: u32 = 0x485f_7c20; // ldxrh w0, [x1]
    const STXRH: u32 = 0x4802_7c20; // stxrh w2, w0, [x1]
    const STLXRH: u32 = 0x4802_fc20; // stlxrh w2, w0, [x1]
    const LDAXP_X: u32 = 0xc87f_8440; // ldaxp x0, x1, [x2]
    const STLXP_X: u32 = 0xc823_8440; // stlxp w3, x0, x1, [x2]
    const BRK: u32 = 0xd420_0000; // brk #0
    const HVC: u32 = 0xd400_0002; // hvc #0
    const LDAR: u32 = 0x88df_fc20; // ldar w0, [x1]
    const STLR: u32 = 0x889f_fc20; // stlr w0, [x1]
    const CASP: u32 = 0x0820_7c82; // casp w0, w1, w2, w3, [x4]
    const CASPAL: u32 = 0x4860_fc82; // caspal x0, x1, x2, x3, [x4]
    const CAS: u32 = 0x88a0_7c41; // cas w0, w1, [x2]
    const ADD_W: u32 = 0x0b10_0011; // add w17, w0, w16
    const CMP_W: u32 = 0x6b10_001f; // cmp w0, w16
    const SVC: u32 = 0xd400_0001; // svc #0
    const DMB: u32 = 0xd503_3bbf; // dmb ish
    const CLREX: u32 = 0xd503_3f5f; // clrex

    /// `b.ne .+offset`.
    fn b_ne(offset: i32) -> u32 {
        0x5400_0001 | ((((offset / 4) as u32) & 0x7_ffff) << 5)
    }

    /// `cbnz w17, .+offset`.
    fn cbnz_w17(offset: i32) -> u32 {
        0x3500_0011 | ((((offset / 4) as u32) & 0x7_ffff) << 5)
    }

    #[test]
    fn the_exclusive_instructions_are_told_from_their_neighbours() {
        for load in [LDXR_W, LDAXR_W, LDXP_X, LDAXP_X, LDXRB, LDXRH, LDAXRH] {
            assert!(is_exclusive(load, true), "{load:#x}");
            assert!(!is_exclusive(load, false), "{load:#x}");
        }
        for store in [
            STXR_W, STLXR_W, STXP_X, STLXP_X, STXRB, STLXRB, STXRH, STLXRH,
        ] {
            assert!(is_exclusive(store, false), "{store:#x}");
            assert!(!is_exclusive(store, true), "{store:#x}");
        }
        for other in [LDAR, STLR, CASP, CASPAL, CAS, ADD_W, NOP, DMB, CLREX] {
            assert!(!is_exclusive(other, true), "{other:#x}");
            assert!(!is_exclusive(other, false), "{other:#x}");
        }
        assert_eq!(b_ne(12), 0x5400_0061);
        assert_eq!(cbnz_w17(-16), 0x35ff_ff91);
    }

    /// The probe of a stepped pc reads one instruction when that is not a
    /// load-exclusive, and the rest of the window only after one that is.
    #[test]
    fn the_exclusive_probe_reads_one_word_unless_it_is_a_load_exclusive() {
        let pc = 0x1000;
        let probe = |code: &[u8]| {
            let mut bytes_read = 0;
            let found = probe_exclusive_sequence(pc, |addr, buf: &mut [u8]| {
                let from = usize::try_from(addr - pc).unwrap().min(code.len());
                let len = buf.len().min(code.len() - from);
                buf[..len].copy_from_slice(&code[from..from + len]);
                bytes_read += len;
                len
            });
            (found, bytes_read)
        };
        let window = vec![NOP; EXCLUSIVE_WINDOW];
        assert_eq!(probe(&bytes(&window)), (false, 4));
        let mut ldadd = vec![LDXR_W, ADD_W, STXR_W, cbnz_w17(-12)];
        ldadd.resize(EXCLUSIVE_WINDOW, NOP);
        assert_eq!(probe(&bytes(&ldadd)), (true, 4 * EXCLUSIVE_WINDOW));
        // A load-exclusive whose sequence does not run as a unit.
        let mut svc = vec![LDXR_W, SVC, STXR_W];
        svc.resize(EXCLUSIVE_WINDOW, NOP);
        assert_eq!(probe(&bytes(&svc)), (false, 4 * EXCLUSIVE_WINDOW));
        // Unreadable or misaligned code.
        assert_eq!(probe(&[]), (false, 0));
        assert!(!probe_exclusive_sequence(pc + 2, |_, buf: &mut [u8]| buf.len()));
    }

    #[test]
    fn an_exclusive_sequence_runs_to_its_store_and_its_exits() {
        let pc = 0x1000;
        let unit = |stops: [u64; 2], branches: [u64; 2], count| {
            Some(ExclusiveSequence {
                stops,
                branches,
                count,
            })
        };
        // libgcc's __aarch64_ldadd4_relax fallback: no branch inside.
        assert_eq!(
            exclusive_sequence(pc, &bytes(&[LDXR_W, ADD_W, STXR_W, cbnz_w17(-12)])),
            unit([0x100c, 0x100c], [0, 0], 1)
        );
        // Its __aarch64_cas4_acq: the comparison leaves to the return, one
        // branch either way.
        let cas = exclusive_sequence(
            pc,
            &bytes(&[LDAXR_W, CMP_W, b_ne(12), STXR_W, cbnz_w17(-16), 0xd65f_03c0]),
        );
        assert_eq!(cas, unit([0x1010, 0x1014], [1, 1], 2));
        assert_eq!(cas.unwrap().most(), 1);
        // Two comparisons that leave to two places make three ends.
        let two = exclusive_sequence(
            pc,
            &bytes(&[LDAXR_W, CMP_W, b_ne(0x40), CMP_W, b_ne(-0x80), STLXR_W]),
        );
        assert_eq!(two, None, "three ends");
        let one_exit_each_side =
            exclusive_sequence(pc, &bytes(&[LDAXR_W, CMP_W, b_ne(-0x100), STLXR_W]));
        assert_eq!(one_exit_each_side, unit([0x0f08, 0x1010], [1, 1], 2));
        // Every exclusive width and form, acquire and release included.
        for (load, store) in [
            (LDXR_W, STXR_W),
            (LDAXR_W, STLXR_W),
            (LDXP_X, STXP_X),
            (LDAXP_X, STLXP_X),
            (LDXRB, STXRB),
            (LDXRB, STLXRB),
            (LDXRH, STXRH),
            (LDAXRH, STLXRH),
        ] {
            assert_eq!(
                exclusive_sequence(pc, &bytes(&[load, NOP, store])),
                unit([0x100c, 0x100c], [0, 0], 1),
                "{load:#x} .. {store:#x}"
            );
        }
        // A branch from the last comparison to just after the store retires
        // as many branches as the path through the store: one end.
        assert_eq!(
            exclusive_sequence(pc, &bytes(&[LDAXR_W, CMP_W, b_ne(8), STXR_W])),
            unit([0x1010, 0x1010], [1, 1], 1)
        );
    }

    #[test]
    fn other_sequences_are_not_units() {
        let pc = 0x1000;
        let refused = |insns: &[u32]| exclusive_sequence(pc, &bytes(insns));
        // Not at a load-exclusive.
        assert_eq!(refused(&[ADD_W, LDXR_W, STXR_W]), None);
        assert_eq!(refused(&[STXR_W]), None);
        assert_eq!(refused(&[LDAR, STLR]), None);
        assert_eq!(refused(&[CASP, STXR_W]), None);
        assert_eq!(refused(&[CAS, STXR_W]), None);
        // Misaligned.
        assert_eq!(exclusive_sequence(pc + 2, &bytes(&[LDXR_W, STXR_W])), None);
        // No store within the window, or the code runs out first.
        let mut long = vec![LDXR_W];
        long.extend([NOP; EXCLUSIVE_WINDOW - 1]);
        long.push(STXR_W);
        assert_eq!(refused(&long), None);
        assert_eq!(refused(&[LDXR_W, ADD_W]), None);
        // Anything that would raise SIGTRAP or stop the unit before its
        // store: an exception-generating instruction, a system instruction a
        // branch run does not run, a second exclusive load.
        for inside in [SVC, BRK, HVC, CLREX, LDXR_W, LDAXP_X] {
            assert_eq!(refused(&[LDXR_W, inside, STXR_W]), None, "{inside:#x}");
        }
        // An unconditional or a register branch before the store.
        assert_eq!(refused(&[LDXR_W, 0x1400_0002, STXR_W]), None);
        assert_eq!(refused(&[LDXR_W, 0xd65f_03c0, STXR_W]), None);
        // A branch that stays inside the sequence, or goes back to the
        // load-exclusive itself.
        assert_eq!(refused(&[LDXR_W, b_ne(8), NOP, STXR_W]), None);
        assert_eq!(refused(&[LDXR_W, NOP, b_ne(-4), STXR_W]), None);
        assert_eq!(refused(&[LDXR_W, b_ne(-4), STXR_W]), None);
        // Two paths to one address with different counts.
        assert_eq!(
            refused(&[LDAXR_W, CMP_W, b_ne(16), CMP_W, b_ne(8), STLXR_W]),
            None
        );
        // Three ends.
        assert_eq!(refused(&[LDXR_W, b_ne(0x40), b_ne(0x80), STXR_W]), None);
    }

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

    /// A guest `rt_sigreturn` (`mov x8, #139; svc #0`) ends a run before
    /// its `svc`, so no run executes one. Shields that decide from the
    /// instruction at pc whether a unit can change the guest's signal mask
    /// rely on this for branch runs.
    #[test]
    fn an_rt_sigreturn_ends_a_run_before_it() {
        let code = bytes(&[ADD, 0xd280_1168, 0xd400_0001, ADD]);
        assert_eq!(first_stop(0x3000, &code), Some((0x3008, Stop::Other)));
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

    /// Registers that log the stop where they are given back.
    struct Logged(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

    impl GiveBack for Logged {
        type Stop = &'static str;

        fn give_back(self, stop: &&'static str) {
            self.0.borrow_mut().push(stop);
        }
    }

    /// Where `approach` returns early, in the order an approach to a precise
    /// target reaches each point.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Exit {
        /// Before a resuming request took effect: the step's request, or a
        /// register write, failed.
        AtStart,
        /// In the wait that follows a resuming request.
        InWait,
        /// At the stop that wait returned: observing it failed.
        AtNextStop,
        /// At an exec's stop, after which the thread holds no breakpoints.
        AfterExec,
        /// After the approach gave the registers back itself.
        AfterGivingBack,
    }

    /// An approach that borrows registers at stop "start", resumes the thread
    /// once, sees it stop at "next", gives the registers back itself at
    /// "returned", and returns early with `?` at `exit`. Returns the stops
    /// where the registers were given back.
    fn approach(exit: Exit) -> Vec<&'static str> {
        let log = std::rc::Rc::default();
        let run = |log: &std::rc::Rc<_>| -> Result<(), Exit> {
            let check = |at: Exit| if at == exit { Err(at) } else { Ok(()) };
            let mut held = Borrowed::new("start");
            *held.regs() = Some(Logged(std::rc::Rc::clone(log)));
            check(Exit::AtStart)?;
            held.resumed();
            check(Exit::InWait)?;
            if exit == Exit::AfterExec {
                held.forget();
            }
            held.stopped("next");
            check(Exit::AtNextStop)?;
            check(Exit::AfterExec)?;
            if let Some(regs) = held.regs().take() {
                regs.give_back(&"returned");
            }
            check(Exit::AfterGivingBack)?;
            Ok(())
        };
        assert_eq!(run(&log), Err(exit));
        log.take()
    }

    /// An error before the resume, such as a failed step request, gives the
    /// registers back at the stop the approach started at.
    #[test]
    fn an_error_before_the_resume_gives_the_registers_back() {
        assert_eq!(approach(Exit::AtStart), ["start"]);
    }

    /// An error at a stop a wait returned, such as a failed observation of
    /// it, gives the registers back at that stop.
    #[test]
    fn an_error_at_a_later_stop_gives_them_back_there() {
        assert_eq!(approach(Exit::AtNextStop), ["next"]);
    }

    /// A failed wait leaves a thread that may be running: nothing is written.
    #[test]
    fn an_error_in_the_wait_writes_nothing() {
        assert_eq!(approach(Exit::InWait), Vec::<&str>::new());
    }

    /// Registers the thread no longer holds, or that the approach gave back
    /// itself, are not written again.
    #[test]
    fn forgotten_or_returned_registers_are_not_written_again() {
        assert_eq!(approach(Exit::AfterExec), Vec::<&str>::new());
        assert_eq!(approach(Exit::AfterGivingBack), ["returned"]);
    }
}
