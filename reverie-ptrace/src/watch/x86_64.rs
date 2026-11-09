/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! x86-64 data breakpoints through the debug registers Linux exposes to a
//! tracer in `struct user`'s `u_debugreg` (`PTRACE_PEEKUSER` and
//! `PTRACE_POKEUSER`, arch/x86/kernel/ptrace.c, `ptrace_get_debugreg` and
//! `ptrace_set_debugreg`).
//!
//! - DR0-DR3 hold the four watched addresses.
//! - DR7 enables each slot with its local-enable bit `L<n>` (bit `2n`), and
//!   gives its access type in `RW<n>` (bits `16 + 4n`, two wide: 01 writes,
//!   11 reads and writes) and its length in `LEN<n>` (bits `18 + 4n`: 00 one
//!   byte, 01 two, 11 four, 10 eight). The address must be aligned to the
//!   length.
//! - DR6, as Linux shows it to a tracer, is the thread's virtual status: the
//!   `B<n>` bits (bits 0-3) of the slots that fired at the latest debug trap,
//!   and `BS` (bit 14) if that trap was a single step. Linux resets it at
//!   each debug trap (`exc_debug_user`), but a SIGTRAP from anything else
//!   (an `int3`, a signal sent with `kill`) leaves it as it was, so a hit's
//!   bits are cleared once read.
//!
//! A data breakpoint is a trap: the CPU reports it after the accessing
//! instruction retires, with rip at the next instruction, so nothing runs
//! again ([`HitTiming::AfterAccess`]).

use reverie::HitTiming;
use reverie::WatchError;
use reverie::WatchKind;
use reverie::WatchSpec;
use safeptrace::Error as TraceError;
use safeptrace::Stopped;

use super::HwWatch;

/// The byte offset of debug register `n` in `struct user`.
fn debugreg(n: usize) -> usize {
    core::mem::offset_of!(libc::user, u_debugreg) + n * core::mem::size_of::<u64>()
}

/// DR6's hit bits, `B0`-`B3`.
const DR6_HITS: u64 = 0xf;

/// The DR7 bits of `slot`: its enable bits (local and global) and its type
/// and length fields.
fn dr7_slot_mask(slot: u8) -> u64 {
    let slot = u64::from(slot);
    (0b11 << (2 * slot)) | (0b1111 << (16 + 4 * slot))
}

/// The DR7 bits that arm `slot` with `spec`: its local-enable bit, type and
/// length.
fn dr7_slot_bits(slot: u8, spec: &WatchSpec) -> u64 {
    let slot = u64::from(slot);
    let rw: u64 = match spec.kind {
        WatchKind::Write => 0b01,
        WatchKind::ReadWrite => 0b11,
    };
    let len: u64 = match spec.len {
        1 => 0b00,
        2 => 0b01,
        4 => 0b11,
        8 => 0b10,
        _ => unreachable!("checked by HwWatch::check"),
    };
    (1 << (2 * slot)) | (rw << (16 + 4 * slot)) | (len << (18 + 4 * slot))
}

/// The length and kind DR7 gives `slot`, if the slot is enabled. Reverie
/// writes only the write and read/write types; an execute or I/O type
/// reads as read/write.
fn dr7_slot_decode(dr7: u64, slot: u8) -> Option<(u8, WatchKind)> {
    let slot = u64::from(slot);
    if dr7 & (0b11 << (2 * slot)) == 0 {
        return None;
    }
    let kind = match (dr7 >> (16 + 4 * slot)) & 0b11 {
        0b01 => WatchKind::Write,
        _ => WatchKind::ReadWrite,
    };
    let len = match (dr7 >> (18 + 4 * slot)) & 0b11 {
        0b00 => 1,
        0b01 => 2,
        0b11 => 4,
        _ => 8,
    };
    Some((len, kind))
}

/// The x86-64 debug registers.
pub(crate) struct DebugRegisters;

impl HwWatch for DebugRegisters {
    const HIT_TIMING: HitTiming = HitTiming::AfterAccess;

    fn slots(_task: &Stopped) -> Result<u8, TraceError> {
        Ok(4)
    }

    fn check(spec: &WatchSpec) -> Result<(), WatchError> {
        if !matches!(spec.len, 1 | 2 | 4 | 8) {
            return Err(WatchError::Length { len: spec.len });
        }
        if !spec.addr.is_multiple_of(u64::from(spec.len)) {
            return Err(WatchError::Misaligned {
                addr: spec.addr,
                len: spec.len,
            });
        }
        Ok(())
    }

    fn arm(task: &Stopped, slot: u8, spec: &WatchSpec) -> Result<(), TraceError> {
        // Disabled first: Linux checks a new address against the slot's
        // current length and type when the slot is enabled.
        Self::disarm(task, slot)?;
        task.pokeuser(debugreg(usize::from(slot)), spec.addr)?;
        let dr7 = task.peekuser(debugreg(7))?;
        task.pokeuser(debugreg(7), dr7 | dr7_slot_bits(slot, spec))
    }

    fn disarm(task: &Stopped, slot: u8) -> Result<(), TraceError> {
        let dr7 = task.peekuser(debugreg(7))?;
        let disarmed = dr7 & !dr7_slot_mask(slot);
        if disarmed == dr7 {
            return Ok(());
        }
        task.pokeuser(debugreg(7), disarmed)
    }

    fn take_hits(task: &Stopped) -> Result<u8, TraceError> {
        let dr6 = task.peekuser(debugreg(6))?;
        let hits = dr6 & DR6_HITS;
        if hits != 0 {
            // Linux keeps the other bits, read back in the hardware's
            // polarity, as they were (`ptrace_set_debugreg`).
            task.pokeuser(debugreg(6), dr6 & !DR6_HITS)?;
        }
        Ok(hits as u8)
    }

    fn read(task: &Stopped, slot: u8) -> Result<Option<WatchSpec>, TraceError> {
        let Some((len, kind)) = dr7_slot_decode(task.peekuser(debugreg(7))?, slot) else {
            return Ok(None);
        };
        Ok(Some(WatchSpec {
            addr: task.peekuser(debugreg(usize::from(slot)))?,
            len,
            kind,
            backtraces: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(addr: u64, len: u8, kind: WatchKind) -> WatchSpec {
        WatchSpec {
            addr,
            len,
            kind,
            backtraces: 0,
        }
    }

    #[test]
    fn debug_registers_sit_where_linux_reads_them() {
        // `struct user` on x86-64: 27 general registers, the FPU area and
        // eight more fields before `u_debugreg` (asm/user_64.h).
        assert_eq!(debugreg(0), 848);
        assert_eq!(debugreg(6), 848 + 48);
        assert_eq!(debugreg(7), 848 + 56);
    }

    #[test]
    fn dr7_encodes_each_slot_as_the_sdm_does() {
        // Slot 0, 8-byte write watch: L0, RW0 = 01, LEN0 = 10.
        assert_eq!(
            dr7_slot_bits(0, &spec(0x1000, 8, WatchKind::Write)),
            0x0009_0001
        );
        // Slot 3, 4-byte read/write watch: L3, RW3 = 11, LEN3 = 11.
        assert_eq!(
            dr7_slot_bits(3, &spec(0x1000, 4, WatchKind::ReadWrite)),
            0xf000_0040
        );
        // Slot 1, 1-byte and 2-byte lengths.
        assert_eq!(
            dr7_slot_bits(1, &spec(0x1000, 1, WatchKind::Write)),
            0x0010_0004
        );
        assert_eq!(
            dr7_slot_bits(1, &spec(0x1000, 2, WatchKind::Write)),
            0x0050_0004
        );
        for slot in 0..4 {
            for len in [1, 2, 4, 8] {
                for kind in [WatchKind::Write, WatchKind::ReadWrite] {
                    let others = !dr7_slot_mask(slot) & 0xffff_ffff;
                    let dr7 = others | dr7_slot_bits(slot, &spec(0x1000, len, kind));
                    assert_eq!(dr7_slot_decode(dr7, slot), Some((len, kind)));
                    assert_eq!(dr7_slot_decode(others, slot), None);
                }
            }
            let bits = dr7_slot_bits(slot, &spec(0x1000, 8, WatchKind::ReadWrite));
            assert_eq!(bits & !dr7_slot_mask(slot), 0, "slot {slot}");
            for other in (0..4).filter(|&other| other != slot) {
                assert_eq!(bits & dr7_slot_mask(other), 0, "{slot} and {other}");
            }
        }
    }

    #[test]
    fn lengths_and_alignment_the_hardware_cannot_watch_are_refused() {
        for len in [1, 2, 4, 8] {
            assert_eq!(
                DebugRegisters::check(&spec(0x1000, len, WatchKind::Write)),
                Ok(())
            );
        }
        for len in [0, 3, 5, 16] {
            assert_eq!(
                DebugRegisters::check(&spec(0x1000, len, WatchKind::Write)),
                Err(WatchError::Length { len })
            );
        }
        assert_eq!(
            DebugRegisters::check(&spec(0x1004, 8, WatchKind::Write)),
            Err(WatchError::Misaligned {
                addr: 0x1004,
                len: 8
            })
        );
        assert_eq!(
            DebugRegisters::check(&spec(0x1001, 2, WatchKind::ReadWrite)),
            Err(WatchError::Misaligned {
                addr: 0x1001,
                len: 2
            })
        );
    }
}
