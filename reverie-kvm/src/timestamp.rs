/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Instruction decoding for the existing Tool timestamp callback. There is no
//! clock here: the callback supplies the entire TSC and optional TSC_AUX value.

use kvm_bindings::kvm_regs;
use reverie::Rdtsc;
use reverie::RdtscResult;

use crate::GuestMemory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimestampInstruction {
    pub(crate) request: Rdtsc,
    pub(crate) length: u8,
}

/// Fetch only bytes belonging to the instruction, including its legal ignored
/// legacy/REX prefixes. LOCK is invalid for both instructions; a sixteenth byte
/// is never fetched. The caller supplies executable guest instruction bytes,
/// not an unchecked read of the supervisor's RAM mapping.
pub(crate) fn decode(mut fetch: impl FnMut(u8) -> Option<u8>) -> Option<TimestampInstruction> {
    let mut length = 0;
    let mut next = || {
        if length == 15 {
            return None;
        }
        let byte = fetch(length)?;
        length += 1;
        Some(byte)
    };
    let opcode = loop {
        match next()? {
            // Operand/address size, repeat, segment override and REX do not
            // change these operandless instructions. In particular a prefix
            // following REX cannot create a different register operand.
            0x66 | 0x67 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x40..=0x4f => {
                continue;
            }
            0x0f => break next()?,
            _ => return None,
        }
    };
    let request = match opcode {
        0x31 => Rdtsc::Tsc,
        0x01 if next()? == 0xf9 => Rdtsc::Tscp,
        _ => return None,
    };
    Some(TimestampInstruction { request, length })
}

pub(crate) fn result_registers(
    mut original: kvm_regs,
    instruction: TimestampInstruction,
    result: RdtscResult,
) -> Option<kvm_regs> {
    original.rip = original.rip.checked_add(u64::from(instruction.length))?;
    // A fault sets RF in its saved frame. Successful retirement clears RF;
    // carrying that fault artifact to the next instruction suppresses its
    // instruction breakpoint. All other flags retain the saved user value.
    original.rflags &= !(1 << 16);
    original.rax = u64::from(result.tsc as u32);
    original.rdx = result.tsc >> 32;
    if instruction.request == Rdtsc::Tscp {
        original.rcx = u64::from(result.aux.unwrap_or(0));
    }
    Some(original)
}

/// Resolve one executable CPL3 byte through the active four-level guest page
/// tables. KVM_TRANSLATE reports data translation, not instruction-fetch NX
/// permission. Check U/S and NX at every level instead; never infer executable
/// access from the supervisor's physically mapped RAM. The caller has already
/// checked long mode, paging, NXE and absence of LA57.
pub(crate) fn fetch_user_byte(memory: &GuestMemory, cr3: u64, address: u64) -> Option<u8> {
    const PHYSICAL: u64 = 0x000f_ffff_ffff_f000;
    const NX: u64 = 1 << 63;
    // This backend's guest arena occupies the lower canonical half. Reject a
    // noncanonical IP instead of wrapping it into an in-arena physical offset.
    if address >= (1 << 47) {
        return None;
    }
    let mut table = cr3 & PHYSICAL;
    for shift in [39, 30, 21, 12] {
        let slot = table.checked_add(((address >> shift) & 0x1ff) * 8)?;
        let mut bytes = [0; 8];
        memory.read_raw(slot, &mut bytes).ok()?;
        let entry = u64::from_le_bytes(bytes);
        if entry & 0x5 != 0x5 || entry & NX != 0 {
            return None;
        }
        let large = shift != 12 && entry & 0x80 != 0;
        if large && shift == 39 {
            return None;
        }
        if shift == 12 || large {
            let offset_mask = (1_u64 << shift) - 1;
            // Large-page bit 12 is PAT; other low address bits are reserved.
            if large && entry & PHYSICAL & offset_mask & !(1 << 12) != 0 {
                return None;
            }
            let physical = (entry & PHYSICAL & !offset_mask) | (address & offset_mask);
            let mut byte = [0];
            memory.read_raw(physical, &mut byte).ok()?;
            return Some(byte[0]);
        }
        table = entry & PHYSICAL;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction(bytes: &[u8]) -> Option<TimestampInstruction> {
        decode(|index| bytes.get(usize::from(index)).copied())
    }

    #[test]
    fn two_byte_rdtsc_decode_does_not_read_a_third_byte() {
        let mut fetched = Vec::new();
        assert_eq!(
            decode(|index| {
                fetched.push(index);
                Some([0x0f, 0x31][usize::from(index)])
            }),
            Some(TimestampInstruction {
                request: Rdtsc::Tsc,
                length: 2
            }),
        );
        assert_eq!(fetched, [0, 1]);
        assert_eq!(
            instruction(&[0x0f, 0x01, 0xf9]).unwrap().request,
            Rdtsc::Tscp
        );
        assert_eq!(instruction(&[0x0f, 0x01]), None);
    }

    #[test]
    fn timestamp_prefixes_and_fifteen_byte_limit_preserve_faults() {
        for prefix in [
            0x66, 0x67, 0xf2, 0xf3, 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x40, 0x4f,
        ] {
            assert_eq!(instruction(&[prefix, 0x0f, 0x31]).unwrap().length, 3);
            assert_eq!(instruction(&[prefix, 0x0f, 0x01, 0xf9]).unwrap().length, 4);
        }
        let mut longest = vec![0x66; 13];
        longest.extend_from_slice(&[0x0f, 0x31]);
        assert_eq!(instruction(&longest).unwrap().length, 15);
        longest.insert(0, 0x66);
        assert_eq!(instruction(&longest), None);
        for invalid in [
            &[0xf0, 0x0f, 0x31][..],
            &[0xf3, 0xf0, 0x0f, 0x01, 0xf9],
            &[0x0f, 0x0b],
            &[0xed],
        ] {
            assert_eq!(instruction(invalid), None);
        }
        let mut fetched = Vec::new();
        assert_eq!(
            decode(|index| {
                fetched.push(index);
                Some(0x66)
            }),
            None
        );
        assert_eq!(fetched, (0..15).collect::<Vec<_>>());
    }

    #[test]
    fn timestamp_writeback_preserves_other_registers_and_full_flags() {
        let original = kvm_regs {
            rax: u64::MAX,
            rbx: 2,
            rcx: u64::MAX,
            rdx: u64::MAX,
            rsi: 5,
            rdi: 6,
            rsp: 7,
            rbp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            r12: 13,
            r13: 14,
            r14: 15,
            r15: 16,
            rip: 0x1234,
            rflags: 0x1_03d7,
        };
        for request in [Rdtsc::Tsc, Rdtsc::Tscp] {
            let actual = result_registers(
                original,
                TimestampInstruction { request, length: 5 },
                RdtscResult {
                    tsc: 0xfedc_ba98_7654_3210,
                    aux: Some(0x8765_4321),
                },
            )
            .unwrap();
            let mut expected = original;
            expected.rip += 5;
            expected.rflags &= !(1 << 16);
            expected.rax = 0x7654_3210;
            expected.rdx = 0xfedc_ba98;
            if request == Rdtsc::Tscp {
                expected.rcx = 0x8765_4321;
            }
            assert_eq!(actual, expected);
        }
        assert!(
            result_registers(
                kvm_regs {
                    rip: u64::MAX,
                    ..original
                },
                TimestampInstruction {
                    request: Rdtsc::Tsc,
                    length: 2
                },
                RdtscResult { tsc: 0, aux: None }
            )
            .is_none()
        );
    }

    #[test]
    fn timestamp_fetch_checks_each_page_and_does_not_cross_a_completed_instruction() {
        let memory = GuestMemory::new(0, 0x10_000).unwrap();
        for (address, value) in [
            (0x1000, 0x2007_u64),
            (0x2000, 0x3007),
            (0x3000, 0x4007),
            (0x4000 + 8 * 8, 0x8007),
            (0x4000 + 9 * 8, 0x9007),
        ] {
            memory.write_raw(address, &value.to_le_bytes()).unwrap();
        }
        memory.write_raw(0x8ffe, &[0x0f, 0x31]).unwrap();
        let read = |memory: &GuestMemory, rip: u64| {
            decode(|offset| fetch_user_byte(memory, 0x1000, rip + u64::from(offset)))
        };
        assert_eq!(read(&memory, 0x8ffe).unwrap().length, 2);
        memory
            .write_raw(0x4000 + 9 * 8, &(0x9007_u64 | (1 << 63)).to_le_bytes())
            .unwrap();
        assert_eq!(read(&memory, 0x8ffe).unwrap().length, 2);
        memory.write_raw(0x8ffe, &[0x0f, 0x01, 0xf9]).unwrap();
        assert_eq!(read(&memory, 0x8ffe), None);
        memory
            .write_raw(0x4000 + 9 * 8, &0x9007_u64.to_le_bytes())
            .unwrap();
        assert_eq!(read(&memory, 0x8ffe).unwrap().request, Rdtsc::Tscp);
        for invalid in [0_u64, 0x9003, 0x9007 | (1 << 63)] {
            memory
                .write_raw(0x4000 + 9 * 8, &invalid.to_le_bytes())
                .unwrap();
            assert_eq!(read(&memory, 0x8ffe), None);
        }
        memory
            .write_raw(0x4000 + 9 * 8, &0x9007_u64.to_le_bytes())
            .unwrap();
        memory
            .write_raw(0x2000, &(0x3007_u64 | (1 << 63)).to_le_bytes())
            .unwrap();
        assert_eq!(read(&memory, 0x8ffe), None);
        assert_eq!(fetch_user_byte(&memory, 0x1000, 1 << 47), None);
    }
}
