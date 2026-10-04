/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The entry proof for a LiteInst jump patch
//! (<https://github.com/rrnewton/reverie/issues/812>).
//!
//! [`reverie_ptrace::liteinst_census`] lists, for each `syscall` site of a
//! loaded object, the lowest known control-transfer entry after it. This
//! module checks a live scan of the bytes a patch would displace against that
//! entry. Under ptrace the tracer builds the census from the tracee's memory
//! and passes the entry to the installation helper; without a tracer the
//! runtime builds the census itself from an [`ObjectImage`].

use iced_x86::Mnemonic;
use liteinst2::patcher::NEAR_JUMP_BYTES;
use liteinst2::scanner::ScannedInstruction;
pub(crate) use reverie_ptrace::liteinst_census::Census;
pub(crate) use reverie_ptrace::liteinst_census::CensusError;
pub(crate) use reverie_ptrace::liteinst_census::REFUSED_ENTRY_LIMIT;
pub(crate) use reverie_ptrace::liteinst_census::Refusal;
use reverie_ptrace::liteinst_census::Segment;
pub(crate) use reverie_ptrace::liteinst_census::SiteEntries;

/// Where a loaded object was mapped when LiteInst initialized.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObjectImage {
    header: u64,
    /// `(start, end, executable)` for each readable mapping.
    ranges: Box<[(u64, u64, bool)]>,
}

impl ObjectImage {
    pub(crate) fn new(header: u64, ranges: Box<[(u64, u64, bool)]>) -> Self {
        Self { header, ranges }
    }

    /// Builds the census of the executable mapping `text` from the object's
    /// current bytes.
    ///
    /// # Safety
    ///
    /// Every recorded range must still be mapped readable.
    pub(crate) unsafe fn census(&self, text: (u64, u64)) -> Result<Census, CensusError> {
        let mut segments = Vec::new();
        segments
            .try_reserve_exact(self.ranges.len())
            .map_err(|_| CensusError::ALLOCATION)?;
        for &(start, end, executable) in &self.ranges {
            let len = end
                .checked_sub(start)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(CensusError::TRUNCATED)?;
            segments.push(Segment {
                address: start,
                // SAFETY: the caller guarantees the range is mapped readable.
                bytes: unsafe { core::slice::from_raw_parts(start as usize as *const u8, len) },
                executable,
            });
        }
        Census::build(&segments, self.header, text)
    }
}

/// Proves that no known entry lands inside the bytes a jump patch at
/// `address` would displace. `instructions` is the live scan from the site.
pub(crate) fn prove(
    census: &Census,
    address: u64,
    instructions: &[ScannedInstruction],
) -> Result<(), Refusal> {
    prove_within(address, census.site(address)?, instructions)
}

/// Proves that a jump patch at `address` would displace the census's
/// `syscall` and whole instructions that end at or before `entries.limit`.
/// `instructions` is the live scan from the site.
pub(crate) fn prove_within(
    address: u64,
    entries: SiteEntries,
    instructions: &[ScannedInstruction],
) -> Result<(), Refusal> {
    let first = instructions.first().ok_or(Refusal::InstructionMismatch)?;
    if first.address() != address
        || first.len() != usize::from(entries.len)
        || first.instruction().mnemonic() != Mnemonic::Syscall
    {
        return Err(Refusal::InstructionMismatch);
    }
    let end = displaced_end(address, instructions).ok_or(Refusal::InstructionMismatch)?;
    if entries.limit < end {
        return Err(Refusal::InteriorEntry {
            entry: entries.limit,
        });
    }
    Ok(())
}

/// Returns the end of the instructions a jump patch at `address` displaces.
///
/// This follows `JumpPatchPlan::from_scan` in liteinst2 2032b49d: whole
/// consecutive instructions from the site until they cover
/// [`NEAR_JUMP_BYTES`].
pub(crate) fn displaced_end(address: u64, instructions: &[ScannedInstruction]) -> Option<u64> {
    let start = instructions
        .iter()
        .position(|instruction| instruction.address() == address)?;
    let mut end = address;
    for instruction in &instructions[start..] {
        if instruction.address() != end {
            return None;
        }
        end = end.checked_add(instruction.len() as u64)?;
        if end - address >= NEAR_JUMP_BYTES as u64 {
            return Some(end);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use iced_x86::Decoder;
    use iced_x86::DecoderOptions;
    use iced_x86::Mnemonic;
    use iced_x86::OpKind;
    use liteinst2::patcher::JumpPatchPlan;
    use liteinst2::patcher::WORD_PATCH_BYTES;
    use liteinst2::scanner::InstructionScanner;

    use super::Census;
    use super::ObjectImage;
    use super::Refusal;
    use super::Segment;
    use super::displaced_end;
    use super::prove as prove_site;

    const BASE: u64 = 0x10_0000;
    const HEADER_BYTES: usize = 0x200;
    const TEXT: u64 = 0x1000;

    // `posix_madvise` from glibc 2.34: the `je` skips the syscall for
    // POSIX_MADV_DONTNEED and lands on the `ret` that a patch displaces.
    const MADVISE: &[u8] = &[
        0x31, 0xc0, // xor %eax,%eax
        0x83, 0xfa, 0x04, // cmp $0x4,%edx
        0x74, 0x09, // je +9, the ret
        0xb8, 0x1c, 0x00, 0x00, 0x00, // mov $0x1c,%eax
        0x0f, 0x05, // syscall
        0xf7, 0xd8, // neg %eax
        0xc3, // ret
    ];
    const MADVISE_SITE: u64 = 12;
    const MADVISE_RET: u64 = 16;

    // The same function with the `je` replaced by two `nop`s.
    const PLAIN: &[u8] = &[
        0x31, 0xc0, 0x83, 0xfa, 0x04, 0x90, 0x90, 0xb8, 0x1c, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xf7,
        0xd8, 0xc3,
    ];

    struct Object {
        header: Vec<u8>,
        text: Vec<u8>,
        tables: Vec<u8>,
        data: Vec<u8>,
    }

    fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    /// Lays out a minimal ELF object: a header page, a text page holding the
    /// given functions at their offsets, a table page holding `.eh_frame_hdr`,
    /// one CIE, one FDE per function and optional LSDAs, and a zeroed data
    /// page.
    ///
    /// Each function is `(offset in text, bytes, landing pad offsets)`.
    fn object(functions: &[(u64, &[u8], &[u64])], text_len: usize) -> Object {
        let tables_address = TEXT + text_len as u64;
        let mut header = vec![0; HEADER_BYTES];
        put(&mut header, 0, b"\x7fELF\x02\x01\x01");
        put(&mut header, 18, &62_u16.to_le_bytes());
        put(&mut header, 32, &64_u64.to_le_bytes());
        put(&mut header, 54, &56_u16.to_le_bytes());
        put(&mut header, 56, &2_u16.to_le_bytes());
        // PT_LOAD at offset 0 and address 0.
        put(&mut header, 64, &1_u32.to_le_bytes());
        // PT_GNU_EH_FRAME at the table page.
        put(&mut header, 120, &0x6474_e550_u32.to_le_bytes());
        put(&mut header, 120 + 16, &tables_address.to_le_bytes());

        let mut text = vec![0xcc; text_len];
        for (offset, bytes, _) in functions {
            put(&mut text, *offset as usize, bytes);
        }

        // .eh_frame_hdr: version, eh_frame_ptr (pcrel sdata4), count (udata4)
        // and table (datarel sdata4).
        let hdr_len = 12 + 8 * functions.len();
        let mut tables = vec![1, 0x1b, 0x03, 0x3b];
        tables.extend_from_slice(&(hdr_len as i32 - 4).to_le_bytes());
        tables.extend_from_slice(&(functions.len() as u32).to_le_bytes());
        let table_offset = tables.len();
        tables.resize(hdr_len, 0);
        // CIE "zLR": LSDA and FDE pointers are pcrel sdata4.
        let cie = tables.len();
        let cie_body: &[u8] = &[
            0, 0, 0, 0, 1, b'z', b'L', b'R', 0, 1, 0x78, 16, 2, 0x1b, 0x1b, 0, 0, 0,
        ];
        tables.extend_from_slice(&(cie_body.len() as u32).to_le_bytes());
        tables.extend_from_slice(cie_body);
        let mut lsdas = Vec::new();
        for (index, (offset, bytes, pads)) in functions.iter().enumerate() {
            let fde = tables.len();
            let search_entry = [
                ((TEXT + offset) as i64 - tables_address as i64) as i32,
                fde as i32,
            ];
            put(
                &mut tables,
                table_offset + 8 * index,
                &search_entry.map(i32::to_le_bytes).concat(),
            );
            tables.extend_from_slice(&20_u32.to_le_bytes());
            tables.extend_from_slice(&((fde + 4 - cie) as u32).to_le_bytes());
            let start_field = tables_address + tables.len() as u64;
            tables.extend_from_slice(
                &(((TEXT + offset) as i64 - start_field as i64) as i32).to_le_bytes(),
            );
            tables.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            tables.push(4);
            let lsda_field = tables.len();
            tables.extend_from_slice(&0_i32.to_le_bytes());
            tables.extend_from_slice(&[0, 0, 0]);
            if !pads.is_empty() {
                lsdas.push((lsda_field, *pads));
            }
        }
        for (lsda_field, pads) in lsdas {
            let lsda = tables.len();
            put(
                &mut tables,
                lsda_field,
                &((lsda - lsda_field) as i32).to_le_bytes(),
            );
            // No LPStart, no type table, uleb128 call sites.
            tables.extend_from_slice(&[0xff, 0xff, 0x01, (4 * pads.len()) as u8]);
            for pad in pads {
                tables.extend_from_slice(&[0, 1, *pad as u8, 0]);
            }
        }
        Object {
            header,
            text,
            tables,
            data: vec![0; 64],
        }
    }

    fn text_address(offset: u64) -> u64 {
        BASE + TEXT + offset
    }

    fn census(object: &Object) -> Census {
        let tables = text_address(object.text.len() as u64);
        let segments = [
            Segment {
                address: BASE,
                bytes: &object.header,
                executable: false,
            },
            Segment {
                address: text_address(0),
                bytes: &object.text,
                executable: true,
            },
            Segment {
                address: tables,
                bytes: &object.tables,
                executable: false,
            },
            Segment {
                address: tables + 0x1000,
                bytes: &object.data,
                executable: false,
            },
        ];
        let text = (text_address(0), text_address(object.text.len() as u64));
        Census::build(&segments, BASE, text).unwrap()
    }

    fn prove(object: &Object, census: &Census, offset: u64) -> Result<(), Refusal> {
        let scan = InstructionScanner::default()
            .scan_prefix(
                &object.text[offset as usize..],
                text_address(offset),
                WORD_PATCH_BYTES,
            )
            .unwrap();
        prove_site(census, text_address(offset), scan.instructions())
    }

    fn madvise_refusal() -> Result<(), Refusal> {
        Err(Refusal::InteriorEntry {
            entry: text_address(0x40 + MADVISE_RET),
        })
    }

    #[test]
    fn a_branch_into_the_displaced_bytes_refuses_the_site() {
        let object = object(&[(0x40, MADVISE, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            madvise_refusal()
        );
    }

    #[test]
    fn a_function_without_interior_entries_proves_the_site() {
        let object = object(&[(0x40, PLAIN, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            Ok(())
        );
    }

    #[test]
    fn a_branch_from_another_function_refuses_the_site() {
        // A cold fragment elsewhere jumps to the plain function's `ret`.
        let displacement = (0x40 + MADVISE_RET) as i32 - (0x80 + 5);
        let mut cold = vec![0xe9];
        cold.extend_from_slice(&displacement.to_le_bytes());
        let object = object(&[(0x40, PLAIN, &[]), (0x80, &cold, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            madvise_refusal()
        );
    }

    #[test]
    fn a_landing_pad_in_the_displaced_bytes_refuses_the_site() {
        let object = object(&[(0x40, PLAIN, &[MADVISE_RET])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            madvise_refusal()
        );
    }

    #[test]
    fn a_code_pointer_in_data_refuses_the_site() {
        let mut object = object(&[(0x40, PLAIN, &[])], 0x100);
        let pointer = text_address(0x40 + MADVISE_RET);
        object.data[8..16].copy_from_slice(&pointer.to_le_bytes());
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            madvise_refusal()
        );
    }

    #[test]
    fn a_rip_relative_lea_of_the_displaced_bytes_refuses_the_site() {
        // `lea disp(%rip),%rcx; ret` in another function computes the address
        // of the plain function's `ret`.
        let displacement = (0x40 + MADVISE_RET) as i32 - (0x80 + 7);
        let mut lea = vec![0x48, 0x8d, 0x0d];
        lea.extend_from_slice(&displacement.to_le_bytes());
        lea.push(0xc3);
        let object = object(&[(0x40, PLAIN, &[]), (0x80, &lea, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            madvise_refusal()
        );
    }

    #[test]
    fn an_indirect_jump_makes_the_function_opaque() {
        let mut switch = PLAIN.to_vec();
        // Replace the two nops with `jmp *%rax`.
        switch[5..7].copy_from_slice(&[0xff, 0xe0]);
        let object = object(&[(0x40, &switch, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            Err(Refusal::OpaqueFunction)
        );
    }

    #[test]
    fn a_last_instruction_crossing_the_function_end_makes_it_opaque() {
        // The unwind entry ends after the first byte of `neg`; the rest of
        // the function follows it in the text.
        let mut object = object(&[(0x40, &PLAIN[..15], &[])], 0x100);
        object.text[0x40 + 15..0x40 + PLAIN.len()].copy_from_slice(&PLAIN[15..]);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            Err(Refusal::OpaqueFunction)
        );
    }

    #[test]
    fn a_site_outside_every_function_is_refused() {
        let mut object = object(&[(0x40, PLAIN, &[])], 0x100);
        object.text[0xa0..0xa0 + PLAIN.len()].copy_from_slice(PLAIN);
        assert_eq!(
            prove(&object, &census(&object), 0xa0 + MADVISE_SITE),
            Err(Refusal::NotInFunction)
        );
    }

    #[test]
    fn a_window_may_cross_into_padding_but_not_into_code() {
        // `mov $0x3c,%eax; syscall` ends the function, so the window takes
        // three bytes after it.
        let tail: &[u8] = &[0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let padded = object(&[(0x40, tail, &[])], 0x100);
        assert_eq!(prove(&padded, &census(&padded), 0x45), Ok(()));

        // Code without unwind information follows the function directly.
        let mut unlisted = object(&[(0x40, tail, &[])], 0x100);
        unlisted.text[0x47..0x4a].copy_from_slice(&[0x48, 0x31, 0xc0]);
        assert_eq!(
            prove(&unlisted, &census(&unlisted), 0x45),
            Err(Refusal::InteriorEntry {
                entry: text_address(0x47)
            })
        );

        // The next listed function starts directly after the syscall.
        let next = object(&[(0x40, tail, &[]), (0x47, PLAIN, &[])], 0x100);
        assert_eq!(
            prove(&next, &census(&next), 0x45),
            Err(Refusal::InteriorEntry {
                entry: text_address(0x47)
            })
        );
    }

    #[test]
    fn an_entry_at_the_displaced_end_is_allowed() {
        // The patch displaces `syscall; neg; ret` and leaves the second `ret`
        // in place, so a branch to that `ret` is safe.
        let mut function = PLAIN.to_vec();
        function.push(0xc3);
        // je +10 lands on the second `ret`.
        function[5..7].copy_from_slice(&[0x74, 0x0a]);
        let object = object(&[(0x40, &function, &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            Ok(())
        );
    }

    #[test]
    fn overlapping_functions_are_opaque() {
        let object = object(&[(0x40, PLAIN, &[]), (0x48, &PLAIN[8..], &[])], 0x100);
        assert_eq!(
            prove(&object, &census(&object), 0x40 + MADVISE_SITE),
            Err(Refusal::OpaqueFunction)
        );
    }

    #[test]
    fn the_displaced_end_matches_liteinst2() {
        let scanner = InstructionScanner::default();
        for bytes in [
            &[0x0f, 0x05, 0xf7, 0xd8, 0xc3, 0x90, 0x90, 0x90][..],
            &[0x0f, 0x05, 0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff, 0x77, 0x01][..],
            &[0x0f, 0x05, 0x89, 0xc6, 0x89, 0xd8, 0x90, 0x90][..],
        ] {
            let address = 0x4000;
            let scan = scanner
                .scan_prefix(bytes, address, WORD_PATCH_BYTES)
                .unwrap();
            let plan = JumpPatchPlan::from_scan(
                &scanner,
                &scan,
                scan.snapshot(),
                address,
                address,
                address + 0x100,
            )
            .unwrap();
            assert_eq!(
                displaced_end(address, scan.instructions()),
                Some(address + plan.displaced_len() as u64)
            );
        }
    }

    struct LoadedObject {
        path: String,
        /// `(start, end, executable)` for each readable mapping.
        ranges: Vec<(u64, u64, bool)>,
        header: u64,
        text: (u64, u64),
    }

    /// Finds this process's mappings of the object that maps `address`
    /// executable.
    fn loaded_object(address: u64) -> LoadedObject {
        struct Mapping<'a> {
            start: u64,
            end: u64,
            permissions: &'a [u8],
            offset: u64,
            identity: (&'a str, u64),
            path: &'a str,
        }
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mappings = maps
            .lines()
            .filter_map(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                let (start, end) = fields.first()?.split_once('-')?;
                Some(Mapping {
                    start: u64::from_str_radix(start, 16).ok()?,
                    end: u64::from_str_radix(end, 16).ok()?,
                    permissions: fields.get(1)?.as_bytes(),
                    offset: u64::from_str_radix(fields.get(2)?, 16).ok()?,
                    identity: (fields.get(3)?, fields.get(4)?.parse().ok()?),
                    path: fields.get(5).copied().unwrap_or(""),
                })
            })
            .collect::<Vec<_>>();
        let text = mappings
            .iter()
            .find(|mapping| mapping.start <= address && address < mapping.end)
            .unwrap();
        assert_eq!(text.permissions[2], b'x');
        let object = mappings
            .iter()
            .filter(|mapping| mapping.identity == text.identity && mapping.permissions[0] == b'r')
            .collect::<Vec<_>>();
        LoadedObject {
            path: text.path.to_owned(),
            ranges: object
                .iter()
                .map(|mapping| (mapping.start, mapping.end, mapping.permissions[2] == b'x'))
                .collect(),
            header: object
                .iter()
                .find(|mapping| mapping.offset == 0)
                .unwrap()
                .start,
            text: (text.start, text.end),
        }
    }

    /// Builds the census of this process's libc and checks `posix_madvise`
    /// against a local decode of it. On glibc 2.34 its `je` enters the
    /// displaced bytes, so the site must be refused; on a libc without such a
    /// branch the test checks only that the census builds.
    #[test]
    fn the_census_of_this_process_libc_agrees_with_a_decode_of_posix_madvise() {
        // SAFETY: the name is NUL-terminated and dlsym does not retain it.
        let function = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"posix_madvise".as_ptr()) } as u64;
        assert_ne!(function, 0);
        let object = loaded_object(function);
        assert!(object.path.contains("libc"), "{}", object.path);
        let image = ObjectImage::new(object.header, object.ranges.into_boxed_slice());
        let started = std::time::Instant::now();
        // SAFETY: each range is a live readable mapping of libc, which this
        // process never unmaps.
        let census = unsafe { image.census(object.text) }.unwrap();
        let elapsed = started.elapsed();
        // SAFETY: as above, for libc's executable mapping.
        let text = unsafe {
            core::slice::from_raw_parts(
                object.text.0 as usize as *const u8,
                (object.text.1 - object.text.0) as usize,
            )
        };
        let opaque = census
            .site_addresses()
            .filter(|address| census.site(*address) == Err(Refusal::OpaqueFunction))
            .count();
        let scan_at = |address: u64| {
            InstructionScanner::default().scan_prefix(
                &text[(address - object.text.0) as usize..],
                address,
                WORD_PATCH_BYTES,
            )
        };

        // Decode posix_madvise through the first `ret` after its syscall and
        // collect its direct branch targets.
        let code = &text[(function - object.text.0) as usize..][..64];
        let mut decoder = Decoder::with_ip(64, code, function, DecoderOptions::NONE);
        let mut site = None;
        let mut targets = Vec::new();
        for instruction in &mut decoder {
            if instruction.op0_kind() == OpKind::NearBranch64 {
                targets.push(instruction.near_branch_target());
            }
            match instruction.mnemonic() {
                Mnemonic::Syscall => site = Some(instruction.ip()),
                Mnemonic::Ret if site.is_some() => break,
                _ => {}
            }
        }
        let site = site.expect("posix_madvise issues a syscall");
        let scan = scan_at(site).unwrap();
        let end = displaced_end(site, scan.instructions()).unwrap();
        let interior = targets
            .iter()
            .copied()
            .filter(|target| site < *target && *target < end)
            .min();
        let proof = prove_site(&census, site, scan.instructions());

        let refused = census
            .site_addresses()
            .filter(|candidate| match scan_at(*candidate) {
                Ok(scan) => prove_site(&census, *candidate, scan.instructions()).is_err(),
                Err(_) => true,
            })
            .count();
        eprintln!(
            "{}: {} sites, {opaque} in opaque functions, {refused} refused, built in \
             {elapsed:?}; posix_madvise site at offset {:#x}: interior branch target \
             {interior:x?}, proof {proof:?}",
            object.path,
            census.site_addresses().count(),
            site - object.text.0,
        );
        let sites = census.site_addresses().count();
        assert!(sites >= 100, "{sites} sites");
        if let Some(entry) = interior {
            assert!(
                matches!(proof, Err(Refusal::InteriorEntry { entry: limit }) if limit <= entry),
                "{proof:?}"
            );
        }
    }
}
