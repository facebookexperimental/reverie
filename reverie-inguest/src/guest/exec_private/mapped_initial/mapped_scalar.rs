//! Native register bridge for the shared no_std mapped-input predicate.
//! Re-exports are numeric data only, never physical origin or readiness.

use reverie_loader::handoff::Error;
use reverie_loader::handoff::Registers;
pub use reverie_loader::mapped_inputs::ConsumerLayout;
pub use reverie_loader::mapped_inputs::ProductionMappedInputs;

/// Local bridge only: copy every exact original word into the consumer's native
/// register value. Never reference the handoff as a `libc::user_regs_struct`.
/// The host still owns original xstate and the actual stopped generation.
pub fn native_registers(words: Registers<'_>) -> Result<libc::user_regs_struct, Error> {
    let r = words.words()?;
    Ok(libc::user_regs_struct {
        r15: r[0],
        r14: r[1],
        r13: r[2],
        r12: r[3],
        rbp: r[4],
        rbx: r[5],
        r11: r[6],
        r10: r[7],
        r9: r[8],
        r8: r[9],
        rax: r[10],
        rcx: r[11],
        rdx: r[12],
        rsi: r[13],
        rdi: r[14],
        orig_rax: r[15],
        rip: r[16],
        cs: r[17],
        eflags: r[18],
        rsp: r[19],
        ss: r[20],
        fs_base: r[21],
        gs_base: r[22],
        ds: r[23],
        es: r[24],
        fs: r[25],
        gs: r[26],
    })
}

#[cfg(test)]
mod tests {
    use reverie_loader::handoff::Extent;
    use reverie_loader::handoff::HEADER_BYTES;
    use reverie_loader::handoff::MAGIC;
    use reverie_loader::handoff::VERSION;

    use super::*;
    use crate::private_runtime::tls;
    // Keep the original fixture's checked numeric construction local to tests;
    // the production decoder and geometry now live in reverie-loader.
    fn extent(start: u64, bytes: u64) -> Result<tls::layout::Extent, Error> {
        Ok(tls::layout::Extent {
            start: usize::try_from(start).map_err(|_| Error::Bounds)?,
            bytes: usize::try_from(bytes).map_err(|_| Error::Bounds)?,
        })
    }
    fn put(b: &mut [u8], word: usize, value: u64) {
        b[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn get(b: &[u8], word: usize) -> u64 {
        u64::from_le_bytes(b[word * 8..word * 8 + 8].try_into().unwrap())
    }
    fn at(b: &[u8], table: usize) -> usize {
        get(b, 81 + table * 3) as usize / 8
    }
    // Numeric synthetic ledger ONLY. No mapping/capture/syscall/adoption is
    // invoked; no tuple is claimed to authenticate an actual ELF or owner.
    fn fixture() -> (Vec<u8>, ConsumerLayout) {
        let mut b = vec![0; 4096];
        let addr = b.as_ptr() as u64;
        let hand = (addr & !4095) - 4096;
        let starts = [
            hand - 0x40000,
            hand - 0x30000,
            hand - 0x20000,
            hand,
            hand + 0x10000,
        ];
        let runtime = 0x6000_e100_0000u64;
        let free_band = Extent {
            start: starts[0],
            end: starts[4] + 0x8000,
        };
        let region = Extent {
            start: free_band.start.min(runtime),
            end: free_band.end.max(runtime + 0x4000),
        };
        for (i, start) in starts.into_iter().enumerate() {
            put(&mut b, 28 + i * 2, start);
            put(&mut b, 29 + i * 2, start + 0x8000);
        }
        put(&mut b, 0, MAGIC);
        put(&mut b, 1, VERSION);
        put(&mut b, 2, 4096);
        put(&mut b, 3, HEADER_BYTES as u64);
        for (i, value) in [
            7,
            starts[4] + 4096,
            64,
            starts[4] + 4160,
            64,
            9,
            0,
            0,
            0,
            runtime + 0x1800,
            runtime,
            4096,
            8192,
            runtime + 512,
            0,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 65 + i, value);
        }
        let mut offset = HEADER_BYTES;
        for (i, (count, stride)) in [
            (7, 32),
            (1, 16),
            (4, 32),
            (8, 1),
            (1, 8),
            (10, 8),
            (8, 1),
            (10, 1),
            (2, 8),
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 81 + i * 3, offset as u64);
            put(&mut b, 82 + i * 3, count);
            put(&mut b, 83 + i * 3, stride);
            if i == 6 {
                b[offset..offset + 8].copy_from_slice(b"hermit!\0");
            }
            if i == 7 {
                b[offset..offset + 10].copy_from_slice(b"/dev/null\0");
            }
            offset = (offset + count as usize * stride as usize + 7) & !7;
        }
        let maps = at(&b, 0);
        for (i, start) in starts.into_iter().enumerate() {
            for (j, w) in [start + 4096, start + 0x7000, if i == 3 { 1 } else { 3 }, 0]
                .into_iter()
                .enumerate()
            {
                put(&mut b, maps + i * 4 + j, w);
            }
        }
        for (i, words) in [
            [runtime, runtime + 4096, 1, 0],
            [runtime + 4096, runtime + 0x4000, 5, 0],
        ]
        .into_iter()
        .enumerate()
        {
            for (j, w) in words.into_iter().enumerate() {
                put(&mut b, maps + (5 + i) * 4 + j, w);
            }
        }
        let code = at(&b, 1);
        put(&mut b, code, runtime + 4096);
        put(&mut b, code + 1, runtime + 0x4000);
        let sites = at(&b, 2);
        for (i, (nr, op)) in [(158, 1), (218, 2), (7, 3), (2, 4)].into_iter().enumerate() {
            for (j, w) in [
                runtime + 0x1100 + i as u64 * 16,
                runtime + 0x1102 + i as u64 * 16,
                nr,
                op,
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut b, sites + i * 4 + j, w);
            }
        }
        let tool_sites = at(&b, 8);
        put(&mut b, tool_sites, runtime + 0x2102);
        put(&mut b, tool_sites + 1, runtime + 0x2202);
        for (i, w) in [
            runtime + 64,
            56,
            1,
            runtime + 2048,
            64,
            128,
            8,
            starts[1] + 4096,
            0x6000,
            runtime,
            4096,
            4096,
        ]
        .into_iter()
        .enumerate()
        {
            put(&mut b, 108 + i, w);
        }
        let aux = at(&b, 5);
        for (i, w) in [3, runtime + 64, 4, 56, 5, 1, 6, 4096, 0, 0]
            .into_iter()
            .enumerate()
        {
            put(&mut b, aux + i, w);
        }
        let plan = tls::layout::plan(
            extent(region.start, region.end - region.start).unwrap(),
            extent(starts[1] + 4096, 0x6000).unwrap(),
            extent(runtime, 4096).unwrap(),
            extent(runtime, 4096).unwrap(),
            tls::layout::Template {
                image: (runtime + 2048) as usize,
                file_bytes: 64,
                memory_bytes: 128,
                alignment: 8,
            },
        )
        .unwrap();
        put(&mut b, 73, plan.pthread().start as u64);
        (
            b,
            ConsumerLayout {
                free_band,
                region,
                control_bytes: 64,
                relay_bytes: 64,
                control_align: 64,
                relay_align: 64,
            },
        )
    }
    #[test]
    fn scalar_consumer_preserves_real_word_codec_and_tls_geometry() {
        let (mut b, expected) = fixture();
        for i in 0..27 {
            put(&mut b, 38 + i, 0x100 + i as u64);
        }
        let input = ProductionMappedInputs::decode(&b, expected).unwrap();
        let regs = native_registers(input.registers()).unwrap();
        assert_eq!(
            [
                regs.r15,
                regs.r14,
                regs.r13,
                regs.r12,
                regs.rbp,
                regs.rbx,
                regs.r11,
                regs.r10,
                regs.r9,
                regs.r8,
                regs.rax,
                regs.rcx,
                regs.rdx,
                regs.rsi,
                regs.rdi,
                regs.orig_rax,
                regs.rip,
                regs.cs,
                regs.eflags,
                regs.rsp,
                regs.ss,
                regs.fs_base,
                regs.gs_base,
                regs.ds,
                regs.es,
                regs.fs,
                regs.gs
            ],
            input.registers().words().unwrap()
        );
        assert_eq!(
            input.tls_plan().pthread().start as u64,
            input.view().scalar(8).unwrap()
        );
        assert_eq!(input.view().bytes().as_ptr(), b.as_ptr());
    }
    #[test]
    fn scalar_consumer_refuses_wx_overlap_and_wrong_native_sizes() {
        for case in 0..3 {
            let (mut b, mut expected) = fixture();
            let maps = at(&b, 0);
            match case {
                0 => put(&mut b, maps + 2, 7),
                1 => {
                    let start = get(&b, maps);
                    put(&mut b, maps + 4, start);
                }
                _ => expected.control_bytes = 128,
            }
            assert!(ProductionMappedInputs::decode(&b, expected).is_err());
        }
    }
    #[test]
    fn scalar_consumer_refuses_tls_tcb_and_private_phdr_aux_mismatch() {
        for case in 0..3 {
            let (mut b, expected) = fixture();
            match case {
                0 => put(&mut b, 73, 1),
                1 => put(&mut b, 112, 8192),
                _ => {
                    let aux = at(&b, 5);
                    put(&mut b, aux + 1, 1);
                }
            }
            assert!(ProductionMappedInputs::decode(&b, expected).is_err());
        }
    }
    #[test]
    fn scalar_consumer_requires_final_ro_dev_null_pointer_not_blob_copy() {
        let (mut b, expected) = fixture();
        let copied = (b.as_ptr() as u64) + get(&b, 102);
        put(&mut b, 78, copied); // same literal bytes in an otherwise valid RO blob
        // Same literal bytes in handoff do not identify the final musl literal.
        assert!(ProductionMappedInputs::decode(&b, expected).is_err());
        let (mut b, expected) = fixture();
        put(&mut b, 78, 0x1234);
        assert!(ProductionMappedInputs::decode(&b, expected).is_err());
    }

    #[test]
    fn scalar_tool_init_site_must_be_inside_qualified_executable_extent() {
        let (mut b, expected) = fixture();
        let sites = at(&b, 8);
        // An adjacent RO header byte and a PC beyond the actual code are not
        // qualified instruction boundaries, even though both are numeric PCs.
        put(&mut b, sites, 0x6000_e100_0002);
        assert!(ProductionMappedInputs::decode(&b, expected).is_err());
        let (mut b, expected) = fixture();
        let sites = at(&b, 8);
        put(&mut b, sites + 1, 0x6000_e100_4002);
        assert!(ProductionMappedInputs::decode(&b, expected).is_err());
    }
    #[test]
    fn arithmetic_extremes_keep_the_existing_decoder_refusal_boundaries() {
        // These are real wire mutations, not direct tests of checked_add/sub.
        // Existing validation must reject each before a speculative arithmetic
        // predecessor can become a panic or authorize an invalid extent.
        for case in 0..7 {
            let (mut bytes, expected) = fixture();
            let code = at(&bytes, 1);
            let sites = at(&bytes, 8);
            let expected_error = match case {
                0 => {
                    put(&mut bytes, code, u64::MAX);
                    put(&mut bytes, code + 1, 0);
                    Error::Value
                }
                1 => {
                    put(&mut bytes, sites, 1);
                    Error::Value
                }
                2 => {
                    put(&mut bytes, 97, 0);
                    Error::Bounds
                }
                3 => {
                    put(&mut bytes, 97, 1);
                    Error::Value
                }
                4 => {
                    put(&mut bytes, 97, u64::MAX);
                    Error::Bounds
                }
                5 => {
                    put(&mut bytes, 30, u64::MAX - 4095);
                    put(&mut bytes, 31, 0);
                    Error::Bounds
                }
                _ => {
                    put(&mut bytes, 30, 0);
                    put(&mut bytes, 31, 4096);
                    Error::Bounds
                }
            };
            assert_eq!(
                ProductionMappedInputs::decode(&bytes, expected).err(),
                Some(expected_error)
            );
        }
    }

    #[test]
    fn earlier_reserved_error_still_precedes_later_arithmetic_invalidity() {
        let (mut bytes, expected) = fixture();
        put(&mut bytes, 4, 1);
        put(&mut bytes, 97, u64::MAX);
        let sites = at(&bytes, 8);
        put(&mut bytes, sites, 0);
        assert_eq!(
            ProductionMappedInputs::decode(&bytes, expected).err(),
            Some(Error::Reserved)
        );
    }

    #[test]
    fn shared_predicate_uses_represented_child_address_not_parent_storage() {
        let (b, expected) = fixture();
        let address = b.as_ptr() as u64;
        let copy = b.clone();
        assert_ne!(copy.as_ptr(), b.as_ptr());
        let validated = ProductionMappedInputs::validate_at(&copy, address, expected).unwrap();
        assert_eq!(validated.view().address(), address);
        assert_eq!(validated.view().bytes().as_ptr(), copy.as_ptr());
        assert!(ProductionMappedInputs::validate_at(&copy, u64::MAX - 7, expected).is_err());
    }
    #[test]
    fn shared_complete_predicate_refuses_lazy_site_aux_and_target_alignment() {
        for case in 0..4 {
            let (mut b, mut expected) = fixture();
            match case {
                0 => {
                    let sites = at(&b, 2);
                    put(&mut b, sites + 3, 99);
                }
                1 => {
                    let aux = at(&b, 5);
                    put(&mut b, aux + 1, 1);
                }
                2 => {
                    let codes = at(&b, 1);
                    put(&mut b, codes + 1, 0);
                }
                _ => expected.relay_align = 0,
            }
            assert!(ProductionMappedInputs::validate_at(&b, b.as_ptr() as u64, expected).is_err());
        }
    }
    #[test]
    fn shared_structure_keeps_packet_and_register_interior_checks() {
        let (b, expected) = fixture();
        let input = ProductionMappedInputs::validate_at(&b, b.as_ptr() as u64, expected).unwrap();
        assert!(input.check_structure().is_ok());
        // A role that clips the represented original-register source refuses.
        let (mut bad, expected) = fixture();
        let address = bad.as_ptr() as u64;
        put(&mut bad, 34, (address & !4095) + 4096);
        assert!(ProductionMappedInputs::validate_at(&bad, address, expected).is_err());
    }
    // Extend only this synthetic wire fixture's table, keeping its allocation
    // and all original fixture/test bodies unchanged. These rows model a file
    // mapping followed by anonymous memory; numeric rows confer no ownership.
    fn split_load_fixture() -> (Vec<u8>, ConsumerLayout) {
        let (mut bytes, mut expected) = fixture();
        let old_end = (at(&bytes, 0) + 7 * 4) * 8;
        let used_end = get(&bytes, 105) as usize + 16;
        bytes.copy_within(old_end..used_end, old_end + 96);
        for table in 1..9 {
            let word = 81 + table * 3;
            let offset = get(&bytes, word);
            put(&mut bytes, word, offset + 96);
        }
        put(&mut bytes, 82, 10);
        let maps = at(&bytes, 0);
        let runtime = 0x6000_e100_0000;
        for (index, row) in [
            [runtime + 0x4000, runtime + 0x6000, 3, 0],
            [runtime + 0x6000, runtime + 0x8000, 1, 0],
            [runtime + 0x8000, runtime + 0xa000, 3, 0],
        ]
        .into_iter()
        .enumerate()
        {
            for (field, value) in row.into_iter().enumerate() {
                put(&mut bytes, maps + (7 + index) * 4 + field, value);
            }
        }
        put(&mut bytes, 111, runtime + 0x4800); // genuine template offset in file row
        put(&mut bytes, 117, runtime + 0x4000); // complete PT_LOAD memory start
        put(&mut bytes, 118, 0x6000); // complete p_memsz, including anonymous tail
        put(&mut bytes, 119, 0x2000); // p_filesz remains a separate extent
        expected.region.end = expected.region.end.max(runtime + 0xa000);
        (bytes, expected)
    }

    #[test]
    fn scalar_load_accepts_split_readable_file_and_anonymous_memory() {
        let (bytes, expected) = split_load_fixture();
        let input = ProductionMappedInputs::decode(&bytes, expected).unwrap();
        assert_eq!(input.view().tls(10).unwrap(), 0x6000);
        assert_eq!(input.view().tls(11).unwrap(), 0x2000);
        assert_eq!(input.tls_plan().template().file_bytes, 64);
        assert_eq!(input.tls_plan().template().memory_bytes, 128);
        // Half-open boundaries meet exactly at 0x6000 and 0x8000; the final
        // load byte is in the last row, whose exclusive end equals load end.
        assert_eq!(
            input.view().map(7).unwrap().end,
            input.view().map(8).unwrap().start
        );
        assert_eq!(
            input.view().map(8).unwrap().end,
            input.view().map(9).unwrap().start
        );
    }

    #[test]
    fn scalar_load_accepts_unsorted_adjacent_readable_rows() {
        let (mut bytes, expected) = split_load_fixture();
        let maps = at(&bytes, 0);
        for field in 0..4 {
            let first = get(&bytes, maps + 7 * 4 + field);
            let last = get(&bytes, maps + 9 * 4 + field);
            put(&mut bytes, maps + 7 * 4 + field, last);
            put(&mut bytes, maps + 9 * 4 + field, first);
        }
        assert!(ProductionMappedInputs::decode(&bytes, expected).is_ok());
    }

    #[test]
    fn scalar_load_preserves_single_row_and_interior_boundary_coverage() {
        let (bytes, expected) = fixture();
        assert!(ProductionMappedInputs::decode(&bytes, expected).is_ok());
        let (mut bytes, expected) = fixture();
        let runtime = 0x6000_e100_0000;
        // The load can begin inside its readable row; its last byte remains
        // inside the row and its exclusive end can equal the row's end.
        put(&mut bytes, 117, runtime + 64);
        put(&mut bytes, 118, 4096 - 64);
        put(&mut bytes, 119, 4096 - 64);
        assert!(ProductionMappedInputs::decode(&bytes, expected).is_ok());
    }

    #[test]
    fn scalar_load_refuses_gap_unreadable_middle_end_and_one_byte_past_end() {
        for case in 0..5 {
            let (mut bytes, expected) = split_load_fixture();
            let maps = at(&bytes, 0);
            match case {
                0 => put(&mut bytes, maps + 8 * 4, 0x6000_e100_7000),
                1 => put(&mut bytes, maps + 8 * 4 + 2, 0),
                2 => put(&mut bytes, maps + 9 * 4 + 2, 0),
                3 => put(&mut bytes, maps + 9 * 4 + 1, 0x6000_e100_9000),
                _ => put(&mut bytes, 118, 0x6001),
            }
            assert_eq!(
                ProductionMappedInputs::decode(&bytes, expected).err(),
                Some(Error::Value)
            );
        }
    }

    #[test]
    fn scalar_load_keeps_existing_overlap_rejection_before_coverage() {
        let (mut bytes, expected) = split_load_fixture();
        let maps = at(&bytes, 0);
        // Both rows are readable, so coverage must not hide their overlap.
        put(&mut bytes, maps + 8 * 4, 0x6000_e100_5000);
        assert_eq!(
            ProductionMappedInputs::decode(&bytes, expected).err(),
            Some(Error::Bounds)
        );
    }

    #[test]
    fn scalar_load_refuses_overflow_and_empty_memory_extent() {
        let (mut bytes, expected) = split_load_fixture();
        put(&mut bytes, 117, u64::MAX - 4095);
        put(&mut bytes, 118, 8192);
        assert_eq!(
            ProductionMappedInputs::decode(&bytes, expected).err(),
            Some(Error::Value)
        );
        let (mut bytes, expected) = split_load_fixture();
        put(&mut bytes, 118, 0);
        assert_eq!(
            ProductionMappedInputs::decode(&bytes, expected).err(),
            Some(Error::Value)
        );
    }
}
