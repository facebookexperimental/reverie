//! Conditional complete Bootstrap::site leaf, separate from View::site.
//!
//! Preconditions: enter the observed start with this compiled ABI; RDI denotes
//! aligned live writable 32-byte result storage, RSI a valid live 24-byte
//! Bootstrap representation, RDX the index. Its immutable nonwrapping backing,
//! code/table, valid stack/return address and result storage remain live. Result
//! storage is disjoint from the representation/backing/code/table. This factory
//! proves none of those physical caller conditions, nor full View validation.
//!
//! Complete finite body argument (entry-relative half-open ranges):
//! 000..081 checks backing header through descriptor2, stride32, aligned offset
//! `>=960`, count1..128, checked end and index<count. Failures reach081.
//! 081..08c writes Bounds byte2 at output0 and FF at24, then RET.
//! 08c..0ab checks row offset/end before loads; failure reaches081.
//! 0ab..0ce requires raw operation1..4 and dispatches through the exact own table.
//! 0ce..0fd requires pairs (1,158),(2,218),(3,7),(4,2), yielding bytes0,1,2,3.
//! 0fd..11d requires nonwrapping syscall_ip+2 == return_ip.
//! 11d..128 writes Value byte3 at0 and FF at24, then RET.
//! 128..138 stores actual IP/post/number at0/8/16 and operation at24, then RET.
//! SUB -32/-2 with carry checks implement checked unsigned additions; the
//! count-minus-one unsigned guard refuses zero. No CALL, DIV, syscall, FS/GS,
//! UD2 or external branch occurs. The only indirect JMP has the four joined
//! internal starts. Error payload8..23 is unspecified. RET assumes ordinary
//! trusted compiled ABI, not arbitrary call/return CFI or exception safety.
//!
//! No installer, async handler, pre-FS closure, guest or Ready authority follows.
use super::view_site::SiteLeafIdentity;
use super::view_site::SiteLeafKind;
use super::*;

pub(super) const CODE_BYTES: usize = 312;
const TABLE_BYTES: usize = 16;
const LEA_FIELD: usize = 0xc1;
const ARMS: [usize; 4] = [0xce, 0xf1, 0xdb, 0xe6];
const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_9Bootstrap4site";
const SOURCE_SHA: &str = "85abd905256f3bc5b526840cf3cd5e090238e4aa770f03d320c2ae907ee7ae75";
const INPUT: [u8; CODE_BYTES] = [
    0x48, 0x89, 0xf8, 0x48, 0x8b, 0x7e, 0x08, 0x48, 0x81, 0xff, 0xc0, 0x02, 0x00, 0x00, 0x72, 0x71,
    0x48, 0x81, 0xff, 0xc8, 0x02, 0x00, 0x00, 0x72, 0x68, 0x48, 0x81, 0xff, 0xd0, 0x02, 0x00, 0x00,
    0x72, 0x5f, 0x48, 0x8b, 0x0e, 0x48, 0x83, 0xb9, 0xc8, 0x02, 0x00, 0x00, 0x20, 0x75, 0x52, 0x48,
    0x8b, 0xb1, 0xb8, 0x02, 0x00, 0x00, 0x40, 0xf6, 0xc6, 0x07, 0x75, 0x45, 0x48, 0x81, 0xfe, 0xc0,
    0x03, 0x00, 0x00, 0x72, 0x3c, 0x4c, 0x8b, 0x81, 0xc0, 0x02, 0x00, 0x00, 0x4d, 0x8d, 0x48, 0xff,
    0x49, 0x83, 0xf9, 0x7f, 0x77, 0x2b, 0x4d, 0x89, 0xc1, 0x49, 0xc1, 0xe1, 0x05, 0x49, 0x01, 0xf1,
    0x49, 0x39, 0xf1, 0x41, 0x0f, 0x93, 0xc2, 0x49, 0x39, 0xf9, 0x41, 0x0f, 0x96, 0xc1, 0x4c, 0x39,
    0xc2, 0x41, 0x0f, 0x92, 0xc0, 0x45, 0x20, 0xd0, 0x45, 0x20, 0xc8, 0x41, 0x80, 0xf8, 0x01, 0x74,
    0x0b, 0xc6, 0x00, 0x02, 0x40, 0xb7, 0xff, 0x40, 0x88, 0x78, 0x18, 0xc3, 0x48, 0xc1, 0xe2, 0x05,
    0x48, 0x01, 0xd6, 0x72, 0xec, 0x48, 0x89, 0xf2, 0x48, 0x83, 0xea, 0xe0, 0x41, 0x0f, 0x93, 0xc0,
    0x48, 0x39, 0xfa, 0x0f, 0x97, 0xc2, 0x44, 0x08, 0xc2, 0x75, 0xd6, 0x48, 0x8b, 0x7c, 0x31, 0x18,
    0x48, 0xff, 0xcf, 0x48, 0x83, 0xff, 0x03, 0x77, 0x64, 0x48, 0x8b, 0x54, 0x31, 0x10, 0x4c, 0x8d,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x49, 0x63, 0x3c, 0xb8, 0x4c, 0x01, 0xc7, 0xff, 0xe7, 0x48, 0x81,
    0xfa, 0x9e, 0x00, 0x00, 0x00, 0x75, 0x46, 0x31, 0xff, 0xeb, 0x22, 0x40, 0xb7, 0x02, 0x48, 0x83,
    0xfa, 0x07, 0x74, 0x19, 0xeb, 0x37, 0x40, 0xb7, 0x03, 0x48, 0x83, 0xfa, 0x02, 0x74, 0x0e, 0xeb,
    0x2c, 0x40, 0xb7, 0x01, 0x48, 0x81, 0xfa, 0xda, 0x00, 0x00, 0x00, 0x75, 0x20, 0x4c, 0x8b, 0x04,
    0x31, 0x48, 0x8b, 0x4c, 0x31, 0x08, 0x4c, 0x89, 0xc6, 0x48, 0x83, 0xee, 0xfe, 0x41, 0x0f, 0x93,
    0xc1, 0x48, 0x39, 0xce, 0x40, 0x0f, 0x95, 0xc6, 0x44, 0x08, 0xce, 0x74, 0x0b, 0xc6, 0x00, 0x03,
    0x40, 0xb7, 0xff, 0x40, 0x88, 0x78, 0x18, 0xc3, 0x4c, 0x89, 0x00, 0x48, 0x89, 0x48, 0x08, 0x48,
    0x89, 0x50, 0x10, 0x40, 0x88, 0x78, 0x18, 0xc3,
];

pub(super) fn source_symbol(digest: &str) -> Result<&'static str> {
    require(
        digest == SOURCE_SHA,
        "Bootstrap::site complete runtime source differs",
    )?;
    Ok(SYMBOL)
}
// Unlike the older View discovery, this exact finite Bootstrap cohort does
// not admit compiler-generated suffix aliases. Keep its complete raw name
// unchanged through the physical-input and final-symbol joins.
pub(super) fn named_site(name: &str, expected: &str) -> bool {
    !name.contains('.') && canonical_rust_symbol(name).as_deref() == Some(expected)
}

pub(super) fn input_code(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "Bootstrap::site finite complete instruction form differs",
    )
}

/// Source-owned conditional normal-return observation, never an entry permit.
/// No public constructor, Clone, Deserialize or conversion to a View observation.
#[derive(Debug, Serialize)]
pub struct BootstrapSiteLeafObservation {
    identity: SiteLeafIdentity,
}
impl BootstrapSiteLeafObservation {
    /// Actual selected entry; calling it still requires all documented premises.
    pub fn entry(&self) -> u64 {
        self.identity.entry
    }
    /// Under the documented physical ABI premises, actual result byte24 is in
    /// this set. FF is an error and does not initialize a successful Site payload.
    pub fn conditional_result_bytes(&self) -> [u8; 5] {
        [0, 1, 2, 3, 0xff]
    }
}
/// Complete compiled checker identity for the ordinary closed source catalog.
pub fn bootstrap_site_implementation_sha256() -> String {
    sha256(include_bytes!("bootstrap_site.rs"))
}
impl VerifiedStaticSource {
    /// Observe only the separate finite Bootstrap leaf in the SAME live source,
    /// archive, selected-definition and final ELF/map transaction. All error and
    /// callback paths close archive/build-script outputs, definitions and files.
    /// This does not authorize a call, prove the installer or validate a View.
    pub fn with_bootstrap_site_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        body: impl FnOnce(&BootstrapSiteLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_site_leaf(
            SiteLeafKind::Bootstrap,
            archive,
            definitions,
            (artifact, link_map),
            runner,
            |identity, runner| {
                require(
                    Arc::ptr_eq(&identity.owner.0, &self.archive_owner)
                        && identity.runtime_archive == archive.file,
                    "Bootstrap::site belongs to another source/archive",
                )?;
                body(&BootstrapSiteLeafObservation { identity }, runner)
            },
        )
    }
}
pub(super) fn input_fields(object: &ObjectInput<'_>, code: usize, table: usize) -> Result<()> {
    let tab = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, tab)?;
    let mut found = Vec::new();
    for (index, rows) in &object.elf.shdr_relocs {
        let rs = checked_relocation_section(&object.elf, object.bytes, *index, tab, rows.len())?;
        if rs.sh_info as usize != code && rs.sh_info as usize != table {
            continue;
        }
        for r in rows.iter() {
            checked_relocation_span(&object.elf, rs, r.r_offset, r.r_type)?;
            let is_code = rs.sh_info as usize == code;
            let target = object
                .elf
                .syms
                .get(r.r_sym)
                .ok_or("Bootstrap::site relocation symbol absent")?;
            super::view_site::section_symbol(object, &target, if is_code { table } else { code })?;
            found.push((
                is_code,
                r.r_offset,
                r.r_type,
                r.r_addend
                    .ok_or("Bootstrap::site input needs explicit addend")?,
            ));
        }
    }
    input_field_shape(&mut found)
}
fn input_field_shape(found: &mut Vec<(bool, u64, u32, i64)>) -> Result<()> {
    let mut expected = vec![(true, LEA_FIELD as u64, reloc::R_X86_64_PC32, -4)];
    for (i, arm) in ARMS.into_iter().enumerate() {
        expected.push((
            false,
            (i * 4) as u64,
            reloc::R_X86_64_PC32,
            (arm + i * 4) as i64,
        ));
    }
    found.sort_unstable();
    expected.sort_unstable();
    require(
        *found == expected,
        "Bootstrap::site five exact typed input relocations differ",
    )
}

pub(super) fn linked_form(
    code: &[u8],
    table: &[u8],
    entry: u64,
    table_address: u64,
    code_fields: &[FinalRelocation],
    table_fields: &[FinalRelocation],
) -> Result<[u64; 4]> {
    require(
        code.len() == CODE_BYTES
            && table.len() == TABLE_BYTES
            && code_fields.len() == 1
            && table_fields.len() == 4,
        "Bootstrap::site full body/table/relocation census differs",
    )?;
    let r = &code_fields[0];
    require(
        r.offset == LEA_FIELD
            && r.kind == reloc::R_X86_64_PC32
            && i128::from(r.symbol_value) + i128::from(r.addend) == i128::from(table_address) - 4,
        "Bootstrap::site LEA does not join exact RO table",
    )?;
    let mut expected = INPUT;
    let place = entry
        .checked_add(LEA_FIELD as u64)
        .ok_or("Bootstrap::site LEA overflow")?;
    expected[LEA_FIELD..LEA_FIELD + 4].copy_from_slice(&checked_pc32(table_address, -4, place)?);
    require(
        code == expected,
        "Bootstrap::site relocated whole body differs",
    )?;
    let mut targets = [0; 4];
    for (i, r) in table_fields.iter().enumerate() {
        let target = entry
            .checked_add(ARMS[i] as u64)
            .ok_or("Bootstrap::site arm overflow")?;
        let offset = (i * 4) as u64;
        require(
            r.offset == i * 4
                && r.kind == reloc::R_X86_64_PC32
                && i128::from(r.symbol_value) + i128::from(r.addend)
                    == i128::from(target) + i128::from(offset),
            "Bootstrap::site relative entry target differs",
        )?;
        let expected = checked_pc32(
            target,
            offset as i64,
            table_address
                .checked_add(offset)
                .ok_or("Bootstrap::site table overflow")?,
        )?;
        require(
            table.get(i * 4..i * 4 + 4) == Some(&expected[..]),
            "Bootstrap::site relative entry bytes differ",
        )?;
        targets[i] = target;
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small synthetic coordinates are test data, NOT a source-owned positive.
    fn linked() -> (Vec<u8>, Vec<u8>, Vec<FinalRelocation>, Vec<FinalRelocation>) {
        let entry = 0x1000;
        let table = 0x3000;
        let mut code = INPUT.to_vec();
        code[LEA_FIELD..LEA_FIELD + 4]
            .copy_from_slice(&checked_pc32(table, -4, entry + LEA_FIELD as u64).unwrap());
        let code_fields = vec![FinalRelocation {
            offset: LEA_FIELD,
            kind: reloc::R_X86_64_PC32,
            addend: -4,
            symbol_value: table,
        }];
        let mut data = Vec::new();
        let mut fields = Vec::new();
        for (i, arm) in ARMS.into_iter().enumerate() {
            let offset = (i * 4) as u64;
            data.extend_from_slice(
                &checked_pc32(entry + arm as u64, offset as i64, table + offset).unwrap(),
            );
            fields.push(FinalRelocation {
                offset: i * 4,
                kind: reloc::R_X86_64_PC32,
                addend: (arm + i * 4) as i64,
                symbol_value: entry,
            });
        }
        (code, data, code_fields, fields)
    }
    #[test]
    fn bootstrap_site_complete_form_refuses_every_changed_byte_and_extent() {
        input_code(&INPUT).unwrap();
        assert!(input_code(&INPUT[..CODE_BYTES - 1]).is_err());
        for at in 0..CODE_BYTES {
            let mut wrong = INPUT;
            wrong[at] ^= 1;
            assert!(input_code(&wrong).is_err(), "changed byte {at}");
        }
    }
    #[test]
    fn bootstrap_site_bounds_operation_number_ip_and_return_stores_are_not_waived() {
        let (code, table, code_fields, table_fields) = linked();
        // Operation upper bound, op/number arms, carry/IP pair, success byte
        // store and BOTH error byte stores: each is an actual executed byte.
        for at in [
            0x26, 0x42, 0x6e, 0x7f, 0xb3, 0xd4, 0xdf, 0xe9, 0xf9, 0x104, 0x123, 0x134,
        ] {
            let mut wrong = code.clone();
            wrong[at] ^= 1;
            assert!(
                linked_form(&wrong, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err(),
                "critical byte {at:x}"
            );
        }
    }
    #[test]
    fn bootstrap_site_synthetic_signed_table_requires_all_four_exact_targets() {
        let (code, table, code_fields, mut table_fields) = linked();
        assert_eq!(
            linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).unwrap(),
            ARMS.map(|n| 0x1000 + n as u64)
        );
        // All entries are negative signed deltas in this fixture.
        assert!(
            table
                .as_chunks::<4>()
                .0
                .iter()
                .all(|b| i32::from_le_bytes(*b) < 0)
        );
        for i in 0..4 {
            let mut wrong = table.clone();
            wrong[i * 4] ^= 1;
            assert!(
                linked_form(&code, &wrong, 0x1000, 0x3000, &code_fields, &table_fields).is_err()
            );
            table_fields[i].addend += 1;
            assert!(
                linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err()
            );
            table_fields[i].addend -= 1;
        }
        table_fields.swap(0, 1);
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err());
    }
    #[test]
    fn bootstrap_site_missing_duplicate_kind_and_wrong_target_fields_refuse() {
        let (code, table, mut code_fields, mut table_fields) = linked();
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &[], &table_fields).is_err());
        assert!(
            linked_form(
                &code,
                &table,
                0x1000,
                0x3000,
                &code_fields,
                &table_fields[..3]
            )
            .is_err()
        );
        table_fields[1] = table_fields[0].clone();
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err());
        let (_, _, _, table_fields) = linked();
        code_fields[0].kind = reloc::R_X86_64_PLT32;
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err());
        code_fields[0].kind = reloc::R_X86_64_PC32;
        code_fields[0].symbol_value += 1;
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).is_err());
        // Exact S+A rebasing is allowed, but the actual whole field bytes stay
        // fixed. This is the existing selected-definition relocation semantics.
        code_fields[0].addend -= 1;
        linked_form(&code, &table, 0x1000, 0x3000, &code_fields, &table_fields).unwrap();
    }
    #[test]
    fn bootstrap_site_input_relocation_census_has_no_optional_field() {
        let mut rows = vec![(true, LEA_FIELD as u64, reloc::R_X86_64_PC32, -4)];
        rows.extend(ARMS.into_iter().enumerate().map(|(i, n)| {
            (
                false,
                (i * 4) as u64,
                reloc::R_X86_64_PC32,
                (n + i * 4) as i64,
            )
        }));
        input_field_shape(&mut rows).unwrap();
        let mut missing = rows.clone();
        missing.pop();
        assert!(input_field_shape(&mut missing).is_err());
        let mut extra = rows.clone();
        extra.push(rows[0]);
        assert!(input_field_shape(&mut extra).is_err());
        let mut wrong = rows;
        wrong[0].3 += 1;
        assert!(input_field_shape(&mut wrong).is_err());
    }
    #[test]
    fn bootstrap_source_and_role_never_accept_view_or_other_cohorts() {
        assert_eq!(source_symbol(SOURCE_SHA).unwrap(), SYMBOL);
        let actual = "_RNvMs1_NtCsiQA3fNasB45_14reverie_loader7handoffNtB5_9Bootstrap4site";
        assert!(named_site(actual, SYMBOL));
        for digest in [
            "85e0f1cb9393c1ed11db4d6115f81dbce5d3f0afcfc733aa4d0cd2d6725245c7",
            "e8b70072083fc78771ecc405433a47254de01d2ea7d4dc0e5368ab0bfe8e4ccf",
            &SOURCE_SHA[..63],
        ] {
            assert!(source_symbol(digest).is_err());
        }
        for wrong in [
            actual.replace("9Bootstrap", "4View"),
            actual.replace("4site", "5table"),
            format!("{actual}.llvm.1"),
            actual.replace("Ms1_", "Ms2_"),
        ] {
            assert!(
                !named_site(&wrong, SYMBOL),
                "unexpected Bootstrap alias {wrong}"
            );
        }
    }
    #[test]
    fn bootstrap_signed_fields_refuse_overflow_and_crossing_or_extra_writers() {
        let (code, table, mut cf, tf) = linked();
        cf[0].offset = LEA_FIELD - 1;
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &cf, &tf).is_err());
        cf[0].offset = LEA_FIELD;
        cf.push(cf[0].clone());
        assert!(linked_form(&code, &table, 0x1000, 0x3000, &cf, &tf).is_err());
        assert!(checked_pc32(u64::MAX, 0, 0).is_err());
        assert!(checked_pc32(0, 0, u64::MAX).is_err());
    }
}
