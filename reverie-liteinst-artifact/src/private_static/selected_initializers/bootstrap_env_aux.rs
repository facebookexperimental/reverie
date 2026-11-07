//! Complete conditional Bootstrap::env_aux_words253 leaf; not project validation.
//!
//! Actual entry premises: RDI is aligned, disjoint live writable result storage
//! at least 16 bytes; RSI points to this compiler's readable immutable Bootstrap
//! representation (backing pointer at0, length at8). The full backing is live,
//! readable, immutable and nonwrapping. Code, stack and return address remain
//! valid under the actual compiled call/return ABI. Output cannot alias backing,
//! representation, code or return slot. Signal/exception preservation, physical
//! mappings and caller tag dominance are NOT established by this observation.
//!
//! Complete finite normal-flow argument (entry-relative half-open ranges):
//! 00..31 saves RDI in RAX; loads length; requires >=752,760,768 before reading
//! backing fields. Bounds branches go d6. At2e the backing pointer is loaded.
//! 31..88 checks descriptor4 at2e8/2f0/2f8: stride8, offset aligned8/>=960,
//! unsigned count-1<=511 (count1..512), no carry from offset+8*count, end<=len.
//! Product<=4096 cannot overflow. Carry and end>len are ORed before refusal.
//! 88..d6 repeats those conditions for descriptor5 at300/308/310. There are no
//! separate aux-header length branches: reaching88 already proves len>=968
//! from env offset>=960/count>=1/end<=len, covering aux-header end792. This
//! implication is essential; no arbitrary unvalidated pointer is admitted.
//! d6..df writes Bounds2 at output1 and tag1 at0; RET. df..eb adds accepted
//! counts (sum2..1024 cannot overflow), compares512; >512 writes Value3/tag1
//! and RET atf3. f4..fd stores sum at output8 and tag0 at0; RET.
//! RAX is the original output pointer on every return, not a sum/tag/errno.
//! Errors initialize only bytes0..1; success only byte0 and bytes8..15. No
//! error payload or padding is read as success. RSI/RDI/RCX/RDX/R8 and flags
//! are clobbered; no useful values are promised in those registers on Err.
//!
//! No CALL, indirect branch, loop, FS/GS/TLS, allocator, panic, syscall, UD2,
//! readonly table or code relocation exists in this complete exact form.
//! This leaf checks descriptors/count only, NOT env/aux contents, adjacency,
//! strings, credentials, secure state, project/installer callers, async/unwind,
//! full pre-FS closure or Ready. Both callers remain independently unproved.
use super::view_site::final_aliases;
use super::view_site::final_section;
use super::view_table::LeafObjects;
use super::view_table::bounded;
use super::view_table::refuse_writer;
use super::*;

const SOURCE_SHA: &str = "85abd905256f3bc5b526840cf3cd5e090238e4aa770f03d320c2ae907ee7ae75";
const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_9Bootstrap13env_aux_words";
const SIZE: usize = 253;
// Entire actual input/final body. There are NO masks or placeholder operands.
const INPUT: [u8; SIZE] = [
    0x48, 0x89, 0xf8, 0x48, 0x8b, 0x4e, 0x08, 0x48, 0x81, 0xf9, 0xf0, 0x02, 0x00, 0x00, 0x0f, 0x82,
    0xc2, 0x00, 0x00, 0x00, 0x48, 0x81, 0xf9, 0xf8, 0x02, 0x00, 0x00, 0x0f, 0x82, 0xb5, 0x00, 0x00,
    0x00, 0x48, 0x81, 0xf9, 0x00, 0x03, 0x00, 0x00, 0x0f, 0x82, 0xa8, 0x00, 0x00, 0x00, 0x48, 0x8b,
    0x36, 0x48, 0x83, 0xbe, 0xf8, 0x02, 0x00, 0x00, 0x08, 0x0f, 0x85, 0x97, 0x00, 0x00, 0x00, 0x48,
    0x8b, 0xbe, 0xe8, 0x02, 0x00, 0x00, 0x40, 0xf6, 0xc7, 0x07, 0x0f, 0x85, 0x86, 0x00, 0x00, 0x00,
    0x48, 0x81, 0xff, 0xc0, 0x03, 0x00, 0x00, 0x72, 0x7d, 0x48, 0x8b, 0x96, 0xf0, 0x02, 0x00, 0x00,
    0x4c, 0x8d, 0x42, 0xff, 0x49, 0x81, 0xf8, 0xff, 0x01, 0x00, 0x00, 0x77, 0x69, 0x4c, 0x8d, 0x04,
    0xd5, 0x00, 0x00, 0x00, 0x00, 0x49, 0x01, 0xf8, 0x40, 0x0f, 0x92, 0xc7, 0x49, 0x39, 0xc8, 0x41,
    0x0f, 0x97, 0xc0, 0x41, 0x08, 0xf8, 0x75, 0x4e, 0x48, 0x83, 0xbe, 0x10, 0x03, 0x00, 0x00, 0x08,
    0x75, 0x44, 0x48, 0x8b, 0xbe, 0x00, 0x03, 0x00, 0x00, 0x40, 0xf6, 0xc7, 0x07, 0x75, 0x37, 0x48,
    0x81, 0xff, 0xc0, 0x03, 0x00, 0x00, 0x72, 0x2e, 0x48, 0x8b, 0xb6, 0x08, 0x03, 0x00, 0x00, 0x4c,
    0x8d, 0x46, 0xff, 0x49, 0x81, 0xf8, 0xff, 0x01, 0x00, 0x00, 0x77, 0x1a, 0x4c, 0x8d, 0x04, 0xf5,
    0x00, 0x00, 0x00, 0x00, 0x49, 0x01, 0xf8, 0x40, 0x0f, 0x92, 0xc7, 0x49, 0x39, 0xc8, 0x0f, 0x97,
    0xc1, 0x40, 0x08, 0xf9, 0x74, 0x09, 0xc6, 0x40, 0x01, 0x02, 0xb1, 0x01, 0x88, 0x08, 0xc3, 0x48,
    0x01, 0xd6, 0x48, 0x81, 0xfe, 0x00, 0x02, 0x00, 0x00, 0x76, 0x09, 0xc6, 0x40, 0x01, 0x03, 0xb1,
    0x01, 0x88, 0x08, 0xc3, 0x48, 0x89, 0x70, 0x08, 0x31, 0xc9, 0x88, 0x08, 0xc3,
];
fn source_symbol(digest: &str) -> Result<&'static str> {
    require(
        digest == SOURCE_SHA,
        "Bootstrap::env_aux_words complete source differs",
    )?;
    Ok(SYMBOL)
}
fn named(name: &str, expected: &str) -> bool {
    !name.contains('.') && canonical_rust_symbol(name).as_deref() == Some(expected)
}
fn code_form(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "Bootstrap::env_aux_words complete finite form differs",
    )
}
fn input(object: &ObjectInput<'_>, symbol: &sym::Sym, name: &str) -> Result<()> {
    require(
        object.member_name.starts_with("reverie_loader-")
            && symbol.st_type() == sym::STT_FUNC
            && symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_other == 0
            && symbol.st_value == 0
            && symbol.st_size == SIZE as u64,
        "Bootstrap::env_aux_words input owner/function differs",
    )?;
    let section = object
        .elf
        .section_headers
        .get(symbol.st_shndx)
        .ok_or("env_aux input section absent")?;
    require(
        section.sh_type == section_header::SHT_PROGBITS
            && section.sh_flags == 6
            && section.sh_size == SIZE as u64
            && section.sh_addralign == 16
            && object.elf.shdr_strtab.get_at(section.sh_name)
                == Some(format!(".text.{name}").as_str()),
        "Bootstrap::env_aux_words exact input geometry differs",
    )?;
    let mut functions = 0;
    let mut sections = 0;
    for s in object
        .elf
        .syms
        .iter()
        .filter(|s| s.st_shndx == symbol.st_shndx)
    {
        if s.st_type() == sym::STT_SECTION {
            super::view_site::section_symbol(object, &s, symbol.st_shndx)?;
            sections += 1;
        } else {
            require(
                s == *symbol && object.elf.strtab.get_at(s.st_name) == Some(name),
                "Bootstrap::env_aux_words unexpected input alias",
            )?;
            functions += 1;
        }
    }
    require(
        functions == 1 && sections == 1,
        "Bootstrap::env_aux_words input symbol census differs",
    )?;
    code_form(section_file_bytes(section, object.bytes)?)?;
    let tab = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, tab)?;
    for (ri, rows) in &object.elf.shdr_relocs {
        let rs = checked_relocation_section(&object.elf, object.bytes, *ri, tab, rows.len())?;
        require(
            rs.sh_info as usize != symbol.st_shndx || rows.is_empty(),
            "Bootstrap::env_aux_words unexpected input relocation",
        )?;
    }
    Ok(())
}
fn final_body<'a>(
    elf: &Elf<'_>,
    bytes: &'a [u8],
    entry: u64,
    name: &str,
    expected: &str,
) -> Result<&'a [u8]> {
    static_image_metadata(elf, bytes)?;
    let tab = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, tab)?;
    let symbols = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx != 0
                && elf
                    .strtab
                    .get_at(s.st_name)
                    .is_some_and(|n| named(n, expected))
        })
        .collect::<Vec<_>>();
    require(
        symbols.len() == 1 && elf.strtab.get_at(symbols[0].st_name) == Some(name),
        "Bootstrap::env_aux_words final definition absent/ambiguous/different",
    )?;
    let symbol = symbols[0];
    require(
        symbol.st_type() == sym::STT_FUNC
            && symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_other == 0
            && symbol.st_value == entry
            && symbol.st_size == SIZE as u64,
        "Bootstrap::env_aux_words final function differs from input/map",
    )?;
    let section = final_section(elf, bytes, entry, SIZE, 5)?;
    final_aliases(elf, entry, SIZE, section, Some(name))?;
    let end = entry
        .checked_add(SIZE as u64)
        .ok_or("env_aux final extent overflow")?;
    for (ri, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *ri, tab, rows.len())?;
        let target = &elf.section_headers[rs.sh_info as usize];
        for row in rows.iter() {
            checked_relocation_span(elf, rs, row.r_offset, row.r_type)?;
            refuse_writer(target, row.r_offset, row.r_type, entry, end)?;
        }
    }
    let body = mapped_bytes(elf, bytes, entry, SIZE as u64, 5)?;
    code_form(body)?;
    Ok(body)
}

/// Private construction; a conditional normal-return fact, never a call permit.
/// No constructor, Clone, Deserialize, transfer resolver or Ready conversion.
#[derive(Debug, Serialize)]
pub struct BootstrapEnvAuxLeafObservation {
    #[serde(skip)]
    owner: DefinitionSourceOwner,
    runtime_archive: FileIdentity,
    artifact: FileIdentity,
    link_map: FileIdentity,
    source: FileIdentity,
    member_name: String,
    member_ordinal: usize,
    member_header: u64,
    member_sha256: String,
    input_section: usize,
    entry: u64,
    body_sha256: String,
    scope: &'static str,
}
impl BootstrapEnvAuxLeafObservation {
    /// Actual complete start; not permission to enter or call it.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Only after actual Ok tag0 under all documented memory/caller premises.
    pub fn conditional_success_words(&self) -> std::ops::RangeInclusive<usize> {
        2..=512
    }
    fn require_owner(&self, source: &VerifiedStaticSource, archive: &StaticArchive) -> Result<()> {
        require(
            Arc::ptr_eq(&self.owner.0, &source.archive_owner)
                && self.runtime_archive == archive.file,
            "Bootstrap::env_aux_words belongs to another source/archive",
        )
    }
}
/// Actual compiled checker bytes for the closed source catalog.
pub fn bootstrap_env_aux_implementation_sha256() -> String {
    sha256(include_bytes!("bootstrap_env_aux.rs"))
}
impl VerifiedStaticSource {
    /// Observe the whole finite env/aux leaf within the same live source/archive/
    /// definitions/ELF/map owner. The existing with_leaf_objects transaction
    /// independently closes its full definitions ledger, archive/build outputs,
    /// source and files on every admitted Result path, including callback Err.
    /// Both project and installer call/output/tag/async contracts remain unproved.
    pub fn with_bootstrap_env_aux_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        callback: impl FnOnce(&BootstrapEnvAuxLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_leaf_objects(
            archive,
            definitions,
            (artifact, link_map),
            runner,
            source_symbol,
            |leaves, runner| {
                let observation = observe(self, archive, artifact, link_map, leaves)?;
                observation.require_owner(self, archive)?;
                callback(&observation, runner)
            },
        )
    }
}
fn observe(
    source: &VerifiedStaticSource,
    archive: &StaticArchive,
    artifact: &FileIdentity,
    link_map: &FileIdentity,
    leaves: LeafObjects<'_, '_>,
) -> Result<BootstrapEnvAuxLeafObservation> {
    let mut selected = Vec::new();
    for (i, object) in leaves.objects.iter().enumerate() {
        for s in object.elf.syms.iter().filter(|s| s.st_shndx != 0) {
            let name = object
                .elf
                .strtab
                .get_at(s.st_name)
                .ok_or("env_aux object name absent")?;
            if named(name, leaves.expected_symbol) {
                selected.push((i, s));
            }
        }
    }
    require(
        selected.len() == 1,
        "Bootstrap::env_aux_words definition absent/ambiguous across archive",
    )?;
    let (i, symbol) = selected[0];
    let object = &leaves.objects[i];
    let name = object
        .elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or("env_aux name absent")?;
    input(object, &symbol, name)?;
    let map_bytes = bounded(link_map)?;
    let map = std::str::from_utf8(&map_bytes).map_err(|e| e.to_string())?;
    let entry = mapped_section(map, object, symbol.st_shndx)?;
    let bytes = bounded(artifact)?;
    let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
    let body = final_body(&elf, &bytes, entry, name, leaves.expected_symbol)?;
    join_relocated_body(
        &elf,
        &bytes,
        entry,
        section_file_bytes(&object.elf.section_headers[symbol.st_shndx], object.bytes)?,
        body,
        &[],
        &[],
    )?;
    Ok(BootstrapEnvAuxLeafObservation {
        owner: DefinitionSourceOwner(source.archive_owner.clone()),
        runtime_archive: archive.file.clone(),
        artifact: artifact.clone(),
        link_map: link_map.clone(),
        source: leaves.source.clone(),
        member_name: object.member_name.to_owned(),
        member_ordinal: object.ordinal,
        member_header: object.header_offset,
        member_sha256: sha256(object.bytes),
        input_section: symbol.st_shndx,
        entry,
        body_sha256: sha256(body),
        scope: "CONDITIONAL_ENV_AUX_COUNT_ONLY_BOTH_CALLERS_PHYSICAL_ASYNC_UNWIND_NOT_PROVEN",
    })
}

#[cfg(test)]
mod tests {
    use super::super::view_table::tests::plain_fixture;
    use super::*;
    const NAME: &str = "_RNvMs1_NtCsunit_14reverie_loader7handoffNtB5_9Bootstrap13env_aux_words";
    const ENTRY: u64 = 0x100000;
    fn fixture(linked: bool, writer: bool, alias: bool) -> Vec<u8> {
        plain_fixture(linked, writer, alias, NAME, &INPUT)
    }
    fn input_fixture(bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
        let symbol = elf.syms.get(2).ok_or("unit symbol absent")?;
        input(
            &ObjectInput {
                archive_path: Path::new("/unit/not-authority.a"),
                member_name: "reverie_loader-unit.o",
                ordinal: 0,
                header_offset: 8,
                bytes,
                elf,
            },
            &symbol,
            NAME,
        )
    }
    fn final_fixture(bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
        final_body(&elf, bytes, ENTRY, NAME, SYMBOL).map(|_| ())
    }
    fn put64(bytes: &mut [u8], at: usize, n: u64) {
        bytes[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    #[test]
    fn env_aux_complete_source_and_role_are_closed() {
        assert_eq!(source_symbol(SOURCE_SHA).unwrap(), SYMBOL);
        assert!(named(NAME, SYMBOL));
        for digest in [
            "0".repeat(64),
            SOURCE_SHA[..63].to_owned(),
            SOURCE_SHA.to_ascii_uppercase(),
        ] {
            assert!(source_symbol(&digest).is_err());
        }
        for name in [
            NAME.replace("Ms1_", "Ms2_"),
            NAME.replace("13env_aux_words", "4role"),
            format!("{NAME}.llvm.0"),
        ] {
            assert!(!named(&name, SYMBOL));
        }
    }
    #[test]
    fn env_aux_entire_body_no_operand_masks() {
        code_form(&INPUT).unwrap();
        assert!(code_form(&INPUT[..SIZE - 1]).is_err());
        for at in 0..SIZE {
            let mut changed = INPUT;
            changed[at] ^= 1;
            assert!(code_form(&changed).is_err(), "changed code byte {at}");
        }
    }
    #[test]
    fn env_aux_result_tags_payload_offsets_and_all_rets_are_exact() {
        assert_eq!(
            &INPUT[0xd6..0xdf],
            &[0xc6, 0x40, 1, 2, 0xb1, 1, 0x88, 8, 0xc3]
        );
        assert_eq!(
            &INPUT[0xeb..0xf4],
            &[0xc6, 0x40, 1, 3, 0xb1, 1, 0x88, 8, 0xc3]
        );
        assert_eq!(
            &INPUT[0xf4..],
            &[0x48, 0x89, 0x70, 8, 0x31, 0xc9, 0x88, 8, 0xc3]
        );
        for at in [0xd9, 0xdb, 0xde, 0xee, 0xf0, 0xf3, 0xf7, 0xfa, 0xfc] {
            let mut b = fixture(true, false, false);
            b[0x1000 + at] ^= 1;
            assert!(final_fixture(&b).is_err());
        }
    }
    #[test]
    fn env_aux_parsed_input_requires_exact_member_shape_aliases_and_no_relocations() {
        input_fixture(&fixture(false, false, false)).unwrap();
        for b in [fixture(false, true, false), fixture(false, false, true)] {
            assert!(input_fixture(&b).is_err());
        }
        for (at, n) in [
            (0x2800 + 64 + 8, 7),
            (0x2800 + 64 + 32, 252),
            (0x2800 + 64 + 48, 8),
            (0x2238, 1),
            (0x2240, 252),
        ] {
            let mut b = fixture(false, false, false);
            put64(&mut b, at, n);
            assert!(input_fixture(&b).is_err());
        }
        let mut b = fixture(false, false, false);
        b[0x2234] = 2;
        assert!(input_fixture(&b).is_err());
    }
    #[test]
    fn env_aux_parsed_final_requires_rx_exact_bytes_aliases_and_map_address() {
        final_fixture(&fixture(true, false, false)).unwrap();
        for b in [fixture(true, true, false), fixture(true, false, true)] {
            assert!(final_fixture(&b).is_err());
        }
        let mut b = fixture(true, false, false);
        b[68..72].copy_from_slice(&7u32.to_le_bytes());
        assert!(final_fixture(&b).is_err());
        for (at, n) in [(0x2238, ENTRY + 1), (0x2240, 252)] {
            let mut b = fixture(true, false, false);
            put64(&mut b, at, n);
            assert!(final_fixture(&b).is_err());
        }
        let mut b = fixture(true, false, false);
        b[0x1000 + 0x2e] ^= 1;
        assert!(final_fixture(&b).is_err());
        let b = fixture(true, false, false);
        let e = Elf::parse(&b).unwrap();
        assert!(final_body(&e, &b, ENTRY + 1, NAME, SYMBOL).is_err());
        assert!(final_body(&e, &b, u64::MAX - 100, NAME, SYMBOL).is_err());
    }
    #[test]
    fn env_aux_zero_writer_census_includes_none_unknown_and_crossings() {
        let b = fixture(true, false, false);
        let e = Elf::parse(&b).unwrap();
        let text = &e.section_headers[1];
        for (at, kind) in [
            (ENTRY, 0),
            (ENTRY, 2),
            (ENTRY - 1, 2),
            (ENTRY - 1, u32::MAX),
        ] {
            assert!(refuse_writer(text, at, kind, ENTRY, ENTRY + SIZE as u64).is_err());
        }
        refuse_writer(text, ENTRY - 8, 1, ENTRY, ENTRY + SIZE as u64).unwrap();
        // Valid typed row targeting the final code section reaches the actual
        // production no-writer refusal, including a nominal NONE record.
        for kind in [0_u64, 2] {
            let mut b = fixture(true, true, false);
            put64(&mut b, 0x2508, (1u64 << 32) | kind);
            assert_eq!(
                final_fixture(&b).unwrap_err(),
                "View::table has unexpected final relocation"
            );
        }
    }
    #[test]
    fn env_aux_range_and_carry_checks_cannot_be_removed() {
        // These retained opcode positions cover short-header checks, stride,
        // alignment, >=960, count-1<=511, BOTH carry/end halves and sum<=512.
        for at in [
            0xe, 0x1b, 0x28, 0x39, 0x4a, 0x57, 0x6b, 0x78, 0x7f, 0x86, 0x90, 0x9d, 0xa6, 0xb8,
            0xba, 0xc7, 0xcb, 0xd4, 0xe9,
        ] {
            let mut b = fixture(true, false, false);
            b[0x1000 + at] ^= 1;
            assert!(final_fixture(&b).is_err(), "guard byte {at:x}");
        }
        // This arithmetic is the finite proof implication, not execution of
        // fabricated runtime pointers: passing env proves aux-header readable.
        let minimum = u32::from_le_bytes(INPUT[0x53..0x57].try_into().unwrap());
        let count_minus_one_limit = u32::from_le_bytes(INPUT[0x67..0x6b].try_into().unwrap());
        let sum_limit = u32::from_le_bytes(INPUT[0xe5..0xe9].try_into().unwrap());
        assert!(minimum + 8 > 0x318);
        assert_eq!((count_minus_one_limit + 1) * 8, 4096);
        assert_eq!(count_minus_one_limit + 1, sum_limit);
    }
}
