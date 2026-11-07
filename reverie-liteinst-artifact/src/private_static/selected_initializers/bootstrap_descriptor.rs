//! Exact conditional Bootstrap::descriptor leaf and two real immutable tables.
//!
//! CALLER PREMISE, NOT AN EMITTED GUARD: RCX is in 0..=6 at actual entry.
//! This private compiler-specialized body indexes its two tables without checking
//! index<7. The 30 real project constant/call-edge joins remain UNPROVED. No
//! method here calls this function, accepts an index or authorizes entry.
//!
//! RDI must point to disjoint aligned live writable result storage >=40 bytes;
//! RSI/RDX are the real immutable readable nonwrapping backing pointer/length;
//! stack/return address and this compiler's actual ABI must be valid. Output
//! cannot alias backing/code/tables/return slot. Code/tables/backing must stay
//! immutable and live; actual signal/exception preservation is not proved here.
//!
//! Complete finite block proof, half-open entry-relative ranges:
//! 00..34: index<=6 bounds 24*i; compare last bytes 0x28f/0x297/0x29f+24*i
//! against length before all descriptor loads. Any failure goes8d.
//! 34..4c: exact PC32 table0 LEA (field37); load stride[i]; compare to actual
//! descriptor stride at0x298+24*i. Mismatch goes8d.
//! 4c..63: read offset0x288+24*i; require aligned8 and >=960; else8d.
//! 63..7c: exact PC32 table1 LEA(field66); read count0x290+24*i and compare
//! count-1 unsigned against max[i]. This refuses zero and count>max.
//! 7c..8d: multiply count*stride, add offset with carry refusal, require end<=len.
//! IMUL has NO overflow check; exact table bounds imply product<=4096, so no
//! multiplication overflow is possible under the stated index premise.
//! 8d..96: write Bounds2 at output+1 and Err tag1 at output+0; RET.
//! 96..ab: store offset/count/stride/end at output+8/16/24/32 and Ok tag0;
//! RET. Error padding/payload is unspecified. RAX is NOT a result pointer/tag
//! ABI here; only the actual output byte0 discriminator may select payload use.
//!
//! All normal edges are internal and finite. No CALL, loop, indirect transfer,
//! FS/GS/TLS, allocator, panic, syscall or UD2 exists. Valid index/caller memory,
//! table identity and exact bytes are essential premises, not hash-only safety.
//! This fact proves no project/iterator/caller/async/exception/pre-FS closure.
use super::view_site::final_aliases_bound;
use super::view_site::final_section;
use super::view_site::section_symbol;
use super::view_table::LeafObjects;
use super::view_table::bounded;
use super::*;

const SOURCE_SHA: &str = "85abd905256f3bc5b526840cf3cd5e090238e4aa770f03d320c2ae907ee7ae75";
const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_9Bootstrap10descriptor";
const SIZE: usize = 171;
const TABLE_SIZE: usize = 56;
const FIELDS: [usize; 2] = [0x37, 0x66];
const STRIDES: [u64; 7] = [32, 16, 32, 1, 8, 8, 1];
const MAXIMA: [u64; 7] = [64, 64, 128, 4096, 512, 512, 4096];
// Only the two typed PC32 fields are zero placeholders. Every other byte,
// including every branch, table load, error/store and return, is compared.
const INPUT: [u8; SIZE] = [
    0x48, 0x8d, 0x04, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x04, 0x40, 0x49, 0x81, 0xc0, 0x8f,
    0x02, 0x00, 0x00, 0x49, 0x39, 0xd0, 0x73, 0x75, 0x4c, 0x8d, 0x04, 0x40, 0x49, 0x8d, 0x80, 0x97,
    0x02, 0x00, 0x00, 0x48, 0x39, 0xd0, 0x73, 0x65, 0x49, 0x8d, 0x80, 0x9f, 0x02, 0x00, 0x00, 0x48,
    0x39, 0xd0, 0x73, 0x59, 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x04, 0xc8, 0x4d,
    0x8d, 0x88, 0x98, 0x02, 0x00, 0x00, 0x4a, 0x39, 0x04, 0x0e, 0x75, 0x41, 0x4e, 0x8b, 0x8c, 0x06,
    0x88, 0x02, 0x00, 0x00, 0x41, 0xf6, 0xc1, 0x07, 0x75, 0x33, 0x49, 0x81, 0xf9, 0xc0, 0x03, 0x00,
    0x00, 0x72, 0x2a, 0x4c, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x8b, 0xb4, 0x06, 0x90, 0x02,
    0x00, 0x00, 0x4c, 0x8d, 0x46, 0xff, 0x4d, 0x3b, 0x04, 0xca, 0x73, 0x11, 0x48, 0x89, 0xf1, 0x48,
    0x0f, 0xaf, 0xc8, 0x4c, 0x01, 0xc9, 0x72, 0x05, 0x48, 0x39, 0xd1, 0x76, 0x09, 0xc6, 0x47, 0x01,
    0x02, 0xb0, 0x01, 0x88, 0x07, 0xc3, 0x4c, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x77, 0x10, 0x48, 0x89,
    0x47, 0x18, 0x48, 0x89, 0x4f, 0x20, 0x31, 0xc0, 0x88, 0x07, 0xc3,
];
fn source_symbol(digest: &str) -> Result<&'static str> {
    require(
        digest == SOURCE_SHA,
        "Bootstrap::descriptor complete source differs",
    )?;
    Ok(SYMBOL)
}
fn named(name: &str, expected: &str) -> bool {
    !name.contains('.') && canonical_rust_symbol(name).as_deref() == Some(expected)
}
fn input_code(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "Bootstrap::descriptor complete input form differs",
    )
}
fn table_bytes(which: usize) -> [u8; TABLE_SIZE] {
    let values = if which == 0 { STRIDES } else { MAXIMA };
    let mut bytes = [0; TABLE_SIZE];
    for (i, value) in values.into_iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
fn exact_table(bytes: &[u8], which: usize) -> Result<()> {
    require(
        which < 2 && bytes == table_bytes(which),
        "Bootstrap::descriptor complete table differs",
    )
}
fn geometry(section: &section_header::SectionHeader, code: bool) -> Result<()> {
    require(
        section.sh_type == section_header::SHT_PROGBITS
            && section.sh_flags == if code { 6 } else { 2 }
            && section.sh_size == if code { SIZE as u64 } else { TABLE_SIZE as u64 }
            && section.sh_addralign == if code { 16 } else { 8 },
        "Bootstrap::descriptor exact input geometry differs",
    )
}
fn input_aliases(object: &ObjectInput<'_>, index: usize, name: Option<&str>) -> Result<()> {
    let mut sections = 0;
    let mut functions = 0;
    for s in object.elf.syms.iter().filter(|s| s.st_shndx == index) {
        if s.st_type() == sym::STT_SECTION {
            section_symbol(object, &s, index)?;
            sections += 1;
        } else {
            require(
                name.is_some()
                    && object.elf.strtab.get_at(s.st_name) == name
                    && s.st_bind() == sym::STB_LOCAL
                    && s.st_type() == sym::STT_FUNC
                    && s.st_other == 0
                    && s.st_value == 0
                    && s.st_size == SIZE as u64,
                "Bootstrap::descriptor unexpected input alias",
            )?;
            functions += 1;
        }
    }
    require(
        sections == 1 && functions == usize::from(name.is_some()),
        "Bootstrap::descriptor input symbol census differs",
    )
}
fn field_shape(fields: &[(usize, u32, i64)]) -> Result<()> {
    require(
        fields
            == [
                (FIELDS[0], reloc::R_X86_64_PC32, -4),
                (FIELDS[1], reloc::R_X86_64_PC32, -4),
            ],
        "Bootstrap::descriptor two exact PC32 fields differ",
    )
}
fn input_tables(object: &ObjectInput<'_>, symbol: &sym::Sym, name: &str) -> Result<[usize; 2]> {
    require(
        object.member_name.starts_with("reverie_loader-")
            && symbol.st_bind() == sym::STB_LOCAL
            && symbol.st_type() == sym::STT_FUNC
            && symbol.st_other == 0
            && symbol.st_value == 0
            && symbol.st_size == SIZE as u64,
        "Bootstrap::descriptor source member/function differs",
    )?;
    let code = symbol.st_shndx;
    let section = object
        .elf
        .section_headers
        .get(code)
        .ok_or("descriptor code section absent")?;
    geometry(section, true)?;
    require(
        object.elf.shdr_strtab.get_at(section.sh_name) == Some(format!(".text.{name}").as_str()),
        "Bootstrap::descriptor own input section differs",
    )?;
    input_aliases(object, code, Some(name))?;
    input_code(section_file_bytes(section, object.bytes)?)?;
    let tab = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, tab)?;
    let mut fields = Vec::new();
    for (index, rows) in &object.elf.shdr_relocs {
        let rs = checked_relocation_section(&object.elf, object.bytes, *index, tab, rows.len())?;
        if rs.sh_info as usize != code {
            continue;
        }
        for r in rows.iter() {
            checked_relocation_span(&object.elf, rs, r.r_offset, r.r_type)?;
            let target = object
                .elf
                .syms
                .get(r.r_sym)
                .ok_or("descriptor input field symbol absent")?;
            section_symbol(object, &target, target.st_shndx)?;
            fields.push((
                usize::try_from(r.r_offset).map_err(|_| "descriptor field offset")?,
                r.r_type,
                r.r_addend.ok_or("descriptor needs explicit addend")?,
                target.st_shndx,
            ));
        }
    }
    fields.sort_unstable();
    field_shape(&fields.iter().map(|x| (x.0, x.1, x.2)).collect::<Vec<_>>())?;
    let tables = [fields[0].3, fields[1].3];
    require(
        tables[0] != tables[1] && !tables.contains(&code),
        "descriptor table identities alias",
    )?;
    for (i, index) in tables.into_iter().enumerate() {
        let section = object
            .elf
            .section_headers
            .get(index)
            .ok_or("descriptor input table absent")?;
        geometry(section, false)?;
        let expected = if i == 0 {
            format!(".rodata..Lswitch.table.{name}.3")
        } else {
            format!(".rodata..Lswitch.table.{name}")
        };
        require(
            object.elf.shdr_strtab.get_at(section.sh_name) == Some(expected.as_str()),
            "descriptor exact own table name differs",
        )?;
        input_aliases(object, index, None)?;
        exact_table(section_file_bytes(section, object.bytes)?, i)?;
        for (ri, rows) in &object.elf.shdr_relocs {
            let rs = checked_relocation_section(&object.elf, object.bytes, *ri, tab, rows.len())?;
            require(
                rs.sh_info as usize != index || rows.is_empty(),
                "descriptor input table has relocation",
            )?;
        }
    }
    Ok(tables)
}
fn final_fields(
    elf: &Elf<'_>,
    bytes: &[u8],
    entry: u64,
    code_section: usize,
    tables: [u64; 2],
    sections: [usize; 2],
) -> Result<Vec<FinalRelocation>> {
    let tab = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, tab)?;
    let end = entry
        .checked_add(SIZE as u64)
        .ok_or("descriptor final extent overflow")?;
    let mut found = Vec::new();
    for (ri, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *ri, tab, rows.len())?;
        for r in rows.iter() {
            let width = checked_relocation_span(elf, rs, r.r_offset, r.r_type)?;
            let target = &elf.section_headers[rs.sh_info as usize];
            // Tables have ZERO fields, including no-op, unknown and crossing rows.
            for table in tables {
                super::view_table::refuse_writer(
                    target,
                    r.r_offset,
                    r.r_type,
                    table,
                    table
                        .checked_add(TABLE_SIZE as u64)
                        .ok_or("descriptor table overflow")?,
                )?;
            }
            if !(entry <= r.r_offset && r.r_offset < end)
                && !selected_field_overlap(target, r.r_offset, r.r_type, entry, end)?
            {
                continue;
            }
            let which = FIELDS
                .iter()
                .position(|off| entry.checked_add(*off as u64) == Some(r.r_offset))
                .ok_or("descriptor unexpected/crossing final writer")?;
            require(
                rs.sh_info as usize == code_section
                    && width == Some(4)
                    && r.r_type == reloc::R_X86_64_PC32,
                "descriptor final typed field differs",
            )?;
            let s = elf
                .syms
                .get(r.r_sym)
                .ok_or("descriptor final target absent")?;
            require(
                s.st_type() == sym::STT_SECTION
                    && s.st_bind() == sym::STB_LOCAL
                    && s.st_other == 0
                    && s.st_size == 0
                    && s.st_shndx == sections[which]
                    && s.st_value == elf.section_headers[sections[which]].sh_addr
                    && elf.strtab.get_at(s.st_name) == Some(""),
                "descriptor final target is not exact rebased table section",
            )?;
            let addend = r
                .r_addend
                .ok_or("descriptor final field needs explicit addend")?;
            require(
                i128::from(s.st_value) + i128::from(addend) == i128::from(tables[which]) - 4,
                "descriptor final field selects wrong table bytes",
            )?;
            found.push(FinalRelocation {
                offset: FIELDS[which],
                kind: r.r_type,
                addend,
                symbol_value: s.st_value,
            });
        }
    }
    found.sort_by_key(|r| r.offset);
    require(
        found.len() == 2 && found[0].offset == FIELDS[0] && found[1].offset == FIELDS[1],
        "descriptor final fields missing/duplicate",
    )?;
    Ok(found)
}
fn linked_code(bytes: &[u8], entry: u64, tables: [u64; 2]) -> Result<()> {
    let mut expected = INPUT;
    for (offset, table) in FIELDS.into_iter().zip(tables) {
        expected[offset..offset + 4].copy_from_slice(&checked_pc32(
            table,
            -4,
            entry
                .checked_add(offset as u64)
                .ok_or("descriptor PC32 place overflow")?,
        )?);
    }
    require(bytes == expected, "descriptor complete linked form differs")
}

/// Private source-owned conditional descriptor fact, not a call/entry permit.
/// No constructor, Deserialize, Clone or conversion to Ready is provided.
#[derive(Debug, Serialize)]
pub struct BootstrapDescriptorLeafObservation {
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
    input_code_section: usize,
    input_table_sections: [usize; 2],
    entry: u64,
    tables: [u64; 2],
    code_sha256: String,
    table_sha256: [String; 2],
    scope: &'static str,
}
impl BootstrapDescriptorLeafObservation {
    /// Actual observed function start; this is not permission to call it.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Required caller premise, NOT a machine-enforced index guard. Every real
    /// caller constant and edge must be joined separately before composition.
    pub fn required_caller_indices(&self) -> std::ops::Range<usize> {
        0..7
    }
    fn require_owner(&self, source: &VerifiedStaticSource, archive: &StaticArchive) -> Result<()> {
        require(
            Arc::ptr_eq(&self.owner.0, &source.archive_owner)
                && self.runtime_archive == archive.file,
            "Bootstrap::descriptor belongs to another source/archive",
        )
    }
}
/// Actual compiled checker identity for the fixed source catalog.
pub fn bootstrap_descriptor_implementation_sha256() -> String {
    sha256(include_bytes!("bootstrap_descriptor.rs"))
}
impl VerifiedStaticSource {
    /// Observe the exact descriptor171/two-table form in the same actual source,
    /// archive and selected-definition transaction. All Result/callback errors
    /// close actual source/build-output/archive/ELF/map identities. The actual
    /// caller MUST establish index0..6 and every documented memory/ABI premise;
    /// no project, async, panic/unwind or startup qualification follows.
    pub fn with_bootstrap_descriptor_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        callback: impl FnOnce(&BootstrapDescriptorLeafObservation, &mut Runner) -> Result<T>,
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
) -> Result<BootstrapDescriptorLeafObservation> {
    let mut selected = Vec::new();
    for (i, object) in leaves.objects.iter().enumerate() {
        for s in object.elf.syms.iter().filter(|s| s.st_shndx != 0) {
            let name = object
                .elf
                .strtab
                .get_at(s.st_name)
                .ok_or("descriptor object name absent")?;
            if named(name, leaves.expected_symbol) {
                selected.push((i, s));
            }
        }
    }
    require(
        selected.len() == 1,
        "descriptor definition absent/ambiguous across archive",
    )?;
    let (i, symbol) = selected[0];
    let object = &leaves.objects[i];
    let name = object
        .elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or("descriptor name absent")?;
    let input_tables = input_tables(object, &symbol, name)?;
    let map_bytes = bounded(link_map)?;
    let map = std::str::from_utf8(&map_bytes).map_err(|e| e.to_string())?;
    let entry = mapped_section(map, object, symbol.st_shndx)?;
    let tables = [
        mapped_section(map, object, input_tables[0])?,
        mapped_section(map, object, input_tables[1])?,
    ];
    require(
        tables[0]
            .checked_add(TABLE_SIZE as u64)
            .is_some_and(|end| end <= tables[1])
            || tables[1]
                .checked_add(TABLE_SIZE as u64)
                .is_some_and(|end| end <= tables[0]),
        "descriptor final tables overlap",
    )?;
    let bytes = bounded(artifact)?;
    let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
    static_image_metadata(&elf, &bytes)?;
    let matches = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx != 0
                && elf
                    .strtab
                    .get_at(s.st_name)
                    .is_some_and(|n| named(n, leaves.expected_symbol))
        })
        .collect::<Vec<_>>();
    require(
        matches.len() == 1
            && elf.strtab.get_at(matches[0].st_name) == Some(name)
            && matches[0].st_value == entry
            && matches[0].st_size == SIZE as u64,
        "descriptor final definition differs from source/map",
    )?;
    let code_section = final_section(&elf, &bytes, entry, SIZE, 5)?;
    final_aliases_bound(&elf, entry, SIZE, code_section, Some(name), sym::STB_LOCAL)?;
    let mut table_sections = [0; 2];
    let mut hashes = [String::new(), String::new()];
    for (i, table) in tables.into_iter().enumerate() {
        table_sections[i] = final_section(&elf, &bytes, table, TABLE_SIZE, 4)?;
        final_aliases_bound(
            &elf,
            table,
            TABLE_SIZE,
            table_sections[i],
            None,
            sym::STB_LOCAL,
        )?;
        let data = mapped_bytes(&elf, &bytes, table, TABLE_SIZE as u64, 4)?;
        exact_table(data, i)?;
        hashes[i] = sha256(data);
    }
    let body = mapped_bytes(&elf, &bytes, entry, SIZE as u64, 5)?;
    linked_code(body, entry, tables)?;
    let actual_fields = final_fields(&elf, &bytes, entry, code_section, tables, table_sections)?;
    let input_fields = FIELDS
        .into_iter()
        .zip(tables)
        .map(|(offset, target)| InputRelocation {
            offset,
            kind: reloc::R_X86_64_PC32,
            addend: -4,
            target: SelectedTarget {
                mapped_input_value: target,
            },
        })
        .collect::<Vec<_>>();
    join_relocated_body(
        &elf,
        &bytes,
        entry,
        section_file_bytes(&object.elf.section_headers[symbol.st_shndx], object.bytes)?,
        body,
        &input_fields,
        &actual_fields,
    )?;
    Ok(BootstrapDescriptorLeafObservation {
        owner: DefinitionSourceOwner(source.archive_owner.clone()),
        runtime_archive: archive.file.clone(),
        artifact: artifact.clone(),
        link_map: link_map.clone(),
        source: leaves.source.clone(),
        member_name: object.member_name.to_owned(),
        member_ordinal: object.ordinal,
        member_header: object.header_offset,
        member_sha256: sha256(object.bytes),
        input_code_section: symbol.st_shndx,
        input_table_sections: input_tables,
        entry,
        tables,
        code_sha256: sha256(body),
        table_sha256: hashes,
        scope: "CONDITIONAL_DESCRIPTOR_INDEX_0_TO_6_ONLY_CALLER_PREMISES_NOT_PROVEN",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const NAME: &str = "_RNvMs1_NtCsunit_14reverie_loader7handoffNtB5_9Bootstrap10descriptor";
    const ENTRY: u64 = 0x100000;
    const TABLES: [u64; 2] = [0x102000, 0x102038];
    fn put16(b: &mut [u8], at: usize, value: u16) {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, value: u64) {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(linked: bool) -> Vec<u8> {
        // Reuse the existing small parsed-ELF constructor, not a compiled object.
        // Add exactly two own tables and two real typed fields for this form.
        let mut b =
            super::super::view_table::tests::plain_fixture(linked, false, false, NAME, &INPUT);
        put16(&mut b, 60, 8);
        let text = format!(".text.{NAME}");
        let t0 = format!(".rodata..Lswitch.table.{NAME}.3");
        let t1 = format!(".rodata..Lswitch.table.{NAME}");
        let names = format!("\0{text}\0.symtab\0.strtab\0.shstrtab\0{t0}\0{t1}\0.rela.text\0");
        b[0x2400..0x2400 + names.len()].copy_from_slice(names.as_bytes());
        for (i, name) in [
            (1, text.as_str()),
            (2, ".symtab"),
            (3, ".strtab"),
            (4, ".shstrtab"),
            (5, t0.as_str()),
            (6, t1.as_str()),
            (7, ".rela.text"),
        ] {
            put32(
                &mut b,
                0x2800 + i * 64,
                names.find(&format!("{name}\0")).unwrap() as u32,
            );
        }
        put64(&mut b, 0x2800 + 4 * 64 + 32, names.len() as u64);
        put64(&mut b, 0x2800 + 2 * 64 + 32, 120);
        put32(&mut b, 0x2800 + 2 * 64 + 44, 5); // all five input/final symbols LOCAL
        b[0x2234] = 2; // exact local FUNC, not global
        for i in 0..2 {
            let index = 5 + i;
            let sh = 0x2800 + index * 64;
            put32(&mut b, sh + 4, 1);
            put64(&mut b, sh + 8, 2);
            put64(&mut b, sh + 16, if linked { TABLES[i] } else { 0 });
            let offset = if linked {
                0x2000 + i * 56
            } else {
                0x1800 + i * 56
            };
            put64(&mut b, sh + 24, offset as u64);
            put64(&mut b, sh + 32, 56);
            put64(&mut b, sh + 48, 8);
            b[offset..offset + 56].copy_from_slice(&table_bytes(i));
            let sym = 0x2200 + (3 + i) * 24;
            b[sym + 4] = 3;
            put16(&mut b, sym + 6, index as u16);
            put64(&mut b, sym + 8, if linked { TABLES[i] } else { 0 });
            let rr = 0x2600 + i * 24;
            put64(
                &mut b,
                rr,
                if linked {
                    ENTRY + FIELDS[i] as u64
                } else {
                    FIELDS[i] as u64
                },
            );
            put64(&mut b, rr + 8, ((3 + i) as u64) << 32 | 2);
            put64(&mut b, rr + 16, (-4i64) as u64);
        }
        let rs = 0x2800 + 7 * 64;
        put32(&mut b, rs + 4, 4);
        put64(&mut b, rs + 24, 0x2600);
        put64(&mut b, rs + 32, 48);
        put32(&mut b, rs + 40, 2);
        put32(&mut b, rs + 44, 1);
        put64(&mut b, rs + 48, 8);
        put64(&mut b, rs + 56, 24);
        if linked {
            put16(&mut b, 56, 2);
            put32(&mut b, 120, 1);
            put32(&mut b, 124, 4);
            put64(&mut b, 128, 0x2000);
            put64(&mut b, 136, TABLES[0]);
            put64(&mut b, 144, TABLES[0]);
            put64(&mut b, 152, 112);
            put64(&mut b, 160, 112);
            put64(&mut b, 168, 4096);
            for (offset, table) in FIELDS.into_iter().zip(TABLES) {
                b[0x1000 + offset..0x1000 + offset + 4]
                    .copy_from_slice(&checked_pc32(table, -4, ENTRY + offset as u64).unwrap());
            }
        }
        b
    }
    fn input_fixture(bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
        let symbol = elf.syms.get(2).ok_or("descriptor unit symbol")?;
        let object = ObjectInput {
            archive_path: Path::new("/unit/not-authority.a"),
            member_name: "reverie_loader-unit.o",
            ordinal: 0,
            header_offset: 8,
            bytes,
            elf,
        };
        require(
            input_tables(&object, &symbol, NAME)? == [5, 6],
            "unit tables differ",
        )
    }
    fn final_fixture(bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
        static_image_metadata(&elf, bytes)?;
        let code = final_section(&elf, bytes, ENTRY, SIZE, 5)?;
        final_aliases_bound(&elf, ENTRY, SIZE, code, Some(NAME), sym::STB_LOCAL)?;
        for (i, table) in TABLES.into_iter().enumerate() {
            let section = final_section(&elf, bytes, table, TABLE_SIZE, 4)?;
            final_aliases_bound(&elf, table, TABLE_SIZE, section, None, sym::STB_LOCAL)?;
            exact_table(mapped_bytes(&elf, bytes, table, TABLE_SIZE as u64, 4)?, i)?;
        }
        let fields = final_fields(&elf, bytes, ENTRY, code, TABLES, [5, 6])?;
        linked_code(
            mapped_bytes(&elf, bytes, ENTRY, SIZE as u64, 5)?,
            ENTRY,
            TABLES,
        )?;
        require(fields.len() == 2, "unit field count differs")
    }
    #[test]
    fn descriptor_exact_source_and_role_do_not_admit_unknowns() {
        assert_eq!(source_symbol(SOURCE_SHA).unwrap(), SYMBOL);
        assert!(named(NAME, SYMBOL));
        for digest in [
            "0".repeat(64),
            SOURCE_SHA[..63].to_owned(),
            format!("{SOURCE_SHA}0"),
            SOURCE_SHA.to_ascii_uppercase(),
        ] {
            assert!(source_symbol(&digest).is_err());
        }
        for name in [
            NAME.replace("Ms1_", "Ms2_"),
            NAME.replace("10descriptor", "4role"),
            format!("{NAME}.llvm.0"),
        ] {
            assert!(!named(&name, SYMBOL));
        }
    }
    #[test]
    fn descriptor_complete_input_and_each_linked_instruction_byte_are_exact() {
        input_code(&INPUT).unwrap();
        assert!(input_code(&INPUT[..170]).is_err());
        for at in 0..SIZE {
            let mut changed = INPUT;
            changed[at] ^= 1;
            assert!(input_code(&changed).is_err(), "input byte {at}");
        }
        let bytes = fixture(true);
        let code = &bytes[0x1000..0x1000 + SIZE];
        linked_code(code, ENTRY, TABLES).unwrap();
        for at in 0..SIZE {
            let mut changed = code.to_vec();
            changed[at] ^= 1;
            assert!(
                linked_code(&changed, ENTRY, TABLES).is_err(),
                "linked byte {at}"
            );
        }
        assert!(linked_code(code, ENTRY, [TABLES[1], TABLES[0]]).is_err());
    }
    #[test]
    fn descriptor_all_table_values_and_finite_product_implication_are_required() {
        for which in 0..2 {
            let bytes = table_bytes(which);
            exact_table(&bytes, which).unwrap();
            assert!(exact_table(&bytes[..55], which).is_err());
            for at in 0..56 {
                let mut changed = bytes;
                changed[at] ^= 1;
                assert!(exact_table(&changed, which).is_err());
            }
        }
        assert!(
            STRIDES
                .into_iter()
                .zip(MAXIMA)
                .all(|(stride, max)| stride > 0 && max > 0 && stride * max <= 4096)
        );
        assert!(exact_table(&table_bytes(1), 0).is_err());
    }
    #[test]
    fn descriptor_two_fields_refuse_missing_extra_duplicate_wrong_kind_and_addend() {
        let fields = [
            (0x37, reloc::R_X86_64_PC32, -4),
            (0x66, reloc::R_X86_64_PC32, -4),
        ];
        field_shape(&fields).unwrap();
        assert!(field_shape(&fields[..1]).is_err());
        assert!(field_shape(&[fields[0], fields[0]]).is_err());
        assert!(field_shape(&[fields[0], fields[1], fields[1]]).is_err());
        assert!(field_shape(&[(0x37, reloc::R_X86_64_PLT32, -4), fields[1]]).is_err());
        assert!(field_shape(&[(0x37, reloc::R_X86_64_PC32, 0), fields[1]]).is_err());
    }
    #[test]
    fn descriptor_parsed_input_requires_local_full_body_and_exact_two_own_tables() {
        input_fixture(&fixture(false)).unwrap();
        let mut b = fixture(false);
        // The second name is a prefix of the first, but must select its own
        // NUL-terminated string rather than the first table's ".3" suffix.
        let first_name =
            u32::from_le_bytes(b[0x2800 + 5 * 64..0x2800 + 5 * 64 + 4].try_into().unwrap());
        put32(&mut b, 0x2800 + 6 * 64, first_name);
        assert_eq!(
            input_fixture(&b).unwrap_err(),
            "descriptor exact own table name differs"
        );
        let mut b = fixture(false);
        b[0x2234] = 0x12;
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false);
        b[0x1800] ^= 1;
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false);
        put64(&mut b, 0x2800 + 5 * 64 + 8, 3);
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false);
        put64(&mut b, 0x2800 + 6 * 64 + 32, 48);
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false);
        put64(&mut b, 0x2600 + 24 + 8, (3u64 << 32) | 2);
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false);
        put64(&mut b, 0x2600 + 16, 0);
        assert!(input_fixture(&b).is_err());
    }
    #[test]
    fn descriptor_parsed_final_requires_ro_tables_pc32_and_exact_local_aliases() {
        final_fixture(&fixture(true)).unwrap();
        let mut b = fixture(true);
        b[0x2234] = 0x12;
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        put32(&mut b, 124, 6);
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        b[0x2038] ^= 1;
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        put64(&mut b, 0x2600, ENTRY + 0x36);
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        put64(&mut b, 0x2600 + 8, 3u64 << 32);
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        put64(&mut b, 0x2600 + 16, (-3i64) as u64);
        assert!(final_fixture(&b).is_err());
        let mut b = fixture(true);
        put64(&mut b, 0x2600, TABLES[0]);
        assert!(final_fixture(&b).is_err());
        // Global-only generic alias predicate still refuses this valid LOCAL role.
        let b = fixture(true);
        let e = Elf::parse(&b).unwrap();
        assert!(super::super::view_site::final_aliases(&e, ENTRY, SIZE, 1, Some(NAME)).is_err());
    }
    #[test]
    fn descriptor_validly_targeted_ro_table_writer_reaches_named_refusal() {
        let mut b = fixture(true);
        // Keep BOTH valid .rela.text rows. Add a separate, structurally valid
        // .rela.table whose sh_info names the actual RO table section5.
        put16(&mut b, 60, 9);
        let strings = 0x2800 + 4 * 64;
        let old_len =
            u64::from_le_bytes(b[strings + 32..strings + 40].try_into().unwrap()) as usize;
        let name = b".rela.table\0";
        b[0x2400 + old_len..0x2400 + old_len + name.len()].copy_from_slice(name);
        put64(&mut b, strings + 32, (old_len + name.len()) as u64);
        let rs = 0x2800 + 8 * 64;
        put32(&mut b, rs, old_len as u32);
        put32(&mut b, rs + 4, 4);
        put64(&mut b, rs + 24, 0x2680);
        put64(&mut b, rs + 32, 24);
        put32(&mut b, rs + 40, 2);
        put32(&mut b, rs + 44, 5);
        put64(&mut b, rs + 48, 8);
        put64(&mut b, rs + 56, 24);
        put64(&mut b, 0x2680, TABLES[0]);
        put64(&mut b, 0x2688, (3u64 << 32) | reloc::R_X86_64_PC32 as u64);
        put64(&mut b, 0x2690, (-4i64) as u64);
        let elf = Elf::parse(&b).unwrap();
        let table = checked_symtab(&elf, &b).unwrap();
        checked_relocation_inventory(&elf, &b, table).unwrap();
        let (_, rows) = elf
            .shdr_relocs
            .iter()
            .find(|(index, _)| *index == 8)
            .unwrap();
        assert_eq!(rows.len(), 1);
        let section = checked_relocation_section(&elf, &b, 8, table, rows.len()).unwrap();
        assert_eq!(section.sh_info, 5);
        let row = rows.iter().next().unwrap();
        assert_eq!(
            checked_relocation_span(&elf, section, row.r_offset, row.r_type).unwrap(),
            Some(4)
        );
        assert_eq!(
            final_fixture(&b).unwrap_err(),
            "View::table has unexpected final relocation"
        );
    }
}
