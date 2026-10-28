//! Finite whole-section native identities, never syscall/entry authorization.
use super::*;

#[derive(Clone, Copy)]
enum Leaf {
    Memset,
    SetThreadArea,
}
impl Leaf {
    fn name(self) -> &'static str {
        match self {
            Self::Memset => "memset",
            Self::SetThreadArea => "__set_thread_area",
        }
    }
    fn member(self) -> &'static str {
        match self {
            Self::Memset => "memset.lo",
            Self::SetThreadArea => "__set_thread_area.lo",
        }
    }
    fn physical(self) -> (usize, u64, &'static str) {
        match self {
            Self::Memset => (
                1077,
                5277274,
                "12189918210a08f6da20af346a76f44296d8ed07477b9670b10335b28416a8d4",
            ),
            Self::SetThreadArea => (
                1223,
                5904434,
                "0f842b24b5425118e12f36fd97e7fd7e91b97728e49a7b52c26a84192754416c",
            ),
        }
    }
    fn source_sha256(self) -> &'static str {
        match self {
            Self::Memset => "aa843bcfb5b75e232df8d26dab6e5cec4f7123b33bebe655ce957f95f839f2e1",
            Self::SetThreadArea => {
                "9a6299228be5f8f467652263e8f98c1f9ab2e0937243589b8c5642f0ebe3236d"
            }
        }
    }
    fn visibility(self) -> u8 {
        match self {
            Self::Memset => 0,
            Self::SetThreadArea => 2,
        }
    }
    fn final_binding(self) -> u8 {
        match self {
            Self::Memset => sym::STB_GLOBAL,
            Self::SetThreadArea => sym::STB_LOCAL,
        }
    }
    fn code(self) -> &'static [u8] {
        match self {
            Self::Memset => &[
                0x48, 0x0f, 0xb6, 0xc6, 0x49, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x49, 0x0f, 0xaf, 0xc0, 0x48, 0x83, 0xfa, 0x7e, 0x77, 0x78, 0x85, 0xd2, 0x74, 0x70,
                0x40, 0x88, 0x37, 0x40, 0x88, 0x74, 0x17, 0xff, 0x83, 0xfa, 0x02, 0x76, 0x63, 0x66,
                0x89, 0x47, 0x01, 0x66, 0x89, 0x44, 0x17, 0xfd, 0x83, 0xfa, 0x06, 0x76, 0x55, 0x89,
                0x47, 0x03, 0x89, 0x44, 0x17, 0xf9, 0x83, 0xfa, 0x0e, 0x76, 0x49, 0x48, 0x89, 0x47,
                0x07, 0x48, 0x89, 0x44, 0x17, 0xf1, 0x83, 0xfa, 0x1e, 0x76, 0x3b, 0x48, 0x89, 0x47,
                0x0f, 0x48, 0x89, 0x47, 0x17, 0x48, 0x89, 0x44, 0x17, 0xe1, 0x48, 0x89, 0x44, 0x17,
                0xe9, 0x83, 0xfa, 0x3e, 0x76, 0x24, 0x48, 0x89, 0x47, 0x1f, 0x48, 0x89, 0x47, 0x27,
                0x48, 0x89, 0x47, 0x2f, 0x48, 0x89, 0x47, 0x37, 0x48, 0x89, 0x44, 0x17, 0xc1, 0x48,
                0x89, 0x44, 0x17, 0xc9, 0x48, 0x89, 0x44, 0x17, 0xd1, 0x48, 0x89, 0x44, 0x17, 0xd9,
                0x48, 0x89, 0xf8, 0xc3, 0xf7, 0xc7, 0x0f, 0x00, 0x00, 0x00, 0x49, 0x89, 0xf8, 0x48,
                0x89, 0x44, 0x17, 0xf8, 0x48, 0x89, 0xd1, 0x75, 0x0b, 0x48, 0xc1, 0xe9, 0x03, 0xf3,
                0x48, 0xab, 0x4c, 0x89, 0xc0, 0xc3, 0x31, 0xd2, 0x29, 0xfa, 0x83, 0xe2, 0x0f, 0x48,
                0x89, 0x07, 0x48, 0x89, 0x47, 0x08, 0x48, 0x29, 0xd1, 0x48, 0x01, 0xd7, 0xeb, 0xdf,
            ],
            Self::SetThreadArea => &[
                0x48, 0x89, 0xfe, 0xbf, 0x02, 0x10, 0x00, 0x00, 0xb8, 0x9e, 0x00, 0x00, 0x00, 0x0f,
                0x05, 0xc3,
            ],
        }
    }
}

/// Fallible file inputs, never supplied provider identities or success records.
/// The existing bundle binds the exact libc/release/recipe; both assembly files
/// must additionally match the exact source text from that bound release.
pub struct NativeLeafInputs<'a> {
    /// Existing exact native memcpy and 47-file source guard inputs.
    pub memcpy: super::super::super::private_machine_diagnostic::NativeMemcpyInputs<'a>,
    /// Exact release src/string/x86_64/memset.s text, hash checked below.
    pub memset_source: &'a Path,
    /// Exact release src/thread/x86_64/__set_thread_area.s text.
    pub set_thread_area_source: &'a Path,
}

/// Bind the additive implementation separately from the preserved initializer
/// module digest; callers must retain this source in their compiled catalog.
pub fn native_leaf_implementation_sha256() -> String {
    sha256(include_bytes!("native_leaves.rs"))
}

/// Derived complete-section observations within an actual source transaction.
/// Private construction; no Deserialize, Ready, syscall permission or image type.
#[derive(Debug, Serialize)]
pub struct NativeLeafObservations {
    runtime_archive: FileIdentity,
    artifact: FileIdentity,
    link_map: FileIdentity,
    source_files: Vec<FileIdentity>,
    memset: LeafObservation,
    set_thread_area: LeafObservation,
    scope: &'static str,
}
#[derive(Debug, Serialize)]
struct LeafObservation {
    symbol: &'static str,
    archive: FileIdentity,
    member_ordinal: usize,
    member_header: u64,
    member_sha256: String,
    input_section: usize,
    complete_section_bytes: usize,
    code_sha256: String,
    final_entry: u64,
    final_binding: u8,
    final_visibility: u8,
    // Preserve actual zero-sized symbol; extent is independent section proof.
    actual_symbol_size: u64,
}
impl NativeLeafObservations {
    /// Actual source/member/map/RX joined entries; not call authorization.
    pub fn addresses(&self) -> (u64, u64) {
        (self.memset.final_entry, self.set_thread_area.final_entry)
    }
    /// Post-SYSCALL instruction address derived from the exact 16-byte body.
    /// This fact does not authorize arch_prctl or authenticate a relay site.
    pub fn set_thread_area_post_syscall(&self) -> u64 {
        // Construction checked the complete 16-byte nonwrapping extent.
        self.set_thread_area.final_entry + 15
    }
}

fn source_digest(role: Leaf, digest: &str) -> Result<()> {
    require(
        digest == role.source_sha256(),
        "native leaf exact release assembly source differs",
    )
}

fn member_identity(role: Leaf, object: &ObjectInput<'_>) -> Result<()> {
    let (ordinal, header, hash) = role.physical();
    require(
        object.member_name == role.member()
            && object.ordinal == ordinal
            && object.header_offset == header
            && sha256(object.bytes) == hash,
        "native leaf physical member/source identity differs",
    )
}

fn input_section(role: Leaf, elf: &Elf<'_>, bytes: &[u8]) -> Result<usize> {
    require(
        elf.header.e_type == header::ET_REL
            && elf.header.e_machine == header::EM_X86_64
            && elf.is_64
            && elf.little_endian,
        "native leaf needs x86-64 LE ET_REL",
    )?;
    let table = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, table)?;
    let sections = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, s)| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .collect::<Vec<_>>();
    require(sections.len() == 1, "native leaf .text absent/duplicate")?;
    let (index, s) = sections[0];
    require(
        s.sh_type == section_header::SHT_PROGBITS
            && s.sh_flags == 6
            && s.sh_addr == 0
            && s.sh_addralign == 1
            && s.sh_size == role.code().len() as u64,
        "native leaf complete section geometry differs",
    )?;
    require(
        section_file_bytes(s, bytes)? == role.code(),
        "native leaf complete code differs",
    )?;
    let aliases = elf
        .syms
        .iter()
        .filter(|s| s.st_shndx == index && s.st_type() != sym::STT_SECTION)
        .collect::<Vec<_>>();
    require(aliases.len() == 1, "native leaf has unknown input alias")?;
    let a = aliases[0];
    require(
        elf.strtab.get_at(a.st_name) == Some(role.name())
            && a.st_bind() == sym::STB_GLOBAL
            && a.st_type() == sym::STT_FUNC
            && a.st_visibility() == role.visibility()
            && a.st_value == 0
            && a.st_size == 0,
        "native leaf actual input alias differs",
    )?;
    // All relocation sections have already been audited, including undeclared
    // decoded records. These two actual code sections have no relocations.
    require(
        elf.section_headers.iter().all(|r| {
            !matches!(
                r.sh_type,
                section_header::SHT_REL | section_header::SHT_RELA
            ) || r.sh_info as usize != index
                || r.sh_size == 0
        }),
        "native leaf code relocation is not supported",
    )?;
    Ok(index)
}

fn join(
    role: Leaf,
    object: &ObjectInput<'_>,
    map: &str,
    artifact: &Elf<'_>,
    bytes: &[u8],
    archive: &FileIdentity,
) -> Result<LeafObservation> {
    member_identity(role, object)?;
    let section = input_section(role, &object.elf, object.bytes)?;
    let entry = mapped_section(map, object, section)?;
    let end = entry
        .checked_add(role.code().len() as u64)
        .ok_or("native leaf extent overflow")?;
    let table = checked_symtab(artifact, bytes)?;
    checked_relocation_inventory(artifact, bytes, table)?;
    static_image_metadata(artifact, bytes)?;
    let named = artifact
        .syms
        .iter()
        .filter(|s| artifact.strtab.get_at(s.st_name) == Some(role.name()) && s.st_shndx != 0)
        .collect::<Vec<_>>();
    require(
        named.len() == 1,
        "native leaf final definition absent/duplicate",
    )?;
    let a = named[0];
    require(
        a.st_value == entry
            && a.st_size == 0
            && a.st_type() == sym::STT_FUNC
            && a.st_bind() == role.final_binding()
            && a.st_visibility() == role.visibility(),
        "native leaf final actual symbol differs",
    )?;
    let final_section = artifact
        .section_headers
        .get(a.st_shndx)
        .ok_or("native leaf final section absent")?;
    require(
        final_section.sh_type == section_header::SHT_PROGBITS
            && final_section.sh_flags == 6
            && final_section.sh_addr <= entry
            && final_section
                .sh_addr
                .checked_add(final_section.sh_size)
                .is_some_and(|n| end <= n),
        "native leaf final section extent differs",
    )?;
    let (load, offset) = unique_file_mapping(artifact, bytes, entry, role.code().len())?;
    require(
        load.p_flags == 5
            && final_section
                .sh_offset
                .checked_add(entry - final_section.sh_addr)
                == Some(offset as u64),
        "native leaf section/PT_LOAD identity differs",
    )?;
    // No generic alias change: all same-address non-SECTION records must be the
    // actual sole role symbol. Reject interior symbols and foreign-section aliases.
    require(
        artifact.syms.iter().all(|s| {
            s.st_shndx == 0
                || (s.st_type() == sym::STT_SECTION
                    && s.st_shndx == a.st_shndx
                    && s.st_value == final_section.sh_addr)
                || s.st_value < entry
                || s.st_value >= end
                || (s.st_name == a.st_name && s.st_shndx == a.st_shndx && s.st_value == entry)
        }),
        "native leaf final alias/interior symbol is unaccounted",
    )?;
    for (index, rows) in &artifact.shdr_relocs {
        let target = &artifact.section_headers[artifact.section_headers[*index].sh_info as usize];
        for r in rows.iter() {
            require(
                !selected_field_overlap(target, r.r_offset, r.r_type, entry, end)?,
                "native leaf final body has relocation/writer",
            )?;
        }
    }
    let linked = bytes
        .get(offset..offset + role.code().len())
        .ok_or("native leaf final bytes absent")?;
    // Existing body machinery also enforces exact no-relocation RX byte equality.
    let _ = join_relocated_body(artifact, bytes, entry, role.code(), linked, &[], &[])?;
    Ok(LeafObservation {
        symbol: role.name(),
        archive: archive.clone(),
        member_ordinal: object.ordinal,
        member_header: object.header_offset,
        member_sha256: sha256(object.bytes),
        input_section: section,
        complete_section_bytes: role.code().len(),
        code_sha256: sha256(linked),
        final_entry: entry,
        final_binding: a.st_bind(),
        final_visibility: a.st_visibility(),
        actual_symbol_size: a.st_size,
    })
}

impl VerifiedStaticSource {
    /// Observe the two exact private-musl whole-section leaves inside this
    /// archive's actual source owner. Native recipe/source/member and all source,
    /// archive, ELF/map identities close even when inspection or the callback
    /// refuses. The callback receives observations only, never execution authority.
    ///
    /// `native` includes the existing pinned memcpy/source-inventory bundle; it
    /// cannot supply addresses, aliases, native definitions or success records.
    pub fn with_native_leaf_definitions<T>(
        &self,
        archive: &StaticArchive,
        native: &NativeLeafInputs<'_>,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        body: impl FnOnce(&NativeLeafObservations) -> Result<T>,
    ) -> Result<T> {
        let mut source_files = Vec::new();
        let result = (|| {
            self.require_archive_owner(archive)?;
            archive.verify()?;
            artifact.verify()?;
            link_map.verify()?;
            for (role, path) in [
                (Leaf::Memset, native.memset_source),
                (Leaf::SetThreadArea, native.set_thread_area_source),
            ] {
                require(
                    fs::metadata(path).map_err(|e| e.to_string())?.len() <= 8192,
                    "native leaf source exceeds bound",
                )?;
                let source = FileIdentity::read(path)?;
                source_files.push(source.clone());
                source_digest(role, &source.sha256)?;
            }
            require(
                native.memcpy.link_map == link_map.path.as_path(),
                "native leaf map inputs differ",
            )?;
            // Reuse the exact libc/release/47-file guard and its close-on-error.
            super::super::super::private_machine_diagnostic::with_native_memcpy(
                &native.memcpy,
                artifact,
                |_| {
                    let libc = FileIdentity::read(native.memcpy.archive)?;
                    let attempt = (|| {
                        let objects = extract_objects(&libc, 1)?;
                        let data = fs::read(&artifact.path).map_err(|e| e.to_string())?;
                        let elf = Elf::parse(&data).map_err(|e| e.to_string())?;
                        require(
                            fs::metadata(&link_map.path)
                                .map_err(|e| e.to_string())?
                                .len()
                                <= 128 * 1024 * 1024,
                            "native leaf map exceeds bound",
                        )?;
                        let map = fs::read_to_string(&link_map.path).map_err(|e| e.to_string())?;
                        let observe = |role: Leaf| -> Result<LeafObservation> {
                            let found = objects
                                .iter()
                                .filter(|m| m.name == role.member())
                                .collect::<Vec<_>>();
                            require(
                                found.len() == 1,
                                "native leaf physical member absent/duplicate",
                            )?;
                            let m = found[0];
                            let object = ObjectInput {
                                archive_path: &libc.path,
                                member_name: &m.name,
                                ordinal: m.ordinal,
                                header_offset: m.header,
                                bytes: &m.bytes,
                                elf: Elf::parse(&m.bytes).map_err(|e| e.to_string())?,
                            };
                            join(role, &object, &map, &elf, &data, &libc)
                        };
                        let observations = NativeLeafObservations {
                            runtime_archive: archive.file.clone(),
                            artifact: artifact.clone(),
                            link_map: link_map.clone(),
                            source_files: source_files.clone(),
                            memset: observe(Leaf::Memset)?,
                            set_thread_area: observe(Leaf::SetThreadArea)?,
                            scope: "SOURCE_MEMBER_MAP_RX_IDENTITIES_ONLY_NOT_SYSCALL_OR_ENTRY_AUTHORIZATION",
                        };
                        body(&observations)
                    })();
                    close_result(attempt, libc.verify())
                },
            )
        })();
        let mut errors = Vec::new();
        if let Err(e) = archive.verify() {
            errors.push(e);
        }
        for f in [artifact, link_map] {
            if let Err(e) = f.verify() {
                errors.push(e);
            }
        }
        for source in &source_files {
            if let Err(e) = source.verify() {
                errors.push(e);
            }
        }
        if let Err(e) = self.guard.close(runner) {
            errors.push(e);
        }
        close_result(result, require(errors.is_empty(), errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MEMSET: &[u8] = &include!("../../../tests/fixtures/musl_memset_member.rs");
    const SET_THREAD_AREA: &[u8] =
        &include!("../../../tests/fixtures/musl_set_thread_area_member.rs");
    fn raw(role: Leaf) -> &'static [u8] {
        match role {
            Leaf::Memset => MEMSET,
            Leaf::SetThreadArea => SET_THREAD_AREA,
        }
    }
    fn object(role: Leaf, data: &[u8]) -> ObjectInput<'_> {
        let (ordinal, header_offset, _) = role.physical();
        ObjectInput {
            archive_path: Path::new("/bound/libc.a"),
            member_name: role.member(),
            ordinal,
            header_offset,
            bytes: data,
            elf: Elf::parse(data).unwrap(),
        }
    }
    fn put(bytes: &mut [u8], offset: usize, n: u64, width: usize) {
        bytes[offset..offset + width].copy_from_slice(&n.to_le_bytes()[..width]);
    }
    // Parser controls carry actual native code, not source/owner authority.
    // No synthetic object can enter the public method without actual owner,
    // pinned native archive/source/member checks and all custody closes.
    fn image(role: Leaf) -> Vec<u8> {
        let mut b = vec![0u8; 0x3000];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, n, width) in [
            (16, 2, 2),
            (18, 62, 2),
            (20, 1, 4),
            (24, 0x101000, 8),
            (32, 64, 8),
            (40, 0x2000, 8),
            (52, 64, 2),
            (54, 56, 2),
            (56, 1, 2),
            (58, 64, 2),
            (60, 5, 2),
            (62, 4, 2),
            (64, 1, 4),
            (68, 5, 4),
            (72, 0, 8),
            (80, 0x100000, 8),
            (88, 0x100000, 8),
            (96, 0x3000, 8),
            (104, 0x3000, 8),
            (112, 4096, 8),
        ] {
            put(&mut b, at, n, width);
        }
        b[0x1000..0x1000 + role.code().len()].copy_from_slice(role.code());
        let names = b"\0.text\0.strtab\0.symtab\0.shstrtab\0";
        b[0x2600..0x2600 + names.len()].copy_from_slice(names);
        let symbol_name = format!("\0{}\0", role.name());
        b[0x2300..0x2300 + symbol_name.len()].copy_from_slice(symbol_name.as_bytes());
        let sections = [
            (
                1,
                1,
                6,
                0x101000,
                0x1000,
                role.code().len() as u64,
                0,
                0,
                1,
                0,
            ),
            (7, 3, 0, 0, 0x2300, symbol_name.len() as u64, 0, 0, 1, 0),
            (
                15,
                2,
                0,
                0,
                0x2400,
                48,
                2,
                if role.final_binding() == sym::STB_LOCAL {
                    2
                } else {
                    1
                },
                8,
                24,
            ),
            (23, 3, 0, 0, 0x2600, names.len() as u64, 0, 0, 1, 0),
        ];
        for (i, (name, kind, flags, addr, offset, size, link, info, align, entsize)) in
            sections.into_iter().enumerate()
        {
            let h = 0x2000 + (i + 1) * 64;
            for (field, n, width) in [
                (0, name, 4),
                (4, kind, 4),
                (8, flags, 8),
                (16, addr, 8),
                (24, offset, 8),
                (32, size, 8),
                (40, link, 4),
                (44, info, 4),
                (48, align, 8),
                (56, entsize, 8),
            ] {
                put(&mut b, h + field, n, width);
            }
        }
        put(&mut b, 0x2418, 1, 4);
        b[0x241c] = (role.final_binding() << 4) | sym::STT_FUNC;
        b[0x241d] = role.visibility();
        put(&mut b, 0x241e, 1, 2);
        put(&mut b, 0x2420, 0x101000, 8);
        b
    }
    fn map(role: Leaf) -> String {
        format!(
            "101000 101000 {:x} 1 /bound/libc.a({}):(.text)\n",
            role.code().len(),
            role.member()
        )
    }
    fn joined(role: Leaf, b: &[u8]) -> Result<LeafObservation> {
        let source = object(role, raw(role));
        let file = FileIdentity {
            path: PathBuf::from("/bound/libc.a"),
            sha256: "test".into(),
        };
        join(
            role,
            &source,
            &map(role),
            &Elf::parse(b).map_err(|e| e.to_string())?,
            b,
            &file,
        )
    }
    #[test]
    fn exact_release_assembly_sources_are_not_caller_selected_text() {
        for (role, text) in [
            (
                Leaf::Memset,
                &include_bytes!("../../../tests/fixtures/musl_memset_source.txt")[..],
            ),
            (
                Leaf::SetThreadArea,
                &include_bytes!("../../../tests/fixtures/musl_set_thread_area_source.txt")[..],
            ),
        ] {
            source_digest(role, &sha256(text)).unwrap();
            for i in 0..text.len() {
                let mut altered = text.to_vec();
                altered[i] ^= 1;
                assert!(source_digest(role, &sha256(&altered)).is_err());
            }
            assert!(source_digest(role, &sha256(&text[..text.len() - 1])).is_err());
        }
    }
    #[test]
    fn actual_native_whole_leaves_keep_zero_sized_symbols_and_exact_code() {
        for role in [Leaf::Memset, Leaf::SetThreadArea] {
            let source = object(role, raw(role));
            member_identity(role, &source).unwrap();
            assert_eq!(input_section(role, &source.elf, source.bytes).unwrap(), 1);
            let b = image(role);
            let observation = joined(role, &b).unwrap();
            assert_eq!(observation.complete_section_bytes, role.code().len());
            assert_eq!(observation.actual_symbol_size, 0);
            let elf = Elf::parse(&b).unwrap();
            let s = elf.syms.iter().find(|s| s.st_shndx != 0).unwrap();
            assert!(!super::super::super::super::executable_symbol(&elf, &s));
        }
    }
    #[test]
    fn native_leaf_source_member_geometry_and_all_code_bytes_are_bound() {
        for role in [Leaf::Memset, Leaf::SetThreadArea] {
            let mut source = object(role, raw(role));
            source.ordinal += 1;
            assert!(member_identity(role, &source).is_err());
            source.ordinal -= 1;
            source.header_offset += 2;
            assert!(member_identity(role, &source).is_err());
            source.header_offset -= 2;
            source.member_name = "unknown.lo";
            assert!(member_identity(role, &source).is_err());
            for i in 0..role.code().len() {
                let mut corrupt = raw(role).to_vec();
                corrupt[64 + i] ^= 1;
                assert!(input_section(role, &Elf::parse(&corrupt).unwrap(), &corrupt).is_err());
                assert!(member_identity(role, &object(role, &corrupt)).is_err());
            }
            for (field, value) in [
                ("size", role.code().len() as u64 - 1),
                ("size", role.code().len() as u64 + 1),
                ("flags", 7),
                ("align", 16),
            ] {
                let mut elf = Elf::parse(raw(role)).unwrap();
                match field {
                    "size" => elf.section_headers[1].sh_size = value,
                    "flags" => elf.section_headers[1].sh_flags = value,
                    _ => elf.section_headers[1].sh_addralign = value,
                }
                assert!(input_section(role, &elf, raw(role)).is_err());
            }
        }
    }
    #[test]
    fn native_leaf_unknown_input_alias_and_code_relocations_refuse() {
        for role in [Leaf::Memset, Leaf::SetThreadArea] {
            let b = raw(role);
            let parsed = Elf::parse(b).unwrap();
            let table = parsed
                .section_headers
                .iter()
                .find(|s| s.sh_type == section_header::SHT_SYMTAB)
                .unwrap();
            // Change a real non-SECTION symbol to an additional code alias.
            let mut corrupt = b.to_vec();
            let at = table.sh_offset as usize + 24;
            corrupt[at + 4] = 0x10;
            put(&mut corrupt, at + 6, 1, 2);
            put(&mut corrupt, at + 8, 0, 8);
            assert!(input_section(role, &Elf::parse(&corrupt).unwrap(), &corrupt).is_err());
            let mut elf = Elf::parse(b).unwrap();
            let rs = elf
                .section_headers
                .iter_mut()
                .find(|s| s.sh_type == section_header::SHT_RELA)
                .unwrap();
            rs.sh_info = 1;
            assert!(input_section(role, &elf, b).is_err());
            // Preserve the previous negative; additionally encode an actual
            // in-bounds relocation so even the 16-byte setter reaches the
            // dedicated unsupported-code-relocation predicate.
            let (index, rs) = parsed
                .section_headers
                .iter()
                .enumerate()
                .find(|(_, s)| s.sh_type == section_header::SHT_RELA)
                .unwrap();
            let mut relocated = b.to_vec();
            put(
                &mut relocated,
                parsed.header.e_shoff as usize + index * 64 + 44,
                1,
                4,
            );
            put(&mut relocated, rs.sh_offset as usize, 0, 8);
            assert_eq!(
                input_section(role, &Elf::parse(&relocated).unwrap(), &relocated).unwrap_err(),
                "native leaf code relocation is not supported"
            );
        }
    }
    #[test]
    fn native_leaf_final_bytes_symbols_mapping_and_map_are_strict() {
        for role in [Leaf::Memset, Leaf::SetThreadArea] {
            let good = image(role);
            for i in 0..role.code().len() {
                let mut b = good.clone();
                b[0x1000 + i] ^= 1;
                assert!(joined(role, &b).is_err());
            }
            for (at, n, width) in [
                (68, 7, 4),
                (0x241c, 0x10, 1),
                (0x2428, 1, 8),
                (0x2420, 0x101001, 8),
                (0x2000 + 64 + 8, 7, 8),
            ] {
                let mut b = good.clone();
                put(&mut b, at, n, width);
                assert!(joined(role, &b).is_err());
            }
            // A second actual symbol-table record at the same entry is not
            // accepted merely because the named role itself still matches.
            let mut alias = good.clone();
            alias[0x2404] = sym::STT_NOTYPE;
            put(&mut alias, 0x2406, 1, 2);
            put(&mut alias, 0x2408, 0x101000, 8);
            assert!(joined(role, &alias).is_err());
            let source = object(role, raw(role));
            let elf = Elf::parse(&good).unwrap();
            let file = FileIdentity {
                path: PathBuf::from("/bound/libc.a"),
                sha256: "test".into(),
            };
            for text in [
                String::new(),
                map(role).repeat(2),
                map(role).replace("101000 101000", "101001 101001"),
                map(role).replace(role.member(), "wrong.lo"),
            ] {
                assert!(join(role, &source, &text, &elf, &good, &file).is_err());
            }
        }
    }
    #[test]
    fn native_leaf_final_retained_relocation_writes_refuse() {
        for role in [Leaf::Memset, Leaf::SetThreadArea] {
            let mut b = image(role);
            // Add a real SHT_RELA owned by the complete symtab and .text.
            put(&mut b, 60, 6, 2);
            for (field, n, width) in [
                (4, 4, 4),
                (24, 0x2700, 8),
                (32, 24, 8),
                (40, 3, 4),
                (44, 1, 4),
                (48, 8, 8),
                (56, 24, 8),
            ] {
                put(&mut b, 0x2000 + 5 * 64 + field, n, width);
            }
            put(&mut b, 0x2700, 0x101000, 8);
            put(&mut b, 0x2708, (1 << 32) | 1, 8);
            assert!(joined(role, &b).is_err());
            let mut dynamic = image(role);
            put(&mut dynamic, 56, 2, 2);
            for (field, n, width) in [
                (0, 2, 4),
                (8, 0x2800, 8),
                (16, 0x102800, 8),
                (32, 16, 8),
                (40, 16, 8),
                (48, 8, 8),
            ] {
                put(&mut dynamic, 120 + field, n, width);
            }
            assert!(joined(role, &dynamic).is_err());
        }
    }
}
