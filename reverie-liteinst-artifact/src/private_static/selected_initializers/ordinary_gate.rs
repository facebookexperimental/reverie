//! Exact ordinary 44-byte provider identity, not syscall or entry authorization.
use super::*;

const OWNER: &str = "reverie_inguest_trusted_syscall";
const NATIVE: &str = "reverie_inguest_trusted_syscall_ip";
const POST: &str = "reverie_inguest_trusted_syscall_return_ip";
const PAGE: &str = "reverie_inguest_mapped_gate_page";
const PAGE_END: &str = "reverie_inguest_mapped_gate_page_end";
const BODY: [u8; 44] = [
    0x41, 0x54, 0x4c, 0x8d, 0x25, 0x1c, 0, 0, 0, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89,
    0xd6, 0x48, 0x89, 0xca, 0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x4c, 0x8b, 0x4c, 0x24, 0x10, 0x0f,
    0x05, 0x41, 0xff, 0xe4, 0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x5c, 0xc3,
];
const TRAP_SHA: &str = "5c9249419574f00c540dec767359181c8ac03a47aa2df0f19e5cef0a59b5755b";
const FIXED_SHA: &str = "ff3f6f6c46e872734ae921e869dbccc0ce1aeefe4bc3af8f29363cf276501e54";
#[cfg(test)]
const MEMBER: &str =
    "reverie_inguest-ba5b7b992d5b00fd.reverie_inguest.5d82eb07abf40ef1-cgu.01.rcgu.o";
#[cfg(test)]
const GATE_MEMBER: &str =
    "reverie_inguest-ba5b7b992d5b00fd.reverie_inguest.5d82eb07abf40ef1-cgu.14.rcgu.o";
const PAGE_SHA: &str = "a852d01cbc01ae5487ff539e229e2ab203d16b22e5f4f6736ee3584d971a8380";
// Closed measured input cohorts. These are not caller-configurable offsets.
// The checker may advance independently of the runtime's selected source pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Cohort {
    LegacyE3,
    CheckedHandoff5b3,
}
impl Cohort {
    #[cfg(test)]
    fn member(self, gate: bool) -> (&'static str, usize, u64, &'static str) {
        match (self, gate) {
            (Self::LegacyE3, false) => (
                MEMBER,
                131,
                61978858,
                "3742f0d92a136c4caa3fb1cc76abd34d32b5d281216abed58f1d36a7b2acf9e4",
            ),
            (Self::LegacyE3, true) => (
                GATE_MEMBER,
                144,
                64989686,
                "83f86faaa075bcf9e06c5d844e3f8c0f03f7d2d115c0a5a1901dae27dbcc8f04",
            ),
            (Self::CheckedHandoff5b3, false) => (
                "reverie_inguest-c04f13744152b221.reverie_inguest.ae73af346ed3e026-cgu.02.rcgu.o",
                132,
                62162754,
                "07bf9c69d32ddf69f08268bc8ce1ed9e0ab74997c23002125259db6c95705ed3",
            ),
            (Self::CheckedHandoff5b3, true) => (
                "reverie_inguest-c04f13744152b221.reverie_inguest.ae73af346ed3e026-cgu.14.rcgu.o",
                144,
                65099178,
                "d843bf6b45591ce5267f80bbf598abaa1924706d3900439d684bf18df94643f9",
            ),
        }
    }
    fn owner_offset(self) -> u64 {
        match self {
            Self::LegacyE3 => 0,
            Self::CheckedHandoff5b3 => 112,
        }
    }
    fn text_size(self) -> u64 {
        match self {
            Self::LegacyE3 => 177,
            Self::CheckedHandoff5b3 => 289,
        }
    }
    fn entry(self, contribution: u64) -> Result<u64> {
        contribution
            .checked_add(self.owner_offset())
            .ok_or("ordinary entry overflow".into())
    }
    #[cfg(test)]
    fn physical_coordinates(self, m: &MemberBytes, gate: bool) -> Result<()> {
        let (name, ordinal, header, _) = self.member(gate);
        require(
            m.name == name && m.ordinal == ordinal && m.header == header,
            "ordinary physical member/cohort differs",
        )
    }
    #[cfg(test)]
    fn physical(self, m: &MemberBytes, gate: bool) -> Result<()> {
        self.physical_coordinates(m, gate)?;
        let (_, _, _, digest) = self.member(gate);
        require(
            sha256(&m.bytes) == digest,
            "ordinary physical member/cohort differs",
        )
    }
}
#[cfg(test)]
fn select_cohort(members: &[MemberBytes]) -> Result<Cohort> {
    let found = [Cohort::LegacyE3, Cohort::CheckedHandoff5b3]
        .into_iter()
        .filter(|c| members.iter().any(|m| m.name == c.member(false).0))
        .collect::<Vec<_>>();
    require(
        found.len() == 1,
        "ordinary physical cohort absent/ambiguous",
    )?;
    Ok(found[0])
}
// Metadata selection only: it cannot construct a provider or supply source
// authority. The sole caller first admits the actual source/archive Arc and
// obtains these bytes itself from that Cargo-selected immutable archive.
fn defining_members(members: &[MemberBytes]) -> Result<(usize, usize)> {
    let names = [OWNER, NATIVE, POST, PAGE, PAGE_END];
    let mut definitions: [Vec<usize>; 5] = std::array::from_fn(|_| Vec::new());
    for (index, member) in members.iter().enumerate() {
        let elf = Elf::parse(&member.bytes).map_err(|e| e.to_string())?;
        require(
            elf.header.e_type == header::ET_REL
                && elf.header.e_machine == header::EM_X86_64
                && elf.is_64
                && elf.little_endian,
            "ordinary archive member is not x86-64 ELF64LE ET_REL",
        )?;
        checked_object_symbol_authority(&elf, &member.bytes)?;
        if elf
            .section_headers
            .iter()
            .any(|s| s.sh_type == section_header::SHT_SYMTAB)
        {
            let table = checked_symtab(&elf, &member.bytes)?;
            checked_relocation_inventory(&elf, &member.bytes, table)?;
        }
        for symbol in elf.syms.iter().filter(|s| s.st_shndx != 0) {
            let name = elf
                .strtab
                .get_at(symbol.st_name)
                .ok_or("ordinary definition name")?;
            for (role, expected) in names.iter().enumerate() {
                if name == *expected {
                    definitions[role].push(index);
                }
            }
        }
    }
    require(
        definitions.iter().all(|rows| rows.len() == 1),
        "ordinary archive defining roles absent/duplicate",
    )?;
    let owner = definitions[0][0];
    let page = definitions[3][0];
    require(
        definitions[1][0] == owner
            && definitions[2][0] == owner
            && definitions[4][0] == page
            && owner != page,
        "ordinary archive defining roles have different owners",
    )?;
    for selected in [owner, page] {
        require(
            members
                .iter()
                .filter(|m| m.name == members[selected].name)
                .count()
                == 1,
            "ordinary selected archive member name is ambiguous",
        )?;
    }
    Ok((owner, page))
}
fn closed_input_shape(object: &ObjectInput<'_>) -> Result<Cohort> {
    // One semantic validator serves both historical fixture checks and the
    // private live-owner path. Unknown offsets/extents remain refusals.
    let mut found = Vec::new();
    for shape in [Cohort::LegacyE3, Cohort::CheckedHandoff5b3] {
        if input(object, false, shape).is_ok() {
            found.push(shape);
        }
    }
    require(
        found.len() == 1,
        "ordinary closed input shape absent/ambiguous",
    )?;
    Ok(found[0])
}

type Alias = (String, u8, u8, u8, usize, u64, u64);
fn alias(elf: &Elf<'_>, s: sym::Sym) -> Result<Alias> {
    Ok((
        elf.strtab
            .get_at(s.st_name)
            .ok_or("ordinary alias name")?
            .into(),
        s.st_bind(),
        s.st_type(),
        s.st_visibility(),
        s.st_shndx,
        s.st_value,
        s.st_size,
    ))
}
fn row(
    name: &str,
    bind: u8,
    kind: u8,
    visibility: u8,
    section: usize,
    value: u64,
    size: u64,
) -> Alias {
    (name.into(), bind, kind, visibility, section, value, size)
}
fn exact_aliases(mut actual: Vec<Alias>, mut expected: Vec<Alias>) -> Result<()> {
    actual.sort();
    expected.sort();
    require(actual == expected, "ordinary exact alias/label set differs")
}
fn sole_named(elf: &Elf<'_>, name: &str) -> Result<sym::Sym> {
    let rows = elf
        .syms
        .iter()
        .filter(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "ordinary named symbol absent/duplicate")?;
    Ok(rows[0])
}
const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
fn artifact_size(bytes: u64) -> Result<()> {
    require(
        bytes <= MAX_ARTIFACT_BYTES,
        "ordinary artifact exceeds 128 MiB bound",
    )
}
fn source_digest(actual: &str, gate: bool) -> Result<()> {
    require(
        actual == if gate { FIXED_SHA } else { TRAP_SHA },
        "ordinary actual source differs",
    )
}
fn code_bytes(bytes: &[u8], gate: bool) -> Result<()> {
    if gate {
        require(
            bytes.len() == 4096 && sha256(bytes) == PAGE_SHA,
            "ordinary preceding page code differs",
        )
    } else {
        require(bytes == BODY.as_slice(), "ordinary complete body differs")
    }
}
#[cfg(test)]
fn physical(m: &MemberBytes, gate: bool) -> Result<()> {
    Cohort::LegacyE3.physical(m, gate)
}
fn geometry(s: &section_header::SectionHeader, address: u64, size: u64, align: u64) -> Result<()> {
    require(
        s.sh_type == section_header::SHT_PROGBITS
            && s.sh_flags == 6
            && s.sh_addr == address
            && s.sh_size == size
            && s.sh_addralign == align,
        "ordinary section geometry differs",
    )
}
fn no_writers(elf: &Elf<'_>, section: usize, begin: u64, end: u64) -> Result<()> {
    for (index, rows) in &elf.shdr_relocs {
        let target = &elf.section_headers[elf.section_headers[*index].sh_info as usize];
        for r in rows.iter() {
            // In ET_REL, offsets are section-relative; other sections cannot write
            // this section. In ET_EXEC, retain all possible cross-boundary writers.
            if elf.header.e_type == header::ET_REL
                && elf.section_headers[*index].sh_info as usize != section
            {
                continue;
            }
            require(
                !selected_field_overlap(target, r.r_offset, r.r_type, begin, end)?,
                "ordinary role has relocation/writer",
            )?;
        }
    }
    Ok(())
}
fn input(object: &ObjectInput<'_>, gate: bool, cohort: Cohort) -> Result<usize> {
    let elf = &object.elf;
    let table = checked_symtab(elf, object.bytes)?;
    checked_relocation_inventory(elf, object.bytes, table)?;
    let name = if gate {
        ".reverie_inguest_mapped_gate_page"
    } else {
        ".text"
    };
    let sections = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, s)| elf.shdr_strtab.get_at(s.sh_name) == Some(name))
        .collect::<Vec<_>>();
    require(
        sections.len() == 1,
        "ordinary input section absent/duplicate",
    )?;
    let (index, section) = sections[0];
    geometry(
        section,
        0,
        if gate { 4096 } else { cohort.text_size() },
        if gate { 4096 } else { 16 },
    )?;
    let data = section_file_bytes(section, object.bytes)?;
    let begin = if gate { 0 } else { cohort.owner_offset() };
    let end = begin
        .checked_add(if gate { 4096 } else { 44 })
        .ok_or("ordinary input extent overflow")?;
    code_bytes(
        if gate {
            data
        } else {
            data.get(
                usize::try_from(begin).map_err(|_| "ordinary body offset")?
                    ..usize::try_from(end).map_err(|_| "ordinary body end")?,
            )
            .ok_or("ordinary body absent")?
        },
        gate,
    )?;
    let limit = if gate { 4097 } else { end };
    let actual = elf
        .syms
        .iter()
        .filter(|s| s.st_shndx == index && begin <= s.st_value && s.st_value < limit)
        .map(|s| alias(elf, s))
        .collect::<Result<Vec<_>>>()?;
    // The actual input has no SECTION symbol in this section. Do not ignore one.
    let expected = if gate {
        vec![
            row(PAGE, 1, 1, 2, index, 0, 4096),
            row(PAGE_END, 1, 0, 2, index, 4096, 0),
        ]
    } else {
        vec![
            row(OWNER, 1, 2, 2, index, begin, 44),
            row(NATIVE, 1, 0, 2, index, begin + 32, 0),
            row(POST, 1, 0, 2, index, begin + 34, 0),
        ]
    };
    exact_aliases(actual, expected)?;
    // Named aliases outside the selected section cannot impersonate its labels.
    for name in if gate {
        vec![PAGE, PAGE_END]
    } else {
        vec![OWNER, NATIVE, POST]
    } {
        let _ = sole_named(elf, name)?;
    }
    no_writers(elf, index, begin, end)?;
    Ok(index)
}

/// Callback-scoped, source-derived ordinary provider observations. Private
/// construction and no Deserialize/Clone, image, syscall permission or Ready.
#[derive(Debug, Serialize)]
pub struct OrdinaryGateObservations {
    runtime_archive: FileIdentity,
    identity_policy: &'static str,
    member_name: String,
    page_member_name: String,
    artifact: FileIdentity,
    link_map: FileIdentity,
    sources: Vec<FileIdentity>,
    cohort: Cohort,
    contribution: u64,
    entry: u64,
    section: usize,
    page_section: usize,
    page_entry: u64,
    member_sha256: String,
    member_ordinal: usize,
    member_header: u64,
    page_member_sha256: String,
    page_member_ordinal: usize,
    page_member_header: u64,
    scope: &'static str,
}
fn same_identity(actual: &FileIdentity, expected: &FileIdentity, error: &str) -> Result<()> {
    require(
        actual.path == expected.path && actual.sha256 == expected.sha256,
        error,
    )
}

#[cfg(test)]
pub(crate) fn composition_test_fixture() -> (Vec<u8>, OrdinaryGateObservations) {
    tests::fixture()
}

impl OrdinaryGateObservations {
    /// Actual SysV entry, native Linux-register SYSCALL label and post-IP.
    /// Native-label entry additionally requires the caller's real R12/stack/state
    /// contract; this observation never authorizes that call or any syscall.
    pub fn addresses(&self) -> (u64, u64, u64) {
        (self.entry, self.entry + 32, self.entry + 34)
    }

    /// Reuse the actual complete root-byte/decoder/caller/RO-GOT diagnostic.
    /// Any unsupported instruction remains a refusal and NOT_PROVEN remains
    /// unconditional. The supplied tool is fallible input, never role authority.
    pub fn inspect_entry_transfers(
        &self,
        objdump: &FileIdentity,
        runner: &mut Runner,
    ) -> Result<super::super::super::private_machine_diagnostic::EntryTransferDiagnostic> {
        super::super::super::private_machine_diagnostic::inspect_entry_transfers_with_ordinary(
            self,
            &self.artifact,
            objdump,
            runner,
        )
    }
    #[cfg(test)]
    pub(crate) fn bind_composition_test_file(&mut self, file: &FileIdentity) {
        self.runtime_archive = file.clone();
        self.artifact = file.clone();
        self.link_map = file.clone();
    }
    // Same callback/source/archive as ordinary44, but this is the DISTINCT
    // fixed-page native ABI and its independent RO expected-page allocation.
    pub(super) fn verify_terminal_fixed_page(
        &self,
        objects: &[ObjectInput<'_>],
        map: &str,
        elf: &Elf<'_>,
        bytes: &[u8],
    ) -> Result<u64> {
        self.verify_final(elf, bytes)?;
        let found = objects
            .iter()
            .filter(|o| {
                o.archive_path == self.runtime_archive.path.as_path()
                    && o.ordinal == self.page_member_ordinal
                    && o.header_offset == self.page_member_header
                    && sha256(o.bytes) == self.page_member_sha256
            })
            .collect::<Vec<_>>();
        require(
            found.len() == 1,
            "terminal fixed/reference physical member differs",
        )?;
        let input = found[0];
        let begin_name = "reverie_inguest_fixed_gate_template";
        let end_name = "reverie_inguest_fixed_gate_template_end";
        let begin = sole_named(&input.elf, begin_name)?;
        let end = sole_named(&input.elf, end_name)?;
        let section = input
            .elf
            .section_headers
            .get(begin.st_shndx)
            .ok_or("terminal reference input section")?;
        require(
            input.elf.shdr_strtab.get_at(section.sh_name)
                == Some(".reverie_inguest_fixed_gate_template")
                && section.sh_type == section_header::SHT_PROGBITS
                && section.sh_flags == 2
                && section.sh_size == 4096
                && section.sh_addralign == 4096
                && section.sh_addr == 0,
            "terminal complete reference input geometry differs",
        )?;
        let actual = input
            .elf
            .syms
            .iter()
            .filter(|s| s.st_shndx == begin.st_shndx)
            .map(|s| alias(&input.elf, s))
            .collect::<Result<Vec<_>>>()?;
        exact_aliases(
            actual,
            vec![
                row(begin_name, 1, 1, 2, begin.st_shndx, 0, 4096),
                row(end_name, 1, 0, 2, begin.st_shndx, 4096, 0),
            ],
        )?;
        require(
            end.st_shndx == begin.st_shndx,
            "reference end section differs",
        )?;
        code_bytes(section_file_bytes(section, input.bytes)?, true)?;
        no_writers(&input.elf, begin.st_shndx, 0, 4096)?;
        let address = mapped_section(map, input, begin.st_shndx)?;
        let final_begin = sole_named(elf, begin_name)?;
        let final_end = sole_named(elf, end_name)?;
        require(
            final_begin.st_value == address
                && final_begin.st_size == 4096
                && final_begin.st_type() == sym::STT_OBJECT
                && final_begin.st_visibility() == sym::STV_HIDDEN
                && final_begin.st_bind() == sym::STB_LOCAL
                && final_end.st_value
                    == address.checked_add(4096).ok_or("reference end overflow")?
                && final_end.st_shndx == final_begin.st_shndx
                && final_end.st_size == 0
                && final_end.st_type() == sym::STT_NOTYPE
                && final_end.st_visibility() == sym::STV_HIDDEN
                && final_end.st_bind() == sym::STB_LOCAL,
            "terminal final reference aliases differ",
        )?;
        let actual_aliases = elf
            .syms
            .iter()
            .filter(|s| {
                s.st_shndx == final_begin.st_shndx
                    && s.st_value >= address
                    && s.st_value < address + 4096
            })
            .map(|s| alias(elf, s))
            .collect::<Result<Vec<_>>>()?;
        // The actual output has an exact unnamed STT_SECTION start alias;
        // this is a section identity, not a second callable provider.
        exact_aliases(
            actual_aliases,
            vec![
                row(begin_name, 0, 1, 2, final_begin.st_shndx, address, 4096),
                row("", 0, 3, 0, final_begin.st_shndx, address, 0),
            ],
        )?;
        let (load, offset) = unique_file_mapping(elf, bytes, address, 4096)?;
        let (executed, executed_offset) = unique_file_mapping(elf, bytes, self.page_entry, 4096)?;
        require(
            load.p_flags == 4
                && executed.p_flags == 5
                && address != self.page_entry
                && (offset
                    .checked_add(4096)
                    .is_some_and(|n| n <= executed_offset)
                    || executed_offset
                        .checked_add(4096)
                        .is_some_and(|n| n <= offset)),
            "terminal reference/executed page aliases or permissions differ",
        )?;
        code_bytes(
            bytes
                .get(offset..offset + 4096)
                .ok_or("reference file bytes")?,
            true,
        )?;
        no_writers(elf, final_begin.st_shndx, address, address + 4096)?;
        // Exact complete native entry + syscall + jump-to-R12 continuation.
        require(
            bytes.get(executed_offset + 124..executed_offset + 133)
                == Some(&[0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x05, 0x41, 0xff, 0xe4][..]),
            "terminal fixed native syscall/continuation differs",
        )?;
        self.page_entry
            .checked_add(124)
            .ok_or("terminal native entry overflow".into())
    }
    pub(crate) fn definition_address(&self) -> u64 {
        self.entry
    }
    pub(crate) fn verify_final(&self, elf: &Elf<'_>, bytes: &[u8]) -> Result<()> {
        self.artifact.verify()?;
        self.link_map.verify()?;
        for source in &self.sources {
            source.verify()?;
        }
        require(
            sha256(bytes) == self.artifact.sha256,
            "ordinary resolver artifact differs",
        )?;
        self.verify_final_shape(elf, bytes)
    }
    // Pure structural controls use this same parser; they do not construct an
    // actual source owner or bypass verify_final's retained file identities.
    fn verify_final_shape(&self, elf: &Elf<'_>, bytes: &[u8]) -> Result<()> {
        static_image_metadata(elf, bytes)?;
        require(
            self.cohort.entry(self.contribution)? == self.entry,
            "ordinary owner/contribution differs",
        )?;
        let ordinary = elf
            .section_headers
            .get(self.section)
            .ok_or("ordinary final section absent")?;
        require(
            elf.shdr_strtab.get_at(ordinary.sh_name) == Some(".text")
                && ordinary.sh_type == 1
                && ordinary.sh_flags == 6
                && ordinary.sh_addr == self.contribution
                && ordinary.sh_addralign == 16
                && ordinary.sh_size >= self.cohort.owner_offset() + 44,
            "ordinary final text geometry differs",
        )?;
        let page = elf
            .section_headers
            .get(self.page_section)
            .ok_or("ordinary preceding section absent")?;
        geometry(page, self.page_entry, 4096, 4096)?;
        require(
            self.page_section != self.section
                && elf.shdr_strtab.get_at(page.sh_name) == Some(".mapped_gate")
                && self.page_entry.checked_add(4096) == Some(self.contribution),
            "ordinary distinct preceding boundary differs",
        )?;
        let (load, offset) = unique_file_mapping(elf, bytes, self.entry, 44)?;
        let (page_load, page_offset) = unique_file_mapping(elf, bytes, self.page_entry, 4096)?;
        require(
            load.p_flags == 5
                && page_load.p_flags == 5
                && ordinary.sh_offset.checked_add(self.cohort.owner_offset())
                    == Some(offset as u64)
                && page.sh_offset == page_offset as u64
                && sha256(&bytes[page_offset..page_offset + 4096]) == PAGE_SHA,
            "ordinary section/actual RX mapping differs",
        )?;
        let end = self.entry.checked_add(44).ok_or("ordinary end overflow")?;
        let actual = elf
            .syms
            .iter()
            .filter(|s| s.st_shndx != 0 && self.contribution <= s.st_value && s.st_value < end)
            .map(|s| alias(elf, s))
            .collect::<Result<Vec<_>>>()?;
        let mut expected = vec![
            row(OWNER, 0, 2, 2, self.section, self.entry, 44),
            row("", 0, 3, 0, self.section, self.contribution, 0),
            row(PAGE_END, 0, 0, 2, self.page_section, self.contribution, 0),
            row(NATIVE, 0, 0, 2, self.section, self.entry + 32, 0),
            row(POST, 0, 0, 2, self.section, self.entry + 34, 0),
        ];
        if self.cohort == Cohort::CheckedHandoff5b3 {
            // Actual diagnostic link 52db89fe: these precede the ordinary
            // body; PAGE_END/SECTION are boundary facts, never owner aliases.
            expected.extend([
                row(
                    "fallback_entry",
                    0,
                    2,
                    2,
                    self.section,
                    self.contribution,
                    48,
                ),
                row(
                    "fallback_completion_syscall",
                    0,
                    0,
                    2,
                    self.section,
                    self.contribution + 44,
                    0,
                ),
                row(
                    "fallback_completion_return",
                    0,
                    0,
                    2,
                    self.section,
                    self.contribution + 46,
                    0,
                ),
                row(
                    "reverie_native_launch_syscall",
                    0,
                    2,
                    2,
                    self.section,
                    self.contribution + 48,
                    55,
                ),
            ]);
            for name in [
                "fallback_entry",
                "fallback_completion_syscall",
                "fallback_completion_return",
                "reverie_native_launch_syscall",
            ] {
                let _ = sole_named(elf, name)?;
            }
        }
        exact_aliases(actual, expected)?;
        for name in [OWNER, NATIVE, POST, PAGE, PAGE_END] {
            let _ = sole_named(elf, name)?;
        }
        let p = sole_named(elf, PAGE)?;
        require(
            alias(elf, p)? == row(PAGE, 0, 1, 2, self.page_section, self.page_entry, 4096),
            "ordinary final page owner differs",
        )?;
        require(
            elf.syms
                .iter()
                .filter(|s| s.st_shndx != 0 && s.st_type() == sym::STT_FUNC)
                .all(|s| {
                    s.st_value == self.entry
                        || s.st_value
                            .checked_add(s.st_size)
                            .is_some_and(|other_end| other_end <= self.entry || s.st_value >= end)
                }),
            "ordinary overlaps a distinct function",
        )?;
        no_writers(elf, self.section, self.entry, end)?;
        no_writers(elf, self.page_section, self.page_entry, self.contribution)?;
        let _ = join_relocated_body(
            elf,
            bytes,
            self.entry,
            &BODY,
            &bytes[offset..offset + 44],
            &[],
            &[],
        )?;
        Ok(())
    }
    pub(crate) fn verify_slot(&self, elf: &Elf<'_>, bytes: &[u8], slot: u64) -> Result<()> {
        self.verify_final(elf, bytes)?;
        self.verify_slot_shape(elf, bytes, slot)
    }
    fn verify_slot_shape(&self, elf: &Elf<'_>, bytes: &[u8], slot: u64) -> Result<()> {
        static_image_metadata(elf, bytes)?;
        let (load, _) = unique_file_mapping(elf, bytes, slot, 8)?;
        require(
            load.p_flags == program_header::PF_R,
            "ordinary GOT needs actual RO non-X",
        )?;
        let target = u64::from_le_bytes(
            readonly_loaded_bytes(elf, bytes, slot, 8)?
                .try_into()
                .map_err(|_| "ordinary GOT width")?,
        );
        require(
            target == self.entry,
            "ordinary GOT target is not exact provider entry",
        )
    }
}

/// Bind this additive implementation as a compiled source input.
pub fn ordinary_gate_implementation_sha256() -> String {
    sha256(include_bytes!("ordinary_gate.rs"))
}

impl VerifiedStaticSource {
    /// Observe both exact finite roles in one diagnostic, created inside this
    /// same source/archive callback. No provider supplied by another context is
    /// accepted. All ordinary/native factories and the existing decoder retain
    /// their checks and closes. This grants no pre-TLS or execution authority.
    pub fn inspect_entry_transfers_with_ordinary_and_musl_memcpy(
        &self,
        archive: &StaticArchive,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        inputs: &super::super::super::private_machine_diagnostic::NativeMemcpyInputs<'_>,
        objdump: &FileIdentity,
        runner: &mut Runner,
    ) -> Result<super::super::super::private_machine_diagnostic::EntryTransferDiagnostic> {
        self.with_ordinary_trusted_gate(archive, artifact, link_map, runner, |ordinary, runner| {
            let actual_map = FileIdentity::read(inputs.link_map)?;
            let result = (|| {
                same_identity(&actual_map, link_map,
                    "combined native/ordinary link maps differ")?;
                super::super::super::private_machine_diagnostic::inspect_entry_transfers_with_ordinary_and_memcpy(
                    ordinary, inputs, artifact, objdump, runner,
                )
            })();
            close_result(result, actual_map.verify())
        })
    }

    /// Derive the complete physical members from this live source-built archive.
    /// Only the two closed ordinary44 semantic shapes are admitted; historical
    /// whole-container constants remain strict fixture controls, not live identity.
    /// The source/archive/build-output/file/tool guards close on every Result,
    /// including callback errors; no supplied paths or names construct a role.
    pub fn with_ordinary_trusted_gate<T>(
        &self,
        archive: &StaticArchive,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        body: impl FnOnce(&OrdinaryGateObservations, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        if let Err(error) = self.require_archive_owner(archive) {
            return close_result(Err(error), self.guard.close(runner));
        }
        let mut files = vec![artifact.clone(), link_map.clone()];
        let result = (|| {
            archive.verify()?;
            self.guard.close(runner)?;
            for file in &files {
                file.verify()?;
            }
            let roots = self
                .guard
                .roots
                .iter()
                .filter(|(_, kind)| matches!(kind, RootBinding::Cargo(_)))
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            require(roots.len() == 1, "ordinary resolved source ambiguous")?;
            for (relative, digest) in [
                ("reverie-inguest/src/trap.rs", TRAP_SHA),
                ("reverie-inguest/src/trap/fixed_gates.rs", FIXED_SHA),
            ] {
                let source = FileIdentity::read(&roots[0].join(relative))?;
                files.push(source.clone());
                source_digest(&source.sha256, digest == FIXED_SHA)?;
            }
            let members = extract_objects(&archive.file, 0)?;
            let (member_index, page_index) = defining_members(&members)?;
            let m = &members[member_index];
            let g = &members[page_index];
            let object = ObjectInput {
                archive_path: &archive.file.path,
                member_name: &m.name,
                ordinal: m.ordinal,
                header_offset: m.header,
                bytes: &m.bytes,
                elf: Elf::parse(&m.bytes).map_err(|e| e.to_string())?,
            };
            let gate = ObjectInput {
                archive_path: &archive.file.path,
                member_name: &g.name,
                ordinal: g.ordinal,
                header_offset: g.header,
                bytes: &g.bytes,
                elf: Elf::parse(&g.bytes).map_err(|e| e.to_string())?,
            };
            let cohort = closed_input_shape(&object)?;
            let section = input(&object, false, cohort)?;
            let gate_section = input(&gate, true, cohort)?;
            require(
                fs::metadata(&link_map.path)
                    .map_err(|e| e.to_string())?
                    .len()
                    <= 128 * 1024 * 1024,
                "ordinary map exceeds bound",
            )?;
            let map = fs::read_to_string(&link_map.path).map_err(|e| e.to_string())?;
            let contribution = mapped_section(&map, &object, section)?;
            let entry = cohort.entry(contribution)?;
            let page_entry = mapped_section(&map, &gate, gate_section)?;
            require(
                page_entry == GATE && page_entry.checked_add(4096) == Some(contribution),
                "ordinary mapped boundary differs",
            )?;
            // Match the existing native artifact ceiling before allocating the
            // caller-supplied file. Any refusal reaches the unchanged closes.
            artifact_size(
                fs::metadata(&artifact.path)
                    .map_err(|e| e.to_string())?
                    .len(),
            )?;
            let data = fs::read(&artifact.path).map_err(|e| e.to_string())?;
            let elf = Elf::parse(&data).map_err(|e| e.to_string())?;
            let table = checked_symtab(&elf, &data)?;
            checked_relocation_inventory(&elf, &data, table)?;
            let role = OrdinaryGateObservations {
                runtime_archive: archive.file.clone(),
                identity_policy: "LIVE_SOURCE_ARC_CARGO_ARCHIVE_DERIVED_COMPLETE_MEMBER_IDENTITY",
                member_name: m.name.clone(),
                page_member_name: g.name.clone(),
                artifact: artifact.clone(),
                link_map: link_map.clone(),
                sources: files[2..].to_vec(),
                cohort,
                contribution,
                entry,
                section: sole_named(&elf, OWNER)?.st_shndx,
                page_section: sole_named(&elf, PAGE)?.st_shndx,
                page_entry,
                member_sha256: sha256(&m.bytes),
                member_ordinal: m.ordinal,
                member_header: m.header,
                page_member_sha256: sha256(&g.bytes),
                page_member_ordinal: g.ordinal,
                page_member_header: g.header,
                scope: "ORDINARY44_SOURCE_MEMBER_MAP_RX_IDENTITY_ONLY_NOT_SYSCALL_OR_READY",
            };
            role.verify_final(&elf, &data)?;
            body(&role, runner)
        })();
        let mut errors = Vec::new();
        if let Err(e) = archive.verify() {
            errors.push(e);
        }
        for file in &files {
            if let Err(e) = file.verify() {
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
    #[test]
    fn ordinary44_artifact_allocation_limit_is_inclusive_and_refuses_one_extra_byte() {
        artifact_size(0).unwrap();
        artifact_size(MAX_ARTIFACT_BYTES - 1).unwrap();
        artifact_size(MAX_ARTIFACT_BYTES).unwrap();
        assert_eq!(
            artifact_size(MAX_ARTIFACT_BYTES + 1).unwrap_err(),
            "ordinary artifact exceeds 128 MiB bound"
        );
        assert_eq!(
            artifact_size(u64::MAX).unwrap_err(),
            "ordinary artifact exceeds 128 MiB bound"
        );
        // This controls the allocation admission predicate, not ELF validity:
        // zero/small files still reach and must satisfy the unchanged ELF checks.
    }
    #[test]
    fn ordinary44_actual_bytes_and_every_byte_negative() {
        assert_eq!(
            sha256(&BODY),
            "7edfc401034338f86f529d6caebc0af3a87c47947825d761bb7f49d0eaa54990"
        );
        assert_eq!(&BODY[32..34], &[0x0f, 0x05]);
        assert_eq!(&BODY[34..37], &[0x41, 0xff, 0xe4]);
        assert_eq!(&BODY[37..], &[0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x5c, 0xc3]);
        code_bytes(&BODY, false).unwrap();
        for i in 0..44 {
            let mut bad = BODY;
            bad[i] ^= 1;
            assert!(code_bytes(&bad, false).is_err());
        }
        assert!(code_bytes(&BODY[..43], false).is_err());
        assert!(code_bytes(&[BODY.as_slice(), &[0x90]].concat(), false).is_err());
    }
    #[test]
    fn ordinary44_exact_boundary_aliases_refuse_additions_and_shifted_labels() {
        let expected = vec![
            row(OWNER, 0, 2, 2, 3, 0x2000, 44),
            row("", 0, 3, 0, 3, 0x2000, 0),
            row(PAGE_END, 0, 0, 2, 2, 0x2000, 0),
            row(NATIVE, 0, 0, 2, 3, 0x2020, 0),
            row(POST, 0, 0, 2, 3, 0x2022, 0),
        ];
        exact_aliases(expected.clone(), expected.clone()).unwrap();
        for i in 0..expected.len() {
            let mut bad = expected.clone();
            bad.remove(i);
            assert!(exact_aliases(bad, expected.clone()).is_err());
            let mut bad = expected.clone();
            bad[i].5 += 1;
            assert!(exact_aliases(bad, expected.clone()).is_err());
            let mut bad = expected.clone();
            bad[i].6 += 1;
            assert!(exact_aliases(bad, expected.clone()).is_err());
            let mut bad = expected.clone();
            bad[i].4 += 1;
            assert!(exact_aliases(bad, expected.clone()).is_err());
        }
        let mut bad = expected.clone();
        bad.push(row("unknown", 0, 0, 2, 3, 0x2000, 0));
        assert!(exact_aliases(bad, expected).is_err());
    }
    #[test]
    fn ordinary44_section_geometry_refuses_wrong_extent_permissions_and_alignment() {
        let mut s = section_header::SectionHeader {
            sh_type: 1,
            sh_flags: 6,
            sh_addr: 0,
            sh_size: 177,
            sh_addralign: 16,
            ..Default::default()
        };
        geometry(&s, 0, 177, 16).unwrap();
        for size in [43, 44, 45, 48, 176, 178] {
            s.sh_size = size;
            assert!(geometry(&s, 0, 177, 16).is_err());
        }
        s.sh_size = 177;
        s.sh_flags = 7;
        assert!(geometry(&s, 0, 177, 16).is_err());
        s.sh_flags = 6;
        s.sh_addralign = 1;
        assert!(geometry(&s, 0, 177, 16).is_err());
    }

    const GATE_PAGE: &[u8] = &include!("../../../tests/fixtures/ordinary_preceding_gate_page.rs");
    fn put(b: &mut [u8], at: usize, n: u64, width: usize) {
        b[at..at + width].copy_from_slice(&n.to_le_bytes()[..width]);
    }
    // A small constructed metadata envelope around the measured two code slices.
    // It supplies no archive, source, build output or live source-owner authority.
    pub(super) fn fixture() -> (Vec<u8>, OrdinaryGateObservations) {
        let mut b = vec![0; 0x7000];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, n, width) in [
            (16, 2, 2),
            (18, 62, 2),
            (20, 1, 4),
            (24, GATE + 4096, 8),
            (32, 64, 8),
            (40, 0x6000, 8),
            (52, 64, 2),
            (54, 56, 2),
            (56, 2, 2),
            (58, 64, 2),
            (60, 6, 2),
            (62, 5, 2),
        ] {
            put(&mut b, at, n, width);
        }
        for (i, flags, off, addr, sz) in [
            (0, 5, 0x1000, GATE, 0x2000),
            (1, 4, 0x4000, GATE + 0x3000, 0x1000),
        ] {
            let h = 64 + i * 56;
            for (at, n, width) in [
                (0, 1, 4),
                (4, flags, 4),
                (8, off, 8),
                (16, addr, 8),
                (24, addr, 8),
                (32, sz, 8),
                (40, sz, 8),
                (48, 4096, 8),
            ] {
                put(&mut b, h + at, n, width);
            }
        }
        b[0x1000..0x2000].copy_from_slice(GATE_PAGE);
        b[0x2000..0x202c].copy_from_slice(&BODY);
        put(&mut b, 0x4000, GATE + 4096, 8);
        let names = b"\0.mapped_gate\0.text\0.strtab\0.symtab\0.shstrtab\0.rela.text\0";
        b[0x5800..0x5800 + names.len()].copy_from_slice(names);
        let mut strings = vec![0];
        let mut name_offsets = Vec::new();
        for name in [PAGE, "", OWNER, NATIVE, POST, PAGE_END] {
            name_offsets.push(if name.is_empty() {
                0
            } else {
                let n = strings.len();
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
                n
            });
        }
        b[0x5000..0x5000 + strings.len()].copy_from_slice(&strings);
        let symbols = [
            row(PAGE, 0, 1, 2, 1, GATE, 4096),
            row("", 0, 3, 0, 2, GATE + 4096, 0),
            row(OWNER, 0, 2, 2, 2, GATE + 4096, 44),
            row(NATIVE, 0, 0, 2, 2, GATE + 4128, 0),
            row(POST, 0, 0, 2, 2, GATE + 4130, 0),
            row(PAGE_END, 0, 0, 2, 1, GATE + 4096, 0),
        ];
        for (i, s) in symbols.iter().enumerate() {
            let at = 0x5400 + (i + 1) * 24;
            put(&mut b, at, name_offsets[i] as u64, 4);
            b[at + 4] = (s.1 << 4) | s.2;
            b[at + 5] = s.3;
            put(&mut b, at + 6, s.4 as u64, 2);
            put(&mut b, at + 8, s.5, 8);
            put(&mut b, at + 16, s.6, 8);
        }
        for (i, (name, kind, flags, addr, off, size, link, info, align, entsize)) in [
            (1, 1, 6, GATE, 0x1000, 4096, 0, 0, 4096, 0),
            (14, 1, 6, GATE + 4096, 0x2000, 177, 0, 0, 16, 0),
            (20, 3, 0, 0, 0x5000, strings.len() as u64, 0, 0, 1, 0),
            (28, 2, 0, 0, 0x5400, 168, 3, 7, 8, 24),
            (36, 3, 0, 0, 0x5800, names.len() as u64, 0, 0, 1, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 0x6000 + (i + 1) * 64;
            for (delta, n, width) in [
                (0, name, 4),
                (4, kind, 4),
                (8, flags, 8),
                (16, addr, 8),
                (24, off, 8),
                (32, size, 8),
                (40, link, 4),
                (44, info, 4),
                (48, align, 8),
                (56, entsize, 8),
            ] {
                put(&mut b, at + delta, n, width);
            }
        }
        let dummy = FileIdentity {
            path: PathBuf::from("/not-source-authority"),
            sha256: String::new(),
        };
        let role = OrdinaryGateObservations {
            runtime_archive: dummy.clone(),
            identity_policy: "HISTORICAL_STRUCTURAL_FIXTURE_NOT_SOURCE_AUTHORITY",
            member_name: MEMBER.into(),
            page_member_name: GATE_MEMBER.into(),
            artifact: dummy.clone(),
            link_map: dummy,
            sources: vec![],
            cohort: Cohort::LegacyE3,
            contribution: GATE + 4096,
            entry: GATE + 4096,
            section: 2,
            page_section: 1,
            page_entry: GATE,
            member_sha256: String::new(),
            member_ordinal: 0,
            member_header: 0,
            page_member_sha256: String::new(),
            page_member_ordinal: 0,
            page_member_header: 0,
            scope: "STRUCTURAL_TEST_ONLY",
        };
        (b, role)
    }
    #[test]
    fn combined_role_identity_refuses_same_hash_other_path_and_same_path_other_hash() {
        let original = FileIdentity {
            path: PathBuf::from("actual"),
            sha256: "bytes".into(),
        };
        same_identity(&original, &original, "mismatch").unwrap();
        let mut wrong = original.clone();
        wrong.path = PathBuf::from("other");
        assert_eq!(
            same_identity(&wrong, &original, "mismatch").unwrap_err(),
            "mismatch"
        );
        wrong = original.clone();
        wrong.sha256 = "changed".into();
        assert_eq!(
            same_identity(&wrong, &original, "mismatch").unwrap_err(),
            "mismatch"
        );
    }

    #[test]
    fn ordinary44_structural_rx_boundary_and_slot_controls() {
        let (raw, role) = fixture();
        let elf = Elf::parse(&raw).unwrap();
        role.verify_final_shape(&elf, &raw).unwrap();
        role.verify_slot_shape(&elf, &raw, GATE + 0x3000).unwrap();
        // All ordinary bytes and the independently joined preceding page matter.
        for at in (0x2000..0x202c).chain([0x1000, 0x1fff]) {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(
                role.verify_final_shape(&Elf::parse(&bad).unwrap(), &bad)
                    .is_err(),
                "byte {at}"
            );
        }
        // Owner extent, native/post label, foreign boundary section, SECTION type.
        for (at, n, width) in [
            (0x5400 + 3 * 24 + 16, 43, 8),
            (0x5400 + 4 * 24 + 8, GATE + 4127, 8),
            (0x5400 + 5 * 24 + 8, GATE + 4131, 8),
            (0x5400 + 6 * 24 + 6, 2, 2),
            (0x5400 + 2 * 24 + 4, 0, 1),
            (0x6000 + 64 + 32, 4095, 8),
            (0x6000 + 2 * 64 + 16, GATE + 4097, 8),
            (68, 7, 4),
        ] {
            let mut bad = raw.clone();
            put(&mut bad, at, n, width);
            assert!(
                role.verify_final_shape(&Elf::parse(&bad).unwrap(), &bad)
                    .is_err(),
                "field {at}"
            );
        }
        for target in [0, GATE, GATE + 4097, GATE + 4128] {
            let mut bad = raw.clone();
            put(&mut bad, 0x4000, target, 8);
            assert!(
                role.verify_slot_shape(&Elf::parse(&bad).unwrap(), &bad, GATE + 0x3000)
                    .is_err()
            );
        }
        let mut bad = raw.clone();
        put(&mut bad, 64 + 56 + 4, 6, 4);
        assert!(
            role.verify_slot_shape(&Elf::parse(&bad).unwrap(), &bad, GATE + 0x3000)
                .is_err()
        );
    }
    #[test]
    fn ordinary44_typed_writers_crossing_and_inside_refuse() {
        let (raw, role) = fixture();
        // Extra actual RELA section targeting .text; raw/decoded tables agree.
        for offset in [role.entry, role.entry + 32, role.entry + 43] {
            let mut bad = raw.clone();
            put(&mut bad, 60, 7, 2);
            let at = 0x6000 + 6 * 64;
            for (d, n, w) in [
                (0, 46, 4),
                (4, 4, 4),
                (24, 0x5700, 8),
                (32, 24, 8),
                (40, 4, 4),
                (44, 2, 4),
                (48, 8, 8),
                (56, 24, 8),
            ] {
                put(&mut bad, at + d, n, w);
            }
            put(&mut bad, 0x5700, offset, 8);
            put(&mut bad, 0x5708, (3u64 << 32) | 14, 8);
            let elf = Elf::parse(&bad).unwrap();
            assert!(role.verify_final_shape(&elf, &bad).is_err());
        }
        let target = section_header::SectionHeader::default();
        assert!(
            selected_field_overlap(&target, role.entry - 7, 1, role.entry, role.entry + 44)
                .unwrap()
        );
        assert!(
            !selected_field_overlap(&target, role.entry - 8, 1, role.entry, role.entry + 44)
                .unwrap()
        );
        assert!(
            !selected_field_overlap(&target, role.entry + 44, 1, role.entry, role.entry + 44)
                .unwrap()
        );
    }
    #[test]
    fn ordinary44_source_member_and_map_mismatch_refuse() {
        source_digest(TRAP_SHA, false).unwrap();
        source_digest(FIXED_SHA, true).unwrap();
        assert!(source_digest(FIXED_SHA, false).is_err());
        assert!(source_digest(TRAP_SHA, true).is_err());
        let m = MemberBytes {
            archive_index: 0,
            name: MEMBER.into(),
            ordinal: 131,
            header: 61978858,
            bytes: BODY.to_vec(),
        };
        assert!(physical(&m, false).is_err()); // Correct names/coordinates cannot bless fake member bytes.
        let (raw, _) = fixture();
        let object = ObjectInput {
            archive_path: Path::new("/actual/runtime.a"),
            member_name: MEMBER,
            ordinal: 131,
            header_offset: 61978858,
            bytes: &raw,
            elf: Elf::parse(&raw).unwrap(),
        };
        let row = format!("6000e1002000 6000e1002000 b1 16 /actual/runtime.a({MEMBER}):(.text)");
        assert_eq!(mapped_section(&row, &object, 2).unwrap(), GATE + 4096);
        assert!(mapped_section("", &object, 2).is_err());
        assert!(mapped_section(&format!("{row}\n{row}"), &object, 2).is_err());
        assert!(mapped_section(&row.replace(" b1 ", " b0 "), &object, 2).is_err());
        assert!(
            mapped_section(
                &row.replace("/actual/runtime.a", "/other/runtime.a"),
                &object,
                2
            )
            .is_err()
        );
    }

    // A constructed ET_REL envelope exercises the production input predicates.
    // It is not a measured member and must never pass the physical SHA check.
    fn input_fixture(gate: bool, cohort: Cohort) -> MemberBytes {
        let (mut raw, _) = fixture();
        put(&mut raw, 16, 1, 2); // ET_REL; no program headers or entry.
        put(&mut raw, 24, 0, 8);
        put(&mut raw, 32, 0, 8);
        put(&mut raw, 54, 0, 2);
        put(&mut raw, 56, 0, 2);
        for index in [1, 2] {
            put(&mut raw, 0x6000 + index * 64 + 16, 0, 8);
        }
        put(&mut raw, 0x6000 + 2 * 64 + 32, cohort.text_size(), 8);
        raw[0x2000..0x2121].fill(0);
        let offset = cohort.owner_offset() as usize;
        raw[0x2000 + offset..0x2000 + offset + 44].copy_from_slice(&BODY);
        let mut names =
            b"\0.mapped_gate\0.text\0.strtab\0.symtab\0.shstrtab\0.rela.text\0".to_vec();
        put(&mut raw, 0x6000 + 64, names.len() as u64, 4);
        names.extend_from_slice(b".reverie_inguest_mapped_gate_page\0");
        raw[0x5800..0x5800 + names.len()].copy_from_slice(&names);
        put(&mut raw, 0x6000 + 5 * 64 + 32, names.len() as u64, 8);
        let aliases = if gate {
            vec![
                row(PAGE, 1, 1, 2, 1, 0, 4096),
                row(PAGE_END, 1, 0, 2, 1, 4096, 0),
            ]
        } else {
            vec![
                row(OWNER, 1, 2, 2, 2, cohort.owner_offset(), 44),
                row(NATIVE, 1, 0, 2, 2, cohort.owner_offset() + 32, 0),
                row(POST, 1, 0, 2, 2, cohort.owner_offset() + 34, 0),
            ]
        };
        let mut strings = vec![0];
        raw[0x5400..0x5500].fill(0);
        for (i, symbol) in aliases.iter().enumerate() {
            let at = 0x5400 + (i + 1) * 24;
            put(&mut raw, at, strings.len() as u64, 4);
            strings.extend_from_slice(symbol.0.as_bytes());
            strings.push(0);
            raw[at + 4] = (symbol.1 << 4) | symbol.2;
            raw[at + 5] = symbol.3;
            put(&mut raw, at + 6, symbol.4 as u64, 2);
            put(&mut raw, at + 8, symbol.5, 8);
            put(&mut raw, at + 16, symbol.6, 8);
        }
        raw[0x5000..0x5400].fill(0);
        raw[0x5000..0x5000 + strings.len()].copy_from_slice(&strings);
        put(&mut raw, 0x6000 + 3 * 64 + 32, strings.len() as u64, 8);
        put(
            &mut raw,
            0x6000 + 4 * 64 + 32,
            ((aliases.len() + 1) * 24) as u64,
            8,
        );
        put(&mut raw, 0x6000 + 4 * 64 + 44, 1, 4);
        let (name, ordinal, header, _) = cohort.member(gate);
        MemberBytes {
            archive_index: 0,
            name: name.into(),
            ordinal,
            header,
            bytes: raw,
        }
    }
    fn input_member(m: &MemberBytes, gate: bool, cohort: Cohort) -> Result<usize> {
        input(
            &ObjectInput {
                archive_path: Path::new("/actual/runtime.a"),
                member_name: &m.name,
                ordinal: m.ordinal,
                header_offset: m.header,
                bytes: &m.bytes,
                elf: Elf::parse(&m.bytes).map_err(|e| e.to_string())?,
            },
            gate,
            cohort,
        )
    }
    #[test]
    fn ordinary44_closed_structural_et_rel_inputs_do_not_mint_physical_authority() {
        for cohort in [Cohort::LegacyE3, Cohort::CheckedHandoff5b3] {
            for gate in [false, true] {
                let member = input_fixture(gate, cohort);
                assert_eq!(
                    input_member(&member, gate, cohort).unwrap(),
                    if gate { 1 } else { 2 }
                );
                cohort.physical_coordinates(&member, gate).unwrap();
                assert!(cohort.physical(&member, gate).is_err());
            }
        }
        let new = input_fixture(false, Cohort::CheckedHandoff5b3);
        assert!(input_member(&new, false, Cohort::LegacyE3).is_err());
        assert_eq!(select_cohort(&[new]).unwrap(), Cohort::CheckedHandoff5b3);
    }
    #[test]
    fn ordinary44_closed_cohort_refuses_unknown_mixed_coordinates_and_member_changes() {
        let original = input_fixture(false, Cohort::CheckedHandoff5b3);
        assert!(select_cohort(&[]).is_err());
        let mut wrong = input_fixture(false, Cohort::CheckedHandoff5b3);
        wrong.name = "unmeasured-member".into();
        assert!(select_cohort(&[wrong]).is_err());
        for field in 0..4 {
            let mut bad = input_fixture(false, Cohort::CheckedHandoff5b3);
            match field {
                0 => bad.name = GATE_MEMBER.into(),
                1 => bad.ordinal += 1,
                2 => bad.header += 1,
                _ => bad.bytes[0x2000 + 112] ^= 1,
            }
            if field < 3 {
                assert!(
                    Cohort::CheckedHandoff5b3
                        .physical_coordinates(&bad, false)
                        .is_err()
                );
            } else {
                Cohort::CheckedHandoff5b3
                    .physical_coordinates(&bad, false)
                    .unwrap();
            }
            assert!(Cohort::CheckedHandoff5b3.physical(&bad, false).is_err());
        }
        let old_named = input_fixture(false, Cohort::LegacyE3);
        assert!(select_cohort(&[original, old_named]).is_err());
        let mut page = input_fixture(true, Cohort::CheckedHandoff5b3);
        page.name = GATE_MEMBER.into();
        assert!(Cohort::CheckedHandoff5b3.physical(&page, true).is_err());
    }
    #[test]
    fn ordinary44_displaced_input_rejects_body_alias_extent_and_crossing_writers() {
        let original = input_fixture(false, Cohort::CheckedHandoff5b3);
        let elf = Elf::parse(&original.bytes).unwrap();
        let table = checked_symtab(&elf, &original.bytes).unwrap();
        let symoff = elf.section_headers[table].sh_offset as usize;
        let owner = elf
            .syms
            .iter()
            .position(|s| elf.strtab.get_at(s.st_name) == Some(OWNER))
            .unwrap();
        for offset in [104, 105, 112, 144, 155, 156] {
            let mut bad = input_fixture(false, Cohort::CheckedHandoff5b3);
            put(&mut bad.bytes, 60, 7, 2);
            let header = 0x6000 + 6 * 64;
            for (delta, value, width) in [
                (0, 46, 4),
                (4, 4, 4),
                (24, 0x5700, 8),
                (32, 24, 8),
                (40, 4, 4),
                (44, 2, 4),
                (48, 8, 8),
                (56, 24, 8),
            ] {
                put(&mut bad.bytes, header + delta, value, width);
            }
            put(&mut bad.bytes, 0x5700, offset, 8);
            put(&mut bad.bytes, 0x5708, (1u64 << 32) | 1, 8);
            if offset == 104 || offset == 156 {
                input_member(&bad, false, Cohort::CheckedHandoff5b3).unwrap();
            } else {
                assert_eq!(
                    input_member(&bad, false, Cohort::CheckedHandoff5b3).unwrap_err(),
                    "ordinary role has relocation/writer"
                );
            }
        }
        for (at, value, width) in [
            (0x2000 + 112, u64::from(original.bytes[0x2000 + 112] ^ 1), 1),
            (symoff + owner * 24 + 8, 0, 8),
            (symoff + owner * 24 + 16, 43, 8),
            (elf.header.e_shoff as usize + 2 * 64 + 32, 177, 8),
        ] {
            let mut bad = input_fixture(false, Cohort::CheckedHandoff5b3);
            put(&mut bad.bytes, at, value, width);
            assert!(input_member(&bad, false, Cohort::CheckedHandoff5b3).is_err());
        }
        let target = &elf.section_headers[2];
        assert!(!selected_field_overlap(target, 104, 1, 112, 156).unwrap());
        assert!(selected_field_overlap(target, 105, 1, 112, 156).unwrap());
        assert!(selected_field_overlap(target, 155, 14, 112, 156).unwrap());
        assert!(!selected_field_overlap(target, 156, 14, 112, 156).unwrap());
    }
    #[test]
    fn ordinary44_live_selection_metadata_has_no_historical_container_authority() {
        let mut owner = input_fixture(false, Cohort::CheckedHandoff5b3);
        let mut page = input_fixture(true, Cohort::CheckedHandoff5b3);
        owner.name = "structural-owner.o".into();
        owner.ordinal = 7;
        owner.header = 1024;
        page.name = "structural-page.o".into();
        page.ordinal = 8;
        page.header = 65536;
        let members = [owner, page];
        assert_eq!(defining_members(&members).unwrap(), (0, 1));
        // Pure parsed geometry is not the positive live-source factory control.
        assert!(
            Cohort::CheckedHandoff5b3
                .physical(&members[0], false)
                .is_err()
        );
        let object = ObjectInput {
            archive_path: Path::new("/not-authority.a"),
            member_name: &members[0].name,
            ordinal: members[0].ordinal,
            header_offset: members[0].header,
            bytes: &members[0].bytes,
            elf: Elf::parse(&members[0].bytes).unwrap(),
        };
        assert_eq!(
            closed_input_shape(&object).unwrap(),
            Cohort::CheckedHandoff5b3
        );
        let mut duplicate = input_fixture(false, Cohort::CheckedHandoff5b3);
        duplicate.name = "duplicate-definitions.o".into();
        let mut with_duplicate = Vec::from(members);
        with_duplicate.push(duplicate);
        assert!(defining_members(&with_duplicate).is_err());
    }
    #[test]
    fn ordinary44_live_selection_refuses_missing_duplicate_names_and_unknown_shape() {
        assert!(defining_members(&[]).is_err());
        let owner = input_fixture(false, Cohort::LegacyE3);
        assert!(defining_members(&[owner]).is_err());
        let mut owner = input_fixture(false, Cohort::LegacyE3);
        let mut page = input_fixture(true, Cohort::LegacyE3);
        page.name = owner.name.clone();
        assert!(defining_members(&[owner, page]).is_err());
        owner = input_fixture(false, Cohort::CheckedHandoff5b3);
        put(&mut owner.bytes, 0x6000 + 2 * 64 + 32, 290, 8);
        let object = ObjectInput {
            archive_path: Path::new("/not-authority.a"),
            member_name: &owner.name,
            ordinal: owner.ordinal,
            header_offset: owner.header,
            bytes: &owner.bytes,
            elf: Elf::parse(&owner.bytes).unwrap(),
        };
        assert!(closed_input_shape(&object).is_err());
    }
    fn displaced_fixture() -> (Vec<u8>, OrdinaryGateObservations) {
        let (mut raw, mut role) = fixture();
        role.cohort = Cohort::CheckedHandoff5b3;
        role.entry = role.cohort.entry(role.contribution).unwrap();
        raw[0x2000..0x202c].fill(0);
        raw[0x2070..0x209c].copy_from_slice(&BODY);
        put(&mut raw, 0x4000, role.entry, 8);
        put(&mut raw, 0x6000 + 2 * 64 + 32, 289, 8);
        for index in [3, 4, 5] {
            let at = 0x5400 + index * 24 + 8;
            let old = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
            put(&mut raw, at, old + 112, 8);
        }
        let strings_end = u64::from_le_bytes(
            raw[0x6000 + 3 * 64 + 32..0x6000 + 3 * 64 + 40]
                .try_into()
                .unwrap(),
        ) as usize;
        let mut strings = raw[0x5000..0x5000 + strings_end].to_vec();
        for (i, name, kind, value, size) in [
            (7, "fallback_entry", 2, role.contribution, 48),
            (
                8,
                "fallback_completion_syscall",
                0,
                role.contribution + 44,
                0,
            ),
            (
                9,
                "fallback_completion_return",
                0,
                role.contribution + 46,
                0,
            ),
            (
                10,
                "reverie_native_launch_syscall",
                2,
                role.contribution + 48,
                55,
            ),
        ] {
            let at = 0x5400 + i * 24;
            put(&mut raw, at, strings.len() as u64, 4);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            raw[at + 4] = kind;
            raw[at + 5] = 2;
            put(&mut raw, at + 6, 2, 2);
            put(&mut raw, at + 8, value, 8);
            put(&mut raw, at + 16, size, 8);
        }
        raw[0x5000..0x5000 + strings.len()].copy_from_slice(&strings);
        put(&mut raw, 0x6000 + 3 * 64 + 32, strings.len() as u64, 8);
        put(&mut raw, 0x6000 + 4 * 64 + 32, 11 * 24, 8);
        put(&mut raw, 0x6000 + 4 * 64 + 44, 11, 4);
        (raw, role)
    }
    #[test]
    fn ordinary44_displaced_final_keeps_boundary_distinct_and_rejects_confusion() {
        let (raw, role) = displaced_fixture();
        role.verify_final_shape(&Elf::parse(&raw).unwrap(), &raw)
            .unwrap();
        role.verify_slot_shape(&Elf::parse(&raw).unwrap(), &raw, GATE + 0x3000)
            .unwrap();
        for (at, value, width) in [
            (0x5400 + 6 * 24 + 8, role.entry, 8), // PAGE_END is not OWNER.
            (0x5400 + 2 * 24 + 8, role.entry, 8), // SECTION remains at base.
            (0x5400 + 3 * 24 + 8, role.contribution, 8),
            (0x5400 + 4 * 24 + 8, role.entry + 31, 8),
            (0x5400 + 7 * 24 + 16, 113, 8), // Fallback must not overlap role.
            (0x5400 + 8 * 24 + 8, role.contribution + 45, 8),
            (0x6000 + 2 * 64 + 16, role.entry, 8),
            (0x2070, u64::from(raw[0x2070] ^ 1), 1),
        ] {
            let mut bad = raw.clone();
            put(&mut bad, at, value, width);
            assert!(
                role.verify_final_shape(&Elf::parse(&bad).unwrap(), &bad)
                    .is_err(),
                "field {at}"
            );
        }
        for wrong in [role.contribution, role.entry + 1, role.entry + 32] {
            let mut bad = raw.clone();
            put(&mut bad, 0x4000, wrong, 8);
            assert!(
                role.verify_slot_shape(&Elf::parse(&bad).unwrap(), &bad, GATE + 0x3000)
                    .is_err()
            );
        }
        let mut wrong_role = role;
        wrong_role.cohort = Cohort::LegacyE3;
        assert!(
            wrong_role
                .verify_final_shape(&Elf::parse(&raw).unwrap(), &raw)
                .is_err()
        );
    }
    #[test]
    fn ordinary44_closed_offsets_and_checked_entry_refuse_overflow() {
        assert_eq!(Cohort::LegacyE3.entry(0x2000).unwrap(), 0x2000);
        assert_eq!(Cohort::CheckedHandoff5b3.entry(0x2000).unwrap(), 0x2070);
        assert_eq!(
            Cohort::CheckedHandoff5b3.entry(u64::MAX - 112).unwrap(),
            u64::MAX
        );
        assert_eq!(
            Cohort::CheckedHandoff5b3.entry(u64::MAX - 111).unwrap_err(),
            "ordinary entry overflow"
        );
        let (raw, mut role) = displaced_fixture();
        role.contribution = u64::MAX - 111;
        assert!(
            role.verify_final_shape(&Elf::parse(&raw).unwrap(), &raw)
                .is_err()
        );
    }
}
