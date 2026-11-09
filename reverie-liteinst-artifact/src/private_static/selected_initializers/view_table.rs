//! One complete conditional View::table leaf, with the existing source owner.
//! This is not generic transfer acceptance or physical entry authority.
//! ## Actual finite form and exact output
//!
//! The retained full body is 146 bytes, SHA `f383abb0155f24095be7cccf62043c1fc2b63af39594cb31834debe6e627a19d`. It is an entire input function/section, with no input relocation fields and no retained final relocation field in the body. Its complete final bytes equal the input bytes. There are no calls, indirect branches, loops, TLS/FS references, syscalls, division, panic path or UD2. Every conditional branch targets the one error epilogue at +0x83; the two RET instructions end the complete extent at +0x82 and +0x91.
//!
//! Let `i` be RDX at entry, `b` the actual backing pointer in View, and `n` its represented backing length. RDI points to the actual 24-byte return buffer; RSI points to this compiler's actual View representation. Define the three LE descriptor words at backing byte offsets `648+24i`, `656+24i`, `664+24i` as `(offset,count,stride)`. No Rust-reference or enum cast is involved in this numeric statement.
//!
//! Under the actual memory/ABI/entry preconditions below, normal return has exactly these alternatives:
//!
//! - **Bounds error niche:** output word0 is zero; output byte8 is 2 (`Error::Bounds` in this actual body). Bytes9..23 and all other uninitialized padding are unspecified, not zeroed. RAX returns the output-buffer pointer. No Records payload may be read as initialized.
//! - **Success niche:** output word0 is the nonnull actual pointer `b+offset`, word1 is the exact non-overflowing unsigned product `count*stride`, and word2 is `stride>0`. `offset+word1` does not overflow and is <=n. RAX returns the output-buffer pointer. These three words initialize the whole 24-byte Records payload.
//!
//! A zero-length table is valid. `count=0,stride>0,offset=n` returns a valid empty slice at the allocation's one-past pointer. Neither `word1>0` nor `offset+word1<n` is required. Zero stride refuses even when count=0. The actual machine ABI is a **pointer niche at output word0**, not the site's byte24 discriminator and not RAX as a result tag. This observation does not stabilize Rust ABI for other compiler cohorts.
//!
//! ## Complete finite block argument
//!
//! All ranges below are entry-relative, start-inclusive/end-exclusive. Every instruction is retained in the proposed exact form; a changed opcode or operand refuses.
//!
//! | Range | Effect |
//! | --- | --- |
//! | `00..06` | Unsigned index >=9 branches to +83. Otherwise i<=8. |
//! | `06..3c` | Read View length. Compute 24i using shift/LEA; bounded i means these arithmetic operations cannot overflow. Check each descriptor word's last byte (`655+24i`, `663+24i`, `671+24i`) is <n before reading the backing pointer or descriptor values. Each failure branches to +83. |
//! | `3c..57` | Read stride and count; unsigned MUL computes count*stride and checks OF (equivalently nonzero high half). Overflow branches to +83. Keep exact product in RAX. |
//! | `57..71` | Read offset and compute offset+product with carry check. Reject end>n, accept end==n. Reject stride=0. Every failure branches to +83. |
//! | `71..83` | Form b+offset, store pointer/product/stride at output0/8/16, return RDI in RAX and RET. Live valid backing plus offset<=end<=n implies pointer arithmetic remains inside or one-past the same allocation and cannot produce null. |
//! | `83..92` | Write only error byte2 at output+8 and zero word at output+0, return RDI in RAX and RET. No Records stride/padding is asserted initialized. |
//!
//! The source path is the actual Cargo-selected `reverie-loader/src/handoff.rs` (runtime SHA `85e0f1cb9393c1ed11db4d6115f81dbce5d3f0afcfc733aa4d0cd2d6725245c7`): View at :248, Records/NonZeroUsize at :178–187, and table at :475–491. A valid Rust View is a stronger input condition than just arbitrary bytes; this proof does not forge one or claim View::parse was called.
//!
//!
//! ## Memory, return and caller conditions still missing
//!
//! The View representation and represented backing allocation must be real, live, readable, immutable, non-wrapping and from this exact compiler ABI. The return buffer must be a live aligned writable 24-byte region disjoint from View, its entire backing, code and the actual return slot. The actual caller must enter at the observed function start with the proper registers, valid stack/return address, and unchanged callee-saved state. The actual loader must enforce code/segment immutability and physical mapping identity; ELF PF_X metadata alone is not a kernel readback. External signals/handlers must preserve or terminally refuse correctly; this leaf does not exempt asynchronous closure.
//!
//! Before consuming the numeric Records facts in a caller proof, join the actual call/RET edge, return-buffer location, niche load and branch, all intervening writes/clobbers, and the same live immutable backing. The zero/error branch must not read word2 or uninitialized error padding. The nonzero/success branch can rely on nonzero stride and checked product/slice bounds only after those joins. Nothing here proves arbitrary pointers from serialized records are actual mappings or source-qualified IPs.
use super::*;

const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_4View5table";
const BOOTSTRAP_SYMBOL: &str = "_RNvMs2_NtCs_14reverie_loader7handoffNtB5_4View5table";
const SOURCE: &str = "reverie-loader/src/handoff.rs";
const SOURCE_SHA: &str = "85e0f1cb9393c1ed11db4d6115f81dbce5d3f0afcfc733aa4d0cd2d6725245c7";
// Declared whole-file source cohort: the additive numeric serializer leaves all
// existing accessor definitions and prerequisites unchanged. Actual source-owned
// member, complete machine form and final relocation checks remain mandatory.
const SERIALIZER_SOURCE_SHA: &str =
    "e8b70072083fc78771ecc405433a47254de01d2ea7d4dc0e5368ab0bfe8e4ccf";
// Additive Bootstrap projection and data tests leave the original View/Records
// definitions unchanged. This source identity never replaces machine checks.
const BOOTSTRAP_SOURCE_SHA: &str =
    "85abd905256f3bc5b526840cf3cd5e090238e4aa770f03d320c2ae907ee7ae75";
const SIZE: usize = 146;
const LIMIT: u64 = 128 * 1024 * 1024;
// The complete block argument above covers every byte. There is no legitimate
// relocation operand, instruction mask or indirect-transfer exception here.
const INPUT: [u8; SIZE] = [
    0x48, 0x83, 0xfa, 0x09, 0x73, 0x7d, 0x4c, 0x8b, 0x46, 0x08, 0x48, 0xc1, 0xe2, 0x03, 0x48, 0x8d,
    0x04, 0x52, 0x48, 0x05, 0x8f, 0x02, 0x00, 0x00, 0x4c, 0x39, 0xc0, 0x73, 0x66, 0x4c, 0x8d, 0x0c,
    0x52, 0x49, 0x8d, 0x81, 0x97, 0x02, 0x00, 0x00, 0x4c, 0x39, 0xc0, 0x73, 0x56, 0x49, 0x8d, 0x81,
    0x9f, 0x02, 0x00, 0x00, 0x4c, 0x39, 0xc0, 0x73, 0x4a, 0x48, 0x8b, 0x36, 0x49, 0x8d, 0x91, 0x90,
    0x02, 0x00, 0x00, 0x49, 0x8d, 0x81, 0x98, 0x02, 0x00, 0x00, 0x48, 0x8b, 0x0c, 0x06, 0x48, 0x89,
    0xc8, 0x48, 0xf7, 0x24, 0x16, 0x70, 0x2c, 0x4a, 0x8b, 0x94, 0x0e, 0x88, 0x02, 0x00, 0x00, 0x49,
    0x89, 0xc1, 0x49, 0x01, 0xd1, 0x72, 0x1c, 0x4d, 0x39, 0xc1, 0x77, 0x17, 0x48, 0x85, 0xc9, 0x74,
    0x12, 0x48, 0x01, 0xd6, 0x48, 0x89, 0x37, 0x48, 0x89, 0x47, 0x08, 0x48, 0x89, 0x4f, 0x10, 0x48,
    0x89, 0xf8, 0xc3, 0xc6, 0x47, 0x08, 0x02, 0x48, 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89,
    0xf8, 0xc3,
];

fn source_digest(digest: &str) -> Result<()> {
    require(
        digest == SOURCE_SHA || digest == SERIALIZER_SOURCE_SHA || digest == BOOTSTRAP_SOURCE_SHA,
        "View::table complete runtime source differs",
    )
}
// The complete retained source digest chooses one canonical role, never a union.
fn source_symbol(digest: &str) -> Result<&'static str> {
    source_digest(digest)?;
    Ok(if digest == BOOTSTRAP_SOURCE_SHA {
        BOOTSTRAP_SYMBOL
    } else {
        SYMBOL
    })
}
fn code_form(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "View::table finite complete form differs",
    )
}
fn selected_name(name: &str, expected_symbol: &str) -> bool {
    canonical_rust_symbol(name).as_deref() == Some(expected_symbol)
}
pub(super) fn bounded(file: &FileIdentity) -> Result<Vec<u8>> {
    use std::io::Read;
    require(
        fs::metadata(&file.path).map_err(|e| e.to_string())?.len() <= LIMIT,
        "View::table ELF/map exceeds 128MiB bound",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(&file.path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 <= LIMIT,
        "View::table ELF/map grew beyond bound",
    )?;
    Ok(bytes)
}

/// Private-construction conditional result-niche observation. The entire
/// Records memory/caller contract documented above remains an unproved precondition.
/// No Clone, Deserialize, Ready conversion, mapping or execution method exists.
#[derive(Debug, Serialize)]
pub struct ViewTableLeafObservation {
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
impl ViewTableLeafObservation {
    /// Actual complete function entry; this does not authorize calling it.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    fn require_owner(&self, source: &VerifiedStaticSource, archive: &StaticArchive) -> Result<()> {
        require(
            Arc::ptr_eq(&self.owner.0, &source.archive_owner)
                && self.runtime_archive == archive.file,
            "View::table observation belongs to another source/archive",
        )
    }
}
/// Compiled checker identity for the existing source catalog.
pub fn view_table_implementation_sha256() -> String {
    sha256(include_bytes!("view_table.rs"))
}

// Closed internal policy only; callers cannot supply names, forms or sizes.
#[derive(Clone, Copy)]
pub(super) enum PlainLeafKind {
    ViewTable,
    BootstrapRole,
}
impl PlainLeafKind {
    fn size(self) -> usize {
        match self {
            Self::ViewTable => SIZE,
            Self::BootstrapRole => super::bootstrap_role::SIZE,
        }
    }
    fn symbol(self, digest: &str) -> Result<&'static str> {
        match self {
            Self::ViewTable => source_symbol(digest),
            Self::BootstrapRole => super::bootstrap_role::source_symbol(digest),
        }
    }
    fn named(self, name: &str, expected: &str) -> bool {
        match self {
            Self::ViewTable => selected_name(name, expected),
            Self::BootstrapRole => super::bootstrap_role::selected_name(name, expected),
        }
    }
    fn form(self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::ViewTable => code_form(bytes),
            Self::BootstrapRole => super::bootstrap_role::code_form(bytes),
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::ViewTable => {
                "CONDITIONAL_RECORDS_NICHE_ONLY_PHYSICAL_CALL_PRECONDITIONS_NOT_PROVEN"
            }
            Self::BootstrapRole => {
                "CONDITIONAL_ROLE_RESULT_ONLY_PHYSICAL_CALL_PRECONDITIONS_NOT_PROVEN"
            }
        }
    }
}

#[cfg(test)]
fn input(object: &ObjectInput<'_>, symbol: &sym::Sym, name: &str) -> Result<()> {
    input_for(PlainLeafKind::ViewTable, object, symbol, name)
}
fn input_for(
    kind: PlainLeafKind,
    object: &ObjectInput<'_>,
    symbol: &sym::Sym,
    name: &str,
) -> Result<()> {
    require(
        object.member_name.starts_with("reverie_loader-")
            && symbol.st_type() == sym::STT_FUNC
            && symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_other == 0
            && symbol.st_value == 0
            && symbol.st_size == kind.size() as u64,
        "View::table sole definition has wrong physical owner/shape",
    )?;
    let section = object
        .elf
        .section_headers
        .get(symbol.st_shndx)
        .ok_or("View::table section absent")?;
    require(
        section.sh_type == section_header::SHT_PROGBITS
            && section.sh_flags == 6
            && section.sh_size == kind.size() as u64
            && section.sh_addralign == 16
            && object.elf.shdr_strtab.get_at(section.sh_name)
                == Some(format!(".text.{name}").as_str()),
        "View::table complete input section geometry differs",
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
            require(
                s.st_bind() == sym::STB_LOCAL
                    && s.st_other == 0
                    && s.st_value == 0
                    && s.st_size == 0
                    && object.elf.strtab.get_at(s.st_name) == Some(""),
                "View::table input section alias differs",
            )?;
            sections += 1;
        } else {
            require(
                s == *symbol && object.elf.strtab.get_at(s.st_name) == Some(name),
                "View::table unexpected input alias",
            )?;
            functions += 1;
        }
    }
    require(
        functions == 1 && sections == 1,
        "View::table input symbol census differs",
    )?;
    kind.form(section_file_bytes(section, object.bytes)?)?;
    let table = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, table)?;
    for (index, rows) in &object.elf.shdr_relocs {
        let rs = checked_relocation_section(&object.elf, object.bytes, *index, table, rows.len())?;
        require(
            rs.sh_info as usize != symbol.st_shndx || rows.is_empty(),
            "View::table has unexpected input relocation",
        )?;
    }
    Ok(())
}
pub(super) fn refuse_writer(
    target: &section_header::SectionHeader,
    offset: u64,
    kind: u32,
    begin: u64,
    end: u64,
) -> Result<()> {
    // Includes nominal no-op records in the body: the finite typed census is
    // empty, not merely 'no known 4-byte writer'. Unknown/crossing widths use
    // the existing conservative overlap rule without an invented maximum.
    require(
        !(begin <= offset && offset < end)
            && !selected_field_overlap(target, offset, kind, begin, end)?,
        "View::table has unexpected final relocation",
    )
}
// Preserve the original legacy fixture entry; production passes its source choice.
#[cfg(test)]
fn final_body<'a>(elf: &Elf<'_>, bytes: &'a [u8], entry: u64, name: &str) -> Result<&'a [u8]> {
    final_body_with_symbol(elf, bytes, entry, name, SYMBOL)
}
#[cfg(test)]
fn final_body_with_symbol<'a>(
    elf: &Elf<'_>,
    bytes: &'a [u8],
    entry: u64,
    name: &str,
    expected_symbol: &str,
) -> Result<&'a [u8]> {
    final_body_for(
        PlainLeafKind::ViewTable,
        elf,
        bytes,
        entry,
        name,
        expected_symbol,
    )
}
fn final_body_for<'a>(
    kind: PlainLeafKind,
    elf: &Elf<'_>,
    bytes: &'a [u8],
    entry: u64,
    name: &str,
    expected_symbol: &str,
) -> Result<&'a [u8]> {
    static_image_metadata(elf, bytes)?;
    let table = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, table)?;
    let names = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx != 0
                && elf
                    .strtab
                    .get_at(s.st_name)
                    .is_some_and(|name| kind.named(name, expected_symbol))
        })
        .collect::<Vec<_>>();
    require(
        names.len() == 1 && elf.strtab.get_at(names[0].st_name) == Some(name),
        "View::table final definition absent/ambiguous/different",
    )?;
    let symbol = names[0];
    require(
        symbol.st_type() == sym::STT_FUNC
            && symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_other == 0
            && symbol.st_value == entry
            && symbol.st_size == kind.size() as u64,
        "View::table final definition/map differs",
    )?;
    let end = entry
        .checked_add(kind.size() as u64)
        .ok_or("View::table extent overflow")?;
    let (load, offset) = unique_file_mapping(elf, bytes, entry, kind.size())?;
    let section = elf
        .section_headers
        .get(symbol.st_shndx)
        .ok_or("View::table final section absent")?;
    require(
        load.p_flags == 5
            && section.sh_type == section_header::SHT_PROGBITS
            && section.sh_flags == 6
            && section.sh_addr <= entry
            && section
                .sh_addr
                .checked_add(section.sh_size)
                .is_some_and(|limit| end <= limit)
            && section.sh_offset.checked_add(entry - section.sh_addr) == Some(offset as u64),
        "View::table final immutable RX geometry differs",
    )?;
    let mut functions = 0;
    for s in elf.syms.iter().filter(|s| s.st_shndx != 0) {
        let limit = s
            .st_value
            .checked_add(s.st_size)
            .ok_or("View::table alias extent overflow")?;
        let overlaps = if s.st_size == 0 {
            entry <= s.st_value && s.st_value < end
        } else {
            s.st_value < end && entry < limit
        };
        if !overlaps {
            continue;
        }
        if s.st_type() == sym::STT_SECTION {
            require(
                s.st_shndx == symbol.st_shndx
                    && s.st_bind() == sym::STB_LOCAL
                    && s.st_other == 0
                    && s.st_size == 0
                    && s.st_value == section.sh_addr
                    && elf.strtab.get_at(s.st_name) == Some(""),
                "View::table unexpected final section alias",
            )?;
        } else {
            require(s == symbol, "View::table unexpected final alias")?;
            functions += 1;
        }
    }
    require(functions == 1, "View::table final symbol census differs")?;
    for (index, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *index, table, rows.len())?;
        for r in rows.iter() {
            checked_relocation_span(elf, rs, r.r_offset, r.r_type)?;
            refuse_writer(
                &elf.section_headers[rs.sh_info as usize],
                r.r_offset,
                r.r_type,
                entry,
                end,
            )?;
        }
    }
    bytes
        .get(
            offset
                ..offset
                    .checked_add(kind.size())
                    .ok_or("View::table file extent overflow")?,
        )
        .ok_or_else(|| "View::table final file range absent".into())
}

// Borrowed lexical inputs only: these cannot outlive this actual transaction.
// No public constructor, owner conversion or serialization exists.
pub(super) struct LeafObjects<'a, 'data> {
    pub(super) source: &'a FileIdentity,
    pub(super) expected_symbol: &'static str,
    pub(super) objects: &'a [ObjectInput<'data>],
}

impl VerifiedStaticSource {
    /// Inspect one source-owned finite table leaf in the existing actual link
    /// transaction. Result-niche claims are conditional on valid immutable View
    /// backing, disjoint writable 24-byte output, actual ABI, entry/return and
    /// signal-state preconditions. This is not a parsed-View or Ready producer.
    /// Every admitted Result path closes the existing complete producer ledger,
    /// archive including build outputs, source/ELF/map files and source guard.
    pub fn with_view_table_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        callback: impl FnOnce(&ViewTableLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_plain_leaf(
            PlainLeafKind::ViewTable,
            archive,
            definitions,
            (artifact, link_map),
            runner,
            |identity, runner| callback(&identity, runner),
        )
    }
    pub(super) fn with_plain_leaf<T>(
        &self,
        kind: PlainLeafKind,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        outputs: (&FileIdentity, &FileIdentity),
        runner: &mut Runner,
        callback: impl FnOnce(ViewTableLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_leaf_objects(
            archive,
            definitions,
            outputs,
            runner,
            |digest| kind.symbol(digest),
            |leaves, runner| {
                let (artifact, link_map) = outputs;
                let source = leaves.source;
                let expected_symbol = leaves.expected_symbol;
                let objects = leaves.objects;
                let mut selected = Vec::new();
                for (i, o) in objects.iter().enumerate() {
                    for s in o.elf.syms.iter().filter(|s| s.st_shndx != 0) {
                        let name = o
                            .elf
                            .strtab
                            .get_at(s.st_name)
                            .ok_or("View::table symbol name absent")?;
                        if kind.named(name, expected_symbol) {
                            selected.push((i, s));
                        }
                    }
                }
                require(
                    selected.len() == 1,
                    "View::table definition absent/ambiguous across actual archive",
                )?;
                let (i, s) = selected[0];
                let object = &objects[i];
                let name = object
                    .elf
                    .strtab
                    .get_at(s.st_name)
                    .ok_or("View::table name absent")?;
                input_for(kind, object, &s, name)?;
                let map = bounded(link_map)?;
                let map = std::str::from_utf8(&map).map_err(|e| e.to_string())?;
                let entry = mapped_section(map, object, s.st_shndx)?;
                let bytes = bounded(artifact)?;
                let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
                let body = final_body_for(kind, &elf, &bytes, entry, name, expected_symbol)?;
                let original =
                    section_file_bytes(&object.elf.section_headers[s.st_shndx], object.bytes)?;
                // Reuse the common whole-byte immutable-RX join with precisely ZERO
                // legitimate fields, after complete input/final typed inventories.
                join_relocated_body(&elf, &bytes, entry, original, body, &[], &[])?;
                let observation = ViewTableLeafObservation {
                    owner: DefinitionSourceOwner(self.archive_owner.clone()),
                    runtime_archive: archive.file.clone(),
                    artifact: artifact.clone(),
                    link_map: link_map.clone(),
                    source: source.clone(),
                    member_name: object.member_name.to_owned(),
                    member_ordinal: object.ordinal,
                    member_header: object.header_offset,
                    member_sha256: sha256(object.bytes),
                    input_section: s.st_shndx,
                    entry,
                    body_sha256: sha256(body),
                    scope: kind.scope(),
                };
                observation.require_owner(self, archive)?;
                callback(observation, runner)
            },
        )
    }

    // Private custody/physical-object transaction, with no public policy or
    // construction authority. Exact machine/table predicates remain in callers.
    pub(super) fn with_leaf_objects<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        outputs: (&FileIdentity, &FileIdentity),
        runner: &mut Runner,
        select_symbol: impl FnOnce(&str) -> Result<&'static str>,
        callback: impl FnOnce(LeafObjects<'_, '_>, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        let (artifact, link_map) = outputs;
        let admission = self
            .require_archive_owner(archive)
            .and_then(|()| {
                selected_owner_identity(
                    &self.archive_owner,
                    &archive.file,
                    &definitions.source_owner,
                    &definitions.core,
                )
            })
            .and_then(|()| {
                require(
                    definitions.core.artifact == *artifact && definitions.core.map == *link_map,
                    "View::table definitions belong to another ELF/map",
                )
            });
        if let Err(e) = admission {
            return close_result(Err(e), self.guard.close(runner));
        }
        let mut files = vec![artifact.clone(), link_map.clone()];
        let result = (|| {
            archive.verify()?;
            definitions.verify()?;
            self.guard.close(runner)?;
            for f in &files {
                f.verify()?;
            }
            let roots = self
                .guard
                .roots
                .iter()
                .filter(|(_, k)| matches!(k, RootBinding::Cargo(_)))
                .map(|(p, _)| p)
                .collect::<Vec<_>>();
            require(roots.len() == 1, "View::table resolved source ambiguous")?;
            let source = FileIdentity::read(&roots[0].join(SOURCE))?;
            files.push(source.clone());
            let expected_symbol = select_symbol(&source.sha256)?;
            let members = extract_objects(&archive.file, 0)?;
            let mut objects = Vec::new();
            for m in &members {
                let elf = Elf::parse(&m.bytes).map_err(|e| e.to_string())?;
                require(
                    elf.header.e_type == header::ET_REL
                        && elf.header.e_machine == header::EM_X86_64
                        && elf.is_64
                        && elf.little_endian,
                    "View::table member is not x86_64 LE relocatable",
                )?;
                checked_object_symbol_authority(&elf, &m.bytes)?;
                objects.push(ObjectInput {
                    archive_path: &archive.file.path,
                    member_name: &m.name,
                    ordinal: m.ordinal,
                    header_offset: m.header,
                    bytes: &m.bytes,
                    elf,
                });
            }
            callback(
                LeafObjects {
                    source: &source,
                    expected_symbol,
                    objects: &objects,
                },
                runner,
            )
        })();
        let mut errors = Vec::new();
        if let Err(e) = definitions.verify() {
            errors.push(e);
        }
        if let Err(e) = archive.verify() {
            errors.push(e);
        }
        for f in &files {
            if let Err(e) = f.verify() {
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
pub(crate) fn check_plain_input_fixture(bytes: &[u8], name: &str) -> Result<()> {
    let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
    let symbol = elf.syms.get(2).ok_or("role unit symbol")?;
    let object = ObjectInput {
        archive_path: Path::new("/unit/not-authority.a"),
        member_name: "reverie_loader-unit.o",
        ordinal: 0,
        header_offset: 8,
        bytes,
        elf,
    };
    input_for(PlainLeafKind::BootstrapRole, &object, &symbol, name)
}
#[cfg(test)]
pub(crate) fn check_plain_final_fixture(bytes: &[u8], name: &str) -> Result<()> {
    let elf = Elf::parse(bytes).map_err(|e| e.to_string())?;
    let body = final_body_for(
        PlainLeafKind::BootstrapRole,
        &elf,
        bytes,
        0x100000,
        name,
        super::bootstrap_role::SYMBOL,
    )?;
    PlainLeafKind::BootstrapRole.form(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    const NAME: &str = "_RNvMs1_NtCsunit_14reverie_loader7handoffNtB5_4View5table";
    const ENTRY: u64 = 0x100000;
    fn p16(b: &mut [u8], i: usize, n: u16) {
        b[i..i + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn p32(b: &mut [u8], i: usize, n: u32) {
        b[i..i + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn p64(b: &mut [u8], i: usize, n: u64) {
        b[i..i + 8].copy_from_slice(&n.to_le_bytes());
    }
    fn fixture(linked: bool, writer: bool, alias: bool) -> Vec<u8> {
        plain_fixture(linked, writer, alias, NAME, &INPUT)
    }
    pub(crate) fn plain_fixture(
        linked: bool,
        writer: bool,
        alias: bool,
        name: &str,
        code: &[u8],
    ) -> Vec<u8> {
        let size = code.len();
        // A small parsed-ELF structural fixture, not a compiled member/source
        // positive. No private build paths or fabricated owner records occur.
        let mut b = vec![0; 0x3000];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        p16(&mut b, 16, if linked { 2 } else { 1 });
        p16(&mut b, 18, 62);
        p32(&mut b, 20, 1);
        p16(&mut b, 52, 64);
        p16(&mut b, 58, 64);
        p16(&mut b, 60, if writer { 6 } else { 5 });
        p16(&mut b, 62, 4);
        p64(&mut b, 40, 0x2800);
        let file = if linked { 0x1000 } else { 0x100 };
        let address = if linked { ENTRY } else { 0 };
        if linked {
            p64(&mut b, 32, 64);
            p16(&mut b, 54, 56);
            p16(&mut b, 56, 1);
            p32(&mut b, 64, 1);
            p32(&mut b, 68, 5);
            p64(&mut b, 72, file);
            p64(&mut b, 80, ENTRY);
            p64(&mut b, 88, ENTRY);
            p64(&mut b, 96, size as u64);
            p64(&mut b, 104, size as u64);
            p64(&mut b, 112, 4096);
        }
        b[file as usize..file as usize + size].copy_from_slice(code);
        let strings = format!("\0{name}\0");
        b[0x2300..0x2300 + strings.len()].copy_from_slice(strings.as_bytes());
        let text = format!(".text.{name}");
        let names = format!("\0{text}\0.symtab\0.strtab\0.shstrtab\0.rela.text\0");
        b[0x2400..0x2400 + names.len()].copy_from_slice(names.as_bytes());
        let name_index = |n: &str| names.find(n).unwrap() as u32;
        {
            let mut section = |i: usize,
                               name: &str,
                               kind: u32,
                               flags: u64,
                               addr: u64,
                               off: u64,
                               size: u64,
                               align: u64,
                               link: u32,
                               info: u32,
                               entry: u64| {
                let s = 0x2800 + i * 64;
                p32(&mut b, s, name_index(name));
                p32(&mut b, s + 4, kind);
                p64(&mut b, s + 8, flags);
                p64(&mut b, s + 16, addr);
                p64(&mut b, s + 24, off);
                p64(&mut b, s + 32, size);
                p32(&mut b, s + 40, link);
                p32(&mut b, s + 44, info);
                p64(&mut b, s + 48, align);
                p64(&mut b, s + 56, entry);
            };
            section(1, &text, 1, 6, address, file, size as u64, 16, 0, 0, 0);
            section(
                2,
                ".symtab",
                2,
                0,
                0,
                0x2200,
                if alias { 96 } else { 72 },
                8,
                3,
                2,
                24,
            );
            section(
                3,
                ".strtab",
                3,
                0,
                0,
                0x2300,
                strings.len() as u64,
                1,
                0,
                0,
                0,
            );
            section(
                4,
                ".shstrtab",
                3,
                0,
                0,
                0x2400,
                names.len() as u64,
                1,
                0,
                0,
                0,
            );
            if writer {
                section(5, ".rela.text", 4, 0, 0, 0x2500, 24, 8, 2, 1, 24);
            }
        } // End the section writer borrow before populating symbols.
        b[0x221c] = 3;
        p16(&mut b, 0x221e, 1);
        p64(&mut b, 0x2220, address);
        p32(&mut b, 0x2230, 1);
        b[0x2234] = 0x12;
        p16(&mut b, 0x2236, 1);
        p64(&mut b, 0x2238, address);
        p64(&mut b, 0x2240, size as u64);
        if alias {
            p32(&mut b, 0x2248, 1);
            b[0x224c] = 0x10;
            p16(&mut b, 0x224e, 1);
            p64(&mut b, 0x2250, address + 1);
        }
        if writer {
            p64(&mut b, 0x2500, address);
            p64(&mut b, 0x2508, (1u64 << 32) | 2);
        }
        b
    }
    fn input_fixture(b: &[u8]) -> Result<()> {
        let elf = Elf::parse(b).map_err(|e| e.to_string())?;
        let s = elf.syms.get(2).ok_or("unit symbol")?;
        let object = ObjectInput {
            archive_path: Path::new("/unit/not-authority.a"),
            member_name: "reverie_loader-unit.o",
            ordinal: 0,
            header_offset: 8,
            bytes: b,
            elf,
        };
        input(&object, &s, NAME)
    }
    #[test]
    fn view_table_complete_form_refuses_every_changed_byte_and_extent() {
        code_form(&INPUT).unwrap();
        assert!(code_form(&INPUT[..SIZE - 1]).is_err());
        for i in 0..SIZE {
            let mut b = INPUT;
            b[i] ^= 1;
            assert!(code_form(&b).is_err(), "byte {i}");
        }
    }
    #[test]
    fn view_table_niche_bounds_product_end_and_nonzero_guards_are_exact() {
        // Index bound; MUL overflow; end carry/bound; nonzero stride; the success
        // word stores; and BOTH error niche/error-byte stores are retained.
        for i in [3, 0x55, 0x65, 0x6a, 0x6f, 0x74, 0x77, 0x7b, 0x86, 0x8a] {
            let mut b = INPUT;
            b[i] ^= 1;
            assert!(code_form(&b).is_err(), "guard/store {i:x}");
        }
        // The actual end guard is JA (not JAE), preserving valid empty tables
        // and end==len. This test does not simulate a runtime Records value.
        assert_eq!(&INPUT[0x6a..0x6c], &[0x77, 0x17]);
        assert_eq!(
            &INPUT[0x83..0x8e],
            &[0xc6, 0x47, 0x08, 0x02, 0x48, 0xc7, 0x07, 0, 0, 0, 0]
        );
    }
    #[test]
    fn view_table_parsed_input_geometry_alias_and_writer_controls() {
        input_fixture(&fixture(false, false, false)).unwrap();
        assert!(input_fixture(&fixture(false, false, true)).is_err());
        assert!(input_fixture(&fixture(false, true, false)).is_err());
        let mut b = fixture(false, false, false);
        p64(&mut b, 0x2800 + 64 + 32, SIZE as u64 + 1);
        assert!(input_fixture(&b).is_err());
        let mut b = fixture(false, false, false);
        b[0x2235] = 2;
        assert!(input_fixture(&b).is_err());
    }
    #[test]
    fn view_table_parsed_final_whole_body_geometry_alias_and_writer_controls() {
        let b = fixture(true, false, false);
        let e = Elf::parse(&b).unwrap();
        let body = final_body(&e, &b, ENTRY, NAME).unwrap();
        join_relocated_body(&e, &b, ENTRY, &INPUT, body, &[], &[]).unwrap();
        for b in [fixture(true, true, false), fixture(true, false, true)] {
            assert!(final_body(&Elf::parse(&b).unwrap(), &b, ENTRY, NAME).is_err());
        }
        let mut b = fixture(true, false, false);
        p32(&mut b, 68, 7);
        assert!(final_body(&Elf::parse(&b).unwrap(), &b, ENTRY, NAME).is_err());
        let mut b = fixture(true, false, false);
        b[0x1000 + 0x6a] = 0x73;
        let e = Elf::parse(&b).unwrap();
        let body = final_body(&e, &b, ENTRY, NAME).unwrap();
        assert!(join_relocated_body(&e, &b, ENTRY, &INPUT, body, &[], &[]).is_err());
    }
    #[test]
    fn view_table_zero_field_inventory_rejects_crossing_unknown_and_noop_records() {
        let b = fixture(true, false, false);
        let e = Elf::parse(&b).unwrap();
        let target = &e.section_headers[1];
        assert!(refuse_writer(target, ENTRY, 2, ENTRY, ENTRY + SIZE as u64).is_err());
        assert!(refuse_writer(target, ENTRY, 0, ENTRY, ENTRY + SIZE as u64).is_err());
        assert!(refuse_writer(target, ENTRY - 1, 2, ENTRY, ENTRY + SIZE as u64).is_err());
        assert!(refuse_writer(target, ENTRY - 1, u32::MAX, ENTRY, ENTRY + SIZE as u64).is_err());
        refuse_writer(target, ENTRY - 8, 1, ENTRY, ENTRY + SIZE as u64).unwrap();
    }
    #[test]
    fn view_table_equal_metadata_is_not_an_archive_source_owner() {
        let owner = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        let other = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        require_same_archive_source(&owner, &owner, "equal", "equal").unwrap();
        assert_eq!(
            require_same_archive_source(&owner, &other, "equal", "equal").unwrap_err(),
            "static archive belongs to another source transaction"
        );
        // No real VerifiedStaticSource/StaticArchive/definition/fact is minted.
        // Actual same-owner success and wrong-owner consumption remain unrun.
    }
    #[test]
    fn view_table_declared_whole_source_cohorts_are_data_only() {
        source_digest(SOURCE_SHA).unwrap();
        source_digest(SERIALIZER_SOURCE_SHA).unwrap();
        // Digest recognition does not construct an owner or prove emitted code.
    }
    #[test]
    fn view_table_source_cohorts_require_complete_exact_digest() {
        for declared in [SOURCE_SHA, SERIALIZER_SOURCE_SHA] {
            for refused in [
                "0".repeat(64),
                declared[..63].to_owned(),
                format!("{declared}0"),
                declared.to_ascii_uppercase(),
                format!("sha256:{declared}"),
            ] {
                assert!(source_digest(&refused).is_err());
            }
            let mut modified = declared.as_bytes().to_vec();
            modified[0] = if modified[0] == b'0' { b'1' } else { b'0' };
            assert!(source_digest(&String::from_utf8(modified).unwrap()).is_err());
        }
    }
    #[test]
    fn view_table_bootstrap_source_cohort_requires_exact_complete_digest() {
        source_digest(BOOTSTRAP_SOURCE_SHA).unwrap();
        // Data recognition neither constructs an owner nor proves new codegen.
        for refused in [
            "0".repeat(64),
            BOOTSTRAP_SOURCE_SHA[..63].to_owned(),
            format!("{BOOTSTRAP_SOURCE_SHA}0"),
            BOOTSTRAP_SOURCE_SHA.to_ascii_uppercase(),
            format!("sha256:{BOOTSTRAP_SOURCE_SHA}"),
        ] {
            assert!(source_digest(&refused).is_err());
        }
        for index in 0..BOOTSTRAP_SOURCE_SHA.len() {
            let mut modified = BOOTSTRAP_SOURCE_SHA.as_bytes().to_vec();
            modified[index] = if modified[index] == b'0' { b'1' } else { b'0' };
            assert!(source_digest(&String::from_utf8(modified).unwrap()).is_err());
        }
    }
    #[test]
    fn view_table_source_symbol_cohorts_do_not_cross() {
        for digest in [SOURCE_SHA, SERIALIZER_SOURCE_SHA] {
            let expected = source_symbol(digest).unwrap();
            assert_eq!(expected, SYMBOL);
            assert!(selected_name(&SYMBOL.replace("Cs_", "Csunit_"), expected));
            assert!(!selected_name(
                &BOOTSTRAP_SYMBOL.replace("Cs_", "Csunit_"),
                expected
            ));
        }
        let expected = source_symbol(BOOTSTRAP_SOURCE_SHA).unwrap();
        assert_eq!(expected, BOOTSTRAP_SYMBOL);
        assert!(selected_name(
            &BOOTSTRAP_SYMBOL.replace("Cs_", "Csunit_"),
            expected
        ));
        assert!(!selected_name(&SYMBOL.replace("Cs_", "Csunit_"), expected));
        for unknown in [
            "0".repeat(64),
            BOOTSTRAP_SOURCE_SHA[..63].to_owned(),
            format!("{BOOTSTRAP_SOURCE_SHA}0"),
        ] {
            assert!(source_symbol(&unknown).is_err());
        }
    }

    #[test]
    fn view_table_source_selected_role_is_exact() {
        let expected = source_symbol(BOOTSTRAP_SOURCE_SHA).unwrap();
        let actual = "_RNvMs2_NtCsiQA3fNasB45_14reverie_loader7handoffNtB5_4View5table";
        assert!(selected_name(actual, expected));
        for wrong in [
            actual.replace("Ms2_", "Ms3_"),
            actual.replace("4View5table", "4View4site"),
            actual.replace("7handoff", "7handofx"),
            format!("{actual}unexpected"),
            actual.replace("CsiQA3fNasB45_", "Cs_"),
        ] {
            assert!(!selected_name(&wrong, expected));
        }
    }
}
