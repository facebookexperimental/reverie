//! Finite conditional contract for one complete source-owned View::site leaf.
//! This is neither generic indirect-transfer acceptance nor startup authority.
//! The following block argument covers every byte of this finite form. Offsets are entry-relative, inclusive block starts and exclusive ends:
//!
//! | Range | Finite effect and exit |
//! | --- | --- |
//! | `000..016` | Read View backing length. Only sufficient header length reaches `022`; otherwise Bounds path. |
//! | `016..022` | Write error byte 2 at output+0 and FF at output+24; return the output pointer. No other error-payload bytes are asserted initialized. |
//! | `022..065` | Read backing pointer and table2's offset/count/stride. Checked unsigned product/addition and range checks plus nonzero stride dominate both DIV instructions. Overflow/zero/out-of-range reaches `016`. |
//! | `065..07f` | Finite 32/64-bit unsigned division selection. High dividend half is cleared; divisor was checked nonzero; quotient fits. No call/TLS/panic or divide trap is introduced. |
//! | `07f..101` | Check stride/row index, multiply/add/shift extents and availability of number/operation fields. Every failure reaches `016`. There are no loops or external calls. |
//! | `101..12f` | Load operation, subtract one, require unsigned result <=3 (including raw zero/underflow refusal). Load syscall number. LEA + MOVSLQ + ADD + JMP uses exactly the four signed relative RO entries above. |
//! | `12f..15b` | Four arms require raw operation/number pairs (1,158), (2,218), (3,7), (4,2). Accepted AL values are respectively 0,1,2,3; mismatch reaches `1a4`. Arm layout order is 1,3,4,2, while table order is 1,2,3,4. |
//! | `15b..17f` | Check IP/post field bounds, read syscall IP. Failures reach `016`. AL remains unchanged. |
//! | `17f..192` | Require IP+2 without unsigned wrap and exact equality to return IP; otherwise `1a4`. AL remains unchanged. |
//! | `192..1a4` | Store the actual IP/post/number at output offsets 0/8/16 and the selected AL at +24; return output pointer. |
//! | `1a4..1b0` | Write error byte 3 at output+0 and FF at output+24; return output pointer. |
//!
//! All direct edges are finite internal block edges. The one indirect jump has precisely the four authenticated internal instruction starts. The complete form contains no CALL, syscall, TLS/FS access, allocation, panic edge or UD2. RET is the ordinary actual caller-return boundary, not a proved arbitrary control-flow target. The resulting conditional fact is specifically: **on normal return, output byte 24 is 0/1/2/3/FF; non-FF is paired with the exact source operation/syscall-number and checked IP+2 equality**. This fact is numeric and tied to this compiled body; it does not declare Rust enum ABI generally stable or authorize a serialized enum cast.
//!
//! ## Preconditions explicitly not proved
//!
//! The real call must enter at this exact entry using this compiler cohort's actual ABI: RDI points to live aligned writable return storage of at least 32 bytes, RSI points to a valid actual View representation, and RDX is the index. View's byte slice must be a live immutable non-wrapping allocation with the represented actual length. View itself and its entire backing storage, code/table and return slot must remain live and satisfy their relevant read/write protections. Return storage must be disjoint from View/backing/code/table so that stores cannot alter future reads. The genuine stack/return address and caller's preserved registers must be valid. The leaf fact does not prove parsed-View provenance, full scalar role validation, syscall IP source identity, actual 0f05 bytes, site uniqueness/coverage, kernel page protections, hardware integrity, signal delivery/restoration, or caller output-buffer identity/byte-load continuation.
//!
//! Errors leave most output payload bytes unspecified. Callers must branch on the actual result discriminator before interpreting Site fields. A follow-up finite caller proof must join its actual call edge, exact return-buffer location, discriminator load, intervening clobbers/stores and the operation jump table. The generic transfer checker remains unchanged until that independent connection is implemented and reviewed. Asynchronous signal entry and every other pre-FS dependency remain required; this leaf never exempts them or grants a no-signal startup model.
use super::*;

mod caller;
pub use caller::ViewSiteInstallerInputs;
pub use caller::ViewSiteInstallerObservation;
pub use caller::view_site_caller_implementation_sha256;

const SYMBOL: &str = "_RNvMs1_NtCs_14reverie_loader7handoffNtB5_4View4site";
const BOOTSTRAP_SYMBOL: &str = "_RNvMs2_NtCs_14reverie_loader7handoffNtB5_4View4site";
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
const CODE_BYTES: usize = 432;
const TABLE_BYTES: usize = 16;
const LEA_FIELD: usize = 289;
const ARMS: [usize; 4] = [303, 336, 316, 326];
const LIMIT: u64 = 128 * 1024 * 1024;

// Every instruction byte is part of this finite reviewed form. The ONLY input
// relocation field is the zero PC32 operand at LEA_FIELD. No opcode, branch,
// return store or non-relocation operand is masked. The block argument and caller preconditions are above.
const INPUT: [u8; CODE_BYTES] = [
    0x4c, 0x8b, 0x4e, 0x08, 0x49, 0x81, 0xf9, 0xc0, 0x02, 0x00, 0x00, 0x72, 0x09, 0x49, 0x81, 0xf9,
    0xd0, 0x02, 0x00, 0x00, 0x73, 0x0c, 0xc6, 0x07, 0x02, 0xb0, 0xff, 0x88, 0x47, 0x18, 0x48, 0x89,
    0xf8, 0xc3, 0x48, 0x8b, 0x36, 0x48, 0x8b, 0x8e, 0xc8, 0x02, 0x00, 0x00, 0x48, 0x89, 0xc8, 0x49,
    0x89, 0xd2, 0x48, 0xf7, 0xa6, 0xc0, 0x02, 0x00, 0x00, 0x70, 0xdb, 0x4c, 0x8b, 0x86, 0xb8, 0x02,
    0x00, 0x00, 0x48, 0x89, 0xc2, 0x4c, 0x01, 0xc2, 0x41, 0x0f, 0x92, 0xc3, 0x4c, 0x39, 0xca, 0x0f,
    0x97, 0xc2, 0x48, 0x85, 0xc9, 0x41, 0x0f, 0x94, 0xc1, 0x45, 0x08, 0xd9, 0x41, 0x08, 0xd1, 0x41,
    0x80, 0xf9, 0x01, 0x74, 0xb1, 0x48, 0x89, 0xc2, 0x48, 0x09, 0xca, 0x49, 0x89, 0xc1, 0x48, 0xc1,
    0xea, 0x20, 0x74, 0x07, 0x31, 0xd2, 0x48, 0xf7, 0xf1, 0xeb, 0x04, 0x31, 0xd2, 0xf7, 0xf1, 0x48,
    0x83, 0xf9, 0x18, 0x72, 0x91, 0x4c, 0x89, 0xd2, 0x49, 0x39, 0xc2, 0x73, 0x89, 0x49, 0x89, 0xca,
    0x49, 0xc1, 0xea, 0x03, 0x48, 0x89, 0xd0, 0x49, 0xf7, 0xe2, 0x0f, 0x80, 0x76, 0xff, 0xff, 0xff,
    0x48, 0x83, 0xf8, 0xfd, 0x0f, 0x87, 0x6c, 0xff, 0xff, 0xff, 0x48, 0xba, 0xfd, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x1f, 0x4c, 0x8d, 0x52, 0x01, 0x4c, 0x39, 0xd0, 0x0f, 0x83, 0x55, 0xff, 0xff,
    0xff, 0x4c, 0x8d, 0x14, 0xc5, 0x17, 0x00, 0x00, 0x00, 0x4d, 0x39, 0xca, 0x0f, 0x83, 0x44, 0xff,
    0xff, 0xff, 0x48, 0x83, 0xf9, 0x20, 0x0f, 0x82, 0x3a, 0xff, 0xff, 0xff, 0x48, 0x39, 0xd0, 0x0f,
    0x83, 0x31, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x0c, 0xc5, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x51,
    0x1f, 0x4c, 0x39, 0xca, 0x0f, 0x83, 0x1c, 0xff, 0xff, 0xff, 0x4c, 0x01, 0xc6, 0x48, 0x8d, 0x51,
    0x18, 0x4c, 0x8b, 0x04, 0x16, 0x49, 0xff, 0xc8, 0x49, 0x83, 0xf8, 0x03, 0x0f, 0x87, 0x92, 0x00,
    0x00, 0x00, 0x48, 0x8d, 0x04, 0xc5, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x14, 0x06, 0x48, 0x8d,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x63, 0x04, 0x80, 0x49, 0x01, 0xc0, 0x41, 0xff, 0xe0, 0x48,
    0x81, 0xfa, 0x9e, 0x00, 0x00, 0x00, 0x75, 0x6c, 0x31, 0xc0, 0xeb, 0x1f, 0xb0, 0x02, 0x48, 0x83,
    0xfa, 0x07, 0x74, 0x17, 0xeb, 0x5e, 0xb0, 0x03, 0x48, 0x83, 0xfa, 0x02, 0x74, 0x0d, 0xeb, 0x54,
    0xb0, 0x01, 0x48, 0x81, 0xfa, 0xda, 0x00, 0x00, 0x00, 0x75, 0x49, 0x49, 0x89, 0xc8, 0x49, 0x83,
    0xc8, 0x07, 0x4d, 0x39, 0xc8, 0x0f, 0x83, 0xab, 0xfe, 0xff, 0xff, 0x4c, 0x8d, 0x41, 0x0f, 0x4d,
    0x39, 0xc8, 0x0f, 0x83, 0x9e, 0xfe, 0xff, 0xff, 0x4c, 0x8b, 0x04, 0x0e, 0x4d, 0x89, 0xc1, 0x49,
    0x83, 0xe9, 0xfe, 0x73, 0x1f, 0x48, 0x83, 0xc1, 0x08, 0x48, 0x8b, 0x0c, 0x0e, 0x49, 0x39, 0xc9,
    0x75, 0x12, 0x4c, 0x89, 0x07, 0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x57, 0x10, 0x88, 0x47, 0x18,
    0x48, 0x89, 0xf8, 0xc3, 0xc6, 0x07, 0x03, 0xb0, 0xff, 0x88, 0x47, 0x18, 0x48, 0x89, 0xf8, 0xc3,
];

fn source_digest(digest: &str) -> Result<()> {
    require(
        digest == SOURCE_SHA || digest == SERIALIZER_SOURCE_SHA || digest == BOOTSTRAP_SOURCE_SHA,
        "View::site complete runtime source differs",
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
fn input_code(bytes: &[u8]) -> Result<()> {
    require(
        bytes == INPUT.as_slice(),
        "View::site finite complete instruction form differs",
    )
}
fn named_site(name: &str, expected_symbol: &str) -> bool {
    canonical_rust_symbol(name).as_deref() == Some(expected_symbol)
}
fn bounded(file: &FileIdentity) -> Result<Vec<u8>> {
    // Bound before allocation AND the read itself if the file changes meanwhile.
    use std::io::Read;
    require(
        fs::metadata(&file.path).map_err(|e| e.to_string())?.len() <= LIMIT,
        "View::site ELF/map exceeds 128MiB bound",
    )?;
    let mut bytes = Vec::new();
    fs::File::open(&file.path)
        .map_err(|e| e.to_string())?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 <= LIMIT,
        "View::site ELF/map grew beyond bound",
    )?;
    Ok(bytes)
}

/// Source/member/relocation-bound conditional leaf observation. No public
/// constructor, Clone, Deserialize, execution method or conversion to Ready.
/// Serialized fields are observations and cannot be imported as this value.
#[derive(Debug, Serialize)]
pub struct ViewSiteLeafObservation {
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
    code_section: usize,
    table_section: usize,
    entry: u64,
    table: u64,
    code_sha256: String,
    table_sha256: String,
    targets: [u64; 4],
    scope: &'static str,
}
impl ViewSiteLeafObservation {
    /// Actual complete leaf entry; this observation does not authorize calling it.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// Return-buffer byte 24 is in this set on normal return under the documented
    /// valid-storage/entry/ABI preconditions; error FF does not initialize Site.
    pub fn conditional_result_bytes(&self) -> [u8; 5] {
        [0, 1, 2, 3, 0xff]
    }
    fn require_owner(&self, source: &VerifiedStaticSource, archive: &StaticArchive) -> Result<()> {
        require(
            Arc::ptr_eq(&self.owner.0, &source.archive_owner)
                && self.runtime_archive == archive.file,
            "View::site contract belongs to another source/archive",
        )
    }
}

/// Digest of the compiled finite leaf checker, for the ordinary source catalog.
pub fn view_site_implementation_sha256() -> String {
    sha256(include_bytes!("view_site.rs"))
}

fn section_shape(object: &ObjectInput<'_>, index: usize, code: bool, name: &str) -> Result<()> {
    section_shape_exact(object, index, code, name, CODE_BYTES)
}
pub(super) fn section_shape_exact(
    object: &ObjectInput<'_>,
    index: usize,
    code: bool,
    name: &str,
    code_bytes: usize,
) -> Result<()> {
    let s = object
        .elf
        .section_headers
        .get(index)
        .ok_or("View::site input section absent")?;
    require(
        s.sh_type == section_header::SHT_PROGBITS
            && s.sh_flags == if code { 6 } else { 2 }
            && s.sh_size
                == if code {
                    code_bytes as u64
                } else {
                    TABLE_BYTES as u64
                }
            && s.sh_addralign == if code { 16 } else { 4 }
            && object.elf.shdr_strtab.get_at(s.sh_name) == Some(name),
        "View::site complete input section geometry differs",
    )
}
pub(super) fn section_symbol(
    object: &ObjectInput<'_>,
    symbol: &sym::Sym,
    index: usize,
) -> Result<()> {
    require(
        symbol.st_shndx == index
            && symbol.st_type() == sym::STT_SECTION
            && symbol.st_bind() == sym::STB_LOCAL
            && symbol.st_other == 0
            && symbol.st_value == 0
            && symbol.st_size == 0
            && object.elf.strtab.get_at(symbol.st_name) == Some(""),
        "View::site relocation does not target exact own section symbol",
    )
}
fn input_aliases(object: &ObjectInput<'_>, code: usize, table: usize, name: &str) -> Result<()> {
    input_aliases_exact(object, code, table, name, CODE_BYTES)
}
fn input_aliases_exact(
    object: &ObjectInput<'_>,
    code: usize,
    table: usize,
    name: &str,
    code_bytes: usize,
) -> Result<()> {
    for (section, is_code) in [(code, true), (table, false)] {
        let symbols = object
            .elf
            .syms
            .iter()
            .filter(|s| s.st_shndx == section)
            .collect::<Vec<_>>();
        let mut functions = 0;
        let mut sections = 0;
        for s in symbols {
            if s.st_type() == sym::STT_SECTION {
                section_symbol(object, &s, section)?;
                sections += 1;
            } else {
                require(
                    is_code
                        && object.elf.strtab.get_at(s.st_name) == Some(name)
                        && s.st_bind() == sym::STB_GLOBAL
                        && s.st_type() == sym::STT_FUNC
                        && s.st_other == 0
                        && s.st_value == 0
                        && s.st_size == code_bytes as u64,
                    "View::site unexpected input alias or incomplete function",
                )?;
                functions += 1;
            }
        }
        require(
            sections == 1 && functions == usize::from(is_code),
            "View::site exact input symbol inventory differs",
        )?;
    }
    Ok(())
}
fn input_fields(object: &ObjectInput<'_>, code: usize, table: usize) -> Result<()> {
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
                .ok_or("View::site relocation symbol absent")?;
            section_symbol(object, &target, if is_code { table } else { code })?;
            found.push((
                is_code,
                r.r_offset,
                r.r_type,
                r.r_addend.ok_or("View::site input needs explicit addend")?,
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
        "View::site five exact typed input relocations differ",
    )
}

pub(super) fn final_section(
    elf: &Elf<'_>,
    bytes: &[u8],
    address: u64,
    size: usize,
    flags: u32,
) -> Result<usize> {
    let (load, file) = unique_file_mapping(elf, bytes, address, size)?;
    require(
        load.p_flags == flags,
        "View::site final RX/RO permission differs",
    )?;
    let end = address
        .checked_add(size as u64)
        .ok_or("View::site final extent overflow")?;
    let mut sections = Vec::new();
    for (i, s) in elf.section_headers.iter().enumerate() {
        if s.sh_flags & section_header::SHF_ALLOC as u64 == 0 {
            continue;
        }
        let limit = s
            .sh_addr
            .checked_add(s.sh_size)
            .ok_or("View::site output section overflow")?;
        if s.sh_addr <= address && end <= limit {
            require(
                s.sh_type == section_header::SHT_PROGBITS
                    && s.sh_flags & 7 == if flags == 5 { 6 } else { 2 }
                    && s.sh_flags & section_header::SHF_TLS as u64 == 0
                    && s.sh_offset.checked_add(address - s.sh_addr) == Some(file as u64),
                "View::site output section/load geometry differs",
            )?;
            sections.push(i);
        }
    }
    require(
        sections.len() == 1,
        "View::site output section absent/ambiguous",
    )?;
    Ok(sections[0])
}
pub(super) fn final_aliases(
    elf: &Elf<'_>,
    address: u64,
    size: usize,
    section: usize,
    name: Option<&str>,
) -> Result<()> {
    final_aliases_bound(elf, address, size, section, name, sym::STB_GLOBAL)
}
// Private exact-binding join: generic View/Site callers retain the global-only
// wrapper above. The separate descriptor source role requires observed LOCAL.
pub(super) fn final_aliases_bound(
    elf: &Elf<'_>,
    address: u64,
    size: usize,
    section: usize,
    name: Option<&str>,
    expected_binding: u8,
) -> Result<()> {
    let end = address
        .checked_add(size as u64)
        .ok_or("View::site symbol extent overflow")?;
    let mut functions = 0;
    for s in elf.syms.iter().filter(|s| s.st_shndx != 0) {
        let limit = s
            .st_value
            .checked_add(s.st_size)
            .ok_or("View::site symbol overflow")?;
        let overlaps = if s.st_size == 0 {
            address <= s.st_value && s.st_value < end
        } else {
            s.st_value < end && address < limit
        };
        if !overlaps {
            continue;
        }
        if s.st_type() == sym::STT_SECTION {
            require(
                s.st_shndx == section
                    && s.st_bind() == sym::STB_LOCAL
                    && s.st_size == 0
                    && s.st_other == 0
                    && elf.strtab.get_at(s.st_name) == Some("")
                    && s.st_value == elf.section_headers[section].sh_addr,
                "View::site unexpected final section alias",
            )?;
        } else {
            require(
                name.is_some()
                    && elf.strtab.get_at(s.st_name) == name
                    && s.st_shndx == section
                    && s.st_value == address
                    && s.st_size == size as u64
                    && s.st_type() == sym::STT_FUNC
                    && s.st_bind() == expected_binding
                    && s.st_other == 0,
                "View::site unexpected final alias or incomplete function",
            )?;
            functions += 1;
        }
    }
    require(
        functions == usize::from(name.is_some()),
        "View::site final definition absent/duplicate",
    )
}
fn final_fields(
    elf: &Elf<'_>,
    bytes: &[u8],
    address: u64,
    size: usize,
    section: usize,
    target_section: usize,
) -> Result<Vec<FinalRelocation>> {
    let tab = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, tab)?;
    let end = address
        .checked_add(size as u64)
        .ok_or("View::site relocation extent overflow")?;
    let mut found = Vec::new();
    for (index, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *index, tab, rows.len())?;
        for r in rows.iter() {
            let width = checked_relocation_span(elf, rs, r.r_offset, r.r_type)?;
            if !selected_field_overlap(
                &elf.section_headers[rs.sh_info as usize],
                r.r_offset,
                r.r_type,
                address,
                end,
            )? {
                continue;
            }
            require(
                rs.sh_info as usize == section
                    && r.r_offset >= address
                    && width == Some(4)
                    && r.r_offset.checked_add(4).is_some_and(|n| n <= end),
                "View::site writer crosses or declares another output extent",
            )?;
            let s = elf
                .syms
                .get(r.r_sym)
                .ok_or("View::site final relocation symbol absent")?;
            require(
                s.st_type() == sym::STT_SECTION
                    && s.st_bind() == sym::STB_LOCAL
                    && s.st_size == 0
                    && s.st_other == 0
                    && s.st_shndx == target_section
                    && s.st_shndx < elf.section_headers.len()
                    && s.st_value == elf.section_headers[s.st_shndx].sh_addr
                    && elf.strtab.get_at(s.st_name) == Some(""),
                "View::site final field not section-rebased input target",
            )?;
            found.push(FinalRelocation {
                offset: usize::try_from(r.r_offset - address)
                    .map_err(|_| "View::site field offset")?,
                kind: r.r_type,
                addend: r.r_addend.ok_or("View::site final needs explicit addend")?,
                symbol_value: s.st_value,
            });
        }
    }
    found.sort_by_key(|r| r.offset);
    Ok(found)
}
fn linked_form(
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
        "View::site full body/table/relocation census differs",
    )?;
    let r = &code_fields[0];
    require(
        r.offset == LEA_FIELD
            && r.kind == reloc::R_X86_64_PC32
            && i128::from(r.symbol_value) + i128::from(r.addend) == i128::from(table_address) - 4,
        "View::site LEA does not join exact RO table",
    )?;
    let mut expected = INPUT;
    let place = entry
        .checked_add(LEA_FIELD as u64)
        .ok_or("View::site LEA overflow")?;
    expected[LEA_FIELD..LEA_FIELD + 4].copy_from_slice(&checked_pc32(table_address, -4, place)?);
    require(code == expected, "View::site relocated whole body differs")?;
    let mut targets = [0; 4];
    for (i, r) in table_fields.iter().enumerate() {
        let target = entry
            .checked_add(ARMS[i] as u64)
            .ok_or("View::site arm overflow")?;
        let offset = (i * 4) as u64;
        require(
            r.offset == i * 4
                && r.kind == reloc::R_X86_64_PC32
                && i128::from(r.symbol_value) + i128::from(r.addend)
                    == i128::from(target) + i128::from(offset),
            "View::site relative entry target differs",
        )?;
        let expected = checked_pc32(
            target,
            offset as i64,
            table_address
                .checked_add(offset)
                .ok_or("View::site table overflow")?,
        )?;
        require(
            table.get(i * 4..i * 4 + 4) == Some(&expected[..]),
            "View::site relative entry bytes differ",
        )?;
        targets[i] = target;
    }
    Ok(targets)
}

// Exactly two separately reviewed finite forms share only this existing
// source/archive/map/close transaction. No public form/policy argument exists.
#[derive(Clone, Copy)]
pub(super) enum SiteLeafKind {
    View,
    Bootstrap,
}
impl SiteLeafKind {
    fn size(self) -> usize {
        match self {
            Self::View => CODE_BYTES,
            Self::Bootstrap => super::bootstrap_site::CODE_BYTES,
        }
    }
    fn symbol(self, digest: &str) -> Result<&'static str> {
        match self {
            Self::View => source_symbol(digest),
            Self::Bootstrap => super::bootstrap_site::source_symbol(digest),
        }
    }
    fn named(self, name: &str, expected: &str) -> bool {
        match self {
            Self::View => named_site(name, expected),
            Self::Bootstrap => super::bootstrap_site::named_site(name, expected),
        }
    }
    fn input(self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::View => input_code(bytes),
            Self::Bootstrap => super::bootstrap_site::input_code(bytes),
        }
    }
    fn fields(self, object: &ObjectInput<'_>, code: usize, table: usize) -> Result<()> {
        match self {
            Self::View => input_fields(object, code, table),
            Self::Bootstrap => super::bootstrap_site::input_fields(object, code, table),
        }
    }
    fn linked(
        self,
        code: &[u8],
        table: &[u8],
        entry: u64,
        table_address: u64,
        code_fields: &[FinalRelocation],
        table_fields: &[FinalRelocation],
    ) -> Result<[u64; 4]> {
        match self {
            Self::View => linked_form(code, table, entry, table_address, code_fields, table_fields),
            Self::Bootstrap => super::bootstrap_site::linked_form(
                code,
                table,
                entry,
                table_address,
                code_fields,
                table_fields,
            ),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct SiteLeafIdentity {
    #[serde(skip)]
    pub(super) owner: DefinitionSourceOwner,
    pub(super) runtime_archive: FileIdentity,
    pub(super) artifact: FileIdentity,
    pub(super) link_map: FileIdentity,
    pub(super) source: FileIdentity,
    pub(super) member_name: String,
    pub(super) member_ordinal: usize,
    pub(super) member_header: u64,
    pub(super) member_sha256: String,
    pub(super) code_section: usize,
    pub(super) table_section: usize,
    pub(super) entry: u64,
    pub(super) table: u64,
    pub(super) code_sha256: String,
    pub(super) table_sha256: String,
    pub(super) targets: [u64; 4],
    pub(super) scope: &'static str,
}

impl VerifiedStaticSource {
    /// Observe the finite complete View::site form under the actual fresh source
    /// and archive owner. No caller supplies an identity policy, code, table,
    /// source path or success fact. All Result paths, including callback failure,
    /// close source/build-output/archive/map/ELF/source-file identities and the
    /// existing selected-definition producer's complete retained link ledger.
    ///
    /// Normal-return semantics are CONDITIONAL on entry at the observed start,
    /// the actual compiler ABI, immutable valid View/backing, a valid return
    /// address and disjoint live writable return storage. This method proves
    /// none of those physical call preconditions and never authorizes entry.
    pub fn with_view_site_leaf<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        runner: &mut Runner,
        body: impl FnOnce(&ViewSiteLeafObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        self.with_site_leaf(
            SiteLeafKind::View,
            archive,
            definitions,
            (artifact, link_map),
            runner,
            |identity, runner| {
                let observation = ViewSiteLeafObservation {
                    owner: identity.owner,
                    runtime_archive: identity.runtime_archive,
                    artifact: identity.artifact,
                    link_map: identity.link_map,
                    source: identity.source,
                    member_name: identity.member_name,
                    member_ordinal: identity.member_ordinal,
                    member_header: identity.member_header,
                    member_sha256: identity.member_sha256,
                    code_section: identity.code_section,
                    table_section: identity.table_section,
                    entry: identity.entry,
                    table: identity.table,
                    code_sha256: identity.code_sha256,
                    table_sha256: identity.table_sha256,
                    targets: identity.targets,
                    scope: identity.scope,
                };
                observation.require_owner(self, archive)?;
                body(&observation, runner)
            },
        )
    }

    pub(super) fn with_site_leaf<T>(
        &self,
        kind: SiteLeafKind,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        outputs: (&FileIdentity, &FileIdentity),
        runner: &mut Runner,
        body: impl FnOnce(SiteLeafIdentity, &mut Runner) -> Result<T>,
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
                    "View::site definitions belong to another ELF/map",
                )
            });
        if let Err(e) = admission {
            // Unadmitted foreign definitions/outputs are never read as input.
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
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            require(roots.len() == 1, "View::site resolved source ambiguous")?;
            let source = FileIdentity::read(&roots[0].join(SOURCE))?;
            files.push(source.clone());
            let expected_symbol = kind.symbol(&source.sha256)?;
            let members = extract_objects(&archive.file, 0)?;
            let mut objects = Vec::new();
            for m in &members {
                let elf = Elf::parse(&m.bytes).map_err(|e| e.to_string())?;
                require(
                    elf.header.e_type == header::ET_REL
                        && elf.header.e_machine == header::EM_X86_64
                        && elf.is_64
                        && elf.little_endian,
                    "View::site member is not actual x86_64 LE relocatable",
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
            let mut definitions = Vec::new();
            for (i, o) in objects.iter().enumerate() {
                for s in o.elf.syms.iter().filter(|s| s.st_shndx != 0) {
                    let name = o
                        .elf
                        .strtab
                        .get_at(s.st_name)
                        .ok_or("View::site symbol name absent")?;
                    if kind.named(name, expected_symbol) {
                        definitions.push((i, s));
                    }
                }
            }
            require(
                definitions.len() == 1,
                "View::site definition absent/ambiguous across actual archive",
            )?;
            let (i, s) = definitions[0];
            let o = &objects[i];
            require(
                o.member_name.starts_with("reverie_loader-")
                    && s.st_type() == sym::STT_FUNC
                    && s.st_bind() == sym::STB_GLOBAL
                    && s.st_value == 0
                    && s.st_size == kind.size() as u64,
                "View::site sole definition has wrong physical owner/shape",
            )?;
            let name = o
                .elf
                .strtab
                .get_at(s.st_name)
                .ok_or("View::site name absent")?;
            let code_index = s.st_shndx;
            match kind {
                SiteLeafKind::View => section_shape(o, code_index, true, &format!(".text.{name}"))?,
                SiteLeafKind::Bootstrap => {
                    section_shape_exact(o, code_index, true, &format!(".text.{name}"), kind.size())?
                }
            };
            let candidates = o
                .elf
                .section_headers
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    o.elf.shdr_strtab.get_at(s.sh_name) == Some(format!(".rodata.{name}").as_str())
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            require(
                candidates.len() == 1,
                "View::site own table absent/ambiguous",
            )?;
            let table_index = candidates[0];
            section_shape(o, table_index, false, &format!(".rodata.{name}"))?;
            match kind {
                SiteLeafKind::View => input_aliases(o, code_index, table_index, name)?,
                SiteLeafKind::Bootstrap => {
                    input_aliases_exact(o, code_index, table_index, name, kind.size())?
                }
            };
            kind.input(section_file_bytes(
                &o.elf.section_headers[code_index],
                o.bytes,
            )?)?;
            require(
                section_file_bytes(&o.elf.section_headers[table_index], o.bytes)?
                    == [0u8; TABLE_BYTES].as_slice(),
                "View::site input table placeholder differs",
            )?;
            kind.fields(o, code_index, table_index)?;
            let map_bytes = bounded(link_map)?;
            let map = std::str::from_utf8(&map_bytes).map_err(|e| e.to_string())?;
            let entry = mapped_section(map, o, code_index)?;
            let table = mapped_section(map, o, table_index)?;
            let data = bounded(artifact)?;
            let elf = Elf::parse(&data).map_err(|e| e.to_string())?;
            static_image_metadata(&elf, &data)?;
            let tab = checked_symtab(&elf, &data)?;
            checked_relocation_inventory(&elf, &data, tab)?;
            // Names select an expected row; physical complete map/bytes prove it.
            let matches = elf
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
                matches.len() == 1 && elf.strtab.get_at(matches[0].st_name) == Some(name),
                "View::site final exact symbol absent/ambiguous/different",
            )?;
            let code_section = final_section(&elf, &data, entry, kind.size(), 5)?;
            let table_section = final_section(&elf, &data, table, TABLE_BYTES, 4)?;
            final_aliases(&elf, entry, kind.size(), code_section, Some(name))?;
            final_aliases(&elf, table, TABLE_BYTES, table_section, None)?;
            let code = mapped_bytes(&elf, &data, entry, kind.size() as u64, 5)?;
            let table_bytes = mapped_bytes(&elf, &data, table, TABLE_BYTES as u64, 4)?;
            let targets = kind.linked(
                code,
                table_bytes,
                entry,
                table,
                &final_fields(&elf, &data, entry, kind.size(), code_section, table_section)?,
                &final_fields(&elf, &data, table, TABLE_BYTES, table_section, code_section)?,
            )?;
            let observation = SiteLeafIdentity {
                owner: DefinitionSourceOwner(self.archive_owner.clone()),
                runtime_archive: archive.file.clone(),
                artifact: artifact.clone(),
                link_map: link_map.clone(),
                source,
                member_name: o.member_name.to_owned(),
                member_ordinal: o.ordinal,
                member_header: o.header_offset,
                member_sha256: sha256(o.bytes),
                code_section: code_index,
                table_section: table_index,
                entry,
                table,
                code_sha256: sha256(code),
                table_sha256: sha256(table_bytes),
                targets,
                scope: "CONDITIONAL_LEAF_RESULT_DOMAIN_ONLY_PHYSICAL_CALL_PRECONDITIONS_NOT_PROVEN",
            };
            body(observation, runner)
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
    fn view_site_complete_form_refuses_every_changed_byte_and_extent() {
        input_code(&INPUT).unwrap();
        assert!(input_code(&INPUT[..CODE_BYTES - 1]).is_err());
        for at in 0..CODE_BYTES {
            let mut wrong = INPUT;
            wrong[at] ^= 1;
            assert!(input_code(&wrong).is_err(), "changed byte {at}");
        }
    }
    #[test]
    fn view_site_bounds_operation_number_ip_and_return_stores_are_not_waived() {
        let (code, table, code_fields, table_fields) = linked();
        // Operation upper bound, op/number arms, carry/IP pair, success byte
        // store and BOTH error byte stores: each is an actual executed byte.
        for at in [
            0x10b, 0x135, 0x141, 0x14b, 0x157, 0x183, 0x190, 0x19d, 0x1b, 0x1a9,
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
    fn view_site_synthetic_signed_table_requires_all_four_exact_targets() {
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
    fn view_site_missing_duplicate_kind_and_wrong_target_fields_refuse() {
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
    fn view_site_input_relocation_census_has_no_optional_field() {
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
    fn put16(b: &mut [u8], at: usize, n: u16) {
        b[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, n: u32) {
        b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    fn geometry() -> Vec<u8> {
        let mut b = vec![0; 0x4000];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut b, 16, 2);
        put16(&mut b, 18, 62);
        put32(&mut b, 20, 1);
        put64(&mut b, 32, 64);
        put64(&mut b, 40, 0x3000);
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 2);
        put16(&mut b, 58, 64);
        put16(&mut b, 60, 5);
        for (i, addr, size, flags) in [(0, 0x1000, CODE_BYTES, 5), (1, 0x3000, TABLE_BYTES, 4)] {
            // Table file bytes occupy 0x2000; VA deliberately differs.
            let file = if i == 0 { 0x1000 } else { 0x2000 };
            let p = 64 + i * 56;
            put32(&mut b, p, 1);
            put32(&mut b, p + 4, flags);
            put64(&mut b, p + 8, file);
            put64(&mut b, p + 16, addr);
            put64(&mut b, p + 24, addr);
            put64(&mut b, p + 32, size as u64);
            put64(&mut b, p + 40, size as u64);
            put64(&mut b, p + 48, 4096);
            let s = 0x3000 + (i + 1) * 64;
            put32(&mut b, s + 4, 1);
            put64(&mut b, s + 8, if i == 0 { 6 } else { 2 });
            put64(&mut b, s + 16, addr);
            put64(&mut b, s + 24, file);
            put64(&mut b, s + 32, size as u64);
            put64(&mut b, s + 48, if i == 0 { 16 } else { 4 });
        }
        // A real linked STRTAB gives the anonymous section target its empty
        // name; this remains a synthetic geometry fixture, not source authority.
        let st = 0x3000 + 3 * 64;
        put32(&mut b, st + 4, 2);
        put64(&mut b, st + 24, 0x2800);
        put64(&mut b, st + 32, 24);
        put32(&mut b, st + 40, 4);
        put32(&mut b, st + 44, 1);
        put64(&mut b, st + 48, 8);
        put64(&mut b, st + 56, 24);
        let strings = 0x3000 + 4 * 64;
        put32(&mut b, strings + 4, 3);
        put64(&mut b, strings + 24, 0x2818);
        put64(&mut b, strings + 32, 1);
        put64(&mut b, strings + 48, 1);
        b
    }
    #[test]
    fn view_site_parsed_elf_table_must_be_unique_ro_not_nominal_relro() {
        let data = geometry();
        let elf = Elf::parse(&data).unwrap();
        assert_eq!(
            final_section(&elf, &data, 0x1000, CODE_BYTES, 5).unwrap(),
            1
        );
        assert_eq!(
            final_section(&elf, &data, 0x3000, TABLE_BYTES, 4).unwrap(),
            2
        );
        for flags in [0, 1, 5, 6, 7] {
            let mut b = data.clone();
            put32(&mut b, 64 + 56 + 4, flags);
            assert!(final_section(&Elf::parse(&b).unwrap(), &b, 0x3000, TABLE_BYTES, 4).is_err());
        }
        let mut b = data.clone();
        put64(&mut b, 0x3000 + 128 + 8, 3);
        assert!(final_section(&Elf::parse(&b).unwrap(), &b, 0x3000, TABLE_BYTES, 4).is_err());
        let mut b = data;
        put64(&mut b, 0x3000 + 128 + 24, 0x2001);
        assert!(final_section(&Elf::parse(&b).unwrap(), &b, 0x3000, TABLE_BYTES, 4).is_err());
    }
    #[test]
    fn view_site_typed_target_requires_actual_own_anonymous_section() {
        let data = geometry();
        let object = ObjectInput {
            archive_path: Path::new("/unit/not-authority.a"),
            member_name: "unit.o",
            ordinal: 0,
            header_offset: 8,
            bytes: &data,
            elf: Elf::parse(&data).unwrap(),
        };
        let mut s = sym::Sym {
            st_name: 0,
            st_info: sym::STT_SECTION,
            st_other: 0,
            st_shndx: 2,
            st_value: 0,
            st_size: 0,
        };
        section_symbol(&object, &s, 2).unwrap();
        assert!(section_symbol(&object, &s, 1).is_err());
        s.st_info = sym::STT_OBJECT;
        assert!(section_symbol(&object, &s, 2).is_err());
        s.st_info = sym::STT_SECTION;
        s.st_value = 1;
        assert!(section_symbol(&object, &s, 2).is_err());
    }
    #[test]
    fn view_site_equal_metadata_cannot_mint_live_source_owner() {
        let owner = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        let other = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        require_same_archive_source(&owner, &owner, "equal", "equal").unwrap();
        assert_eq!(
            require_same_archive_source(&owner, &other, "equal", "equal").unwrap_err(),
            "static archive belongs to another source transaction"
        );
        source_digest(SOURCE_SHA).unwrap();
        assert!(source_digest(&"0".repeat(64)).is_err());
        // No fake VerifiedStaticSource/StaticArchive or positive production fact
        // is constructed here; the actual same-owner factory remains unrun.
    }
    #[test]
    fn view_site_declared_whole_source_cohorts_are_data_only() {
        source_digest(SOURCE_SHA).unwrap();
        source_digest(SERIALIZER_SOURCE_SHA).unwrap();
        // Digest recognition does not construct an owner or prove emitted code.
    }
    #[test]
    fn view_site_source_cohorts_require_complete_exact_digest() {
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
    fn view_site_bootstrap_source_cohort_requires_exact_complete_digest() {
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
    fn view_site_source_symbol_cohorts_do_not_cross() {
        for digest in [SOURCE_SHA, SERIALIZER_SOURCE_SHA] {
            let expected = source_symbol(digest).unwrap();
            assert_eq!(expected, SYMBOL);
            assert!(named_site(&SYMBOL.replace("Cs_", "Csunit_"), expected));
            assert!(!named_site(
                &BOOTSTRAP_SYMBOL.replace("Cs_", "Csunit_"),
                expected
            ));
        }
        let expected = source_symbol(BOOTSTRAP_SOURCE_SHA).unwrap();
        assert_eq!(expected, BOOTSTRAP_SYMBOL);
        assert!(named_site(
            &BOOTSTRAP_SYMBOL.replace("Cs_", "Csunit_"),
            expected
        ));
        assert!(!named_site(&SYMBOL.replace("Cs_", "Csunit_"), expected));
        for unknown in [
            "0".repeat(64),
            BOOTSTRAP_SOURCE_SHA[..63].to_owned(),
            format!("{BOOTSTRAP_SOURCE_SHA}0"),
        ] {
            assert!(source_symbol(&unknown).is_err());
        }
    }

    #[test]
    fn view_site_source_selected_role_is_exact() {
        let expected = source_symbol(BOOTSTRAP_SOURCE_SHA).unwrap();
        let actual = "_RNvMs2_NtCsiQA3fNasB45_14reverie_loader7handoffNtB5_4View4site";
        assert!(named_site(actual, expected));
        for wrong in [
            actual.replace("Ms2_", "Ms3_"),
            actual.replace("4View4site", "4View5table"),
            actual.replace("7handoff", "7handofx"),
            format!("{actual}unexpected"),
            actual.replace("CsiQA3fNasB45_", "Cs_"),
        ] {
            assert!(!named_site(&wrong, expected));
        }
    }
}
