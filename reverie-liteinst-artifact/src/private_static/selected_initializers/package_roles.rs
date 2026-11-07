//! Three complete source-owned package bodies; no execution/Ready capability.
use super::*;

const LIBC_MEMBER: &str = "03a51c3b19a635b7131c7bad1d006c63cdae299fc82de51963e2d699a13d4d76";
const TP_MEMBER: &str = "1f6fb1dbc48a52b1803d941e2cd6a76664eaf2a1c7548784069ef2be685eb624";
const STRINGS: &[u8] = b"\0/dev/null\0";
const LIBC_RELOCS: &[(u64, u32, i64, &str)] = &[
    (31, 9, -4, "__environ"),
    (60, 2, 4, "__libc"),
    (106, 2, -4, "__hwcap"),
    (126, 2, -4, "__sysinfo"),
    (138, 2, 44, "__libc"),
    (150, 9, -4, "__progname_full"),
    (157, 9, -4, "__progname"),
    (184, 2, -4, ".LC0"),
    (222, 4, -4, "__init_tls"),
    (235, 4, -4, "__init_ssp"),
    (330, 2, -4, ".LC1"),
    (400, 2, -3, "__libc"),
];
const TP_RELOCS: &[(u64, u32, i64, &str)] = &[
    (8, 4, -4, "__set_thread_area"),
    (20, 2, -5, "__libc"),
    (40, 2, -4, "__thread_list_lock"),
    (52, 2, 52, "__libc"),
    (80, 2, -4, "__sysinfo"),
];

/// Additive compiled source identity, independently catalog-bound by callers.
pub fn package_role_implementation_sha256() -> String {
    sha256(include_bytes!("package_roles.rs"))
}

#[derive(Debug, Serialize)]
pub struct PackageRoleObservation {
    schema: &'static str,
    scope: &'static str,
    implementation_sha256: String,
    runtime_archive: FileIdentity,
    libc_archive: FileIdentity,
    artifact: FileIdentity,
    link_map: FileIdentity,
    sources: Vec<FileIdentity>,
    roles: Vec<RoleBody>,
    merged_literals: Vec<MergedLiteral>,
    ssp_override: SspOverride,
}
impl PackageRoleObservation {
    pub fn to_json_pretty(&self) -> Result<Vec<u8>> {
        let data = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        require(
            data.len() <= 65536,
            "package role observation exceeds bound",
        )?;
        Ok(data)
    }
}
#[derive(Debug, Serialize)]
struct RoleBody {
    symbol: &'static str,
    member_name: String,
    member_ordinal: usize,
    member_header: u64,
    member_sha256: String,
    input_section: usize,
    input_offset: u64,
    complete_bytes: usize,
    input_body_sha256: String,
    final_entry: u64,
    final_body_sha256: String,
    relocations: Vec<Relocation>,
    sites: Vec<Site>,
    aliases: BTreeMap<&'static str, usize>,
}
#[derive(Debug, Serialize)]
struct Relocation {
    offset: usize,
    kind: u32,
    addend: i64,
    source_symbol_index: usize,
    source_symbol: String,
    selected_target: u64,
    selection: &'static str,
    final_symbol_index: usize,
    final_symbol_value: u64,
    final_addend: i64,
}
#[derive(Debug, Serialize)]
struct Site {
    offset: usize,
    number: u64,
    operation: u64,
}
#[derive(Debug, Serialize)]
struct MergedLiteral {
    source_symbol: &'static str,
    input_symbol_index: usize,
    input_section: usize,
    input_offset: u64,
    bytes: usize,
    sha256: String,
    file_symbol_index: usize,
    final_symbol_index: usize,
    final_address: u64,
    final_section: usize,
    final_file_offset: usize,
    anchor_symbol_index: usize,
    anchor_address: u64,
}
#[derive(Debug, Serialize)]
struct SspOverride {
    source_symbol_index: usize,
    source_section: usize,
    selected_member_name: String,
    selected_member_ordinal: usize,
    selected_member_header: u64,
    selected_member_sha256: String,
    final_entry: u64,
    complete_bytes: usize,
}

fn named(elf: &Elf<'_>, name: &str) -> Result<(usize, sym::Sym)> {
    let rows = elf
        .syms
        .iter()
        .enumerate()
        .filter(|(_, s)| s.st_shndx != 0 && elf.strtab.get_at(s.st_name) == Some(name))
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        format!("package role symbol absent/duplicate: {name}"),
    )?;
    Ok(rows[0])
}
fn section_name<'a>(elf: &'a Elf<'_>, symbol: &sym::Sym) -> Result<&'a str> {
    let section = elf
        .section_headers
        .get(symbol.st_shndx)
        .ok_or("package target section absent")?;
    elf.shdr_strtab
        .get_at(section.sh_name)
        .ok_or("package target section name absent".into())
}
fn target_name(object: &ObjectInput<'_>, symbol: &sym::Sym) -> Result<String> {
    let name = object
        .elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or("package target name absent")?;
    if name.is_empty() && symbol.st_type() == sym::STT_SECTION {
        Ok(section_name(&object.elf, symbol)?.into())
    } else {
        Ok(name.into())
    }
}
fn file_symbol_shape(symbol: &sym::Sym) -> bool {
    symbol.st_type() == sym::STT_FILE
        && symbol.st_bind() == sym::STB_LOCAL
        && symbol.st_visibility() == sym::STV_DEFAULT
        && symbol.st_shndx == section_header::SHN_ABS as usize
        && symbol.st_value == 0
        && symbol.st_size == 0
}
fn relocation_rows(
    object: &ObjectInput<'_>,
    section: usize,
    extent: usize,
) -> Result<Vec<(u64, u32, i64, usize)>> {
    let table = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, table)?;
    let mut rows = Vec::new();
    for (index, relocs) in &object.elf.shdr_relocs {
        let rs =
            checked_relocation_section(&object.elf, object.bytes, *index, table, relocs.len())?;
        if rs.sh_info as usize != section {
            continue;
        }
        for r in relocs.iter() {
            let width = checked_relocation_span(&object.elf, rs, r.r_offset, r.r_type)?;
            if r.r_offset >= extent as u64 {
                continue;
            }
            require(
                width.is_some_and(|n| {
                    r.r_offset
                        .checked_add(n)
                        .is_some_and(|end| end <= extent as u64)
                }),
                "package relocation crosses complete owner",
            )?;
            rows.push((
                r.r_offset,
                r.r_type,
                r.r_addend.ok_or("package relocation addend absent")?,
                r.r_sym,
            ));
        }
    }
    rows.sort_by_key(|r| r.0);
    Ok(rows)
}
fn require_native_member(role: InitializerRole, object: &ObjectInput<'_>) -> Result<()> {
    let (name, ordinal, header, hash) = match role {
        InitializerRole::PackageLibc => ("__libc_start_main.lo", 135, 699442, LIBC_MEMBER),
        InitializerRole::PackageTp => ("__init_tls.lo", 134, 692078, TP_MEMBER),
        _ => return Err("package native role differs".into()),
    };
    require(
        object.member_name == name
            && object.ordinal == ordinal
            && object.header_offset == header
            && sha256(object.bytes) == hash,
        "package native physical member differs",
    )
}
pub(super) fn validate_native_input(role: InitializerRole, object: &ObjectInput<'_>) -> Result<()> {
    require_native_member(role, object)?;
    native_input_form(role, object)
}
fn native_input_form(role: InitializerRole, object: &ObjectInput<'_>) -> Result<()> {
    let (_, symbol) = named(&object.elf, role.symbol())?;
    let (index, size, name, expected) = match role {
        InitializerRole::PackageLibc => (7, 413, ".text.__init_libc", LIBC_RELOCS),
        InitializerRole::PackageTp => (4, 107, ".text.__init_tp", TP_RELOCS),
        _ => return Err("package native role differs".into()),
    };
    require(
        symbol.st_shndx == index
            && symbol.st_size == size
            && symbol.st_value == 0
            && symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_visibility() == sym::STV_HIDDEN
            && symbol.st_type() == sym::STT_FUNC
            && section_name(&object.elf, &symbol)? == name,
        "package native complete input symbol differs",
    )?;
    let rows = relocation_rows(object, index, size as usize)?;
    let typed = rows
        .iter()
        .map(|&(offset, kind, addend, target)| {
            let symbol = object
                .elf
                .syms
                .get(target)
                .ok_or("package native target absent")?;
            Ok((offset, kind, addend, target_name(object, &symbol)?))
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        typed.len() == expected.len()
            && typed
                .iter()
                .zip(expected)
                .all(|(a, b)| a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3),
        "package native exact relocation inventory differs",
    )
}

// A finite local-symbol-group join for only these two source strings. The
// expected address is selected before inspecting the instruction displacement.
fn literals(
    owner: &ObjectInput<'_>,
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<Vec<MergedLiteral>> {
    require_native_member(InitializerRole::PackageLibc, owner)?;
    literal_form(owner, map, elf, bytes)
}
fn literal_form(
    owner: &ObjectInput<'_>,
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<Vec<MergedLiteral>> {
    let section = owner
        .elf
        .section_headers
        .get(6)
        .ok_or("package literal input section absent")?;
    require(
        owner.elf.shdr_strtab.get_at(section.sh_name) == Some(".rodata.__init_libc.str1.1")
            && section.sh_type == 1
            && section.sh_flags == 50
            && section.sh_addralign == 1
            && section.sh_entsize == 1
            && section.sh_size == 11
            && section_file_bytes(section, owner.bytes)? == STRINGS,
        "package complete merged input strings differ",
    )?;
    require(
        relocation_rows(owner, 6, 11)?.is_empty(),
        "package merged input string has relocation",
    )?;
    let input_files = owner
        .elf
        .syms
        .iter()
        .filter(|s| s.st_type() == sym::STT_FILE)
        .collect::<Vec<_>>();
    require(
        input_files.len() == 1
            && file_symbol_shape(&input_files[0])
            && owner.elf.strtab.get_at(input_files[0].st_name) == Some("__libc_start_main.c"),
        "package input FILE identity differs",
    )?;
    let (_, source_anchor) = named(&owner.elf, "__init_libc")?;
    let address = mapped_definition(map, owner, &source_anchor)?;
    let (anchor_index, anchor) = named(elf, "__init_libc")?;
    require(
        anchor.st_type() == sym::STT_FUNC
            && anchor.st_bind() == sym::STB_LOCAL
            && anchor.st_visibility() == sym::STV_HIDDEN
            && anchor.st_value == address
            && anchor.st_size == 413,
        "package literal map/member anchor differs",
    )?;
    let files = elf
        .syms
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.st_type() == sym::STT_FILE
                && elf.strtab.get_at(s.st_name) == Some("__libc_start_main.c")
        })
        .collect::<Vec<_>>();
    require(
        files.len() == 1,
        "package final FILE identity absent/duplicate",
    )?;
    require(
        file_symbol_shape(&files[0].1),
        "package final FILE symbol shape differs",
    )?;
    let file_index = files[0].0;
    let end = elf
        .syms
        .iter()
        .enumerate()
        .skip(file_index + 1)
        .find(|(_, s)| s.st_type() == sym::STT_FILE)
        .map_or(elf.syms.len(), |(i, _)| i);
    require(
        file_index < anchor_index && anchor_index < end,
        "package native anchor outside FILE group",
    )?;
    let mut result = Vec::new();
    for (name, input_offset, expected) in [(".LC0", 0, &STRINGS[..1]), (".LC1", 1, &STRINGS[1..])] {
        let (input_index, input) = named(&owner.elf, name)?;
        require(
            input.st_shndx == 6
                && input.st_value == input_offset
                && input.st_size == 0
                && input.st_bind() == sym::STB_LOCAL
                && input.st_type() == sym::STT_NOTYPE
                && input.st_visibility() == sym::STV_DEFAULT,
            "package input literal label/bounds differ",
        )?;
        let selected = elf
            .syms
            .iter()
            .enumerate()
            .skip(file_index + 1)
            .take(end - file_index - 1)
            .filter(|(_, s)| elf.strtab.get_at(s.st_name) == Some(name))
            .collect::<Vec<_>>();
        require(
            selected.len() == 1,
            "package anchored literal label absent/duplicate",
        )?;
        let (final_index, symbol) = selected[0];
        require(
            symbol.st_bind() == sym::STB_LOCAL
                && symbol.st_type() == sym::STT_NOTYPE
                && symbol.st_visibility() == sym::STV_DEFAULT
                && symbol.st_size == 0,
            "package final literal symbol shape differs",
        )?;
        let out = elf
            .section_headers
            .get(symbol.st_shndx)
            .ok_or("package literal output section absent")?;
        require(
            elf.shdr_strtab.get_at(out.sh_name) == Some(".rodata")
                && out.sh_type == 1
                && out.sh_flags & 7 == 2
                && symbol.st_value >= out.sh_addr
                && symbol
                    .st_value
                    .checked_add(expected.len() as u64)
                    .is_some_and(|limit| {
                        out.sh_addr
                            .checked_add(out.sh_size)
                            .is_some_and(|end| limit <= end)
                    }),
            "package complete literal outside allocated RO section",
        )?;
        let (load, offset) = unique_file_mapping(elf, bytes, symbol.st_value, expected.len())?;
        require(
            load.p_flags == 4 && bytes.get(offset..offset + expected.len()) == Some(expected),
            "package complete source literal RO bytes differ",
        )?;
        result.push(MergedLiteral {
            source_symbol: name,
            input_symbol_index: input_index,
            input_section: 6,
            input_offset,
            bytes: expected.len(),
            sha256: sha256(expected),
            file_symbol_index: file_index,
            final_symbol_index: final_index,
            final_address: symbol.st_value,
            final_section: symbol.st_shndx,
            final_file_offset: offset,
            anchor_symbol_index: anchor_index,
            anchor_address: address,
        });
    }
    Ok(result)
}
fn strong_ssp<'o>(
    owner: &ObjectInput<'_>,
    objects: &'o [ObjectInput<'o>],
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<(&'o ObjectInput<'o>, RelocatedDefinition)> {
    let mut selected = Vec::new();
    for object in objects {
        for s in object.elf.syms.iter().filter(|s| {
            object.elf.strtab.get_at(s.st_name) == Some("__init_ssp")
                && s.st_shndx != 0
                && s.st_bind() == sym::STB_GLOBAL
        }) {
            if role_section_is_selected(map, object, &s)? {
                require(
                    object.archive_path == owner.archive_path
                        && object.member_name == "__stack_chk_fail.lo",
                    "package SSP selected physical owner differs",
                )?;
                selected.push(object);
            }
        }
    }
    require(selected.len() == 1, "package strong SSP absent/duplicate")?;
    let object = selected[0];
    let joined =
        join_selected_initializer(InitializerRole::MuslSsp, map, object, objects, elf, bytes)?;
    Ok((object, joined))
}
fn ssp_override(
    owner: &ObjectInput<'_>,
    objects: &[ObjectInput<'_>],
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<SspOverride> {
    require_native_member(InitializerRole::PackageLibc, owner)?;
    let (index, weak) = weak_source_form(owner)?;
    let (strong, joined) = strong_ssp(owner, objects, map, elf, bytes)?;
    Ok(SspOverride {
        source_symbol_index: index,
        source_section: weak.st_shndx,
        selected_member_name: strong.member_name.into(),
        selected_member_ordinal: strong.ordinal,
        selected_member_header: strong.header_offset,
        selected_member_sha256: sha256(strong.bytes),
        final_entry: joined.address,
        complete_bytes: joined.bytes,
    })
}
fn weak_source_form(owner: &ObjectInput<'_>) -> Result<(usize, sym::Sym)> {
    let (index, weak) = named(&owner.elf, "__init_ssp")?;
    let section = owner
        .elf
        .section_headers
        .get(weak.st_shndx)
        .ok_or("package SSP weak section absent")?;
    require(
        weak.st_bind() == sym::STB_WEAK
            && weak.st_type() == sym::STT_FUNC
            && weak.st_visibility() == sym::STV_HIDDEN
            && weak.st_value == 0
            && weak.st_size == 1
            && weak.st_shndx == 5
            && section.sh_type == 1
            && section.sh_flags == 6
            && section.sh_size == 1
            && section_name(&owner.elf, &weak)? == ".text.dummy1"
            && section_file_bytes(section, owner.bytes)? == [0xc3],
        "package SSP exact weak source fallback differs",
    )?;
    Ok((index, weak))
}
pub(super) fn resolve_libc_target(
    map: &str,
    owner: &ObjectInput<'_>,
    index: usize,
    objects: &[ObjectInput<'_>],
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<SelectedTarget> {
    let source = owner
        .elf
        .syms
        .get(index)
        .ok_or("package libc source target absent")?;
    let name = owner
        .elf
        .strtab
        .get_at(source.st_name)
        .ok_or("package libc target name absent")?;
    let address = match name {
        ".LC0" | ".LC1" => {
            let rows = literals(owner, map, elf, bytes)?;
            let chosen = rows
                .iter()
                .find(|row| row.source_symbol == name && row.input_symbol_index == index)
                .ok_or("package source literal index differs")?;
            chosen.final_address
        }
        "__init_ssp" => ssp_override(owner, objects, map, elf, bytes)?.final_entry,
        _ => return resolve_input_target(map, owner, index, objects, elf, bytes),
    };
    Ok(SelectedTarget {
        mapped_input_value: address,
    })
}
pub(super) fn validate_literal_relocation(
    owner: &ObjectInput<'_>,
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
    offset: u64,
    index: usize,
) -> Result<()> {
    let name = match offset {
        184 => ".LC0",
        330 => ".LC1",
        _ => return Ok(()),
    };
    let rows = literals(owner, map, elf, bytes)?;
    let row = rows
        .iter()
        .find(|row| row.source_symbol == name)
        .ok_or("package merged literal absent")?;
    require(
        index == row.final_symbol_index,
        "package retained literal relocation symbol INDEX differs",
    )
}

fn fallback_target(
    map: &str,
    owner: &ObjectInput<'_>,
    index: usize,
    offset: u64,
    objects: &[ObjectInput<'_>],
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<SelectedTarget> {
    let source = owner
        .elf
        .syms
        .get(index)
        .ok_or("package fallback target absent")?;
    let suffix = match offset {
        6 => "14CALLBACK_MXCSR",
        14 => "8dispatch",
        19 => "21completion_generation",
        _ => return Err("package fallback target field differs".into()),
    };
    require(
        source.st_type() == sym::STT_SECTION
            && source.st_bind() == sym::STB_LOCAL
            && source.st_value == 0
            && source.st_size == 0,
        "package fallback source section target differs",
    )?;
    let name = section_name(&owner.elf, &source)?;
    let prefix = if offset == 6 { ".rodata." } else { ".text." };
    let rust = name
        .strip_prefix(prefix)
        .ok_or("package fallback target section kind differs")?;
    let expected = format!("_RNvNtNtCs_15reverie_inguest5guest12continuation{suffix}");
    require(
        !rust.contains(".llvm.")
            && canonical_rust_symbol(rust).as_deref() == Some(expected.as_str()),
        "package fallback exact source operand path differs",
    )?;
    let definitions = owner
        .elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx == source.st_shndx && owner.elf.strtab.get_at(s.st_name) == Some(rust)
        })
        .collect::<Vec<_>>();
    require(
        definitions.len() == 1,
        "package fallback source operand absent/duplicate",
    )?;
    let target = definitions[0];
    let section = &owner.elf.section_headers[source.st_shndx];
    require(
        target.st_value == 0
            && target.st_size == section.sh_size
            && target.st_size > 0
            && target.st_size <= 4096
            && section.sh_type == 1
            && target.st_bind() == sym::STB_LOCAL
            && target.st_type()
                == if offset == 6 {
                    sym::STT_OBJECT
                } else {
                    sym::STT_FUNC
                },
        "package fallback complete source operand extent differs",
    )?;
    let selected = resolve_input_target(map, owner, index, objects, elf, bytes)?;
    let finals = elf
        .syms
        .iter()
        .filter(|s| elf.strtab.get_at(s.st_name) == Some(rust) && s.st_shndx != 0)
        .collect::<Vec<_>>();
    require(
        finals.len() == 1
            && finals[0].st_value == selected.mapped_input_value
            && finals[0].st_size == target.st_size
            && finals[0].st_type() == target.st_type()
            && finals[0].st_bind() == sym::STB_LOCAL,
        "package fallback selected final operand differs",
    )?;
    let final_section = elf
        .section_headers
        .get(finals[0].st_shndx)
        .ok_or("package fallback final operand section absent")?;
    require(
        final_section.sh_type == 1
            && final_section.sh_flags & 7 == section.sh_flags
            && finals[0].st_value >= final_section.sh_addr
            && finals[0]
                .st_value
                .checked_add(target.st_size)
                .is_some_and(|end| {
                    final_section
                        .sh_addr
                        .checked_add(final_section.sh_size)
                        .is_some_and(|limit| end <= limit)
                }),
        "package fallback final operand escapes declared section",
    )?;
    let length = usize::try_from(target.st_size).map_err(|_| "package target size")?;
    let (mapping, at) = unique_file_mapping(elf, bytes, selected.mapped_input_value, length)?;
    if offset == 6 {
        require(
            target.st_size == 4
                && section.sh_flags == 2
                && mapping.p_flags == 4
                && section_file_bytes(section, owner.bytes)? == [0x80, 0x1f, 0, 0]
                && bytes.get(at..at + 4) == Some(&[0x80, 0x1f, 0, 0]),
            "package fallback MXCSR complete source/RO value differs",
        )?;
    } else {
        require(
            section.sh_flags == 6 && mapping.p_flags == 5,
            "package fallback selected call target not RX",
        )?;
    }
    Ok(selected)
}
const FALLBACK_SECTION: &str = ".text.reverie_inguest_fallback_entry";

fn fallback_input(owner: &ObjectInput<'_>) -> Result<sym::Sym> {
    require(
        owner.member_name.starts_with("reverie_inguest-"),
        "package fallback runtime member differs",
    )?;
    let (_, symbol) = named(&owner.elf, "fallback_entry")?;
    let dedicated = section_name(&owner.elf, &symbol)? == FALLBACK_SECTION;
    let section = owner
        .elf
        .section_headers
        .get(symbol.st_shndx)
        .ok_or("package fallback section absent")?;
    require(
        symbol.st_bind() == sym::STB_GLOBAL
            && symbol.st_visibility() == sym::STV_HIDDEN
            && symbol.st_type() == sym::STT_FUNC
            && symbol.st_value == 0
            && symbol.st_size == 48
            && section.sh_type == 1
            && section.sh_flags == 6
            && section.sh_size == if dedicated { 48 } else { 289 }
            && section.sh_addralign == 16
            && (dedicated || section_name(&owner.elf, &symbol)? == ".text"),
        "package fallback exact complete function/contribution differs",
    )?;
    let mut aliases = vec![
        ("fallback_completion_syscall", 44, 0, sym::STT_NOTYPE),
        ("fallback_completion_return", 46, 0, sym::STT_NOTYPE),
    ];
    if dedicated {
        // The whole source-owned contribution is the one complete function.
        // No compiler-selected neighboring function is a custody witness.
        require(
            owner
                .elf
                .syms
                .iter()
                .filter(|s| s.st_shndx == symbol.st_shndx)
                .count()
                == 3,
            "package fallback dedicated input has extra aliases",
        )?;
    } else {
        // Keep the previously qualified historical contribution closed.
        aliases.extend([
            ("reverie_native_launch_syscall", 48, 55, sym::STT_FUNC),
            ("reverie_inguest_trusted_syscall", 112, 44, sym::STT_FUNC),
            (
                "reverie_inguest_trusted_syscall_ip",
                144,
                0,
                sym::STT_NOTYPE,
            ),
            (
                "reverie_inguest_trusted_syscall_return_ip",
                146,
                0,
                sym::STT_NOTYPE,
            ),
        ]);
    }
    for (name, offset, size, kind) in aliases {
        let (_, alias) = named(&owner.elf, name)?;
        require(
            alias.st_shndx == symbol.st_shndx
                && alias.st_value == offset
                && alias.st_size == size
                && alias.st_type() == kind
                && alias.st_bind() == sym::STB_GLOBAL
                && alias.st_visibility() == sym::STV_HIDDEN,
            "package fallback exact input aliases differ",
        )?;
    }
    let rows = relocation_rows(owner, symbol.st_shndx, 48)?;
    require(
        rows.len() == 3
            && rows
                .iter()
                .zip([(6, 2, -4), (14, 4, -4), (19, 4, -4)])
                .all(|(a, b)| (a.0, a.1, a.2) == b),
        "package fallback exact three relocation fields differ",
    )?;
    Ok(symbol)
}
fn emitted_rows(
    elf: &Elf<'_>,
    bytes: &[u8],
    section: usize,
    address: u64,
    extent: usize,
) -> Result<Vec<(usize, u32, i64, usize)>> {
    let table = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, table)?;
    let end = address
        .checked_add(extent as u64)
        .ok_or("package final end overflow")?;
    let mut result = Vec::new();
    for (index, relocs) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *index, table, relocs.len())?;
        for r in relocs.iter() {
            let width = checked_relocation_span(elf, rs, r.r_offset, r.r_type)?;
            let target = &elf.section_headers[rs.sh_info as usize];
            if !selected_field_overlap(target, r.r_offset, r.r_type, address, end)? {
                continue;
            }
            require(
                rs.sh_info as usize == section
                    && r.r_offset >= address
                    && width.is_some_and(|n| {
                        r.r_offset.checked_add(n).is_some_and(|limit| limit <= end)
                    }),
                "package retained relocation crosses/declares another owner",
            )?;
            result.push((
                (r.r_offset - address) as usize,
                r.r_type,
                r.r_addend
                    .ok_or("package retained relocation addend absent")?,
                r.r_sym,
            ));
        }
    }
    result.sort_by_key(|r| r.0);
    Ok(result)
}
fn join_fallback(
    owner: &ObjectInput<'_>,
    objects: &[ObjectInput<'_>],
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<RelocatedDefinition> {
    let symbol = fallback_input(owner)?;
    let address = mapped_definition(map, owner, &symbol)?;
    let dedicated = section_name(&owner.elf, &symbol)? == FALLBACK_SECTION;
    let ordinary = if dedicated {
        None
    } else {
        let (_, ordinary) = named(elf, "reverie_inguest_trusted_syscall")?;
        require(
            ordinary.st_value == address + 112
                && ordinary.st_size == 44
                && ordinary.st_type() == sym::STT_FUNC
                && ordinary.st_bind() == sym::STB_LOCAL
                && ordinary.st_visibility() == sym::STV_HIDDEN,
            "package fallback final ordinary physical contribution differs",
        )?;
        Some(ordinary)
    };
    let (_, linked) = named(elf, "fallback_entry")?;
    require(
        linked.st_value == address
            && linked.st_size == 48
            && linked.st_type() == sym::STT_FUNC
            && linked.st_bind() == sym::STB_LOCAL
            && linked.st_visibility() == sym::STV_HIDDEN,
        "package fallback final extent/binding differs",
    )?;
    let section = elf
        .section_headers
        .get(linked.st_shndx)
        .ok_or("package fallback final section absent")?;
    require(
        ordinary.is_none_or(|s| s.st_shndx == linked.st_shndx)
            && section.sh_type == 1
            && section.sh_flags & 7 == 6
            && address >= section.sh_addr
            && address
                .checked_add(if dedicated { 48 } else { 156 })
                .is_some_and(|end| {
                    section
                        .sh_addr
                        .checked_add(section.sh_size)
                        .is_some_and(|limit| end <= limit)
                }),
        "package fallback/ordinary contribution escapes declared RX section",
    )?;
    if dedicated {
        require(
            elf.syms
                .iter()
                .filter(|s| s.st_shndx != 0 && s.st_value >= address && s.st_value < address + 48)
                .count()
                == 3,
            "package fallback dedicated final body has extra aliases",
        )?;
    }
    for (name, offset) in [
        ("fallback_completion_syscall", 44),
        ("fallback_completion_return", 46),
    ] {
        let (_, alias) = named(elf, name)?;
        require(
            alias.st_shndx == linked.st_shndx
                && alias.st_value == address + offset
                && alias.st_size == 0
                && alias.st_type() == sym::STT_NOTYPE
                && alias.st_bind() == sym::STB_LOCAL
                && alias.st_visibility() == sym::STV_HIDDEN,
            "package fallback final completion alias differs",
        )?;
    }
    let input =
        &section_file_bytes(&owner.elf.section_headers[symbol.st_shndx], owner.bytes)?[..48];
    let (mapping, at) = unique_file_mapping(elf, bytes, address, 48)?;
    require(mapping.p_flags == 5, "package fallback final body not RX")?;
    let source = relocation_rows(owner, symbol.st_shndx, 48)?
        .iter()
        .map(|&(offset, kind, addend, index)| {
            Ok(InputRelocation {
                offset: offset as usize,
                kind,
                addend,
                target: fallback_target(map, owner, index, offset, objects, elf, bytes)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let emitted = emitted_rows(elf, bytes, linked.st_shndx, address, 48)?
        .iter()
        .map(|&(offset, kind, addend, index)| {
            Ok(FinalRelocation {
                offset,
                kind,
                addend,
                symbol_value: elf
                    .syms
                    .get(index)
                    .ok_or("package final symbol absent")?
                    .st_value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut joined = join_relocated_body(
        elf,
        bytes,
        address,
        input,
        &bytes[at..at + 48],
        &source,
        &emitted,
    )?;
    joined.member = Some((owner.member_name.into(), owner.ordinal, owner.header_offset));
    joined.member_sha256 = sha256(owner.bytes);
    joined.input_body_sha256 = sha256(input);
    joined.section_index = symbol.st_shndx;
    Ok(joined)
}

fn role_body(
    role: InitializerRole,
    owner: &ObjectInput<'_>,
    objects: &[ObjectInput<'_>],
    map: &str,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<RoleBody> {
    let joined = if matches!(role, InitializerRole::PackageFallback) {
        join_fallback(owner, objects, map, elf, bytes)?
    } else {
        join_selected_initializer(role, map, owner, objects, elf, bytes)?
    };
    let (_, symbol) = named(elf, role.symbol())?;
    let finals = emitted_rows(elf, bytes, symbol.st_shndx, joined.address, joined.bytes)?;
    let source = relocation_rows(owner, joined.section_index, joined.bytes)?;
    require(
        source.len() == finals.len(),
        "package observation relocation counts differ",
    )?;
    let mut relocations = Vec::new();
    for (&(offset, kind, addend, index), &(fo, fk, fa, fi)) in source.iter().zip(&finals) {
        require(
            offset as usize == fo && kind == fk,
            "package observation relocation pairing differs",
        )?;
        let target = owner
            .elf
            .syms
            .get(index)
            .ok_or("package observation source symbol absent")?;
        let name = target_name(owner, &target)?;
        let chosen = match role {
            InitializerRole::PackageFallback => {
                fallback_target(map, owner, index, offset, objects, elf, bytes)?
            }
            InitializerRole::PackageLibc => {
                resolve_libc_target(map, owner, index, objects, elf, bytes)?
            }
            _ => resolve_input_target(map, owner, index, objects, elf, bytes)?,
        };
        let selection =
            if matches!(role, InitializerRole::PackageLibc) && (name == ".LC0" || name == ".LC1") {
                "anchored_merged_literal"
            } else if matches!(role, InitializerRole::PackageLibc) && name == "__init_ssp" {
                "selected_strong_ssp"
            } else {
                "map_selected_input"
            };
        relocations.push(Relocation {
            offset: fo,
            kind,
            addend,
            source_symbol_index: index,
            source_symbol: name,
            selected_target: chosen.mapped_input_value,
            selection,
            final_symbol_index: fi,
            final_symbol_value: elf
                .syms
                .get(fi)
                .ok_or("package final symbol absent")?
                .st_value,
            final_addend: fa,
        });
    }
    let sites = match role {
        InitializerRole::PackageFallback => vec![Site {
            offset: 44,
            number: 39,
            operation: 0,
        }],
        InitializerRole::PackageLibc => vec![
            Site {
                offset: 302,
                number: 7,
                operation: 3,
            },
            Site {
                offset: 388,
                number: 2,
                operation: 4,
            },
        ],
        InitializerRole::PackageTp => vec![Site {
            offset: 44,
            number: 218,
            operation: 2,
        }],
        _ => return Err("package role outside closed set".into()),
    };
    let (_, at) = unique_file_mapping(elf, bytes, joined.address, joined.bytes)?;
    let body = &bytes[at..at + joined.bytes];
    for site in &sites {
        require(
            body.get(site.offset..site.offset + 2) == Some(&[0x0f, 0x05]),
            "package exact source syscall offset differs",
        )?;
    }
    let aliases = if matches!(role, InitializerRole::PackageFallback) {
        require(
            body.get(44..48) == Some(&[0x0f, 0x05, 0x0f, 0x0b]),
            "package exact completion bytes differ",
        )?;
        BTreeMap::from([
            ("fallback_completion_syscall", 44),
            ("fallback_completion_return", 46),
        ])
    } else {
        BTreeMap::new()
    };
    Ok(RoleBody {
        symbol: role.symbol(),
        member_name: owner.member_name.into(),
        member_ordinal: owner.ordinal,
        member_header: owner.header_offset,
        member_sha256: joined.member_sha256,
        input_section: joined.section_index,
        input_offset: 0,
        complete_bytes: joined.bytes,
        input_body_sha256: joined.input_body_sha256,
        final_entry: joined.address,
        final_body_sha256: sha256(body),
        relocations,
        sites,
        aliases,
    })
}

pub(super) fn observe(
    proof: &SelectedInitializerDefinitions,
    sources: &[FileIdentity],
) -> Result<PackageRoleObservation> {
    proof.verify()?;
    require(
        sources.len() == 3
            && sources[0]
                .path
                .ends_with("reverie-inguest/src/guest/continuation.rs")
            && sources[1].sha256
                == "5e5487e579a3c8f14fcb38bb54f2ede10a74f94130ebb9134dcba8d5f28c0cf4"
            && sources[2].sha256
                == "6cb2c2f1ce53b87b9c7f2452010925ddf3356c4ae40d5e8a77f7bee3960febd6",
        "package role source custody differs",
    )?;
    for file in sources {
        file.verify()?;
    }
    let core = &proof.core;
    let archives = [&core.runtime, &core.libc];
    let mut backing = extract_objects(&core.runtime, 0)?;
    backing.extend(extract_objects(&core.libc, 1)?);
    let objects = backing
        .iter()
        .map(|member| {
            Ok(ObjectInput {
                archive_path: &archives[member.archive_index].path,
                member_name: &member.name,
                ordinal: member.ordinal,
                header_offset: member.header,
                bytes: &member.bytes,
                elf: Elf::parse(&member.bytes).map_err(|e| e.to_string())?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for object in &objects {
        checked_object_symbol_authority(&object.elf, object.bytes)?;
    }
    let raw = fs::read(&core.artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&raw).map_err(|e| e.to_string())?;
    static_image_metadata(&elf, &raw)?;
    let map = fs::read_to_string(&core.map.path).map_err(|e| e.to_string())?;
    let mut roles = Vec::new();
    for role in [
        InitializerRole::PackageFallback,
        InitializerRole::PackageLibc,
        InitializerRole::PackageTp,
    ] {
        let owner = select_role(&role, &objects, &map, &core.runtime.path)?;
        roles.push(role_body(role, owner, &objects, &map, &elf, &raw)?);
    }
    let libc = select_role(
        &InitializerRole::PackageLibc,
        &objects,
        &map,
        &core.runtime.path,
    )?;
    let ssp = ssp_override(libc, &objects, &map, &elf, &raw)?;
    require(
        ssp.final_entry == proof.ssp.address
            && ssp.complete_bytes == proof.ssp.bytes
            && ssp.selected_member_sha256 == proof.ssp.member_sha256,
        "package SSP differs from same-token selected definition",
    )?;
    require(
        roles.iter().map(|r| r.relocations.len()).sum::<usize>() == 20,
        "package complete twenty-field census differs",
    )?;
    let observed = PackageRoleObservation {
        schema: "reverie.private-static-package-role-observation.v1",
        scope: "THREE_COMPLETE_SOURCE_MEMBER_RELOCATED_BODIES_AND_FINITE_SITE_IDENTITIES_ONLY",
        implementation_sha256: package_role_implementation_sha256(),
        runtime_archive: core.runtime.clone(),
        libc_archive: core.libc.clone(),
        artifact: core.artifact.clone(),
        link_map: core.map.clone(),
        sources: sources.to_vec(),
        roles,
        merged_literals: literals(libc, &map, &elf, &raw)?,
        ssp_override: ssp,
    };
    observed.to_json_pretty()?;
    // Preserve all independent closes, including when a role/body failed: the
    // enclosing original link method owns its complete input/output ledger.
    proof.verify()?;
    for file in sources {
        file.verify()?;
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Retained exact ET_REL DATA fixtures. None constructs a source/archive owner.
    const LIBC: &[u8] = &include!("../../../tests/fixtures/package_roles_libc_member.rs");
    const TP: &[u8] = &include!("../../../tests/fixtures/package_roles_tp_member.rs");
    const FALLBACK: &[u8] = &include!("../../../tests/fixtures/package_roles_fallback_member.rs");
    fn object(raw: &[u8], role: InitializerRole) -> ObjectInput<'_> {
        let (path, name, ordinal, header) = match role {
            InitializerRole::PackageLibc => ("/bound/libc.a", "__libc_start_main.lo", 135, 699442),
            InitializerRole::PackageTp => ("/bound/libc.a", "__init_tls.lo", 134, 692078),
            // Deliberately no historical runtime member coordinates/hash credential.
            _ => ("/bound/runtime.a", "reverie_inguest-data.o", 0, 8),
        };
        ObjectInput {
            archive_path: Path::new(path),
            member_name: name,
            ordinal,
            header_offset: header,
            bytes: raw,
            elf: Elf::parse(raw).unwrap(),
        }
    }
    fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
        b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }
    type Row<'a> = (&'a str, u8, u8, usize, u64, u64);
    // Tiny real ELF DATA with distinct RX and RO mappings, raw symtab and RELA.
    fn image(rows: &[Row<'_>], body: &[u8], relocs: &[(u64, u32, i64, usize)]) -> Vec<u8> {
        let mut b = vec![0; 0xa000];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, width, value) in [
            (16, 2, 2),
            (18, 2, 62),
            (20, 4, 1),
            (24, 8, 0x401000),
            (32, 8, 64),
            (40, 8, 0x9000),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 2),
            (58, 2, 64),
            (60, 2, 7),
            (62, 2, 5),
        ] {
            put(&mut b, at, width, value);
        }
        for (i, flags, off, address, size) in [
            (0, 5, 0x1000, 0x401000, 0x4000),
            (1, 4, 0x6000, 0x500000, 0x1000),
        ] {
            let at = 64 + i * 56;
            for (field, width, value) in [
                (0, 4, 1),
                (4, 4, flags),
                (8, 8, off),
                (16, 8, address),
                (24, 8, address),
                (32, 8, size),
                (40, 8, size),
                (48, 8, 4096),
            ] {
                put(&mut b, at + field, width, value);
            }
        }
        b[0x1000..0x1000 + body.len()].copy_from_slice(body);
        b[0x6010..0x601a].copy_from_slice(b"/dev/null\0");
        let mut strings = vec![0];
        for (i, (name, info, visibility, section, address, size)) in rows.iter().enumerate() {
            let at = 0x8000 + (i + 1) * 24;
            put(&mut b, at, 4, strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            b[at + 4] = *info;
            b[at + 5] = *visibility;
            put(&mut b, at + 6, 2, *section as u64);
            put(&mut b, at + 8, 8, *address);
            put(&mut b, at + 16, 8, *size);
        }
        b[0x8800..0x8800 + strings.len()].copy_from_slice(&strings);
        let shnames = b"\0.text\0.rodata\0.symtab\0.strtab\0.shstrtab\0.rela.text\0";
        b[0x8f00..0x8f00 + shnames.len()].copy_from_slice(shnames);
        for (i, row) in [
            [1, 1, 6, 0x401000, 0x1000, 0x4000, 0, 0, 16, 0],
            [7, 1, 0x200032, 0x500000, 0x6000, 0x1000, 0, 0, 1, 0],
            [
                15,
                2,
                0,
                0,
                0x8000,
                ((rows.len() + 1) * 24) as u64,
                4,
                (rows.len() + 1) as u64,
                8,
                24,
            ],
            [23, 3, 0, 0, 0x8800, strings.len() as u64, 0, 0, 1, 0],
            [31, 3, 0, 0, 0x8f00, shnames.len() as u64, 0, 0, 1, 0],
            [41, 4, 0, 0, 0x8600, (relocs.len() * 24) as u64, 3, 1, 8, 24],
        ]
        .iter()
        .enumerate()
        {
            let at = 0x9000 + (i + 1) * 64;
            for (j, width, field) in [
                (0, 4, 0),
                (4, 4, 1),
                (8, 8, 2),
                (16, 8, 3),
                (24, 8, 4),
                (32, 8, 5),
                (40, 4, 6),
                (44, 4, 7),
                (48, 8, 8),
                (56, 8, 9),
            ] {
                put(&mut b, at + j, width, row[field]);
            }
        }
        for (i, (offset, kind, addend, symbol)) in relocs.iter().enumerate() {
            let at = 0x8600 + i * 24;
            put(&mut b, at, 8, *offset);
            put(
                &mut b,
                at + 8,
                8,
                ((*symbol as u64) << 32) | u64::from(*kind),
            );
            put(&mut b, at + 16, 8, *addend as u64);
        }
        b
    }
    fn literal_image() -> Vec<u8> {
        image(
            &[
                (
                    "__libc_start_main.c",
                    sym::STT_FILE,
                    0,
                    section_header::SHN_ABS as usize,
                    0,
                    0,
                ),
                (".LC0", 0, 0, 2, 0x500000, 0),
                (".LC1", 0, 0, 2, 0x500010, 0),
                ("__init_libc", sym::STT_FUNC, 2, 1, 0x401000, 413),
                (
                    "other.c",
                    sym::STT_FILE,
                    0,
                    section_header::SHN_ABS as usize,
                    0,
                    0,
                ),
                (".LC0", 0, 0, 2, 0x500000, 0),
            ],
            &[0x90; 413],
            &[],
        )
    }
    fn map_row(owner: &ObjectInput<'_>, index: usize, address: u64) -> String {
        let s = &owner.elf.section_headers[index];
        format!(
            "{address:x} {address:x} {:x} {} {}({}):({})\n",
            s.sh_size,
            s.sh_addralign,
            owner.archive_path.display(),
            owner.member_name,
            owner.elf.shdr_strtab.get_at(s.sh_name).unwrap()
        )
    }
    #[test]
    fn package_roles_native_members_and_complete_form_are_exact() {
        for (raw, role) in [
            (LIBC, InitializerRole::PackageLibc),
            (TP, InitializerRole::PackageTp),
        ] {
            let obj = object(raw, role);
            validate_native_input(role, &obj).unwrap();
            let mut wrong = object(raw, role);
            wrong.ordinal += 1;
            assert!(
                validate_native_input(role, &wrong)
                    .unwrap_err()
                    .contains("physical member")
            );
            let (_, s) = named(&obj.elf, role.symbol()).unwrap();
            let at = obj.elf.section_headers[s.st_shndx].sh_offset as usize;
            for n in [0, s.st_size as usize / 2, s.st_size as usize - 1] {
                let mut bad = raw.to_vec();
                bad[at + n] ^= 1;
                assert!(validate_native_input(role, &object(&bad, role)).is_err());
            }
        }
    }
    #[test]
    fn package_roles_all_seventeen_native_relocation_records_are_checked() {
        for (raw, role) in [
            (LIBC, InitializerRole::PackageLibc),
            (TP, InitializerRole::PackageTp),
        ] {
            let obj = object(raw, role);
            let (_, s) = named(&obj.elf, role.symbol()).unwrap();
            let rel = obj
                .elf
                .section_headers
                .iter()
                .find(|h| h.sh_type == 4 && h.sh_info as usize == s.st_shndx)
                .unwrap();
            native_input_form(role, &obj).unwrap();
            for n in 0..rel.sh_size as usize / 24 {
                for field in [0, 8, 12, 16] {
                    let mut bad = raw.to_vec();
                    bad[rel.sh_offset as usize + n * 24 + field] ^= 1;
                    assert!(
                        native_input_form(role, &object(&bad, role)).is_err(),
                        "{n}/{field}"
                    );
                }
            }
        }
    }
    #[test]
    fn package_roles_weak_ssp_is_distinct_from_named_dummy() {
        let obj = object(LIBC, InitializerRole::PackageLibc);
        let (index, weak) = weak_source_form(&obj).unwrap();
        assert_eq!(weak.st_shndx, 5);
        assert_eq!(named(&obj.elf, "dummy").unwrap().1.st_shndx, 4);
        let table = obj
            .elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 2)
            .unwrap();
        for (field, width, value) in [(4, 1, 0x12), (5, 1, 0), (6, 2, 4), (8, 8, 1), (16, 8, 2)] {
            let mut bad = LIBC.to_vec();
            put(
                &mut bad,
                table.sh_offset as usize + index * 24 + field,
                width,
                value,
            );
            assert!(weak_source_form(&object(&bad, InitializerRole::PackageLibc)).is_err());
        }
    }
    #[test]
    fn package_roles_merged_strings_keep_member_group_and_complete_ro_bounds() {
        let owner = object(LIBC, InitializerRole::PackageLibc);
        let raw = literal_image();
        let elf = Elf::parse(&raw).unwrap();
        let map = map_row(&owner, 7, 0x401000);
        let rows = literals(&owner, &map, &elf, &raw).unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| (r.input_offset, r.bytes, r.final_symbol_index))
                .collect::<Vec<_>>(),
            [(0, 1, 2), (1, 10, 3)]
        );
        assert_ne!(rows[0].final_address + 1, rows[1].final_address);
        validate_literal_relocation(&owner, &map, &elf, &raw, 184, 2).unwrap();
        // Same bytes and same address in another FILE group cannot substitute.
        assert!(
            validate_literal_relocation(&owner, &map, &elf, &raw, 184, 6)
                .unwrap_err()
                .contains("INDEX")
        );
    }
    #[test]
    fn package_roles_file_anchors_require_complete_local_absolute_shape() {
        let owner = object(LIBC, InitializerRole::PackageLibc);
        let raw = literal_image();
        let map = map_row(&owner, 7, 0x401000);
        let elf = Elf::parse(&raw).unwrap();
        literal_form(&owner, &map, &elf, &raw).unwrap();
        let table = owner
            .elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 2)
            .unwrap();
        for (field, width, value) in [(4, 1, 0x14), (5, 1, 2), (6, 2, 0), (8, 8, 1), (16, 8, 1)] {
            let mut bad = LIBC.to_vec();
            put(
                &mut bad,
                table.sh_offset as usize + 24 + field,
                width,
                value,
            );
            assert!(
                literal_form(
                    &object(&bad, InitializerRole::PackageLibc),
                    &map,
                    &elf,
                    &raw
                )
                .is_err()
            );
            let mut bad = raw.clone();
            put(&mut bad, 0x8000 + 24 + field, width, value);
            let bad_elf = Elf::parse(&bad).unwrap();
            assert!(literal_form(&owner, &map, &bad_elf, &bad).is_err());
        }
    }
    #[test]
    fn package_roles_merged_strings_refuse_foreign_duplicate_labels_and_wrong_map() {
        let owner = object(LIBC, InitializerRole::PackageLibc);
        let map = map_row(&owner, 7, 0x401000);
        let raw = literal_image();
        for (at, width, value) in [
            (0x8000 + 4 * 24 + 8, 8, 0x401001), // anchor moved from the selected member.
            (0x8000 + 2 * 24 + 6, 2, 1),        // literal in text.
            (0x8000 + 2 * 24 + 8, 8, 0x501000), // outside RO span.
            (0x8000 + 3 * 24, 4, raw[0x8000 + 2 * 24] as u64), // duplicate LC0, missing LC1.
            (0x8000 + 4 * 24 + 4, 1, sym::STT_FILE as u64), // anchor splits group.
            (0x9000 + 2 * 64 + 8, 8, 3),        // writable section.
            (64 + 56 + 4, 4, 6),                // writable actual mapping.
        ] {
            let mut bad = raw.clone();
            put(&mut bad, at, width, value);
            let elf = Elf::parse(&bad).unwrap();
            assert!(literals(&owner, &map, &elf, &bad).is_err(), "offset {at:x}");
        }
        let mut bad = raw.clone();
        bad[0x6019] = 1;
        let elf = Elf::parse(&bad).unwrap();
        assert!(literals(&owner, &map, &elf, &bad).is_err());
        let elf = Elf::parse(&raw).unwrap();
        assert!(literals(&owner, &map.replace("401000", "401001"), &elf, &raw).is_err());
    }
    #[test]
    fn package_roles_complete_input_string_keyset_and_labels_are_not_optional() {
        let owner = object(LIBC, InitializerRole::PackageLibc);
        let raw = literal_image();
        let elf = Elf::parse(&raw).unwrap();
        let map = map_row(&owner, 7, 0x401000);
        let s = &owner.elf.section_headers[6];
        for n in 0..11 {
            let mut bad = LIBC.to_vec();
            bad[s.sh_offset as usize + n] ^= 1;
            assert!(
                literal_form(
                    &object(&bad, InitializerRole::PackageLibc),
                    &map,
                    &elf,
                    &raw
                )
                .is_err()
            );
        }
        let table = owner
            .elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 2)
            .unwrap();
        for (field, width, value) in [(6, 2, 7), (8, 8, 2), (16, 8, 1), (4, 1, 0x10)] {
            let mut bad = LIBC.to_vec();
            put(
                &mut bad,
                table.sh_offset as usize + 18 * 24 + field,
                width,
                value,
            );
            assert!(
                literal_form(
                    &object(&bad, InitializerRole::PackageLibc),
                    &map,
                    &elf,
                    &raw
                )
                .is_err()
            );
        }
    }
    fn reconstructed(
        role: InitializerRole,
        raw: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<InputRelocation>, Vec<FinalRelocation>) {
        let obj = object(raw, role);
        let (_, s) = named(&obj.elf, role.symbol()).unwrap();
        let input = section_file_bytes(&obj.elf.section_headers[s.st_shndx], raw).unwrap()
            [..s.st_size as usize]
            .to_vec();
        let mut body = input.clone();
        let mut image = image(&[], &body, &[]);
        let mut source = Vec::new();
        let mut emitted = Vec::new();
        for (i, (offset, kind, addend, _)) in relocation_rows(&obj, s.st_shndx, body.len())
            .unwrap()
            .into_iter()
            .enumerate()
        {
            let target = 0x500800 + i as u64 * 16;
            let slot = 0x500100 + i as u64 * 8;
            if kind == 9 {
                image[0x6000 + (slot - 0x500000) as usize..0x6000 + (slot - 0x500000) as usize + 8]
                    .copy_from_slice(&target.to_le_bytes());
            }
            let field = checked_pc32(
                if kind == 9 { slot } else { target },
                addend,
                0x401000 + offset,
            )
            .unwrap();
            body[offset as usize..offset as usize + 4].copy_from_slice(&field);
            source.push(InputRelocation {
                offset: offset as usize,
                kind,
                addend,
                target: SelectedTarget {
                    mapped_input_value: target,
                },
            });
            emitted.push(FinalRelocation {
                offset: offset as usize,
                kind,
                addend,
                symbol_value: target,
            });
        }
        image[0x1000..0x1000 + body.len()].copy_from_slice(&body);
        (image, input, source, emitted)
    }
    const GENERAL: &[&str] = &[
        "__environ",
        "__libc",
        "__hwcap",
        "__sysinfo",
        "__progname_full",
        "__progname",
        "__init_tls",
        "__set_thread_area",
        "memcpy",
    ];
    fn member_image(rows: &[Row<'_>], body: &[u8], relocs: &[(u64, u32, i64, usize)]) -> Vec<u8> {
        let mut raw = image(rows, body, relocs);
        for (at, width, value) in [
            (16, 2, 1),
            (24, 8, 0),
            (32, 8, 0),
            (56, 2, 0),
            (0x9000 + 64 + 16, 8, 0),
            (0x9000 + 64 + 32, 8, body.len() as u64),
            (0x9000 + 2 * 64 + 16, 8, 0),
            (0x9000 + 3 * 64 + 44, 4, 1),
        ] {
            put(&mut raw, at, width, value);
        }
        raw
    }
    fn native_objects(backing: &[Vec<u8>]) -> Vec<ObjectInput<'_>> {
        vec![
            object(&backing[0], InitializerRole::PackageLibc),
            object(&backing[1], InitializerRole::PackageTp),
            ObjectInput {
                archive_path: Path::new("/bound/libc.a"),
                member_name: "__stack_chk_fail.lo",
                ordinal: 0,
                header_offset: 8,
                bytes: &backing[2],
                elf: Elf::parse(&backing[2]).unwrap(),
            },
            ObjectInput {
                archive_path: Path::new("/bound/libc.a"),
                member_name: "general-data.lo",
                ordinal: 1,
                header_offset: 16,
                bytes: &backing[3],
                elf: Elf::parse(&backing[3]).unwrap(),
            },
        ]
    }
    // Synthetic selected providers exercise the real finite role joins. They
    // never enter a VerifiedStaticSource/archive factory or stand for a real link.
    fn native_image() -> (Vec<Vec<u8>>, Vec<u8>, String) {
        let global = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
        let general_rows = GENERAL
            .iter()
            .enumerate()
            .map(|(i, name)| (*name, global, 0, 1, i as u64 * 8, 8))
            .collect::<Vec<_>>();
        let backing = vec![
            LIBC.to_vec(),
            TP.to_vec(),
            member_image(
                &[
                    ("__init_ssp", global, 0, 1, 0, 6),
                    ("memcpy", sym::STB_GLOBAL << 4, 0, 0, 0, 0),
                ],
                &[0xe8, 0, 0, 0, 0, 0xc3],
                &[(1, 4, -4, 2)],
            ),
            member_image(&general_rows, &[0x90; 72], &[]),
        ];
        let objects = native_objects(&backing);
        let mut rows = vec![
            (
                "__libc_start_main.c",
                sym::STT_FILE,
                0,
                section_header::SHN_ABS as usize,
                0,
                0,
            ),
            (".LC0", 0, 0, 2, 0x500000, 0),
            (".LC1", 0, 0, 2, 0x500010, 0),
            ("__init_libc", sym::STT_FUNC, 2, 1, 0x401000, 413),
            (
                "__init_tls.c",
                sym::STT_FILE,
                0,
                section_header::SHN_ABS as usize,
                0,
                0,
            ),
            ("__init_tp", sym::STT_FUNC, 2, 1, 0x402000, 107),
            (
                "ssp.c",
                sym::STT_FILE,
                0,
                section_header::SHN_ABS as usize,
                0,
                0,
            ),
            ("__init_ssp", sym::STT_FUNC, 2, 1, 0x403000, 6),
        ];
        for (i, name) in GENERAL.iter().enumerate() {
            rows.push((*name, sym::STT_FUNC, 0, 1, 0x404000 + i as u64 * 8, 8));
        }
        rows.extend([
            ("__thread_list_lock", sym::STT_OBJECT, 2, 2, 0x500400, 4),
            (
                "foreign.c",
                sym::STT_FILE,
                0,
                section_header::SHN_ABS as usize,
                0,
                0,
            ),
            (".LC0", 0, 0, 2, 0x500000, 0),
            ("weak_dummy", sym::STT_FUNC, 2, 1, 0x404f00, 1),
        ]);
        let mut final_relocs = Vec::new();
        let mut bodies = Vec::new();
        let mut got = Vec::new();
        for (which, role, address) in [
            (0, InitializerRole::PackageLibc, 0x401000),
            (1, InitializerRole::PackageTp, 0x402000),
            (2, InitializerRole::MuslSsp, 0x403000),
        ] {
            let owner = &objects[which];
            let (_, symbol) = named(&owner.elf, role.symbol()).unwrap();
            let mut body =
                section_file_bytes(&owner.elf.section_headers[symbol.st_shndx], owner.bytes)
                    .unwrap()
                    .to_vec();
            for (offset, kind, addend, index) in
                relocation_rows(owner, symbol.st_shndx, body.len()).unwrap()
            {
                let source = owner.elf.syms.get(index).unwrap();
                let name = owner.elf.strtab.get_at(source.st_name).unwrap();
                let selected = match name {
                    ".LC0" => 2,
                    ".LC1" => 3,
                    "__init_ssp" => 8,
                    "__thread_list_lock" => 18,
                    _ => 9 + GENERAL.iter().position(|n| *n == name).unwrap(),
                };
                let target = rows[selected - 1].4;
                let field_target = if kind == 9 {
                    let slot = 0x500100 + got.len() as u64 * 8;
                    got.push((slot, target));
                    slot
                } else {
                    target
                };
                let field = checked_pc32(field_target, addend, address + offset).unwrap();
                body[offset as usize..offset as usize + 4].copy_from_slice(&field);
                final_relocs.push((address + offset, kind, addend, selected));
            }
            bodies.push((address, body));
        }
        let mut raw = image(&rows, &[], &final_relocs);
        for (address, body) in bodies {
            let at = 0x1000 + (address - 0x401000) as usize;
            raw[at..at + body.len()].copy_from_slice(&body);
        }
        for (slot, target) in got {
            put(&mut raw, 0x6000 + (slot - 0x500000) as usize, 8, target);
        }
        let mut map = map_row(&objects[0], 7, 0x401000)
            + &map_row(&objects[1], 4, 0x402000)
            + &map_row(&objects[2], 1, 0x403000)
            + &map_row(&objects[3], 1, 0x404000);
        map.push_str("500400 500400 4 4 /bound/libc.a(__init_tls.lo):(COMMON)\n");
        drop(objects);
        (backing, raw, map)
    }
    #[test]
    fn package_roles_native_full_joins_include_strong_ssp_literals_and_general_targets() {
        let (backing, raw, map) = native_image();
        let objects = native_objects(&backing);
        let elf = Elf::parse(&raw).unwrap();
        for (i, role, size, count) in [
            (0, InitializerRole::PackageLibc, 413, 12),
            (1, InitializerRole::PackageTp, 107, 5),
        ] {
            checked_object_symbol_authority(&objects[i].elf, objects[i].bytes).unwrap();
            let selected =
                select_role(&role, &objects, &map, Path::new("/bound/runtime.a")).unwrap();
            let row = role_body(role, selected, &objects, &map, &elf, &raw).unwrap();
            assert_eq!((row.complete_bytes, row.relocations.len()), (size, count));
        }
        let ssp = ssp_override(&objects[0], &objects, &map, &elf, &raw).unwrap();
        assert_eq!(
            (ssp.source_section, ssp.final_entry, ssp.complete_bytes),
            (5, 0x403000, 6)
        );
        let rows = literals(&objects[0], &map, &elf, &raw).unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| r.final_symbol_index)
                .collect::<Vec<_>>(),
            [2, 3]
        );
    }
    #[test]
    fn package_roles_native_full_joins_refuse_wrong_ssp_literal_and_emitted_inventory() {
        let (backing, raw, map) = native_image();
        let objects = native_objects(&backing);
        let reject = |bad: &[u8]| {
            let elf = Elf::parse(bad).unwrap();
            assert!(
                role_body(
                    InitializerRole::PackageLibc,
                    &objects[0],
                    &objects,
                    &map,
                    &elf,
                    bad
                )
                .is_err()
            );
        };
        // Same address/bytes in a foreign FILE group is not the selected label.
        let mut bad = raw.clone();
        put(&mut bad, 0x8600 + 7 * 24 + 8, 8, (20u64 << 32) | 2);
        reject(&bad);
        // A relocation that actually calls the weak dummy cannot satisfy the strong join.
        let mut bad = raw.clone();
        put(&mut bad, 0x8600 + 9 * 24 + 8, 8, (21u64 << 32) | 4);
        let field = checked_pc32(0x404f00, -4, 0x401000 + 235).unwrap();
        bad[0x1000 + 235..0x1000 + 239].copy_from_slice(&field);
        reject(&bad);
        let elf = Elf::parse(&raw).unwrap();
        let mut foreign = native_objects(&backing);
        foreign[2].member_name = "foreign-ssp.lo";
        let foreign_map = map.replace("__stack_chk_fail.lo", "foreign-ssp.lo");
        assert!(
            role_body(
                InitializerRole::PackageLibc,
                &foreign[0],
                &foreign,
                &foreign_map,
                &elf,
                &raw
            )
            .is_err()
        );
        for (offset, count) in [(0x401001, 19), (0x401000 + 411, 19)] {
            let mut bad = raw.clone();
            let at = 0x8600 + 18 * 24;
            put(&mut bad, at, 8, offset);
            put(&mut bad, at + 8, 8, (9u64 << 32) | 2);
            put(&mut bad, at + 16, 8, (-4i64) as u64);
            put(&mut bad, 0x9000 + 6 * 64 + 32, 8, count * 24);
            reject(&bad);
        }
        let mut bad = raw.clone();
        put(&mut bad, 0x8600 + 24, 8, 0x401000 + 32);
        reject(&bad);
        let mut bad = raw.clone();
        bad.copy_within(0x8600 + 24..0x8600 + 18 * 24, 0x8600);
        put(&mut bad, 0x9000 + 6 * 64 + 32, 8, 17 * 24);
        reject(&bad);
    }
    #[test]
    fn package_roles_twenty_fields_reconstruct_every_byte_and_reject_redirection() {
        let mut count = 0;
        for (role, raw) in [
            (InitializerRole::PackageFallback, FALLBACK),
            (InitializerRole::PackageLibc, LIBC),
            (InitializerRole::PackageTp, TP),
        ] {
            let (image, input, source, emitted) = reconstructed(role, raw);
            let elf = Elf::parse(&image).unwrap();
            let body = &image[0x1000..0x1000 + input.len()];
            assert_eq!(
                join_relocated_body(&elf, &image, 0x401000, &input, body, &source, &emitted)
                    .unwrap()
                    .bytes,
                input.len()
            );
            count += source.len();
            for n in 0..input.len() {
                if source.iter().any(|r| r.offset <= n && n < r.offset + 4) {
                    continue;
                }
                let mut bad = image.clone();
                bad[0x1000 + n] ^= 1;
                let bad_elf = Elf::parse(&bad).unwrap();
                assert!(
                    join_relocated_body(
                        &bad_elf,
                        &bad,
                        0x401000,
                        &input,
                        &bad[0x1000..0x1000 + input.len()],
                        &source,
                        &emitted
                    )
                    .is_err()
                );
            }
            for n in 0..emitted.len() {
                let mut wrong = emitted.clone();
                wrong[n].symbol_value += 1;
                assert!(
                    join_relocated_body(&elf, &image, 0x401000, &input, body, &source, &wrong)
                        .is_err()
                );
            }
            let mut missing = emitted.clone();
            missing.pop();
            assert!(
                join_relocated_body(&elf, &image, 0x401000, &input, body, &source, &missing)
                    .is_err()
            );
        }
        assert_eq!(count, 20);
    }
    fn fallback_image_from(input: &[u8]) -> (Vec<u8>, String) {
        let owner = object(input, InitializerRole::PackageFallback);
        let symbol = fallback_input(&owner).unwrap();
        let source = relocation_rows(&owner, symbol.st_shndx, 48).unwrap();
        let targets = source
            .iter()
            .map(|r| {
                let section = owner.elf.syms.get(r.3).unwrap();
                let name = section_name(&owner.elf, &section).unwrap();
                let raw_name = name
                    .strip_prefix(if r.0 == 6 { ".rodata." } else { ".text." })
                    .unwrap();
                (
                    raw_name.to_owned(),
                    section.st_shndx,
                    if r.0 == 6 {
                        0x500100
                    } else if r.0 == 14 {
                        0x402000
                    } else {
                        0x403000
                    },
                )
            })
            .collect::<Vec<_>>();
        let mut rows = vec![
            (
                "runtime.rs",
                sym::STT_FILE,
                0,
                section_header::SHN_ABS as usize,
                0,
                0,
            ),
            ("fallback_entry", sym::STT_FUNC, 2, 1, 0x401000, 48),
            ("fallback_completion_syscall", 0, 2, 1, 0x40102c, 0),
            ("fallback_completion_return", 0, 2, 1, 0x40102e, 0),
            (
                "reverie_inguest_trusted_syscall",
                sym::STT_FUNC,
                2,
                1,
                0x401070,
                44,
            ),
        ];
        for (name, index, address) in &targets {
            rows.push((
                name.as_str(),
                if *address == 0x500100 {
                    sym::STT_OBJECT
                } else {
                    sym::STT_FUNC
                },
                0,
                if *address == 0x500100 { 2 } else { 1 },
                *address,
                owner.elf.section_headers[*index].sh_size,
            ));
        }
        let body = section_file_bytes(&owner.elf.section_headers[symbol.st_shndx], input).unwrap();
        let relocs = source
            .iter()
            .enumerate()
            .map(|(i, r)| (0x401000 + r.0, r.1, r.2, 6 + i))
            .collect::<Vec<_>>();
        let mut result = image(&rows, body, &relocs);
        let mut map = map_row(&owner, symbol.st_shndx, 0x401000);
        for (i, (_, section, address)) in targets.iter().enumerate() {
            map.push_str(&map_row(&owner, *section, *address));
            let data = section_file_bytes(&owner.elf.section_headers[*section], input).unwrap();
            let at = if *address == 0x500100 {
                0x6100
            } else if *address == 0x402000 {
                0x2000
            } else {
                0x3000
            };
            result[at..at + data.len()].copy_from_slice(data);
            let r = source[i];
            let encoded = checked_pc32(*address, r.2, 0x401000 + r.0).unwrap();
            result[0x1000 + r.0 as usize..0x1000 + r.0 as usize + 4].copy_from_slice(&encoded);
        }
        (result, map)
    }
    fn fallback_image() -> (Vec<u8>, String) {
        fallback_image_from(FALLBACK)
    }

    // Synthetic ELF DATA for the exact isolated-function geometry. Preserve
    // the historical fixture and its negative controls; this is no source or
    // compiler provenance claim. The same three body relocations and their
    // actual operand sections are retained for the production join parser.
    fn isolated_fallback_data() -> Vec<u8> {
        let owner = object(FALLBACK, InitializerRole::PackageFallback);
        let (_, symbol) = named(&owner.elf, "fallback_entry").unwrap();
        let elf = &owner.elf;
        let shoff = elf.header.e_shoff as usize;
        let strings_index = elf.header.e_shstrndx as usize;
        let strings = section_file_bytes(&elf.section_headers[strings_index], FALLBACK).unwrap();
        let mut raw = FALLBACK.to_vec();
        let strings_at = raw.len();
        raw.extend_from_slice(strings);
        raw.extend_from_slice(FALLBACK_SECTION.as_bytes());
        raw.push(0);
        put(
            &mut raw,
            shoff + strings_index * 64 + 24,
            8,
            strings_at as u64,
        );
        put(
            &mut raw,
            shoff + strings_index * 64 + 32,
            8,
            (strings.len() + FALLBACK_SECTION.len() + 1) as u64,
        );
        put(
            &mut raw,
            shoff + symbol.st_shndx * 64,
            4,
            strings.len() as u64,
        );
        put(&mut raw, shoff + symbol.st_shndx * 64 + 32, 8, 48);
        let table = elf.section_headers.iter().find(|s| s.sh_type == 2).unwrap();
        for (index, s) in elf.syms.iter().enumerate() {
            if s.st_shndx == symbol.st_shndx
                && !matches!(
                    elf.strtab.get_at(s.st_name),
                    Some(
                        "fallback_entry"
                            | "fallback_completion_syscall"
                            | "fallback_completion_return"
                    )
                )
            {
                // The synthetic contribution has no neighboring definitions.
                put(
                    &mut raw,
                    table.sh_offset as usize + index * 24 + 6,
                    2,
                    section_header::SHN_ABS as u64,
                );
            }
        }
        let (rel_index, rel) = elf
            .section_headers
            .iter()
            .enumerate()
            .find(|(_, s)| s.sh_type == 4 && s.sh_info as usize == symbol.st_shndx)
            .unwrap();
        raw.resize((raw.len() + 7) & !7, 0);
        let rel_at = raw.len();
        for i in 0..rel.sh_size as usize / 24 {
            let at = rel.sh_offset as usize + i * 24;
            if u64::from_le_bytes(FALLBACK[at..at + 8].try_into().unwrap()) < 48 {
                raw.extend_from_slice(&FALLBACK[at..at + 24]);
            }
        }
        assert_eq!(raw.len() - rel_at, 72);
        put(&mut raw, shoff + rel_index * 64 + 24, 8, rel_at as u64);
        put(&mut raw, shoff + rel_index * 64 + 32, 8, 72);
        raw
    }

    #[test]
    fn package_roles_isolated_fallback_owns_the_complete_function_and_three_operands() {
        let data = isolated_fallback_data();
        let owner = object(&data, InitializerRole::PackageFallback);
        let symbol = fallback_input(&owner).unwrap();
        assert_eq!(owner.elf.section_headers[symbol.st_shndx].sh_size, 48);
        let (raw, map) = fallback_image_from(&data);
        let elf = Elf::parse(&raw).unwrap();
        let observed = role_body(
            InitializerRole::PackageFallback,
            &owner,
            std::slice::from_ref(&owner),
            &map,
            &elf,
            &raw,
        )
        .unwrap();
        assert_eq!(
            (observed.complete_bytes, observed.relocations.len()),
            (48, 3)
        );
        assert_eq!(observed.aliases["fallback_completion_return"], 46);
        let section_at = owner.elf.header.e_shoff as usize + symbol.st_shndx * 64;
        for size in [47, 49, 103, 289] {
            let mut bad = data.clone();
            put(&mut bad, section_at + 32, 8, size);
            assert!(
                fallback_input(&object(&bad, InitializerRole::PackageFallback))
                    .unwrap_err()
                    .contains("complete function/contribution")
            );
        }
        let (_, rel) = owner
            .elf
            .section_headers
            .iter()
            .enumerate()
            .find(|(_, s)| s.sh_type == 4 && s.sh_info as usize == symbol.st_shndx)
            .unwrap();
        for offset in [24, 47] {
            let mut bad = data.clone();
            put(&mut bad, rel.sh_offset as usize, 8, offset);
            assert!(fallback_input(&object(&bad, InitializerRole::PackageFallback)).is_err());
        }
        let mut bad = raw.clone();
        // An unexpected local alias in the function cannot be hidden by a
        // neighboring contribution or by otherwise correct relocation bytes.
        put(&mut bad, 0x8000 + 5 * 24 + 8, 8, 0x401001);
        let bad_elf = Elf::parse(&bad).unwrap();
        assert!(
            join_fallback(&owner, std::slice::from_ref(&owner), &map, &bad_elf, &bad)
                .unwrap_err()
                .contains("extra aliases")
        );
    }
    #[test]
    fn package_roles_fallback_joins_actual_48b_and_all_three_source_operands() {
        let (raw, map) = fallback_image();
        let elf = Elf::parse(&raw).unwrap();
        let objects = [object(FALLBACK, InitializerRole::PackageFallback)];
        let joined = join_fallback(&objects[0], &objects, &map, &elf, &raw).unwrap();
        assert_eq!((joined.bytes, joined.relocation_fields), (48, 3));
        let observed = role_body(
            InitializerRole::PackageFallback,
            &objects[0],
            &objects,
            &map,
            &elf,
            &raw,
        )
        .unwrap();
        assert_eq!(observed.aliases["fallback_completion_return"], 46);
        assert_eq!(observed.relocations.len(), 3);
        // Another source operand, even a genuine function in the same member,
        // cannot replace the explicitly selected dispatch operand.
        let source = relocation_rows(&objects[0], 2, 48).unwrap();
        assert!(fallback_target(&map, &objects[0], source[2].3, 14, &objects, &elf, &raw).is_err());
        let mut bad = raw.clone();
        bad[0x6100] ^= 1;
        let bad_elf = Elf::parse(&bad).unwrap();
        assert!(join_fallback(&objects[0], &objects, &map, &bad_elf, &bad).is_err());
        let mut bad = raw.clone();
        put(&mut bad, 0x8000 + 7 * 24 + 8, 8, 0x402001);
        let bad_elf = Elf::parse(&bad).unwrap();
        assert!(join_fallback(&objects[0], &objects, &map, &bad_elf, &bad).is_err());
        for (at, width, value) in [
            (0x8000 + 7 * 24 + 6, 2, 2), // genuine call address declared in RO section.
            (0x8000 + 2 * 24 + 6, 2, 2), // fallback itself declared outside RX contribution.
            (0x8000 + 5 * 24 + 6, 2, 2), // ordinary anchor declared in another section.
        ] {
            let mut bad = raw.clone();
            put(&mut bad, at, width, value);
            let bad_elf = Elf::parse(&bad).unwrap();
            assert!(join_fallback(&objects[0], &objects, &map, &bad_elf, &bad).is_err());
        }
    }
    #[test]
    fn package_roles_fallback_exact_subextent_never_weakens_whole_section_join() {
        let obj = object(FALLBACK, InitializerRole::PackageFallback);
        let symbol = fallback_input(&obj).unwrap();
        assert_eq!(symbol.st_size, 48);
        assert_eq!(obj.elf.section_headers[symbol.st_shndx].sh_size, 289);
        let table = obj
            .elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 2)
            .unwrap();
        let (index, _) = named(&obj.elf, "fallback_entry").unwrap();
        for (field, width, value) in [(8, 8, 1), (16, 8, 47), (16, 8, 49), (5, 1, 0)] {
            let mut bad = FALLBACK.to_vec();
            put(
                &mut bad,
                table.sh_offset as usize + index * 24 + field,
                width,
                value,
            );
            assert!(fallback_input(&object(&bad, InitializerRole::PackageFallback)).is_err());
        }
        let section_at = obj.elf.header.e_shoff as usize + symbol.st_shndx * 64;
        for size in [288, 290] {
            let mut bad = FALLBACK.to_vec();
            put(&mut bad, section_at + 32, 8, size);
            assert!(fallback_input(&object(&bad, InitializerRole::PackageFallback)).is_err());
        }
        let rel = obj
            .elf
            .section_headers
            .iter()
            .find(|s| s.sh_type == 4 && s.sh_info as usize == symbol.st_shndx)
            .unwrap();
        let outside = (0..rel.sh_size as usize / 24)
            .find(|i| {
                let at = rel.sh_offset as usize + i * 24;
                u64::from_le_bytes(FALLBACK[at..at + 8].try_into().unwrap()) >= 48
            })
            .unwrap();
        for offset in [24, 47] {
            let mut bad = FALLBACK.to_vec();
            put(&mut bad, rel.sh_offset as usize + outside * 24, 8, offset);
            assert!(fallback_input(&object(&bad, InitializerRole::PackageFallback)).is_err());
        }
        let mut symbol = symbol;
        assert!(InitializerRole::PackageFallback.binding(symbol, true));
        symbol.st_info = (sym::STB_LOCAL << 4) | sym::STT_FUNC;
        assert!(InitializerRole::PackageFallback.binding(symbol, false));
        symbol.st_other = 0;
        assert!(!InitializerRole::PackageFallback.binding(symbol, false));
        assert!(!InitializerRole::PackageFallback.terminal_name("fallback_entry"));
    }
}
