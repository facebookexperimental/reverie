//! Source-owned selected-definition join in private_static; not a public
//! local-symbol waiver. Inputs below must be constructed by the source/archive
//! selector described in README.md, never deserialized or accepted from callers.
use super::super::private_machine_diagnostic::static_image_metadata;
use super::*;

mod bootstrap_env_aux;
pub use bootstrap_env_aux::BootstrapEnvAuxLeafObservation;
pub use bootstrap_env_aux::bootstrap_env_aux_implementation_sha256;

mod bootstrap_descriptor;
pub use bootstrap_descriptor::BootstrapDescriptorLeafObservation;
pub use bootstrap_descriptor::bootstrap_descriptor_implementation_sha256;

mod bootstrap_role;
pub use bootstrap_role::BootstrapRoleLeafObservation;
pub use bootstrap_role::bootstrap_role_implementation_sha256;

mod bootstrap_site;
pub use bootstrap_site::BootstrapSiteLeafObservation;
pub use bootstrap_site::bootstrap_site_implementation_sha256;

mod view_site;
pub use view_site::ViewSiteInstallerInputs;
pub use view_site::ViewSiteInstallerObservation;
pub use view_site::ViewSiteLeafObservation;
pub use view_site::view_site_caller_implementation_sha256;
pub use view_site::view_site_implementation_sha256;

mod view_table;
pub use view_table::ViewTableLeafObservation;
pub use view_table::view_table_implementation_sha256;

mod terminal_observation;
pub use terminal_observation::MappedTerminalObservation;

mod ordinary_gate;
pub use ordinary_gate::OrdinaryGateObservations;
#[cfg(test)]
pub(crate) use ordinary_gate::composition_test_fixture;
pub use ordinary_gate::ordinary_gate_implementation_sha256;

mod native_leaves;
pub use native_leaves::NativeLeafInputs;
pub use native_leaves::NativeLeafObservations;
pub use native_leaves::native_leaf_implementation_sha256;

// Private target identities produced from actual selected archive sections and
// final map placement, including COMMON allocations; not final-name lookup.
#[derive(Clone, Debug)]
struct SelectedTarget {
    mapped_input_value: u64,
}
#[derive(Clone, Debug)]
struct InputRelocation {
    offset: usize,
    kind: u32,
    addend: i64,
    target: SelectedTarget,
}
#[derive(Clone, Debug)]
struct FinalRelocation {
    offset: usize,
    kind: u32,
    addend: i64,
    // Actual final symtab value, including output-section-symbol rebasing.
    symbol_value: u64,
}
// This concrete token is definition identity only; no execution/entry method.
#[derive(Debug)]
struct RelocatedDefinition {
    address: u64,
    bytes: usize,
    relocation_fields: usize,
    member: Option<(String, usize, u64)>,
    member_sha256: String,
    input_body_sha256: String,
    section_index: usize,
    memcpy_target: Option<u64>,
}

fn checked_pc32(target: u64, addend: i64, place: u64) -> Result<[u8; 4]> {
    let value = i128::from(target) + i128::from(addend) - i128::from(place);
    let signed = i32::try_from(value).map_err(|_| "selected initializer PC32 overflow")?;
    Ok(signed.to_le_bytes())
}

// No relocation masking: reconstruct each exact field and compare every other
// byte. Final retained relocation metadata must correspond one-for-one too.
fn join_relocated_body(
    elf: &Elf<'_>,
    final_file: &[u8],
    address: u64,
    input: &[u8],
    linked: &[u8],
    input_relocs: &[InputRelocation],
    final_relocs: &[FinalRelocation],
) -> Result<RelocatedDefinition> {
    static_image_metadata(elf, final_file)?;
    require(
        !input.is_empty() && input.len() <= 4096 && input.len() == linked.len(),
        "selected initializer body extent differs",
    )?;
    let (load, offset) = unique_file_mapping(elf, final_file, address, input.len())?;
    require(
        load.p_flags == 5 && final_file.get(offset..offset + linked.len()) == Some(linked),
        "selected initializer is not actual unique immutable RX bytes",
    )?;
    require(
        input_relocs.len() == final_relocs.len(),
        "selected initializer relocation census differs",
    )?;
    let mut original = input_relocs.iter().collect::<Vec<_>>();
    original.sort_by_key(|r| r.offset);
    let mut emitted = final_relocs.iter().collect::<Vec<_>>();
    emitted.sort_by_key(|r| r.offset);
    let mut expected = input.to_vec();
    let mut previous_end = 0;
    for (source, final_r) in original.into_iter().zip(emitted) {
        let end = source
            .offset
            .checked_add(4)
            .ok_or("initializer relocation end overflow")?;
        require(
            source.offset >= previous_end && end <= input.len(),
            "selected initializer relocation overlaps or escapes",
        )?;
        require(
            source.offset == final_r.offset && source.kind == final_r.kind,
            "selected initializer relocation kind/offset changed",
        )?;
        let place = address
            .checked_add(u64::try_from(source.offset).map_err(|_| "relocation offset")?)
            .ok_or("initializer relocation place overflow")?;
        let target = source.target.mapped_input_value;
        let field = match source.kind {
            reloc::R_X86_64_PC32 | reloc::R_X86_64_PLT32 => {
                // Only direct PC-relative relocations may rebase an input
                // section symbol to the output section plus adjusted addend.
                require(
                    i128::from(target) + i128::from(source.addend)
                        == i128::from(final_r.symbol_value) + i128::from(final_r.addend),
                    "direct initializer relocation target/addend differs",
                )?;
                // Non-dynamic ET_EXEC, no runtime writers. PLT32's actual direct
                // target is the selected definition, never an unexamined PLT.
                checked_pc32(target, source.addend, place)?
            }
            reloc::R_X86_64_GOTPCREL => {
                // G is derived using A, not S+A: compensating changes to S/A
                // would otherwise authenticate a different slot expression.
                require(
                    target == final_r.symbol_value && source.addend == final_r.addend,
                    "GOT initializer symbol/addend differs",
                )?;
                let displacement = i32::from_le_bytes(
                    linked[source.offset..end]
                        .try_into()
                        .map_err(|_| "GOT field width")?,
                );
                // encoded = G + A - P; derive G from exact emitted field,
                // then authenticate its real immutable loaded pointer to S.
                let slot = i128::from(place) + i128::from(displacement) - i128::from(source.addend);
                let slot = u64::try_from(slot).map_err(|_| "selected initializer GOT overflow")?;
                let (mapping, _) = unique_file_mapping(elf, final_file, slot, 8)?;
                require(
                    mapping.p_flags == program_header::PF_R,
                    "selected initializer GOT is not actual RO non-X",
                )?;
                let bytes = readonly_loaded_bytes(elf, final_file, slot, 8)?;
                require(
                    u64::from_le_bytes(bytes.try_into().map_err(|_| "GOT width")?) == target,
                    "selected initializer GOT target differs",
                )?;
                checked_pc32(slot, source.addend, place)?
            }
            _ => return Err("selected initializer unsupported relocation; no field waiver".into()),
        };
        expected[source.offset..end].copy_from_slice(&field);
        previous_end = end;
    }
    require(
        expected == linked,
        "selected initializer whole relocated bytes differ",
    )?;
    Ok(RelocatedDefinition {
        address,
        bytes: linked.len(),
        relocation_fields: input_relocs.len(),
        member: None,
        member_sha256: String::new(),
        input_body_sha256: String::new(),
        section_index: 0,
        memcpy_target: None,
    })
}

struct ObjectInput<'a> {
    archive_path: &'a Path,
    member_name: &'a str,
    ordinal: usize,
    header_offset: u64,
    bytes: &'a [u8],
    elf: Elf<'a>,
}

fn mapped_section(map: &str, object: &ObjectInput<'_>, index: usize) -> Result<u64> {
    let section = object
        .elf
        .section_headers
        .get(index)
        .ok_or("initializer input section absent")?;
    let name = object
        .elf
        .shdr_strtab
        .get_at(section.sh_name)
        .ok_or("initializer input section name")?;
    let suffix = format!(
        "{}({}):({})",
        object.archive_path.display(),
        object.member_name,
        name
    );
    let rows = map
        .lines()
        .filter(|line| line.trim_end().ends_with(&suffix))
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        "initializer input section not uniquely selected by map",
    )?;
    let fields = rows[0].split_whitespace().collect::<Vec<_>>();
    require(
        fields.len() == 5 && fields[0] == fields[1],
        "initializer map row shape",
    )?;
    let address = u64::from_str_radix(fields[0], 16).map_err(|_| "initializer map address")?;
    let size = u64::from_str_radix(fields[2], 16).map_err(|_| "initializer map size")?;
    let align = fields[3]
        .parse::<u64>()
        .map_err(|_| "initializer map alignment")?;
    require(
        size == section.sh_size
            && align == section.sh_addralign
            && align.is_power_of_two()
            && address % align == 0,
        "initializer section size/alignment differs",
    )?;
    address
        .checked_add(size)
        .ok_or("initializer mapped section overflows")?;
    Ok(address)
}

fn mapped_common(map: &str, object: &ObjectInput<'_>, symbol: &sym::Sym) -> Result<u64> {
    // The V12 selected __stack_chk_fail.lo has one COMMON guard. Refuse general
    // common coalescing/packing instead of guessing alignment or name offsets.
    let common = object
        .elf
        .syms
        .iter()
        .filter(|s| s.st_shndx == section_header::SHN_COMMON as usize)
        .collect::<Vec<_>>();
    require(
        common.len() == 1
            && common[0].st_name == symbol.st_name
            && common[0].st_value == symbol.st_value
            && common[0].st_size == symbol.st_size,
        "initializer ambiguous COMMON allocation",
    )?;
    let suffix = format!(
        "{}({}):(COMMON)",
        object.archive_path.display(),
        object.member_name
    );
    let rows = map
        .lines()
        .filter(|line| line.trim_end().ends_with(&suffix))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "initializer COMMON map missing/ambiguous")?;
    let f = rows[0].split_whitespace().collect::<Vec<_>>();
    require(f.len() == 5 && f[0] == f[1], "initializer COMMON row shape")?;
    let start = u64::from_str_radix(f[0], 16).map_err(|_| "COMMON address")?;
    let size = u64::from_str_radix(f[2], 16).map_err(|_| "COMMON size")?;
    let align = f[3].parse::<u64>().map_err(|_| "COMMON alignment")?;
    require(
        size == symbol.st_size
            && align == symbol.st_value
            && align.is_power_of_two()
            && start % align == 0,
        "initializer COMMON geometry differs",
    )?;
    start.checked_add(size).ok_or("COMMON end overflows")?;
    Ok(start)
}

fn mapped_definition(map: &str, object: &ObjectInput<'_>, symbol: &sym::Sym) -> Result<u64> {
    if symbol.st_shndx == section_header::SHN_COMMON as usize {
        return mapped_common(map, object, symbol);
    }
    require(
        symbol.st_shndx > 0 && symbol.st_shndx < object.elf.section_headers.len(),
        "initializer undefined/absolute/reserved definition",
    )?;
    let section = &object.elf.section_headers[symbol.st_shndx];
    require(
        section.sh_flags & section_header::SHF_ALLOC as u64 != 0,
        "initializer target is not allocated input",
    )?;
    require(
        symbol
            .st_value
            .checked_add(symbol.st_size)
            .is_some_and(|end| end <= section.sh_size),
        "initializer input target escapes section",
    )?;
    mapped_section(map, object, symbol.st_shndx)?
        .checked_add(symbol.st_value)
        .ok_or_else(|| "initializer target address overflows".into())
}

// A finite extension for the actual pinned libc.lo; not COMMON packing or
// coalescing. The old singleton mapper above remains byte-identical.
fn mapped_libc_common_pair(
    map: &str,
    object: &ObjectInput<'_>,
    symbol: &sym::Sym,
    final_elf: &Elf<'_>,
    final_bytes: &[u8],
) -> Result<u64> {
    require(
        object.member_name == "libc.lo"
            && object.ordinal == 171
            && object.header_offset == 867642
            && sha256(object.bytes)
                == "c9b3acc6ec4f5a5c1652e93cf9b35121fa860d37de27df9d228528020a6fdad2",
        "paired COMMON native source/member identity differs",
    )?;
    // The enclosing same-owner link transaction's unchanged native guard binds
    // exact libc.a/release/recipe. Its decoded declarations remain checked here.
    let table = checked_symtab(&object.elf, object.bytes)?;
    checked_relocation_inventory(&object.elf, object.bytes, table)?;
    let expected = [("__hwcap", 6usize, 8u64, 8u64), ("__libc", 7, 104, 32)];
    let common = object
        .elf
        .syms
        .iter()
        .enumerate()
        .filter(|(_, s)| s.st_shndx == section_header::SHN_COMMON as usize)
        .collect::<Vec<_>>();
    require(
        common.len() == expected.len(),
        "paired COMMON declarations differ",
    )?;
    for ((index, s), (name, expected_index, size, align)) in common.iter().zip(expected) {
        require(
            *index == expected_index
                && object.elf.strtab.get_at(s.st_name) == Some(name)
                && s.st_bind() == sym::STB_GLOBAL
                && s.st_type() == sym::STT_OBJECT
                && s.st_visibility() == sym::STV_HIDDEN
                && s.st_size == size
                && s.st_value == align,
            "paired COMMON exact native declaration differs",
        )?;
    }
    let selected = common
        .iter()
        .filter(|(_, s)| {
            s.st_name == symbol.st_name
                && s.st_shndx == symbol.st_shndx
                && s.st_info == symbol.st_info
                && s.st_other == symbol.st_other
                && s.st_value == symbol.st_value
                && s.st_size == symbol.st_size
        })
        .collect::<Vec<_>>();
    require(
        selected.len() == 1,
        "paired COMMON selected declaration differs",
    )?;
    static_image_metadata(final_elf, final_bytes)?;
    let final_table = checked_symtab(final_elf, final_bytes)?;
    checked_relocation_inventory(final_elf, final_bytes, final_table)?;
    let suffix = format!(
        "{}({}):(COMMON)",
        object.archive_path.display(),
        object.member_name
    );
    let lines = map.lines().collect::<Vec<_>>();
    let rows = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim_end().ends_with(&suffix))
        .collect::<Vec<_>>();
    require(
        rows.len() == 2,
        "paired COMMON needs two distinct allocation blocks",
    )?;
    let mut allocations = BTreeMap::new();
    for (index, line) in rows {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        require(
            fields.len() == 5 && fields[0] == fields[1] && fields[4] == suffix,
            "paired COMMON allocation row shape differs",
        )?;
        let child = lines
            .get(index + 1)
            .ok_or("paired COMMON symbol row missing")?;
        let named = child.split_whitespace().collect::<Vec<_>>();
        require(
            named.len() == 5
                && named[0] == fields[0]
                && named[1] == fields[1]
                && named[2] == fields[2]
                && named[3] == "1",
            "paired COMMON adjacent symbol row shape differs",
        )?;
        let declarations = expected
            .iter()
            .filter(|(name, _, _, _)| *name == named[4])
            .collect::<Vec<_>>();
        require(
            declarations.len() == 1,
            "paired COMMON adjacent name unknown",
        )?;
        let (name, _, size, align) = *declarations[0];
        let address = u64::from_str_radix(fields[0], 16).map_err(|_| "paired COMMON address")?;
        require(
            u64::from_str_radix(fields[2], 16).map_err(|_| "paired COMMON size")? == size
                && fields[3]
                    .parse::<u64>()
                    .map_err(|_| "paired COMMON alignment")?
                    == align
                && address % align == 0,
            "paired COMMON allocation geometry differs",
        )?;
        let end = address
            .checked_add(size)
            .ok_or("paired COMMON end overflow")?;
        let parent_column = line.rfind(&suffix).ok_or("paired COMMON owner column")?;
        let child_column = child.rfind(name).ok_or("paired COMMON symbol column")?;
        require(
            child_column > parent_column,
            "paired COMMON symbol not nested in allocation",
        )?;
        if let Some(next) = lines
            .iter()
            .skip(index + 2)
            .find(|line| !line.trim().is_empty())
        {
            let next_fields = next.split_whitespace().collect::<Vec<_>>();
            require(
                next_fields.len() == 5,
                "paired COMMON allocation boundary row malformed",
            )?;
            let last = next_fields[4];
            require(
                next.rfind(last).is_some_and(|column| column < child_column),
                "paired COMMON allocation has additional symbol rows",
            )?;
        }
        require(
            allocations.insert(name, (address, end)).is_none(),
            "paired COMMON duplicate named allocation",
        )?;
    }
    require(
        allocations.len() == 2,
        "paired COMMON missing named allocation",
    )?;
    let a = allocations["__libc"];
    let b = allocations["__hwcap"];
    require(
        a.1 <= b.0 || b.1 <= a.0,
        "paired COMMON allocations overlap",
    )?;
    for (name, _, size, _) in expected {
        let (address, end) = allocations[name];
        let definitions = final_elf
            .syms
            .iter()
            .filter(|s| s.st_shndx != 0 && final_elf.strtab.get_at(s.st_name) == Some(name))
            .collect::<Vec<_>>();
        require(
            definitions.len() == 1,
            "paired COMMON final definition absent/duplicate",
        )?;
        let s = definitions[0];
        require(
            s.st_type() == sym::STT_OBJECT
                && s.st_bind() == sym::STB_LOCAL
                && s.st_visibility() == sym::STV_HIDDEN
                && s.st_size == size
                && s.st_value == address,
            "paired COMMON final declaration/map identity differs",
        )?;
        let section = final_elf
            .section_headers
            .get(s.st_shndx)
            .ok_or("paired COMMON final section")?;
        require(
            section.sh_type == section_header::SHT_NOBITS
                && section.sh_flags == 3
                && section.sh_addr <= address
                && section
                    .sh_addr
                    .checked_add(section.sh_size)
                    .is_some_and(|limit| end <= limit),
            "paired COMMON final BSS geometry differs",
        )?;
        let loads = final_elf
            .program_headers
            .iter()
            .filter(|p| {
                p.p_type == program_header::PT_LOAD
                    && p.p_vaddr <= address
                    && p.p_vaddr
                        .checked_add(p.p_memsz)
                        .is_some_and(|limit| end <= limit)
            })
            .collect::<Vec<_>>();
        require(
            loads.len() == 1
                && loads[0].p_flags == 6
                && loads[0]
                    .p_vaddr
                    .checked_add(loads[0].p_filesz)
                    .is_some_and(|file_end| file_end <= address),
            "paired COMMON is not uniquely zero-backed RW non-X memory",
        )?;
        for (index, relocations) in &final_elf.shdr_relocs {
            let target =
                &final_elf.section_headers[final_elf.section_headers[*index].sh_info as usize];
            for r in relocations.iter() {
                require(
                    !selected_field_overlap(target, r.r_offset, r.r_type, address, end)?,
                    "paired COMMON has overlapping retained relocation",
                )?;
            }
        }
    }
    let name = object
        .elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or("paired COMMON selected name")?;
    Ok(allocations[name].0)
}

fn mapped_relocation_definition(
    map: &str,
    object: &ObjectInput<'_>,
    symbol: &sym::Sym,
    final_elf: &Elf<'_>,
    final_bytes: &[u8],
) -> Result<u64> {
    if symbol.st_shndx == section_header::SHN_COMMON as usize
        && object
            .elf
            .syms
            .iter()
            .filter(|s| s.st_shndx == section_header::SHN_COMMON as usize)
            .count()
            != 1
    {
        mapped_libc_common_pair(map, object, symbol, final_elf, final_bytes)
    } else {
        mapped_definition(map, object, symbol)
    }
}

fn resolve_input_target(
    map: &str,
    owner: &ObjectInput<'_>,
    index: usize,
    objects: &[ObjectInput<'_>],
    final_elf: &Elf<'_>,
    final_bytes: &[u8],
) -> Result<SelectedTarget> {
    let source = owner
        .elf
        .syms
        .get(index)
        .ok_or("initializer input relocation symbol")?;
    let address = if source.st_shndx != 0 {
        mapped_relocation_definition(map, owner, &source, final_elf, final_bytes)?
    } else {
        let name = owner
            .elf
            .strtab
            .get_at(source.st_name)
            .ok_or("initializer undefined name")?;
        require(
            !name.is_empty() && source.st_bind() == sym::STB_GLOBAL,
            "initializer weak/unnamed unresolved reference",
        )?;
        let mut selected = Vec::new();
        for object in objects {
            for target in object.elf.syms.iter().filter(|s| {
                object.elf.strtab.get_at(s.st_name) == Some(name)
                    && s.st_shndx != 0
                    && s.st_bind() == sym::STB_GLOBAL
            }) {
                // Only a real map-selected full input section may resolve it.
                // Absent map rows mean the candidate was not selected; malformed
                // present rows must be propagated by the outer selector, not
                // silently discarded through Result::ok/filter_map.
                let section_name = if target.st_shndx == section_header::SHN_COMMON as usize {
                    "COMMON"
                } else {
                    let section = object
                        .elf
                        .section_headers
                        .get(target.st_shndx)
                        .ok_or("initializer candidate section")?;
                    object
                        .elf
                        .shdr_strtab
                        .get_at(section.sh_name)
                        .ok_or("candidate section name")?
                };
                let suffix = format!(
                    "{}({}):({})",
                    object.archive_path.display(),
                    object.member_name,
                    section_name
                );
                if map.lines().any(|line| line.trim_end().ends_with(&suffix)) {
                    selected.push(mapped_relocation_definition(
                        map,
                        object,
                        &target,
                        final_elf,
                        final_bytes,
                    )?);
                }
            }
        }
        require(
            selected.len() == 1,
            "initializer target absent/duplicate selected strong definition",
        )?;
        selected[0]
    };
    Ok(SelectedTarget {
        mapped_input_value: address,
    })
}

// These are the ONLY roles allowed into this selector; ordinary exported roles
// continue through existing strong_function/GLOBAL checks unchanged.
#[derive(Clone, Copy)]
enum InitializerRole {
    RustTls,
    RustMallocAlias,
    RustFreeAlias,
    MuslSsp,
    MuslFail,
    MappedRoot,
    MappedTerminal,
    InitializationFailed,
    InitialTerminal,
    MappedObserver,
}
impl InitializerRole {
    fn symbol(&self) -> &'static str {
        match self {
            Self::RustTls => "__init_tls",
            Self::RustMallocAlias => "__libc_malloc",
            Self::RustFreeAlias => "__libc_free",
            Self::MuslSsp => "__init_ssp",
            Self::MuslFail => "__stack_chk_fail",
            Self::MappedRoot => "detcore_liteinst_mapped_entry",
            Self::MappedTerminal => {
                "_RNvNtNtCs2FQ3I8A8V8D_16detcore_liteinst12exec_initial12mapped_entry8terminal"
            }
            Self::InitializationFailed => {
                "_RNvNtNtCsjyMJYRcpkaN_15reverie_inguest5guest12exec_private21initialization_failed"
            }
            Self::InitialTerminal => {
                "_RNvNtNtCsjyMJYRcpkaN_15reverie_inguest5guest12exec_private16initial_terminal"
            }
            Self::MappedObserver => {
                "_RNvNtNtCs2FQ3I8A8V8D_16detcore_liteinst12exec_initial12mapped_entry26observe_initializer_return"
            }
        }
    }
    // Discovery only for four source-owned terminal paths. Crate disambiguators
    // are compiler choices, not source identity or acceptance credentials.
    fn terminal_path(self) -> Option<&'static str> {
        match self {
            Self::MappedTerminal => Some("16detcore_liteinst12exec_initial12mapped_entry8terminal"),
            Self::MappedObserver => {
                Some("16detcore_liteinst12exec_initial12mapped_entry26observe_initializer_return")
            }
            Self::InitializationFailed => {
                Some("15reverie_inguest5guest12exec_private21initialization_failed")
            }
            Self::InitialTerminal => {
                Some("15reverie_inguest5guest12exec_private16initial_terminal")
            }
            _ => None,
        }
    }
    fn terminal_name(self, name: &str) -> bool {
        let Some(path) = self.terminal_path() else {
            return false;
        };
        // The shared normalizer permits LLVM suffixes for other roles; these
        // four measured source paths require their unsuffixed actual owner.
        !name.contains(".llvm.")
            && canonical_rust_symbol(name).as_deref() == Some(format!("_RNvNtNtCs_{path}").as_str())
    }
    // Closed source roles only; original TLS/SSP binding checks stay identical.
    fn binding(self, symbol: sym::Sym, input: bool) -> bool {
        match self {
            Self::MappedTerminal => {
                symbol.st_bind() == sym::STB_LOCAL && symbol.st_visibility() == sym::STV_DEFAULT
            }
            Self::MappedObserver | Self::InitialTerminal => {
                symbol.st_visibility() == sym::STV_HIDDEN
                    && symbol.st_bind()
                        == if input {
                            sym::STB_GLOBAL
                        } else {
                            sym::STB_LOCAL
                        }
            }
            Self::MappedRoot => {
                symbol.st_bind() == sym::STB_GLOBAL && symbol.st_visibility() == sym::STV_PROTECTED
            }
            Self::InitializationFailed => {
                symbol.st_bind() == sym::STB_GLOBAL && symbol.st_visibility() == sym::STV_DEFAULT
            }
            Self::RustTls
            | Self::RustMallocAlias
            | Self::RustFreeAlias
            | Self::MuslSsp
            | Self::MuslFail => {
                if input {
                    symbol.st_bind() == sym::STB_GLOBAL
                } else {
                    (symbol.st_bind() == sym::STB_LOCAL
                        && symbol.st_visibility() == sym::STV_HIDDEN)
                        || symbol.st_bind() == sym::STB_GLOBAL
                }
            }
        }
    }
}

// Only the two actual Rust allocation ABI alias groups need a localized
// symbol proof. This does not relax the ordinary GLOBAL final-symbol policy.
fn allocator_alias_names(role: &InitializerRole) -> Option<&'static [&'static str]> {
    match role {
        InitializerRole::RustMallocAlias => {
            Some(&["__libc_malloc", "__libc_malloc_impl", "malloc"])
        }
        InitializerRole::RustFreeAlias => Some(&["__libc_free", "free"]),
        _ => None,
    }
}
type RustAliasRow = (String, u8, u8, u8, usize, u64, u64);
fn rust_alias_rows(
    elf: &Elf<'_>,
    section: usize,
    begin: u64,
    end: u64,
) -> Result<Vec<RustAliasRow>> {
    elf.syms
        .iter()
        .filter(|s| s.st_shndx == section && begin <= s.st_value && s.st_value < end)
        .map(|s| {
            Ok((
                elf.strtab
                    .get_at(s.st_name)
                    .ok_or("Rust alias name")?
                    .into(),
                s.st_bind(),
                s.st_type(),
                s.st_visibility(),
                s.st_shndx,
                s.st_value,
                s.st_size,
            ))
        })
        .collect()
}
fn exact_rust_alias_rows(
    mut actual: Vec<RustAliasRow>,
    mut expected: Vec<RustAliasRow>,
) -> Result<()> {
    actual.sort();
    expected.sort();
    require(
        actual == expected,
        "selected Rust allocator alias set differs",
    )
}
fn allocator_aliases(
    names: &[&str],
    input: &ObjectInput<'_>,
    source: &sym::Sym,
    final_elf: &Elf<'_>,
    linked: &sym::Sym,
) -> Result<()> {
    let input_end = source
        .st_value
        .checked_add(source.st_size)
        .ok_or("Rust alias input end")?;
    let final_end = linked
        .st_value
        .checked_add(linked.st_size)
        .ok_or("Rust alias final end")?;
    let mut expected = vec![(String::new(), 0, 3, 0, source.st_shndx, source.st_value, 0)];
    for name in names {
        let found = input
            .elf
            .syms
            .iter()
            .filter(|s| input.elf.strtab.get_at(s.st_name) == Some(*name))
            .count();
        require(found == 1, "selected Rust input alias absent/duplicate")?;
        expected.push((
            (*name).into(),
            1,
            2,
            0,
            source.st_shndx,
            source.st_value,
            source.st_size,
        ));
    }
    exact_rust_alias_rows(
        rust_alias_rows(&input.elf, source.st_shndx, source.st_value, input_end)?,
        expected,
    )?;
    let mut expected = Vec::new();
    for name in names {
        let alias = named(final_elf, name)?;
        // The role itself may be localized HIDDEN by LLD. Its actual GLOBAL
        // aliases remain GLOBAL; no unrelated local function is admitted.
        let (bind, visibility) = if *name == names[0] && linked.st_bind() == sym::STB_LOCAL {
            (sym::STB_LOCAL, sym::STV_HIDDEN)
        } else {
            (sym::STB_GLOBAL, sym::STV_DEFAULT)
        };
        require(
            alias.st_bind() == bind && alias.st_visibility() == visibility,
            "selected Rust final alias binding differs",
        )?;
        expected.push((
            (*name).into(),
            bind,
            sym::STT_FUNC,
            visibility,
            linked.st_shndx,
            linked.st_value,
            linked.st_size,
        ));
    }
    exact_rust_alias_rows(
        rust_alias_rows(final_elf, linked.st_shndx, linked.st_value, final_end)?,
        expected,
    )
}

// Raw table declarations are authority for Goblin's decoded rows. Do not
// accept a numerically overlapping relocation from another sh_info/sh_link.
fn section_file_bytes<'a>(s: &section_header::SectionHeader, bytes: &'a [u8]) -> Result<&'a [u8]> {
    let start = usize::try_from(s.sh_offset).map_err(|_| "table offset")?;
    let len = usize::try_from(s.sh_size).map_err(|_| "table size")?;
    bytes
        .get(start..start.checked_add(len).ok_or("table file end overflow")?)
        .ok_or_else(|| "table outside actual owning ELF".into())
}
fn checked_symtab(elf: &Elf<'_>, bytes: &[u8]) -> Result<usize> {
    require(
        elf.header.e_shentsize == 64
            && elf.header.e_shnum as usize == elf.section_headers.len()
            && elf
                .header
                .e_shoff
                .checked_add(
                    (elf.section_headers.len() as u64)
                        .checked_mul(64)
                        .ok_or("section table size overflow")?,
                )
                .is_some_and(|end| end <= bytes.len() as u64),
        "initializer actual section-header extent differs",
    )?;
    let tables = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, s)| s.sh_type == section_header::SHT_SYMTAB)
        .collect::<Vec<_>>();
    require(
        tables.len() == 1,
        "initializer needs unique full symbol table",
    )?;
    let (index, table) = tables[0];
    let strings = elf
        .section_headers
        .get(table.sh_link as usize)
        .ok_or("symbol string-table link")?;
    require(
        strings.sh_type == section_header::SHT_STRTAB
            && table.sh_entsize == 24
            && table.sh_size % 24 == 0
            && table.sh_size / 24 == elf.syms.len() as u64
            && table.sh_info as u64 <= table.sh_size / 24,
        "initializer symbol-table declarations differ",
    )?;
    section_file_bytes(table, bytes)?;
    let raw = section_file_bytes(strings, bytes)?;
    require(
        !raw.is_empty() && raw[0] == 0 && raw.last() == Some(&0),
        "symbol string-table bounds",
    )?;
    for symbol in elf.syms.iter() {
        require(
            raw.get(symbol.st_name..)
                .is_some_and(|tail| tail.contains(&0)),
            "symbol name outside linked string table",
        )?;
    }
    Ok(index)
}
// This exact compiler-generated ET_REL shape has no symbolic authority:
// empty text/data/bss, no symbol or relocation tables, and only GNU property
// note bytes plus the section-name string table. It stays in the full object
// inventory and original linker input; it can never supply a role/target.
fn checked_object_symbol_authority(elf: &Elf<'_>, bytes: &[u8]) -> Result<()> {
    if elf
        .section_headers
        .iter()
        .any(|s| s.sh_type == section_header::SHT_SYMTAB)
    {
        checked_symtab(elf, bytes)?;
        return Ok(());
    }
    // Every byte/section field of the finite metadata-only alternative is
    // checked. Unknown symbol-less objects refuse; this is not a name filter.
    const HEADER: [u8; 64] = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
        0x07, 0x00, 0x06, 0x00,
    ];
    const PROPERTY: [u8; 48] = [
        0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55,
        0x00, 0x02, 0x00, 0x01, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    const SHAPES: [[u64; 10]; 7] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [11, 1, 6, 0, 64, 0, 0, 0, 1, 0],
        [17, 1, 3, 0, 64, 0, 0, 0, 1, 0],
        [23, 8, 3, 0, 64, 0, 0, 0, 1, 0],
        [28, 7, 2, 0, 64, 48, 0, 0, 8, 0],
        [47, 1, 0, 0, 112, 0, 0, 0, 1, 0],
        [1, 3, 0, 0, 112, 63, 0, 0, 1, 0],
    ];
    require(
        bytes.len() == 624
            && bytes.get(..64) == Some(&HEADER[..])
            && bytes.get(64..112) == Some(&PROPERTY[..])
            && bytes.get(112..175)
                == Some(
                    &b"\0.shstrtab\0.text\0.data\0.bss\0.note.gnu.property\0.note.GNU-stack\0"[..],
                )
            && bytes.get(175) == Some(&0)
            && elf.header.e_type == header::ET_REL
            && elf.header.e_machine == header::EM_X86_64
            && elf.is_64
            && elf.little_endian
            && elf.program_headers.is_empty()
            && elf.syms.is_empty()
            && elf.dynsyms.is_empty()
            && elf.shdr_relocs.is_empty()
            && elf.section_headers.len() == SHAPES.len(),
        "symbol-less initializer object is not finite inert GNU property metadata",
    )?;
    for (section, expected) in elf.section_headers.iter().zip(SHAPES) {
        let fields = [
            u64::try_from(section.sh_name).map_err(|_| "metadata section name overflow")?,
            u64::from(section.sh_type),
            section.sh_flags,
            section.sh_addr,
            section.sh_offset,
            section.sh_size,
            u64::from(section.sh_link),
            u64::from(section.sh_info),
            section.sh_addralign,
            section.sh_entsize,
        ];
        require(
            fields == expected,
            "symbol-less metadata section shape differs",
        )?;
        section_file_bytes(section, bytes)?;
    }
    Ok(())
}

fn checked_relocation_section<'a>(
    elf: &'a Elf<'_>,
    bytes: &[u8],
    index: usize,
    symtab: usize,
    decoded_count: usize,
) -> Result<&'a section_header::SectionHeader> {
    let rs = elf
        .section_headers
        .get(index)
        .ok_or("relocation section index")?;
    require(
        rs.sh_type == section_header::SHT_RELA
            && rs.sh_link as usize == symtab
            && rs.sh_info > 0
            && (rs.sh_info as usize) < elf.section_headers.len()
            && rs.sh_entsize == 24
            && rs.sh_size % 24 == 0
            && rs.sh_size / 24 == decoded_count as u64,
        "initializer relocation table ownership/record declarations differ",
    )?;
    section_file_bytes(rs, bytes)?;
    Ok(rs)
}
fn checked_relocation_inventory(elf: &Elf<'_>, bytes: &[u8], symtab: usize) -> Result<()> {
    for (index, s) in elf.section_headers.iter().enumerate() {
        if !matches!(
            s.sh_type,
            section_header::SHT_RELA | section_header::SHT_REL
        ) {
            continue;
        }
        require(
            s.sh_type == section_header::SHT_RELA,
            "implicit relocation table unsupported",
        )?;
        let decoded = elf
            .shdr_relocs
            .iter()
            .filter(|(i, _)| *i == index)
            .collect::<Vec<_>>();
        if s.sh_size == 0 && decoded.is_empty() {
            checked_relocation_section(elf, bytes, index, symtab, 0)?;
        } else {
            require(
                decoded.len() == 1,
                "raw relocation table missing/duplicate in decoded census",
            )?;
            checked_relocation_section(elf, bytes, index, symtab, decoded[0].1.len())?;
        }
    }
    for (index, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *index, symtab, rows.len())?;
        for r in rows.iter() {
            require(
                r.r_sym < elf.syms.len(),
                "relocation symbol outside linked table",
            )?;
            checked_relocation_span(elf, rs, r.r_offset, r.r_type)?;
        }
    }
    Ok(())
}
// SysV AMD64 field widths, not an arbitrary maximum. Unsupported encodings
// remain unknown; this table never makes them acceptable inside a body.
fn relocation_width(kind: u32) -> Option<u64> {
    match kind {
        0 | 35 => Some(0),
        1 | 6 | 7 | 8 | 16 | 17 | 18 | 24 | 25 | 27 | 28 | 29 | 30 | 31 | 33 | 37 | 38 => Some(8),
        2 | 3 | 4 | 9 | 10 | 11 | 19 | 20 | 21 | 22 | 23 | 26 | 32 | 34 | 41 | 42 => Some(4),
        12 | 13 => Some(2),
        14 | 15 => Some(1),
        36 => Some(16),
        _ => None,
    }
}
fn checked_relocation_span(
    elf: &Elf<'_>,
    rs: &section_header::SectionHeader,
    offset: u64,
    kind: u32,
) -> Result<Option<u64>> {
    let target = &elf.section_headers[rs.sh_info as usize];
    let base = if elf.header.e_type == header::ET_REL {
        0
    } else {
        target.sh_addr
    };
    let end = base
        .checked_add(target.sh_size)
        .ok_or("relocation section end overflow")?;
    require(
        offset >= base && offset <= end,
        "relocation not in declared target section",
    )?;
    let width = relocation_width(kind);
    if let Some(width) = width {
        require(
            offset.checked_add(width).is_some_and(|limit| limit <= end),
            "relocation field escapes declared target section",
        )?;
    } else {
        require(
            offset < end,
            "unknown relocation starts outside declared target",
        )?;
    }
    Ok(width)
}

fn selected_field_overlap(
    target: &section_header::SectionHeader,
    offset: u64,
    kind: u32,
    begin: u64,
    end: u64,
) -> Result<bool> {
    require(begin < end, "selected extent empty/reversed")?;
    let target_end = target
        .sh_addr
        .checked_add(target.sh_size)
        .ok_or("relocation target end")?;
    match relocation_width(kind) {
        Some(0) => Ok(false),
        Some(n) => Ok(offset < end
            && offset
                .checked_add(n)
                .ok_or("initializer final relocation width overflow")?
                > begin),
        None => {
            // Unknown encodings have no invented maximum field width.
            require(
                !(target.sh_addr < end && target_end > begin) || offset >= end,
                "unknown final relocation may intersect initializer",
            )?;
            Ok(false)
        }
    }
}

fn join_selected_initializer(
    role: InitializerRole,
    map: &str,
    selected: &ObjectInput<'_>,
    all_objects: &[ObjectInput<'_>],
    final_elf: &Elf<'_>,
    final_bytes: &[u8],
) -> Result<RelocatedDefinition> {
    join_selected_initializer_named(
        role,
        role.symbol(),
        map,
        selected,
        all_objects,
        final_elf,
        final_bytes,
    )
}

fn join_selected_initializer_named(
    role: InitializerRole,
    actual_name: &str,
    map: &str,
    selected: &ObjectInput<'_>,
    all_objects: &[ObjectInput<'_>],
    final_elf: &Elf<'_>,
    final_bytes: &[u8],
) -> Result<RelocatedDefinition> {
    require(
        actual_name == role.symbol() || role.terminal_name(actual_name),
        "initializer selected name outside exact role path",
    )?;
    require(
        selected.elf.header.e_type == header::ET_REL
            && selected.elf.header.e_machine == header::EM_X86_64
            && selected.elf.is_64
            && selected.elf.little_endian,
        "initializer input is not actual x86-64 ELF64LE relocatable object",
    )?;
    let definitions = selected
        .elf
        .syms
        .iter()
        .filter(|s| selected.elf.strtab.get_at(s.st_name) == Some(actual_name) && s.st_shndx != 0)
        .collect::<Vec<_>>();
    require(
        definitions.len() == 1,
        "initializer input definition absent/ambiguous",
    )?;
    let input_symbol = &definitions[0];
    require(
        role.binding(*input_symbol, true) && input_symbol.st_type() == sym::STT_FUNC,
        "initializer input is not strong GLOBAL function",
    )?;
    let section = selected
        .elf
        .section_headers
        .get(input_symbol.st_shndx)
        .ok_or("initializer input body section")?;
    require(
        section.sh_type == section_header::SHT_PROGBITS
            && section.sh_flags == 6
            && input_symbol.st_value == 0
            && input_symbol.st_size == section.sh_size
            && section.sh_size > 0
            && section.sh_size <= 4096,
        "initializer definition is not complete bounded allocated RX input section",
    )?;
    let address = mapped_definition(map, selected, input_symbol)?;
    let final_symbols = final_elf
        .syms
        .iter()
        .filter(|s| final_elf.strtab.get_at(s.st_name) == Some(actual_name) && s.st_shndx != 0)
        .collect::<Vec<_>>();
    require(
        final_symbols.len() == 1,
        "initializer final definition absent/ambiguous",
    )?;
    let linked = &final_symbols[0];
    require(
        linked.st_type() == sym::STT_FUNC
            && linked.st_value == address
            && linked.st_size == input_symbol.st_size
            && role.binding(*linked, false),
        "initializer final kind/binding/map extent differs",
    )?;
    if let Some(names) = allocator_alias_names(&role) {
        allocator_aliases(names, selected, input_symbol, final_elf, linked)?;
    }
    let start = usize::try_from(section.sh_offset).map_err(|_| "initializer body offset")?;
    let size = usize::try_from(section.sh_size).map_err(|_| "initializer body size")?;
    let input = selected
        .bytes
        .get(
            start
                ..start
                    .checked_add(size)
                    .ok_or("initializer input end overflow")?,
        )
        .ok_or("initializer input outside owning member")?;
    let (load, offset) = unique_file_mapping(final_elf, final_bytes, address, size)?;
    require(load.p_flags == 5, "initializer final body not immutable RX")?;
    let final_body = final_bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or("initializer final end overflow")?,
        )
        .ok_or("initializer final body outside file")?;
    let source_table = checked_symtab(&selected.elf, selected.bytes)?;
    let final_table = checked_symtab(final_elf, final_bytes)?;
    checked_relocation_inventory(&selected.elf, selected.bytes, source_table)?;
    checked_relocation_inventory(final_elf, final_bytes, final_table)?;
    let final_section = final_elf
        .section_headers
        .get(linked.st_shndx)
        .ok_or("initializer final symbol section missing")?;
    require(
        final_section.sh_flags & section_header::SHF_ALLOC as u64 != 0
            && address >= final_section.sh_addr
            && address.checked_add(size as u64).is_some_and(|end| {
                final_section
                    .sh_addr
                    .checked_add(final_section.sh_size)
                    .is_some_and(|limit| end <= limit)
            }),
        "initializer final symbol escapes declared section",
    )?;
    let mut source_relocs = Vec::new();
    for (section_index, relocs) in &selected.elf.shdr_relocs {
        let rs = checked_relocation_section(
            &selected.elf,
            selected.bytes,
            *section_index,
            source_table,
            relocs.len(),
        )?;
        if rs.sh_info as usize != input_symbol.st_shndx {
            continue;
        }
        for r in relocs.iter() {
            checked_relocation_span(&selected.elf, rs, r.r_offset, r.r_type)?;
            source_relocs.push(InputRelocation {
                offset: usize::try_from(r.r_offset).map_err(|_| "initializer relocation offset")?,
                kind: r.r_type,
                addend: r.r_addend.ok_or("initializer relocation addend absent")?,
                target: resolve_input_target(
                    map,
                    selected,
                    r.r_sym,
                    all_objects,
                    final_elf,
                    final_bytes,
                )?,
            });
        }
    }
    let end = address
        .checked_add(size as u64)
        .ok_or("initializer final end")?;
    let mut linked_relocs = Vec::new();
    for (section_index, relocs) in &final_elf.shdr_relocs {
        let rs = checked_relocation_section(
            final_elf,
            final_bytes,
            *section_index,
            final_table,
            relocs.len(),
        )?;
        for r in relocs.iter() {
            let width = checked_relocation_span(final_elf, rs, r.r_offset, r.r_type)?;
            let target = &final_elf.section_headers[rs.sh_info as usize];
            let overlaps = selected_field_overlap(target, r.r_offset, r.r_type, address, end)?;
            if !overlaps {
                continue;
            }
            require(
                rs.sh_info as usize == linked.st_shndx,
                "initializer relocation declares another output section",
            )?;
            require(
                r.r_offset >= address
                    && width.is_some_and(|n| {
                        r.r_offset.checked_add(n).is_some_and(|limit| limit <= end)
                    }),
                "initializer relocation crosses selected extent",
            )?;
            let symbol = final_elf
                .syms
                .get(r.r_sym)
                .ok_or("initializer final relocation symbol")?;
            linked_relocs.push(FinalRelocation {
                offset: usize::try_from(r.r_offset - address)
                    .map_err(|_| "initializer final offset")?,
                kind: r.r_type,
                addend: r
                    .r_addend
                    .ok_or("initializer final explicit addend absent")?,
                symbol_value: symbol.st_value,
            });
        }
    }
    let mut proof = join_relocated_body(
        final_elf,
        final_bytes,
        address,
        input,
        final_body,
        &source_relocs,
        &linked_relocs,
    )?;
    proof.member = Some((
        selected.member_name.to_owned(),
        selected.ordinal,
        selected.header_offset,
    ));
    proof.member_sha256 = sha256(selected.bytes);
    proof.input_body_sha256 = sha256(input);
    proof.section_index = input_symbol.st_shndx;
    if matches!(role, InitializerRole::MuslSsp) {
        let targets = selected
            .elf
            .shdr_relocs
            .iter()
            .filter(|(index, _)| {
                selected.elf.section_headers[*index].sh_info as usize == input_symbol.st_shndx
            })
            .flat_map(|(_, rows)| rows.iter())
            .filter(|r| {
                selected
                    .elf
                    .syms
                    .get(r.r_sym)
                    .and_then(|s| selected.elf.strtab.get_at(s.st_name))
                    == Some("memcpy")
            })
            .map(|r| {
                resolve_input_target(map, selected, r.r_sym, all_objects, final_elf, final_bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        require(
            targets.len() == 1,
            "SSP exact memcpy relocation missing/ambiguous",
        )?;
        proof.memcpy_target = Some(targets[0].mapped_input_value);
    }
    Ok(proof)
}

/// Digest of this compiled implementation, bound separately from lib.rs.
pub fn implementation_sha256() -> String {
    sha256(include_bytes!("selected_initializers.rs"))
}

/// Explicit file inputs for a fresh real link. These paths are inputs, not
/// authority tuples. All byte/member/address facts are re-derived below.
pub struct InitializerLinkInputs<'a> {
    pub lld: &'a Path,
    pub script: &'a Path,
    pub libc: &'a Path,
    pub supporting_archives: &'a [&'a Path],
    pub memcpy_source: &'a Path,
    pub musl_source_authority: &'a Path,
    pub stack_chk_source: &'a Path,
    pub output_directory: &'a Path,
}

// Private live transaction brand, never supplied as a scalar or serialized.
struct DefinitionSourceOwner(Arc<ArchiveSourceOwner>);
impl std::fmt::Debug for DefinitionSourceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DefinitionSourceOwner(private)")
    }
}
// Named core roles stay distinct from the full producer custody ledger.
#[derive(Debug)]
struct DefinitionCore {
    runtime: FileIdentity,
    libc: FileIdentity,
    artifact: FileIdentity,
    map: FileIdentity,
}
impl DefinitionCore {
    fn new(
        runtime: &FileIdentity,
        libc: &FileIdentity,
        artifact: &FileIdentity,
        map: &FileIdentity,
    ) -> Self {
        Self {
            runtime: runtime.clone(),
            libc: libc.clone(),
            artifact: artifact.clone(),
            map: map.clone(),
        }
    }
    fn files(&self) -> Vec<FileIdentity> {
        vec![
            self.runtime.clone(),
            self.libc.clone(),
            self.artifact.clone(),
            self.map.clone(),
        ]
    }
    fn require_ledger(&self, files: &[FileIdentity]) -> Result<()> {
        let core = self.files();
        require(
            core.iter().all(|file| files.contains(file))
                && core
                    .iter()
                    .map(|file| &file.path)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 4,
            "selected definition named core absent/aliased in complete custody ledger",
        )
    }
}

/// Source/archive/relocated-definition proof only. No Deserialize/Clone,
/// constructor, Ready flag, executable image or admission conversion.
#[derive(Debug)]
pub struct SelectedInitializerDefinitions {
    source_owner: DefinitionSourceOwner,
    core: DefinitionCore,
    tls: RelocatedDefinition,
    ssp: RelocatedDefinition,
    fail: RelocatedDefinition,
    malloc_alias: RelocatedDefinition,
    free_alias: RelocatedDefinition,
    files: Vec<FileIdentity>,
}
impl SelectedInitializerDefinitions {
    pub fn addresses(&self) -> (u64, u64) {
        (self.tls.address, self.ssp.address)
    }
    pub fn verify(&self) -> Result<()> {
        self.core.require_ledger(&self.files)?;
        let mut extents = Vec::new();
        for role in [
            &self.tls,
            &self.ssp,
            &self.fail,
            &self.malloc_alias,
            &self.free_alias,
        ] {
            require(
                role.bytes > 0
                    && role.bytes <= 4096
                    && role.relocation_fields <= role.bytes / 4
                    && role.member.is_some()
                    && role.section_index > 0
                    && role.member_sha256.len() == 64
                    && role.input_body_sha256.len() == 64,
                "selected initializer internal definition identity incomplete",
            )?;
            let end = role
                .address
                .checked_add(role.bytes as u64)
                .ok_or("definition end overflow")?;
            require(
                extents.iter().all(|&(a, b)| role.address >= b || end <= a),
                "selected initializer definition extents overlap",
            )?;
            extents.push((role.address, end));
        }
        for file in &self.files {
            file.verify()?;
        }
        Ok(())
    }
}

struct MemberBytes {
    archive_index: usize,
    name: String,
    ordinal: usize,
    header: u64,
    bytes: Vec<u8>,
}
fn extract_objects(archive: &FileIdentity, archive_index: usize) -> Result<Vec<MemberBytes>> {
    archive.verify()?;
    require(
        fs::metadata(&archive.path)
            .map_err(|e| e.to_string())?
            .len()
            <= 256 * 1024 * 1024,
        "initializer archive exceeds bound",
    )?;
    let bytes = fs::read(&archive.path).map_err(|e| e.to_string())?;
    let parsed = goblin::archive::Archive::parse(&bytes).map_err(|e| e.to_string())?;
    let mut objects = Vec::new();
    for ordinal in 0..parsed.len() {
        let member = parsed
            .get_at(ordinal)
            .ok_or("initializer archive member missing")?;
        let offset = usize::try_from(member.offset).map_err(|_| "initializer member offset")?;
        let body = bytes
            .get(
                offset
                    ..offset
                        .checked_add(member.size())
                        .ok_or("initializer member end")?,
            )
            .ok_or("initializer archive member outside owning bytes")?;
        if !body.starts_with(b"\x7fELF") {
            // Rust metadata has no linkable definitions. Unknown actual object
            // formats (including LTO bitcode) refuse rather than disappear.
            require(
                member.extended_name() == "rust.metadata.bin"
                    || member.extended_name().ends_with(".rmeta"),
                "initializer archive contains unsupported non-ELF object",
            )?;
            continue;
        }
        let elf = Elf::parse(body).map_err(|e| e.to_string())?;
        require(
            elf.header.e_type == header::ET_REL
                && elf.header.e_machine == header::EM_X86_64
                && elf.is_64
                && elf.little_endian,
            "initializer archive object format differs",
        )?;
        objects.push(MemberBytes {
            archive_index,
            name: member.extended_name().to_owned(),
            ordinal,
            header: member.header_offset,
            bytes: body.to_vec(),
        });
    }
    archive.verify()?;
    Ok(objects)
}

// Selection is a linker-map fact, not the presence of a strong definition
// anywhere in an input archive. Keep discarded objects in the full inventory;
// a present candidate row still passes the original strict mapper below.
fn role_section_is_selected(
    map: &str,
    object: &ObjectInput<'_>,
    symbol: &sym::Sym,
) -> Result<bool> {
    require(
        symbol.st_shndx > 0 && symbol.st_shndx < object.elf.section_headers.len(),
        "initializer candidate undefined/absolute/reserved section",
    )?;
    let section = &object.elf.section_headers[symbol.st_shndx];
    require(
        section.sh_flags & section_header::SHF_ALLOC as u64 != 0
            && symbol
                .st_value
                .checked_add(symbol.st_size)
                .is_some_and(|end| end <= section.sh_size),
        "initializer candidate is not bounded allocated input",
    )?;
    let name = object
        .elf
        .shdr_strtab
        .get_at(section.sh_name)
        .ok_or("initializer candidate section name")?;
    let suffix = format!(
        "{}({}):({})",
        object.archive_path.display(),
        object.member_name,
        name
    );
    if !map.lines().any(|line| line.trim_end().ends_with(&suffix)) {
        return Ok(false);
    }
    // Do not turn malformed/duplicate present rows into discarded candidates.
    mapped_definition(map, object, symbol)?;
    Ok(true)
}

fn select_role<'o>(
    role: &InitializerRole,
    objects: &'o [ObjectInput<'o>],
    map: &str,
    runtime_path: &Path,
) -> Result<&'o ObjectInput<'o>> {
    select_role_named(role, objects, map, runtime_path, false).map(|(object, _)| object)
}

fn select_role_named<'o>(
    role: &InitializerRole,
    objects: &'o [ObjectInput<'o>],
    map: &str,
    runtime_path: &Path,
    terminal_discovery: bool,
) -> Result<(&'o ObjectInput<'o>, String)> {
    let mut found = Vec::new();
    for object in objects {
        for symbol in object.elf.syms.iter().filter(|s| {
            s.st_shndx != 0
                && object.elf.strtab.get_at(s.st_name).is_some_and(|name| {
                    if terminal_discovery {
                        role.terminal_name(name)
                    } else {
                        name == role.symbol()
                    }
                })
                && role.binding(*s, true)
                && s.st_type() == sym::STT_FUNC
        }) {
            if !role_section_is_selected(map, object, &symbol)? {
                continue;
            }
            let correct_owner = match role {
                InitializerRole::RustTls
                | InitializerRole::RustMallocAlias
                | InitializerRole::RustFreeAlias
                | InitializerRole::InitializationFailed
                | InitializerRole::InitialTerminal => {
                    object.member_name.starts_with("reverie_inguest-")
                        && object.archive_path == runtime_path
                }
                InitializerRole::MappedRoot
                | InitializerRole::MappedTerminal
                | InitializerRole::MappedObserver => {
                    object.member_name.starts_with("detcore_liteinst-")
                        && object.archive_path == runtime_path
                }
                InitializerRole::MuslSsp | InitializerRole::MuslFail => {
                    object.member_name == "__stack_chk_fail.lo"
                        && object.archive_path != runtime_path
                }
            };
            require(
                correct_owner,
                "initializer strong definition has wrong physical source owner",
            )?;
            // mapped_definition propagates malformed/duplicate/absent map rows.
            let _ = mapped_definition(map, object, &symbol)?;
            let name = object
                .elf
                .strtab
                .get_at(symbol.st_name)
                .ok_or("initializer selected full name absent")?
                .to_owned();
            found.push((object, name));
        }
    }
    require(
        found.len() == 1,
        "initializer selected strong definition absent/duplicate",
    )?;
    Ok(found.remove(0))
}

fn join_from_files(
    source_owner: &Arc<ArchiveSourceOwner>,
    runtime: &FileIdentity,
    libc: &FileIdentity,
    artifact: &FileIdentity,
    link_map: &FileIdentity,
) -> Result<SelectedInitializerDefinitions> {
    let archives = [runtime.clone(), libc.clone()];
    let mut backing = extract_objects(runtime, 0)?;
    backing.extend(extract_objects(libc, 1)?);
    require(
        !backing.is_empty() && backing[0].archive_index == 0,
        "runtime input inventory empty",
    )?;
    let mut objects = Vec::new();
    for member in &backing {
        objects.push(ObjectInput {
            archive_path: &archives[member.archive_index].path,
            member_name: &member.name,
            ordinal: member.ordinal,
            header_offset: member.header,
            bytes: &member.bytes,
            elf: Elf::parse(&member.bytes).map_err(|e| e.to_string())?,
        });
    }
    require(
        fs::metadata(&artifact.path)
            .map_err(|e| e.to_string())?
            .len()
            <= 128 * 1024 * 1024
            && fs::metadata(&link_map.path)
                .map_err(|e| e.to_string())?
                .len()
                <= 128 * 1024 * 1024,
        "initializer ELF/map observation exceeds maintained bound",
    )?;
    let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
    static_image_metadata(&elf, &bytes)?;
    for object in &objects {
        checked_object_symbol_authority(&object.elf, object.bytes)?;
    }
    let text = fs::read_to_string(&link_map.path).map_err(|e| e.to_string())?;
    let role_join = |role: InitializerRole| -> Result<RelocatedDefinition> {
        let object = select_role(&role, &objects, &text, &runtime.path)?;
        join_selected_initializer(role, &text, object, &objects, &elf, &bytes)
    };
    let tls = role_join(InitializerRole::RustTls)?;
    let ssp = role_join(InitializerRole::MuslSsp)?;
    let fail = role_join(InitializerRole::MuslFail)?;
    let malloc_alias = role_join(InitializerRole::RustMallocAlias)?;
    let free_alias = role_join(InitializerRole::RustFreeAlias)?;
    let core = DefinitionCore::new(runtime, libc, artifact, link_map);
    let files = core.files();
    Ok(SelectedInitializerDefinitions {
        source_owner: DefinitionSourceOwner(Arc::clone(source_owner)),
        core,
        tls,
        ssp,
        fail,
        malloc_alias,
        free_alias,
        files,
    })
}

impl VerifiedStaticSource {
    /// Perform one fresh real static link of this maintained archive, then join
    /// actual strong TLS/SSP definitions. Does not execute the resulting image.
    /// Whole pre-FS semantics, optional weak guards, source-to-machine qualification
    /// and entry admission remain separate; this return type cannot mint them.
    pub fn link_and_join_initializer_definitions(
        &self,
        archive: &StaticArchive,
        input: &InitializerLinkInputs<'_>,
        runner: &mut Runner,
    ) -> Result<SelectedInitializerDefinitions> {
        let mut files = Vec::new();
        let mut bind = |path: &Path| -> Result<FileIdentity> {
            let file = FileIdentity::read(path)?;
            files.push(file.clone());
            Ok(file)
        };
        // Every Result after archive/source admission passes the close below.
        let result = (|| {
            // Private actual source-transaction ownership precedes ALL output
            // creation/linking; metadata equality is not source provenance.
            self.require_archive_owner(archive)?;
            archive.verify()?;
            require(
                archive.metadata_sha256 == self.metadata_sha256,
                "initializer archive is not this actual source transaction",
            )?;
            self.guard.close(runner)?;
            let lld = bind(input.lld)?;
            require(
                lld.sha256 == "eb9b9bc681e57f7ff4166f8fb57fad7336d29a51c85e8c70ba1ca203600e392b",
                "initializer linker is not the bound July12 rust-lld",
            )?;
            let script = bind(input.script)?;
            let script_bytes = fs::read(&script.path).map_err(|e| e.to_string())?;
            require(
                script_bytes.len() <= 128 * 1024 * 1024,
                "initializer link script exceeds bound",
            )?;
            let script_text = std::str::from_utf8(&script_bytes).map_err(|e| e.to_string())?;
            // No unbound auxiliary file can enter through linker-script input
            // directives. Deliberately conservative on this generated script.
            require(
                !script_text
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|t| ["INCLUDE", "INPUT", "GROUP", "SEARCH_DIR", "STARTUP"].contains(&t)),
                "initializer script can introduce unbound file inputs",
            )?;
            let libc = bind(input.libc)?;
            require(
                libc.sha256 == "e699c64b0c6b427d89ad5bf767bf78beb30c19930c5dedff635951636e8f9f70",
                "initializer libc is not exact private July12 native input",
            )?;
            let inventory = bind(&input.musl_source_authority.join("inventory.json"))?;
            require(
                inventory.sha256
                    == "6aeea4469c8ba49c4c475a6694972e6a1ef3974954c9f986f99d7d1bce926275",
                "initializer native source authority inventory differs",
            )?;
            let native_sources: Value =
                serde_json::from_slice(&fs::read(&inventory.path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            for row in native_sources["files"]
                .as_array()
                .ok_or("native source inventory files")?
            {
                let relative = Path::new(row["path"].as_str().ok_or("native source path")?);
                require(
                    !relative.is_absolute()
                        && relative
                            .components()
                            .all(|c| matches!(c, std::path::Component::Normal(_))),
                    "native source inventory escape",
                )?;
                let source = bind(&input.musl_source_authority.join(relative))?;
                require(
                    Some(source.sha256.as_str()) == row["sha256"].as_str(),
                    "initializer native source identity differs",
                )?;
            }
            bind(input.memcpy_source)?;
            let stack_source = bind(input.stack_chk_source)?;
            require(
                stack_source.sha256
                    == "2ea4d8cf6758daddecf8973913ac196ffa76fdb355cea391ca890aeafdc2ac6c",
                "initializer SSP source differs from source-bound musl archive member",
            )?;
            let mut supporting = Vec::new();
            for path in input.supporting_archives {
                supporting.push(bind(path)?);
            }
            require(
                supporting.len() == 1
                    && supporting[0].sha256
                        == "eb16569e611a5d6cdda2e7604fd6402a3ad810817dd8d63ed50baa2ce8070aaa",
                "initializer supporting inputs differ from existing V12 private libunwind",
            )?;
            // Bind actual Cargo-selected Rust TLS source/ABI from its guarded
            // resolved Cargo root, rather than a caller-provided source path/hash.
            let roots = self
                .guard
                .roots
                .iter()
                .filter(|(_, kind)| matches!(kind, RootBinding::Cargo(_)))
                .map(|(path, _)| path)
                .collect::<Vec<_>>();
            require(
                roots.len() == 1,
                "initializer resolved runtime source root ambiguous",
            )?;
            let mut tls_files = Vec::new();
            let tls_variant = super::tls_sources::bind(roots[0], &mut tls_files);
            for file in tls_files {
                // Reuse this transaction's ordinary complete file ledger.
                bind(&file.path)?;
            }
            tls_variant?;
            let output = input.output_directory;
            require(
                output.is_absolute()
                    && output.starts_with(&self.target_dir)
                    && output
                        .parent()
                        .is_some_and(|p| fs::canonicalize(p).ok().as_deref() == Some(p)),
                "initializer link output must have canonical sole-target parent",
            )?;
            fs::create_dir(output).map_err(|e| e.to_string())?;
            let elf_path = output.join("initializer-definitions.not-qualified.elf");
            let map_path = output.join("initializer-definitions.map");
            let args = {
                // Exact existing V12-v2 link transaction. Preparation owns
                // section inventory/classification/script; this is the ONE link
                // invocation, with the still-owned maintained StaticArchive.
                let mut args: Vec<String> = [
                    "-flavor",
                    "gnu",
                    "--threads=4",
                    "-m",
                    "elf_x86_64",
                    "-static",
                    "--no-dynamic-linker",
                    "--no-undefined",
                    "--gc-sections",
                    "--no-relax",
                    "--emit-relocs",
                    "--orphan-handling=error",
                    "-z",
                    "max-page-size=4096",
                    "-z",
                    "common-page-size=4096",
                    "--undefined=detcore_liteinst_mapped_entry",
                    "--undefined=__stack_chk_fail",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect();
                for name in [
                    "__init_tls",
                    "malloc",
                    "__libc_malloc",
                    "__libc_malloc_impl",
                    "calloc",
                    "__libc_calloc",
                    "free",
                    "__libc_free",
                    "realloc",
                    "__libc_realloc",
                    "reallocarray",
                    "aligned_alloc",
                    "memalign",
                    "valloc",
                    "posix_memalign",
                    "malloc_usable_size",
                    "__malloc_allzerop",
                ] {
                    args.push(format!("--undefined={name}"));
                }
                args.extend([
                    "--entry=detcore_liteinst_mapped_entry".into(),
                    "-T".into(),
                    script.path.to_str().ok_or("link script UTF8")?.into(),
                    format!("-Map={}", map_path.display()),
                    "--trace".into(),
                    "--print-gc-sections".into(),
                    "-o".into(),
                    elf_path.to_str().ok_or("link output UTF8")?.into(),
                    archive
                        .file
                        .path
                        .to_str()
                        .ok_or("runtime archive UTF8")?
                        .into(),
                    libc.path.to_str().ok_or("libc archive UTF8")?.into(),
                ]);
                for file in &supporting {
                    args.push(file.path.to_str().ok_or("support archive UTF8")?.into());
                }
                args
            };
            // Actual argv is retained by the existing bounded Runner. No supplied
            // success result/JSON/old feasibility output can construct this proof.
            let program = lld.path.to_str().ok_or("LLD UTF8")?;
            let enclosing_deadline = runner.deadline;
            runner.deadline = runner
                .deadline
                .min(Instant::now() + Duration::from_secs(600));
            let link = runner.run(program, &args, output);
            runner.deadline = enclosing_deadline;
            let produced_elf = if elf_path.exists() {
                bind(&elf_path).map(Some)
            } else {
                Ok(None)
            };
            let produced_map = if map_path.exists() {
                bind(&map_path).map(Some)
            } else {
                Ok(None)
            };
            // Attempt BOTH output seals even when LLD or the first seal failed.
            let mut failures = Vec::new();
            if let Err(e) = &link {
                failures.push(e.clone());
            }
            if let Err(e) = &produced_elf {
                failures.push(e.clone());
            }
            if let Err(e) = &produced_map {
                failures.push(e.clone());
            }
            require(failures.is_empty(), failures.join("; "))?;
            let produced_elf = produced_elf?;
            let produced_map = produced_map?;
            let artifact = produced_elf.ok_or("actual link produced no ELF")?;
            let map = produced_map.ok_or("actual link produced no map")?;
            let native = super::super::private_machine_diagnostic::NativeMemcpyInputs {
                archive: &libc.path,
                source: input.memcpy_source,
                source_authority: input.musl_source_authority,
                link_map: &map.path,
            };
            // Reuse the existing pinned 47-file native recipe/patch/source guard,
            // exact libc/member/map/full memcpy role, and every native close.
            super::super::private_machine_diagnostic::with_native_memcpy(
                &native,
                &artifact,
                |memcpy| {
                    let proof = join_from_files(
                        &self.archive_owner,
                        &archive.file,
                        &libc,
                        &artifact,
                        &map,
                    )?;
                    require(
                        proof.ssp.memcpy_target == Some(memcpy.definition_address()),
                        "SSP memcpy edge is not the source/member/final verified native role",
                    )?;
                    Ok(proof)
                },
            )
        })();
        let mut errors = Vec::new();
        if let Err(e) = archive.verify() {
            errors.push(e);
        }
        if let Err(e) = self.guard.close(runner) {
            errors.push(e);
        }
        for file in &files {
            if let Err(e) = file.verify() {
                errors.push(e);
            }
        }
        let close = if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        };
        let mut result = close_result(result, close)?;
        result.files.extend(files);
        result.verify()?;
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // Tiny structural ET_REL fixtures exercise the production selector only;
    // they are not source-owned archives or selected-definition proof tokens.
    fn role_selection_image(name: &str) -> Vec<u8> {
        let mut bytes = table_image();
        let names = b"\0.strtab\0.symtab\0.text\0.rela.text\0.shstrtab\0";
        bytes[80..80 + names.len()].copy_from_slice(names);
        put(&mut bytes, 60, 2, 6);
        put(&mut bytes, 62, 2, 5);
        for (index, offset) in [(1, 1), (2, 9), (3, 17), (4, 23)] {
            put(&mut bytes, 512 + index * 64, 4, offset);
        }
        let h = 512 + 5 * 64;
        for (at, width, value) in [
            (0, 4, 34),
            (4, 4, 3),
            (24, 8, 80),
            (32, 8, names.len() as u64),
            (48, 8, 1),
        ] {
            put(&mut bytes, h + at, width, value);
        }
        let text = format!("\0{name}\0");
        bytes[128..128 + text.len()].copy_from_slice(text.as_bytes());
        put(&mut bytes, 512 + 64 + 32, 8, text.len() as u64);
        put(&mut bytes, 512 + 3 * 64 + 8, 8, 6);
        // One real GLOBAL FUNC definition in the allocated .text section.
        put(&mut bytes, 184, 4, 1);
        bytes[188] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
        put(&mut bytes, 190, 2, 3);
        put(&mut bytes, 200, 8, 4);
        // Empty but structurally declared RELA section; no synthetic writer.
        put(&mut bytes, 512 + 4 * 64 + 32, 8, 0);
        bytes
    }
    fn role_selection_object<'a>(
        bytes: &'a [u8],
        path: &'a Path,
        member: &'a str,
    ) -> ObjectInput<'a> {
        ObjectInput {
            archive_path: path,
            member_name: member,
            ordinal: 0,
            header_offset: 8,
            bytes,
            elf: Elf::parse(bytes).unwrap(),
        }
    }
    fn role_selection_row(path: &Path, member: &str) -> String {
        format!("1000 1000 40 8 {}({member}):(.text)\n", path.display())
    }
    #[test]
    fn selected_roles_use_actual_map_contribution_before_source_owner() {
        let runtime = Path::new("/runtime.a");
        let libc = Path::new("/libc.a");
        for (role, selected_member, selected_path) in [
            (InitializerRole::RustTls, "reverie_inguest-tls.o", runtime),
            (
                InitializerRole::RustMallocAlias,
                "reverie_inguest-allocator.o",
                runtime,
            ),
            (
                InitializerRole::RustFreeAlias,
                "reverie_inguest-allocator.o",
                runtime,
            ),
            (InitializerRole::MuslSsp, "__stack_chk_fail.lo", libc),
            (InitializerRole::MuslFail, "__stack_chk_fail.lo", libc),
        ] {
            let bytes = role_selection_image(role.symbol());
            let selected = role_selection_object(&bytes, selected_path, selected_member);
            let discarded = role_selection_object(&bytes, libc, "unselected-native.lo");
            let map = role_selection_row(selected_path, selected_member);
            let objects = [selected, discarded];
            checked_object_symbol_authority(&objects[0].elf, &bytes).unwrap();
            checked_relocation_inventory(
                &objects[0].elf,
                &bytes,
                checked_symtab(&objects[0].elf, &bytes).unwrap(),
            )
            .unwrap();
            let found = select_role(&role, &objects, &map, runtime).unwrap();
            assert_eq!(found.member_name, selected_member);
            assert_eq!(found.archive_path, selected_path);
            assert!(
                mapped_definition(&map, &objects[1], &objects[1].elf.syms.get(1).unwrap()).is_err()
            );
        }
    }
    #[test]
    fn selected_roles_keep_wrong_owner_ambiguity_and_absent_refusals() {
        let runtime = Path::new("/runtime.a");
        let libc = Path::new("/libc.a");
        let bytes = role_selection_image("__libc_malloc");
        let objects = [
            role_selection_object(&bytes, runtime, "reverie_inguest-first.o"),
            role_selection_object(&bytes, runtime, "reverie_inguest-second.o"),
            role_selection_object(&bytes, libc, "lite_malloc.lo"),
        ];
        let role = InitializerRole::RustMallocAlias;
        assert!(select_role(&role, &objects, "", runtime).is_err());
        let wrong = role_selection_row(libc, "lite_malloc.lo");
        assert!(
            select_role(&role, &objects, &wrong, runtime)
                .err()
                .unwrap()
                .contains("wrong physical source owner")
        );
        let selected = role_selection_row(runtime, "reverie_inguest-first.o");
        assert!(select_role(&role, &objects, &(selected.clone() + &wrong), runtime).is_err());
        let duplicate = selected.clone() + &role_selection_row(runtime, "reverie_inguest-second.o");
        assert!(select_role(&role, &objects, &duplicate, runtime).is_err());
        assert!(select_role(&role, &objects, &(selected.clone() + &selected), runtime).is_err());
        for malformed in [
            selected.replace("1000 1000", "1000 1001"),
            selected.replace("40 8", "3f 8"),
            selected.replace("40 8", "40 4"),
            selected.replace("1000 1000", "zzzz zzzz"),
        ] {
            assert!(select_role(&role, &objects, &malformed, runtime).is_err());
        }
    }
    #[test]
    fn discarded_role_candidates_still_require_bounded_real_input_sections() {
        let runtime = Path::new("/runtime.a");
        let original = role_selection_image("__init_tls");
        for field in 0..4 {
            let mut bytes = original.clone();
            match field {
                0 => put(&mut bytes, 190, 2, 0xfff1),
                1 => put(&mut bytes, 512 + 3 * 64 + 8, 8, 0),
                2 => put(&mut bytes, 192, 8, u64::MAX),
                _ => put(&mut bytes, 200, 8, 65),
            }
            let object = role_selection_object(&bytes, runtime, "reverie_inguest-bad.o");
            assert!(select_role(&InitializerRole::RustTls, &[object], "", runtime).is_err());
        }
    }

    fn terminal_selection_image(name: &str, role: InitializerRole) -> Vec<u8> {
        let mut bytes = role_selection_image("__init_tls");
        // Long Rust names must not overlap the fixture's symtab at160.
        bytes.resize(2048, 0);
        let names = format!("\0{name}\0");
        bytes[1024..1024 + names.len()].copy_from_slice(names.as_bytes());
        put(&mut bytes, 512 + 64 + 24, 8, 1024);
        put(&mut bytes, 512 + 64 + 32, 8, names.len() as u64);
        let (binding, visibility) = match role {
            InitializerRole::MappedTerminal => (sym::STB_LOCAL, sym::STV_DEFAULT),
            InitializerRole::MappedObserver | InitializerRole::InitialTerminal => {
                (sym::STB_GLOBAL, sym::STV_HIDDEN)
            }
            _ => (sym::STB_GLOBAL, sym::STV_DEFAULT),
        };
        bytes[188] = (binding << 4) | sym::STT_FUNC;
        bytes[189] = visibility;
        put(
            &mut bytes,
            512 + 2 * 64 + 44,
            4,
            if binding == sym::STB_LOCAL { 2 } else { 1 },
        );
        bytes
    }
    #[test]
    fn terminal_name_discovery_is_only_the_four_complete_v0_paths() {
        for role in [
            InitializerRole::MappedTerminal,
            InitializerRole::MappedObserver,
            InitializerRole::InitializationFailed,
            InitializerRole::InitialTerminal,
        ] {
            let path = role.terminal_path().unwrap();
            for disambiguator in ["0", "A9z", "j9ILj95Z7eA", "5RBfKwZN2n8"] {
                assert!(role.terminal_name(&format!("_RNvNtNtCs{disambiguator}_{path}")));
            }
            for bad in [
                format!("_RNvNtNtCs_{path}"),
                format!("_RNvNtNtCsA-{path}"),
                format!("_RNvNtNtCsA!_{path}"),
                format!("_RNvNtNtCsA__{path}"),
                format!("prefix_RNvNtNtCsA_{path}"),
                format!("_RNvNtNtCsA_{path}suffix"),
                format!("_RNvNtNtCsA_{path}.llvm.123"),
                format!(
                    "_RNvNtNtCsA_{}",
                    path.replace("12exec_private", "11exec_private")
                ),
                format!(
                    "_RNvNtNtCsA_{}",
                    path.replace("12mapped_entry", "13mapped_entry")
                ),
            ] {
                if bad != format!("_RNvNtNtCsA_{path}") {
                    assert!(!role.terminal_name(&bad), "{bad}");
                }
            }
        }
        for role in [
            InitializerRole::MappedRoot,
            InitializerRole::RustTls,
            InitializerRole::MuslSsp,
            InitializerRole::RustMallocAlias,
        ] {
            assert!(!role.terminal_name(role.symbol()));
        }
    }
    #[test]
    fn terminal_discovery_keeps_actual_selected_owner_name_and_duplicate_refusal() {
        let role = InitializerRole::MappedTerminal;
        let name = "_RNvNtNtCsj9ILj95Z7eA_16detcore_liteinst12exec_initial12mapped_entry8terminal";
        let bytes = terminal_selection_image(name, role);
        let runtime = Path::new("/runtime.a");
        let map = role_selection_row(runtime, "detcore_liteinst-first.o");
        let objects = [role_selection_object(
            &bytes,
            runtime,
            "detcore_liteinst-first.o",
        )];
        let (object, actual) = select_role_named(&role, &objects, &map, runtime, true).unwrap();
        assert_eq!(actual, name);
        assert_eq!(object.member_name, "detcore_liteinst-first.o");
        assert!(select_role(&role, &objects, &map, runtime).is_err()); // default remains exact.
        let duplicate = [
            role_selection_object(&bytes, runtime, "detcore_liteinst-first.o"),
            role_selection_object(&bytes, runtime, "detcore_liteinst-second.o"),
        ];
        let both = map.clone() + &role_selection_row(runtime, "detcore_liteinst-second.o");
        assert!(
            select_role_named(&role, &duplicate, &both, runtime, true)
                .err()
                .unwrap()
                .contains("selected strong definition absent/duplicate")
        );
        let wrong = [role_selection_object(
            &bytes,
            runtime,
            "reverie_inguest-wrong.o",
        )];
        assert!(
            select_role_named(
                &role,
                &wrong,
                &role_selection_row(runtime, "reverie_inguest-wrong.o"),
                runtime,
                true
            )
            .err()
            .unwrap()
            .contains("wrong physical source owner")
        );
        assert!(select_role_named(&role, &objects, "", runtime, true).is_err());
    }

    #[test]
    fn terminal_output_must_keep_the_exact_selected_full_name() {
        let role = InitializerRole::MappedTerminal;
        let input_name = "_RNvNtNtCsA9z_16detcore_liteinst12exec_initial12mapped_entry8terminal";
        let output_name = "_RNvNtNtCsB8y_16detcore_liteinst12exec_initial12mapped_entry8terminal";
        assert!(role.terminal_name(input_name) && role.terminal_name(output_name));
        let bytes = terminal_selection_image(output_name, role);
        let elf = Elf::parse(&bytes).unwrap();
        assert!(terminal_observation::exact_terminal_output(&elf, input_name).is_err());
        assert!(terminal_observation::exact_terminal_output(&elf, output_name).is_ok());
    }

    fn binding_definition() -> RelocatedDefinition {
        // Shape control only: no source-owned token is constructed or returned.
        RelocatedDefinition {
            address: 0x1000,
            bytes: 19,
            relocation_fields: 0,
            member: Some(("structural-only".into(), 0, 0)),
            member_sha256: "0".repeat(64),
            input_body_sha256: "0".repeat(64),
            section_index: 3,
            memcpy_target: None,
        }
    }
    #[test]
    fn selected_final_function_requires_exact_joined_extent_and_keeps_global_default_strict() {
        let raw = table_image();
        let elf = Elf::parse(&raw).unwrap();
        let mut symbol = elf.syms.get(1).unwrap();
        symbol.st_value = 0x1000;
        symbol.st_size = 19;
        symbol.st_info = (sym::STB_LOCAL << 4) | sym::STT_FUNC;
        symbol.st_other = sym::STV_HIDDEN;
        let definition = binding_definition();
        selected_symbol_shape(&symbol, &definition).unwrap();
        assert!(!strong_kind(&symbol)); // The ordinary GLOBAL gate is unchanged.
        for field in 0..6 {
            let mut bad = symbol;
            match field {
                0 => bad.st_value += 1,
                1 => bad.st_size += 1,
                2 => bad.st_size = 0,
                3 => bad.st_info = (sym::STB_WEAK << 4) | sym::STT_FUNC,
                4 => bad.st_other = sym::STV_DEFAULT,
                _ => bad.st_info = (sym::STB_LOCAL << 4) | sym::STT_OBJECT,
            }
            assert!(selected_symbol_shape(&bad, &definition).is_err());
        }
        symbol.st_info = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
        symbol.st_other = sym::STV_DEFAULT;
        selected_symbol_shape(&symbol, &definition).unwrap();
        assert!(strong_kind(&symbol));
        assert!(allocator_alias_names(&InitializerRole::RustTls).is_none());
        assert_eq!(
            allocator_alias_names(&InitializerRole::RustMallocAlias).unwrap(),
            &["__libc_malloc", "__libc_malloc_impl", "malloc"]
        );
        assert_eq!(
            allocator_alias_names(&InitializerRole::RustFreeAlias).unwrap(),
            &["__libc_free", "free"]
        );
    }
    #[test]
    fn selected_allocator_exact_alias_rows_refuse_weak_missing_extra_shifted_or_short_aliases() {
        let expected = vec![
            ("__libc_malloc".into(), 0, 2, 2, 3, 0x1000, 19),
            ("__libc_malloc_impl".into(), 1, 2, 0, 3, 0x1000, 19),
            ("malloc".into(), 1, 2, 0, 3, 0x1000, 19),
        ];
        exact_rust_alias_rows(expected.clone(), expected.clone()).unwrap();
        for field in 0..7 {
            let mut bad = expected.clone();
            match field {
                0 => {
                    bad.remove(0);
                }
                1 => bad.push(("unexpected".into(), 1, 2, 0, 3, 0x1000, 19)),
                2 => bad[1].1 = sym::STB_WEAK,
                3 => bad[1].4 += 1,
                4 => bad[1].5 += 1,
                5 => bad[1].6 -= 1,
                _ => bad[0].3 = sym::STV_DEFAULT,
            }
            assert!(exact_rust_alias_rows(bad, expected.clone()).is_err());
        }
    }
    #[test]
    fn selected_final_owner_refuses_another_transaction_even_with_identical_runtime_identity() {
        let source = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        let other = Arc::new(ArchiveSourceOwner { _reserved: 0 });
        let runtime = FileIdentity {
            path: PathBuf::from("runtime"),
            sha256: "same".into(),
        };
        let libc = FileIdentity {
            path: PathBuf::from("libc"),
            sha256: "libc".into(),
        };
        let artifact = FileIdentity {
            path: PathBuf::from("image"),
            sha256: "image".into(),
        };
        let map = FileIdentity {
            path: PathBuf::from("map"),
            sha256: "map".into(),
        };
        let core = DefinitionCore::new(&runtime, &libc, &artifact, &map);
        selected_owner_identity(
            &source,
            &runtime,
            &DefinitionSourceOwner(Arc::clone(&source)),
            &core,
        )
        .unwrap();
        assert_eq!(
            selected_owner_identity(&source, &runtime, &DefinitionSourceOwner(other), &core)
                .unwrap_err(),
            "selected final inspection belongs to another source transaction"
        );
        let mut wrong_runtime = runtime.clone();
        wrong_runtime.path = PathBuf::from("other-runtime");
        assert_eq!(
            selected_owner_identity(
                &source,
                &wrong_runtime,
                &DefinitionSourceOwner(source.clone()),
                &core
            )
            .unwrap_err(),
            "selected final runtime archive differs"
        );
    }
    fn hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn actual() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/selected_init_v12.json")).unwrap()
    }
    fn rows(v: &Value) -> (Vec<InputRelocation>, Vec<FinalRelocation>) {
        let mut source = Vec::new();
        let mut linked = Vec::new();
        for r in v["relocations"].as_array().unwrap() {
            let offset = r["offset"].as_u64().unwrap() as usize;
            let kind = r["kind"].as_u64().unwrap() as u32;
            source.push(InputRelocation {
                offset,
                kind,
                addend: r["input_addend"].as_i64().unwrap(),
                target: SelectedTarget {
                    mapped_input_value: r["mapped_input_target"].as_u64().unwrap(),
                },
            });
            linked.push(FinalRelocation {
                offset,
                kind,
                addend: r["final_addend"].as_i64().unwrap(),
                symbol_value: r["final_symbol_value"].as_u64().unwrap(),
            });
        }
        (source, linked)
    }
    fn put(b: &mut [u8], at: usize, width: usize, n: u64) {
        b[at..at + width].copy_from_slice(&n.to_le_bytes()[..width]);
    }
    // Minimal actual ELF parser input carrying the retained complete body/slots.
    // This is test container geometry, never represented as production ownership.
    fn container(v: &Value) -> Vec<u8> {
        let address = v["address"].as_u64().unwrap();
        let body = hex(v["linked_hex"].as_str().unwrap());
        let slots = v["ro_slots"].as_object().unwrap();
        let lo = slots
            .keys()
            .map(|k| k.parse::<u64>().unwrap())
            .min()
            .unwrap()
            & !4095;
        let hi = (slots
            .keys()
            .map(|k| k.parse::<u64>().unwrap())
            .max()
            .unwrap()
            + 8
            + 4095)
            & !4095;
        let rxbase = address & !4095;
        let rxlen = ((address - rxbase) + body.len() as u64 + 4095) & !4095;
        let rooff = 4096 + rxlen;
        let mut b = vec![0; (rooff + hi - lo) as usize];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, width, n) in [
            (16, 2, 2),
            (18, 2, 62),
            (20, 4, 1),
            (24, 8, address),
            (32, 8, 64),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 2),
        ] {
            put(&mut b, at, width, n);
        }
        for (i, flags, off, va, len) in [(0, 5, 4096, rxbase, rxlen), (1, 4, rooff, lo, hi - lo)] {
            let h = 64 + i * 56;
            for (at, width, n) in [
                (0, 4, 1),
                (4, 4, flags),
                (8, 8, off),
                (16, 8, va),
                (32, 8, len),
                (40, 8, len),
                (48, 8, 4096),
            ] {
                put(&mut b, h + at, width, n);
            }
        }
        let off = (4096 + address - rxbase) as usize;
        b[off..off + body.len()].copy_from_slice(&body);
        for (slot, target) in slots {
            put(
                &mut b,
                (rooff + slot.parse::<u64>().unwrap() - lo) as usize,
                8,
                target.as_u64().unwrap(),
            );
        }
        b
    }
    fn check(
        v: &Value,
        image: &[u8],
        source: &[InputRelocation],
        linked: &[FinalRelocation],
        body: &[u8],
    ) -> Result<RelocatedDefinition> {
        let elf = Elf::parse(image).map_err(|e| e.to_string())?;
        join_relocated_body(
            &elf,
            image,
            v["address"].as_u64().unwrap(),
            &hex(v["input_hex"].as_str().unwrap()),
            body,
            source,
            linked,
        )
    }
    #[test]
    fn actual_v12_full_tls_ssp_relocations_and_negative_controls() {
        for v in actual()["roles"].as_array().unwrap() {
            let image = container(v);
            let body = hex(v["linked_hex"].as_str().unwrap());
            let (source, linked) = rows(v);
            let proof = check(v, &image, &source, &linked, &body).unwrap();
            assert_eq!(proof.bytes, body.len());
            assert_eq!(proof.relocation_fields, source.len());
            let mut missing = linked.clone();
            missing.pop();
            assert!(check(v, &image, &source, &missing, &body).is_err());
            let mut wrong = linked.clone();
            wrong[0].addend += 1;
            assert!(check(v, &image, &source, &wrong, &body).is_err());
            let got = source
                .iter()
                .position(|r| r.kind == reloc::R_X86_64_GOTPCREL)
                .unwrap();
            let mut compensated = linked.clone();
            compensated[got].symbol_value += 4;
            compensated[got].addend -= 4;
            assert!(check(v, &image, &source, &compensated, &body).is_err());
            let mut wrong = source.clone();
            wrong[0].target.mapped_input_value += 1;
            assert!(check(v, &image, &wrong, &linked, &body).is_err());
            let mut unknown = source.clone();
            unknown[0].kind = reloc::R_X86_64_64;
            let mut unknown_final = linked.clone();
            unknown_final[0].kind = reloc::R_X86_64_64;
            assert!(check(v, &image, &unknown, &unknown_final, &body).is_err());
            let mut overlap = source.clone();
            overlap.push(source[0].clone());
            let mut overlap_final = linked.clone();
            overlap_final.push(linked[0].clone());
            assert!(check(v, &image, &overlap, &overlap_final, &body).is_err());
            let elf = Elf::parse(&image).unwrap();
            let (_, offset) =
                unique_file_mapping(&elf, &image, v["address"].as_u64().unwrap(), body.len())
                    .unwrap();
            let mut changed = image.clone();
            changed[offset] ^= 1;
            let mut changed_body = body.clone();
            changed_body[0] ^= 1;
            assert!(check(v, &changed, &source, &linked, &changed_body).is_err());
            let mut writable = image.clone();
            put(&mut writable, 64 + 56 + 4, 4, 6);
            assert!(check(v, &writable, &source, &linked, &body).is_err());
            let slot = v["ro_slots"]
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            let (_, offset) = unique_file_mapping(&elf, &image, slot, 8).unwrap();
            let mut wrong_slot = image.clone();
            wrong_slot[offset] ^= 1;
            assert!(check(v, &wrong_slot, &source, &linked, &body).is_err());
            let mut dynamic = Elf::parse(&image).unwrap();
            dynamic.program_headers[1].p_type = program_header::PT_DYNAMIC;
            assert!(
                join_relocated_body(
                    &dynamic,
                    &image,
                    v["address"].as_u64().unwrap(),
                    &hex(v["input_hex"].as_str().unwrap()),
                    &body,
                    &source,
                    &linked
                )
                .is_err()
            );
        }
    }
    #[test]
    fn pc32_refuses_truncation_at_both_extremes() {
        assert!(checked_pc32(u64::MAX, 0, 0).is_err());
        assert!(checked_pc32(0, -4, u64::MAX).is_err());
        assert_eq!(
            checked_pc32(0x1000, -4, 0x2000).unwrap(),
            (-0x1004i32).to_le_bytes()
        );
    }
    fn table_image() -> Vec<u8> {
        // A real parsed ELF header and raw sections/symbol/RELA records.
        // One null symbol, one zero-name symbol; one four-byte PC32 record.
        let mut b = vec![0u8; 1024];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, width, n) in [
            (16, 2, 1),
            (18, 2, 62),
            (20, 4, 1),
            (40, 8, 512),
            (52, 2, 64),
            (58, 2, 64),
            (60, 2, 5),
        ] {
            put(&mut b, at, width, n);
        }
        // Section indices: 1=strtab,2=symtab,3=body,4=RELA.
        for (index, kind, off, len, link, info, entry) in [
            (1, 3, 128, 1, 0, 0, 0),
            (2, 2, 160, 48, 1, 1, 24),
            (3, 1, 256, 64, 0, 0, 0),
            (4, 4, 320, 24, 2, 3, 24),
        ] {
            let h = 512 + index * 64;
            for (at, width, n) in [
                (4, 4, kind),
                (24, 8, off),
                (32, 8, len),
                (40, 4, link),
                (44, 4, info),
                (48, 8, 8),
                (56, 8, entry),
            ] {
                put(&mut b, h + at, width, n);
            }
        }
        put(&mut b, 320, 8, 12);
        put(&mut b, 328, 8, (1u64 << 32) | 2);
        b
    }
    #[test]
    fn actual_elf_table_ownership_and_crossing_width_controls() {
        let bytes = table_image();
        let elf = Elf::parse(&bytes).unwrap();
        let table = checked_symtab(&elf, &bytes).unwrap();
        checked_relocation_inventory(&elf, &bytes, table).unwrap();
        let rs = &elf.section_headers[4];
        assert_eq!(checked_relocation_span(&elf, rs, 60, 2).unwrap(), Some(4));
        assert!(checked_relocation_span(&elf, rs, 61, 2).is_err());
        assert!(checked_relocation_span(&elf, rs, 60, 1).is_err());
        assert_eq!(relocation_width(36), Some(16));
        assert_eq!(relocation_width(0xffff), None);
        // The 4-byte field at 12 ends exactly at prospective body start16;
        // it is NOT an eight-byte field crossing that boundary.
        assert!(!selected_field_overlap(&elf.section_headers[3], 12, 2, 16, 32).unwrap());
        assert!(selected_field_overlap(&elf.section_headers[3], 12, 1, 16, 32).unwrap());
        assert!(selected_field_overlap(&elf.section_headers[3], 12, 0xffff, 16, 32).is_err());
        assert!(!selected_field_overlap(&elf.section_headers[3], 32, 2, 16, 32).unwrap());
        for (offset, width, value) in [
            (512 + 4 * 64 + 40, 4, 1),    // relocation sh_link to STRTAB
            (512 + 4 * 64 + 44, 4, 0),    // absent target section
            (512 + 4 * 64 + 44, 4, 1),    // numerically borrowed record in wrong target section
            (512 + 4 * 64 + 56, 8, 16),   // wrong record width
            (512 + 4 * 64 + 32, 8, 23),   // partial record
            (512 + 4 * 64 + 24, 8, 1016), // record crosses file end
            (512 + 2 * 64 + 40, 4, 3),    // SYMTAB sh_link to body
            (512 + 2 * 64 + 56, 8, 16),   // wrong symbol record width
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, offset, width, value);
            let refused = match Elf::parse(&bad) {
                Err(_) => true,
                Ok(e) => checked_symtab(&e, &bad)
                    .and_then(|t| checked_relocation_inventory(&e, &bad, t))
                    .is_err(),
            };
            assert!(refused, "raw table mutation was accepted at {offset}");
        }
        // A declared target section may be valid but cannot lend its records
        // to another section merely because the numeric r_offset overlaps.
        let mut final_elf = Elf::parse(&bytes).unwrap();
        final_elf.header.e_type = header::ET_EXEC;
        final_elf.section_headers[3].sh_addr = 0x1000;
        assert!(checked_relocation_span(&final_elf, &final_elf.section_headers[4], 12, 2).is_err());
    }

    fn actual_property_only_member() -> Vec<u8> {
        // Actual private July12 libc.a __invtrigl.lo ordinal521/header2759394,
        // identical to ceill.lo526, expm1l.lo529 and truncl.lo553.
        // SHA256 d0699f19b13402a97c7b9412ce6456664035926121fdb3b54920e94cc3efcd2e.
        hex(concat!(
            "7f454c4602010100000000000000000001003e000100000000000000000000000000000000000000b000000000000000",
            "00000000400000000000400007000600040000002000000005000000474e5500020001c0040000000000000000000000",
            "010001c0040000000100000000000000002e7368737472746162002e74657874002e64617461002e627373002e6e6f74",
            "652e676e752e70726f7065727479002e6e6f74652e474e552d737461636b000000000000000000000000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0b0000000100000006000000000000000000000000000000400000000000000000000000000000000000000000000000",
            "010000000000000000000000000000001100000001000000030000000000000000000000000000004000000000000000",
            "000000000000000000000000000000000100000000000000000000000000000017000000080000000300000000000000",
            "000000000000000040000000000000000000000000000000000000000000000001000000000000000000000000000000",
            "1c0000000700000002000000000000000000000000000000400000000000000030000000000000000000000000000000",
            "080000000000000000000000000000002f00000001000000000000000000000000000000000000007000000000000000",
            "000000000000000000000000000000000100000000000000000000000000000001000000030000000000000000000000",
            "000000000000000070000000000000003f00000000000000000000000000000001000000000000000000000000000000",
        ))
    }
    #[test]
    fn actual_symbol_less_metadata_is_not_definition_authority() {
        let bytes = actual_property_only_member();
        let elf = Elf::parse(&bytes).unwrap();
        assert_eq!(
            checked_symtab(&elf, &bytes).unwrap_err(),
            "initializer needs unique full symbol table"
        );
        checked_object_symbol_authority(&elf, &bytes).unwrap();
        assert!(elf.syms.is_empty() && elf.shdr_relocs.is_empty());
        assert!(elf.section_headers.iter().all(|s| s.sh_size == 0
            || s.sh_type == section_header::SHT_NOTE
            || s.sh_type == section_header::SHT_STRTAB));
    }
    #[test]
    fn symbol_less_metadata_refuses_code_data_relocations_and_any_byte_change() {
        let bytes = actual_property_only_member();
        for (section, field, width, value) in [
            (1, 32, 8, 1), // allocated code bytes
            (2, 32, 8, 1), // allocated data bytes
            (3, 32, 8, 1), // nonzero BSS
            (1, 4, 4, 4),  // even an empty RELA table needs real symbol authority
            (1, 4, 4, 9),  // implicit REL remains refused
            (1, 4, 4, 11), // DYNSYM is not a substitute full symbol table
            (4, 8, 8, 3),  // writable GNU metadata is not this inert shape
        ] {
            let mut bad = bytes.clone();
            put(&mut bad, 176 + section * 64 + field, width, value);
            let refused = match Elf::parse(&bad) {
                Ok(elf) => checked_object_symbol_authority(&elf, &bad).is_err(),
                Err(_) => true,
            };
            assert!(
                refused,
                "symbol-less authority mutation accepted: {section}/{field}"
            );
        }
        // Covers ELF/header extent, all note/property bytes, strings, padding
        // and every section-header byte; no unchecked payload can enter here.
        for at in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            let refused = match Elf::parse(&bad) {
                Ok(elf) => checked_object_symbol_authority(&elf, &bad).is_err(),
                Err(_) => true,
            };
            assert!(refused, "inert metadata byte mutation accepted at {at}");
        }
    }
    #[test]
    fn symbolic_objects_keep_unique_full_table_requirement() {
        let bytes = table_image();
        let elf = Elf::parse(&bytes).unwrap();
        checked_object_symbol_authority(&elf, &bytes).unwrap();
        let mut duplicate = Elf::parse(&bytes).unwrap();
        duplicate.section_headers[3].sh_type = section_header::SHT_SYMTAB;
        assert_eq!(
            checked_object_symbol_authority(&duplicate, &bytes).unwrap_err(),
            "initializer needs unique full symbol table"
        );
        let mut missing = bytes.clone();
        put(&mut missing, 512 + 2 * 64 + 4, 4, 0);
        let missing = Elf::parse(&missing).unwrap();
        assert!(checked_object_symbol_authority(&missing, &bytes).is_err());
        assert!(checked_symtab(&missing, &bytes).is_err());
    }

    const ACTUAL_LIBC_COMMON: &[u8] = &include!("../../tests/fixtures/musl_libc_common_member.rs");
    const ACTUAL_LIBC_COMMON_MAP: &str =
        include_str!("../../tests/fixtures/musl_libc_common_map.txt");
    fn common_pair_object(bytes: &[u8]) -> ObjectInput<'_> {
        ObjectInput {
            archive_path: Path::new("/bound/libc.a"),
            member_name: "libc.lo",
            ordinal: 171,
            header_offset: 867642,
            bytes,
            elf: Elf::parse(bytes).unwrap(),
        }
    }
    // Synthetic parser geometry carrying actual final symbol addresses, sizes,
    // binding and BSS shape; not a source-owner or linked-image capability.
    fn common_pair_image() -> Vec<u8> {
        let mut b = vec![0; 0x3000];
        b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        for (at, width, n) in [
            (16, 2, 2),
            (18, 2, 62),
            (20, 4, 1),
            (32, 8, 64),
            (40, 8, 0x2000),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 2),
            (58, 2, 64),
            (60, 2, 4),
        ] {
            put(&mut b, at, width, n);
        }
        for (i, flags, off, addr, filesz, memsz) in [
            (0, 4, 0, 0x6000e1000000, 0x3000, 0x3000),
            (1, 6, 0x3000, 0x6000e5af8000, 0, 4096),
        ] {
            let h = 64 + i * 56;
            for (at, width, n) in [
                (0, 4, 1),
                (4, 4, flags),
                (8, 8, off),
                (16, 8, addr),
                (24, 8, addr),
                (32, 8, filesz),
                (40, 8, memsz),
                (48, 8, 4096),
            ] {
                put(&mut b, h + at, width, n);
            }
        }
        let names = b"\0__libc\0__hwcap\0";
        b[0x2300..0x2300 + names.len()].copy_from_slice(names);
        for (i, kind, flags, addr, off, size, link, info, align, entsize) in [
            (1, 3, 0, 0, 0x2300, names.len() as u64, 0, 0, 1, 0),
            (2, 2, 0, 0, 0x2400, 72, 1, 3, 8, 24),
            (3, 8, 3, 0x6000e5af8000, 0x3000, 4096, 0, 0, 32, 0),
        ] {
            let h = 0x2000 + i * 64;
            for (at, width, n) in [
                (4, 4, kind),
                (8, 8, flags),
                (16, 8, addr),
                (24, 8, off),
                (32, 8, size),
                (40, 4, link),
                (44, 4, info),
                (48, 8, align),
                (56, 8, entsize),
            ] {
                put(&mut b, h + at, width, n);
            }
        }
        for (i, name, address, size) in [(1, 1, 0x6000e5af8520, 104), (2, 8, 0x6000e5af85a8, 8)] {
            let at = 0x2400 + i * 24;
            put(&mut b, at, 4, name);
            b[at + 4] = 1;
            b[at + 5] = 2;
            put(&mut b, at + 6, 2, 3);
            put(&mut b, at + 8, 8, address);
            put(&mut b, at + 16, 8, size);
        }
        b
    }
    fn check_common_pair(map: &str, image: &[u8], symbol_index: usize) -> Result<u64> {
        let source = common_pair_object(ACTUAL_LIBC_COMMON);
        let symbol = source.elf.syms.get(symbol_index).unwrap();
        mapped_relocation_definition(
            map,
            &source,
            &symbol,
            &Elf::parse(image).map_err(|e| e.to_string())?,
            image,
        )
    }
    #[test]
    fn actual_two_common_native_member_joins_separate_named_allocations() {
        assert_eq!(
            sha256(ACTUAL_LIBC_COMMON),
            "c9b3acc6ec4f5a5c1652e93cf9b35121fa860d37de27df9d228528020a6fdad2"
        );
        let source = common_pair_object(ACTUAL_LIBC_COMMON);
        let symbol = source.elf.syms.get(7).unwrap();
        assert_eq!(
            mapped_common(ACTUAL_LIBC_COMMON_MAP, &source, &symbol).unwrap_err(),
            "initializer ambiguous COMMON allocation"
        );
        let image = common_pair_image();
        assert_eq!(
            check_common_pair(ACTUAL_LIBC_COMMON_MAP, &image, 7).unwrap(),
            0x6000e5af8520
        );
        assert_eq!(
            check_common_pair(ACTUAL_LIBC_COMMON_MAP, &image, 6).unwrap(),
            0x6000e5af85a8
        );
        // Final/map addresses are joined, not hardcoded to the observed cohort.
        let shifted = ACTUAL_LIBC_COMMON_MAP.replace("6000e5af8520", "6000e5af8500");
        let mut moved = image.clone();
        put(&mut moved, 0x2418 + 8, 8, 0x6000e5af8500);
        assert_eq!(
            check_common_pair(&shifted, &moved, 7).unwrap(),
            0x6000e5af8500
        );
    }
    #[test]
    fn paired_common_refuses_missing_duplicate_wrong_name_overlap_and_packing() {
        let image = common_pair_image();
        let lines = ACTUAL_LIBC_COMMON_MAP.lines().collect::<Vec<_>>();
        let wrong = [
            String::new(),
            lines[..2].join("\n"),
            ACTUAL_LIBC_COMMON_MAP.repeat(2),
            ACTUAL_LIBC_COMMON_MAP.replace("__libc", "unknown"),
            ACTUAL_LIBC_COMMON_MAP.replace("__hwcap", "__libc"),
            ACTUAL_LIBC_COMMON_MAP.replace("6000e5af85a8", "6000e5af8520"),
            ACTUAL_LIBC_COMMON_MAP.replace("libc.lo", "foreign.lo"),
            ACTUAL_LIBC_COMMON_MAP.replace("       68    32", "       70    32"),
            ACTUAL_LIBC_COMMON_MAP.replace("6000e5af8520", "6000e5af8521"),
            format!("{}\n{}\n{}\n", lines[0], lines[1], lines[3]), // one packed/coalesced owner row
            format!(
                "{}\n{}\n{}\n{}\n{}\n",
                lines[0], lines[1], lines[1], lines[2], lines[3]
            ),
        ];
        for map in wrong {
            assert!(check_common_pair(&map, &image, 7).is_err(), "{map}");
        }
        let hidden_extra = format!(
            "{}\n{}\nmalformed\n{}\n{}\n{}\n",
            lines[0], lines[1], lines[1], lines[2], lines[3]
        );
        assert_eq!(
            check_common_pair(&hidden_extra, &image, 7).unwrap_err(),
            "paired COMMON allocation boundary row malformed"
        );
    }
    #[test]
    fn paired_common_final_definition_and_zero_backing_are_mandatory() {
        let image = common_pair_image();
        for (at, width, n) in [
            (0x2418 + 6, 2, 0),               // missing final definition
            (0x2418 + 4, 1, 0x11),            // wrong final binding
            (0x2418 + 5, 1, 0),               // visibility
            (0x2418 + 16, 8, 103),            // size
            (0x2418 + 8, 8, 0x6000e5af8540),  // address
            (0x2430, 4, 1),                   // duplicate named final definition
            (0x2000 + 3 * 64 + 4, 4, 1),      // file-backed section
            (0x2000 + 3 * 64 + 8, 8, 7),      // executable/writable section
            (0x2000 + 3 * 64 + 32, 8, 0x520), // section ends before object end
            (64 + 56 + 4, 4, 7),              // executable load
            (64 + 56 + 32, 8, 0x530),         // file backing reaches first object
            (64 + 56 + 40, 8, 0x580),         // load cannot cover both objects
        ] {
            let mut bad = image.clone();
            put(&mut bad, at, width, n);
            assert!(
                check_common_pair(ACTUAL_LIBC_COMMON_MAP, &bad, 7).is_err(),
                "offset {at:x}"
            );
        }
        // A file-backed span entirely inside the file/load bounds must still
        // refuse: the actual COMMON storage is required to start zero-backed.
        let mut backed = image.clone();
        put(&mut backed, 64 + 56 + 8, 8, 0x2000);
        put(&mut backed, 64 + 56 + 32, 8, 0x530);
        assert!(check_common_pair(ACTUAL_LIBC_COMMON_MAP, &backed, 7).is_err());
    }
    #[test]
    fn paired_common_requires_exact_physical_native_declarations() {
        let image = common_pair_image();
        let final_elf = Elf::parse(&image).unwrap();
        for bad in ["name", "ordinal", "header", "source"] {
            let mut bytes = ACTUAL_LIBC_COMMON.to_vec();
            if bad == "source" {
                bytes[64] ^= 1;
            }
            let mut source = common_pair_object(&bytes);
            match bad {
                "name" => source.member_name = "not-libc.lo",
                "ordinal" => source.ordinal += 1,
                "header" => source.header_offset += 2,
                _ => {}
            }
            let symbol = source.elf.syms.get(7).unwrap();
            assert!(
                mapped_relocation_definition(
                    ACTUAL_LIBC_COMMON_MAP,
                    &source,
                    &symbol,
                    &final_elf,
                    &image
                )
                .is_err()
            );
        }
        // The exact selected declaration is checked too; no arbitrary target can
        // borrow either real allocation just by supplying a same-named symbol.
        let source = common_pair_object(ACTUAL_LIBC_COMMON);
        let mut symbol = source.elf.syms.get(7).unwrap();
        symbol.st_value = 8;
        assert!(
            mapped_relocation_definition(
                ACTUAL_LIBC_COMMON_MAP,
                &source,
                &symbol,
                &final_elf,
                &image
            )
            .is_err()
        );
    }
    #[test]
    fn singleton_common_mapping_keeps_its_original_support_and_refusals() {
        let mut bytes = table_image();
        put(
            &mut bytes,
            160 + 24 + 6,
            2,
            section_header::SHN_COMMON as u64,
        );
        put(&mut bytes, 160 + 24 + 8, 8, 8);
        put(&mut bytes, 160 + 24 + 16, 8, 8);
        let source = ObjectInput {
            archive_path: Path::new("/bound/libc.a"),
            member_name: "guard.lo",
            ordinal: 0,
            header_offset: 0,
            bytes: &bytes,
            elf: Elf::parse(&bytes).unwrap(),
        };
        let symbol = source.elf.syms.get(1).unwrap();
        let map = "2000 2000 8 8 /bound/libc.a(guard.lo):(COMMON)\n";
        let image = common_pair_image();
        let final_elf = Elf::parse(&image).unwrap();
        assert_eq!(
            mapped_relocation_definition(map, &source, &symbol, &final_elf, &image).unwrap(),
            0x2000
        );
        for wrong in [
            String::new(),
            map.repeat(2),
            map.replace("8 8", "8 4"),
            map.replace("2000", "2001"),
        ] {
            assert!(
                mapped_relocation_definition(&wrong, &source, &symbol, &final_elf, &image).is_err()
            );
        }
    }
}

// Private finite optional-use observation. This module does not participate in
// generic undefined-symbol rejection or construct an executable capability.
mod optional_zero {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum Role {
        Gettid,
        Cxa,
        Dynamic,
    }
    impl Role {
        fn name(self) -> &'static str {
            match self {
                Self::Gettid => "gettid",
                Self::Cxa => "__cxa_thread_atexit_impl",
                Self::Dynamic => "_DYNAMIC",
            }
        }
        fn from_name(name: &str) -> Option<Self> {
            [Self::Gettid, Self::Cxa, Self::Dynamic]
                .into_iter()
                .find(|r| r.name() == name)
        }
    }

    // No caller can supply these records through the public observation API.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Use {
        role: Role,
        place: u64,
        addend: i64,
        object: usize,
        section: usize,
        offset: u64,
    }
    struct Owner {
        object: usize,
        section: usize,
        input_start: u64,
        start: u64,
        size: u64,
        role: Role,
        uses: Vec<Use>,
    }
    #[derive(Debug)]
    struct Guard {
        begin: usize,
        branch: usize,
        zero: usize,
        consumers: BTreeSet<usize>,
        // Each window is a complete instruction interval; unrelated TLS
        // relaxation bytes between windows are not compared or masked.
        windows: Vec<(usize, usize)>,
    }
    #[derive(Debug)]
    struct ClosedGuard {
        role: Role,
        owner: u64,
        slot: u64,
        uses: usize,
        windows: usize,
    }

    /// Observations only, without a constructor or executable conversion.
    #[derive(Debug)]
    pub struct OptionalZeroObservation {
        source_owner: DefinitionSourceOwner,
        core: DefinitionCore,
        guards: Vec<ClosedGuard>,
        selected_uses: usize,
        unselected_input_uses: usize,
        files: Vec<FileIdentity>,
    }
    impl OptionalZeroObservation {
        /// No source-machine/pre-FS/Ready claim is implied by this count.
        pub fn selected_use_count(&self) -> usize {
            self.selected_uses
        }
        /// Exact unselected archive uses were seen but did not survive selection.
        pub fn unselected_input_use_count(&self) -> usize {
            self.unselected_input_uses
        }
        /// Recheck the actual files retained through the source close.
        pub fn verify(&self) -> Result<()> {
            self.core.require_ledger(&self.files)?;
            require(self.guards.len() == 3, "optional role census incomplete")?;
            require(
                self.guards.iter().map(|g| g.uses).sum::<usize>() == self.selected_uses,
                "optional closed-use census differs",
            )?;
            let mut roles = BTreeSet::new();
            for guard in &self.guards {
                require(
                    roles.insert(guard.role)
                        && guard.owner != 0
                        && guard.slot != 0
                        && guard.uses > 0
                        && guard.windows > 0,
                    "optional observation incomplete",
                )?;
            }
            close_files(&self.files)
        }
        pub(super) fn require_owner(
            &self,
            source: &Arc<ArchiveSourceOwner>,
            runtime: &FileIdentity,
        ) -> Result<()> {
            require(
                Arc::ptr_eq(source, &self.source_owner.0),
                "optional final inspection belongs to another source transaction",
            )?;
            self.core.require_ledger(&self.files)?;
            require(
                self.core.runtime == *runtime,
                "optional final runtime archive differs",
            )
        }
        pub(super) fn require_artifact(&self, artifact: &FileIdentity) -> Result<()> {
            require(
                self.core.artifact == *artifact,
                "optional final artifact differs",
            )
        }
        pub(super) fn require_final_rows(&self, elf: &Elf<'_>, bytes: &[u8]) -> Result<()> {
            self.core.require_ledger(&self.files)?;
            require(
                sha256(bytes) == self.core.artifact.sha256,
                "optional final artifact bytes differ",
            )?;
            let actual = final_undefined_rows(elf)?;
            require(
                actual.keys().copied().collect::<BTreeSet<_>>()
                    == self
                        .guards
                        .iter()
                        .map(|guard| guard.role)
                        .collect::<BTreeSet<_>>(),
                "optional final observed role set differs",
            )
        }
    }

    fn bind_expected(
        files: &mut Vec<FileIdentity>,
        path: &Path,
        expected: &str,
    ) -> Result<FileIdentity> {
        let file = FileIdentity::read(path)?;
        files.push(file.clone());
        require(
            file.sha256 == expected,
            "optional exact tool/source input differs",
        )?;
        Ok(file)
    }
    fn close_files(files: &[FileIdentity]) -> Result<()> {
        let errors = files
            .iter()
            .filter_map(|f| f.verify().err())
            .collect::<Vec<_>>();
        require(errors.is_empty(), errors.join("; "))
    }
    fn combine<T>(body: Result<T>, close: Result<()>) -> Result<T> {
        match (body, close) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Err(e), Err(c)) => Err(format!("{e}; optional close: {c}")),
        }
    }

    // This is the one finite final-symbol classifier. It is not a public
    // name exception: only a successful same-owner observation may use it at
    // the explicit final-inspection boundary. All final uses are separately
    // joined by enumerate before that observation can be constructed.
    fn final_undefined_rows(elf: &Elf<'_>) -> Result<BTreeMap<Role, usize>> {
        let mut undefined = BTreeMap::new();
        for (index, s) in elf.syms.iter().enumerate().filter(|(_, s)| s.st_shndx == 0) {
            let name = elf.strtab.get_at(s.st_name).ok_or("optional final name")?;
            if s.st_name == 0 {
                continue;
            }
            require(
                !name.is_empty(),
                "optional final undefined has empty nonzero name",
            )?;
            let role = Role::from_name(name).ok_or("unclassified final undefined reference")?;
            require(
                s.st_value == 0
                    && s.st_size == 0
                    && s.st_type() == sym::STT_NOTYPE
                    && match role {
                        Role::Dynamic => {
                            s.st_visibility() == sym::STV_HIDDEN
                                && matches!(s.st_bind(), sym::STB_LOCAL | sym::STB_WEAK)
                        }
                        _ => s.st_bind() == sym::STB_WEAK && s.st_visibility() == sym::STV_DEFAULT,
                    },
                "optional final undefined binding/type differs",
            )?;
            require(
                undefined.insert(role, index).is_none(),
                "duplicate final optional symbol",
            )?;
        }
        require(
            undefined.len() == 3,
            "optional final undefined role set differs",
        )?;
        Ok(undefined)
    }

    // All symbolic uses in all tables are checked, then projected through the
    // actual live input-section map. A discarded section is not a final use.
    fn enumerate(
        objects: &[ObjectInput<'_>],
        map: &str,
        elf: &Elf<'_>,
        bytes: &[u8],
    ) -> Result<(Vec<Use>, usize)> {
        static_image_metadata(elf, bytes)?;
        let table = checked_symtab(elf, bytes)?;
        checked_relocation_inventory(elf, bytes, table)?;
        let undefined = final_undefined_rows(elf)?;
        let mut final_uses = BTreeSet::new();
        for (index, rows) in &elf.shdr_relocs {
            let rs = checked_relocation_section(elf, bytes, *index, table, rows.len())?;
            for r in rows.iter() {
                if let Some((&role, _)) = undefined.iter().find(|(_, symbol)| **symbol == r.r_sym) {
                    require(
                        r.r_type == reloc::R_X86_64_GOTPCREL
                            && elf.section_headers[rs.sh_info as usize].sh_flags
                                & section_header::SHF_ALLOC as u64
                                != 0,
                        "optional final use is not allocated GOTPCREL",
                    )?;
                    require(
                        final_uses.insert((
                            role,
                            r.r_offset,
                            r.r_addend.ok_or("optional final addend")?,
                        )),
                        "duplicate final optional use",
                    )?;
                }
            }
        }
        let mut selected = Vec::new();
        let mut dead = 0usize;
        let mut input_uses = BTreeSet::new();
        for (object_index, object) in objects.iter().enumerate() {
            checked_object_symbol_authority(&object.elf, object.bytes)?;
            if object.elf.syms.is_empty() {
                continue;
            }
            let st = checked_symtab(&object.elf, object.bytes)?;
            checked_relocation_inventory(&object.elf, object.bytes, st)?;
            for (index, rows) in &object.elf.shdr_relocs {
                let rs =
                    checked_relocation_section(&object.elf, object.bytes, *index, st, rows.len())?;
                for r in rows.iter() {
                    let symbol = object
                        .elf
                        .syms
                        .get(r.r_sym)
                        .ok_or("optional input symbol")?;
                    let name = object
                        .elf
                        .strtab
                        .get_at(symbol.st_name)
                        .ok_or("optional input name")?;
                    let Some(role) = Role::from_name(name) else {
                        continue;
                    };
                    let section = rs.sh_info as usize;
                    let sh = &object.elf.section_headers[section];
                    let name = object
                        .elf
                        .shdr_strtab
                        .get_at(sh.sh_name)
                        .ok_or("optional section name")?;
                    let suffix = format!(
                        "{}({}):({})",
                        object.archive_path.display(),
                        object.member_name,
                        name
                    );
                    if !map.lines().any(|line| line.trim_end().ends_with(&suffix)) {
                        dead = dead.checked_add(1).ok_or("optional dead count overflow")?;
                        continue;
                    }
                    require(
                        symbol.st_shndx == 0
                            && symbol.st_value == 0
                            && symbol.st_size == 0
                            && symbol.st_bind() == sym::STB_WEAK
                            && symbol.st_type() == sym::STT_NOTYPE
                            && symbol.st_visibility()
                                == if role == Role::Dynamic {
                                    sym::STV_HIDDEN
                                } else {
                                    sym::STV_DEFAULT
                                }
                            && r.r_type == reloc::R_X86_64_GOTPCREL
                            && sh.sh_flags == 6,
                        "selected optional input is not exact weak RX GOTPCREL origin",
                    )?;
                    let place = mapped_section(map, object, section)?
                        .checked_add(r.r_offset)
                        .ok_or("optional input placement overflow")?;
                    let addend = r.r_addend.ok_or("optional input addend")?;
                    require(
                        input_uses.insert((role, place, addend)),
                        "duplicate selected optional use",
                    )?;
                    selected.push(Use {
                        role,
                        place,
                        addend,
                        object: object_index,
                        section,
                        offset: r.r_offset,
                    });
                }
            }
        }
        require(
            input_uses == final_uses && !selected.is_empty(),
            "optional input/final use census differs",
        )?;
        Ok((selected, dead))
    }

    fn owners(
        objects: &[ObjectInput<'_>],
        map: &str,
        elf: &Elf<'_>,
        uses: &[Use],
    ) -> Result<Vec<Owner>> {
        let mut result: Vec<Owner> = Vec::new();
        for u in uses {
            let object = &objects[u.object];
            let candidates = object
                .elf
                .syms
                .iter()
                .filter(|s| {
                    s.st_shndx == u.section
                        && s.st_type() == sym::STT_FUNC
                        && s.st_size > 0
                        && s.st_value <= u.offset
                        && s.st_value
                            .checked_add(s.st_size)
                            .is_some_and(|end| u.offset.checked_add(4).is_some_and(|v| v <= end))
                })
                .collect::<Vec<_>>();
            require(!candidates.is_empty(), "optional input owner absent")?;
            let first = &candidates[0];
            require(
                candidates
                    .iter()
                    .all(|s| s.st_value == first.st_value && s.st_size == first.st_size),
                "optional input owner aliases/extent disagree",
            )?;
            let start = mapped_definition(map, object, first)?;
            let ranges = selected_function_ranges(elf, BTreeSet::from([start]))?;
            require(
                ranges[&start] == first.st_size && first.st_size <= 1024 * 1024,
                "optional final owner extent differs/exceeds bound",
            )?;
            let end = start
                .checked_add(first.st_size)
                .ok_or("optional owner end")?;
            require(
                !elf.syms.iter().any(|s| {
                    s.st_type() == sym::STT_FUNC && s.st_value > start && s.st_value < end
                }),
                "optional owner has an interior function entry",
            )?;
            if let Some(owner) = result.iter_mut().find(|o| o.start == start) {
                require(
                    owner.object == u.object
                        && owner.section == u.section
                        && owner.input_start == first.st_value
                        && owner.role == u.role,
                    "optional owner identity differs",
                )?;
                owner.uses.push(u.clone());
            } else {
                result.push(Owner {
                    object: u.object,
                    section: u.section,
                    input_start: first.st_value,
                    start,
                    size: first.st_size,
                    role: u.role,
                    uses: vec![u.clone()],
                });
            }
        }
        require(result.len() == 3, "optional complete owner census differs")?;
        Ok(result)
    }

    fn relative(i: &EncodedConstructorInstruction, at: usize, width: usize) -> Result<u64> {
        let displacement = match width {
            1 => i64::from(*i.bytes.get(at).ok_or("optional branch byte")? as i8),
            4 => i64::from(i32::from_le_bytes(
                i.bytes
                    .get(at..at + 4)
                    .ok_or("optional branch width")?
                    .try_into()
                    .map_err(|_| "optional branch width")?,
            )),
            _ => return Err("optional branch width unsupported".into()),
        };
        i.address
            .checked_add(i.bytes.len() as u64)
            .and_then(|v| v.checked_add_signed(displacement))
            .ok_or_else(|| "optional branch address overflow".into())
    }
    fn rip_slot(i: &EncodedConstructorInstruction, at: usize) -> Result<u64> {
        relative(i, at, 4)
    }
    fn position(code: &[EncodedConstructorInstruction], address: u64) -> Result<usize> {
        code.iter()
            .position(|i| i.address == address)
            .ok_or_else(|| "optional target is not an instruction boundary".into())
    }
    fn next_address(i: &EncodedConstructorInstruction) -> Result<u64> {
        i.address
            .checked_add(i.bytes.len() as u64)
            .ok_or_else(|| "optional instruction end overflow".into())
    }

    // Instruction boundaries and encodings come from the existing bound
    // disassembler + exact ELF verifier. This only classifies local transfers;
    // it is not another decoder and never finds an instruction by byte scan.
    fn cfg(code: &[EncodedConstructorInstruction], guard: &Guard) -> Result<Vec<Vec<usize>>> {
        let (start, boundaries) = preparation_instruction_boundaries(code)?;
        require(code.len() <= 262144, "optional CFG instruction budget")?;
        let end = next_address(code.last().ok_or("optional empty owner")?)?;
        let mut result = Vec::new();
        for (index, i) in code.iter().enumerate() {
            let b = &i.bytes;
            let prefix = b
                .iter()
                .take_while(|b| {
                    matches!(
                        **b,
                        0xf0 | 0xf2
                            | 0xf3
                            | 0x26
                            | 0x2e
                            | 0x36
                            | 0x3e
                            | 0x64
                            | 0x65
                            | 0x66
                            | 0x67
                            | 0x40..=0x4f
                    )
                })
                .count();
            let op = *b.get(prefix).ok_or("optional prefix-only instruction")?;
            let mut successors = Vec::new();
            let fall = |out: &mut Vec<usize>| {
                if index + 1 < code.len() {
                    out.push(index + 1);
                }
            };
            match op {
                0xc3 | 0xc2 => {}
                0xe8 => {
                    require(
                        prefix == 0 && b.len() == 5,
                        "optional unsupported CALL form",
                    )?;
                    fall(&mut successors);
                }
                0xe9 | 0xeb | 0x70..=0x7f | 0xe0..=0xe3 => {
                    require(prefix == 0, "optional prefixed branch unsupported")?;
                    let width = if op == 0xe9 { 4 } else { 1 };
                    require(b.len() == 1 + width, "optional branch width differs")?;
                    let target = relative(i, 1, width)?;
                    if boundaries.contains(&target) {
                        successors.push(position(code, target)?);
                    } else {
                        require(
                            matches!(op, 0xe9 | 0xeb) && !(start..end).contains(&target),
                            "optional conditional/interior branch escapes",
                        )?;
                    }
                    if !matches!(op, 0xe9 | 0xeb) {
                        fall(&mut successors);
                    }
                }
                0x0f if b
                    .get(prefix + 1)
                    .is_some_and(|op| (0x80..=0x8f).contains(op)) =>
                {
                    require(prefix == 0 && b.len() == 6, "optional near condition form")?;
                    successors.push(position(code, relative(i, 2, 4)?)?);
                    fall(&mut successors);
                }
                0xff => {
                    let group = (b.get(prefix + 1).ok_or("optional FF missing ModRM")? >> 3) & 7;
                    match group {
                        2 => fall(&mut successors), // trusted ordinary ABI CALL/return
                        4 => require(
                            guard.consumers.contains(&index),
                            "unknown optional-relevant indirect tail edge",
                        )?,
                        3 | 5 => return Err("optional far transfer unsupported".into()),
                        _ => fall(&mut successors),
                    }
                }
                0xc7 if b.get(prefix + 1) == Some(&0xf8) => {
                    return Err("optional XBEGIN edge unsupported".into());
                }
                0xc6 if b.get(prefix + 1) == Some(&0xf8) => {
                    return Err("optional XABORT edge unsupported".into());
                }
                0x0f if b.get(prefix + 1) == Some(&0x01)
                    && b.get(prefix + 2)
                        .is_some_and(|v| matches!(*v, 0xc1..=0xc3 | 0xd9)) =>
                {
                    return Err("optional VM/system edge unsupported".into());
                }
                0x9a | 0xea | 0xca | 0xcb | 0xcf | 0xcc | 0xcd | 0xce | 0xf1 | 0xf4 => {
                    return Err("optional exceptional/far transfer unsupported".into());
                }
                0x0f if matches!(
                    b.get(prefix + 1),
                    Some(0x05 | 0x07 | 0x34 | 0x35 | 0x37 | 0xaa)
                ) =>
                {
                    return Err("optional system transfer unsupported".into());
                }
                0x0f if b.get(prefix + 1) == Some(&0x0b) => {} // UD2 terminates; cannot bypass guard
                _ => fall(&mut successors),
            }
            result.push(successors);
        }
        Ok(result)
    }
    fn reachable(
        edges: &[Vec<usize>],
        entries: &[usize],
        omit: Option<usize>,
        zero: Option<(usize, usize)>,
    ) -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut pending = entries.to_vec();
        while let Some(node) = pending.pop() {
            if Some(node) == omit || !seen.insert(node) {
                continue;
            }
            if let Some((_, target)) = zero.filter(|(branch, _)| node == *branch) {
                pending.push(target);
                continue;
            }
            pending.extend(edges[node].iter().copied());
        }
        seen
    }

    fn check_guard(code: &[EncodedConstructorInstruction], guard: &Guard) -> Result<()> {
        require(
            guard.begin < guard.branch && guard.zero < code.len() && !guard.consumers.is_empty(),
            "optional guard structure incomplete",
        )?;
        let edges = cfg(code, guard)?;
        // No potentially unwinding CALL precedes this guard. All later local
        // landing entries are conservatively seeded below. Signal delivery
        // follows the explicit ordinary ABI/context-preservation assumption.
        for i in &code[..guard.begin] {
            let p = i
                .bytes
                .iter()
                .take_while(|b| matches!(**b, 0x40..=0x4f | 0xf2 | 0xf3 | 0x66))
                .count();
            require(
                i.bytes.get(p) != Some(&0xe8)
                    && !(i.bytes.get(p) == Some(&0xff)
                        && i.bytes.get(p + 1).is_some_and(|m| (m >> 3) & 7 == 2)),
                "unproved exception entry before optional guard",
            )?;
        }
        let all = reachable(&edges, &[0], None, None);
        require(
            all.contains(&guard.branch) && guard.consumers.iter().all(|c| all.contains(c)),
            "optional guard/use is unreachable",
        )?;
        let bypass = reachable(&edges, &[0], Some(guard.begin), None);
        require(
            !bypass.contains(&guard.branch) && guard.consumers.is_disjoint(&bypass),
            "optional load guard does not dominate use",
        )?;
        // No local edge may enter between load and branch. This also prevents
        // entering a TEST with stale flags/registers instead of the real load.
        for (from, successors) in edges.iter().enumerate() {
            for &to in successors {
                require(
                    !(guard.begin < to && to <= guard.branch) || from + 1 == to,
                    "optional guard has an interior predecessor",
                )?;
            }
        }
        let zero = reachable(&edges, &[0], None, Some((guard.branch, guard.zero)));
        require(
            guard.consumers.is_disjoint(&zero),
            "optional zero path reaches consumption",
        )?;
        // Treat every instruction after the last consumption as a conservative
        // local error/landing entry. Any return to a consumer still needs the
        // same guard. Ordinary calls return normally; arbitrary interior entry
        // by a callee is excluded by the explicit trusted ABI scope assumption.
        let last = *guard
            .consumers
            .iter()
            .next_back()
            .ok_or("optional consumption absent")?;
        let landing_entries = ((last + 1)..code.len()).collect::<Vec<_>>();
        let landing_zero = reachable(
            &edges,
            &landing_entries,
            None,
            Some((guard.branch, guard.zero)),
        );
        require(
            guard.consumers.is_disjoint(&landing_zero),
            "optional later/error entry bypasses zero guard",
        )?;
        Ok(())
    }

    // Account for recorded alternate entries only over the live guard prefix.
    // Later local entries were already conservatively seeded by check_guard.
    // This is not whole-program CFI: ordinary valid ABI entry/return and the
    // separately required source/input contract remain explicit assumptions.
    fn external_guard_entries(
        elf: &Elf<'_>,
        bytes: &[u8],
        owner: &Owner,
        code: &[EncodedConstructorInstruction],
        guard: &Guard,
    ) -> Result<()> {
        let last = *guard
            .consumers
            .iter()
            .next_back()
            .ok_or("optional live interval absent")?;
        let protected_end = next_address(&code[last])?;
        let owner_end = owner
            .start
            .checked_add(owner.size)
            .ok_or("optional owner end")?;
        let interior = |address: u64| owner.start < address && address < protected_end;
        require(
            !elf.syms.iter().any(|s| {
                s.st_shndx != 0 && s.st_type() != sym::STT_SECTION && interior(s.st_value)
            }),
            "optional live guard has a recorded interior symbol entry",
        )?;
        let table = checked_symtab(elf, bytes)?;
        checked_relocation_inventory(elf, bytes, table)?;
        for (index, rows) in &elf.shdr_relocs {
            let rs = checked_relocation_section(elf, bytes, *index, table, rows.len())?;
            let target = &elf.section_headers[rs.sh_info as usize];
            if target.sh_flags & section_header::SHF_ALLOC as u64 == 0 {
                continue;
            }
            for r in rows.iter() {
                if (owner.start..owner_end).contains(&r.r_offset) {
                    continue;
                }
                let symbol = elf.syms.get(r.r_sym).ok_or("optional incoming symbol")?;
                if symbol.st_shndx == 0 {
                    continue;
                }
                let addend = r.r_addend.ok_or("optional incoming addend")?;
                let destination = match r.r_type {
                    reloc::R_X86_64_PC32 | reloc::R_X86_64_PLT32 => {
                        // Executable disp32 uses point after their four-byte
                        // field; data PC-relative encodings (e.g. FDE) do not.
                        let end_bias =
                            if target.sh_flags & section_header::SHF_EXECINSTR as u64 != 0 {
                                4
                            } else {
                                0
                            };
                        Some(i128::from(symbol.st_value) + i128::from(addend) + end_bias)
                    }
                    reloc::R_X86_64_64 | reloc::R_X86_64_32 | reloc::R_X86_64_32S => {
                        Some(i128::from(symbol.st_value) + i128::from(addend))
                    }
                    reloc::R_X86_64_GOTPCREL | 41 | 42 => Some(i128::from(symbol.st_value)),
                    _ => {
                        if let Some(definition) = elf.section_headers.get(symbol.st_shndx) {
                            let end = definition
                                .sh_addr
                                .checked_add(definition.sh_size)
                                .ok_or("incoming definition end")?;
                            require(
                                definition.sh_flags & section_header::SHF_EXECINSTR as u64 == 0
                                    || end <= owner.start
                                    || definition.sh_addr >= protected_end,
                                "unclassified recorded reference to optional live code section",
                            )?;
                        }
                        None
                    }
                };
                if let Some(destination) = destination.and_then(|v| u64::try_from(v).ok()) {
                    require(
                        !interior(destination),
                        "optional live guard has a recorded external entry/address reference",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn recognize(
        role: Role,
        code: &[EncodedConstructorInstruction],
        uses: &[Use],
        slot: u64,
    ) -> Result<Guard> {
        let mut indices = Vec::new();
        for u in uses {
            let mut found = Vec::new();
            for (index, i) in code.iter().enumerate() {
                if i.address <= u.place
                    && u.place
                        .checked_add(4)
                        .is_some_and(|v| next_address(i).is_ok_and(|end| v <= end))
                {
                    found.push(index);
                }
            }
            require(
                found.len() == 1,
                "optional operand crosses/misses decoded instruction",
            )?;
            let instruction = &code[found[0]];
            let field = if instruction.bytes.starts_with(&[0x48, 0x83, 0x3d])
                || instruction.bytes.starts_with(&[0x4c, 0x8b, 0x05])
            {
                3
            } else if instruction.bytes.starts_with(&[0xff, 0x15])
                || instruction.bytes.starts_with(&[0xff, 0x25])
            {
                2
            } else {
                return Err("optional relocation is not the exact guarded operand".into());
            };
            require(
                instruction.address.checked_add(field) == Some(u.place),
                "optional relocation does not designate exact disp32 field",
            )?;
            indices.push(found[0]);
        }
        indices.sort_unstable();
        require(
            indices.windows(2).all(|p| p[0] != p[1]),
            "duplicate optional instruction operand",
        )?;
        let begin = *indices.first().ok_or("optional operand absent")?;
        let b = |i: usize| {
            code.get(i)
                .map(|i| i.bytes.as_slice())
                .ok_or_else(|| "optional guard truncated".to_owned())
        };
        let (branch, consumers, end) = match role {
            Role::Gettid | Role::Cxa => {
                require(
                    indices.len() == 2
                        && b(begin)?.len() == 8
                        && b(begin)?[..3] == [0x48, 0x83, 0x3d]
                        && b(begin)?[7] == 0
                        && rip_slot(&code[begin], 3)? == slot,
                    "optional compare is not exact slot == 0",
                )?;
                let branch = begin + 1;
                require(
                    b(branch)?.len() == 2 && b(branch)?[0] == 0x74,
                    "optional null JE missing",
                )?;
                let consumer = indices[1];
                let expected = if role == Role::Gettid { 0x15 } else { 0x25 };
                require(
                    b(consumer)?.len() == 6
                        && b(consumer)?[..2] == [0xff, expected]
                        && rip_slot(&code[consumer], 2)? == slot,
                    "optional consumer does not use same slot",
                )?;
                if role == Role::Gettid {
                    require(
                        consumer == begin + 2 && b(consumer + 1)?.first() == Some(&0xeb),
                        "gettid nonzero path differs",
                    )?;
                    let fallback = consumer + 2;
                    require(
                        b(fallback)? == [0xbf, 0xba, 0, 0, 0]
                            && b(fallback + 1)? == [0x31, 0xc0]
                            && b(fallback + 2)?.len() == 6
                            && b(fallback + 2)?[..2] == [0xff, 0x15],
                        "gettid raw syscall fallback differs",
                    )?;
                    require(
                        relative(&code[branch], 1, 1)? == code[fallback].address
                            && relative(&code[consumer + 1], 1, 1)?
                                == next_address(&code[fallback + 2])?,
                        "gettid guard/fallback reconvergence differs",
                    )?;
                    (branch, BTreeSet::from([consumer]), fallback + 3)
                } else {
                    require(
                        relative(&code[branch], 1, 1)? == next_address(&code[consumer])?,
                        "cxa zero path does not bypass tailcall",
                    )?;
                    (branch, BTreeSet::from([consumer]), consumer + 1)
                }
            }
            Role::Dynamic => {
                require(
                    indices.len() == 1
                        && b(begin)?.len() == 7
                        && b(begin)?[..3] == [0x4c, 0x8b, 0x05]
                        && rip_slot(&code[begin], 3)? == slot
                        && b(begin + 1)? == [0x4d, 0x85, 0xc0]
                        && b(begin + 2)?.len() == 2
                        && b(begin + 2)?[0] == 0x74
                        && b(begin + 3)? == [0x4c, 0x89, 0xc0]
                        && b(begin + 4)? == [0x48, 0x2b, 0x41, 0x10]
                        && b(begin + 5)?.len() == 2
                        && b(begin + 5)?[0] == 0xeb,
                    "dynamic load/test/guarded subtraction differs",
                )?;
                require(
                    relative(&code[begin + 2], 1, 1)? == relative(&code[begin + 5], 1, 1)?,
                    "dynamic zero/nonzero continuation differs",
                )?;
                (begin + 2, BTreeSet::from([begin + 3, begin + 4]), begin + 6)
            }
        };
        let zero = position(code, relative(&code[branch], 1, 1)?)?;
        let guard = Guard {
            begin,
            branch,
            zero,
            consumers,
            windows: vec![(begin, end)],
        };
        check_guard(code, &guard)?;
        Ok(guard)
    }

    // R8 has no implicit architectural uses in these instructions. Enumerate
    // every explicit mention in the bound decoder output, then track the one
    // optional load until a genuine 32-bit PHDR reload kills it. This prevents
    // an unrelocated register call/store from escaping the null-use census.
    fn dynamic_register_lifetime(
        text: &str,
        code: &[EncodedConstructorInstruction],
        guard: &Guard,
    ) -> Result<()> {
        let mut mentions = BTreeSet::new();
        for line in text.lines() {
            let Some((address, rest)) = line.trim().split_once(':') else {
                continue;
            };
            let Ok(address) = u64::from_str_radix(address, 16) else {
                continue;
            };
            let operands = rest
                .split('#')
                .next()
                .ok_or("dynamic decoder operand text")?;
            if operands.contains("%r8") {
                mentions.insert(position(code, address)?);
            }
        }
        require(
            mentions.contains(&guard.begin)
                && mentions.contains(&(guard.begin + 1))
                && mentions.contains(&(guard.begin + 3)),
            "dynamic decoded R8 uses incomplete",
        )?;
        let edges = cfg(code, guard)?;
        let mut pending = vec![(0usize, false)];
        let mut seen = BTreeSet::new();
        while let Some((node, mut tainted)) = pending.pop() {
            if !seen.insert((node, tainted)) {
                continue;
            }
            if mentions.contains(&node) {
                let b = code[node].bytes.as_slice();
                if node == guard.begin {
                    tainted = true;
                } else if b == [0x44, 0x8b, 0x01] {
                    tainted = false;
                } else if node == guard.begin + 1 {
                    require(
                        tainted,
                        "dynamic TEST not reached through actual pointer load",
                    )?;
                } else if matches!(
                    b,
                    [0x41, 0x83, 0xf8, 0x07] | [0x41, 0x83, 0xf8, 0x06] | [0x41, 0x83, 0xf8, 0x02]
                ) {
                    require(
                        !tainted,
                        "dynamic optional pointer reaches an unguarded PHDR comparison",
                    )?;
                } else {
                    return Err("dynamic optional register has an unclassified use/escape".into());
                }
            }
            if node == guard.branch {
                pending.push((guard.zero, tainted));
            } else {
                pending.extend(edges[node].iter().map(|next| (*next, tainted)));
            }
        }
        // Account for all decoded mentions, including the nonzero arm. The
        // only skipped R8 consumption is the exact already-joined MOV->SUB arm.
        for node in mentions {
            require(
                node == guard.begin
                    || node == guard.begin + 1
                    || node == guard.begin + 3
                    || matches!(
                        code[node].bytes.as_slice(),
                        [0x44, 0x8b, 0x01]
                            | [0x41, 0x83, 0xf8, 0x07]
                            | [0x41, 0x83, 0xf8, 0x06]
                            | [0x41, 0x83, 0xf8, 0x02]
                    ),
                "dynamic unreachable R8 use is outside finite joined shape",
            )?;
        }
        Ok(())
    }

    fn join_window(
        objects: &[ObjectInput<'_>],
        map: &str,
        elf: &Elf<'_>,
        bytes: &[u8],
        owner: &Owner,
        code: &[EncodedConstructorInstruction],
        (first, limit): (usize, usize),
    ) -> Result<()> {
        let object = &objects[owner.object];
        require(
            first < limit && limit <= code.len(),
            "optional joined window incomplete",
        )?;
        let address = code[first].address;
        let end = next_address(&code[limit - 1])?;
        let input_begin = owner
            .input_start
            .checked_add(address - owner.start)
            .ok_or("optional window input offset")?;
        let input_end = input_begin
            .checked_add(end - address)
            .ok_or("optional window input end")?;
        let section = &object.elf.section_headers[owner.section];
        let source = section_file_bytes(section, object.bytes)?
            .get(
                usize::try_from(input_begin).map_err(|_| "window offset")?
                    ..usize::try_from(input_end).map_err(|_| "window end")?,
            )
            .ok_or("optional input window escapes section")?;
        let (load, offset) = unique_file_mapping(elf, bytes, address, source.len())?;
        require(load.p_flags == 5, "optional window is not RX")?;
        let linked = bytes
            .get(offset..offset + source.len())
            .ok_or("optional final window escapes")?;
        let mut input = Vec::new();
        let mut emitted = Vec::new();
        for (index, rows) in &object.elf.shdr_relocs {
            let rs = checked_relocation_section(
                &object.elf,
                object.bytes,
                *index,
                checked_symtab(&object.elf, object.bytes)?,
                rows.len(),
            )?;
            if rs.sh_info as usize != owner.section {
                continue;
            }
            for r in rows.iter() {
                let width = checked_relocation_span(&object.elf, rs, r.r_offset, r.r_type)?;
                if r.r_offset >= input_end
                    || width.is_some_and(|w| {
                        r.r_offset.checked_add(w).is_some_and(|e| e <= input_begin)
                    })
                {
                    continue;
                }
                require(
                    r.r_offset >= input_begin
                        && width == Some(4)
                        && r.r_offset.checked_add(4).is_some_and(|e| e <= input_end),
                    "optional input relocation crosses joined window",
                )?;
                let symbol = object
                    .elf
                    .syms
                    .get(r.r_sym)
                    .ok_or("optional window input symbol")?;
                let name = object
                    .elf
                    .strtab
                    .get_at(symbol.st_name)
                    .ok_or("optional window input name")?;
                let target = if Role::from_name(name) == Some(owner.role) {
                    require(
                        symbol.st_shndx == 0
                            && symbol.st_bind() == sym::STB_WEAK
                            && r.r_type == reloc::R_X86_64_GOTPCREL,
                        "optional joined operand lost weak origin",
                    )?;
                    SelectedTarget {
                        mapped_input_value: 0,
                    }
                } else {
                    resolve_input_target(map, object, r.r_sym, objects, elf, bytes)?
                };
                input.push(InputRelocation {
                    offset: usize::try_from(r.r_offset - input_begin)
                        .map_err(|_| "window relocation offset")?,
                    kind: r.r_type,
                    addend: r.r_addend.ok_or("optional input addend")?,
                    target,
                });
            }
        }
        for (index, rows) in &elf.shdr_relocs {
            let rs = checked_relocation_section(
                elf,
                bytes,
                *index,
                checked_symtab(elf, bytes)?,
                rows.len(),
            )?;
            for r in rows.iter() {
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
                    r.r_offset >= address
                        && relocation_width(r.r_type) == Some(4)
                        && r.r_offset.checked_add(4).is_some_and(|e| e <= end),
                    "optional final relocation crosses joined window",
                )?;
                emitted.push(FinalRelocation {
                    offset: usize::try_from(r.r_offset - address)
                        .map_err(|_| "window final relocation offset")?,
                    kind: r.r_type,
                    addend: r.r_addend.ok_or("optional final addend")?,
                    symbol_value: elf
                        .syms
                        .get(r.r_sym)
                        .ok_or("optional final window symbol")?
                        .st_value,
                });
            }
        }
        let _ = join_relocated_body(elf, bytes, address, source, linked, &input, &emitted)?;
        Ok(())
    }

    fn cxa_setters(
        owner: &Owner,
        object: &ObjectInput<'_>,
        code: &[EncodedConstructorInstruction],
    ) -> Result<Vec<usize>> {
        let mut setters = Vec::new();
        for (section_index, rows) in &object.elf.shdr_relocs {
            if object.elf.section_headers[*section_index].sh_info as usize != owner.section {
                continue;
            }
            for r in rows.iter() {
                if object
                    .elf
                    .syms
                    .get(r.r_sym)
                    .and_then(|s| object.elf.strtab.get_at(s.st_name))
                    == Some("pthread_setspecific")
                {
                    // Restrict below to the actual owner, not a different section.
                    if r.r_offset >= owner.input_start
                        && r.r_offset < owner.input_start + owner.size
                    {
                        let address = owner
                            .start
                            .checked_add(r.r_offset - owner.input_start)
                            .ok_or("cxa setter offset")?;
                        for (index, i) in code.iter().enumerate() {
                            if i.address.checked_add(2) == Some(address)
                                && i.bytes.len() == 6
                                && i.bytes[..2] == [0xff, 0x15]
                            {
                                setters.push(index);
                            }
                        }
                    }
                }
            }
        }
        Ok(setters)
    }

    // Finite continuation of the real std Linux destructor fallback. This
    // establishes local normal-return registration, not correctness of TLS,
    // grow/lazy-init implementations, unwinding or whole-runtime execution.
    fn cxa_continuation(
        code: &[EncodedConstructorInstruction],
        guard: &Guard,
        setter: usize,
        store: usize,
        store_end: usize,
        ordinary_end: usize,
    ) -> Result<()> {
        let zero = guard.zero;
        let b = |index: usize| {
            code.get(index)
                .map(|i| i.bytes.as_slice())
                .ok_or("cxa fallback truncated")
        };
        require(
            b(zero)? == [0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0]
                && b(zero + 1)?.len() == 8
                && b(zero + 1)?[..3] == [0x48, 0x83, 0xb8]
                && b(zero + 1)?[7] == 0
                && b(zero + 3)?.len() == 7
                && b(zero + 3)?[..3] == [0x4c, 0x8d, 0xb8]
                && b(zero + 1)?[3..7] == b(zero + 3)?[3..7]
                && b(zero + 4)? == [0x49, 0xc7, 0x07, 0xff, 0xff, 0xff, 0xff],
            "cxa TLS borrow prefix is outside the finite actual shape",
        )?;
        // These three TLS-relaxed operations are shape checks only. They are
        // never represented as source/final byte equality or a TLS proof.
        let edges = cfg(code, guard)?;
        let inside = reachable(&edges, &[zero], None, None);
        require(
            !inside.iter().any(|i| *i >= ordinary_end),
            "cxa ordinary continuation reaches exception-only cleanup",
        )?;
        for begin in [store, setter - 1] {
            let limit = if begin == store {
                store_end
            } else {
                setter + 1
            };
            for to in (begin + 1)..limit {
                require(
                    edges
                        .iter()
                        .enumerate()
                        .all(|(from, next)| !next.contains(&to) || from + 1 == to),
                    "cxa registration anchor has an interior predecessor",
                )?;
            }
        }
        let mut pending = vec![(zero, 0u8)];
        let mut seen = BTreeSet::new();
        let mut returns = 0usize;
        while let Some((node, mut stage)) = pending.pop() {
            if !seen.insert((node, stage)) {
                continue;
            }
            if node == setter {
                require(stage == 0, "cxa setter is repeated or out of order")?;
                stage = 1;
            }
            if node == store {
                require(stage == 1, "cxa stores bypass real setter")?;
            }
            if node == store_end - 1 {
                require(stage == 1, "cxa count store lacks ordered registration")?;
                stage = 2;
            }
            if edges[node].is_empty() {
                if matches!(code[node].bytes.first(), Some(0xc2 | 0xc3)) {
                    require(
                        stage == 2,
                        "cxa normal zero-path return bypasses registration",
                    )?;
                    returns += 1;
                } else {
                    require(
                        code[node].bytes == [0x0f, 0x0b],
                        "unproved cxa zero-path terminal escape",
                    )?;
                }
            }
            pending.extend(edges[node].iter().map(|next| (*next, stage)));
        }
        require(
            returns > 0,
            "cxa zero fallback has no proved normal registration return",
        )
    }

    fn fallback_windows(
        role: Role,
        code: &[EncodedConstructorInstruction],
        guard: &mut Guard,
        setters: &[usize],
    ) -> Result<()> {
        if role == Role::Cxa {
            // Preserve original argument saves, not merely a later same-byte store.
            require(
                code.get(8).is_some_and(|i| i.bytes == [0x49, 0x89, 0xfe])
                    && code.get(7).is_some_and(|i| i.bytes == [0x48, 0x89, 0xf3]),
                "cxa original destructor/data argument saves differ",
            )?;
            guard.windows[0].0 = 0;
            let pattern: &[&[u8]] = &[
                &[0x49, 0x8b, 0x47, 0x10],
                &[0x4c, 0x89, 0xe1],
                &[0x48, 0xc1, 0xe1, 0x04],
                &[0x4c, 0x89, 0x34, 0x08],
                &[0x48, 0x89, 0x5c, 0x08, 0x08],
                &[0x49, 0xff, 0xc4],
                &[0x4d, 0x89, 0x67, 0x18],
            ];
            let stores = code
                .windows(pattern.len())
                .enumerate()
                .filter(|(_, window)| {
                    window
                        .iter()
                        .zip(pattern)
                        .all(|(i, p)| i.bytes.as_slice() == *p)
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            require(
                stores.len() == 1,
                "cxa genuine list pair/count store anchors absent/ambiguous",
            )?;
            require(
                setters.len() == 1
                    && setters[0] > 0
                    && code[setters[0] - 1].bytes == [0xbe, 1, 0, 0, 0],
                "cxa actual TLS destructor key setter anchor differs",
            )?;
            require(
                code.len() >= 3
                    && code[code.len() - 3].bytes == [0x49, 0xff, 0x07]
                    && code[code.len() - 2].bytes == [0x48, 0x89, 0xc7]
                    && code[code.len() - 1].bytes.len() == 5
                    && code[code.len() - 1].bytes[0] == 0xe8,
                "cxa exception-only cleanup boundary differs",
            )?;
            let ordinary_end = code.len() - 3;
            cxa_continuation(
                code,
                guard,
                setters[0],
                stores[0],
                stores[0] + pattern.len(),
                ordinary_end,
            )?;
            // Join the source-local control edges and all ordinary non-TLS
            // continuation bytes, including error/lazy-init edges. The TLS
            // MOV/CMP/LEA instructions remain explicitly outside byte equality.
            guard.windows.push((guard.zero + 2, guard.zero + 3));
            guard.windows.push((guard.zero + 4, ordinary_end));
        }
        if role == Role::Dynamic {
            require(
                guard.begin >= 2
                    && code[guard.begin - 2].bytes == [0x41, 0x83, 0xf8, 2]
                    && code[guard.begin - 1].bytes.len() == 2
                    && code[guard.begin - 1].bytes[0] == 0x75,
                "dynamic optional use lost actual PT_DYNAMIC predicate",
            )?;
            guard.windows[0].0 = guard.begin - 2;
        }
        Ok(())
    }

    /// Only paths are supplied. Their actual bytes are bound before use and
    /// checked after the source transaction closes, including failure paths.
    pub struct OptionalSourceInputs<'a> {
        /// Exact bound GNU disassembler used by the existing instruction verifier.
        pub objdump: &'a Path,
        /// Pinned Rust std weak-syscall fallback source.
        pub std_weak_syscall: &'a Path,
        /// Pinned Rust std Linux destructor-registration fallback source.
        pub std_destructor_registration: &'a Path,
        /// Pinned private musl dl_iterate_phdr source.
        pub musl_dl_iterate_phdr: &'a Path,
    }

    fn zero_slot(elf: &Elf<'_>, bytes: &[u8], address: u64) -> Result<()> {
        static_image_metadata(elf, bytes)?;
        let (mapping, _) = unique_file_mapping(elf, bytes, address, 8)?;
        require(
            mapping.p_flags == program_header::PF_R
                && readonly_loaded_bytes(elf, bytes, address, 8)? == [0; 8],
            "optional slot is not actual immutable RO zero",
        )
    }

    fn inspect(
        runtime: &FileIdentity,
        libc: &FileIdentity,
        artifact: &FileIdentity,
        link_map: &FileIdentity,
        objdump: &FileIdentity,
        runner: &mut Runner,
        files: &mut Vec<FileIdentity>,
    ) -> Result<(Vec<ClosedGuard>, usize, usize)> {
        let archives = [runtime.clone(), libc.clone()];
        let mut backing = extract_objects(runtime, 0)?;
        backing.extend(extract_objects(libc, 1)?);
        let mut objects = Vec::new();
        for m in &backing {
            objects.push(ObjectInput {
                archive_path: &archives[m.archive_index].path,
                member_name: &m.name,
                ordinal: m.ordinal,
                header_offset: m.header,
                bytes: &m.bytes,
                elf: Elf::parse(&m.bytes).map_err(|e| e.to_string())?,
            });
        }
        for file in [artifact, link_map] {
            require(
                fs::metadata(&file.path).map_err(|e| e.to_string())?.len() <= 128 * 1024 * 1024,
                "optional ELF/map exceeds maintained bound",
            )?;
        }
        let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
        let elf = Elf::parse(&bytes).map_err(|e| e.to_string())?;
        let map = fs::read_to_string(&link_map.path).map_err(|e| e.to_string())?;
        let (uses, dead) = enumerate(&objects, &map, &elf, &bytes)?;
        let owners = owners(&objects, &map, &elf, &uses)?;
        let mut guards = Vec::new();
        for owner in owners {
            require(
                match owner.role {
                    Role::Dynamic => {
                        objects[owner.object].archive_path == libc.path
                            && objects[owner.object].member_name == "dl_iterate_phdr.lo"
                    }
                    _ => {
                        objects[owner.object].archive_path == runtime.path
                            && objects[owner.object].member_name.starts_with("std-")
                            && objects[owner.object].member_name.ends_with(".rcgu.o")
                    }
                },
                "optional policy has wrong actual archive/member owner",
            )?;
            let ranges = selected_function_ranges(&elf, BTreeSet::from([owner.start]))?;
            let expected = proof_function_bytes_after_metadata(&elf, &bytes, &ranges)?;
            let end = owner
                .start
                .checked_add(owner.size)
                .ok_or("optional owner end")?;
            let args = vec![
                "--disassemble".into(),
                "--show-raw-insn".into(),
                "--disassemble-zeroes".into(),
                "--insn-width=16".into(),
                "--wide".into(),
                format!("--start-address={:#x}", owner.start),
                format!("--stop-address={end:#x}"),
                artifact
                    .path
                    .to_str()
                    .ok_or("optional ELF path UTF8")?
                    .into(),
            ];
            let before = runner.commands.len();
            close_files(files)?;
            let raw = runner.run_with_combined_limit(
                objdump.path.to_str().ok_or("optional objdump UTF8")?,
                &args,
                artifact.path.parent().ok_or("optional ELF parent")?,
                Some(runner.max_stream_bytes.min(16 * 1024 * 1024)),
            );
            for command in &runner.commands[before..] {
                files.push(command.stdout.clone());
                files.push(command.stderr.clone());
            }
            let raw = combine(raw, close_files(files))?;
            let text = std::str::from_utf8(&raw).map_err(|e| e.to_string())?;
            require(
                !text
                    .lines()
                    .any(|line| line.contains("(bad)") || line.contains("\t.byte")),
                "optional decoder reported invalid/raw data",
            )?;
            verify_disassembly_bytes(text, &expected)?;
            let code = constructor_instructions(text, owner.start)?;
            let mut slot = None;
            for u in &owner.uses {
                let (_, at) = unique_file_mapping(&elf, &bytes, u.place, 4)?;
                let displacement = i32::from_le_bytes(
                    bytes
                        .get(at..at + 4)
                        .ok_or("optional disp32")?
                        .try_into()
                        .map_err(|_| "optional disp32 width")?,
                );
                let address = u64::try_from(
                    i128::from(u.place) + i128::from(displacement) - i128::from(u.addend),
                )
                .map_err(|_| "optional GOT address overflow")?;
                zero_slot(&elf, &bytes, address)?;
                require(
                    slot.is_none_or(|old| old == address),
                    "optional owner uses distinct slots",
                )?;
                slot = Some(address);
            }
            let slot = slot.ok_or("optional slot absent")?;
            let mut guard = recognize(owner.role, &code, &owner.uses, slot)?;
            external_guard_entries(&elf, &bytes, &owner, &code, &guard)?;
            if owner.role == Role::Dynamic {
                dynamic_register_lifetime(text, &code, &guard)?;
            }
            let setters = if owner.role == Role::Cxa {
                cxa_setters(&owner, &objects[owner.object], &code)?
            } else {
                Vec::new()
            };
            fallback_windows(owner.role, &code, &mut guard, &setters)?;
            for &(begin, end) in &guard.windows {
                join_window(&objects, &map, &elf, &bytes, &owner, &code, (begin, end))?;
            }
            guards.push(ClosedGuard {
                role: owner.role,
                owner: owner.start,
                slot,
                uses: owner.uses.len(),
                windows: guard.windows.len(),
            });
        }
        Ok((guards, uses.len(), dead))
    }

    impl VerifiedStaticSource {
        /// Observe finite optional zero uses in a previously linked definition
        /// result from THIS live source transaction. Does not relax undefined
        /// rejection, prove whole-owner equivalence, or authorize execution.
        /// Ordinary valid ABI call/return is assumed for trusted compiled code;
        /// compiler/native source-machine and pre-FS proofs remain separate.
        pub fn observe_optional_zero_references(
            &self,
            archive: &StaticArchive,
            definitions: &SelectedInitializerDefinitions,
            input: &OptionalSourceInputs<'_>,
            runner: &mut Runner,
        ) -> Result<OptionalZeroObservation> {
            // Wrong-owner refusal precedes even reads of the supplied files.
            let admission = self.require_archive_owner(archive).and_then(|_| {
                require(
                    Arc::ptr_eq(&self.archive_owner, &definitions.source_owner.0),
                    "optional definitions belong to another source transaction",
                )
            });
            if let Err(error) = admission {
                return combine(Err(error), self.guard.close(runner));
            }
            let mut files = definitions.files.clone();
            let result = (|| {
                archive.verify()?;
                definitions.verify()?;
                self.guard.close(runner)?;
                definitions.core.require_ledger(&definitions.files)?;
                require(
                    definitions.core.runtime == archive.file,
                    "optional runtime archive differs",
                )?;
                let objdump = bind_expected(
                    &mut files,
                    input.objdump,
                    "0a1b558f444ed2bca7fb467dede7416a651bc490b1abc77705ab470d99c527c1",
                )?;
                for (path, expected) in [
                    (
                        input.std_weak_syscall,
                        "0f9c4e63d9f15b2486e8c0a9af89c4c2ad88fcad7c1a5127a95d8031e13ec2d3",
                    ),
                    (
                        input.std_destructor_registration,
                        "5634b13e8faa9ead0e7dac104abf51a990bc14cbc39c5c6bae22a7b70811e2b3",
                    ),
                    (
                        input.musl_dl_iterate_phdr,
                        "802a537924c900ff607b65bda465bf66899890b7b0707c0cd55c7b800db20327",
                    ),
                ] {
                    bind_expected(&mut files, path, expected)?;
                }
                inspect(
                    &definitions.core.runtime,
                    &definitions.core.libc,
                    &definitions.core.artifact,
                    &definitions.core.map,
                    &objdump,
                    runner,
                    &mut files,
                )
            })();
            // Attempt every actual close even when source/earlier closes fail.
            let source_close = self.guard.close(runner);
            let archive_close = archive.verify();
            let definitions_close = definitions.verify();
            let file_close = close_files(&files);
            let closed = combine(
                combine(combine(source_close, archive_close), definitions_close),
                file_close,
            );
            let (guards, selected_uses, unselected_input_uses) = combine(result, closed)?;
            let observation = OptionalZeroObservation {
                source_owner: DefinitionSourceOwner(Arc::clone(&self.archive_owner)),
                core: DefinitionCore::new(
                    &definitions.core.runtime,
                    &definitions.core.libc,
                    &definitions.core.artifact,
                    &definitions.core.map,
                ),
                guards,
                selected_uses,
                unselected_input_uses,
                files,
            };
            observation.verify()?;
            Ok(observation)
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        // These are structural/private-binding controls only. No test fixture
        // creates a VerifiedStaticSource or a successful public factory proof.
        fn final_row_fixture() -> Vec<u8> {
            let mut bytes = super::super::super::tests::elf_fixture();
            bytes.resize(0x3400, 0);
            let strings = b"\0_DYNAMIC\0gettid\0__cxa_thread_atexit_impl\0unknown\0";
            bytes[0x3000..0x3000 + strings.len()].copy_from_slice(strings);
            bytes[40..48].copy_from_slice(&0x3200u64.to_le_bytes());
            bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
            bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
            for (at, kind, offset, size, link, info, entsize) in [
                (
                    0x3240,
                    3u32,
                    0x3000u64,
                    strings.len() as u64,
                    0u32,
                    0u32,
                    0u64,
                ),
                (0x3280, 2, 0x3100, 4 * 24, 1, 2, 24),
            ] {
                bytes[at + 4..at + 8].copy_from_slice(&kind.to_le_bytes());
                bytes[at + 24..at + 32].copy_from_slice(&offset.to_le_bytes());
                bytes[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
                bytes[at + 40..at + 44].copy_from_slice(&link.to_le_bytes());
                bytes[at + 44..at + 48].copy_from_slice(&info.to_le_bytes());
                bytes[at + 56..at + 64].copy_from_slice(&entsize.to_le_bytes());
            }
            for (index, name, bind, visibility) in
                [(1usize, 1u32, 0u8, 2u8), (2, 10, 2, 0), (3, 17, 2, 0)]
            {
                let at = 0x3100 + index * 24;
                bytes[at..at + 4].copy_from_slice(&name.to_le_bytes());
                bytes[at + 4] = bind << 4;
                bytes[at + 5] = visibility;
            }
            bytes
        }
        fn final_row_observation(bytes: &[u8]) -> OptionalZeroObservation {
            let file = |name: &str| FileIdentity {
                path: PathBuf::from(format!("/not-a-factory/{name}")),
                sha256: if name == "elf" {
                    sha256(bytes)
                } else {
                    name.into()
                },
            };
            let core =
                DefinitionCore::new(&file("runtime"), &file("libc"), &file("elf"), &file("map"));
            let files = core.files();
            OptionalZeroObservation {
                source_owner: DefinitionSourceOwner(Arc::new(ArchiveSourceOwner { _reserved: 0 })),
                core,
                guards: [Role::Dynamic, Role::Gettid, Role::Cxa]
                    .into_iter()
                    .map(|role| ClosedGuard {
                        role,
                        owner: 1,
                        slot: 8,
                        uses: 1,
                        windows: 1,
                    })
                    .collect(),
                selected_uses: 3,
                unselected_input_uses: 0,
                files,
            }
        }
        #[test]
        fn optional_final_owner_rejects_equal_metadata_but_distinct_transaction() {
            let observation = final_row_observation(&final_row_fixture());
            observation
                .require_owner(&observation.source_owner.0, &observation.core.runtime)
                .unwrap();
            let other = Arc::new(ArchiveSourceOwner { _reserved: 0 });
            // Equal metadata/identities never replace the actual non-ZST Arc.
            assert!(
                require_same_archive_source(
                    &observation.source_owner.0,
                    &other,
                    "same-cargo-metadata",
                    "same-cargo-metadata"
                )
                .is_err()
            );
            assert_eq!(
                observation
                    .require_owner(&other, &observation.core.runtime)
                    .unwrap_err(),
                "optional final inspection belongs to another source transaction"
            );
        }
        #[test]
        fn optional_final_core_runtime_artifact_and_complete_ledger_are_distinct() {
            let mut observation = final_row_observation(&final_row_fixture());
            let mut changed = observation.core.runtime.clone();
            changed.sha256.push('0');
            assert_eq!(
                observation
                    .require_owner(&observation.source_owner.0, &changed)
                    .unwrap_err(),
                "optional final runtime archive differs"
            );
            let mut other = observation.core.artifact.clone();
            other.path.push("other");
            assert_eq!(
                observation.require_artifact(&other).unwrap_err(),
                "optional final artifact differs"
            );
            other = observation.core.artifact.clone();
            other.sha256.push('0');
            assert!(observation.require_artifact(&other).is_err());
            observation
                .files
                .retain(|file| file != &observation.core.map);
            assert!(
                observation
                    .require_owner(&observation.source_owner.0, &observation.core.runtime)
                    .unwrap_err()
                    .contains("named core absent/aliased")
            );
            observation.files = observation.core.files();
            observation.core.map = observation.core.artifact.clone();
            assert!(
                observation
                    .require_owner(&observation.source_owner.0, &observation.core.runtime)
                    .unwrap_err()
                    .contains("named core absent/aliased")
            );
        }
        #[test]
        fn optional_final_exact_undefined_rows_reject_changes_duplicates_and_unknowns() {
            let bytes = final_row_fixture();
            assert_eq!(
                final_undefined_rows(&Elf::parse(&bytes).unwrap())
                    .unwrap()
                    .len(),
                3
            );
            for (at, value) in [
                (0x3100 + 2 * 24 + 4, 0u8),  // strong/local instead of weak
                (0x3100 + 2 * 24 + 4, 0x22), // FUNC instead of NOTYPE
                (0x3100 + 2 * 24 + 5, 2),    // hidden gettid
                (0x3100 + 2 * 24 + 8, 1),    // nonzero symbol value
                (0x3100 + 2 * 24 + 16, 1),   // nonzero symbol size
            ] {
                let mut bad = bytes.clone();
                bad[at] = value;
                assert_eq!(
                    final_undefined_rows(&Elf::parse(&bad).unwrap()).unwrap_err(),
                    "optional final undefined binding/type differs"
                );
            }
            let mut duplicate = bytes.clone();
            duplicate[0x3100 + 3 * 24..0x3100 + 3 * 24 + 4].copy_from_slice(&10u32.to_le_bytes());
            assert_eq!(
                final_undefined_rows(&Elf::parse(&duplicate).unwrap()).unwrap_err(),
                "duplicate final optional symbol"
            );
            let mut unknown = bytes.clone();
            unknown[0x3100 + 3 * 24..0x3100 + 3 * 24 + 4].copy_from_slice(&42u32.to_le_bytes());
            assert_eq!(
                final_undefined_rows(&Elf::parse(&unknown).unwrap()).unwrap_err(),
                "unclassified final undefined reference"
            );
            let mut empty = bytes.clone();
            empty[0x3100 + 3 * 24..0x3100 + 3 * 24 + 4].copy_from_slice(&9u32.to_le_bytes());
            assert_eq!(
                final_undefined_rows(&Elf::parse(&empty).unwrap()).unwrap_err(),
                "optional final undefined has empty nonzero name"
            );
            let mut missing = bytes.clone();
            missing[0x3280 + 32..0x3280 + 40].copy_from_slice(&(3u64 * 24).to_le_bytes());
            assert_eq!(
                final_undefined_rows(&Elf::parse(&missing).unwrap()).unwrap_err(),
                "optional final undefined role set differs"
            );
            let mut extra = bytes.clone();
            extra[0x3280 + 32..0x3280 + 40].copy_from_slice(&(5u64 * 24).to_le_bytes());
            extra[0x3100 + 4 * 24..0x3100 + 4 * 24 + 4].copy_from_slice(&42u32.to_le_bytes());
            assert_eq!(
                final_undefined_rows(&Elf::parse(&extra).unwrap()).unwrap_err(),
                "unclassified final undefined reference"
            );
        }
        #[test]
        fn optional_final_bytes_and_observed_roles_cannot_be_substituted() {
            let bytes = final_row_fixture();
            let mut observation = final_row_observation(&bytes);
            observation
                .require_final_rows(&Elf::parse(&bytes).unwrap(), &bytes)
                .unwrap();
            let mut changed = bytes.clone();
            changed[0x1000] ^= 1;
            assert_eq!(
                observation
                    .require_final_rows(&Elf::parse(&changed).unwrap(), &changed)
                    .unwrap_err(),
                "optional final artifact bytes differ"
            );
            observation.guards.pop();
            assert_eq!(
                observation
                    .require_final_rows(&Elf::parse(&bytes).unwrap(), &bytes)
                    .unwrap_err(),
                "optional final observed role set differs"
            );
        }
        #[test]
        fn optional_final_shared_geometry_preserves_strict_and_unrelated_refusals() {
            let bytes = final_row_fixture();
            let observation = final_row_observation(&bytes);
            let elf = Elf::parse(&bytes).unwrap();
            assert_eq!(
                super::super::super::geometry(&elf, &bytes).unwrap_err(),
                "static final ELF has unresolved symbols"
            );
            super::super::super::geometry_impl(&elf, &bytes, Some(&observation)).unwrap();
            // Rebind only the test's byte identity to reach the shared geometry
            // guard. This is NOT a fresh authentic optional observation.
            for (at, value, width) in [
                (16usize, 3u64, 2usize),
                (64 + 56 + 4, 7, 4),
                (64 + 3 * 56 + 48, 3, 8),
                (64 + 4 * 56 + 4, 7, 4),
            ] {
                let mut bad = bytes.clone();
                bad[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
                let structural_only = final_row_observation(&bad);
                assert!(
                    super::super::super::geometry_impl(
                        &Elf::parse(&bad).unwrap(),
                        &bad,
                        Some(&structural_only)
                    )
                    .is_err(),
                    "field {at}"
                );
            }
        }
        #[test]
        fn optional_final_close_preserves_body_and_all_changed_file_errors() {
            struct Scratch(PathBuf);
            impl Drop for Scratch {
                fn drop(&mut self) {
                    let _ = fs::remove_dir_all(&self.0);
                }
            }
            let directory = Scratch(std::env::temp_dir().join(format!(
                    "optional-final-close-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )));
            fs::create_dir(&directory.0).unwrap();
            let mut files = Vec::new();
            for name in ["first-script", "second-output"] {
                let path = directory.0.join(name);
                write_new(&path, b"original input").unwrap();
                files.push(FileIdentity::read(&path).unwrap());
                fs::write(&path, b"changed retained input").unwrap();
            }
            let error =
                combine::<()>(Err("body rejected".into()), close_files(&files)).unwrap_err();
            assert!(
                error.contains("body rejected") && error.contains("optional close"),
                "{error}"
            );
            for file in files {
                assert!(error.contains(file.path.to_str().unwrap()), "{error}");
            }
        }
        #[test]
        fn optional_final_read_limit_is_exact_and_inclusive() {
            super::super::super::final_artifact_size(128 * 1024 * 1024).unwrap();
            assert_eq!(
                super::super::super::final_artifact_size(128 * 1024 * 1024 + 1).unwrap_err(),
                "static final artifact exceeds 128 MiB bound"
            );
            assert!(super::super::super::final_artifact_size(u64::MAX).is_err());
        }

        fn fixture() -> Value {
            serde_json::from_str(include_str!("optional-zero-a03.json")).unwrap()
        }
        fn data(v: &Value) -> Vec<u8> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
                .collect()
        }
        fn role(v: &Value) -> Role {
            match v["role"].as_str().unwrap() {
                "Gettid" => Role::Gettid,
                "Cxa" => Role::Cxa,
                "Dynamic" => Role::Dynamic,
                _ => panic!("fixture role"),
            }
        }
        fn code(v: &Value) -> Vec<EncodedConstructorInstruction> {
            v["instructions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| EncodedConstructorInstruction {
                    address: i["address"].as_u64().unwrap(),
                    bytes: data(&i["bytes"]),
                })
                .collect()
        }
        fn uses(v: &Value) -> Vec<Use> {
            v["uses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| Use {
                    role: role(v),
                    place: u["place"].as_u64().unwrap(),
                    addend: u["addend"].as_i64().unwrap(),
                    object: 0,
                    section: 1,
                    offset: u["place"].as_u64().unwrap() - v["start"].as_u64().unwrap(),
                })
                .collect()
        }
        fn slot(v: &Value) -> u64 {
            let code = code(v);
            let u = &uses(v)[0];
            let instruction = code
                .iter()
                .find(|i| i.address <= u.place && u.place + 4 <= i.address + i.bytes.len() as u64)
                .unwrap();
            let at = usize::try_from(u.place - instruction.address).unwrap();
            u64::try_from(
                i128::from(u.place)
                    + i128::from(i32::from_le_bytes(
                        instruction.bytes[at..at + 4].try_into().unwrap(),
                    ))
                    - i128::from(u.addend),
            )
            .unwrap()
        }
        fn guarded(v: &Value) -> Guard {
            let c = code(v);
            recognize(role(v), &c, &uses(v), slot(v)).unwrap()
        }
        fn full_guard(v: &Value) -> Guard {
            let c = code(v);
            let mut guard = guarded(v);
            let setters = v["input_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["name"] == "pthread_setspecific")
                .map(|r| {
                    position(
                        &c,
                        v["start"].as_u64().unwrap() + r["offset"].as_u64().unwrap() - 2,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            fallback_windows(role(v), &c, &mut guard, &setters).unwrap();
            guard
        }
        fn put16(b: &mut [u8], at: usize, v: u16) {
            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        fn put32(b: &mut [u8], at: usize, v: u32) {
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn put64(b: &mut [u8], at: usize, v: u64) {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        // Reduced structural unit ELF containing real a03 body/GOT bytes. This
        // is NOT a source-owned linked-image positive or imported proof token.
        fn unit_elf(f: &Value) -> Vec<u8> {
            let mut b = vec![0u8; 4096];
            b[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            put16(&mut b, 16, 2);
            put16(&mut b, 18, 62);
            put32(&mut b, 20, 1);
            put64(&mut b, 32, 64);
            put16(&mut b, 52, 64);
            put16(&mut b, 54, 56);
            put16(&mut b, 56, 4);
            put16(&mut b, 58, 64);
            let mut parts = f["owners"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    let c = code(v);
                    (
                        v["start"].as_u64().unwrap(),
                        c.iter()
                            .flat_map(|i| i.bytes.iter().copied())
                            .collect::<Vec<_>>(),
                        5u32,
                    )
                })
                .collect::<Vec<_>>();
            parts.push((
                f["readonly"]["address"].as_u64().unwrap(),
                data(&f["readonly"]["bytes"]),
                4,
            ));
            for (index, (address, bytes, flags)) in parts.into_iter().enumerate() {
                let offset = b.len();
                let prefix = (address & 4095) as usize;
                let length = (prefix + bytes.len() + 4095) & !4095;
                b.resize(offset + length, 0);
                b[offset + prefix..offset + prefix + bytes.len()].copy_from_slice(&bytes);
                let at = 64 + index * 56;
                put32(&mut b, at, 1);
                put32(&mut b, at + 4, flags);
                put64(&mut b, at + 8, offset as u64);
                put64(&mut b, at + 16, address & !4095);
                put64(&mut b, at + 32, (prefix + bytes.len()) as u64);
                put64(&mut b, at + 40, (prefix + bytes.len()) as u64);
                put64(&mut b, at + 48, 4096);
            }
            b
        }
        fn window_join(
            v: &Value,
            c: &[EncodedConstructorInstruction],
            begin: usize,
            limit: usize,
            file: &[u8],
            original: &[u8],
        ) -> Result<()> {
            let elf = Elf::parse(file).map_err(|e| e.to_string())?;
            let address = c[begin].address;
            let end = next_address(&c[limit - 1])?;
            let offset = usize::try_from(address - v["start"].as_u64().unwrap())
                .map_err(|_| "fixture offset")?;
            let size = usize::try_from(end - address).map_err(|_| "fixture size")?;
            let input = v["input_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| {
                    let at = r["offset"].as_u64().unwrap() as usize;
                    offset <= at && at < offset + size
                })
                .map(|r| InputRelocation {
                    offset: r["offset"].as_u64().unwrap() as usize - offset,
                    kind: r["kind"].as_u64().unwrap() as u32,
                    addend: r["addend"].as_i64().unwrap(),
                    // Extracted independently from exact member/selected map rows,
                    // never inferred by rebasing the final relocation value.
                    target: SelectedTarget {
                        mapped_input_value: r["mapped_target"]
                            .as_u64()
                            .expect("actual selected fixture target"),
                    },
                })
                .collect::<Vec<_>>();
            let emitted = v["final_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| {
                    let at = r["offset"].as_u64().unwrap() as usize;
                    offset <= at && at < offset + size
                })
                .map(|r| FinalRelocation {
                    offset: r["offset"].as_u64().unwrap() as usize - offset,
                    kind: r["kind"].as_u64().unwrap() as u32,
                    addend: r["addend"].as_i64().unwrap(),
                    symbol_value: r["symbol"].as_u64().unwrap(),
                })
                .collect::<Vec<_>>();
            let (_, at) = unique_file_mapping(&elf, file, address, size)?;
            join_relocated_body(
                &elf,
                file,
                address,
                &original[offset..offset + size],
                &file[at..at + size],
                &input,
                &emitted,
            )
            .map(|_| ())
        }

        #[test]
        fn actual_three_complete_owners_prove_local_zero_guards() {
            let f = fixture();
            for (v, count) in f["owners"].as_array().unwrap().iter().zip([151, 64, 73]) {
                let c = code(v);
                assert_eq!(c.len(), count);
                let expected = BTreeMap::from([(
                    v["start"].as_u64().unwrap(),
                    c.iter().flat_map(|i| i.bytes.iter().copied()).collect(),
                )]);
                verify_disassembly_bytes(v["disassembly"].as_str().unwrap(), &expected).unwrap();
                let g = full_guard(v);
                check_guard(&c, &g).unwrap();
                if role(v) == Role::Dynamic {
                    dynamic_register_lifetime(v["disassembly"].as_str().unwrap(), &c, &g).unwrap();
                }
            }
        }
        #[test]
        fn actual_local_windows_join_without_tls_masking() {
            let f = fixture();
            let image = unit_elf(&f);
            for v in f["owners"].as_array().unwrap() {
                let c = code(v);
                let g = full_guard(v);
                let original = data(&v["input"]);
                for (a, b) in g.windows {
                    window_join(v, &c, a, b, &image, &original).unwrap();
                }
            }
            // The source/final TLS-containing full bodies really differ; the
            // narrower successful windows must not be reported as that join.
            for v in &f["owners"].as_array().unwrap()[..2] {
                let final_body = code(v)
                    .iter()
                    .flat_map(|i| i.bytes.iter().copied())
                    .collect::<Vec<_>>();
                assert_ne!(data(&v["input"]), final_body);
            }
        }
        #[test]
        fn optional_guard_rejects_inversion_wrong_slot_operand_and_extra_use() {
            let f = fixture();
            for v in f["owners"].as_array().unwrap() {
                let c = code(v);
                let g = guarded(v);
                let mut inverted = c.clone();
                inverted[g.branch].bytes[0] ^= 1;
                assert!(recognize(role(v), &inverted, &uses(v), slot(v)).is_err());
                let mut wrong = c.clone();
                wrong[g.begin].bytes[3] ^= 8;
                assert!(recognize(role(v), &wrong, &uses(v), slot(v)).is_err());
                let mut shifted = uses(v);
                shifted[0].place += 1;
                assert!(recognize(role(v), &c, &shifted, slot(v)).is_err());
                let mut extra = uses(v);
                extra.push(extra[0].clone());
                assert!(recognize(role(v), &c, &extra, slot(v)).is_err());
            }
        }
        #[test]
        fn optional_cfg_rejects_real_guard_bypass_and_interior_target() {
            let f = fixture();
            let v = &f["owners"][0];
            let c = code(v);
            let g = guarded(v);
            let branch = c
                .iter()
                .enumerate()
                .rfind(|(i, n)| *i < g.begin && n.bytes.len() == 2 && n.bytes[0] == 0xeb)
                .unwrap()
                .0;
            for target in [
                c[*g.consumers.first().unwrap()].address,
                c[g.begin].address + 1,
            ] {
                let mut bad = c.clone();
                bad[branch].bytes[1] = i8::try_from(
                    i128::from(target) - i128::from(next_address(&bad[branch]).unwrap()),
                )
                .unwrap() as u8;
                assert!(recognize(role(v), &bad, &uses(v), slot(v)).is_err());
            }
            let mut discontinuous = c.clone();
            discontinuous[g.begin].address += 1;
            assert!(check_guard(&discontinuous, &g).is_err());
        }
        #[test]
        fn optional_fallbacks_reject_wrong_syscall_and_discarded_registration() {
            let f = fixture();
            let v = &f["owners"][0];
            let mut c = code(v);
            let g = guarded(v);
            c[g.zero].bytes[1] ^= 1;
            assert!(recognize(role(v), &c, &uses(v), slot(v)).is_err());
            let v = &f["owners"][1];
            let mut c = code(v);
            let mut g = guarded(v);
            let setter = v["input_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == "pthread_setspecific")
                .unwrap();
            let index = position(
                &c,
                v["start"].as_u64().unwrap() + setter["offset"].as_u64().unwrap() - 2,
            )
            .unwrap();
            let store = c
                .iter()
                .position(|i| i.bytes == [0x4c, 0x89, 0x34, 0x08])
                .unwrap();
            c[store].bytes = vec![0x90; 4];
            assert!(fallback_windows(role(v), &c, &mut g, &[index]).is_err());
        }
        #[test]
        fn optional_actual_slot_requires_full_ro_zero_bytes() {
            let f = fixture();
            let image = unit_elf(&f);
            let elf = Elf::parse(&image).unwrap();
            for v in f["owners"].as_array().unwrap() {
                zero_slot(&elf, &image, slot(v)).unwrap();
            }
            let address = slot(&f["owners"][0]);
            let (_, at) = unique_file_mapping(&elf, &image, address, 8).unwrap();
            let mut nonzero = image.clone();
            nonzero[at] = 1;
            assert!(zero_slot(&Elf::parse(&nonzero).unwrap(), &nonzero, address).is_err());
            for flags in [6, 5, 7] {
                let mut bad = image.clone();
                put32(&mut bad, 64 + 3 * 56 + 4, flags);
                assert!(zero_slot(&Elf::parse(&bad).unwrap(), &bad, address).is_err());
            }
            assert!(zero_slot(&elf, &image, u64::MAX - 3).is_err());
        }
        #[test]
        fn optional_joined_bytes_refuse_change_and_crossing_tls_field() {
            let f = fixture();
            let image = unit_elf(&f);
            let v = &f["owners"][0];
            let c = code(v);
            let g = full_guard(v);
            let (a, b) = g.windows[0];
            let mut original = data(&v["input"]);
            let at = (c[a].address - v["start"].as_u64().unwrap()) as usize;
            original[at] ^= 1;
            assert!(window_join(v, &c, a, b, &image, &original).is_err());
            // A real preceding TLS-relaxed window does NOT gain a field waiver.
            let tls = c
                .iter()
                .position(|i| i.bytes.starts_with(&[0x64, 0x48, 0x8b]))
                .unwrap();
            let limit = position(&c, v["start"].as_u64().unwrap() + 87).unwrap();
            let error = window_join(v, &c, tls, limit, &image, &data(&v["input"])).unwrap_err();
            assert!(error.contains("unsupported relocation"), "{error}");
        }

        #[test]
        fn dynamic_register_cannot_escape_after_the_zero_branch() {
            let f = fixture();
            let v = &f["owners"][2];
            let c = code(v);
            let g = guarded(v);
            let at = g.zero + 1;
            let mut bad = c.clone();
            // The real loop continuation would now consume the optional R8.
            bad[at].bytes = vec![0x41, 0xff, 0xd0];
            let text = v["disassembly"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| {
                    if line.trim().starts_with(&format!("{:x}:", bad[at].address)) {
                        format!("{:x}: 41 ff d0 callq *%r8", bad[at].address)
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(dynamic_register_lifetime(&text, &bad, &g).is_err());
        }
        #[test]
        fn optional_error_aggregation_and_wrong_owner_are_not_success() {
            assert_eq!(
                combine::<()>(Err("body".into()), Err("close".into())).unwrap_err(),
                "body; optional close: close"
            );
            let first = Arc::new(ArchiveSourceOwner { _reserved: 0 });
            let second = Arc::new(ArchiveSourceOwner { _reserved: 0 });
            assert!(require_same_archive_source(&first, &first, "same", "same").is_ok());
            assert!(require_same_archive_source(&first, &second, "same", "same").is_err());
        }
        struct Section {
            name: &'static str,
            kind: u32,
            flags: u64,
            address: u64,
            offset: u64,
            size: u64,
            link: u32,
            info: u32,
            align: u64,
            entry: u64,
        }
        fn append_section(b: &mut Vec<u8>, name: &'static str, kind: u32, bytes: &[u8]) -> Section {
            let offset = b.len() as u64;
            b.extend_from_slice(bytes);
            Section {
                name,
                kind,
                flags: 0,
                address: 0,
                offset,
                size: bytes.len() as u64,
                link: 0,
                info: 0,
                align: 1,
                entry: 0,
            }
        }
        fn sections(b: &mut Vec<u8>, mut rows: Vec<Section>) {
            let mut strings = vec![0u8];
            let mut offsets = Vec::new();
            for row in &rows {
                offsets.push(strings.len() as u32);
                strings.extend_from_slice(row.name.as_bytes());
                strings.push(0);
            }
            let names = strings.len() as u32;
            strings.extend_from_slice(b".shstrtab\0");
            let names_row = append_section(b, ".shstrtab", 3, &strings);
            rows.push(names_row);
            offsets.push(names);
            let start = b.len();
            b.resize(start + (rows.len() + 1) * 64, 0);
            put64(b, 40, start as u64);
            put16(b, 60, (rows.len() + 1) as u16);
            put16(b, 62, rows.len() as u16);
            for (index, (row, name)) in rows.into_iter().zip(offsets).enumerate() {
                let at = start + (index + 1) * 64;
                put32(b, at, name);
                put32(b, at + 4, row.kind);
                put64(b, at + 8, row.flags);
                put64(b, at + 16, row.address);
                put64(b, at + 24, row.offset);
                put64(b, at + 32, row.size);
                put32(b, at + 40, row.link);
                put32(b, at + 44, row.info);
                put64(b, at + 48, row.align);
                put64(b, at + 56, row.entry);
            }
        }
        fn relocation_rows(v: &Value, final_indices: bool) -> Vec<u8> {
            let mut out = Vec::new();
            for u in v["uses"].as_array().unwrap() {
                let at = out.len();
                out.resize(at + 24, 0);
                let offset = if final_indices {
                    u["place"].as_u64().unwrap()
                } else {
                    u["place"].as_u64().unwrap() - v["start"].as_u64().unwrap()
                };
                let symbol = if final_indices {
                    match role(v) {
                        Role::Dynamic => 1,
                        Role::Gettid => 2,
                        Role::Cxa => 3,
                    }
                } else {
                    1
                };
                put64(&mut out, at, offset);
                put64(&mut out, at + 8, (symbol << 32) | 9);
                put64(&mut out, at + 16, u["addend"].as_i64().unwrap() as u64);
            }
            out
        }
        // Valid structural ELF tables with real owner/operand bytes and exact
        // actual weak/localized binding shapes. They do not impersonate an ar
        // member hash or a qualifying source-owned factory result.
        fn input_table_fixture(v: &Value) -> Vec<u8> {
            let mut b = vec![0u8; 64];
            b[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            put16(&mut b, 16, 1);
            put16(&mut b, 18, 62);
            put32(&mut b, 20, 1);
            put16(&mut b, 52, 64);
            put16(&mut b, 58, 64);
            let mut text = append_section(&mut b, ".text", 1, &data(&v["input"]));
            text.flags = 6;
            let mut symbols = vec![0u8; 48];
            put32(&mut symbols, 24, 1);
            symbols[28] = 0x20;
            if role(v) == Role::Dynamic {
                symbols[29] = 2;
            }
            let mut st = append_section(&mut b, ".symtab", 2, &symbols);
            st.link = 3;
            st.info = 1;
            st.entry = 24;
            st.align = 8;
            let mut strings = vec![0u8];
            strings.extend_from_slice(role(v).name().as_bytes());
            strings.push(0);
            let strings = append_section(&mut b, ".strtab", 3, &strings);
            let mut rel = append_section(&mut b, ".rela.text", 4, &relocation_rows(v, false));
            rel.link = 2;
            rel.info = 1;
            rel.entry = 24;
            rel.align = 8;
            sections(&mut b, vec![text, st, strings, rel]);
            b
        }
        fn final_table_fixture(f: &Value) -> Vec<u8> {
            let mut b = unit_elf(f);
            let mut rows = Vec::new();
            for (index, v) in f["owners"].as_array().unwrap().iter().enumerate() {
                let load = 64 + index * 56;
                let offset = u64::from_le_bytes(b[load + 8..load + 16].try_into().unwrap());
                let address = v["start"].as_u64().unwrap();
                rows.push(Section {
                    name: [".text.gettid", ".text.cxa", ".text.dynamic"][index],
                    kind: 1,
                    flags: 6,
                    address,
                    offset: offset + (address & 4095),
                    size: v["size"].as_u64().unwrap(),
                    link: 0,
                    info: 0,
                    align: 1,
                    entry: 0,
                });
            }
            let mut symbols = vec![0u8; 96];
            let mut strings = vec![0u8];
            for (index, role) in [Role::Dynamic, Role::Gettid, Role::Cxa]
                .into_iter()
                .enumerate()
            {
                put32(&mut symbols, (index + 1) * 24, strings.len() as u32);
                strings.extend_from_slice(role.name().as_bytes());
                strings.push(0);
                symbols[(index + 1) * 24 + 4] = if role == Role::Dynamic { 0 } else { 0x20 };
                symbols[(index + 1) * 24 + 5] = if role == Role::Dynamic { 2 } else { 0 };
            }
            let mut st = append_section(&mut b, ".symtab", 2, &symbols);
            st.link = 5;
            st.info = 2;
            st.entry = 24;
            st.align = 8;
            rows.push(st);
            rows.push(append_section(&mut b, ".strtab", 3, &strings));
            for (index, v) in f["owners"].as_array().unwrap().iter().enumerate() {
                let mut rel = append_section(
                    &mut b,
                    [".rela.gettid", ".rela.cxa", ".rela.dynamic"][index],
                    4,
                    &relocation_rows(v, true),
                );
                rel.link = 4;
                rel.info = (index + 1) as u32;
                rel.entry = 24;
                rel.align = 8;
                rows.push(rel);
            }
            sections(&mut b, rows);
            b
        }
        fn table_census(
            input: &[Vec<u8>],
            final_bytes: &[u8],
            include_dead: bool,
        ) -> Result<(Vec<Use>, usize)> {
            let f = fixture();
            let mut objects = Vec::new();
            let mut map = String::new();
            let names = [
                "std-gettid.rcgu.o",
                "std-cxa.rcgu.o",
                "dl_iterate_phdr.lo",
                "unselected.o",
            ];
            for (index, b) in input.iter().enumerate() {
                objects.push(ObjectInput {
                    archive_path: Path::new("/unit/actual-shape.a"),
                    member_name: names[index],
                    ordinal: index,
                    header_offset: 0,
                    bytes: b,
                    elf: Elf::parse(b).map_err(|e| e.to_string())?,
                });
                if index < 3 || !include_dead {
                    let v = &f["owners"][index % 3];
                    let address = v["start"].as_u64().unwrap();
                    let size = v["size"].as_u64().unwrap();
                    map.push_str(&format!(
                        "{address:x} {address:x} {size:x} 1 /unit/actual-shape.a({}):(.text)\n",
                        names[index]
                    ));
                }
            }
            enumerate(
                &objects,
                &map,
                &Elf::parse(final_bytes).map_err(|e| e.to_string())?,
                final_bytes,
            )
        }
        #[test]
        fn optional_actual_shape_tables_join_all_five_uses_and_record_dead_input() {
            let f = fixture();
            let mut input = f["owners"]
                .as_array()
                .unwrap()
                .iter()
                .map(input_table_fixture)
                .collect::<Vec<_>>();
            let image = final_table_fixture(&f);
            let (uses, dead) = table_census(&input, &image, false).unwrap();
            assert_eq!((uses.len(), dead), (5, 0));
            input.push(input[0].clone());
            let (uses, dead) = table_census(&input, &image, true).unwrap();
            assert_eq!((uses.len(), dead), (5, 2));
        }
        #[test]
        fn optional_table_census_refuses_changed_weak_origin_and_link_authority() {
            let f = fixture();
            let input = f["owners"]
                .as_array()
                .unwrap()
                .iter()
                .map(input_table_fixture)
                .collect::<Vec<_>>();
            let image = final_table_fixture(&f);
            let mut wrong = input.clone();
            let e = Elf::parse(&wrong[0]).unwrap();
            let st = e.section_headers[2].sh_offset as usize;
            wrong[0][st + 24 + 4] = 0x10;
            let error = table_census(&wrong, &image, false).err().unwrap();
            assert!(error.contains("weak"), "{error}");
            let mut bad = image.clone();
            let e = Elf::parse(&bad).unwrap();
            let header = e.header.e_shoff as usize;
            put32(&mut bad, header + 6 * 64 + 40, 1);
            let error = table_census(&input, &bad, false).err().unwrap();
            assert!(error.contains("ownership"), "{error}");
        }
        #[test]
        fn optional_table_census_refuses_duplicate_missing_or_changed_addend_use() {
            let f = fixture();
            let input = f["owners"]
                .as_array()
                .unwrap()
                .iter()
                .map(input_table_fixture)
                .collect::<Vec<_>>();
            let image = final_table_fixture(&f);
            let e = Elf::parse(&image).unwrap();
            let header = e.header.e_shoff as usize;
            let at = e.section_headers[6].sh_offset as usize;
            let mut duplicate = image.clone();
            let row = duplicate[at..at + 24].to_vec();
            duplicate[at + 24..at + 48].copy_from_slice(&row);
            let error = table_census(&input, &duplicate, false).err().unwrap();
            assert!(error.contains("duplicate final optional use"), "{error}");
            let mut missing = image.clone();
            put64(&mut missing, header + 6 * 64 + 32, 24);
            let error = table_census(&input, &missing, false).err().unwrap();
            assert!(error.contains("census differs"), "{error}");
            let mut addend = image.clone();
            put64(&mut addend, at + 16, (-4i64) as u64);
            let error = table_census(&input, &addend, false).err().unwrap();
            assert!(error.contains("census differs"), "{error}");
        }

        #[test]
        fn optional_guard_refuses_recorded_external_entry() {
            let f = fixture();
            let v = &f["owners"][0];
            let c = code(v);
            let g = guarded(v);
            let owner = Owner {
                object: 0,
                section: 1,
                input_start: 0,
                start: v["start"].as_u64().unwrap(),
                size: v["size"].as_u64().unwrap(),
                role: Role::Gettid,
                uses: uses(v),
            };
            let image = final_table_fixture(&f);
            external_guard_entries(&Elf::parse(&image).unwrap(), &image, &owner, &c, &g).unwrap();
            let e = Elf::parse(&image).unwrap();
            let table = e.section_headers[4].sh_offset as usize;
            let mut alias = image.clone();
            put16(&mut alias, table + 24 + 6, 1);
            put64(&mut alias, table + 24 + 8, c[g.begin + 1].address);
            let error =
                external_guard_entries(&Elf::parse(&alias).unwrap(), &alias, &owner, &c, &g)
                    .unwrap_err();
            assert!(error.contains("interior symbol"), "{error}");
            // A section-symbol relocation into the guard has no named alias.
            let mut edge = image.clone();
            edge[table + 24 + 4] = 3;
            put16(&mut edge, table + 24 + 6, 1);
            put64(&mut edge, table + 24 + 8, owner.start);
            let rel = e.section_headers[8].sh_offset as usize;
            put64(&mut edge, rel + 8, (1u64 << 32) | 2);
            put64(
                &mut edge,
                rel + 16,
                c[g.begin + 1].address - owner.start - 4,
            );
            let error = external_guard_entries(&Elf::parse(&edge).unwrap(), &edge, &owner, &c, &g)
                .unwrap_err();
            assert!(error.contains("external entry"), "{error}");
        }

        #[test]
        fn cxa_exact_epilogue_bypass_is_refused_by_continuation() {
            let f = fixture();
            let v = &f["owners"][1];
            let original = code(v);
            let g = guarded(v);
            let at = g.zero + 2;
            assert_eq!(original[at].bytes, [0x75, 0x64]);
            let mut bad = original.clone();
            bad[at].bytes = vec![0xeb, 0x57];
            assert_eq!(
                relative(&bad[at], 1, 1).unwrap(),
                original
                    .iter()
                    .find(|i| i.bytes == [0x48, 0x83, 0xc4, 0x10]
                        && i.address > original[g.zero].address)
                    .unwrap()
                    .address
            );
            // R1's null guard still succeeds and every genuine anchor remains.
            let mut guarded = recognize(role(v), &bad, &uses(v), slot(v)).unwrap();
            let setter = v["input_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["name"] == "pthread_setspecific")
                .unwrap();
            let setter = position(
                &bad,
                v["start"].as_u64().unwrap() + setter["offset"].as_u64().unwrap() - 2,
            )
            .unwrap();
            let error = fallback_windows(role(v), &bad, &mut guarded, &[setter]).unwrap_err();
            assert!(
                error.contains("normal zero-path return bypasses registration"),
                "{error}"
            );
        }
        #[test]
        fn cxa_control_edge_bytes_are_joined_without_tls_fields() {
            let f = fixture();
            let v = &f["owners"][1];
            let c = code(v);
            let g = full_guard(v);
            let image = unit_elf(&f);
            let edge = g.zero + 2;
            let window = g
                .windows
                .iter()
                .find(|(a, b)| *a <= edge && edge < *b)
                .unwrap();
            window_join(v, &c, window.0, window.1, &image, &data(&v["input"])).unwrap();
            let elf = Elf::parse(&image).unwrap();
            let (_, at) = unique_file_mapping(&elf, &image, c[edge].address, 2).unwrap();
            let mut diverted = image.clone();
            diverted[at..at + 2].copy_from_slice(&[0xeb, 0x57]);
            assert!(window_join(v, &c, window.0, window.1, &diverted, &data(&v["input"])).is_err());
            let setters = v["input_relocations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["name"] == "pthread_setspecific")
                .map(|r| {
                    position(
                        &c,
                        v["start"].as_u64().unwrap() + r["offset"].as_u64().unwrap() - 2,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            // A source-changed branch bypassing only the setter must also fail,
            // even when the list-store anchor bytes are left intact.
            let store = c
                .iter()
                .position(|i| i.bytes == [0x49, 0x8b, 0x47, 0x10])
                .unwrap();
            let branch = c.iter().position(|i| i.bytes == [0x74, 0x6d]).unwrap();
            let mut bad = c.clone();
            bad[branch].bytes = vec![
                0xeb,
                i8::try_from(
                    i128::from(c[store].address) - i128::from(next_address(&c[branch]).unwrap()),
                )
                .unwrap() as u8,
            ];
            let mut guard = recognize(role(v), &bad, &uses(v), slot(v)).unwrap();
            let error = fallback_windows(role(v), &bad, &mut guard, &setters).unwrap_err();
            assert!(error.contains("stores bypass real setter"), "{error}");
        }
        #[test]
        fn real_producer_shaped_ledger_retains_named_core_and_direct_tool_binding() {
            struct Scratch(PathBuf);
            impl Drop for Scratch {
                fn drop(&mut self) {
                    let _ = fs::remove_dir_all(&self.0);
                }
            }
            let path = std::env::temp_dir().join(format!(
                "optional-zero-ledger-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            let directory = Scratch(path);
            let mut identities = Vec::new();
            for name in [
                "runtime",
                "libc",
                "elf",
                "map",
                "lld",
                "script",
                "link-stdout",
                "objdump",
            ] {
                let path = directory.0.join(name);
                write_new(&path, name.as_bytes()).unwrap();
                identities.push(FileIdentity::read(&path).unwrap());
            }
            let core = DefinitionCore::new(
                &identities[0],
                &identities[1],
                &identities[2],
                &identities[3],
            );
            // The sole public producer uses this same four-role constructor and
            // then extends, never trims, the complete actual custody ledger.
            let mut files = core.files();
            files.extend(identities[4..7].iter().cloned());
            core.require_ledger(&files).unwrap();
            assert_eq!(files.len(), 7);
            let tool =
                bind_expected(&mut files, &identities[7].path, &identities[7].sha256).unwrap();
            assert_eq!(tool, identities[7]);
            assert_ne!(tool, files[4]);
            assert_eq!(files.len(), 8);
            assert_eq!(core.runtime, identities[0]);
            assert_eq!(core.libc, identities[1]);
            assert_eq!(core.artifact, identities[2]);
            assert_eq!(core.map, identities[3]);
            close_files(&files).unwrap();
            let mut missing = files.clone();
            missing.remove(2);
            assert!(core.require_ledger(&missing).is_err());
            fs::write(&identities[5].path, b"changed retained script").unwrap();
            assert!(close_files(&files).is_err());
        }
    }
}

pub use optional_zero::OptionalSourceInputs;
pub use optional_zero::OptionalZeroObservation;

// Parent-only reuse of the existing private observation. These functions do not
// create observations and are not available to callers of the artifact library.
pub(super) fn optional_final_owner(
    source: &VerifiedStaticSource,
    archive: &StaticArchive,
    observation: &OptionalZeroObservation,
) -> Result<()> {
    observation.require_owner(&source.archive_owner, &archive.file)
}
pub(super) fn optional_final_artifact(
    observation: &OptionalZeroObservation,
    artifact: &FileIdentity,
) -> Result<()> {
    observation.require_artifact(artifact)
}
pub(super) fn optional_final_rows(
    observation: &OptionalZeroObservation,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<()> {
    observation.require_final_rows(elf, bytes)
}

// Parent-only bridge: these checks reuse the sole producer's private proof;
// names, JSON, scalar addresses and a foreign transaction cannot mint it.
fn selected_owner_identity(
    source: &Arc<ArchiveSourceOwner>,
    runtime: &FileIdentity,
    proof_owner: &DefinitionSourceOwner,
    core: &DefinitionCore,
) -> Result<()> {
    require(
        Arc::ptr_eq(source, &proof_owner.0),
        "selected final inspection belongs to another source transaction",
    )?;
    require(
        core.runtime == *runtime,
        "selected final runtime archive differs",
    )
}
pub(super) fn selected_final_owner(
    source: &VerifiedStaticSource,
    archive: &StaticArchive,
    definitions: &SelectedInitializerDefinitions,
) -> Result<()> {
    selected_owner_identity(
        &source.archive_owner,
        &archive.file,
        &definitions.source_owner,
        &definitions.core,
    )
}
pub(super) fn selected_final_artifact(
    definitions: &SelectedInitializerDefinitions,
    artifact: &FileIdentity,
) -> Result<()> {
    require(
        definitions.core.artifact == *artifact,
        "selected final artifact differs",
    )
}
fn selected_symbol_shape(symbol: &sym::Sym, definition: &RelocatedDefinition) -> Result<()> {
    require(
        symbol.st_type() == sym::STT_FUNC
            && symbol.st_size > 0
            && symbol.st_size == definition.bytes as u64
            && symbol.st_value == definition.address
            && (symbol.st_bind() == sym::STB_GLOBAL
                || (symbol.st_bind() == sym::STB_LOCAL
                    && symbol.st_visibility() == sym::STV_HIDDEN)),
        "selected final function differs from joined strong input",
    )
}
pub(super) fn selected_final_function(
    definitions: &SelectedInitializerDefinitions,
    elf: &Elf<'_>,
    bytes: &[u8],
    name: &str,
) -> Result<Option<sym::Sym>> {
    let definition = match name {
        "__init_tls" => &definitions.tls,
        "__libc_malloc" => &definitions.malloc_alias,
        "__libc_free" => &definitions.free_alias,
        _ => return Ok(None),
    };
    let symbol = named(elf, name)?;
    selected_symbol_shape(&symbol, definition)?;
    mapped_bytes(elf, bytes, symbol.st_value, symbol.st_size, 5)?;
    Ok(Some(symbol))
}
