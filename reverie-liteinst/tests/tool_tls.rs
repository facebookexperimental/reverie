//! Closed owned-TLS inventory for the authenticated standalone DEV runtime.
//! Optimized and Detcore images have different emission; the existing runtime
//! consumer supplies the exact DEV/source/fixture recipe, without input skips.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;

use goblin::elf::Elf;
use goblin::elf::header;
use goblin::elf::program_header;
use goblin::elf::section_header;
use goblin::elf::sym;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;

use liteinst_runtime::artifact;

// Complete Rust-v0 identities from the actual DEV emission, with only crate
// disambiguators removed. The first sixteen are production cells; MARKER is
// the retained allocator-fixture diagnostic. No CURRENT_EVENT replacement is
// allowed, even if its spelling changes or an existing cell disappears.
const EXPECTED: [(&str, u64); 17] = [
    (
        "_RNvNCNKNvNtCs_16reverie_liteinst11patch_alloc18INSTALLATION_DEPTH0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock15RCB_CLOCK_OWNER0s_023___RUST_STD_INTERNAL_VAL",
        4,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock16RCB_CLOCK_OFFSET0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock17RCB_HANDLER_DEPTH0s_023___RUST_STD_INTERNAL_VAL",
        4,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock17RCB_HANDLER_ENTRY0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock18RCB_CLOCK_RESTORED0s_023___RUST_STD_INTERNAL_VAL",
        1,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock18RCB_COUNTER_ORIGIN0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock21RCB_CLOCK_UNAVAILABLE0s_023___RUST_STD_INTERNAL_VAL",
        1,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock21RCB_HANDLER_DEDUCTION0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5clock9RCB_CLOCK0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest5alloc14DISPATCH_DEPTH0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest7support20TOOL_CALLBACK_ACTIVE0s_023___RUST_STD_INTERNAL_VAL",
        1,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest12continuation5OWNER0s_023___RUST_STD_INTERNAL_VAL",
        8,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest12continuation5READY0s_023___RUST_STD_INTERNAL_VAL",
        1,
    ),
    (
        "_RNvNCNKNvNtNtCs_15reverie_inguest5guest12continuation7PENDING0s_023___RUST_STD_INTERNAL_VAL",
        16,
    ),
    (
        "_RNvNCNKNvNtCs_15reverie_inguest4trap10IN_HANDLER0s_023___RUST_STD_INTERNAL_VAL",
        1,
    ),
    (
        "_RNvNCNKNvNtCs_16reverie_liteinst13stack_fixture6MARKER0s_023___RUST_STD_INTERNAL_VAL",
        64,
    ),
];

fn demand(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

// Same bounded Cs<alphanumeric>_ normalization as m1_artifact's private
// canonical_rust_symbol. Preserve everything else, including LLVM suffixes.
fn canonical_rust_symbol(name: &str) -> Option<String> {
    if !name.starts_with("_R") {
        return None;
    }
    let mut canonical = String::new();
    let mut remaining = name;
    while let Some(offset) = remaining.find("Cs") {
        canonical.push_str(&remaining[..offset]);
        remaining = &remaining[offset + 2..];
        let end = remaining
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric())
            .count();
        if end == 0 || remaining.as_bytes().get(end) != Some(&b'_') {
            return None;
        }
        canonical.push_str("Cs_");
        remaining = &remaining[end + 1..];
    }
    canonical.push_str(remaining);
    Some(canonical)
}

struct TlsCell {
    table: &'static str,
    index: usize,
    symbol: sym::Sym,
    name: String,
    canonical: Option<String>,
    owned: bool,
}

fn cells(elf: &Elf<'_>) -> Result<Vec<TlsCell>, String> {
    let mut result = Vec::new();
    for (table, symbols, strings) in [
        ("symtab", &elf.syms, &elf.strtab),
        ("dynsym", &elf.dynsyms, &elf.dynstrtab),
    ] {
        for (index, symbol) in symbols.iter().enumerate() {
            if symbol.st_type() != sym::STT_TLS {
                if let Some(name) = strings.get_at(symbol.st_name) {
                    let owned =
                        name.contains("reverie_liteinst") || name.contains("reverie_inguest");
                    demand(
                        !owned
                            || elf
                                .section_headers
                                .get(symbol.st_shndx)
                                .is_none_or(|section| {
                                    section.sh_flags & u64::from(section_header::SHF_TLS) == 0
                                }),
                        format!("owned TLS section storage has non-STT_TLS definition: {name}"),
                    )?;
                }
                continue;
            }
            let name = strings
                .get_at(symbol.st_name)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("undecodable TLS name in {table}[{index}]"))?;
            result.push(TlsCell {
                table,
                index,
                symbol,
                name: name.to_owned(),
                canonical: canonical_rust_symbol(name),
                // Conservative refusal for unfamiliar owned mangling. A new
                // owned role must never be classified as foreign by default.
                owned: name.contains("reverie_liteinst") || name.contains("reverie_inguest"),
            });
        }
    }
    Ok(result)
}

fn extent(start: u64, size: u64) -> Result<u64, String> {
    start.checked_add(size).ok_or("TLS extent overflow".into())
}

fn validate_layout(elf: &Elf<'_>, bytes: &[u8], cells: &[TlsCell]) -> Result<(), String> {
    demand(
        elf.is_64
            && elf.little_endian
            && elf.header.e_machine == header::EM_X86_64
            && elf.header.e_type == header::ET_DYN,
        "inventory requires the actual x86-64 ELF shared runtime",
    )?;
    let segments: Vec<_> = elf
        .program_headers
        .iter()
        .filter(|segment| segment.p_type == program_header::PT_TLS)
        .collect();
    demand(segments.len() == 1, "missing/ambiguous PT_TLS")?;
    let tls = segments[0];
    demand(
        tls.p_memsz > 0
            && tls.p_filesz <= tls.p_memsz
            && tls.p_align.is_power_of_two()
            && tls.p_vaddr % tls.p_align == tls.p_offset % tls.p_align
            && extent(tls.p_offset, tls.p_filesz)? <= bytes.len() as u64,
        "malformed PT_TLS definition/file extent/alignment",
    )?;
    extent(tls.p_vaddr, tls.p_memsz)?;
    let mut sections = BTreeMap::new();
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_flags & u64::from(section_header::SHF_TLS) == 0 {
            continue;
        }
        let start = section
            .sh_addr
            .checked_sub(tls.p_vaddr)
            .ok_or("TLS section precedes PT_TLS")?;
        let end = extent(start, section.sh_size)?;
        demand(
            section.sh_size > 0
                && section.sh_flags
                    & u64::from(section_header::SHF_ALLOC | section_header::SHF_WRITE)
                    == u64::from(section_header::SHF_ALLOC | section_header::SHF_WRITE)
                && section.sh_flags & u64::from(section_header::SHF_EXECINSTR) == 0
                && section.sh_addralign.is_power_of_two()
                && section.sh_addralign <= tls.p_align
                && section.sh_addr % section.sh_addralign == 0
                && end <= tls.p_memsz,
            format!("invalid TLS section definition/range/alignment: section {index}"),
        )?;
        match section.sh_type {
            section_header::SHT_PROGBITS => demand(
                end <= tls.p_filesz
                    && section.sh_offset == extent(tls.p_offset, start)?
                    && extent(section.sh_offset, section.sh_size)? <= bytes.len() as u64,
                "TLS initialized section is outside PT_TLS file span",
            )?,
            section_header::SHT_NOBITS => demand(
                start >= tls.p_filesz,
                "TLS zero-fill section overlaps initialized PT_TLS span",
            )?,
            _ => return Err("invalid TLS section type".into()),
        }
        demand(
            sections
                .values()
                .all(|&(other_start, other_end)| end <= other_start || start >= other_end),
            "overlapping TLS sections",
        )?;
        sections.insert(index, (start, end));
    }
    demand(!sections.is_empty(), "missing allocated TLS sections")?;
    let mut ranges = Vec::new();
    for cell in cells {
        let symbol = &cell.symbol;
        if cell.owned {
            demand(
                cell.table == "symtab"
                    && symbol.st_bind() == sym::STB_LOCAL
                    && symbol.st_other == sym::STV_HIDDEN,
                format!("bad owned TLS definition/binding/visibility: {}", cell.name),
            )?;
        }
        // Foreign imports do not define storage in this image. Defined foreign
        // rows remain visible and participate in overlap checks, without any
        // claimed removal or recipe-independent foreign count.
        if !cell.owned && symbol.st_shndx == section_header::SHN_UNDEF as usize {
            continue;
        }
        let &(start, end) = sections.get(&symbol.st_shndx).ok_or_else(|| {
            format!(
                "TLS definition outside allocated TLS sections: {}",
                cell.name
            )
        })?;
        let symbol_end = extent(symbol.st_value, symbol.st_size)?;
        demand(
            symbol.st_size > 0 && symbol.st_value >= start && symbol_end <= end,
            format!("TLS symbol outside section/PT_TLS range: {}", cell.name),
        )?;
        // A foreign dynamic alias is another view of storage already in symtab.
        // Owned dynamic definitions were refused above, rather than deduplicated.
        if cell.table == "symtab" {
            demand(
                ranges.iter().all(|&(other_start, other_end)| {
                    symbol_end <= other_start || symbol.st_value >= other_end
                }),
                format!("overlapping TLS symbols: {}", cell.name),
            )?;
            ranges.push((symbol.st_value, symbol_end));
        }
    }
    Ok(())
}

fn validate_inventory(elf: &Elf<'_>, bytes: &[u8], cells: &[TlsCell]) -> Result<(), String> {
    let mut owned = BTreeMap::new();
    for cell in cells.iter().filter(|cell| cell.owned) {
        let role = cell
            .canonical
            .as_deref()
            .ok_or_else(|| format!("unclassifiable owned TLS role: {}", cell.name))?;
        demand(
            owned.insert(role, cell).is_none(),
            format!("duplicate owned TLS role: {role}"),
        )?;
    }
    validate_layout(elf, bytes, cells)?;
    let mut differences = Vec::new();
    for (&role, cell) in &owned {
        if !EXPECTED.iter().any(|&(expected, _)| role == expected) {
            differences.push(format!(
                "unexpected owned TLS role {role}: size={} offset={:#x} raw={}",
                cell.symbol.st_size, cell.symbol.st_value, cell.name,
            ));
        }
    }
    for (role, size) in EXPECTED {
        match owned.get(role) {
            None => differences.push(format!("missing retained owned TLS role {role}")),
            Some(cell) if cell.symbol.st_size != size => differences.push(format!(
                "wrong owned TLS size {role}: expected={size} actual={}",
                cell.symbol.st_size,
            )),
            Some(_) => {}
        }
    }
    demand(
        differences.is_empty(),
        format!(
            "DEV owned TLS inventory differs from 16 production cells plus MARKER (observed {} owned):\n{}",
            owned.len(),
            differences.join("\n"),
        ),
    )
}

fn diagnostic(elf: &Elf<'_>, cells: &[TlsCell]) -> String {
    let mut output = String::new();
    for segment in &elf.program_headers {
        if segment.p_type == program_header::PT_TLS {
            writeln!(
                output,
                "PT_TLS offset={:#x} vaddr={:#x} filesz={:#x} memsz={:#x} align={:#x}",
                segment.p_offset,
                segment.p_vaddr,
                segment.p_filesz,
                segment.p_memsz,
                segment.p_align
            )
            .unwrap();
        }
    }
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_flags & u64::from(section_header::SHF_TLS) != 0 {
            writeln!(output, "TLS section[{index}] name={:?} type={} flags={:#x} addr={:#x} offset={:#x} size={:#x} align={:#x}",
                elf.shdr_strtab.get_at(section.sh_name), section.sh_type, section.sh_flags,
                section.sh_addr, section.sh_offset, section.sh_size, section.sh_addralign).unwrap();
        }
    }
    writeln!(
        output,
        "STT_TLS total={} owned={} foreign={}",
        cells.len(),
        cells.iter().filter(|cell| cell.owned).count(),
        cells.iter().filter(|cell| !cell.owned).count()
    )
    .unwrap();
    for cell in cells {
        writeln!(output, "{}[{}] offset={:#x} size={} bind={} other={} section={} owned={} raw={} canonical={:?}",
            cell.table, cell.index, cell.symbol.st_value, cell.symbol.st_size,
            cell.symbol.st_bind(), cell.symbol.st_other, cell.symbol.st_shndx,
            cell.owned, cell.name, cell.canonical).unwrap();
    }
    output
}

fn authenticated_bytes() -> Result<Vec<u8>, String> {
    let runtime = liteinst_runtime::required_runtime()?;
    let bytes =
        fs::read(&runtime.path).map_err(|error| format!("read qualified runtime: {error}"))?;
    demand(
        artifact::sha256(&bytes) == runtime.receipt.artifact.sha256,
        "runtime bytes changed after DEV qualification",
    )?;
    Ok(bytes)
}

#[test]
fn authenticated_dev_runtime_has_only_retained_tool_tls() -> Result<(), String> {
    let runtime = liteinst_runtime::required_runtime()?;
    let evidence = liteinst_runtime::evidence_directory("tool-tls")?;
    let bytes = authenticated_bytes()?;
    let elf = Elf::parse(&bytes).map_err(|error| format!("qualified runtime ELF: {error}"))?;
    let cells = cells(&elf)?;
    let inventory = format!(
        "runtime={} sha256={} receipt={} source_head={} source_tree={} profile={} features={:?} cargo_profile={}\n{}",
        runtime.path.display(),
        runtime.receipt.artifact.sha256,
        runtime.receipt_path.display(),
        runtime.source.head,
        runtime.source.tree,
        runtime.receipt.profile_name,
        runtime.receipt.cargo_artifact.features,
        runtime.receipt.cargo_artifact.profile,
        diagnostic(&elf, &cells),
    );
    artifact::write_new(
        &evidence.join("tool-tls.inventory.txt"),
        inventory.as_bytes(),
    )?;
    eprintln!("{inventory}Tool TLS raw evidence: {}", evidence.display());
    let result = validate_inventory(&elf, &bytes, &cells);
    if let Err(error) = &result {
        artifact::write_new(&evidence.join("tool-tls.failure.txt"), error.as_bytes())?;
    }
    // Preserve the source/artifact identity check even for the intended real
    // baseline inventory failure. A setup mismatch is never failing-first proof.
    liteinst_runtime::verify_unchanged(&evidence)?;
    result.map_err(|error| format!("{error}; raw inventory {}", evidence.display()))
}

// Negative controls modify a private byte copy of the authenticated ELF. They
// neither load it nor rewrite the producer artifact, receipt or source. Each
// named refusal must be observed, even when baseline CURRENT_EVENT is present.
fn reject_mutation(
    original: &[u8],
    edit: impl FnOnce(&mut [u8]),
    expected: &str,
) -> Result<(), String> {
    let mut changed = original.to_vec();
    edit(&mut changed);
    let elf =
        Elf::parse(&changed).map_err(|error| format!("negative control ELF parse: {error}"))?;
    let result = cells(&elf).and_then(|cells| validate_inventory(&elf, &changed, &cells));
    match result {
        Err(error) if error.contains(expected) => Ok(()),
        result => Err(format!(
            "negative control must refuse {expected:?}, observed {result:?}"
        )),
    }
}

#[test]
fn authenticated_elf_mutations_cannot_hide_owned_tls() -> Result<(), String> {
    let bytes = authenticated_bytes()?;
    let elf = Elf::parse(&bytes).map_err(|error| format!("qualified runtime ELF: {error}"))?;
    let cells = cells(&elf)?;
    validate_layout(&elf, &bytes, &cells)?;
    let find = |role| {
        let matching: Vec<_> = cells
            .iter()
            .filter(|cell| cell.table == "symtab" && cell.canonical.as_deref() == Some(role))
            .collect();
        demand(
            matching.len() == 1,
            "negative control requires one actual retained cell",
        )?;
        Ok::<_, String>(matching[0])
    };
    let depth = find(EXPECTED[0].0)?;
    let ready = find(EXPECTED[13].0)?;
    let clock = find(EXPECTED[2].0)?;
    let tables: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|section| section.sh_type == section_header::SHT_SYMTAB)
        .collect();
    demand(
        tables.len() == 1 && tables[0].sh_entsize == 24,
        "negative controls require actual ELF64 symtab",
    )?;
    let table = tables[0];
    let entry = |cell: &TlsCell| -> Result<usize, String> {
        let offset = extent(table.sh_offset, cell.index as u64 * 24)?;
        demand(
            extent(offset, 24)? <= bytes.len() as u64,
            "negative-control symtab entry outside file",
        )?;
        usize::try_from(offset).map_err(|_| "negative-control offset overflow".into())
    };
    let depth_entry = entry(depth)?;
    let ready_entry = entry(ready)?;
    let strings = elf
        .section_headers
        .get(table.sh_link as usize)
        .ok_or("negative-control symtab strings missing")?;
    let name_offset = usize::try_from(extent(strings.sh_offset, depth.symbol.st_name as u64)?)
        .map_err(|_| "negative-control name offset overflow")?;
    let spelling = depth
        .name
        .find("INSTALLATION_DEPTH")
        .ok_or("negative-control role spelling missing")?;
    let renamed_role = EXPECTED[0]
        .0
        .replace("INSTALLATION_DEPTH", "INSTALLATION_DEPTX");
    reject_mutation(
        &bytes,
        |changed| {
            changed[name_offset + spelling + "INSTALLATION_DEPTH".len() - 1] = b'X';
        },
        &format!("unexpected owned TLS role {renamed_role}"),
    )?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[ready_entry..ready_entry + 24]
                .copy_from_slice(&bytes[depth_entry..depth_entry + 24]);
        },
        &format!("duplicate owned TLS role: {}", EXPECTED[0].0),
    )?;
    let disambiguator_end = depth
        .name
        .find("_16reverie_liteinst")
        .ok_or("negative-control crate disambiguator boundary missing")?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[name_offset + disambiguator_end] = b'!';
        },
        "unclassifiable owned TLS role",
    )?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[depth_entry + 16..depth_entry + 24].copy_from_slice(&4_u64.to_le_bytes());
        },
        &format!(
            "wrong owned TLS size {}: expected=8 actual=4",
            EXPECTED[0].0
        ),
    )?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[depth_entry + 4] = sym::STT_OBJECT;
        },
        "owned TLS section storage has non-STT_TLS definition",
    )?;
    let tls = elf
        .program_headers
        .iter()
        .find(|segment| segment.p_type == program_header::PT_TLS)
        .ok_or("negative-control PT_TLS missing")?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[depth_entry + 8..depth_entry + 16].copy_from_slice(&tls.p_memsz.to_le_bytes());
        },
        "TLS symbol outside section/PT_TLS range",
    )?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[depth_entry + 6..depth_entry + 8].copy_from_slice(&0_u16.to_le_bytes());
        },
        "TLS definition outside allocated TLS sections",
    )?;
    reject_mutation(
        &bytes,
        |changed| {
            changed[depth_entry + 8..depth_entry + 16]
                .copy_from_slice(&clock.symbol.st_value.to_le_bytes());
        },
        "overlapping TLS symbols",
    )?;
    let evidence = liteinst_runtime::evidence_directory("tool-tls-negative-controls")?;
    liteinst_runtime::verify_unchanged(&evidence)
}
