//! One finite installer normal-return connection, under the genuine leaf owner.
//! No complete-entry fact is issued: caller FDE/CIE/LSDA and async/frame facts
//! are explicitly unjoined. Generic FF and startup admission remain unchanged.
use super::*;

const INSTALLER: &str = "_RNvMs0_NtNtNtNtCs_15reverie_inguest5guest12exec_private14mapped_initial10libc_relayNtB7_21CapturedMappedInitial18install_libc_relay";
const INSTALLER_SOURCE: &str =
    "reverie-inguest/src/guest/exec_private/mapped_initial/libc_relay.rs";
const INSTALLER_SOURCE_SHA: &str =
    "f6689fc40a20d9f3f566dbe37655de6dad0f97b86e8882c4951fa13504a1a3b3";
const INSTALLER_BYTES: usize = 5206;
// Exact retained GNU instruction-decoder tool, not a caller-selected decoder.
const OBJDUMP_SHA: &str = "0a1b558f444ed2bca7fb467dede7416a651bc490b1abc77705ab470d99c527c1";
// This binds the reviewed whole input, including frame instructions outside the
// small slices. It is NOT the dataflow proof: normal_cfg and both finite slices
// below establish the normal-control connection, with physical premises open.
const INSTALLER_INPUT_SHA: &str =
    "c8ce2c99cd3f556906c3051f99c703ca5bb4776206bd6a7e39f0601166e60985";
const ARM_OFFSETS: [usize; 4] = [2093, 2129, 2105, 2117];
const CALL: usize = 2058;
const DISPATCH: usize = 2091;
const BODY_ENTRY: usize = 2035;
const BACKEDGE: usize = 2446;
const CALL_FIELDS: [usize; 2] = [2021, 2435];
const TABLE_FIELDS: [usize; 2] = [2028, 2442];
const CORE_START: usize = 2005;
const CORE_END: usize = 2139;
const CORE: &[u8] = &[
    0x45, 0x31, 0xff, 0x48, 0x8d, 0x7c, 0x24, 0x10, 0x4c, 0x8d, 0x74, 0x24, 0x60, 0x48, 0x8b, 0x0d,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x45, 0x31, 0xe4, 0x48, 0x8b,
    0x43, 0x10, 0x48, 0x89, 0x44, 0x24, 0x70, 0x0f, 0x10, 0x03, 0x0f, 0x29, 0x44, 0x24, 0x60, 0x4c,
    0x89, 0xf6, 0x4c, 0x89, 0xfa, 0xff, 0xd1, 0x0f, 0xb6, 0x44, 0x24, 0x28, 0x3d, 0xff, 0x00, 0x00,
    0x00, 0x0f, 0x84, 0xae, 0xfb, 0xff, 0xff, 0x89, 0xc0, 0x49, 0x63, 0x44, 0x85, 0x00, 0x4c, 0x01,
    0xe8, 0x4c, 0x89, 0x7c, 0x24, 0x48, 0xff, 0xe0, 0xb8, 0x9e, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4c,
    0x24, 0x0f, 0xeb, 0x22, 0xb8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x0d, 0xeb, 0x16,
    0xb8, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x0c, 0xeb, 0x0a, 0xb8, 0xda, 0x00, 0x00,
    0x00, 0x48, 0x8d, 0x4c, 0x24, 0x0e,
];
const CORE_ROWS: &[(usize, usize)] = &[
    (2005, 3),
    (2008, 5),
    (2013, 5),
    (2018, 7),
    (2025, 7),
    (2032, 3),
    (2035, 4),
    (2039, 5),
    (2044, 3),
    (2047, 5),
    (2052, 3),
    (2055, 3),
    (2058, 2),
    (2060, 5),
    (2065, 5),
    (2070, 6),
    (2076, 2),
    (2078, 5),
    (2083, 3),
    (2086, 5),
    (2091, 2),
    (2093, 5),
    (2098, 5),
    (2103, 2),
    (2105, 5),
    (2110, 5),
    (2115, 2),
    (2117, 5),
    (2122, 5),
    (2127, 2),
    (2129, 5),
    (2134, 5),
];
const RELOAD_START: usize = 2403;
const RELOAD_END: usize = 2452;
const RELOAD: &[u8] = &[
    0x49, 0x89, 0xdc, 0x4c, 0x8b, 0x7c, 0x24, 0x48, 0x4c, 0x3b, 0xbc, 0x24, 0x90, 0x00, 0x00, 0x00,
    0x48, 0x8d, 0x9c, 0x24, 0xd8, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x7c, 0x24, 0x10, 0x48, 0x8b, 0x0d,
    0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x85, 0x5f, 0xfe, 0xff,
    0xff,
];
const RELOAD_ROWS: &[(usize, usize)] = &[
    (2403, 3),
    (2406, 5),
    (2411, 8),
    (2419, 8),
    (2427, 5),
    (2432, 7),
    (2439, 7),
    (2446, 6),
];

/// Conditional local normal-flow observation, never an executable capability.
/// Private construction, no Deserialize/Clone or conversion to an entry permit.
#[derive(Debug, Serialize)]
pub struct ViewSiteInstallerObservation {
    runtime_archive: FileIdentity,
    artifact: FileIdentity,
    link_map: FileIdentity,
    source: FileIdentity,
    objdump: FileIdentity,
    disassembly: FileIdentity,
    member_name: String,
    member_ordinal: usize,
    member_header: u64,
    member_sha256: String,
    input_sha256: String,
    final_sha256: String,
    entry: u64,
    call: u64,
    leaf_entry: u64,
    result_frame_offset: usize,
    result_discriminator_offset: usize,
    operation_table: u64,
    targets: [u64; 4],
    decoded_instructions: usize,
    source_object_join: &'static str,
    normal_return_connection: &'static str,
    complete_entry_fact: &'static str,
    required_unjoined: [&'static str; 4],
}
impl ViewSiteInstallerObservation {
    /// Actual proved local dispatch coordinate, not permission to execute it.
    pub fn dispatch(&self) -> u64 {
        self.entry + DISPATCH as u64
    }
}

/// Source-catalog digest; callers cannot supply a proof implementation identity.
pub fn view_site_caller_implementation_sha256() -> String {
    sha256(include_bytes!("caller.rs"))
}

fn input_shape(input: &[u8]) -> Result<()> {
    require(
        input.len() == INSTALLER_BYTES && sha256(input) == INSTALLER_INPUT_SHA,
        "installer complete reviewed input form differs",
    )?;
    finite_slices(input)
}
fn finite_slices(input: &[u8]) -> Result<()> {
    require(
        input.get(CORE_START..CORE_END) == Some(CORE)
            && input.get(RELOAD_START..RELOAD_END) == Some(RELOAD),
        "installer result/call/error/table/reload slice differs",
    )
}
fn offset(entry: u64, n: usize) -> Result<u64> {
    entry
        .checked_add(u64::try_from(n).map_err(|_| "installer offset width")?)
        .ok_or("installer address overflow".into())
}

// This classifies control edges of ALREADY decoded and byte-verified complete
// instructions. It is not a second x86 decoder and never scans arbitrary bytes.
// Every unknown indirect jump refuses. Other calls have only ordinary ABI
// fallthrough, explicitly NOT a callee/exception/no-unwind qualification.
fn successors(
    i: &EncodedConstructorInstruction,
    bounds: &BTreeSet<u64>,
    end: u64,
    dispatch: u64,
    arms: &[u64; 4],
) -> Result<Vec<u64>> {
    let b = &i.bytes;
    let prefix = b
        .iter()
        .take_while(|x| {
            matches!(
                **x,
                0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0x40
                    ..=0x4f
            )
        })
        .count();
    let op = *b.get(prefix).ok_or("installer prefix-only instruction")?;
    let next = i
        .address
        .checked_add(b.len() as u64)
        .ok_or("installer next overflow")?;
    let fall = || {
        if next < end {
            Ok(vec![next])
        } else if next == end {
            Ok(Vec::new())
        } else {
            Err("installer decoded instruction escapes body".into())
        }
    };
    let relative = |start: usize, width: usize| -> Result<u64> {
        require(
            prefix == 0 && b.len() == start + width,
            "installer prefixed/truncated direct edge",
        )?;
        let d = match width {
            1 => i64::from(b[start] as i8),
            4 => i64::from(i32::from_le_bytes(
                b[start..].try_into().map_err(|_| "installer rel32 width")?,
            )),
            _ => return Err("installer edge width".into()),
        };
        next.checked_add_signed(d)
            .ok_or("installer branch overflow".into())
    };
    if op == 0xc3 {
        require(prefix == 0 && b.len() == 1, "installer RET form")?;
        return Ok(Vec::new());
    }
    require(
        !matches!(
            op,
            0x9a | 0xea | 0xca | 0xcb | 0xcf | 0xc2 | 0xcc | 0xcd | 0xce | 0xf1 | 0xf4
        ),
        "installer unknown/system/interrupt/return predecessor",
    )?;
    if op == 0xff {
        let group = (*b.get(prefix + 1).ok_or("installer truncated FF")? >> 3) & 7;
        if group == 4 {
            require(
                i.address == dispatch && b.as_slice() == [0xff, 0xe0],
                "installer unknown indirect predecessor",
            )?;
            return Ok(arms.to_vec());
        }
        require(
            !matches!(group, 3 | 5),
            "installer far indirect predecessor",
        )?;
        return fall(); // group2 ordinary call; 0/1/6 data/stack operations.
    }
    if op == 0xe8 {
        let target = relative(1, 4)?;
        require(
            !bounds
                .first()
                .is_some_and(|first| *first <= target && target < end),
            "installer interior call entry is not proved",
        )?;
        return fall();
    }
    let (target, conditional) = if matches!(op, 0xe9 | 0xeb) {
        (Some(relative(1, if op == 0xeb { 1 } else { 4 })?), false)
    } else if matches!(op,0x70..=0x7f|0xe0..=0xe3) {
        (Some(relative(1, 1)?), true)
    } else if op == 0x0f && b.get(prefix + 1).is_some_and(|x| (0x80..=0x8f).contains(x)) {
        (Some(relative(2, 4)?), true)
    } else {
        (None, false)
    };
    if let Some(target) = target {
        require(
            bounds.contains(&target),
            "installer external/interior direct predecessor",
        )?;
        let mut out = vec![target];
        if conditional {
            out.extend(fall()?);
        }
        return Ok(out);
    }
    require(
        !(op == 0x0f
            && b.get(prefix + 1)
                .is_some_and(|x| matches!(*x, 0x05 | 0x07 | 0x0b | 0x34 | 0x35 | 0x37 | 0xaa))),
        "installer unqualified system/terminal instruction",
    )?;
    fall()
}

fn normal_cfg(entry: u64, instructions: &[EncodedConstructorInstruction]) -> Result<()> {
    let (first, bounds) = preparation_instruction_boundaries(instructions)?;
    let end = offset(entry, INSTALLER_BYTES)?;
    require(
        first == entry
            && instructions
                .last()
                .is_some_and(|i| i.address.checked_add(i.bytes.len() as u64) == Some(end)),
        "installer incomplete decoded body",
    )?;
    for rows in [CORE_ROWS, RELOAD_ROWS] {
        for &(o, n) in rows {
            require(
                instructions.iter().any(|i| {
                    i.address == offset(entry, o).unwrap_or(u64::MAX) && i.bytes.len() == n
                }),
                "installer finite instruction boundaries differ",
            )?;
        }
    }
    let arms = ARM_OFFSETS
        .map(|n| offset(entry, n))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let arms: [u64; 4] = arms.try_into().map_err(|_| "installer arms count")?;
    require(
        arms.iter().all(|a| bounds.contains(a)),
        "installer arm not decoded boundary",
    )?;
    let protected = |a: u64| -> bool {
        [(CORE_START, CORE_END), (RELOAD_START, RELOAD_END)]
            .iter()
            .any(|(s, z)| {
                offset(entry, *s).is_ok_and(|s| s <= a) && offset(entry, *z).is_ok_and(|z| a < z)
            })
    };
    for i in instructions {
        for to in successors(i, &bounds, end, offset(entry, DISPATCH)?, &arms)? {
            require(
                bounds.contains(&to),
                "installer normal edge not decoded boundary",
            )?;
            if !protected(to) {
                continue;
            }
            let normal_next = i.address.checked_add(i.bytes.len() as u64) == Some(to);
            let from_core = protected(i.address);
            // Only the exact validated slices may create internal branches.
            // Outside predecessors can fall through into either slice START,
            // never into its middle, its post-call load or post-error index.
            let entering_start =
                to == offset(entry, CORE_START)? || to == offset(entry, RELOAD_START)?;
            require(
                from_core || (normal_next && entering_start),
                "installer predecessor bypasses call/result/error/reload chain",
            )?;
        }
    }
    // The complete input's exact branch operands give the unique loop edge.
    let back = instructions
        .iter()
        .find(|i| i.address == offset(entry, BACKEDGE).unwrap_or(u64::MAX))
        .ok_or("installer backedge absent")?;
    require(
        successors(back, &bounds, end, offset(entry, DISPATCH)?, &arms)?
            .contains(&offset(entry, BODY_ENTRY)?),
        "installer backedge does not reload actual result/call/table",
    )
}

fn aliases(o: &ObjectInput<'_>, code: usize, table: usize, name: &str) -> Result<()> {
    for (section, is_code) in [(code, true), (table, false)] {
        let mut function = 0;
        let mut section_count = 0;
        for s in o.elf.syms.iter().filter(|s| s.st_shndx == section) {
            if s.st_type() == sym::STT_SECTION {
                section_symbol(o, &s, section)?;
                section_count += 1;
            } else {
                require(
                    is_code
                        && o.elf.strtab.get_at(s.st_name) == Some(name)
                        && s.st_type() == sym::STT_FUNC
                        && s.st_bind() == sym::STB_GLOBAL
                        && s.st_other == 0
                        && s.st_value == 0
                        && s.st_size == INSTALLER_BYTES as u64,
                    "installer input alias/interior entry differs",
                )?;
                function += 1;
            }
        }
        require(
            section_count == 1 && function == usize::from(is_code),
            "installer input alias census differs",
        )?;
    }
    Ok(())
}

fn emitted_fields(
    elf: &Elf<'_>,
    bytes: &[u8],
    address: u64,
    size: usize,
    section: usize,
) -> Result<Vec<FinalRelocation>> {
    let tab = checked_symtab(elf, bytes)?;
    checked_relocation_inventory(elf, bytes, tab)?;
    let end = offset(address, size)?;
    let mut out = Vec::new();
    for (idx, rows) in &elf.shdr_relocs {
        let rs = checked_relocation_section(elf, bytes, *idx, tab, rows.len())?;
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
                    && r.r_offset.checked_add(4).is_some_and(|z| z <= end),
                "installer final writer crosses/declares wrong section",
            )?;
            let s = elf
                .syms
                .get(r.r_sym)
                .ok_or("installer final target symbol absent")?;
            out.push(FinalRelocation {
                offset: usize::try_from(r.r_offset - address)
                    .map_err(|_| "installer field offset")?,
                kind: r.r_type,
                addend: r.r_addend.ok_or("installer final RELA addend absent")?,
                symbol_value: s.st_value,
            });
        }
    }
    out.sort_by_key(|r| r.offset);
    Ok(out)
}
fn input_fields_all(
    map: &str,
    o: &ObjectInput<'_>,
    section: usize,
    objects: &[ObjectInput<'_>],
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<Vec<InputRelocation>> {
    let tab = checked_symtab(&o.elf, o.bytes)?;
    checked_relocation_inventory(&o.elf, o.bytes, tab)?;
    let mut out = Vec::new();
    for (idx, rows) in &o.elf.shdr_relocs {
        let rs = checked_relocation_section(&o.elf, o.bytes, *idx, tab, rows.len())?;
        if rs.sh_info as usize != section {
            continue;
        }
        for r in rows.iter() {
            require(
                checked_relocation_span(&o.elf, rs, r.r_offset, r.r_type)? == Some(4)
                    && matches!(
                        r.r_type,
                        reloc::R_X86_64_PC32 | reloc::R_X86_64_PLT32 | reloc::R_X86_64_GOTPCREL
                    ),
                "installer unsupported input writer",
            )?;
            out.push(InputRelocation {
                offset: usize::try_from(r.r_offset).map_err(|_| "installer input offset")?,
                kind: r.r_type,
                addend: r.r_addend.ok_or("installer input RELA addend absent")?,
                target: resolve_input_target(map, o, r.r_sym, objects, elf, bytes)?,
            });
        }
    }
    out.sort_by_key(|r| r.offset);
    Ok(out)
}
// New closed caller policy: aggregate EXACTLY 5206 bytes and 76 fields. The
// generic 4096-byte bound is unchanged. This reuse is byte-relocation equality
// only: join_relocated_body has no CFG/symbol/whole-function semantic check.
// The caller has already established its single complete symbol/section.
// Partition that exact full body into
// bounded, nonoverlapping chunks, moving a cut before a relocation field if
// necessary. Every byte/field is joined once; no field or TLS bytes are masked.
fn aggregate_fields(
    input_len: usize,
    linked_len: usize,
    source: &[InputRelocation],
    emitted: &[FinalRelocation],
) -> Result<()> {
    require(
        input_len == INSTALLER_BYTES
            && linked_len == INSTALLER_BYTES
            && source.len() == 76
            && emitted.len() == 76,
        "installer finite aggregate 5206-byte/76-field policy differs",
    )?;
    let mut previous = 0;
    for (a, b) in source.iter().zip(emitted) {
        let end = a
            .offset
            .checked_add(4)
            .ok_or("installer aggregate field overflow")?;
        require(
            a.offset >= previous
                && end <= INSTALLER_BYTES
                && a.offset == b.offset
                && a.kind == b.kind,
            "installer aggregate writer overlap/gap/offset/kind differs",
        )?;
        previous = end;
    }
    Ok(())
}
// Called only after aggregate_fields: all widths are exactly four and within
// the finite extent. Adjacent returned ranges cover it once, with no split field.
fn chunk_plan(source: &[InputRelocation]) -> Result<Vec<(usize, usize)>> {
    let mut ranges = Vec::new();
    let mut begin = 0;
    while begin < INSTALLER_BYTES {
        let mut end = (begin + 4096).min(INSTALLER_BYTES);
        for r in source {
            if r.offset < end && r.offset.checked_add(4).is_some_and(|z| z > end) {
                end = r.offset;
            }
        }
        require(end > begin, "installer empty relocation-safe chunk")?;
        ranges.push((begin, end));
        begin = end;
    }
    Ok(ranges)
}
fn joined_chunks(
    elf: &Elf<'_>,
    bytes: &[u8],
    entry: u64,
    input: &[u8],
    linked: &[u8],
    source: &[InputRelocation],
    emitted: &[FinalRelocation],
) -> Result<()> {
    aggregate_fields(input.len(), linked.len(), source, emitted)?;
    let mut covered_bytes = 0;
    let mut covered_fields = 0;
    let mut covered_end = 0;
    for (begin, end) in chunk_plan(source)? {
        require(
            begin == covered_end && begin < end && end - begin <= 4096 && end <= INSTALLER_BYTES,
            "installer aggregate chunk gap/overlap/extent",
        )?;
        let sr = source
            .iter()
            .filter(|r| begin <= r.offset && r.offset < end)
            .map(|r| InputRelocation {
                offset: r.offset - begin,
                kind: r.kind,
                addend: r.addend,
                target: r.target.clone(),
            })
            .collect::<Vec<_>>();
        let fr = emitted
            .iter()
            .filter(|r| begin <= r.offset && r.offset < end)
            .map(|r| FinalRelocation {
                offset: r.offset - begin,
                kind: r.kind,
                addend: r.addend,
                symbol_value: r.symbol_value,
            })
            .collect::<Vec<_>>();
        join_relocated_body(
            elf,
            bytes,
            offset(entry, begin)?,
            &input[begin..end],
            &linked[begin..end],
            &sr,
            &fr,
        )?;
        covered_bytes += end - begin;
        covered_fields += sr.len();
        covered_end = end;
    }
    require(
        covered_end == INSTALLER_BYTES
            && covered_bytes == INSTALLER_BYTES
            && covered_fields == source.len(),
        "installer aggregate coverage differs",
    )
}
// Both inventories have four-byte writers (the complete join checks widths).
// Test interval intersection, not just a writer's starting address: a field
// crossing either protected boundary must refuse too. No other writer may
// change a semantic operand while retaining its instruction boundary.
fn protected_writers(fields: impl Iterator<Item = (usize, u32)>) -> Result<()> {
    let expected = BTreeSet::from([2021, 2028, 2435, 2442]);
    let mut seen = BTreeSet::new();
    for (at, kind) in fields {
        let end = at
            .checked_add(4)
            .ok_or("installer protected writer overflow")?;
        let overlaps = [(CORE_START, CORE_END), (RELOAD_START, RELOAD_END)]
            .iter()
            .any(|&(begin, limit)| at < limit && begin < end);
        if !overlaps {
            continue;
        }
        let expected_kind = if CALL_FIELDS.contains(&at) {
            Some(reloc::R_X86_64_GOTPCREL)
        } else if TABLE_FIELDS.contains(&at) {
            Some(reloc::R_X86_64_PC32)
        } else {
            None
        };
        require(
            expected_kind == Some(kind) && seen.insert(at),
            "installer unexpected protected semantic writer",
        )?;
    }
    require(
        seen == expected,
        "installer protected four-writer set differs",
    )
}
// Independent final operand check, in addition to the whole 5206-byte typed
// relocation join. Normalize ONLY the exact four admitted displacement fields;
// every other byte of CORE and RELOAD must remain the reviewed input byte.
// The source fields still require exact addends/targets in local_fields, and
// joined_chunks still proves every final relocation equation (including final
// section-symbol addend rebasing). This comparison replaces neither check.
fn protected_final_slices(
    input: &[u8],
    linked: &[u8],
    source: &[InputRelocation],
    emitted: &[FinalRelocation],
) -> Result<()> {
    finite_slices(input)?;
    protected_writers(source.iter().map(|r| (r.offset, r.kind)))?;
    protected_writers(emitted.iter().map(|r| (r.offset, r.kind)))?;
    for (begin, end) in [(CORE_START, CORE_END), (RELOAD_START, RELOAD_END)] {
        let mut expected = input
            .get(begin..end)
            .ok_or("installer protected input extent")?
            .to_vec();
        let mut actual = linked
            .get(begin..end)
            .ok_or("installer protected final extent")?
            .to_vec();
        for at in [2021, 2028, 2435, 2442] {
            if begin <= at && at < end {
                let start = at - begin;
                expected
                    .get_mut(start..start + 4)
                    .ok_or("installer protected mask extent")?
                    .fill(0);
                actual
                    .get_mut(start..start + 4)
                    .ok_or("installer protected mask extent")?
                    .fill(0);
            }
        }
        require(
            actual == expected,
            "installer final protected semantic bytes differ",
        )?;
    }
    Ok(())
}
fn local_fields(source: &[InputRelocation], entry: u64, leaf: u64, table: u64) -> Result<()> {
    protected_writers(source.iter().map(|r| (r.offset, r.kind)))?;
    for n in CALL_FIELDS {
        let r = source.iter().filter(|r| r.offset == n).collect::<Vec<_>>();
        require(
            r.len() == 1
                && r[0].kind == reloc::R_X86_64_GOTPCREL
                && r[0].addend == -4
                && r[0].target.mapped_input_value == leaf,
            "installer call/reload does not target actual leaf",
        )?;
    }
    for n in TABLE_FIELDS {
        let r = source.iter().filter(|r| r.offset == n).collect::<Vec<_>>();
        require(
            r.len() == 1
                && r[0].kind == reloc::R_X86_64_PC32
                && r[0].addend == -4
                && r[0].target.mapped_input_value == table,
            "installer table/reload does not target actual own RO section",
        )?;
    }
    let _ = offset(entry, INSTALLER_BYTES)?;
    Ok(())
}
fn joined_table(
    input: &[InputRelocation],
    emitted: &[FinalRelocation],
    raw: &[u8],
    entry: u64,
    table: u64,
) -> Result<[u64; 4]> {
    require(
        raw.len() == 16 && input.len() == 4 && emitted.len() == 4,
        "installer four-entry table census differs",
    )?;
    let mut targets = [0; 4];
    for i in 0..4 {
        let target = offset(entry, ARM_OFFSETS[i])?;
        let add = (ARM_OFFSETS[i] + i * 4) as i64;
        let a = &input[i];
        let b = &emitted[i];
        require(
            a.offset == i * 4
                && a.kind == reloc::R_X86_64_PC32
                && a.addend == add
                && a.target.mapped_input_value == entry
                && b.offset == a.offset
                && b.kind == a.kind
                && i128::from(b.symbol_value) + i128::from(b.addend)
                    == i128::from(target) + (i * 4) as i128,
            "installer table input/final target/addend differs",
        )?;
        let expected = checked_pc32(target, (i * 4) as i64, offset(table, i * 4)?)?;
        require(
            raw.get(i * 4..i * 4 + 4) == Some(&expected[..]),
            "installer signed table bytes differ",
        )?;
        targets[i] = target;
    }
    Ok(targets)
}

/// Borrowed file observations to authenticate; this is not a source or entry proof.
pub struct ViewSiteInstallerInputs<'a> {
    pub artifact: &'a FileIdentity,
    pub link_map: &'a FileIdentity,
    pub objdump: &'a FileIdentity,
}

impl VerifiedStaticSource {
    /// Observe one finite normal-return caller connection using the actual live
    /// leaf, source/archive/selected owner. This deliberately returns no complete
    /// caller-entry fact: exception entries, asynchronous frame/storage integrity,
    /// physical View provenance and error-terminal closure remain unproved.
    /// Every callback/error path retains full source/archive/build-output/selected
    /// and newly read source/tool/disassembly identity closes.
    pub fn with_view_site_installer_caller<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        inputs: ViewSiteInstallerInputs<'_>,
        runner: &mut Runner,
        body: impl FnOnce(&ViewSiteInstallerObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        let ViewSiteInstallerInputs {
            artifact,
            link_map,
            objdump,
        } = inputs;
        self.with_view_site_leaf(archive,definitions,artifact,link_map,runner,|leaf,runner| {
            leaf.require_owner(self,archive)?;
            let mut files=vec![artifact.clone(),link_map.clone(),objdump.clone(),definitions.core.libc.clone()];
            let result=(|| {
                for f in &files {f.verify()?;}
                require(objdump.sha256==OBJDUMP_SHA,"installer trusted GNU decoder differs")?;
                let roots=self.guard.roots.iter().filter(|(_,k)|matches!(k,RootBinding::Cargo(_))).map(|(p,_)|p).collect::<Vec<_>>();
                require(roots.len()==1,"installer actual source ambiguous")?;
                let source=FileIdentity::read(&roots[0].join(INSTALLER_SOURCE))?;files.push(source.clone());
                require(source.sha256==INSTALLER_SOURCE_SHA,"installer runtime source differs; fresh qualification required")?;
                let mut members=extract_objects(&archive.file,0)?;members.extend(extract_objects(&definitions.core.libc,1)?);
                let paths=[&archive.file.path,&definitions.core.libc.path];let mut objects=Vec::new();
                for m in &members {
                    let elf=Elf::parse(&m.bytes).map_err(|e|e.to_string())?;
                    require(elf.header.e_type==header::ET_REL&&elf.header.e_machine==header::EM_X86_64&&elf.is_64&&elf.little_endian,
                        "installer input not x86_64 LE ET_REL")?;
                    checked_object_symbol_authority(&elf,&m.bytes)?;
                    objects.push(ObjectInput{archive_path:paths[m.archive_index],member_name:&m.name,ordinal:m.ordinal,
                        header_offset:m.header,bytes:&m.bytes,elf});
                }
                let mut matches=Vec::new();
                for (i,o) in objects.iter().enumerate() {for s in o.elf.syms.iter().filter(|s|s.st_shndx!=0) {
                    if o.elf.strtab.get_at(s.st_name).and_then(canonical_rust_symbol).as_deref()==Some(INSTALLER) {matches.push((i,s));}
                }}
                require(matches.len()==1,"installer input defining symbol absent/ambiguous")?;
                let (oi,s)=matches[0];let o=&objects[oi];
                require(o.archive_path==archive.file.path.as_path()&&o.member_name.starts_with("reverie_inguest-")&&
                    s.st_type()==sym::STT_FUNC&&s.st_bind()==sym::STB_GLOBAL&&s.st_other==0&&s.st_value==0&&s.st_size==INSTALLER_BYTES as u64,
                    "installer actual owner/function shape differs")?;
                let name=o.elf.strtab.get_at(s.st_name).ok_or("installer name absent")?;let code=s.st_shndx;
                let tables=o.elf.section_headers.iter().enumerate().filter(|(_,s)|o.elf.shdr_strtab.get_at(s.sh_name)==Some(format!(".rodata.{name}").as_str())).map(|(i,_)|i).collect::<Vec<_>>();
                require(tables.len()==1,"installer own operation table absent/ambiguous")?;let table=tables[0];
                for (index,flags,len,align,expected_name) in [(code,6,INSTALLER_BYTES as u64,16,format!(".text.{name}")),(table,2,16,4,format!(".rodata.{name}"))] {
                    let s=&o.elf.section_headers[index];require(s.sh_type==section_header::SHT_PROGBITS&&s.sh_flags==flags&&s.sh_size==len&&s.sh_addralign==align&&o.elf.shdr_strtab.get_at(s.sh_name)==Some(expected_name.as_str()),
                        "installer exact input code/table geometry differs")?;
                }
                aliases(o,code,table,name)?;
                let input=section_file_bytes(&o.elf.section_headers[code],o.bytes)?;input_shape(input)?;
                require(section_file_bytes(&o.elf.section_headers[table],o.bytes)?==[0u8;16],"installer input table placeholders differ")?;
                let map_raw=bounded(link_map)?;let map=std::str::from_utf8(&map_raw).map_err(|e|e.to_string())?;
                let entry=mapped_section(map,o,code)?;let table_address=mapped_section(map,o,table)?;
                let data=bounded(artifact)?;let elf=Elf::parse(&data).map_err(|e|e.to_string())?;static_image_metadata(&elf,&data)?;
                let code_section=final_section(&elf,&data,entry,INSTALLER_BYTES,5)?;
                let table_section=final_section(&elf,&data,table_address,16,4)?;
                final_aliases(&elf,entry,INSTALLER_BYTES,code_section,Some(name))?;
                final_aliases(&elf,table_address,16,table_section,None)?;
                let linked=mapped_bytes(&elf,&data,entry,INSTALLER_BYTES as u64,5)?;
                let source_fields=input_fields_all(map,o,code,&objects,&elf,&data)?;
                let final_fields=emitted_fields(&elf,&data,entry,INSTALLER_BYTES,code_section)?;
                require(source_fields.len()==76,"installer complete typed field census differs")?;
                local_fields(&source_fields,entry,leaf.entry(),table_address)?;
                joined_chunks(&elf,&data,entry,input,linked,&source_fields,&final_fields)?;
                protected_final_slices(input,linked,&source_fields,&final_fields)?;
                let targets=joined_table(&input_fields_all(map,o,table,&objects,&elf,&data)?,
                    &emitted_fields(&elf,&data,table_address,16,table_section)?,
                    mapped_bytes(&elf,&data,table_address,16,4)?,entry,table_address)?;
                let end=offset(entry,INSTALLER_BYTES)?;let program=objdump.path.to_str().ok_or("installer tool path")?;
                let path=artifact.path.to_str().ok_or("installer artifact path")?;
                let args=vec!["--disassemble".into(),"--show-raw-insn".into(),"--disassemble-zeroes".into(),"--insn-width=16".into(),"--wide".into(),
                    format!("--start-address={entry:#x}"),format!("--stop-address={end:#x}"),path.into()];
                let before=runner.commands.len();objdump.verify()?;
                let raw=runner.run_with_combined_limit(program,&args,artifact.path.parent().ok_or("installer cwd")?,Some(1024*1024));
                let mut disassembly=None;
                if runner.commands.len()>before {let c=runner.commands.last().ok_or("installer tool receipt absent")?;
                    disassembly=Some(c.stdout.clone());files.extend([c.stdout.clone(),c.stderr.clone()]);}
                let raw=raw?;let text=std::str::from_utf8(&raw).map_err(|e|e.to_string())?;
                verify_disassembly_bytes(text,&BTreeMap::from([(entry,linked.to_vec())]))?;
                let instructions=constructor_instructions(text,entry)?;normal_cfg(entry,&instructions)?;
                let observation=ViewSiteInstallerObservation {runtime_archive:archive.file.clone(),artifact:artifact.clone(),link_map:link_map.clone(),
                    source,objdump:objdump.clone(),disassembly:disassembly.ok_or("installer disassembly identity absent")?,
                    member_name:o.member_name.into(),member_ordinal:o.ordinal,member_header:o.header_offset,member_sha256:sha256(o.bytes),
                    input_sha256:sha256(input),final_sha256:sha256(linked),entry,call:offset(entry,CALL)?,leaf_entry:leaf.entry(),
                    result_frame_offset:16,result_discriminator_offset:24,operation_table:table_address,targets,decoded_instructions:instructions.len(),
                    source_object_join:"COMPLETE_TYPED_INPUT_FINAL_BODY_AND_TABLE_JOIN",
                    normal_return_connection:"CONDITIONAL_NORMAL_CONTROL_AND_ACTUAL_LEAF_RESULT_ONLY",
                    complete_entry_fact:"REFUSED_REQUIRED_PREDECESSOR_JOINS_MISSING",required_unjoined:[
                        "INSTALLER_FDE_CIE_LSDA_AND_EXCEPTION_LANDING_PREDECESSORS_NOT_JOINED",
                        "ASYNC_FRAME_RESTORE_AND_DISJOINT_LIVE_RETURN_STORAGE_NOT_PROVEN",
                        "VALID_IMMUTABLE_VIEW_AND_ORDINARY_RETURN_ABI_REQUIRED",
                        "ERROR_ABORT_FAULT_AND_OTHER_HELPER_CLOSURE_NOT_PROVEN"]};
                body(&observation,runner)
            })();
            let mut errors=Vec::new();
            if let Err(e)=definitions.verify(){errors.push(e);}
            if let Err(e)=archive.verify(){errors.push(e);}
            for f in &files {if let Err(e)=f.verify(){errors.push(e);}}
            if let Err(e)=self.guard.close(runner){errors.push(e);}
            close_result(result,require(errors.is_empty(),errors.join("; ")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Structural normal-CFG data only. This is NOT a complete input body, an
    // archive or a public source-factory positive. input_shape rejects it.
    fn structural(
        extra: Option<(usize, Vec<u8>)>,
    ) -> (Vec<u8>, Vec<EncodedConstructorInstruction>) {
        let mut code = vec![0x90; INSTALLER_BYTES];
        code[CORE_START..CORE_END].copy_from_slice(CORE);
        code[RELOAD_START..RELOAD_END].copy_from_slice(RELOAD);
        code[INSTALLER_BYTES - 1] = 0xc3;
        let mut rows = BTreeMap::new();
        for &(o, n) in CORE_ROWS.iter().chain(RELOAD_ROWS) {
            rows.insert(o, n);
        }
        if let Some((o, b)) = extra {
            code[o..o + b.len()].copy_from_slice(&b);
            rows.insert(o, b.len());
        }
        let mut at = 0;
        let mut instructions = Vec::new();
        while at < code.len() {
            let n = rows.get(&at).copied().unwrap_or(1);
            instructions.push(EncodedConstructorInstruction {
                address: 0x1000 + at as u64,
                bytes: code[at..at + n].to_vec(),
            });
            at += n;
        }
        (code, instructions)
    }
    fn jump(from: usize, to: usize) -> Vec<u8> {
        let mut bytes = vec![0xe9];
        bytes.extend(
            i32::try_from(to as i64 - from as i64 - 5)
                .unwrap()
                .to_le_bytes(),
        );
        bytes
    }
    fn table_fixture() -> (Vec<InputRelocation>, Vec<FinalRelocation>, Vec<u8>) {
        let mut source = Vec::new();
        let mut final_rows = Vec::new();
        let mut bytes = Vec::new();
        for (i, arm) in ARM_OFFSETS.into_iter().enumerate() {
            source.push(InputRelocation {
                offset: i * 4,
                kind: reloc::R_X86_64_PC32,
                addend: (arm + i * 4) as i64,
                target: SelectedTarget {
                    mapped_input_value: 0x1000,
                },
            });
            final_rows.push(FinalRelocation {
                offset: i * 4,
                kind: reloc::R_X86_64_PC32,
                addend: (arm + i * 4) as i64,
                symbol_value: 0x1000,
            });
            bytes.extend(
                checked_pc32(0x1000 + arm as u64, (i * 4) as i64, 0x8000 + (i * 4) as u64).unwrap(),
            );
        }
        (source, final_rows, bytes)
    }

    #[test]
    fn installer_structural_call_load_guard_dispatch_and_reloaded_loop_connect() {
        let (code, ins) = structural(None);
        finite_slices(&code).unwrap();
        normal_cfg(0x1000, &ins).unwrap();
        assert!(
            input_shape(&code).is_err(),
            "structural data must not mint whole source input"
        );
    }
    #[test]
    fn installer_actual_buffer_byte24_call_and_error_operands_are_required() {
        let (code, _) = structural(None);
        // RDI result offset, byte24 load, indirect-call register, FF immediate,
        // conditional-error opcode, index scale and four operation arm values.
        for at in [2012, 2064, 2059, 2066, 2071, 2081, 2094, 2130, 2106, 2118] {
            let mut changed = code.clone();
            changed[at] ^= 1;
            assert!(
                finite_slices(&changed).is_err(),
                "changed semantic operand at {at}"
            );
        }
    }
    #[test]
    fn installer_every_backedge_reload_and_disjoint_store_are_exact() {
        let (code, _) = structural(None);
        // RDI reload, RCX reload opcode, table reload opcode, backedge target,
        // saved iterator slot (must not overwrite result+24).
        for at in [2431, 2432, 2439, 2448, 2088] {
            let mut changed = code.clone();
            changed[at] ^= 1;
            assert!(finite_slices(&changed).is_err());
        }
    }
    #[test]
    fn installer_external_normal_predecessors_cannot_bypass_call_or_error() {
        for target in [BODY_ENTRY, CALL, CALL + 2, 2076, 2085, DISPATCH] {
            let (_, ins) = structural(Some((100, jump(100, target))));
            assert!(normal_cfg(0x1000, &ins).is_err(), "bypass to {target}");
        }
    }
    #[test]
    fn installer_unknown_indirect_and_interior_direct_entries_refuse() {
        let (_, ins) = structural(Some((100, vec![0xff, 0xe0])));
        assert!(normal_cfg(0x1000, &ins).is_err());
        let (_, ins) = structural(Some((100, jump(100, CALL + 1))));
        assert!(normal_cfg(0x1000, &ins).is_err());
        let (_, ins) = structural(Some((100, vec![0xe8, 0, 0, 0, 0])));
        assert!(
            normal_cfg(0x1000, &ins).is_err(),
            "interior normal call is not a new entry premise"
        );
    }
    #[test]
    fn installer_complete_decoder_gaps_overlaps_and_unknown_prefixes_refuse() {
        let (_, mut ins) = structural(None);
        ins.remove(20);
        assert!(normal_cfg(0x1000, &ins).is_err());
        let (_, mut ins) = structural(None);
        ins.insert(20, ins[20].clone());
        assert!(normal_cfg(0x1000, &ins).is_err());
        let (_, ins) = structural(Some((100, vec![0x66, 0xeb, 0])));
        assert!(normal_cfg(0x1000, &ins).is_err());
    }
    #[test]
    fn installer_four_typed_signed_entries_are_not_arbitrary_rx_targets() {
        let (source, rows, bytes) = table_fixture();
        assert_eq!(
            joined_table(&source, &rows, &bytes, 0x1000, 0x8000).unwrap(),
            ARM_OFFSETS.map(|a| 0x1000 + a as u64)
        );
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(joined_table(&source, &rows, &changed, 0x1000, 0x8000).is_err());
        for i in 0..4 {
            let (mut source, rows, bytes) = table_fixture();
            source[i].target.mapped_input_value += 1;
            assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
            let (source, mut rows, bytes) = table_fixture();
            rows[i].addend += 1;
            assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
        }
    }
    #[test]
    fn installer_missing_extra_crossing_and_permuted_table_fields_refuse() {
        let (mut source, rows, bytes) = table_fixture();
        source.pop();
        assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
        let (source, mut rows, bytes) = table_fixture();
        rows.push(rows[0].clone());
        assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
        let (mut source, rows, bytes) = table_fixture();
        source[0].offset = 1;
        assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
        let (mut source, rows, bytes) = table_fixture();
        source.swap(0, 1);
        assert!(joined_table(&source, &rows, &bytes, 0x1000, 0x8000).is_err());
    }
    #[test]
    fn installer_both_actual_call_and_table_relocation_targets_are_required() {
        let make = || {
            CALL_FIELDS
                .into_iter()
                .map(|offset| InputRelocation {
                    offset,
                    kind: reloc::R_X86_64_GOTPCREL,
                    addend: -4,
                    target: SelectedTarget {
                        mapped_input_value: 0x2000,
                    },
                })
                .chain(TABLE_FIELDS.into_iter().map(|offset| InputRelocation {
                    offset,
                    kind: reloc::R_X86_64_PC32,
                    addend: -4,
                    target: SelectedTarget {
                        mapped_input_value: 0x8000,
                    },
                }))
                .collect::<Vec<_>>()
        };
        local_fields(&make(), 0x1000, 0x2000, 0x8000).unwrap();
        for i in 0..4 {
            let mut changed = make();
            changed[i].target.mapped_input_value += 1;
            assert!(local_fields(&changed, 0x1000, 0x2000, 0x8000).is_err());
            let mut changed = make();
            changed[i].addend -= 1;
            assert!(local_fields(&changed, 0x1000, 0x2000, 0x8000).is_err());
        }
    }
    #[test]
    fn installer_aggregate_and_address_overflow_are_refusals() {
        let (_, ins) = structural(None);
        assert!(normal_cfg(u64::MAX - 10, &ins).is_err());
        assert!(offset(u64::MAX, 1).is_err());
        assert!(input_shape(&[]).is_err());
        let (source, rows, bytes) = table_fixture();
        assert!(joined_table(&source, &rows, &bytes, u64::MAX - 1, 0x8000).is_err());
    }
    #[test]
    fn installer_full_aggregate_field_inventory_is_mandatory() {
        let source = (0..76)
            .map(|i| InputRelocation {
                offset: i * 50,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x1000,
                },
            })
            .collect::<Vec<_>>();
        let rows = source
            .iter()
            .map(|r| FinalRelocation {
                offset: r.offset,
                kind: r.kind,
                addend: r.addend,
                symbol_value: r.target.mapped_input_value,
            })
            .collect::<Vec<_>>();
        aggregate_fields(5206, 5206, &source, &rows).unwrap();
        for len in [4096, 5205, 5207] {
            assert!(aggregate_fields(len, 5206, &source, &rows).is_err());
        }
        let mut changed = source.clone();
        changed[1].offset = 2;
        assert!(aggregate_fields(5206, 5206, &changed, &rows).is_err());
        let mut changed = source.clone();
        changed[75].offset = 5204;
        assert!(aggregate_fields(5206, 5206, &changed, &rows).is_err());
        let mut changed = rows.clone();
        changed[0].offset += 1;
        assert!(aggregate_fields(5206, 5206, &source, &changed).is_err());
        let mut changed = rows.clone();
        changed[0].kind = reloc::R_X86_64_GOTPCREL;
        assert!(aggregate_fields(5206, 5206, &source, &changed).is_err());
        assert!(aggregate_fields(5206, 5206, &source[..75], &rows).is_err());
    }

    #[test]
    fn installer_crossing_relocation_moves_cut_without_gap_or_split() {
        let mut source = (0..76)
            .map(|i| InputRelocation {
                offset: i * 50,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x1000,
                },
            })
            .collect::<Vec<_>>();
        source[75].offset = 4095;
        let rows = source
            .iter()
            .map(|r| FinalRelocation {
                offset: r.offset,
                kind: r.kind,
                addend: r.addend,
                symbol_value: r.target.mapped_input_value,
            })
            .collect::<Vec<_>>();
        aggregate_fields(5206, 5206, &source, &rows).unwrap();
        let ranges = chunk_plan(&source).unwrap();
        assert_eq!(ranges, vec![(0, 4095), (4095, 5206)]);
        assert_eq!(ranges.iter().map(|(a, b)| b - a).sum::<usize>(), 5206);
        for r in &source {
            assert_eq!(
                ranges
                    .iter()
                    .filter(|(a, b)| *a <= r.offset && r.offset + 4 <= *b)
                    .count(),
                1
            );
        }
        source[75].offset = 4092;
        assert_eq!(chunk_plan(&source).unwrap(), vec![(0, 4096), (4096, 5206)]);
    }

    // Production predicates on structural data; never an actual source-factory
    // positive. Keep 76 fields even when moving a nonprotected writer into a
    // protected operand, so the old aggregate count cannot hide the regression.
    fn protected_fixture() -> (Vec<u8>, Vec<InputRelocation>, Vec<FinalRelocation>) {
        let (code, _) = structural(None);
        let mut source = (0..72)
            .map(|i| InputRelocation {
                offset: 10 + i * 20,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x1000,
                },
            })
            .chain(CALL_FIELDS.into_iter().map(|offset| InputRelocation {
                offset,
                kind: reloc::R_X86_64_GOTPCREL,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x2000,
                },
            }))
            .chain(TABLE_FIELDS.into_iter().map(|offset| InputRelocation {
                offset,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x8000,
                },
            }))
            .collect::<Vec<_>>();
        source.sort_by_key(|r| r.offset);
        let rows = source
            .iter()
            .map(|r| FinalRelocation {
                offset: r.offset,
                kind: r.kind,
                addend: r.addend,
                symbol_value: r.target.mapped_input_value,
            })
            .collect();
        (code, source, rows)
    }
    #[test]
    fn installer_moved_writer_cannot_rewrite_operation_byte24_or_error_guard() {
        // SetFs imm32, output+24 load, error255 comparison, error branch.
        for at in [2094, 2061, 2066, 2072] {
            let (code, mut source, mut rows) = protected_fixture();
            source[0].offset = at;
            rows[0].offset = at;
            source.sort_by_key(|r| r.offset);
            rows.sort_by_key(|r| r.offset);
            // These malicious inventories satisfy the old full count, matching
            // offsets/kinds, containment and nonoverlap guard. All four actual
            // call/table fields remain present; the NEW guard must reject.
            aggregate_fields(5206, 5206, &source, &rows).unwrap();
            let mut linked = code.clone();
            linked[at..at + 4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            assert_eq!(
                local_fields(&source, 0x1000, 0x2000, 0x8000)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
            assert_eq!(
                protected_final_slices(&code, &linked, &source, &rows)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
        }
    }
    #[test]
    fn installer_added_and_crossing_protected_writers_refuse_in_both_inventories() {
        for at in [
            2094,
            2061,
            2066,
            2072,
            CORE_START - 3,
            CORE_END - 1,
            RELOAD_START - 3,
            RELOAD_END - 1,
            2020,
        ] {
            let (code, source, rows) = protected_fixture();
            let mut changed = source.clone();
            changed.push(InputRelocation {
                offset: at,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                target: SelectedTarget {
                    mapped_input_value: 0x1000,
                },
            });
            assert_eq!(
                protected_final_slices(&code, &code, &changed, &rows)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
            let mut changed = rows.clone();
            changed.push(FinalRelocation {
                offset: at,
                kind: reloc::R_X86_64_PC32,
                addend: -4,
                symbol_value: 0x1000,
            });
            assert_eq!(
                protected_final_slices(&code, &code, &source, &changed)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
        }
    }
    #[test]
    fn installer_final_semantic_comparison_masks_only_four_displacements() {
        let (code, source, rows) = protected_fixture();
        local_fields(&source, 0x1000, 0x2000, 0x8000).unwrap();
        aggregate_fields(5206, 5206, &source, &rows).unwrap();
        let mut relocated = code.clone();
        for at in [2021, 2028, 2435, 2442] {
            relocated[at..at + 4].copy_from_slice(&[1, 2, 3, 4]);
        }
        protected_final_slices(&code, &relocated, &source, &rows).unwrap();
        for at in (CORE_START..CORE_END).chain(RELOAD_START..RELOAD_END) {
            if [2021, 2028, 2435, 2442]
                .iter()
                .any(|&start| start <= at && at < start + 4)
            {
                continue;
            }
            let mut changed = relocated.clone();
            changed[at] ^= 1;
            assert_eq!(
                protected_final_slices(&code, &changed, &source, &rows)
                    .unwrap_err()
                    .to_string(),
                "installer final protected semantic bytes differ",
                "final byte {at}"
            );
        }
        assert!(
            protected_final_slices(&code, &relocated[..RELOAD_END - 1], &source, &rows).is_err()
        );
    }
    #[test]
    fn installer_protected_writer_set_requires_each_exact_kind_once() {
        let (code, source, rows) = protected_fixture();
        for at in [2021, 2028, 2435, 2442] {
            let mut missing = rows.clone();
            missing.retain(|r| r.offset != at);
            assert_eq!(
                protected_final_slices(&code, &code, &source, &missing)
                    .unwrap_err()
                    .to_string(),
                "installer protected four-writer set differs"
            );
            let mut wrong = rows.clone();
            wrong.iter_mut().find(|r| r.offset == at).unwrap().kind = reloc::R_X86_64_PLT32;
            assert_eq!(
                protected_final_slices(&code, &code, &source, &wrong)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
            let mut duplicate = rows.clone();
            duplicate.push(rows.iter().find(|r| r.offset == at).unwrap().clone());
            assert_eq!(
                protected_final_slices(&code, &code, &source, &duplicate)
                    .unwrap_err()
                    .to_string(),
                "installer unexpected protected semantic writer"
            );
        }
    }
}
