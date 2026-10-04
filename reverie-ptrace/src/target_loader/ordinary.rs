/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Resolve the explicit LiteInst host initializer as an ordinary ELF export.
//!
//! This policy is separate from the versioned public `dlopen` parser and does
//! not change which providers that parser accepts.

use super::*;

const INITIALIZER: &str = "reverie_liteinst_initialize_host";
const MAX_RUNTIME_FILE: usize = 64 * 1024 * 1024;
const MAX_RUNTIME_SYMBOLS: usize = 65536;
const LOAD_PAGE: u64 = 4096;

fn runtime_file_bound(length: usize) -> io::Result<()> {
    if length > MAX_RUNTIME_FILE {
        return Err(invalid("runtime exceeds file bound"));
    }
    Ok(())
}

/// An exact ordinary initializer observed in a stopped target image.
///
/// These coordinates expire when any task sharing the address space resumes,
/// just as they do for [`TargetDlopen`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetHostInitializer {
    /// Observed stopped TID.
    pub tid: i32,
    /// Kernel start ticks for that TID.
    pub start_ticks: u64,
    /// Original executable program headers.
    pub executable_phdr: u64,
    /// Runtime node in the default link map.
    pub link_map: u64,
    /// Runtime load bias.
    pub load_bias: u64,
    /// Ordinary, unversioned initializer address.
    pub address: u64,
    /// Observed backing device/inode tuple.
    pub mapping_identity: (u64, u64, u64),
}

/// Resolve the exact unversioned host initializer without running target code.
///
/// The controller supplies independently bound runtime bytes. All tasks sharing
/// this image must remain stopped. The mapping, default-namespace link-map,
/// exact non-writable PT_LOAD file-byte comparison, and before/after snapshot
/// readback checks of [`resolve_dlopen`] apply. Provider selection requires an
/// ordinary unversioned initializer, without `dlopen`'s versioned libc/libdl
/// export policy. This does not authorize executing the result.
pub fn resolve_host_initializer(
    task: &Stopped,
    expected_runtime: &[u8],
) -> io::Result<TargetHostInitializer> {
    let tid = task.pid().as_raw();
    let before = Snapshot::read(tid)?;
    let maps = parse_maps(&before.maps)?;
    let aux = parse_auxv(&before.auxv)?;
    let provider = parse_runtime(expected_runtime)?;
    let mut memory = Memory::new(&maps, |address, bytes: &mut [u8]| {
        let address = usize::try_from(address).map_err(|_| invalid("target address overflow"))?;
        task.read_exact(address, bytes)
            .map_err(|error| io::Error::other(format!("read target at {address:#x}: {error}")))
    });
    let resolved = resolve(&mut memory, &aux, &provider)?;
    if Snapshot::read(tid)? != before {
        return Err(invalid(
            "target process, maps, auxv or mount namespace changed",
        ));
    }
    Ok(TargetHostInitializer {
        tid,
        start_ticks: before.start_ticks,
        executable_phdr: resolved.executable_phdr,
        link_map: resolved.link_map,
        load_bias: resolved.load_bias,
        address: resolved.address,
        mapping_identity: resolved.mapping_identity,
    })
}

// Linux maps PT_LOAD segments a page at a time. For the runtime parser, reject
// segments that need execute-only mappings or incompatible projections of one
// virtual page. Keep this stricter policy local so resolve_dlopen is unchanged.
fn validate_runtime_loads(headers: &[goblin::elf::ProgramHeader]) -> io::Result<()> {
    validate_loads(headers)?;
    let mut rounded_loads: Vec<(u64, u64, u32, u64, u64)> = Vec::new();
    for load in headers.iter().filter(|header| header.p_type == ph::PT_LOAD) {
        let end = add(load.p_vaddr, load.p_memsz)?;
        if load.p_flags & ph::PF_W == 0 && load.p_flags & ph::PF_R == 0
            || load.p_vaddr % LOAD_PAGE != load.p_offset % LOAD_PAGE
        {
            return Err(invalid("malformed runtime load segment"));
        }

        let page_start = load.p_vaddr & !(LOAD_PAGE - 1);
        let page_end = end
            .checked_add(LOAD_PAGE - 1)
            .map(|end| end & !(LOAD_PAGE - 1))
            .ok_or_else(|| invalid("runtime load page range overflow"))?;
        let file_memory_end = add(load.p_vaddr, load.p_filesz)?;
        let file_page_end = if load.p_filesz == 0 {
            page_start
        } else {
            file_memory_end
                .checked_add(LOAD_PAGE - 1)
                .map(|end| end & !(LOAD_PAGE - 1))
                .ok_or_else(|| invalid("runtime load page range overflow"))?
                .min(page_end)
        };
        let file_page_start = load.p_offset & !(LOAD_PAGE - 1);

        for &(prior_start, prior_end, prior_flags, prior_file_end, prior_file_start) in
            &rounded_loads
        {
            let overlap_start = page_start.max(prior_start);
            let overlap_end = page_end.min(prior_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let prior_file_overlap_end = prior_file_end.clamp(overlap_start, overlap_end);
            let file_overlap_end = file_page_end.clamp(overlap_start, overlap_end);
            let file_projection_matches = file_overlap_end == overlap_start
                || add(prior_file_start, overlap_start - prior_start)?
                    == add(file_page_start, overlap_start - page_start)?;
            if prior_flags != load.p_flags
                || prior_file_overlap_end != file_overlap_end
                || !file_projection_matches
            {
                return Err(invalid("incompatible runtime load page mappings"));
            }
        }

        rounded_loads.push((
            page_start,
            page_end,
            load.p_flags,
            file_page_end,
            file_page_start,
        ));
    }
    Ok(())
}

fn gnu_hash(bytes: &[u8]) -> u32 {
    bytes.iter().fold(5381_u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    })
}

fn validate_sysv_hash(
    elf: &Elf<'_>,
    bytes: &[u8],
    strings: &[u8],
    address: u64,
    selected: usize,
) -> io::Result<()> {
    let header = Provider::ro_file(elf, bytes, address, 8)?;
    let bucket_count = u32_at(header, 0) as usize;
    let chain_count = u32_at(header, 4) as usize;
    if bucket_count == 0
        || bucket_count > MAX_RUNTIME_SYMBOLS
        || chain_count != elf.dynsyms.len()
        || chain_count > MAX_RUNTIME_SYMBOLS
    {
        return Err(invalid("malformed runtime SysV hash table"));
    }
    let words = 2_usize
        .checked_add(bucket_count)
        .and_then(|words| words.checked_add(chain_count))
        .ok_or_else(|| invalid("runtime SysV hash table size overflow"))?;
    let length = words
        .checked_mul(4)
        .ok_or_else(|| invalid("runtime SysV hash table size overflow"))?;
    let table = Provider::ro_file(elf, bytes, address, length as u64)?;
    let buckets = &table[8..8 + bucket_count * 4];
    let chains = &table[8 + bucket_count * 4..];
    if u32_at(chains, 0) != 0
        || (0..chain_count).any(|index| u32_at(chains, index * 4) as usize >= chain_count)
    {
        return Err(invalid("malformed runtime SysV hash table"));
    }

    // Every chain, including one not referenced by a bucket, must terminate.
    // The three-state traversal keeps this linear in the bounded symbol count.
    let mut chain_state = vec![0_u8; chain_count];
    chain_state[0] = 2;
    for start in 1..chain_count {
        if chain_state[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut index = start;
        while index != 0 && chain_state[index] == 0 {
            chain_state[index] = 1;
            path.push(index);
            index = u32_at(chains, index * 4) as usize;
        }
        if index != 0 && chain_state[index] == 1 {
            return Err(invalid("malformed runtime SysV hash table"));
        }
        for index in path {
            chain_state[index] = 2;
        }
    }

    let mut selected_reachable = false;
    for bucket_number in 0..bucket_count {
        let mut index = u32_at(buckets, bucket_number * 4) as usize;
        let mut steps = 0;
        while index != 0 {
            if index >= chain_count || steps >= chain_count {
                return Err(invalid("malformed runtime SysV hash table"));
            }
            let symbol = elf
                .dynsyms
                .get(index)
                .ok_or_else(|| invalid("malformed runtime SysV hash table"))?;
            let name = c_string(strings, symbol.st_name)?;
            if elf_hash(name.as_bytes()) as usize % bucket_count != bucket_number {
                return Err(invalid("runtime SysV hash table disagrees with symbols"));
            }
            selected_reachable |= index == selected;
            index = u32_at(chains, index * 4) as usize;
            steps += 1;
        }
    }
    if !selected_reachable {
        return Err(invalid("initializer is unreachable from runtime SysV hash"));
    }
    Ok(())
}

fn validate_gnu_hash(
    elf: &Elf<'_>,
    bytes: &[u8],
    strings: &[u8],
    address: u64,
    selected: usize,
) -> io::Result<()> {
    let header = Provider::ro_file(elf, bytes, address, 16)?;
    let bucket_count = u32_at(header, 0) as usize;
    let symbol_offset = u32_at(header, 4) as usize;
    let bloom_count = u32_at(header, 8) as usize;
    let bloom_shift = u32_at(header, 12);
    if bucket_count == 0
        || bucket_count > MAX_RUNTIME_SYMBOLS
        || bloom_count == 0
        || bloom_count > MAX_RUNTIME_SYMBOLS
        || !bloom_count.is_power_of_two()
        || bloom_shift >= 32
        || symbol_offset >= elf.dynsyms.len()
        || elf.dynsyms.len() > MAX_RUNTIME_SYMBOLS
    {
        return Err(invalid("malformed runtime GNU hash table"));
    }
    let chain_count = elf.dynsyms.len() - symbol_offset;
    let length = 16_usize
        .checked_add(
            bloom_count
                .checked_mul(8)
                .ok_or_else(|| invalid("runtime GNU hash table size overflow"))?,
        )
        .and_then(|length| length.checked_add(bucket_count.checked_mul(4)?))
        .and_then(|length| length.checked_add(chain_count.checked_mul(4)?))
        .ok_or_else(|| invalid("runtime GNU hash table size overflow"))?;
    let table = Provider::ro_file(elf, bytes, address, length as u64)?;
    let bloom_start = 16;
    let bucket_start = bloom_start + bloom_count * 8;
    let chain_start = bucket_start + bucket_count * 4;
    let mut reachable = vec![false; elf.dynsyms.len()];

    for bucket_number in 0..bucket_count {
        let mut index = u32_at(table, bucket_start + bucket_number * 4) as usize;
        if index == 0 {
            continue;
        }
        if index < symbol_offset || index >= elf.dynsyms.len() {
            return Err(invalid("malformed runtime GNU hash table"));
        }
        loop {
            if index >= elf.dynsyms.len() || reachable[index] {
                return Err(invalid("malformed runtime GNU hash table"));
            }
            let symbol = elf
                .dynsyms
                .get(index)
                .ok_or_else(|| invalid("malformed runtime GNU hash table"))?;
            let name = c_string(strings, symbol.st_name)?;
            let hash = gnu_hash(name.as_bytes());
            let word = u64_at(
                table,
                bloom_start + ((hash as usize / 64) & (bloom_count - 1)) * 8,
            );
            let bloom_mask = 1_u64 << (hash & 63) | 1_u64 << ((hash >> bloom_shift) & 63);
            let chain = u32_at(table, chain_start + (index - symbol_offset) * 4);
            if hash as usize % bucket_count != bucket_number
                || word & bloom_mask != bloom_mask
                || chain & !1 != hash & !1
            {
                return Err(invalid("runtime GNU hash table disagrees with symbols"));
            }
            reachable[index] = true;
            if chain & 1 != 0 {
                break;
            }
            index += 1;
        }
    }
    if !reachable[selected] {
        return Err(invalid("initializer is unreachable from runtime GNU hash"));
    }
    if reachable[symbol_offset..]
        .iter()
        .any(|reachable| !reachable)
    {
        return Err(invalid("malformed runtime GNU hash table"));
    }
    Ok(())
}

fn validate_runtime_hashes(
    elf: &Elf<'_>,
    bytes: &[u8],
    strings: &[u8],
    unique: &BTreeMap<u64, u64>,
    selected: usize,
) -> io::Result<()> {
    let sysv = unique.get(&dynamic::DT_HASH).copied();
    let gnu = unique.get(&dynamic::DT_GNU_HASH).copied();
    if let Some(address) = sysv {
        validate_sysv_hash(elf, bytes, strings, address, selected)?;
    }
    if let Some(address) = gnu {
        validate_gnu_hash(elf, bytes, strings, address, selected)?;
    }
    Ok(())
}

fn parse_runtime(bytes: &[u8]) -> io::Result<Provider<'_>> {
    // The measured unstripped release runtime is 35,223,752 bytes, exceeding
    // the public dlopen provider's 32 MiB limit. Keep a separate bounded 64 MiB
    // runtime policy with room for build variation; this is not an ABI limit.
    runtime_file_bound(bytes.len())?;
    let elf = Elf::parse(bytes).map_err(|_| invalid("malformed runtime ELF"))?;
    if !elf.is_64
        || !elf.little_endian
        || elf.header.e_machine != header::EM_X86_64
        || elf.header.e_type != header::ET_DYN
        || elf.header.e_ehsize != 64
        || elf.header.e_version != 1
        || elf.header.e_phentsize != 56
        || elf.program_headers.len() > 128
    {
        return Err(invalid("runtime is not supported x86-64 ELF"));
    }
    validate_runtime_loads(&elf.program_headers)?;
    for load in &elf.program_headers {
        if load.p_type == ph::PT_LOAD {
            range(bytes, load.p_offset, load.p_filesz)?;
        }
    }

    let segments: Vec<_> = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == ph::PT_DYNAMIC)
        .collect();
    if segments.len() != 1 {
        return Err(invalid("ambiguous runtime dynamic segment"));
    }
    let segment = segments[0];
    let (dynamic, dynamic_offset, dynamic_size) =
        (segment.p_vaddr, segment.p_offset, segment.p_filesz);
    if dynamic_size == 0
        || dynamic_size % 16 != 0
        || dynamic_size / 16 > MAX_DYNAMIC as u64
        || load_file_offset(&elf.program_headers, dynamic, dynamic_size, false)? != dynamic_offset
    {
        return Err(invalid("runtime dynamic layout invalid"));
    }
    range(bytes, dynamic_offset, dynamic_size)?;

    let tags = elf
        .dynamic
        .as_ref()
        .ok_or_else(|| invalid("missing runtime dynamic table"))?;
    if !tags
        .dyns
        .last()
        .is_some_and(|entry| entry.d_tag == dynamic::DT_NULL)
        || tags.info.textrel
    {
        return Err(invalid(
            "runtime has text relocation or unterminated dynamic table",
        ));
    }

    let mut unique = BTreeMap::new();
    for entry in &tags.dyns {
        if [
            dynamic::DT_STRTAB,
            dynamic::DT_STRSZ,
            dynamic::DT_SYMTAB,
            dynamic::DT_SYMENT,
            dynamic::DT_VERSYM,
            dynamic::DT_FLAGS,
            dynamic::DT_HASH,
            dynamic::DT_GNU_HASH,
        ]
        .contains(&entry.d_tag)
            && unique.insert(entry.d_tag, entry.d_val).is_some()
        {
            return Err(invalid("duplicate runtime symbol metadata"));
        }
    }
    let tag = |key| {
        unique
            .get(&key)
            .copied()
            .ok_or_else(|| invalid("missing runtime symbol metadata"))
    };
    if !unique.contains_key(&dynamic::DT_HASH) && !unique.contains_key(&dynamic::DT_GNU_HASH) {
        return Err(invalid("missing runtime symbol hash table"));
    }
    if tag(dynamic::DT_SYMENT)? != 24
        || elf.dynsyms.is_empty()
        || elf.dynsyms.len() > MAX_RUNTIME_SYMBOLS
        || unique.get(&dynamic::DT_FLAGS).copied().unwrap_or(0) & dynamic::DF_TEXTREL != 0
    {
        return Err(invalid("unsupported runtime symbols or text relocations"));
    }

    let strings = Provider::ro_file(
        &elf,
        bytes,
        tag(dynamic::DT_STRTAB)?,
        tag(dynamic::DT_STRSZ)?,
    )?;
    let records = Provider::ro_file(
        &elf,
        bytes,
        tag(dynamic::DT_SYMTAB)?,
        (elf.dynsyms.len() * 24) as u64,
    )?;
    let versions = unique
        .get(&dynamic::DT_VERSYM)
        .map(|address| Provider::ro_file(&elf, bytes, *address, (elf.dynsyms.len() * 2) as u64))
        .transpose()?;

    let mut selected = None;
    for (index, symbol) in elf.dynsyms.iter().enumerate() {
        let record = &records[index * 24..(index + 1) * 24];
        if symbol.st_name != u32_at(record, 0) as usize
            || symbol.st_info != record[4]
            || symbol.st_other != record[5]
            || symbol.st_shndx != u16_at(record, 6) as usize
            || symbol.st_value != u64_at(record, 8)
            || symbol.st_size != u64_at(record, 16)
        {
            return Err(invalid("runtime dynamic symbol table disagreement"));
        }
        if c_string(strings, symbol.st_name)? != INITIALIZER {
            continue;
        }
        if symbol.st_bind() != sym::STB_GLOBAL
            || symbol.st_type() != sym::STT_FUNC
            || symbol.st_other != sym::STV_DEFAULT
            || symbol.st_shndx == 0
            || symbol.st_shndx >= 0xff00
            || symbol.st_size == 0
            || symbol.st_size > 1024 * 1024
            || versions.is_some_and(|table| u16_at(table, index * 2) != 1)
        {
            return Err(invalid(
                "initializer is not an ordinary unversioned global function",
            ));
        }
        Provider::ro_file(&elf, bytes, symbol.st_value, symbol.st_size)?;
        if !elf.program_headers.iter().any(|load| {
            load.p_type == ph::PT_LOAD
                && load.p_flags == (ph::PF_R | ph::PF_X)
                && symbol.st_value >= load.p_vaddr
                && add(symbol.st_value, symbol.st_size)
                    .ok()
                    .zip(add(load.p_vaddr, load.p_filesz).ok())
                    .is_some_and(|(symbol_end, load_end)| symbol_end <= load_end)
        }) {
            return Err(invalid("initializer is outside exact executable bytes"));
        }
        if selected.replace((index, symbol)).is_some() {
            return Err(invalid("ambiguous ordinary initializer"));
        }
    }

    let (selected_index, symbol) =
        selected.ok_or_else(|| invalid("ordinary initializer absent"))?;
    validate_runtime_hashes(&elf, bytes, strings, &unique, selected_index)?;

    Ok(Provider {
        bytes,
        elf,
        symbol,
        version: "unversioned",
        dynamic,
        dynamic_offset,
        dynamic_size,
    })
}

#[cfg(test)]
mod tests;
