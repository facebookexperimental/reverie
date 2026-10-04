/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Resolve a public target loader entry without executing target code.
//!
//! This validates a caller-supplied expected provider against readable target
//! mappings and the original loader's default-namespace link map. It does not
//! select trusted provider bytes, load a runtime, or authorize a later call.

use std::collections::BTreeMap;
use std::io::Read;
use std::io::{self};
use std::os::unix::fs::MetadataExt;

use goblin::elf::Elf;
use goblin::elf::dynamic;
use goblin::elf::header;
use goblin::elf::program_header as ph;
use goblin::elf::sym;
use reverie::syscalls::MemoryAccess;
use safeptrace::Stopped;

mod ordinary;
pub use ordinary::TargetHostInitializer;
pub use ordinary::resolve_host_initializer;

const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_MAPS: usize = 2 * 1024 * 1024;
const MAX_READ: usize = 8 * 1024 * 1024;
const MAX_LINKS: usize = 256;
const MAX_DYNAMIC: usize = 4096;

/// A public `dlopen` definition in one observed target image.
///
/// These coordinates expire when any task sharing this address space resumes.
/// They are not a capability to execute the address or a loader-state transfer.
#[derive(Debug, Eq, PartialEq)]
pub struct TargetDlopen {
    /// Target thread ID of the stopped-task observation.
    pub tid: i32,
    /// Kernel start ticks of that target thread.
    pub start_ticks: u64,
    /// Address of the original executable's program headers.
    pub executable_phdr: u64,
    /// Provider node in the default-namespace link map.
    pub link_map: u64,
    /// Difference between provider ELF virtual addresses and target addresses.
    pub load_bias: u64,
    /// Validated executable entry address of the public function.
    pub address: u64,
    /// Exact requested default symbol version.
    pub version: String,
    /// Backing-file device and inode as reported by the target's maps.
    /// This does not assert equality with a pathname's `stat` identity.
    pub mapping_identity: (u64, u64, u64),
}

/// Resolve the expected provider's default-version public `dlopen` in `task`.
///
/// `expected_provider` must be independently bound libc/libdl ELF bytes chosen
/// by the controller; neither a guest pathname nor an observed SONAME establishes
/// trust. `version` must name its intended public default version. This compares
/// all non-writable PT_LOAD file bytes, including the selected symbol/version
/// metadata and code, with the actual target. Writable data/TLS is not compared.
///
/// The caller must keep **all** tasks sharing this address space quiescent for
/// the entire observation. `Stopped` owns one TID, not that wider condition.
/// Before/after reads detect changes but do not replace quiescence. No target
/// code runs. All coordinates require renewed validation after any resume/exec.
/// The loader's writable rendezvous/link-map records are structural observations,
/// not a defense against target tampering. This must run before provider code
/// instrumentation. The selected provider's code must match without exceptions.
/// The provider's complete program-header table must be mapped at its ELF file
/// offset relative to the initial load containing the ELF header.
///
/// Only x86-64 little-endian ELF, an executable PT_PHDR/DT_DEBUG rendezvous,
/// consistent default-namespace link maps and a unique normal function are
/// accepted. IFUNCs, private/non-default versions, interposed provider selection
/// and loader/audit callbacks are not resolved by this operation.
pub fn resolve_dlopen(
    task: &Stopped,
    expected_provider: &[u8],
    version: &str,
) -> io::Result<TargetDlopen> {
    let tid = task.pid().as_raw();
    resolve_dlopen_observed(
        tid,
        expected_provider,
        version,
        || Snapshot::read(tid),
        |address, bytes: &mut [u8]| {
            let address =
                usize::try_from(address).map_err(|_| invalid("target address overflow"))?;
            task.read_exact(address, bytes)
                .map_err(|error| io::Error::other(format!("read target at {address:#x}: {error}")))
        },
    )
}

fn resolve_dlopen_observed<
    S: FnMut() -> io::Result<Snapshot>,
    F: FnMut(u64, &mut [u8]) -> io::Result<()>,
>(
    tid: i32,
    expected_provider: &[u8],
    version: &str,
    mut snapshot: S,
    read_memory: F,
) -> io::Result<TargetDlopen> {
    let before = snapshot()?;
    let maps = parse_maps(&before.maps)?;
    let aux = parse_auxv(&before.auxv)?;
    let provider = Provider::parse(expected_provider, version)?;
    let mut memory = Memory::new(&maps, read_memory);
    let mut result = resolve(&mut memory, &aux, &provider)?;
    if snapshot()? != before {
        return Err(invalid(
            "target process, maps, auxv or mount namespace changed",
        ));
    }
    result.tid = tid;
    result.start_ticks = before.start_ticks;
    Ok(result)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn add(a: u64, b: u64) -> io::Result<u64> {
    a.checked_add(b).ok_or_else(|| invalid("address overflow"))
}
fn range(bytes: &[u8], offset: u64, length: u64) -> io::Result<&[u8]> {
    let end = add(offset, length)?;
    bytes
        .get(
            usize::try_from(offset).map_err(|_| invalid("offset overflow"))?
                ..usize::try_from(end).map_err(|_| invalid("offset overflow"))?,
        )
        .ok_or_else(|| invalid("truncated ELF data"))
}
fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    start_ticks: u64,
    exe: (u64, u64),
    mount_namespace: (u64, u64),
    maps: Vec<u8>,
    auxv: Vec<u8>,
}
fn bounded_file(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("proc file exceeds bound"));
    }
    Ok(bytes)
}
impl Snapshot {
    fn read(tid: i32) -> io::Result<Self> {
        let root = format!("/proc/{tid}");
        let stat = bounded_file(&format!("{root}/stat"), 65536)?;
        let first = stat
            .split(|b| *b == b' ')
            .next()
            .ok_or_else(|| invalid("malformed proc stat"))?;
        if std::str::from_utf8(first)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            != Some(tid)
        {
            return Err(invalid("proc stat thread identity disagrees"));
        }
        let close = stat
            .iter()
            .rposition(|b| *b == b')')
            .ok_or_else(|| invalid("malformed proc stat"))?;
        let tail =
            std::str::from_utf8(&stat[close + 1..]).map_err(|_| invalid("malformed proc stat"))?;
        let start_ticks = tail
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| invalid("missing start ticks"))?
            .parse()
            .map_err(|_| invalid("invalid start ticks"))?;
        let exe = std::fs::metadata(format!("{root}/exe"))?;
        let ns = std::fs::metadata(format!("{root}/ns/mnt"))?;
        Ok(Self {
            start_ticks,
            exe: (exe.dev(), exe.ino()),
            mount_namespace: (ns.dev(), ns.ino()),
            maps: bounded_file(&format!("{root}/maps"), MAX_MAPS)?,
            auxv: bounded_file(&format!("{root}/auxv"), 8192)?,
        })
    }
}

#[derive(Debug, Clone)]
struct Map {
    start: u64,
    end: u64,
    offset: u64,
    identity: (u64, u64, u64),
    read: bool,
    write: bool,
    execute: bool,
    private: bool,
}
fn parse_maps(bytes: &[u8]) -> io::Result<Vec<Map>> {
    if bytes.len() > MAX_MAPS {
        return Err(invalid("maps exceeds bound"));
    }
    let mut maps: Vec<Map> = Vec::new();
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            return Err(invalid("empty maps line"));
        }
        let mut fields = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|f| !f.is_empty());
        let mut field = || fields.next().ok_or_else(|| invalid("truncated maps line"));
        let span = std::str::from_utf8(field()?).map_err(|_| invalid("invalid maps range"))?;
        let (start, end) = span
            .split_once('-')
            .ok_or_else(|| invalid("invalid maps range"))?;
        let hex = |s| u64::from_str_radix(s, 16).map_err(|_| invalid("invalid maps number"));
        let (start, end) = (hex(start)?, hex(end)?);
        let permissions = field()?;
        if permissions.len() != 4
            || !matches!(permissions[0], b'r' | b'-')
            || !matches!(permissions[1], b'w' | b'-')
            || !matches!(permissions[2], b'x' | b'-')
            || !matches!(permissions[3], b'p' | b's')
        {
            return Err(invalid("invalid maps permissions"));
        }
        let offset = hex(std::str::from_utf8(field()?).map_err(|_| invalid("invalid offset"))?)?;
        let device = std::str::from_utf8(field()?).map_err(|_| invalid("invalid device"))?;
        let (major, minor) = device
            .split_once(':')
            .ok_or_else(|| invalid("invalid device"))?;
        let identity = (
            hex(major)?,
            hex(minor)?,
            std::str::from_utf8(field()?)
                .map_err(|_| invalid("invalid inode"))?
                .parse()
                .map_err(|_| invalid("invalid inode"))?,
        );
        if start >= end || maps.last().is_some_and(|m| m.end > start) {
            return Err(invalid("overlapping or unordered maps"));
        }
        maps.push(Map {
            start,
            end,
            offset,
            identity,
            read: permissions[0] == b'r',
            write: permissions[1] == b'w',
            execute: permissions[2] == b'x',
            private: permissions[3] == b'p',
        });
    }
    if maps.is_empty() {
        return Err(invalid("empty maps"));
    }
    Ok(maps)
}
fn parse_auxv(bytes: &[u8]) -> io::Result<BTreeMap<u64, u64>> {
    let (entries, remainder) = bytes.as_chunks::<16>();
    if !remainder.is_empty() {
        return Err(invalid("truncated auxv"));
    }
    let mut result = BTreeMap::new();
    let mut ended = false;
    for entry in entries {
        let (tag, value) = (u64_at(entry, 0), u64_at(entry, 8));
        if ended && (tag != 0 || value != 0) {
            return Err(invalid("data after auxv terminator"));
        }
        if tag == 0 {
            ended = true;
            continue;
        }
        if result.insert(tag, value).is_some() {
            return Err(invalid("duplicate auxv tag"));
        }
    }
    if !ended {
        return Err(invalid("unterminated auxv"));
    }
    Ok(result)
}

struct Memory<'a, F> {
    maps: &'a [Map],
    read: F,
    observed: Vec<(u64, Vec<u8>)>,
    total: usize,
}
impl<'a, F: FnMut(u64, &mut [u8]) -> io::Result<()>> Memory<'a, F> {
    fn new(maps: &'a [Map], read: F) -> Self {
        Self {
            maps,
            read,
            observed: Vec::new(),
            total: 0,
        }
    }
    fn mapping(&self, address: u64) -> io::Result<&Map> {
        self.maps
            .iter()
            .find(|m| m.start <= address && address < m.end && m.read)
            .ok_or_else(|| invalid("target range is not readable"))
    }
    fn get(&mut self, address: u64, length: usize) -> io::Result<Vec<u8>> {
        self.total = self
            .total
            .checked_add(length)
            .ok_or_else(|| invalid("read budget overflow"))?;
        if self.total > MAX_READ {
            return Err(invalid("target read budget exceeded"));
        }
        let end = add(address, length as u64)?;
        let mut at = address;
        while at < end {
            at = self.mapping(at)?.end.min(end);
        }
        let mut bytes = vec![0; length];
        (self.read)(address, &mut bytes)?;
        self.observed.push((address, bytes.clone()));
        Ok(bytes)
    }
    fn recheck(&mut self) -> io::Result<()> {
        for (address, bytes) in &self.observed {
            let mut after = vec![0; bytes.len()];
            (self.read)(*address, &mut after)?;
            if &after != bytes {
                return Err(invalid("target memory changed during resolution"));
            }
        }
        Ok(())
    }
}

struct Provider<'a> {
    bytes: &'a [u8],
    elf: Elf<'a>,
    symbol: goblin::elf::sym::Sym,
    version: &'a str,
    dynamic: u64,
    dynamic_offset: u64,
    dynamic_size: u64,
}
impl<'a> Provider<'a> {
    fn parse(bytes: &'a [u8], version: &'a str) -> io::Result<Self> {
        if bytes.len() > MAX_FILE
            || version.is_empty()
            || version.len() > 128
            || version == "GLIBC_PRIVATE"
        {
            return Err(invalid("provider or version outside supported bounds"));
        }
        let elf = Elf::parse(bytes).map_err(|_| invalid("malformed provider ELF"))?;
        if !elf.is_64
            || !elf.little_endian
            || elf.header.e_machine != header::EM_X86_64
            || elf.header.e_type != header::ET_DYN
            || elf.header.e_ehsize != 64
            || elf.header.e_version != 1
            || elf.header.e_phentsize != 56
            || elf.program_headers.len() > 128
            || !matches!(elf.soname, Some("libc.so.6" | "libdl.so.2"))
        {
            return Err(invalid("provider is not supported libc/libdl ELF"));
        }
        validate_loads(&elf.program_headers)?;
        for p in &elf.program_headers {
            if p.p_type == ph::PT_LOAD {
                range(bytes, p.p_offset, p.p_filesz)?;
            }
        }
        let dynamic = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == ph::PT_DYNAMIC)
            .collect::<Vec<_>>();
        if dynamic.len() != 1 {
            return Err(invalid("ambiguous provider dynamic segment"));
        }
        let (dynamic, dynamic_offset, dynamic_size) =
            (dynamic[0].p_vaddr, dynamic[0].p_offset, dynamic[0].p_filesz);
        if dynamic_size == 0 || dynamic_size % 16 != 0 || dynamic_size / 16 > MAX_DYNAMIC as u64 {
            return Err(invalid("provider dynamic table exceeds bound"));
        }
        range(bytes, dynamic_offset, dynamic_size)?;
        if load_file_offset(&elf.program_headers, dynamic, dynamic_size, false)? != dynamic_offset {
            return Err(invalid("provider dynamic segment disagrees with load"));
        }
        let tags = elf
            .dynamic
            .as_ref()
            .ok_or_else(|| invalid("missing provider dynamic table"))?;
        if !tags
            .dyns
            .last()
            .is_some_and(|entry| entry.d_tag == dynamic::DT_NULL)
        {
            return Err(invalid("unterminated provider dynamic table"));
        }
        let mut unique = BTreeMap::new();
        for entry in &tags.dyns {
            if [
                dynamic::DT_STRTAB,
                dynamic::DT_STRSZ,
                dynamic::DT_SYMTAB,
                dynamic::DT_SYMENT,
                dynamic::DT_VERSYM,
                dynamic::DT_VERDEF,
                dynamic::DT_VERDEFNUM,
                dynamic::DT_HASH,
                dynamic::DT_GNU_HASH,
                dynamic::DT_SONAME,
                dynamic::DT_FLAGS,
            ]
            .contains(&entry.d_tag)
                && unique.insert(entry.d_tag, entry.d_val).is_some()
            {
                return Err(invalid("duplicate symbol metadata tag"));
            }
        }
        let tag = |key| {
            unique
                .get(&key)
                .copied()
                .ok_or_else(|| invalid("missing versioned symbol metadata"))
        };
        if tag(dynamic::DT_SYMENT)? != 24
            || tags.info.textrel
            || unique.get(&dynamic::DT_FLAGS).copied().unwrap_or(0) & dynamic::DF_TEXTREL != 0
            || elf.dynsyms.len() > 65536
        {
            return Err(invalid("unsupported provider symbols or text relocations"));
        }
        let strtab = Self::ro_file(
            &elf,
            bytes,
            tag(dynamic::DT_STRTAB)?,
            tag(dynamic::DT_STRSZ)?,
        )?;
        if c_string(
            strtab,
            usize::try_from(tag(dynamic::DT_SONAME)?)
                .map_err(|_| invalid("SONAME offset overflow"))?,
        )? != elf.soname.unwrap()
        {
            return Err(invalid("provider SONAME table disagreement"));
        }
        let symbols = Self::ro_file(
            &elf,
            bytes,
            tag(dynamic::DT_SYMTAB)?,
            (elf.dynsyms.len() * 24) as u64,
        )?;
        let versions = Self::ro_file(
            &elf,
            bytes,
            tag(dynamic::DT_VERSYM)?,
            (elf.dynsyms.len() * 2) as u64,
        )?;
        // Goblin's section-based verdef iterator may stop early on malformed
        // chains. Walk the bounded DT_VERDEF chain explicitly, using goblin's
        // ELF/load/symbol parsing and the loader's actual dynamic metadata.
        let count = tag(dynamic::DT_VERDEFNUM)?;
        if count == 0 || count > 256 {
            return Err(invalid("version definition count outside bound"));
        }
        let mut address = tag(dynamic::DT_VERDEF)?;
        let mut definitions = BTreeMap::new();
        for i in 0..count {
            let def = Self::ro_file(&elf, bytes, address, 20)?;
            let number = u16_at(def, 4);
            let flags = u16_at(def, 2);
            let aux_count = u16_at(def, 6);
            if number == 0
                || number & 0x8000 != 0
                || flags & !3 != 0
                || (flags & 1 != 0) != (number == 1)
                || u16_at(def, 0) != 1
                || aux_count == 0
                || aux_count > 256
                || u32_at(def, 12) < 20
            {
                return Err(invalid("malformed version definition"));
            }
            let next_definition = u32_at(def, 16);
            if (i + 1 == count) != (next_definition == 0)
                || (next_definition != 0 && next_definition < 20)
            {
                return Err(invalid("malformed version chain"));
            }
            let mut aux = add(address, u32_at(def, 12) as u64)?;
            let mut name = None;
            for j in 0..aux_count {
                if next_definition != 0 && add(aux, 8)? > add(address, next_definition as u64)? {
                    return Err(invalid("version auxiliary chain overlaps next definition"));
                }
                let value = Self::ro_file(&elf, bytes, aux, 8)?;
                let text = c_string(strtab, u32_at(value, 0) as usize)?;
                if j == 0 {
                    name = Some(text);
                }
                let next = u32_at(value, 4);
                if (j + 1 == aux_count) != (next == 0) || (next != 0 && next < 8) {
                    return Err(invalid("malformed version auxiliary chain"));
                }
                aux = add(aux, next as u64)?;
            }
            let name = name.unwrap();
            if u32_at(def, 8) != elf_hash(name.as_bytes()) {
                return Err(invalid("version definition hash disagrees"));
            }
            if definitions.insert(number, name).is_some() {
                return Err(invalid("duplicate version definition"));
            }
            address = add(address, next_definition as u64)?;
        }
        let mut selected = None;
        for index in 0..elf.dynsyms.len() {
            let symbol = elf
                .dynsyms
                .get(index)
                .ok_or_else(|| invalid("truncated dynamic symbols"))?;
            // Require agreement with the table named by DT_SYMTAB, not an
            // independently chosen section table or an unvalidated address.
            let record = &symbols[index * 24..(index + 1) * 24];
            if symbol.st_name != u32_at(record, 0) as usize
                || symbol.st_value != u64_at(record, 8)
                || symbol.st_size != u64_at(record, 16)
                || symbol.st_info != record[4]
                || symbol.st_other != record[5]
                || symbol.st_shndx != u16_at(record, 6) as usize
            {
                return Err(invalid("dynamic symbol table disagreement"));
            }
            if c_string(strtab, symbol.st_name)? != "dlopen" {
                continue;
            }
            let raw_version = u16_at(versions, index * 2);
            if raw_version & 0x8000 != 0 || raw_version <= 1 {
                continue;
            }
            if definitions.get(&(raw_version & 0x7fff)).copied() != Some(version) {
                continue;
            }
            if symbol.st_type() != sym::STT_FUNC
                || !matches!(symbol.st_bind(), sym::STB_GLOBAL | sym::STB_WEAK)
                || symbol.st_other != sym::STV_DEFAULT
                || symbol.st_shndx == 0
                || symbol.st_shndx >= 0xff00
                || symbol.st_size == 0
                || symbol.st_size > 1024 * 1024
            {
                return Err(invalid("dlopen is not a public normal function"));
            }
            Self::ro_file(&elf, bytes, symbol.st_value, symbol.st_size)?;
            if !elf.program_headers.iter().any(|p| {
                p.p_type == ph::PT_LOAD
                    && p.p_flags == (ph::PF_R | ph::PF_X)
                    && symbol.st_value >= p.p_vaddr
                    && add(symbol.st_value, symbol.st_size)
                        .ok()
                        .zip(add(p.p_vaddr, p.p_filesz).ok())
                        .is_some_and(|(a, b)| a <= b)
            }) {
                return Err(invalid("dlopen is not in executable provider bytes"));
            }
            if selected.replace(symbol).is_some() {
                return Err(invalid("ambiguous public dlopen symbol"));
            }
        }
        let symbol =
            selected.ok_or_else(|| invalid("requested default dlopen version is absent"))?;
        Ok(Self {
            bytes,
            elf,
            symbol,
            version,
            dynamic,
            dynamic_offset,
            dynamic_size,
        })
    }
    fn ro_file(elf: &Elf<'_>, bytes: &'a [u8], address: u64, len: u64) -> io::Result<&'a [u8]> {
        range(
            bytes,
            load_file_offset(&elf.program_headers, address, len, true)?,
            len,
        )
    }
}
fn c_string(bytes: &[u8], offset: usize) -> io::Result<&str> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| invalid("string offset outside table"))?;
    let tail = &tail[..tail.len().min(4096)];
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid("unterminated ELF string"))?;
    std::str::from_utf8(&tail[..end]).map_err(|_| invalid("invalid ELF string"))
}

fn elf_hash(bytes: &[u8]) -> u32 {
    let mut hash = 0_u32;
    for byte in bytes {
        hash = (hash << 4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        hash ^= high >> 24;
        hash &= !high;
    }
    hash
}

// File-backed PT_LOAD ranges must be unambiguous before translating addresses.
fn validate_loads(headers: &[goblin::elf::ProgramHeader]) -> io::Result<()> {
    let mut loads = Vec::new();
    for p in headers.iter().filter(|p| p.p_type == ph::PT_LOAD) {
        let end = add(p.p_vaddr, p.p_memsz)?;
        add(p.p_offset, p.p_filesz)?;
        if p.p_filesz > p.p_memsz
            || p.p_flags & !7 != 0
            || (p.p_align > 1
                && (!p.p_align.is_power_of_two()
                    || p.p_vaddr % p.p_align != p.p_offset % p.p_align))
        {
            return Err(invalid("malformed ELF load segment"));
        }
        if loads
            .iter()
            .any(|(start, stop)| p.p_vaddr < *stop && *start < end)
        {
            return Err(invalid("overlapping ELF load segments"));
        }
        loads.push((p.p_vaddr, end));
    }
    if loads.is_empty() {
        return Err(invalid("missing ELF load segments"));
    }
    Ok(())
}
fn load_file_offset(
    headers: &[goblin::elf::ProgramHeader],
    address: u64,
    length: u64,
    read_only: bool,
) -> io::Result<u64> {
    let end = add(address, length)?;
    let mut found = None;
    for p in headers.iter().filter(|p| p.p_type == ph::PT_LOAD) {
        if p.p_flags & ph::PF_R != 0
            && (!read_only || p.p_flags & ph::PF_W == 0)
            && address >= p.p_vaddr
            && end <= add(p.p_vaddr, p.p_filesz)?
        {
            let offset = add(p.p_offset, address - p.p_vaddr)?;
            if found.replace(offset).is_some() {
                return Err(invalid("ambiguous ELF file range"));
            }
        }
    }
    found.ok_or_else(|| invalid("ELF range is not in required readable load bytes"))
}

fn check_file_range<F: FnMut(u64, &mut [u8]) -> io::Result<()>>(
    memory: &Memory<'_, F>,
    address: u64,
    offset: u64,
    size: u64,
    identity: (u64, u64, u64),
) -> io::Result<()> {
    let end = add(address, size)?;
    let mut at = address;
    while at < end {
        let mapping = memory.mapping(at)?;
        if mapping.identity != identity
            || !mapping.private
            || add(mapping.offset, at - mapping.start)? != add(offset, at - address)?
        {
            return Err(invalid("mapped ELF file range disagrees"));
        }
        at = mapping.end.min(end);
    }
    Ok(())
}

fn resolve<F: FnMut(u64, &mut [u8]) -> io::Result<()>>(
    memory: &mut Memory<'_, F>,
    aux: &BTreeMap<u64, u64>,
    provider: &Provider<'_>,
) -> io::Result<TargetDlopen> {
    let aux = |tag| {
        aux.get(&tag)
            .copied()
            .ok_or_else(|| invalid("missing auxv entry"))
    };
    let phdr = aux(libc::AT_PHDR)?;
    let count = aux(libc::AT_PHNUM)?;
    if count == 0 || count > 128 || aux(libc::AT_PHENT)? != 56 {
        return Err(invalid("invalid executable program headers"));
    }
    let headers = memory.get(phdr, (count * 56) as usize)?;
    let mut phdr_segment = None;
    let mut dynamic_segment = None;
    let (header_records, remainder) = headers.as_chunks::<56>();
    debug_assert!(remainder.is_empty());
    let program_headers: Vec<_> = header_records
        .iter()
        .map(|p| goblin::elf::ProgramHeader {
            p_type: u32_at(p, 0),
            p_flags: u32_at(p, 4),
            p_offset: u64_at(p, 8),
            p_vaddr: u64_at(p, 16),
            p_paddr: u64_at(p, 24),
            p_filesz: u64_at(p, 32),
            p_memsz: u64_at(p, 40),
            p_align: u64_at(p, 48),
        })
        .collect();
    validate_loads(&program_headers)?;
    for p in header_records {
        if matches!(u32_at(p, 0), ph::PT_PHDR | ph::PT_DYNAMIC) && u64_at(p, 32) > u64_at(p, 40) {
            return Err(invalid("executable segment file size exceeds memory size"));
        }
        match u32_at(p, 0) {
            ph::PT_PHDR => {
                if phdr_segment
                    .replace((u64_at(p, 8), u64_at(p, 16), u64_at(p, 32)))
                    .is_some()
                {
                    return Err(invalid("duplicate PT_PHDR"));
                }
            }
            ph::PT_DYNAMIC
                if dynamic_segment
                    .replace((u64_at(p, 8), u64_at(p, 16), u64_at(p, 32)))
                    .is_some() =>
            {
                return Err(invalid("duplicate executable PT_DYNAMIC"));
            }
            ph::PT_DYNAMIC => {}
            _ => {}
        }
    }
    let (phdr_offset, phdr_vaddr, phdr_size) =
        phdr_segment.ok_or_else(|| invalid("missing executable PT_PHDR"))?;
    if load_file_offset(&program_headers, phdr_vaddr, phdr_size, false)? != phdr_offset {
        return Err(invalid("executable PT_PHDR disagrees with load"));
    }
    if phdr_size != count * 56 {
        return Err(invalid("executable PT_PHDR size disagrees"));
    }
    let main_bias = phdr
        .checked_sub(phdr_vaddr)
        .ok_or_else(|| invalid("invalid executable load bias"))?;
    let main_header = phdr
        .checked_sub(phdr_offset)
        .ok_or_else(|| invalid("invalid executable ELF header"))?;
    let header = memory.get(main_header, 64)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(u16_at(&header, 16), header::ET_EXEC | header::ET_DYN)
        || u16_at(&header, 18) != header::EM_X86_64
        || u64_at(&header, 32) != phdr_offset
        || u16_at(&header, 52) != 64
        || u16_at(&header, 54) != 56
        || u16_at(&header, 56) as u64 != count
    {
        return Err(invalid("executable ELF header disagrees with auxv"));
    }
    if u16_at(&header, 16) == header::ET_EXEC && main_bias != 0 {
        return Err(invalid("ET_EXEC has nonzero load bias"));
    }
    let header_vaddr = main_header
        .checked_sub(main_bias)
        .ok_or_else(|| invalid("ELF header load bias overflow"))?;
    if load_file_offset(&program_headers, header_vaddr, 64, true)? != 0 {
        return Err(invalid("executable ELF header disagrees with load"));
    }
    let main_identity = memory.mapping(main_header)?.identity;
    if main_identity.2 == 0 {
        return Err(invalid("executable headers have no mapped file identity"));
    }
    check_file_range(memory, main_header, 0, 64, main_identity)?;
    check_file_range(memory, phdr, phdr_offset, phdr_size, main_identity)?;
    let (dynamic_offset, dynamic_vaddr, dynamic_size) =
        dynamic_segment.ok_or_else(|| invalid("missing executable PT_DYNAMIC"))?;
    if dynamic_size == 0
        || !dynamic_size.is_multiple_of(16)
        || dynamic_size / 16 > MAX_DYNAMIC as u64
    {
        return Err(invalid("executable dynamic table exceeds bound"));
    }
    if load_file_offset(&program_headers, dynamic_vaddr, dynamic_size, false)? != dynamic_offset {
        return Err(invalid("executable dynamic segment disagrees with load"));
    }
    let main_dynamic = add(main_bias, dynamic_vaddr)?;
    check_file_range(
        memory,
        main_dynamic,
        dynamic_offset,
        dynamic_size,
        main_identity,
    )?;
    let table = memory.get(main_dynamic, dynamic_size as usize)?;
    let mut debug = None;
    let mut terminated = false;
    for d in table.as_chunks::<16>().0 {
        if u64_at(d, 0) == dynamic::DT_NULL {
            terminated = true;
            break;
        }
        if u64_at(d, 0) == dynamic::DT_DEBUG && debug.replace(u64_at(d, 8)).is_some() {
            return Err(invalid("duplicate DT_DEBUG"));
        }
    }
    if !terminated {
        return Err(invalid("unterminated executable dynamic table"));
    }
    let debug = debug
        .filter(|p| *p != 0)
        .ok_or_else(|| invalid("loader rendezvous is unavailable"))?;
    let rendezvous = memory.get(debug, 40)?;
    if !matches!(u32_at(&rendezvous, 0), 1 | 2)
        || u32_at(&rendezvous, 24) != 0
        || u64_at(&rendezvous, 32) != aux(libc::AT_BASE)?
    {
        return Err(invalid(
            "loader is not in a consistent default-namespace state",
        ));
    }
    let loader_base = aux(libc::AT_BASE)?;
    let loader_header = memory.get(loader_base, 64)?;
    if &loader_header[..7] != b"\x7fELF\x02\x01\x01"
        || u16_at(&loader_header, 16) != header::ET_DYN
        || u16_at(&loader_header, 18) != header::EM_X86_64
    {
        return Err(invalid("AT_BASE does not name an x86-64 interpreter ELF"));
    }
    let loader_mapping = memory.mapping(loader_base)?;
    if loader_mapping.write || !loader_mapping.private {
        return Err(invalid(
            "interpreter header is not private read-only memory",
        ));
    }
    let loader_identity = loader_mapping.identity;
    check_file_range(memory, loader_base, 0, 64, loader_identity)?;
    let breakpoint = memory.mapping(u64_at(&rendezvous, 16))?;
    if loader_identity.2 == 0
        || breakpoint.identity != loader_identity
        || !breakpoint.execute
        || breakpoint.write
        || !breakpoint.private
    {
        return Err(invalid(
            "loader rendezvous breakpoint is not in interpreter code",
        ));
    }
    let mut node = u64_at(&rendezvous, 8);
    let mut previous = 0;
    let mut visited = Vec::new();
    let mut selected = None;
    while node != 0 {
        if visited.len() >= MAX_LINKS || visited.contains(&node) {
            return Err(invalid("link map cycle or bound"));
        }
        visited.push(node);
        let link = memory.get(node, 40)?;
        let bias = u64_at(&link, 0);
        let ld = u64_at(&link, 16);
        if u64_at(&link, 32) != previous {
            return Err(invalid("inconsistent link map back pointer"));
        }
        if previous == 0 && (bias != main_bias || ld != main_dynamic) {
            return Err(invalid("default link map does not begin with executable"));
        }
        if ld == add(bias, provider.dynamic)? && provider_matches(memory, provider, bias)? {
            if selected.is_some() {
                return Err(invalid("provider appears twice in default namespace"));
            }
            let address = add(bias, provider.symbol.st_value)?;
            let mapping = memory.mapping(address)?;
            if !mapping.execute || mapping.write || !mapping.private {
                return Err(invalid("selected entry is not private executable memory"));
            }
            let identity = mapping.identity;
            selected = Some(TargetDlopen {
                tid: 0,
                start_ticks: 0,
                executable_phdr: phdr,
                link_map: node,
                load_bias: bias,
                address,
                version: provider.version.to_owned(),
                mapping_identity: identity,
            });
        }
        previous = node;
        node = u64_at(&link, 24);
    }
    let result =
        selected.ok_or_else(|| invalid("expected provider is absent from default link map"))?;
    memory.recheck()?;
    Ok(result)
}

fn provider_matches<F: FnMut(u64, &mut [u8]) -> io::Result<()>>(
    memory: &mut Memory<'_, F>,
    provider: &Provider<'_>,
    bias: u64,
) -> io::Result<bool> {
    let first = provider
        .elf
        .program_headers
        .iter()
        .find(|p| {
            p.p_type == ph::PT_LOAD
                && p.p_offset == 0
                && p.p_flags & ph::PF_R != 0
                && p.p_flags & ph::PF_W == 0
                && p.p_filesz >= 64
        })
        .ok_or_else(|| invalid("provider headers are not in first read-only load"))?;
    let start = add(bias, first.p_vaddr)?;
    let mapping = match memory.mapping(start) {
        Ok(m) => m,
        Err(_) => return Ok(false),
    };
    if mapping.identity.2 == 0 || mapping.write || !mapping.private {
        return Ok(false);
    }
    let identity = mapping.identity;
    if memory.get(start, 64)? != provider.bytes[..64] {
        return Ok(false);
    }
    // Establish the candidate's complete load layout before applying the
    // expected provider's permission and file-offset relationships. Different
    // DSOs can share the ELF header and dynamic RVA but have different loads.
    let phdr_offset = provider.elf.header.e_phoff;
    let phdr_size = (provider.elf.program_headers.len() * 56) as u64;
    let phdr_address = add(start, phdr_offset)?;
    check_file_range(memory, phdr_address, phdr_offset, phdr_size, identity)?;
    let headers = memory.get(phdr_address, phdr_size as usize)?;
    if headers != range(provider.bytes, phdr_offset, phdr_size)? {
        return Ok(false);
    }
    // Equal headers and a PT_DYNAMIC RVA do not identify a DSO. A different
    // object can precede the exact expected provider in the default list.
    // Still finish every range/read check: a byte mismatch must not hide an
    // observation failure or invalid mapping later in this candidate.
    let mut identical = true;
    for p in &provider.elf.program_headers {
        if p.p_type != ph::PT_LOAD || p.p_flags & ph::PF_W != 0 {
            continue;
        }
        if p.p_flags & ph::PF_R == 0 || p.p_filesz > p.p_memsz {
            return Err(invalid("invalid read-only provider load"));
        }
        let expected = range(provider.bytes, p.p_offset, p.p_filesz)?;
        let start = add(bias, p.p_vaddr)?;
        let end = add(start, p.p_filesz)?;
        let mut at = start;
        while at < end {
            let mapping = memory.mapping(at)?;
            if mapping.identity != identity
                || mapping.write
                || !mapping.private
                || mapping.execute != (p.p_flags & ph::PF_X != 0)
                || add(mapping.offset, at - mapping.start)? != add(p.p_offset, at - start)?
            {
                return Err(invalid(
                    "provider mapping identity, permissions or offset disagrees",
                ));
            }
            let amount = (mapping.end.min(end) - at).min(65536) as usize;
            let bytes = memory.get(at, amount)?;
            let offset = (at - start) as usize;
            if bytes != expected[offset..offset + amount] {
                identical = false;
            }
            at = add(at, amount as u64)?;
        }
    }
    check_file_range(
        memory,
        add(bias, provider.dynamic)?,
        provider.dynamic_offset,
        provider.dynamic_size,
        identity,
    )?;
    Ok(identical)
}

#[cfg(test)]
mod tests;
