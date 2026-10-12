/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The canonical vDSO: one fixed image that every backend maps into its
//! guests in place of the host kernel's vDSO.
//!
//! glibc's loader parses the vDSO's dynamic section and looks up the functions
//! it can use, and the branches it spends doing so become Detcore virtual time.
//! A guest that runs the host's vDSO therefore starts up differently on every
//! kernel whose vDSO differs, and a backend that cannot map the host's (KVM)
//! starts up differently from one that can (ptrace)
//! (<https://github.com/rrnewton/reverie/issues/947>). This image is the same on
//! every host: it exports the six functions glibc 2.42 looks up, under both of
//! the names the x86_64 kernel exports, and each is the syscall stub the patch
//! plan gives it, so a call reaches the Tool as a syscall.
//!
//! Like the kernel's, the image versions every export as `LINUX_2.6`
//! (`.gnu.version` and `.gnu.version_d`). Go's runtime walks the version
//! definitions of any vDSO it finds without checking that they exist, so an
//! unversioned image crashes every Go program at startup.

use std::sync::LazyLock;

use reverie_syscalls::Sysno;

use super::syscall_stub;

/// The guest address at which every backend maps [`canonical_vdso_image`].
/// It is below any address Linux gives a program without `MAP_FIXED`, and it is
/// where reverie-kvm's boot-reserved layout keeps its vDSO page.
pub const CANONICAL_VDSO_ADDRESS: u64 = 0x14f000;

/// The bytes reserved for the canonical vDSO: one page.
pub const CANONICAL_VDSO_SIZE: u64 = 4096;

/// The `LINUX_VERSION_CODE` in the canonical vDSO's kernel-version note,
/// which glibc reads (`_dl_discover_osversion`) instead of calling `uname(2)`:
/// 6.0.0, the release reverie-kvm reports through `uname(2)`.
pub const CANONICAL_LINUX_VERSION_CODE: u32 = 6 << 16;

/// Each function the image exports, by its `__vdso_` name, with its alias and
/// its syscall. These are the functions glibc 2.42 looks up on x86_64.
const FUNCTIONS: [(&str, &str, Sysno); 6] = [
    (
        "__vdso_clock_gettime",
        "clock_gettime",
        Sysno::clock_gettime,
    ),
    ("__vdso_gettimeofday", "gettimeofday", Sysno::gettimeofday),
    ("__vdso_time", "time", Sysno::time),
    ("__vdso_getcpu", "getcpu", Sysno::getcpu),
    ("__vdso_clock_getres", "clock_getres", Sysno::clock_getres),
    ("__vdso_getrandom", "getrandom", Sysno::getrandom),
];

static IMAGE: LazyLock<Vec<u8>> = LazyLock::new(build);

/// The canonical vDSO image, linked at 0, to be mapped at
/// [`CANONICAL_VDSO_ADDRESS`] and named by `AT_SYSINFO_EHDR`.
pub fn canonical_vdso_image() -> &'static [u8] {
    &IMAGE
}

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const SHDR_SIZE: usize = 64;
const SYM_SIZE: usize = 24;
const DYN_SIZE: usize = 16;
const VERSYM_SIZE: usize = 2;
const VERDEF_SIZE: usize = 20;
const VERDAUX_SIZE: usize = 8;

/// The kernel's vDSO soname, the name of its base version definition.
const SONAME: &str = "linux-vdso.so.1";
/// The one version the x86_64 kernel gives every vDSO export.
const VERSION: &str = "LINUX_2.6";
/// [`VERSION`]'s index in the version definitions; 1 is the base (soname).
const VERSION_INDEX: u16 = 2;
const VER_FLG_BASE: u16 = 1;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_SYMENT: u64 = 11;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_VERDEF: u64 = 0x6fff_fffc;
const DT_VERDEFNUM: u64 = 0x6fff_fffd;

const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STT_FUNC: u8 = 2;

/// Section indices, in the order of the section header table.
const SECTION_NAMES: [&str; 10] = [
    "",
    ".hash",
    ".dynsym",
    ".dynstr",
    ".gnu.version",
    ".gnu.version_d",
    ".text",
    ".note",
    ".dynamic",
    ".shstrtab",
];
const DYNSYM: usize = 2;
const DYNSTR: usize = 3;
const TEXT: usize = 6;
const SHSTRTAB: usize = 9;

/// One section header, linked at 0: an allocated section's address is its
/// offset.
#[derive(Default)]
struct Section {
    kind: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

fn put16(image: &mut [u8], at: usize, value: u16) {
    image[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(image: &mut [u8], at: usize, value: u32) {
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// The System V ELF hash, which version definitions carry for their names.
fn elf_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in name.bytes() {
        hash = (hash << 4).wrapping_add(u32::from(byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

/// A string table and the offset of each string in it.
fn string_table<'a>(strings: impl IntoIterator<Item = &'a str>) -> (Vec<u8>, Vec<usize>) {
    let mut table = vec![0];
    let mut offsets = Vec::new();
    for string in strings {
        if string.is_empty() {
            offsets.push(0);
            continue;
        }
        offsets.push(table.len());
        table.extend_from_slice(string.as_bytes());
        table.push(0);
    }
    (table, offsets)
}

fn build() -> Vec<u8> {
    // Symbols 1.. are each function's `__vdso_` name, then its alias.
    let names: Vec<&str> = FUNCTIONS
        .iter()
        .flat_map(|(name, alias, _)| [*name, *alias])
        .collect();
    let symbol_count = names.len() + 1;
    let (dynstr, string_offsets) = string_table(names.iter().copied().chain([SONAME, VERSION]));
    let name_offsets = &string_offsets[..names.len()];
    let soname_offset = string_offsets[names.len()];
    let version_offset = string_offsets[names.len() + 1];
    let (shstrtab, section_name_offsets) = string_table(SECTION_NAMES);
    let stubs: Vec<&[u8]> = FUNCTIONS
        .iter()
        .map(|(name, _, sysno)| {
            syscall_stub(*sysno).unwrap_or_else(|| panic!("{name} has no syscall stub"))
        })
        .collect();

    // File layout, which is also the address layout: the image is linked at 0.
    let phdrs = EHDR_SIZE;
    let hash = (phdrs + 3 * PHDR_SIZE).next_multiple_of(8);
    let hash_size = 4 * (2 + 1 + symbol_count);
    let dynsym = (hash + hash_size).next_multiple_of(8);
    let dynstr_at = dynsym + symbol_count * SYM_SIZE;
    let versym = (dynstr_at + dynstr.len()).next_multiple_of(2);
    let versym_size = symbol_count * VERSYM_SIZE;
    // Two definitions, each one verdef and the verdaux naming it.
    let verdef = (versym + versym_size).next_multiple_of(8);
    let verdef_size = 2 * (VERDEF_SIZE + VERDAUX_SIZE);
    let text = (verdef + verdef_size).next_multiple_of(16);
    let mut function_offsets = Vec::new();
    let mut text_end = text;
    for stub in &stubs {
        function_offsets.push(text_end);
        text_end = (text_end + stub.len()).next_multiple_of(16);
    }
    let note = text_end;
    let note_size = 12 + 8 + 4;
    let dynamic = (note + note_size).next_multiple_of(8);
    let dynamic_entries: [(u64, u64); 10] = [
        (DT_HASH, hash as u64),
        (DT_STRTAB, dynstr_at as u64),
        (DT_SYMTAB, dynsym as u64),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_SYMENT, SYM_SIZE as u64),
        (DT_SONAME, soname_offset as u64),
        (DT_VERSYM, versym as u64),
        (DT_VERDEF, verdef as u64),
        (DT_VERDEFNUM, 2),
        (DT_NULL, 0),
    ];
    let shstrtab_at = dynamic + dynamic_entries.len() * DYN_SIZE;
    let shdrs = (shstrtab_at + shstrtab.len()).next_multiple_of(8);
    let size = shdrs + SECTION_NAMES.len() * SHDR_SIZE;
    assert!(
        size as u64 <= CANONICAL_VDSO_SIZE,
        "canonical vDSO is {size} bytes"
    );
    // Never executed: fill between functions traps.
    let mut image = vec![0u8; size];
    image[text..text_end].fill(0xcc);

    // ELF header.
    image[0..4].copy_from_slice(b"\x7fELF");
    image[4] = 2; // ELFCLASS64
    image[5] = 1; // ELFDATA2LSB
    image[6] = 1; // EV_CURRENT
    put16(&mut image, 16, 3); // ET_DYN
    put16(&mut image, 18, 62); // EM_X86_64
    put32(&mut image, 20, 1); // e_version
    put64(&mut image, 32, phdrs as u64); // e_phoff
    put64(&mut image, 40, shdrs as u64); // e_shoff
    put16(&mut image, 52, EHDR_SIZE as u16);
    put16(&mut image, 54, PHDR_SIZE as u16);
    put16(&mut image, 56, 3); // e_phnum
    put16(&mut image, 58, SHDR_SIZE as u16);
    put16(&mut image, 60, SECTION_NAMES.len() as u16);
    put16(&mut image, 62, SHSTRTAB as u16);

    // Program headers: the whole image as one read+execute load, its dynamic
    // section and its note.
    let segments = [
        (PT_LOAD, PF_R | PF_X, 0, size, CANONICAL_VDSO_SIZE as usize),
        (
            PT_DYNAMIC,
            PF_R,
            dynamic,
            dynamic_entries.len() * DYN_SIZE,
            8,
        ),
        (PT_NOTE, PF_R, note, note_size, 4),
    ];
    for (index, (kind, flags, offset, length, align)) in segments.into_iter().enumerate() {
        let at = phdrs + index * PHDR_SIZE;
        put32(&mut image, at, kind);
        put32(&mut image, at + 4, flags);
        put64(&mut image, at + 8, offset as u64); // p_offset
        put64(&mut image, at + 16, offset as u64); // p_vaddr
        put64(&mut image, at + 24, offset as u64); // p_paddr
        put64(&mut image, at + 32, length as u64); // p_filesz
        put64(&mut image, at + 40, length as u64); // p_memsz
        put64(&mut image, at + 48, align as u64);
    }

    // SysV hash table with one bucket chaining every symbol: lookups walk the
    // whole table, the same walk on every host.
    put32(&mut image, hash, 1); // nbucket
    put32(&mut image, hash + 4, symbol_count as u32); // nchain
    put32(&mut image, hash + 8, 1); // bucket[0]: the first symbol
    for symbol in 1..symbol_count {
        let next = if symbol + 1 < symbol_count {
            symbol + 1
        } else {
            0
        };
        put32(&mut image, hash + 12 + 4 * symbol, next as u32);
    }

    // Dynamic symbols. Symbol 0 is the null symbol.
    for (index, name_offset) in name_offsets.iter().enumerate() {
        let function = index / 2;
        let binding = if index % 2 == 0 { STB_GLOBAL } else { STB_WEAK };
        let at = dynsym + (index + 1) * SYM_SIZE;
        put32(&mut image, at, *name_offset as u32); // st_name
        image[at + 4] = (binding << 4) | STT_FUNC; // st_info
        put16(&mut image, at + 6, TEXT as u16); // st_shndx
        put64(&mut image, at + 8, function_offsets[function] as u64); // st_value
        put64(&mut image, at + 16, stubs[function].len() as u64); // st_size
    }
    image[dynstr_at..dynstr_at + dynstr.len()].copy_from_slice(&dynstr);

    // Symbol versions: the null symbol is local (0), every export LINUX_2.6.
    for symbol in 1..symbol_count {
        put16(&mut image, versym + symbol * VERSYM_SIZE, VERSION_INDEX);
    }

    // Version definitions, as the kernel lays them out: the base definition
    // naming the soname, then LINUX_2.6, each followed by its one verdaux.
    let definitions = [
        (VER_FLG_BASE, 1, SONAME, soname_offset),
        (0, VERSION_INDEX, VERSION, version_offset),
    ];
    for (index, (flags, ndx, name, name_offset)) in definitions.into_iter().enumerate() {
        let at = verdef + index * (VERDEF_SIZE + VERDAUX_SIZE);
        let last = index + 1 == definitions.len();
        put16(&mut image, at, 1); // vd_version
        put16(&mut image, at + 2, flags); // vd_flags
        put16(&mut image, at + 4, ndx); // vd_ndx
        put16(&mut image, at + 6, 1); // vd_cnt
        put32(&mut image, at + 8, elf_hash(name)); // vd_hash
        put32(&mut image, at + 12, VERDEF_SIZE as u32); // vd_aux
        let next = if last { 0 } else { VERDEF_SIZE + VERDAUX_SIZE };
        put32(&mut image, at + 16, next as u32); // vd_next
        put32(&mut image, at + VERDEF_SIZE, name_offset as u32); // vda_name
        put32(&mut image, at + VERDEF_SIZE + 4, 0); // vda_next
    }

    for (offset, stub) in function_offsets.iter().zip(&stubs) {
        image[*offset..*offset + stub.len()].copy_from_slice(stub);
    }

    // The kernel-version note: "Linux", type 0, LINUX_VERSION_CODE.
    put32(&mut image, note, 6); // n_namesz
    put32(&mut image, note + 4, 4); // n_descsz
    put32(&mut image, note + 8, 0); // n_type
    image[note + 12..note + 18].copy_from_slice(b"Linux\0");
    put32(&mut image, note + 20, CANONICAL_LINUX_VERSION_CODE);

    for (index, (tag, value)) in dynamic_entries.into_iter().enumerate() {
        put64(&mut image, dynamic + index * DYN_SIZE, tag);
        put64(&mut image, dynamic + index * DYN_SIZE + 8, value);
    }
    image[shstrtab_at..shstrtab_at + shstrtab.len()].copy_from_slice(&shstrtab);

    let sections = [
        Section::default(),
        Section {
            kind: SHT_HASH,
            flags: SHF_ALLOC,
            offset: hash,
            size: hash_size,
            link: DYNSYM as u32,
            align: 8,
            entsize: 4,
            ..Section::default()
        },
        Section {
            kind: SHT_DYNSYM,
            flags: SHF_ALLOC,
            offset: dynsym,
            size: symbol_count * SYM_SIZE,
            link: DYNSTR as u32,
            info: 1,
            align: 8,
            entsize: SYM_SIZE as u64,
        },
        Section {
            kind: SHT_STRTAB,
            flags: SHF_ALLOC,
            offset: dynstr_at,
            size: dynstr.len(),
            align: 1,
            ..Section::default()
        },
        Section {
            kind: SHT_GNU_VERSYM,
            flags: SHF_ALLOC,
            offset: versym,
            size: versym_size,
            link: DYNSYM as u32,
            align: 2,
            entsize: VERSYM_SIZE as u64,
            ..Section::default()
        },
        Section {
            kind: SHT_GNU_VERDEF,
            flags: SHF_ALLOC,
            offset: verdef,
            size: verdef_size,
            link: DYNSTR as u32,
            info: definitions.len() as u32,
            align: 8,
            ..Section::default()
        },
        Section {
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            offset: text,
            size: text_end - text,
            align: 16,
            ..Section::default()
        },
        Section {
            kind: SHT_NOTE,
            flags: SHF_ALLOC,
            offset: note,
            size: note_size,
            align: 4,
            ..Section::default()
        },
        Section {
            kind: SHT_DYNAMIC,
            flags: SHF_ALLOC,
            offset: dynamic,
            size: dynamic_entries.len() * DYN_SIZE,
            link: DYNSTR as u32,
            align: 8,
            entsize: DYN_SIZE as u64,
            ..Section::default()
        },
        Section {
            kind: SHT_STRTAB,
            offset: shstrtab_at,
            size: shstrtab.len(),
            align: 1,
            ..Section::default()
        },
    ];
    for (index, section) in sections.into_iter().enumerate() {
        let at = shdrs + index * SHDR_SIZE;
        put32(&mut image, at, section_name_offsets[index] as u32);
        put32(&mut image, at + 4, section.kind);
        put64(&mut image, at + 8, section.flags);
        let address = if section.flags & SHF_ALLOC != 0 {
            section.offset
        } else {
            0
        };
        put64(&mut image, at + 16, address as u64);
        put64(&mut image, at + 24, section.offset as u64);
        put64(&mut image, at + 32, section.size as u64);
        put32(&mut image, at + 40, section.link);
        put32(&mut image, at + 44, section.info);
        put64(&mut image, at + 48, section.align);
        put64(&mut image, at + 56, section.entsize);
    }
    image
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subscription;
    use crate::vdso::KnownEntry;
    use crate::vdso::VdsoEntryKind;
    use crate::vdso::classify_vdso_image;
    use crate::vdso::patch_vdso_image;
    use crate::vdso::vdso_exports;

    #[test]
    fn the_canonical_vdso_fits_its_page() {
        assert!(canonical_vdso_image().len() as u64 <= CANONICAL_VDSO_SIZE);
    }

    /// Patching the canonical image changes nothing: every entry point is
    /// already the stub the patch plan gives it.
    #[test]
    fn the_canonical_vdso_is_a_fixed_point_of_the_patch_plan() {
        let image = canonical_vdso_image();
        let entries = classify_vdso_image(image).unwrap();
        assert_eq!(entries.len(), FUNCTIONS.len());
        for entry in &entries {
            assert!(
                matches!(entry.kind, VdsoEntryKind::Known(KnownEntry::Syscall(..))),
                "{}",
                entry.describe()
            );
        }
        let mut patched = image.to_vec();
        patch_vdso_image(&mut patched, &entries, &Subscription::all()).unwrap();
        assert_eq!(patched, image);
    }

    /// It exports the six functions glibc looks up, each under the kernel's
    /// two names.
    #[test]
    fn the_canonical_vdso_exports_the_functions_glibc_looks_up() {
        let mut names: Vec<String> = vdso_exports(canonical_vdso_image())
            .unwrap()
            .into_iter()
            .map(|export| export.name)
            .collect();
        names.sort();
        let mut expected: Vec<String> = FUNCTIONS
            .iter()
            .flat_map(|(name, alias, _)| [name.to_string(), alias.to_string()])
            .collect();
        expected.sort();
        assert_eq!(names, expected);
    }

    /// glibc reads the version from the "Linux" note of the vDSO's PT_NOTE.
    #[test]
    fn the_canonical_vdso_reports_its_fixed_kernel_version() {
        let image = canonical_vdso_image();
        let elf = goblin::elf::Elf::parse(image).unwrap();
        let notes: Vec<_> = elf
            .iter_note_headers(image)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].name, "Linux");
        assert_eq!(notes[0].n_type, 0);
        assert_eq!(notes[0].desc, CANONICAL_LINUX_VERSION_CODE.to_le_bytes());
        assert!(elf.dynamic.is_some());
    }

    /// Like the kernel's, the image names itself `linux-vdso.so.1`: glibc names
    /// the vDSO's link map from DT_SONAME, so `dlopen("linux-vdso.so.1",
    /// RTLD_NOLOAD)` finds it only if the image carries one.
    #[test]
    fn the_canonical_vdso_has_the_kernels_soname() {
        let elf = goblin::elf::Elf::parse(canonical_vdso_image()).unwrap();
        assert_eq!(elf.soname, Some(SONAME));
    }

    /// `LINUX_2.6`'s hash as Go's runtime (`vdsoLinuxVersion`) and glibc
    /// (`dl_vdso_vsym`) hard-code it.
    #[test]
    fn the_version_hash_is_the_one_go_and_glibc_expect() {
        assert_eq!(elf_hash(VERSION), 0x3ae_75f6);
    }

    /// Walk the version definitions the way Go's runtime does
    /// (`vdsoFindVersion` follows `DT_VERDEF` without checking that it
    /// exists), and check that every export carries the version it finds,
    /// as in the kernel's vDSO.
    #[test]
    fn the_canonical_vdso_versions_every_export_as_linux_2_6() {
        let image = canonical_vdso_image();
        let elf = goblin::elf::Elf::parse(image).unwrap();
        let dynamic = elf.dynamic.as_ref().unwrap();
        let tag = |wanted: u64| {
            dynamic
                .dyns
                .iter()
                .find(|entry| entry.d_tag == wanted)
                .map(|entry| entry.d_val as usize)
                .unwrap_or_else(|| panic!("no dynamic tag {wanted:#x}"))
        };
        let versym = tag(DT_VERSYM);
        let verdef = tag(DT_VERDEF);
        assert_eq!(tag(DT_VERDEFNUM), 2);
        let strtab = tag(DT_STRTAB);
        let u16_at = |at: usize| u16::from_le_bytes(image[at..at + 2].try_into().unwrap());
        let u32_at = |at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
        let string_at = |at: usize| {
            let end = image[at..].iter().position(|byte| *byte == 0).unwrap();
            std::str::from_utf8(&image[at..at + end]).unwrap()
        };

        let mut definitions = Vec::new();
        let mut def = verdef;
        loop {
            assert_eq!(u16_at(def), 1, "vd_version");
            assert_eq!(u16_at(def + 6), 1, "vd_cnt: one verdaux per definition");
            let aux = def + u32_at(def + 12) as usize;
            assert_eq!(u32_at(aux + 4), 0, "vda_next: no second verdaux");
            definitions.push((
                u16_at(def + 2),
                u16_at(def + 4),
                u32_at(def + 8),
                string_at(strtab + u32_at(aux) as usize).to_owned(),
            ));
            let next = u32_at(def + 16) as usize;
            if next == 0 {
                break;
            }
            def += next;
        }
        assert_eq!(
            definitions,
            [
                (VER_FLG_BASE, 1, elf_hash(SONAME), SONAME.to_owned()),
                (0, VERSION_INDEX, 0x3ae_75f6, VERSION.to_owned()),
            ]
        );

        // The section headers link the tables as the kernel's do:
        // .gnu.version to .dynsym, .gnu.version_d to .dynstr with sh_info
        // counting the definitions.
        let section = |name: &str| {
            elf.section_headers
                .iter()
                .find(|header| elf.shdr_strtab.get_at(header.sh_name) == Some(name))
                .unwrap_or_else(|| panic!("no {name} section"))
        };
        let versym_section = section(".gnu.version");
        assert_eq!(versym_section.sh_link as usize, DYNSYM);
        assert_eq!(versym_section.sh_entsize, VERSYM_SIZE as u64);
        assert_eq!(versym_section.sh_addr as usize, versym);
        let verdef_section = section(".gnu.version_d");
        assert_eq!(verdef_section.sh_link as usize, DYNSTR);
        assert_eq!(verdef_section.sh_info, 2);
        assert_eq!(verdef_section.sh_addr as usize, verdef);

        let symbols = elf.dynsyms.len();
        assert_eq!(symbols, 1 + 2 * FUNCTIONS.len());
        assert_eq!(u16_at(versym), 0, "the null symbol is local");
        for symbol in 1..symbols {
            assert_eq!(
                u16_at(versym + 2 * symbol),
                VERSION_INDEX,
                "symbol {symbol}"
            );
        }
    }
}
