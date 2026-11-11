//! Regression (dh-6ocv6, mirroring dh-gpc0m): an included `.S`
//! chunk must not leave a non-executable section selected for
//! whatever assembly follows it in the same compiler output unit.
//! Both chunks below open with `.text` but historically ended
//! with a bare `.section .note.GNU-stack`, so a following chunk
//! with no section directive of its own landed in
//! `.note.GNU-stack` (not executable, not loaded).
//!
//! Deliberately dependency-free (no goblin/tempfile dev-deps):
//! `reverie-inguest/Cargo.toml` is pinned by size and sha256 in
//! `CONTENT_REVERIE_CATALOG`, so this test uses
//! `CARGO_TARGET_TMPDIR` scratch space and a minimal ELF64
//! symbol/section lookup instead.

#![cfg(target_arch = "x86_64")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const SHF_EXECINSTR: u64 = 0x4;
const SHT_SYMTAB: u32 = 2;

fn assemble(label: &str, source: String) -> Vec<u8> {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("gnu-stack-tails-{label}-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let input = directory.join("concat.s");
    let output = directory.join("concat.o");
    fs::write(&input, source).unwrap();
    let result = Command::new("cc")
        .args(["-x", "assembler", "-c"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to assemble section probe:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let bytes = fs::read(&output).unwrap();
    let _ = fs::remove_dir_all(&directory);
    bytes
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn strtab_name(tab: &[u8], offset: usize) -> String {
    let rest = &tab[offset..];
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

struct Section {
    name: String,
    sh_type: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

/// Minimal ELF64 little-endian relocatable lookup: return the
/// (section name, sh_flags) of the section defining `name`.
/// Only what this test needs; panics with context on any
/// structural surprise rather than guessing.
fn symbol_section(bytes: &[u8], name: &str) -> (String, u64) {
    assert!(
        bytes.len() >= 64 && &bytes[..4] == b"\x7fELF" && bytes[4] == 2 && bytes[5] == 1,
        "assembled probe must be an ELF64 little-endian object"
    );
    let shoff = read_u64(bytes, 0x28) as usize;
    let shentsize = read_u16(bytes, 0x3a) as usize;
    let shnum = read_u16(bytes, 0x3c) as usize;
    let shstrndx = read_u16(bytes, 0x3e) as usize;
    assert_eq!(shentsize, 64, "unexpected section header size");
    assert!(shnum > 0, "extended section numbering not supported here");
    let raw_sections: Vec<(usize, u32, u64, usize, usize, usize, usize)> = (0..shnum)
        .map(|index| {
            let base = shoff + index * shentsize;
            (
                read_u32(bytes, base) as usize,
                read_u32(bytes, base + 4),
                read_u64(bytes, base + 8),
                read_u64(bytes, base + 24) as usize,
                read_u64(bytes, base + 32) as usize,
                read_u32(bytes, base + 40) as usize,
                read_u64(bytes, base + 56) as usize,
            )
        })
        .collect();
    let shstr = {
        let (_, _, _, offset, size, _, _) = raw_sections[shstrndx];
        &bytes[offset..offset + size]
    };
    let sections: Vec<Section> = raw_sections
        .iter()
        .map(
            |&(name_off, sh_type, flags, offset, size, link, entsize)| Section {
                name: strtab_name(shstr, name_off),
                sh_type,
                flags,
                offset,
                size,
                link,
                entsize,
            },
        )
        .collect();
    let symtab = sections
        .iter()
        .find(|section| section.sh_type == SHT_SYMTAB)
        .expect("assembled probe must have a symbol table");
    let strtab_section = &sections[symtab.link];
    let strtab = &bytes[strtab_section.offset..strtab_section.offset + strtab_section.size];
    assert!(symtab.entsize >= 24, "unexpected symbol entry size");
    for index in 0..symtab.size / symtab.entsize {
        let base = symtab.offset + index * symtab.entsize;
        if strtab_name(strtab, read_u32(bytes, base) as usize) == name {
            let section = &sections[read_u16(bytes, base + 6) as usize];
            return (section.name.clone(), section.flags);
        }
    }
    panic!("assembled probe is missing symbol {name}");
}

fn assert_symbol_section_is_executable(bytes: &[u8], name: &str, executable: bool) {
    let (section_name, flags) = symbol_section(bytes, name);
    assert_eq!(
        flags & SHF_EXECINSTR != 0,
        executable,
        "symbol {name} landed in section {section_name} flags={flags:#x}"
    );
}

fn assert_tail_restores_text(label: &str, asm: &str, code_symbols: &[&str]) {
    // The probe deliberately carries no section directive: it
    // lands in whatever section the included chunk leaves active.
    let source = format!(
        ".intel_syntax noprefix\n{asm}\n\
         .globl __section_probe_after_tail\n\
         .type __section_probe_after_tail,@function\n\
         __section_probe_after_tail:\n\
         ret\n\
         .size __section_probe_after_tail, .-__section_probe_after_tail"
    );
    let bytes = assemble(label, source);
    for name in code_symbols {
        assert_symbol_section_is_executable(&bytes, name, true);
    }
    assert_symbol_section_is_executable(&bytes, "__section_probe_after_tail", true);
    eprintln!("{label}: tail restores an executable section");
}

#[test]
fn gnu_stack_tails_restore_text_section() {
    assert_tail_restores_text(
        "pkey_buffers/syscall.S",
        include_str!("../src/bin/pkey_buffers/syscall.S"),
        &["pkey_buffer_syscall"],
    );
    assert_tail_restores_text(
        "tool_region_keyed_oracle_probe.S",
        include_str!("../src/guest/tool_region_keyed_oracle_probe.S"),
        &[
            "reverie_keyed_oracle_load",
            "reverie_keyed_oracle_load_mov",
            "reverie_keyed_oracle_store",
            "reverie_keyed_oracle_store_mov",
            "reverie_keyed_oracle_sigreturn",
        ],
    );
}
