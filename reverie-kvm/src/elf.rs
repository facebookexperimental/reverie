/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use goblin::elf::Elf;
use goblin::elf::header::EI_CLASS;
use goblin::elf::header::EI_DATA;
use goblin::elf::header::ELFCLASS64;
use goblin::elf::header::ELFDATA2LSB;
use goblin::elf::header::EM_X86_64;
use goblin::elf::header::ET_DYN;
use goblin::elf::header::ET_EXEC;
use goblin::elf::program_header::PF_X;
use goblin::elf::program_header::PT_INTERP;
use goblin::elf::program_header::PT_LOAD;

use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::PROGRAM_HEADERS_ADDRESS;

const PAGE_SIZE: u64 = 4096;
pub(crate) const STACK_LIMIT: u64 = 8 * 1024 * 1024;
const STACK_STRING_HEADROOM: u64 = 4096;
const MMAP_GAP: u64 = 1024 * 1024;
const MAX_PROGRAM_HEADERS_SIZE: usize = PAGE_SIZE as usize;
const MAX_INTERPRETER_BYTES: u64 = 16 * 1024 * 1024;
const MAIN_LOAD_BIAS: u64 = 2 * 1024 * 1024;
const INTERPRETER_LOAD_BIAS: u64 = 16 * 1024 * 1024;

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

#[derive(Debug)]
pub(crate) struct LoadedStaticElf {
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub program_break: u64,
    pub brk_limit: u64,
    pub mmap_next: u64,
    pub mmap_limit: u64,
    pub argv0: Vec<u8>,
    pub cwd: PathBuf,
    pub cwd_fd: std::fs::File,
    pub stdin: Option<std::fs::File>,
    pub auxv: Vec<(libc::c_ulong, libc::c_ulong)>,
    pub fs_base: u64,
    pub gs_base: u64,
    pub files: std::collections::BTreeMap<i32, std::fs::File>,
    pub closed_standard_fds: std::collections::BTreeSet<i32>,
}

pub(crate) fn load_static_elf(
    memory: &mut GuestMemory,
    image: &[u8],
    argv: &[&str],
    envp: &[&str],
    cwd: &Path,
) -> Result<LoadedStaticElf> {
    let elf = Elf::parse(image)?;
    validate_elf(&elf, true)?;

    let argv0 = *argv
        .first()
        .ok_or_else(|| Error::UnsupportedElf("argv must contain at least argv[0]".to_string()))?;
    for entry in argv.iter().chain(envp.iter()) {
        if entry.as_bytes().contains(&0) {
            return Err(Error::UnsupportedElf(
                "an argv/envp entry contains an embedded NUL byte".to_string(),
            ));
        }
    }

    let main_bias = if elf.header.e_type == ET_DYN {
        MAIN_LOAD_BIAS
    } else {
        0
    };
    let main_end = load_segments(memory, image, &elf, main_bias)?;
    let main_entry = main_bias
        .checked_add(elf.entry)
        .ok_or_else(|| Error::UnsupportedElf("main entry point overflow".to_string()))?;

    let (entry_point, at_base, image_end) = if let Some(path) = interpreter_path(image, &elf)? {
        if main_end > INTERPRETER_LOAD_BIAS {
            return Err(Error::UnsupportedElf(format!(
                "main image end {main_end:#x} overlaps interpreter base {INTERPRETER_LOAD_BIAS:#x}",
            )));
        }
        let interpreter_image = read_interpreter_image(&path)?;
        let interpreter = Elf::parse(&interpreter_image)?;
        validate_elf(&interpreter, false)?;
        if interpreter.header.e_type != ET_DYN {
            return Err(Error::UnsupportedElf(
                "program interpreter must be ET_DYN".to_string(),
            ));
        }
        let interpreter_end = load_segments(
            memory,
            &interpreter_image,
            &interpreter,
            INTERPRETER_LOAD_BIAS,
        )?;
        let interpreter_entry = INTERPRETER_LOAD_BIAS
            .checked_add(interpreter.entry)
            .ok_or_else(|| Error::UnsupportedElf("interpreter entry point overflow".to_string()))?;
        (
            interpreter_entry,
            INTERPRETER_LOAD_BIAS,
            main_end.max(interpreter_end),
        )
    } else {
        (main_entry, 0, main_end)
    };

    copy_program_headers(memory, image, &elf)?;
    let program_headers_address = elf
        .program_headers
        .iter()
        .find(|header| header.p_type == goblin::elf::program_header::PT_PHDR)
        .and_then(|header| main_bias.checked_add(header.p_vaddr))
        .unwrap_or(PROGRAM_HEADERS_ADDRESS);
    let (stack_pointer, auxv) = build_initial_stack(
        memory,
        &elf,
        argv,
        envp,
        program_headers_address,
        at_base,
        main_entry,
    )?;
    let program_break = align_up(main_end, PAGE_SIZE)?;
    let mmap_next = align_up(
        image_end
            .checked_add(MMAP_GAP)
            .ok_or_else(|| Error::UnsupportedElf("initial mmap base overflow".to_string()))?,
        PAGE_SIZE,
    )?;
    let mmap_limit = memory
        .guest_end()
        .checked_sub(STACK_LIMIT)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    if mmap_next >= mmap_limit {
        return Err(Error::LongModeMemoryTooSmall);
    }
    let brk_limit = if at_base == 0 {
        mmap_next
    } else {
        INTERPRETER_LOAD_BIAS
    };

    let cwd_fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(cwd)?;

    Ok(LoadedStaticElf {
        entry_point,
        stack_pointer,
        program_break,
        brk_limit,
        mmap_next,
        mmap_limit,
        argv0: argv0.as_bytes().to_vec(),
        cwd: cwd.to_owned(),
        cwd_fd,
        stdin: None,
        auxv,
        fs_base: 0,
        gs_base: 0,
        files: std::collections::BTreeMap::new(),
        closed_standard_fds: std::collections::BTreeSet::new(),
    })
}

fn validate_elf(elf: &Elf<'_>, allow_interpreter: bool) -> Result<()> {
    if elf.header.e_ident[EI_CLASS] != ELFCLASS64
        || elf.header.e_ident[EI_DATA] != ELFDATA2LSB
        || elf.header.e_machine != EM_X86_64
    {
        return Err(Error::UnsupportedElf(
            "expected a little-endian ELF64 x86-64 image".to_string(),
        ));
    }
    if elf.header.e_type != ET_EXEC && elf.header.e_type != ET_DYN {
        return Err(Error::UnsupportedElf(
            "only ET_EXEC and ET_DYN images are supported".to_string(),
        ));
    }
    if !allow_interpreter
        && elf
            .program_headers
            .iter()
            .any(|header| header.p_type == PT_INTERP)
    {
        return Err(Error::UnsupportedElf(
            "nested PT_INTERP is not supported".to_string(),
        ));
    }
    if !elf
        .program_headers
        .iter()
        .any(|header| header.p_type == PT_LOAD)
    {
        return Err(Error::UnsupportedElf(
            "image contains no PT_LOAD segments".to_string(),
        ));
    }
    Ok(())
}

fn interpreter_path(image: &[u8], elf: &Elf<'_>) -> Result<Option<String>> {
    let Some(header) = elf
        .program_headers
        .iter()
        .find(|header| header.p_type == PT_INTERP)
    else {
        return Ok(None);
    };
    let start = usize::try_from(header.p_offset)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP offset is too large".to_string()))?;
    let size = usize::try_from(header.p_filesz)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP size is too large".to_string()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::UnsupportedElf("PT_INTERP range overflow".to_string()))?;
    let bytes = image
        .get(start..end)
        .ok_or_else(|| Error::UnsupportedElf("PT_INTERP extends past the image".to_string()))?;
    let Some(bytes) = bytes.strip_suffix(&[0]) else {
        return Err(Error::UnsupportedElf(
            "PT_INTERP path is not NUL-terminated".to_string(),
        ));
    };
    if bytes.contains(&0) {
        return Err(Error::UnsupportedElf(
            "PT_INTERP path contains an embedded NUL".to_string(),
        ));
    }
    let path = std::str::from_utf8(bytes)
        .map_err(|_| Error::UnsupportedElf("PT_INTERP path is not UTF-8".to_string()))?;
    Ok(Some(path.to_string()))
}

fn read_interpreter_image(path: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|error| {
        Error::UnsupportedElf(format!("cannot open interpreter {path:?}: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::UnsupportedElf(format!("cannot stat interpreter {path:?}: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} is not a regular file",
        )));
    }
    if metadata.len() > MAX_INTERPRETER_BYTES {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} exceeds {MAX_INTERPRETER_BYTES} bytes",
        )));
    }

    let mut image = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_INTERPRETER_BYTES + 1)
        .read_to_end(&mut image)
        .map_err(|error| {
            Error::UnsupportedElf(format!("cannot read interpreter {path:?}: {error}"))
        })?;
    if image.len() as u64 > MAX_INTERPRETER_BYTES {
        return Err(Error::UnsupportedElf(format!(
            "interpreter {path:?} exceeds {MAX_INTERPRETER_BYTES} bytes",
        )));
    }
    Ok(image)
}

fn load_segments(
    memory: &mut GuestMemory,
    image: &[u8],
    elf: &Elf<'_>,
    load_bias: u64,
) -> Result<u64> {
    let entry = load_bias
        .checked_add(elf.entry)
        .ok_or_else(|| Error::UnsupportedElf("ELF entry point overflow".to_string()))?;
    let mut image_end = 0;
    let mut entry_is_executable = false;
    for header in elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
    {
        if header.p_filesz > header.p_memsz {
            return Err(Error::UnsupportedElf(format!(
                "PT_LOAD filesz {:#x} exceeds memsz {:#x}",
                header.p_filesz, header.p_memsz
            )));
        }

        let segment_start = load_bias
            .checked_add(header.p_vaddr)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))?;
        let segment_end = segment_start
            .checked_add(header.p_memsz)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD address overflow".to_string()))?;
        if segment_start < BOOT_RESERVED_END && segment_end > 0 {
            return Err(Error::UnsupportedElf(format!(
                "PT_LOAD {segment_start:#x}..{segment_end:#x} overlaps bootstrap memory"
            )));
        }

        let file_start = usize::try_from(header.p_offset)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD offset is too large".to_string()))?;
        let file_size = usize::try_from(header.p_filesz)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD filesz is too large".to_string()))?;
        let file_end = file_start
            .checked_add(file_size)
            .ok_or_else(|| Error::UnsupportedElf("PT_LOAD file range overflow".to_string()))?;
        let contents = image.get(file_start..file_end).ok_or_else(|| {
            Error::UnsupportedElf("PT_LOAD extends past the ELF image".to_string())
        })?;

        memory.write(segment_start, contents)?;
        let zero_start = segment_start + header.p_filesz;
        let zero_len = usize::try_from(header.p_memsz - header.p_filesz)
            .map_err(|_| Error::UnsupportedElf("PT_LOAD memsz is too large".to_string()))?;
        memory.zero(zero_start, zero_len)?;

        entry_is_executable |=
            header.p_flags & PF_X != 0 && (segment_start..segment_end).contains(&entry);
        image_end = image_end.max(segment_end);
    }

    if !entry_is_executable {
        return Err(Error::UnsupportedElf(
            "entry point is not inside an executable PT_LOAD segment".to_string(),
        ));
    }
    Ok(image_end)
}

fn copy_program_headers(memory: &mut GuestMemory, image: &[u8], elf: &Elf<'_>) -> Result<()> {
    let start = usize::try_from(elf.header.e_phoff)
        .map_err(|_| Error::UnsupportedElf("program-header offset is too large".to_string()))?;
    let size = usize::from(elf.header.e_phentsize)
        .checked_mul(usize::from(elf.header.e_phnum))
        .ok_or_else(|| Error::UnsupportedElf("program-header size overflow".to_string()))?;
    if size > MAX_PROGRAM_HEADERS_SIZE {
        return Err(Error::UnsupportedElf(
            "program-header table exceeds one page".to_string(),
        ));
    }
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::UnsupportedElf("program-header range overflow".to_string()))?;
    let headers = image.get(start..end).ok_or_else(|| {
        Error::UnsupportedElf("program-header table extends past the image".to_string())
    })?;
    memory.write(PROGRAM_HEADERS_ADDRESS, headers)
}

fn build_initial_stack(
    memory: &mut GuestMemory,
    elf: &Elf<'_>,
    argv: &[&str],
    envp: &[&str],
    program_headers_address: u64,
    at_base: u64,
    at_entry: u64,
) -> Result<(u64, Vec<(libc::c_ulong, libc::c_ulong)>)> {
    // Strings (argv[], envp[], the AT_RANDOM bytes) live in a high region that
    // grows downward from the top of guest memory; the pointer arrays and auxv
    // that reference them are written lower, at the final `rsp`.
    let mut cursor = memory.guest_end().saturating_sub(STACK_STRING_HEADROOM);

    // Push argv/envp strings, recording each guest address. argv[0] is first.
    let mut arg_addresses = Vec::with_capacity(argv.len());
    for arg in argv {
        cursor = push_c_string(memory, cursor, arg.as_bytes())?;
        arg_addresses.push(cursor);
    }
    let mut env_addresses = Vec::with_capacity(envp.len());
    for entry in envp {
        cursor = push_c_string(memory, cursor, entry.as_bytes())?;
        env_addresses.push(cursor);
    }
    let argv0_address = arg_addresses[0];

    let random = [
        0x52, 0x65, 0x76, 0x65, 0x72, 0x69, 0x65, 0x2d, 0x4b, 0x56, 0x4d, 0x2d, 0x45, 0x4c, 0x46,
        0x21,
    ];
    cursor = cursor
        .checked_sub(random.len() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write(cursor, &random)?;
    let random_address = cursor;

    // Build the SysV initial stack image, low to high:
    //   argc, argv[0..], NULL, envp[0..], NULL, auxv pairs.., AT_NULL/0
    let auxv = vec![
        (AT_PHDR, program_headers_address),
        (AT_PHENT, u64::from(elf.header.e_phentsize)),
        (AT_PHNUM, u64::from(elf.header.e_phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, at_base),
        (AT_ENTRY, at_entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, random_address),
        (AT_EXECFN, argv0_address),
    ];

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend_from_slice(&arg_addresses);
    words.push(0);
    words.extend_from_slice(&env_addresses);
    words.push(0);
    for (key, value) in &auxv {
        words.extend_from_slice(&[*key, *value]);
    }
    words.extend_from_slice(&[AT_NULL, 0]);

    let stack_size = (words.len() * std::mem::size_of::<u64>()) as u64;
    // The kernel enters `_start` with `%rsp` 16-byte aligned and argc at [rsp].
    cursor = cursor
        .checked_sub(stack_size)
        .ok_or(Error::LongModeMemoryTooSmall)?
        & !0xf;
    if cursor < memory.guest_end().saturating_sub(STACK_LIMIT) {
        return Err(Error::LongModeMemoryTooSmall);
    }

    let mut stack = Vec::with_capacity(stack_size as usize);
    for word in words {
        stack.extend_from_slice(&word.to_le_bytes());
    }
    memory.write(cursor, &stack)?;
    Ok((cursor, auxv))
}

/// Writes a NUL-terminated copy of `bytes` ending just below `cursor` and
/// returns the guest address of the first byte (the new, lower cursor).
fn push_c_string(memory: &mut GuestMemory, cursor: u64, bytes: &[u8]) -> Result<u64> {
    let start = cursor
        .checked_sub((bytes.len() + 1) as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    memory.write(start, bytes)?;
    memory.write(start + bytes.len() as u64, &[0])?;
    Ok(start)
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| Error::UnsupportedElf("address alignment overflow".to_string()))
}
