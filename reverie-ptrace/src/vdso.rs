/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! provide APIs to disable VDSOs at runtime.
use goblin::elf::Elf;

use lazy_static::lazy_static;
use nix::sys::mman::ProtFlags;
use nix::unistd;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Mprotect;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use std::collections::HashMap;
use tracing::debug;

/*
 * byte code for the new psudo vdso functions
 * which do the actual syscalls.
 * NB: the byte code must be 8 bytes
 * aligned
 */

#[allow(non_upper_case_globals)]
const __vdso_time: &[u8] = &[
    0xb8, 0xc9, 0x0, 0x0, 0x0, // mov %SYS_time, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

#[allow(non_upper_case_globals)]
const __vdso_clock_gettime: &[u8] = &[
    0xb8, 0xe4, 0x00, 0x00, 0x00, // mov SYS_clock_gettime, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

#[allow(non_upper_case_globals)]
const __vdso_getcpu: &[u8] = &[
    0x48, 0x85, 0xff, // test %rdi, %rdi
    0x74, 0x06, // je ..
    0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // movl $0x0, (%rdi)
    0x48, 0x85, 0xf6, // test %rsi, %rsi
    0x74, 0x06, // je ..
    0xc7, 0x06, 0x00, 0x00, 0x00, 0x00, // movl $0x0, (%rsi)
    0x31, 0xc0, // xor %eax, %eax
    0xc3, // retq
    0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
]; // nopl 0x0(%rax)

#[allow(non_upper_case_globals)]
const __vdso_gettimeofday: &[u8] = &[
    0xb8, 0x60, 0x00, 0x00, 0x00, // mov SYS_gettimeofday, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

#[allow(non_upper_case_globals)]
const __vdso_clock_getres: &[u8] = &[
    0xb8, 0xe5, 0x00, 0x00, 0x00, // mov SYS_clock_getres, %eax
    0x0f, 0x05, // syscall
    0xc3, // retq
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax, %rax, 1)
    0x00,
];

const VDSO_SYMBOLS: &[(&str, &[u8])] = &[
    ("__vdso_time", __vdso_time),
    ("__vdso_clock_gettime", __vdso_clock_gettime),
    ("__vdso_getcpu", __vdso_getcpu),
    ("__vdso_gettimeofday", __vdso_gettimeofday),
    ("__vdso_clock_getres", __vdso_clock_getres),
];

lazy_static! {
    static ref VDSO_PATCH_INFO: HashMap<String, (u64, usize, &'static [u8])> = {
        let info = vdso_get_symbols_info();
        let mut res: HashMap<String, (u64, usize, &'static [u8])> = HashMap::new();

        for (k, v) in VDSO_SYMBOLS {
            let name = String::from(*k);
            if let Some(&(base, size)) = info.get(&name) {
                assert!(v.len() <= size);
                res.insert(String::from(*k), (base, size, v));
            }
        }
        res
    };
}

// get vdso symbols offset/size from current process
// assuming vdso binary is the same for all processes
// so that we don't have to decode vdso for each process
fn vdso_get_symbols_info() -> HashMap<String, (u64, usize)> {
    let mut res: HashMap<String, (u64, usize)> = HashMap::new();
    procfs::process::Process::new(unistd::getpid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .find(|e| e.pathname == procfs::process::MMapPath::Vdso)
        .and_then(|vdso| {
            let slice = unsafe {
                std::slice::from_raw_parts(
                    vdso.address.0 as *mut u8,
                    (vdso.address.1 - vdso.address.0) as usize,
                )
            };
            Elf::parse(slice)
                .map(|elf| {
                    let strtab = elf.dynstrtab;
                    elf.dynsyms.iter().for_each(|sym| {
                        let sym_name = &strtab[sym.st_name];
                        if VDSO_SYMBOLS.iter().any(|&(name, _)| name == sym_name) {
                            debug_assert!(sym.is_function());
                            res.insert(
                                String::from(sym_name),
                                (sym.st_value, sym.st_size as usize),
                            );
                        }
                    });
                })
                .ok()
        });
    res
}

/// patch VDSOs when enabled
///
/// `guest` must be in one of ptrace's stopped states.
pub async fn vdso_patch<G, T>(guest: &mut G) -> Result<(), Error>
where
    G: Guest<T>,
    T: Tool,
{
    if let Some(vdso) = procfs::process::Process::new(guest.pid().as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .find(|e| e.pathname == procfs::process::MMapPath::Vdso)
    {
        let mut memory = guest.memory();

        // Allow write access to the vdso memory page.
        guest
            .inject_with_retry(
                Mprotect::new()
                    .with_addr(AddrMut::from_raw(vdso.address.0 as usize))
                    .with_len((vdso.address.1 - vdso.address.0) as usize)
                    .with_protection(
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
                    ),
            )
            .await?;

        for (name, (offset, size, bytes)) in VDSO_PATCH_INFO.iter() {
            let start = vdso.address.0 + offset;
            assert!(bytes.len() <= *size);
            let rptr = AddrMut::from_raw(start as usize).unwrap();
            memory.write_exact(rptr, bytes)?;
            assert!(*size >= bytes.len());
            if *size > bytes.len() {
                let fill: Vec<u8> = std::iter::repeat(0x90u8).take(size - bytes.len()).collect();
                memory.write_exact(unsafe { rptr.add(bytes.len()) }, &fill)?;
            }
            debug!("{} patched {}@{:x}", guest.pid(), name, start);
        }

        guest
            .inject_with_retry(
                Mprotect::new()
                    .with_addr(AddrMut::from_raw(vdso.address.0 as usize))
                    .with_len((vdso.address.1 - vdso.address.0) as usize)
                    .with_protection(ProtFlags::PROT_READ | ProtFlags::PROT_EXEC),
            )
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_find_vdso() {
        assert!(
            procfs::process::Process::new(unistd::getpid().as_raw())
                .and_then(|p| p.maps())
                .unwrap_or_else(|_| Vec::new())
                .iter()
                .any(|e| e.pathname == procfs::process::MMapPath::Vdso)
        );
    }

    #[test]
    fn vdso_can_find_symbols_info() {
        assert!(!vdso_get_symbols_info().is_empty());
    }

    #[test]
    fn vdso_patch_info_is_valid() {
        let info = &VDSO_PATCH_INFO;
        info.iter().for_each(|i| println!("info: {:x?}", i));
        assert!(!info.is_empty());
    }
}
