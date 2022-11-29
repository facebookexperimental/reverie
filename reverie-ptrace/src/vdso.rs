/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provides APIs to disable VDSOs at runtime.
use std::collections::HashMap;

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
use tracing::debug;

// Byte code for the new pseudo vdso functions which do the actual syscalls.
// Note: the byte code must be 8 bytes aligned
#[cfg(target_arch = "x86_64")]
mod vdso_syms {
    #![allow(non_upper_case_globals)]

    pub const time: &[u8; 8] = &[
        0xb8, 0xc9, 0x00, 0x00, 0x00, // mov %SYS_time, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ];

    pub const clock_gettime: &[u8; 8] = &[
        0xb8, 0xe4, 0x00, 0x00, 0x00, // mov SYS_clock_gettime, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ];

    pub const getcpu: &[u8; 8] = &[
        0xb8, 0x35, 0x01, 0x00, 0x00, // mov SYS_getcpu, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ];

    pub const gettimeofday: &[u8; 8] = &[
        0xb8, 0x60, 0x00, 0x00, 0x00, // mov SYS_gettimeofday, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ];

    pub const clock_getres: &[u8; 8] = &[
        0xb8, 0xe5, 0x00, 0x00, 0x00, // mov SYS_clock_getres, %eax
        0x0f, 0x05, // syscall
        0xc3, // retq
    ];
}

#[cfg(target_arch = "aarch64")]
mod vdso_syms {
    #![allow(non_upper_case_globals)]

    // See this example for how to generate the byte code: https://godbolt.org/z/hbzK7Ydc3
    //
    // Example below:
    // ```
    // __attribute__((noinline)) static int sys_gettimeofday(void) {
    //     register long x0 __asm__("x0");
    //     asm volatile("bti c; mov x8, 169; svc 0" : "=r"(x0) : : "memory", "cc");
    //     return (int)x0;
    // }
    // ```
    //
    // Notes:
    //  * The byte order below may be different from what the disassembler will
    //    show. aarch64 is little-endian by default whereas the 4-byte
    //    instructions are usually displayed in big-endian.
    //  * The aarch64 calling convention matches syscall arguments, so no need
    //    to adjust registers x0-x5 or the stack pointer before calling the
    //    syscall.
    //  * The `bti c` instruction is the "Branch Target Identification"
    //    instruction. This is here because this is the first instruction of the
    //    vdso function and will be the branch target. This also effectively
    //    serves as a NOP instruction to pad out the size of the thunk.
    //    See also
    //    https://developer.arm.com/documentation/ddi0596/2021-06/Base-Instructions/BTI--Branch-Target-Identification-

    pub const clock_getres: &[u8; 16] = &[
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x48, 0x0e, 0x80, 0xd2, // mov x8, 114 (#__NR_clock_getres)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];

    pub const clock_gettime: &[u8; 16] = &[
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x28, 0x0e, 0x80, 0xd2, // mov x8, 113 (#__NR_clock_gettime)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];

    pub const gettimeofday: &[u8; 16] = &[
        0x5f, 0x24, 0x03, 0xd5, // bti c
        0x28, 0x15, 0x80, 0xd2, // mov x8, 169 (#__NR_gettimeofday)
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];

    // On aarch64, the vdso version of rt_sigreturn is only 8 bytes, so our
    // patch can't exceed that size. However, since this syscall doesn't return,
    // we can just call it without the `ret` instruction.
    //
    // NOTE: This is currently *exactly* how the kernel implements the
    // rt_sigreturn vdso, so we could probably get away with not even patching
    // it. See also `linux/arch/arm64/kernel/vdso/sigreturn.S`.
    pub const rt_sigreturn: &[u8; 8] = &[
        0x68, 0x11, 0x80, 0xd2, // mov x8, 139 (#__NR_rt_sigreturn)
        0x01, 0x00, 0x00, 0xd4, // svc 0
    ];
}

#[cfg(target_arch = "x86_64")]
const VDSO_SYMBOLS: &[(&str, &[u8])] = &[
    ("__vdso_time", vdso_syms::time),
    ("__vdso_clock_gettime", vdso_syms::clock_gettime),
    ("__vdso_getcpu", vdso_syms::getcpu),
    ("__vdso_gettimeofday", vdso_syms::gettimeofday),
    ("__vdso_clock_getres", vdso_syms::clock_getres),
];

#[cfg(target_arch = "aarch64")]
const VDSO_SYMBOLS: &[(&str, &[u8])] = &[
    ("__kernel_clock_getres", vdso_syms::clock_getres),
    ("__kernel_clock_gettime", vdso_syms::clock_gettime),
    ("__kernel_gettimeofday", vdso_syms::gettimeofday),
    ("__kernel_rt_sigreturn", vdso_syms::rt_sigreturn),
];

/// Rounds up `value` so that it is a multiple of `alignment`.
fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & alignment.wrapping_neg()
}

lazy_static! {
    static ref VDSO_PATCH_INFO: HashMap<&'static str, (u64, usize, &'static [u8])> = {
        let info = vdso_get_symbols_info();
        let mut res = HashMap::new();

        for (k, v) in VDSO_SYMBOLS {
            if let Some(&(base, size)) = info.get(*k) {
                // NOTE: There is padding at the end of every VDSO entry to
                // bring it up to a 16-byte size alignment. The dynamic symbol
                // table doesn't report the aligned size, so we must do the same
                // alignment here. For example, some VDSO entries might only be
                // 5 bytes, but they have padding to align them up to 16 bytes.
                let aligned_size = align_up(size, 16);
                assert!(
                    v.len() <= aligned_size,
                    "vdso symbol {}'s real size is {} bytes, but trying to replace it with {} bytes",
                    k,
                    size,
                    v.len()
                );
                res.insert(*k, (base, aligned_size, *v));
            }
        }

        res
    };
}

// get vdso symbols offset/size from current process
// assuming vdso binary is the same for all processes
// so that we don't have to decode vdso for each process
fn vdso_get_symbols_info() -> HashMap<&'static str, (u64, usize)> {
    let mut res = HashMap::new();
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
                        if let Some((name, _)) =
                            VDSO_SYMBOLS.iter().find(|&(name, _)| name == &sym_name)
                        {
                            debug_assert!(sym.is_function());
                            res.insert(*name, (sym.st_value, sym.st_size as usize));
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
    fn test_align_up() {
        assert_eq!(align_up(0, 16), 0);
        assert_eq!(align_up(1, 16), 16);
        assert_eq!(align_up(15, 16), 16);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(17, 16), 32);
    }

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
