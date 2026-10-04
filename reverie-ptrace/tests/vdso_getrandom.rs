/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Regression coverage for the vDSO getrandom entry point under ptrace.
//!
//! Linux 6.11+ exports `__vdso_getrandom` (`__kernel_getrandom` on aarch64),
//! which glibc 2.41+ uses for `getrandom()`. Left unpatched it generates bytes
//! with an in-process ChaCha20 state and only re-keys through the getrandom
//! syscall when the host crng generation changes, so the guest's syscall
//! stream depends on host time and the tool never sees most draws.
//!
//! The patched entry point must:
//! - refuse glibc's parameter query `(NULL, 0, 0, params, ~0UL)` with -ENOSYS
//!   without writing `params`, so glibc never allocates vDSO state; and
//! - forward every other call to the getrandom syscall, so a caller that
//!   already holds state (such as a process that queried before patching)
//!   still observes the tool's result.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use goblin::elf::Elf;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;

#[cfg(target_arch = "x86_64")]
const SYMBOL: &str = "__vdso_getrandom";
#[cfg(target_arch = "aarch64")]
const SYMBOL: &str = "__kernel_getrandom";

/// A length no runtime library is expected to request, so only the guest's
/// own draws are counted.
const DRAW_LEN: usize = 37;
const DRAWS: usize = 5;
const PATTERN: u8 = 0xa5;

static DRAWS_SEEN: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Default, Clone)]
struct PatternTool;

#[reverie::tool]
impl Tool for PatternTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Getrandom(call) if call.buflen() == DRAW_LEN => {
                let buf = call.buf().expect("guest draws into a real buffer");
                guest.memory().write_exact(buf, &[PATTERN; DRAW_LEN])?;
                DRAWS_SEEN.fetch_add(1, Ordering::SeqCst);
                Ok(DRAW_LEN as i64)
            }
            otherwise => guest.tail_inject(otherwise).await,
        }
    }
}

/// The kernel's `struct vgetrandom_opaque_params`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpaqueParams {
    size_of_opaque_state: u32,
    mmap_prot: u32,
    mmap_flags: u32,
    reserved: [u32; 13],
}

type VdsoGetrandom = unsafe extern "C" fn(
    buffer: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_uint,
    opaque_state: *mut libc::c_void,
    opaque_len: libc::size_t,
) -> libc::ssize_t;

/// Resolves this process's vDSO getrandom entry point, if the kernel has one.
fn resolve_vdso_getrandom() -> Option<VdsoGetrandom> {
    let maps = procfs::process::Process::myself().ok()?.maps().ok()?;
    let vdso = maps
        .iter()
        .find(|map| map.pathname == procfs::process::MMapPath::Vdso)?;
    let start = vdso.address.0 as usize;
    let image =
        unsafe { std::slice::from_raw_parts(start as *const u8, vdso.address.1 as usize - start) };
    let elf = Elf::parse(image).ok()?;
    let symbol = elf
        .dynsyms
        .iter()
        .find(|sym| elf.dynstrtab.get_at(sym.st_name) == Some(SYMBOL) && sym.st_value != 0)?;
    Some(unsafe { std::mem::transmute::<usize, VdsoGetrandom>(start + symbol.st_value as usize) })
}

fn query(getrandom: VdsoGetrandom, params: &mut OpaqueParams) -> libc::ssize_t {
    unsafe {
        getrandom(
            std::ptr::null_mut(),
            0,
            0,
            (params as *mut OpaqueParams).cast(),
            !0,
        )
    }
}

#[test]
fn patched_vdso_getrandom_refuses_the_query_and_forwards_draws() {
    let Some(getrandom) = resolve_vdso_getrandom() else {
        eprintln!("skipping: this kernel's vDSO exports no {SYMBOL}");
        return;
    };
    // The guest must still be able to drive the original entry point the way
    // a process that queried before patching would, so take the kernel's
    // state shape natively, outside the guest.
    let mut native = OpaqueParams {
        size_of_opaque_state: 0,
        mmap_prot: 0,
        mmap_flags: 0,
        reserved: [0; 13],
    };
    let ret = query(getrandom, &mut native);
    if ret != 0 {
        eprintln!("skipping: native {SYMBOL} parameter query returned {ret}");
        return;
    }

    reverie_ptrace::testing::check_fn::<PatternTool, _>(move || {
        let sentinel = OpaqueParams {
            size_of_opaque_state: !0,
            mmap_prot: !0,
            mmap_flags: !0,
            reserved: [!0; 13],
        };
        let mut params = sentinel;
        let ret = query(getrandom, &mut params);
        assert_eq!(
            ret,
            -(libc::ENOSYS as libc::ssize_t),
            "patched {SYMBOL} must refuse the parameter query"
        );
        assert_eq!(params, sentinel, "a refused query must not write params");

        let state = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                native.size_of_opaque_state as usize,
                native.mmap_prot as libc::c_int,
                native.mmap_flags as libc::c_int,
                -1,
                0,
            )
        };
        assert_ne!(state, libc::MAP_FAILED, "allocate vDSO getrandom state");
        for draw in 0..DRAWS {
            let mut buf = [0u8; DRAW_LEN];
            let ret = unsafe {
                getrandom(
                    buf.as_mut_ptr().cast(),
                    DRAW_LEN,
                    0,
                    state,
                    native.size_of_opaque_state as libc::size_t,
                )
            };
            assert_eq!(ret, DRAW_LEN as libc::ssize_t, "draw {draw} length");
            assert_eq!(
                buf, [PATTERN; DRAW_LEN],
                "draw {draw} must come from the tool"
            );
        }
    });

    assert_eq!(
        DRAWS_SEEN.load(Ordering::SeqCst),
        DRAWS,
        "every draw must reach the tool as a getrandom syscall"
    );
}
