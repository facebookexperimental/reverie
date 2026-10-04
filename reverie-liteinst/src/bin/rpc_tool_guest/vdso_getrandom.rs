/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! LiteInst coverage for the vDSO getrandom entry point.
//!
//! glibc 2.41+ queries `__vdso_getrandom` during early startup, long before a
//! preloaded LiteInst runtime patches the vDSO, and keeps using vDSO state it
//! sized from that query. This guest reproduces that order: it queries and
//! allocates state natively, then installs the Tool, then requires that the
//! patched entry point refuses new queries and forwards every draw made with
//! the old state to the Tool as a getrandom syscall.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::path::Path;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;

#[cfg(target_arch = "x86_64")]
const SYMBOL: &core::ffi::CStr = c"__vdso_getrandom";
#[cfg(target_arch = "aarch64")]
const SYMBOL: &core::ffi::CStr = c"__kernel_getrandom";

/// A length no runtime library is expected to request.
const DRAW_LEN: usize = 37;
const DRAWS: usize = 5;
const PATTERN: u8 = 0xa5;

static DRAWS_SEEN: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct PatternTool;

#[reverie::tool]
impl Tool for PatternTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::getrandom].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Getrandom(call) if call.buflen() == DRAW_LEN => {
                let buf = call.buf().expect("guest draws into a real buffer");
                guest.memory().write_exact(buf, &[PATTERN; DRAW_LEN])?;
                DRAWS_SEEN.fetch_add(1, Ordering::Relaxed);
                Ok(DRAW_LEN as i64)
            }
            otherwise => Ok(guest.inject(otherwise).await?),
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

fn resolve() -> Option<VdsoGetrandom> {
    let vdso = unsafe {
        libc::dlopen(
            c"linux-vdso.so.1".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
        )
    };
    if vdso.is_null() {
        return None;
    }
    let symbol = unsafe { libc::dlsym(vdso, SYMBOL.as_ptr()) };
    (!symbol.is_null())
        .then(|| unsafe { core::mem::transmute::<*mut libc::c_void, VdsoGetrandom>(symbol) })
}

fn query(getrandom: VdsoGetrandom, params: &mut OpaqueParams) -> libc::ssize_t {
    unsafe {
        getrandom(
            core::ptr::null_mut(),
            0,
            0,
            (params as *mut OpaqueParams).cast(),
            !0,
        )
    }
}

pub(crate) fn run(path: &Path) {
    let Some(getrandom) = resolve() else {
        println!("vdso-getrandom=absent");
        return;
    };
    let mut native = OpaqueParams {
        size_of_opaque_state: 0,
        mmap_prot: 0,
        mmap_flags: 0,
        reserved: [0; 13],
    };
    let ret = query(getrandom, &mut native);
    if ret != 0 {
        println!("vdso-getrandom=unqueryable ret={ret}");
        return;
    }
    let state = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            native.size_of_opaque_state as usize,
            native.mmap_prot as libc::c_int,
            native.mmap_flags as libc::c_int,
            -1,
            0,
        )
    };
    assert_ne!(state, libc::MAP_FAILED, "allocate vDSO getrandom state");

    unsafe { reverie_liteinst::install_tool::<PatternTool>(path) }.unwrap();

    let sentinel = OpaqueParams {
        size_of_opaque_state: !0,
        mmap_prot: !0,
        mmap_flags: !0,
        reserved: [!0; 13],
    };
    let mut params = sentinel;
    assert_eq!(
        query(getrandom, &mut params),
        -(libc::ENOSYS as libc::ssize_t),
        "patched vDSO getrandom must refuse the parameter query"
    );
    assert_eq!(params, sentinel, "a refused query must not write params");

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
            "draw {draw} must come from the Tool"
        );
    }
    assert_eq!(DRAWS_SEEN.load(Ordering::Relaxed), DRAWS);
    println!("vdso-getrandom=patched draws={DRAWS}");
}
