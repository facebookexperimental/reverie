/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A non-PIE test guest for glibc_compat: its executable holds the canonical
//! PLT entries of `dl_iterate_phdr` and `gnu_get_libc_version`, so every
//! object's references to those functions bind to addresses in the executable,
//! not in libc. build.rs links it with `-no-pie`, and with the static unwinder
//! the guest preload uses.
//!
//! Given the path of a C bridge library, it prints one line,
//! `canonical=A static=B resolved=C caught=D`, each 0 or 1:
//! - canonical: both functions' addresses lie in the executable;
//! - static: neither `_dl_find_object` nor `_Unwind_RaiseException` is in the
//!   executable's dynamic symbols, so the unwinder is the static one and its
//!   `_dl_find_object` is glibc_compat's;
//! - resolved: `reverie::glibc_symbol` finds `_dl_find_object@GLIBC_2.35`
//!   exactly where `dlvsym` does (both absent counts);
//! - caught: a panic through a frame of the bridge, loaded with
//!   `dlmopen(LM_ID_NEWLM)`, is caught.

// Compile the same compatibility implementation as the preload leaf. The
// allocator-neutral core does not propagate this module or its linker policy.
#[path = "../glibc_compat.rs"]
mod glibc_compat;

#[used]
#[unsafe(link_section = ".init_array")]
static RESOLVE_REAL_DL_FIND_OBJECT: extern "C" fn() = glibc_compat::resolve_real_dl_find_object;

// The cdylib's native archive dependency does not propagate to this binary.
// Bind it here too; build.rs forces extraction before std's dynamic unwinder.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[link(name = "gcc_eh", kind = "static", modifiers = "-bundle")]
unsafe extern "C" {}

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_int;
use std::ffi::c_void;

// Absolute references from code link only into a non-PIE executable, where
// the linker gives each function a canonical PLT entry in the executable,
// which then is the function's address for every object.
std::arch::global_asm!(
    ".pushsection .text.reverie_liteinst_canonical_plt,\"ax\",@progbits",
    ".globl reverie_liteinst_canonical_plt",
    ".type reverie_liteinst_canonical_plt,@function",
    "reverie_liteinst_canonical_plt:",
    "mov eax, offset dl_iterate_phdr",
    "mov eax, offset gnu_get_libc_version",
    "ret",
    ".popsection",
);

unsafe extern "C" {
    fn reverie_liteinst_canonical_plt();
}

fn main() {
    // SAFETY: the function only loads two addresses into a scratch register.
    unsafe { reverie_liteinst_canonical_plt() };
    let bridge = std::env::args_os()
        .nth(1)
        .expect("usage: reverie-liteinst-glibc-compat-guest BRIDGE.so");
    let bridge = CString::new(bridge.into_encoded_bytes()).unwrap();
    // First, so that this is the process's first unwind.
    let caught = catch_a_panic_through_the_bridge(&bridge);
    let canonical = in_this_executable(libc::dl_iterate_phdr as *const () as usize)
        && in_this_executable(libc::gnu_get_libc_version as *const () as usize);
    let statically_bound = !dynamic_strings_contain(b"_dl_find_object")
        && !dynamic_strings_contain(b"_Unwind_RaiseException");
    let found = reverie::glibc_symbol::glibc_versioned_function(b"_dl_find_object", b"GLIBC_2.35");
    // SAFETY: both strings are NUL-terminated.
    let expected = unsafe {
        libc::dlvsym(
            libc::RTLD_DEFAULT,
            c"_dl_find_object".as_ptr(),
            c"GLIBC_2.35".as_ptr(),
        )
    };
    let expected = (!expected.is_null()).then_some(expected as usize);
    println!(
        "canonical={} static={} resolved={} caught={}",
        u8::from(canonical),
        u8::from(statically_bound),
        u8::from(found == expected),
        u8::from(caught)
    );
}

/// Loads the bridge into a new namespace and reports whether a panic through
/// it was caught.
fn catch_a_panic_through_the_bridge(path: &CStr) -> bool {
    // SAFETY: `path` names a shared object built by the test.
    let handle = unsafe { libc::dlmopen(libc::LM_ID_NEWLM, path.as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "cannot load the bridge");
    // SAFETY: `handle` is a loaded library.
    let symbol = unsafe { libc::dlsym(handle, c"bridge_call".as_ptr()) };
    assert!(!symbol.is_null());
    // SAFETY: the bridge defines bridge_call with this signature, and its
    // frame has unwind tables (-fexceptions).
    let bridge_call = unsafe {
        std::mem::transmute::<*mut c_void, unsafe extern "C-unwind" fn(extern "C-unwind" fn())>(
            symbol,
        )
    };
    extern "C-unwind" fn callback() {
        panic!("unwinding through the bridge");
    }
    // SAFETY: as above.
    std::panic::catch_unwind(|| unsafe { bridge_call(callback) }).is_err()
}

/// Whether `address` lies in the object that holds this function.
fn in_this_executable(address: usize) -> bool {
    let base = |address: usize| {
        // SAFETY: dladdr only fills `info`.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        let found = unsafe { libc::dladdr(address as *const c_void, &mut info) };
        (found != 0).then_some(info.dli_fbase as usize)
    };
    let this = in_this_executable as fn(usize) -> bool as usize;
    base(address).is_some() && base(address) == base(this)
}

/// Whether `name` is one of the executable's dynamic symbol names.
fn dynamic_strings_contain(name: &[u8]) -> bool {
    struct Search<'a> {
        name: &'a [u8],
        found: bool,
    }

    /// An ELF64 dynamic-section entry.
    #[repr(C)]
    struct Dyn {
        tag: i64,
        value: u64,
    }

    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut c_void,
    ) -> c_int {
        // SAFETY: `data` is the `Search` below, and the first object glibc
        // passes is the executable, whose program headers and dynamic section
        // are mapped and readable.
        let (search, info) = unsafe { (&mut *data.cast::<Search>(), &*info) };
        let base = info.dlpi_addr as usize;
        // SAFETY: as above.
        let headers = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum.into()) };
        let Some(dynamic) = headers
            .iter()
            .find(|header| header.p_type == libc::PT_DYNAMIC)
        else {
            return 1;
        };
        let mut entry = base.wrapping_add(dynamic.p_vaddr as usize) as *const Dyn;
        let (mut strtab, mut strsz) = (0, 0);
        loop {
            // SAFETY: the dynamic section ends with DT_NULL.
            let dyn_entry = unsafe { &*entry };
            match dyn_entry.tag {
                0 => break,
                5 => strtab = dyn_entry.value as usize,
                10 => strsz = dyn_entry.value as usize,
                _ => {}
            }
            // SAFETY: as above.
            entry = unsafe { entry.add(1) };
        }
        if strtab != 0 && strtab < base {
            strtab += base;
        }
        if strtab != 0 {
            // SAFETY: DT_STRTAB and DT_STRSZ describe the mapped string table.
            let strings = unsafe { std::slice::from_raw_parts(strtab as *const u8, strsz) };
            search.found = strings
                .split(|byte| *byte == 0)
                .any(|string| string == search.name);
        }
        1
    }

    let mut search = Search { name, found: false };
    // SAFETY: `visit` matches dl_iterate_phdr's callback contract and `search`
    // outlives the call.
    unsafe { libc::dl_iterate_phdr(Some(visit), (&raw mut search).cast()) };
    search.found
}
