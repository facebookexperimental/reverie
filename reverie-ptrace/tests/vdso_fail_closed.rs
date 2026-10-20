/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The vDSO patch is fail-closed: an entry point with no syscall equivalent
//! must not keep running the kernel's code unobserved.
//!
//! The x86_64 vDSO exports `__vdso_sgx_enter_enclave` on kernels built with
//! SGX support. Before the patch enumerated the vDSO's own symbol table, no
//! backend listed it, so it stayed native. Called with an invalid ENCLU leaf
//! the native code returns -EINVAL; the -ENOSYS stub returns -ENOSYS.

#![cfg(target_arch = "x86_64")]

use goblin::elf::Elf;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Sysno;

const SGX: &str = "__vdso_sgx_enter_enclave";
const CLOCK_GETTIME: &str = "__vdso_clock_gettime";

/// `mov $-ENOSYS, %rax; ret`
const ENOSYS_STUB: [u8; 8] = [0x48, 0xc7, 0xc0, 0xda, 0xff, 0xff, 0xff, 0xc3];

type SgxEnterEnclave = unsafe extern "C" fn(
    rdi: libc::c_ulong,
    rsi: libc::c_ulong,
    rdx: libc::c_ulong,
    function: libc::c_uint,
    r8: libc::c_ulong,
    r9: libc::c_ulong,
    run: *mut libc::c_void,
) -> libc::c_int;

/// Observes every syscall, the default.
#[derive(Debug, Default, Clone)]
struct AllSyscalls;

#[reverie::tool]
impl Tool for AllSyscalls {
    type GlobalState = ();
    type ThreadState = ();
}

/// Observes one syscall that has no vDSO fast path.
#[derive(Debug, Default, Clone)]
struct OpenatOnly;

#[reverie::tool]
impl Tool for OpenatOnly {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::openat]);
        s
    }
}

/// Observes no syscall at all.
#[derive(Debug, Default, Clone)]
struct NoSyscalls;

#[reverie::tool]
impl Tool for NoSyscalls {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }
}

/// The address of this process's vDSO entry point `name`, if exported.
fn resolve(name: &str) -> Option<usize> {
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
        .find(|sym| elf.dynstrtab.get_at(sym.st_name) == Some(name) && sym.st_value != 0)?;
    Some(start + symbol.st_value as usize)
}

fn entry_bytes(address: usize) -> [u8; 16] {
    unsafe { std::ptr::read_unaligned(address as *const [u8; 16]) }
}

/// Calls SGX enclave entry with leaf 0, which is neither EENTER nor ERESUME.
fn call_sgx_invalid_leaf(address: usize) -> libc::c_int {
    let sgx = unsafe { std::mem::transmute::<usize, SgxEnterEnclave>(address) };
    unsafe { sgx(0, 0, 0, 0, 0, 0, std::ptr::null_mut()) }
}

fn resolve_sgx() -> Option<usize> {
    let sgx = resolve(SGX);
    if sgx.is_none() {
        eprintln!("skipping: this kernel's vDSO exports no {SGX}");
    }
    sgx
}

#[test]
fn sgx_entry_is_stubbed_for_a_tool_observing_all_syscalls() {
    let Some(sgx) = resolve_sgx() else { return };
    assert_eq!(
        call_sgx_invalid_leaf(sgx),
        -libc::EINVAL,
        "native {SGX} rejects leaf 0"
    );

    reverie_ptrace::testing::check_fn::<AllSyscalls, _>(move || {
        assert_eq!(entry_bytes(sgx)[..8], ENOSYS_STUB, "{SGX} must be stubbed");
        assert_eq!(
            call_sgx_invalid_leaf(sgx),
            -libc::ENOSYS,
            "patched {SGX} must return -ENOSYS"
        );
    });
}

/// The stub does not depend on the tool subscribing to a vDSO syscall, while
/// an unsubscribed syscall fast path stays native.
#[test]
fn sgx_entry_is_stubbed_for_a_tool_observing_no_vdso_syscall() {
    let Some(sgx) = resolve_sgx() else { return };
    let clock_gettime = resolve(CLOCK_GETTIME).expect("the x86_64 vDSO exports clock_gettime");
    let native_clock_gettime = entry_bytes(clock_gettime);

    reverie_ptrace::testing::check_fn::<OpenatOnly, _>(move || {
        assert_eq!(
            call_sgx_invalid_leaf(sgx),
            -libc::ENOSYS,
            "patched {SGX} must return -ENOSYS"
        );
        assert_eq!(
            entry_bytes(clock_gettime),
            native_clock_gettime,
            "{CLOCK_GETTIME} is not subscribed and must stay native"
        );
    });
}

/// A tool that observes no syscall leaves the vDSO alone: nothing a vDSO
/// function does could bypass it.
#[test]
fn vdso_is_untouched_for_a_tool_observing_no_syscall() {
    let Some(sgx) = resolve_sgx() else { return };
    let native_sgx = entry_bytes(sgx);

    reverie_ptrace::testing::check_fn::<NoSyscalls, _>(move || {
        assert_eq!(entry_bytes(sgx), native_sgx);
        assert_eq!(call_sgx_invalid_leaf(sgx), -libc::EINVAL);
    });
}
