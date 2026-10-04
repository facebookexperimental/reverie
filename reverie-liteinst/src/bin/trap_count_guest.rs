/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::arch::global_asm;
use std::ffi::CStr;

const CALLS: u64 = 32;

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_fixed_getpid
    .hidden reverie_liteinst_fixed_getpid
    .type reverie_liteinst_fixed_getpid,@function
reverie_liteinst_fixed_getpid:
    .cfi_startproc
    mov eax, 39
    .global reverie_liteinst_fixed_getpid_site
    .hidden reverie_liteinst_fixed_getpid_site
reverie_liteinst_fixed_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_fixed_getpid, .-reverie_liteinst_fixed_getpid

    .p2align 6
    .global reverie_liteinst_self_lea
    .hidden reverie_liteinst_self_lea
    .type reverie_liteinst_self_lea,@function
reverie_liteinst_self_lea:
    .cfi_startproc
    mov eax, 39
    .global reverie_liteinst_self_lea_syscall
    .hidden reverie_liteinst_self_lea_syscall
reverie_liteinst_self_lea_syscall:
    syscall
    .global reverie_liteinst_self_lea_site
    .hidden reverie_liteinst_self_lea_site
reverie_liteinst_self_lea_site:
    lea rax, [rip + reverie_liteinst_self_lea_site]
    ret
    .cfi_endproc
    .size reverie_liteinst_self_lea, .-reverie_liteinst_self_lea

    .p2align 6
    .global reverie_liteinst_start_lea
    .hidden reverie_liteinst_start_lea
    .type reverie_liteinst_start_lea,@function
reverie_liteinst_start_lea:
    .cfi_startproc
    mov eax, 39
    .global reverie_liteinst_start_lea_syscall
    .hidden reverie_liteinst_start_lea_syscall
reverie_liteinst_start_lea_syscall:
    syscall
    lea rax, [rip + reverie_liteinst_start_lea]
    ret
    .cfi_endproc
    .size reverie_liteinst_start_lea, .-reverie_liteinst_start_lea
"#
);

unsafe extern "C" {
    fn reverie_liteinst_fixed_getpid() -> i64;
    static reverie_liteinst_fixed_getpid_site: u8;
    fn reverie_liteinst_self_lea() -> u64;
    static reverie_liteinst_self_lea_syscall: u8;
    static reverie_liteinst_self_lea_site: u8;
    fn reverie_liteinst_start_lea() -> u64;
    static reverie_liteinst_start_lea_syscall: u8;
}

type CountFn = unsafe extern "C" fn(u64) -> u64;

unsafe fn count_function(name: &CStr) -> CountFn {
    // SAFETY: RTLD_DEFAULT searches already loaded DSOs and name is terminated.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    assert!(!symbol.is_null(), "missing preload counter export");
    // SAFETY: both exported counter symbols have this exact C ABI.
    unsafe { core::mem::transmute(symbol) }
}

fn main() {
    if let Some(mode) = std::env::args().nth(1) {
        match mode.as_str() {
            "pc-relative-native" => self_lea(false),
            "pc-relative-hooked" => self_lea(true),
            _ => panic!("unknown trap-count mode: {mode}"),
        }
        return;
    }

    let mut expected = None;
    for _ in 0..CALLS {
        // SAFETY: the assembly function preserves the C ABI and returns getpid.
        let observed = unsafe { reverie_liteinst_fixed_getpid() };
        assert_eq!(*expected.get_or_insert(observed), observed);
    }

    let address = core::ptr::addr_of!(reverie_liteinst_fixed_getpid_site) as usize as u64;
    // SAFETY: names and exported function signatures are fixed by the runtime.
    let traps = unsafe { count_function(c"reverie_liteinst_site_trap_count")(address) };
    // SAFETY: names and exported function signatures are fixed by the runtime.
    let hooks = unsafe { count_function(c"reverie_liteinst_site_hook_count")(address) };
    println!("calls={CALLS} traps={traps} hooks={hooks}");
    assert_eq!(traps, 1);
    assert_eq!(hooks, CALLS);
}

fn self_lea(hooked: bool) {
    // In both functions the two-byte syscall and seven-byte LEA share the
    // displaced prefix.
    //
    // reverie_liteinst_self_lea's LEA names its own retained instruction, so a
    // relocation that treats the address as an internal encoder label returns
    // a trampoline address. That address lies inside the displaced bytes, and
    // the entry census cannot tell a computed code address from a later jump
    // target (https://github.com/rrnewton/reverie/issues/812), so LiteInst
    // must leave this site on the trap path and every call must still return
    // the original address. liteinst2's own relocation tests keep covering
    // the retained-LEA encoding.
    //
    // reverie_liteinst_start_lea's LEA names the function start, outside the
    // displaced bytes, so the site is patched and its relocated LEA must still
    // return the original address.
    let expected = core::ptr::addr_of!(reverie_liteinst_self_lea_site) as usize as u64;
    let start = reverie_liteinst_start_lea as unsafe extern "C" fn() -> u64 as usize as u64;
    let mut addresses = 0;
    let mut start_addresses = 0;
    for call in 0..CALLS {
        // SAFETY: the function preserves the C ABI and computes an address.
        let observed = unsafe { reverie_liteinst_self_lea() };
        assert_eq!(
            observed, expected,
            "self-relative LEA changed at call {call}"
        );
        addresses += 1;
        // SAFETY: the function preserves the C ABI and computes an address.
        let observed = unsafe { reverie_liteinst_start_lea() };
        assert_eq!(observed, start, "function-start LEA changed at call {call}");
        start_addresses += 1;
    }
    if hooked {
        let address = core::ptr::addr_of!(reverie_liteinst_self_lea_syscall) as usize as u64;
        // SAFETY: the runtime exports both functions with this exact C ABI.
        let traps = unsafe { count_function(c"reverie_liteinst_site_trap_count")(address) };
        let hooks = unsafe { count_function(c"reverie_liteinst_site_hook_count")(address) };
        assert_eq!(traps, CALLS);
        assert_eq!(hooks, 0);
        let start_address = core::ptr::addr_of!(reverie_liteinst_start_lea_syscall) as usize as u64;
        // SAFETY: the runtime exports both functions with this exact C ABI.
        let start_traps =
            unsafe { count_function(c"reverie_liteinst_site_trap_count")(start_address) };
        let start_hooks =
            unsafe { count_function(c"reverie_liteinst_site_hook_count")(start_address) };
        assert_eq!(start_traps, 1);
        assert_eq!(start_hooks, CALLS);
        println!(
            "pc-relative hooked: calls={CALLS} addresses={addresses} traps={traps} hooks={hooks} \
             start_addresses={start_addresses} start_traps={start_traps} start_hooks={start_hooks}"
        );
    } else {
        // SAFETY: dlsym only searches already loaded DSOs for this fixed name.
        let counter = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"reverie_liteinst_site_trap_count".as_ptr(),
            )
        };
        assert!(
            counter.is_null(),
            "native oracle loaded the LiteInst runtime"
        );
        println!(
            "pc-relative native: calls={CALLS} addresses={addresses} \
             start_addresses={start_addresses}"
        );
    }
}
