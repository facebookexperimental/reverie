/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! FullTool callback routing, selected before the guest branch clock starts.
//!
//! Native strace/compat retain their existing callbacks and signal-stack
//! behavior. The unpublished exact-syscall adapter has its own continuation
//! protocol and is deliberately not part of this table.

use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;
use std::io;

use liteinst2::trampoline::HookCallback;
use liteinst2::trampoline::HookContext;
pub(crate) use reverie_inguest::guest::installed_stack::PreparedCallbacks;

pub(super) struct Callbacks {
    pub(super) syscall: HookCallback,
    pub(super) cpuid: HookCallback,
    pub(super) rdtsc: HookCallback,
    pub(super) rdtscp: HookCallback,
    pub(super) time: HookCallback,
    pub(super) clock_gettime: HookCallback,
    pub(super) getcpu: HookCallback,
    pub(super) gettimeofday: HookCallback,
    pub(super) clock_getres: HookCallback,
    pub(super) getrandom: HookCallback,
}

static LEGACY: Callbacks = Callbacks {
    syscall: super::installed_syscall_hook,
    cpuid: super::installed_cpuid_hook,
    rdtsc: super::installed_rdtsc_hook,
    rdtscp: super::installed_rdtscp_hook,
    time: super::installed_vdso_time_hook,
    clock_gettime: super::installed_vdso_clock_gettime_hook,
    getcpu: super::installed_vdso_getcpu_hook,
    gettimeofday: super::installed_vdso_gettimeofday_hook,
    clock_getres: super::installed_vdso_clock_getres_hook,
    getrandom: super::installed_vdso_getrandom_hook,
};

static OWNED: Callbacks = Callbacks {
    syscall: owned_syscall_entry,
    cpuid: owned_cpuid_entry,
    rdtsc: owned_rdtsc_entry,
    rdtscp: owned_rdtscp_entry,
    time: owned_vdso_time_entry,
    clock_gettime: owned_vdso_clock_gettime_entry,
    getcpu: owned_vdso_getcpu_entry,
    gettimeofday: owned_vdso_gettimeofday_entry,
    clock_getres: owned_vdso_clock_getres_entry,
    getrandom: owned_vdso_getrandom_entry,
};

// Both possible targets are immutable process-lifetime tables. Native modes
// never call prepare(), and retain the exact original Rust entry addresses.
static SELECTED: AtomicPtr<Callbacks> = AtomicPtr::new((&raw const LEGACY).cast_mut());

pub(crate) fn prepare() -> io::Result<PreparedCallbacks> {
    let prepared = reverie_inguest::guest::installed_stack::prepare()?;
    // Pool ownership/publication has completed. Select every route before
    // initialize_rcb_clock; no later mode branch or lazy setup is required.
    SELECTED.store((&raw const OWNED).cast_mut(), Ordering::Release);
    Ok(prepared)
}

#[inline]
pub(super) fn selected() -> &'static Callbacks {
    // SAFETY: the initial and sole replacement pointers refer to the two
    // immutable static tables above. Neither is freed or modified.
    unsafe { &*SELECTED.load(Ordering::Acquire) }
}

macro_rules! owned_entry {
    ($entry:ident, $body:path) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $entry(_context: *mut HookContext) {
            // RDI is still the real HookContext. LI has already captured the
            // guest state; RSI is a caller-clobbered native bridge argument.
            // There is no Rust prologue, stack write, TLS access or resolver.
            core::arch::naked_asm!(
                "endbr64",
                "lea rsi, [rip + {body}]",
                "jmp {entry}",
                body = sym $body,
                entry = sym reverie_inguest::guest::installed_stack::entry,
            );
        }
    };
}

owned_entry!(owned_syscall_entry, super::installed_syscall_hook);
owned_entry!(owned_cpuid_entry, super::installed_cpuid_hook);
owned_entry!(owned_rdtsc_entry, super::installed_rdtsc_hook);
owned_entry!(owned_rdtscp_entry, super::installed_rdtscp_hook);
owned_entry!(owned_vdso_time_entry, super::installed_vdso_time_hook);
owned_entry!(
    owned_vdso_clock_gettime_entry,
    super::installed_vdso_clock_gettime_hook
);
owned_entry!(owned_vdso_getcpu_entry, super::installed_vdso_getcpu_hook);
owned_entry!(
    owned_vdso_gettimeofday_entry,
    super::installed_vdso_gettimeofday_hook
);
owned_entry!(
    owned_vdso_clock_getres_entry,
    super::installed_vdso_clock_getres_hook
);
owned_entry!(
    owned_vdso_getrandom_entry,
    super::installed_vdso_getrandom_hook
);

#[cfg(test)]
mod tests {
    use iced_x86::Decoder;
    use iced_x86::DecoderOptions;
    use iced_x86::Mnemonic;
    use iced_x86::Register;

    use super::*;

    // The checked addresses are the callback table's actual entries, not a
    // second test bridge. Each must reach its original Rust body only through
    // the common stack-owning entry, before a prologue can touch guest memory.
    #[test]
    fn actual_owned_callback_entries_have_only_native_transfers() {
        let entries = [
            (OWNED.syscall, LEGACY.syscall),
            (OWNED.cpuid, LEGACY.cpuid),
            (OWNED.rdtsc, LEGACY.rdtsc),
            (OWNED.rdtscp, LEGACY.rdtscp),
            (OWNED.time, LEGACY.time),
            (OWNED.clock_gettime, LEGACY.clock_gettime),
            (OWNED.getcpu, LEGACY.getcpu),
            (OWNED.gettimeofday, LEGACY.gettimeofday),
            (OWNED.clock_getres, LEGACY.clock_getres),
            (OWNED.getrandom, LEGACY.getrandom),
        ];
        for (entry, body) in entries {
            // SAFETY: each entry is the naked function above containing the
            // 4-byte ENDBR, 7-byte RIP-relative LEA and 5-byte direct JMP.
            let bytes = unsafe { std::slice::from_raw_parts(entry as *const u8, 16) };
            let mut decoder =
                Decoder::with_ip(64, bytes, entry as usize as u64, DecoderOptions::NONE);
            assert_eq!(decoder.decode().mnemonic(), Mnemonic::Endbr64);
            let address = decoder.decode();
            assert_eq!(address.mnemonic(), Mnemonic::Lea);
            assert_eq!(address.op0_register(), Register::RSI);
            assert!(address.is_ip_rel_memory_operand());
            assert_eq!(address.ip_rel_memory_address(), body as usize as u64);
            let jump = decoder.decode();
            assert_eq!(jump.mnemonic(), Mnemonic::Jmp);
            assert_eq!(
                jump.near_branch_target(),
                reverie_inguest::guest::installed_stack::entry as *const () as u64
            );
            assert_eq!(decoder.position(), bytes.len());
        }
    }

    #[test]
    fn full_tool_preparation_publishes_every_callback_route() {
        const CHILD: &str = "REVERIE_LITEINST_CALLBACK_ROUTE_TEST_CHILD";
        const COMPLETED: &str = "FULL_TOOL_CALLBACK_ROUTES_CHECKED";
        if std::env::var_os(CHILD).is_none() {
            // Process-local publication is one-way, like real installation.
            // A fresh test process keeps other tests' native mode untouched.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::installed_entries::tests::full_tool_preparation_publishes_every_callback_route",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            print!("{stdout}");
            eprint!("{stderr}");
            assert!(
                output.status.success(),
                "callback publication child: {}",
                output.status
            );
            assert_eq!(stdout.lines().filter(|line| *line == COMPLETED).count(), 1);
            return;
        }

        assert!(std::ptr::eq(selected(), &LEGACY));
        assert_routes(&LEGACY);
        let _proof = prepare().unwrap();
        assert!(std::ptr::eq(selected(), &OWNED));
        assert_routes(&OWNED);
        // libtest may already have printed its unfinished "test ..." line.
        println!("\n{COMPLETED}");
    }

    fn assert_routes(expected: &Callbacks) {
        use super::super::InstructionEventKind;

        for (kind, callback) in [
            (InstructionEventKind::Cpuid, expected.cpuid),
            (InstructionEventKind::Rdtsc, expected.rdtsc),
            (InstructionEventKind::Rdtscp, expected.rdtscp),
        ] {
            assert!(std::ptr::fn_addr_eq(
                super::super::instruction_callback(kind),
                callback
            ));
        }
        for (number, callback) in [
            (libc::SYS_time, expected.time),
            (libc::SYS_clock_gettime, expected.clock_gettime),
            (libc::SYS_getcpu, expected.getcpu),
            (libc::SYS_gettimeofday, expected.gettimeofday),
            (libc::SYS_clock_getres, expected.clock_getres),
            (libc::SYS_getrandom, expected.getrandom),
        ] {
            assert!(std::ptr::fn_addr_eq(
                super::super::vdso_callback(number).unwrap(),
                callback
            ));
        }
        assert!(std::ptr::fn_addr_eq(selected().syscall, expected.syscall));
    }
}
