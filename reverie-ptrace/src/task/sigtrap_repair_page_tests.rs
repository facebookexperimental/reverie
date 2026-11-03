/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The SIGTRAP repair without `mseal` (Linux before 6.10): the repair page is
//! used unsealed, as this crate's test switch
//! (`SigtrapRepairTestSwitches::unseal_on_this_thread`) forces on a kernel
//! that has `mseal`. Every state of `sigtrap_steps` must survive as it does
//! with the page sealed, and a page the guest replaced must never be written:
//! the repair is reported lost instead. Without the switch the page is sealed
//! wherever `mseal` works.
//!
//! The switch exists only under `cfg(test)`, so these are the crate's own unit
//! tests rather than integration tests. They run the guests of
//! `tests/sigtrap_steps`, which `tests/sigtrap_state_timer_steps.rs` runs
//! with the page sealed.

#[path = "../../tests/sigtrap_steps/mod.rs"]
mod sigtrap_steps;

use std::io::Write;

use super::SigtrapRepairTestSwitches;

/// Makes the tracers this test starts, on its own thread, leave their repair
/// pages unsealed.
fn unsealed() {
    SigtrapRepairTestSwitches::unseal_on_this_thread();
}

#[test]
fn unsealed_sigtrap_action_and_mask_survive_precise_timer_steps() {
    unsealed();
    sigtrap_steps::sigtrap_action_and_mask_survive_precise_timer_steps();
}

#[test]
fn unsealed_sigtrap_state_survives_a_timer_step_over_sigreturn() {
    unsealed();
    sigtrap_steps::sigtrap_state_survives_a_timer_step_over_sigreturn();
}

#[test]
fn unsealed_a_repair_at_a_seccomp_stop_runs_the_syscall_once() {
    unsealed();
    sigtrap_steps::a_repair_at_a_seccomp_stop_runs_the_syscall_once();
}

/// A guest that maps its own page over the unsealed repair page: Reverie must
/// never write into it. The guest fills the page, ignores SIGTRAP, and lets a
/// timer's steps reset it, which would owe a repair through the page; the
/// page must come back exactly as the guest left it, and SIGTRAP's action as
/// the reset left it (the repair is lost, and reported).
#[test]
fn a_replaced_unsealed_repair_page_is_never_written() {
    unsealed();
    if !reverie_ptrace::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    reverie_ptrace::testing::check_fn::<sigtrap_steps::SyscallSteppingTool, _>(|| {
        // SAFETY: plain libc calls; the mapping is the guest's own, made over
        // Reverie's unsealed page on purpose, and only this thread runs.
        unsafe {
            let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let mapped = libc::mmap(
                reverie_ptrace::testing::sigtrap_repair_page() as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            assert_eq!(
                mapped as usize,
                reverie_ptrace::testing::sigtrap_repair_page(),
                "map over the repair page"
            );
            std::ptr::write_bytes(mapped.cast::<u8>(), 0x5a, page);
            let mut ignore: libc::sigaction = std::mem::zeroed();
            ignore.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ignore.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, &ignore, std::ptr::null_mut()),
                0
            );
            for _ in 0..4 {
                // The Tool arms a timer 40 branches out; its steps reach the
                // next syscall, where a repair would run.
                libc::getpid();
                libc::getppid();
            }
            let untouched = std::slice::from_raw_parts(mapped.cast::<u8>(), page)
                .iter()
                .all(|&byte| byte == 0x5a);
            // The steps did reset the ignored SIGTRAP, so a repair was owed,
            // and it was lost rather than written through the guest's page.
            let mut now: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
                0
            );
            let _ = writeln!(
                std::io::stderr(),
                "guest page untouched: {untouched}, action {:#x}",
                now.sa_sigaction
            );
            assert!(untouched, "Reverie wrote into the guest's page");
            assert_eq!(now.sa_sigaction, libc::SIG_DFL, "no repair was owed");
        }
    });
}

/// `mseal(2)`'s number on x86-64 and aarch64, which `libc` does not name.
const SYS_MSEAL: libc::c_long = 462;

/// Whether `mseal` works on this kernel, tried on a page of this process,
/// which stays mapped and sealed.
fn mseal_works() -> bool {
    // SAFETY: a fresh private anonymous page of this process, which nothing
    // else uses, is mapped and sealed.
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED, "map a page to seal");
        libc::syscall(SYS_MSEAL, mapped, page, 0) == 0
    }
}

/// Without the test switch the repair page is sealed wherever `mseal` works:
/// a guest's `mmap` over it fails with EPERM exactly there. The tracer starts
/// on a thread of its own, on which no switch was ever set, so the switch's
/// default decides.
#[test]
fn the_repair_page_is_sealed_by_default() {
    let sealed = mseal_works();
    std::thread::spawn(move || {
        reverie_ptrace::testing::check_fn::<sigtrap_steps::SyscallSteppingTool, _>(move || {
            // SAFETY: plain libc calls; a mapping that succeeds replaces only
            // Reverie's repair page, which this guest does not use
            // afterwards, and only this thread runs.
            unsafe {
                let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                let mapped = libc::mmap(
                    reverie_ptrace::testing::sigtrap_repair_page() as *mut libc::c_void,
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                );
                let errno = std::io::Error::last_os_error().raw_os_error();
                let refused = mapped == libc::MAP_FAILED && errno == Some(libc::EPERM);
                let _ = writeln!(
                    std::io::stderr(),
                    "mseal works: {sealed}; mapping over the repair page refused with EPERM: {refused}"
                );
                assert_eq!(
                    refused, sealed,
                    "the repair page must be sealed exactly where mseal works"
                );
            }
        });
    })
    .join()
    .expect("the guest found the repair page sealed exactly where mseal works");
}
