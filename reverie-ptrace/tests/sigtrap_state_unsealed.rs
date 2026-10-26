/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The SIGTRAP repair without `mseal` (Linux before 6.10): the repair page is
//! used unsealed, as `REVERIE_SIGTRAP_REPAIR_NO_MSEAL` forces on a kernel
//! that has `mseal`. Every state of `sigtrap_steps` must survive as it does
//! with the page sealed, and a page the guest replaced must never be written:
//! its canary is gone, so the repair is reported lost instead.

mod sigtrap_steps;

use std::io::Write;

/// Sets `REVERIE_SIGTRAP_REPAIR_NO_MSEAL` once, before any tracer in this
/// test binary maps a repair page. Every test here sets the same value.
fn unsealed() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: every test in this binary sets the same variable to the same
    // value through this `Once`, before it starts a tracer; nothing reads the
    // environment concurrently with a different expectation.
    ONCE.call_once(|| unsafe { std::env::set_var("REVERIE_SIGTRAP_REPAIR_NO_MSEAL", "1") });
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

/// Reverie's repair page: right after the trampoline's page on x86_64, and at
/// the next 64 KiB boundary on aarch64 (reverie-ptrace `cp::SCRATCH_BASE`).
#[cfg(target_arch = "x86_64")]
const REPAIR_PAGE: usize = 0x7100_1000;
#[cfg(target_arch = "aarch64")]
const REPAIR_PAGE: usize = 0x7101_0000;

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
                REPAIR_PAGE as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            );
            assert_eq!(mapped as usize, REPAIR_PAGE, "map over the repair page");
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
