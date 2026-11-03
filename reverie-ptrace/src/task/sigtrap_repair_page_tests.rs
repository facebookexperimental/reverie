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

#[test]
fn unsealed_a_pending_blocked_sigtrap_is_kept_across_timer_steps() {
    unsealed();
    sigtrap_steps::a_pending_blocked_sigtrap_is_kept_across_timer_steps();
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

/// A guest that replaces the unsealed repair page with a shared mapping of a
/// file of its own (a memfd), holding a copy of Reverie's page, canary
/// included, as a guest that read the page can make: the canary matches, but
/// Reverie must still never write into the mapping, since a write there
/// would reach the file. The page and the file must come back exactly as the
/// guest left them, and SIGTRAP's action as the reset left it (the repair is
/// lost, and reported).
#[test]
fn a_shared_page_with_a_copied_canary_is_never_written() {
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
            let repair_page = reverie_ptrace::testing::sigtrap_repair_page();
            // Reverie's page, canary included, with its start, where a repair
            // writes, filled with a pattern no action matches.
            let mut copy = std::slice::from_raw_parts(repair_page as *const u8, page).to_vec();
            copy[..page / 2].fill(0x5a);
            let fd = libc::memfd_create(c"repair-page".as_ptr(), 0);
            assert!(fd >= 0, "memfd_create");
            assert_eq!(
                libc::pwrite(fd, copy.as_ptr().cast(), page, 0),
                page as isize,
                "fill the file"
            );
            let mapped = libc::mmap(
                repair_page as *mut libc::c_void,
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                0,
            );
            assert_eq!(mapped as usize, repair_page, "map over the repair page");
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
            let page_untouched = std::slice::from_raw_parts(mapped.cast::<u8>(), page) == copy;
            let mut file = vec![0u8; page];
            assert_eq!(
                libc::pread(fd, file.as_mut_ptr().cast(), page, 0),
                page as isize,
                "read the file back"
            );
            let file_untouched = file == copy;
            // The steps did reset the ignored SIGTRAP, so a repair was owed,
            // and it was lost rather than written through the guest's file.
            let mut now: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
                0
            );
            let _ = writeln!(
                std::io::stderr(),
                "guest page untouched: {page_untouched}, file untouched: {file_untouched}, action {:#x}",
                now.sa_sigaction
            );
            assert!(page_untouched, "Reverie wrote into the guest's shared page");
            assert!(file_untouched, "Reverie wrote into the guest's file");
            assert_eq!(now.sa_sigaction, libc::SIG_DFL, "no repair was owed");
        }
    });
}

/// Ignores SIGTRAP, lets `SyscallSteppingTool`'s timers step to the next
/// syscalls, where a repair of the steps' reset is owed, and returns
/// SIGTRAP's handler read back after them.
fn ignore_sigtrap_then_step() -> libc::sighandler_t {
    // SAFETY: plain libc signal calls on this thread's own state.
    unsafe {
        let mut ignore: libc::sigaction = std::mem::zeroed();
        ignore.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut ignore.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGTRAP, &ignore, std::ptr::null_mut()),
            0
        );
        for _ in 0..4 {
            libc::getpid();
            libc::getppid();
        }
        let mut now: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut now),
            0
        );
        now.sa_sigaction
    }
}

/// A SIGTRAP repair through an unsealed page that does not take is lost by
/// name: the address space is marked as having no repair page
/// (`TracedTask::lose_untaken_sigtrap_repair`), so no later repair goes
/// through it. The first repair here has the reset put back into its page
/// between its write and its call (`CHANGED_REPAIR_PAGES_FOR_TEST`), as a page
/// changed in between would, so it does not take: SIGTRAP reads `SIG_DFL`
/// after the first round, and the address space must be marked as having no
/// repair page. The second round's steps reset SIGTRAP again, and no repair
/// may be made through the page that did not carry the first: SIGTRAP reads
/// `SIG_DFL` again. Unmarked, the second round's repair took, and SIGTRAP
/// read `SIG_IGN`.
#[tokio::test(flavor = "current_thread")]
async fn an_unsealed_repair_that_does_not_take_is_lost() {
    if !crate::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    unsealed();
    super::CHANGED_REPAIR_PAGES_FOR_TEST.with(|count| count.set(1));
    let pages = super::UNSEALED_REPAIR_PAGES_FOR_TEST.with(|count| count.get());
    let untaken = super::UNTAKEN_REPAIRS_FOR_TEST.with(|count| count.get());
    let tracer = crate::spawn_fn_with_config::<sigtrap_steps::SyscallSteppingTool, _>(
        || {
            let first = ignore_sigtrap_then_step();
            let second = ignore_sigtrap_then_step();
            // The guest's panic message is not shown; this line is.
            let _ = writeln!(
                std::io::stderr(),
                "after the untaken repair: {first:#x}; after the next steps: {second:#x}"
            );
            assert_eq!(first, libc::SIG_DFL, "the changed repair took");
            assert_eq!(second, libc::SIG_DFL, "a repair went through the page");
        },
        (),
        true,
    )
    .await
    .expect("start the tracer");
    let (output, ()) = tracer.wait_with_output().await.expect("run the guest");
    assert_eq!(
        output.status,
        reverie::ExitStatus::Exited(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        super::UNSEALED_REPAIR_PAGES_FOR_TEST.with(|count| count.get()) - pages,
        1,
        "the guest's page was left unsealed"
    );
    assert_eq!(
        super::CHANGED_REPAIR_PAGES_FOR_TEST.with(|count| count.get()),
        0,
        "the first repair's page was changed"
    );
    assert_eq!(
        super::UNTAKEN_REPAIRS_FOR_TEST.with(|count| count.get()) - untaken,
        1,
        "the untaken repair marked its address space"
    );
}
