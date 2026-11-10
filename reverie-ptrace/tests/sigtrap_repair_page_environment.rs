/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The environment cannot unseal Reverie's SIGTRAP repair page. The variable
//! that once did, `REVERIE_SIGTRAP_REPAIR_NO_MSEAL`, is set here before any
//! tracer in this binary starts, and the page must still be sealed wherever
//! the kernel has `mseal` (Linux 6.10): only the crate's own unit tests can
//! leave it unsealed there, through a switch that exists only under
//! `cfg(test)`. This file holds one test, so that nothing else in the process
//! reads the environment while it is set.

use std::io::Write;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;

/// `mseal(2)`'s number on x86-64 and aarch64, which `libc` does not name.
const SYS_MSEAL: libc::c_long = 462;

/// Passes every syscall on, under a serialized-execution contract, so that
/// pre-init sets up a repair page.
#[derive(Debug, Default, Clone)]
struct SerializedTool;

#[reverie::tool]
impl Tool for SerializedTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all_syscalls()
    }

    fn enforces_serialized_execution(_config: &()) -> bool {
        true
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(syscall).await
    }
}

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

#[test]
fn the_environment_does_not_unseal_the_repair_page() {
    // SAFETY: the only test in this binary sets the variable before it
    // starts a tracer or any other thread.
    unsafe { std::env::set_var("REVERIE_SIGTRAP_REPAIR_NO_MSEAL", "1") };
    let sealed = mseal_works();
    reverie_ptrace::testing::check_fn::<SerializedTool, _>(move || {
        // SAFETY: plain libc calls; a mapping that succeeds replaces only
        // Reverie's repair page, which this guest does not use afterwards,
        // and only this thread runs.
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
}
