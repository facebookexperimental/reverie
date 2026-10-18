/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The shared runtime's patcher registry, in its own test binary because the
//! registration is process-wide: before a patcher is registered every query
//! declines (NoPatcher); after, the registered patcher sees mapping changes,
//! a different patcher cannot replace it, and the shared Tool-mode callback
//! reports to it.

#![cfg(feature = "coordinator-rpc")]

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie_inguest::guest::event::SyscallDispatch;
use reverie_inguest::guest::event::SyscallEvent;
use reverie_inguest::guest::patcher::NoPatcher;
use reverie_inguest::guest::patcher::Patcher;
use reverie_inguest::guest::runtime_seam::PatcherRef;
use reverie_inguest::guest::runtime_seam::observe_registered_mapping;
use reverie_inguest::guest::runtime_seam::process_tool_syscall_callback;
use reverie_inguest::guest::runtime_seam::register_patcher;
use reverie_inguest::guest::runtime_seam::registered_patcher;
use reverie_inguest::stats::LiteinstDispatchPath;

struct ObservingPatcher {
    observed: AtomicU64,
}

// SAFETY: declines every site; only counts mapping observations.
unsafe impl Patcher for ObservingPatcher {
    fn observe_mapping(&self, _event: &SyscallEvent) {
        self.observed.fetch_add(1, Ordering::Relaxed);
    }

    fn fallback_path(&self, _instruction_pointer: u64) -> LiteinstDispatchPath {
        LiteinstDispatchPath::UnpatchableOrOtherFallback
    }
}

static OBSERVING: ObservingPatcher = ObservingPatcher {
    observed: AtomicU64::new(0),
};
static OBSERVING_REF: PatcherRef = PatcherRef(&OBSERVING);
static OTHER: NoPatcher = NoPatcher;
static OTHER_REF: PatcherRef = PatcherRef(&OTHER);

fn munmap_event() -> SyscallEvent {
    event(libc::SYS_munmap, [0x1000, 0x1000, 0, 0, 0, 0])
}

fn event(number: i64, args: [u64; 6]) -> SyscallEvent {
    SyscallEvent {
        number,
        args,
        instruction_pointer: 0x2000,
        result: 0,
        context: 0,
        dispatch: SyscallDispatch::Fallback,
        guest_pkru: None,
    }
}

#[test]
fn registration_routes_queries_from_no_patcher_to_the_registered_one() {
    // Before registration: NoPatcher, which classifies as patching disabled
    // and ignores mapping changes.
    assert_eq!(
        registered_patcher().fallback_path(0x2000),
        LiteinstDispatchPath::PatchingDisabledFallback
    );
    observe_registered_mapping(&munmap_event());
    assert_eq!(OBSERVING.observed.load(Ordering::Relaxed), 0);

    register_patcher(&OBSERVING_REF).unwrap();
    assert_eq!(
        registered_patcher().fallback_path(0x2000),
        LiteinstDispatchPath::UnpatchableOrOtherFallback
    );
    observe_registered_mapping(&munmap_event());
    assert_eq!(OBSERVING.observed.load(Ordering::Relaxed), 1);

    // Set once: the same patcher again is accepted, a different one refused,
    // and the first stays registered.
    register_patcher(&OBSERVING_REF).unwrap();
    assert_eq!(
        register_patcher(&OTHER_REF).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        registered_patcher().fallback_path(0x2000),
        LiteinstDispatchPath::UnpatchableOrOtherFallback
    );

    // The shared Tool-mode callback: with no Tool installed in this process
    // the dispatch answers ENOSYS, and the registered patcher then sees the
    // completed syscall.
    let mut getpid = event(libc::SYS_getpid, [0; 6]);
    // SAFETY: a unique live event for this synchronous call; getpid names no
    // descriptor, and no Tool is installed to act on it.
    unsafe { process_tool_syscall_callback((&raw mut getpid).cast()) };
    assert_eq!(getpid.result, -i64::from(libc::ENOSYS));
    assert_eq!(OBSERVING.observed.load(Ordering::Relaxed), 2);

    // A call the runtime refuses before the Tool (an alternate signal stack)
    // never reaches the Tool or the patcher.
    let mut sigaltstack = event(libc::SYS_sigaltstack, [0x1000, 0, 0, 0, 0, 0]);
    // SAFETY: as above; the refused call runs nothing.
    unsafe { process_tool_syscall_callback((&raw mut sigaltstack).cast()) };
    assert_eq!(sigaltstack.result, -i64::from(libc::EPERM));
    assert_eq!(OBSERVING.observed.load(Ordering::Relaxed), 2);
}
