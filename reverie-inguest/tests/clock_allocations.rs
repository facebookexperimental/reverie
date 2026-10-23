/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A thread binds its in-guest RCB clock on first use, which for a fork child
//! is the syscall hook's exit path, outside any Tool callback. Whether binding
//! succeeds depends on the host's PMU, so binding must allocate nothing through
//! the system allocator (the guest's malloc inside a guest): a counter that
//! binds and one that cannot must leave the guest's heap the same.
//!
//! This binary's global allocator is the runtime's [`GuestAllocator`], wrapped
//! to count, on a watched thread, every allocation that did not come from the
//! Tool heap. A fresh thread's clock has no owner, so its first
//! `enter_rcb_handler` binds through the same owner-mismatch path a fork child
//! takes.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::cell::Cell;

use reverie_inguest::guest::alloc::GuestAllocator;
use reverie_inguest::guest::alloc::tool_heap_contains;
use reverie_inguest::guest::clock;

thread_local! {
    static WATCHED: Cell<bool> = const { Cell::new(false) };
    static SYSTEM_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingGuestAllocator;

impl CountingGuestAllocator {
    fn note(pointer: *mut u8) {
        if WATCHED.get() && !pointer.is_null() && !tool_heap_contains(pointer) {
            SYSTEM_ALLOCATIONS.set(SYSTEM_ALLOCATIONS.get() + 1);
        }
    }
}

// SAFETY: every operation is forwarded to GuestAllocator unchanged.
unsafe impl GlobalAlloc for CountingGuestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { GuestAllocator.alloc(layout) };
        Self::note(pointer);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { GuestAllocator.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = unsafe { GuestAllocator.realloc(pointer, layout, new_size) };
        Self::note(replacement);
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: CountingGuestAllocator = CountingGuestAllocator;

/// Binds this thread's clock through its first callback entry and returns how
/// many system allocations binding made, and whether the clock is available.
fn bind_on_first_use() -> (usize, bool) {
    SYSTEM_ALLOCATIONS.set(0);
    WATCHED.set(true);
    let entered = clock::enter_rcb_handler();
    let left = clock::leave_rcb_handler();
    WATCHED.set(false);
    entered.unwrap();
    left.unwrap();
    let available = match clock::read_guest_rcb_clock() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => false,
        Err(error) => panic!("reading the clock failed: {error}"),
    };
    (SYSTEM_ALLOCATIONS.get(), available)
}

/// Makes perf_event_open fail with EACCES on the calling thread only, so the
/// counter cannot bind there whatever the host's PMU offers.
fn deny_perf_event_open_on_this_thread() {
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0, // seccomp_data.nr
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_perf_event_open as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: the program outlives the call; without SECCOMP_FILTER_FLAG_TSYNC
    // the filter applies to this thread alone.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
}

#[test]
fn binding_an_available_counter_allocates_only_from_the_tool_heap() {
    let (system_allocations, available) = std::thread::spawn(bind_on_first_use).join().unwrap();
    if !available {
        eprintln!("this host offers no in-guest branch counter: only the unavailable path ran");
    }
    assert_eq!(system_allocations, 0, "available={available}");
}

#[test]
fn binding_an_unavailable_counter_allocates_only_from_the_tool_heap() {
    let (system_allocations, available) = std::thread::spawn(|| {
        deny_perf_event_open_on_this_thread();
        bind_on_first_use()
    })
    .join()
    .unwrap();
    assert!(
        !available,
        "perf_event_open was denied, yet the clock bound"
    );
    assert_eq!(system_allocations, 0);
}
