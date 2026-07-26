//! Allocation reserve for first-trap instrumentation planning.
//!
//! A seccomp SIGSYS handler cannot let the system allocator issue brk or mmap.
//! During a bounded installation scope, allocations from liteinst2 and
//! iced-x86 therefore come from this prepublished process-lifetime buffer.
//! Objects that survive registration are intentionally never reclaimed.

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::alloc::System;

const PATCH_HEAP_BYTES: usize = 32 * 1024 * 1024;

struct PatchHeap {
    bytes: UnsafeCell<[u8; PATCH_HEAP_BYTES]>,
    next: AtomicUsize,
}

// SAFETY: reservations use a single atomic cursor and never overlap.
unsafe impl Sync for PatchHeap {}

impl PatchHeap {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; PATCH_HEAP_BYTES]),
            next: AtomicUsize::new(0),
        }
    }

    fn allocate(&self, layout: Layout) -> *mut u8 {
        let base = self.bytes.get().cast::<u8>() as usize;
        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            let Some(aligned_address) = base
                .checked_add(current)
                .and_then(|address| address.checked_add(layout.align() - 1))
                .map(|address| address & !(layout.align() - 1))
            else {
                return ptr::null_mut();
            };
            let offset = aligned_address - base;
            let Some(end) = offset.checked_add(layout.size()) else {
                return ptr::null_mut();
            };
            if end > PATCH_HEAP_BYTES {
                return ptr::null_mut();
            }
            match self
                .next
                .compare_exchange_weak(current, end, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return aligned_address as *mut u8,
                Err(observed) => current = observed,
            }
        }
    }

    fn contains(&self, pointer: *mut u8) -> bool {
        let base = self.bytes.get().cast::<u8>() as usize;
        (base..base + PATCH_HEAP_BYTES).contains(&(pointer as usize))
    }
}

static PATCH_HEAP: PatchHeap = PatchHeap::new();

#[thread_local]
static mut INSTALLATION_DEPTH: usize = 0;

pub(crate) struct PatchAllocationScope;

impl Drop for PatchAllocationScope {
    fn drop(&mut self) {
        // SAFETY: scopes are entered and dropped on the same thread.
        unsafe {
            INSTALLATION_DEPTH -= 1;
        }
    }
}

pub(crate) fn enter() -> PatchAllocationScope {
    // SAFETY: the counter belongs exclusively to this thread.
    unsafe {
        INSTALLATION_DEPTH += 1;
    }
    PatchAllocationScope
}

fn installation_active() -> bool {
    // SAFETY: reading this thread's scalar TLS value has no side effects.
    unsafe { INSTALLATION_DEPTH != 0 }
}

pub(crate) struct PatchAllocator;

// SAFETY: normal allocations delegate to System. Installation allocations
// receive unique bump-arena ranges that remain valid for the process lifetime.
unsafe impl GlobalAlloc for PatchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if installation_active() {
            PATCH_HEAP.allocate(layout)
        } else {
            // SAFETY: forwarded to the process system allocator.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { self.alloc(layout) };
        if !pointer.is_null() {
            // SAFETY: alloc returned layout.size writable bytes.
            unsafe { pointer.write_bytes(0, layout.size()) };
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if !PATCH_HEAP.contains(pointer) {
            // SAFETY: non-patch pointers came from System with this layout.
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        if !PATCH_HEAP.contains(pointer) {
            // SAFETY: non-patch pointers came from System with this layout.
            return unsafe { System.realloc(pointer, old, new_size) };
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        let replacement = PATCH_HEAP.allocate(new_layout);
        if !replacement.is_null() {
            // SAFETY: both allocations are valid and non-overlapping.
            unsafe {
                ptr::copy_nonoverlapping(pointer, replacement, old.size().min(new_size));
            }
        }
        replacement
    }
}
