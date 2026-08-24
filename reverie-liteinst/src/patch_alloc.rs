//! Allocation reserves for instrumentation planning and tool dispatch.
//!
//! A seccomp SIGSYS handler cannot let the system allocator issue brk or mmap.
//! During a bounded installation scope, allocations from liteinst2 and
//! iced-x86 therefore come from this prepublished process-lifetime buffer.
//! Objects that survive registration are intentionally never reclaimed.
//!
//! Tool callbacks use a separate reusable arena because a callback can interrupt
//! the guest allocator itself. Its temporary and persistent allocations are
//! therefore isolated from libc until they are released or the process exits.

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::mem::align_of;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::alloc::System;
use std::cell::Cell;

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
const TOOL_HEAP_BYTES: usize = 32 * 1024 * 1024;
const FREE_LIST_END: usize = usize::MAX;

#[repr(align(64))]
struct ToolHeapBytes([u8; TOOL_HEAP_BYTES]);

#[repr(C)]
struct ToolHeapBlock {
    span: usize,
    next: usize,
}

/// Reusable storage for allocations made while the guest allocator is interrupted.
struct ToolHeap {
    bytes: UnsafeCell<ToolHeapBytes>,
    next: UnsafeCell<usize>,
    free_head: UnsafeCell<usize>,
    locked: AtomicBool,
}

// SAFETY: every metadata access is serialized by `locked`.
unsafe impl Sync for ToolHeap {}

impl ToolHeap {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new(ToolHeapBytes([0; TOOL_HEAP_BYTES])),
            next: UnsafeCell::new(0),
            free_head: UnsafeCell::new(FREE_LIST_END),
            locked: AtomicBool::new(false),
        }
    }

    fn base(&self) -> *mut u8 {
        // SAFETY: UnsafeCell::get returns the stable, non-null arena address.
        unsafe { ptr::addr_of_mut!((*self.bytes.get()).0).cast::<u8>() }
    }

    fn lock(&self) -> ToolHeapLock<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        ToolHeapLock { heap: self }
    }

    fn layout_end(&self, block_offset: usize, layout: Layout) -> Option<(*mut u8, usize)> {
        let base = self.base() as usize;
        let block_address = base.checked_add(block_offset)?;
        let payload_start = block_address
            .checked_add(size_of::<ToolHeapBlock>())?
            .checked_add(size_of::<usize>())?;
        let payload_address = align_up(payload_start, layout.align().max(align_of::<usize>()))?;
        let payload_end = payload_address.checked_add(layout.size().max(1))?;
        Some((payload_address as *mut u8, payload_end - base))
    }

    fn block(&self, offset: usize) -> *mut ToolHeapBlock {
        self.base().wrapping_add(offset).cast()
    }

    fn allocate(&self, layout: Layout) -> *mut u8 {
        let _guard = self.lock();
        let mut previous = FREE_LIST_END;
        // SAFETY: the heap lock serializes free-list access.
        let mut current = unsafe { *self.free_head.get() };

        while current != FREE_LIST_END {
            let block = self.block(current);
            // SAFETY: free-list offsets always point at initialized headers.
            let (span, next) = unsafe { ((*block).span, (*block).next) };
            let fits = self
                .layout_end(current, layout)
                .filter(|(_, end)| *end <= current.saturating_add(span));
            if let Some((pointer, _)) = fits {
                // SAFETY: the heap lock serializes free-list mutation.
                unsafe {
                    if previous == FREE_LIST_END {
                        *self.free_head.get() = next;
                    } else {
                        (*self.block(previous)).next = next;
                    }
                    pointer
                        .sub(size_of::<usize>())
                        .cast::<usize>()
                        .write(current);
                }
                return pointer;
            }
            previous = current;
            current = next;
        }

        // SAFETY: the heap lock serializes bump-cursor access.
        let cursor = unsafe { *self.next.get() };
        let Some(block_offset) = align_up(cursor, align_of::<ToolHeapBlock>()) else {
            return ptr::null_mut();
        };
        let Some((pointer, end)) = self.layout_end(block_offset, layout) else {
            return ptr::null_mut();
        };
        if end > TOOL_HEAP_BYTES {
            return ptr::null_mut();
        }

        // SAFETY: this fresh bump range is exclusive and within the heap.
        unsafe {
            self.block(block_offset).write(ToolHeapBlock {
                span: end - block_offset,
                next: FREE_LIST_END,
            });
            pointer
                .sub(size_of::<usize>())
                .cast::<usize>()
                .write(block_offset);
            *self.next.get() = end;
        }
        pointer
    }

    unsafe fn deallocate(&self, pointer: *mut u8) {
        // SAFETY: each tool-heap allocation records its block offset here.
        let block_offset = unsafe { pointer.sub(size_of::<usize>()).cast::<usize>().read() };
        let _guard = self.lock();
        // SAFETY: the block header remains reserved until this allocation is freed.
        unsafe {
            (*self.block(block_offset)).next = *self.free_head.get();
            *self.free_head.get() = block_offset;
        }
    }

    fn contains(&self, pointer: *mut u8) -> bool {
        let base = self.base() as usize;
        (base..base + TOOL_HEAP_BYTES).contains(&(pointer as usize))
    }
}

struct ToolHeapLock<'a> {
    heap: &'a ToolHeap,
}

thread_local! {
    // Const, no-drop TLS is important here: the global allocator consults
    // these counters before it can choose a safe backing heap.
    static INSTALLATION_DEPTH: Cell<usize> = const { Cell::new(0) };
    static DISPATCH_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct PatchAllocationScope;

impl Drop for PatchAllocationScope {
    fn drop(&mut self) {
        INSTALLATION_DEPTH.set(INSTALLATION_DEPTH.get() - 1);
    }
}

pub(crate) fn enter() -> PatchAllocationScope {
    INSTALLATION_DEPTH.set(INSTALLATION_DEPTH.get() + 1);
    PatchAllocationScope
}

fn installation_active() -> bool {
    INSTALLATION_DEPTH.get() != 0
}

// TODO-HUMAN-REVIEW(PR-148): Review the dispatch allocator scope API.
pub(crate) struct DispatchAllocationScope;

impl Drop for DispatchAllocationScope {
    fn drop(&mut self) {
        DISPATCH_DEPTH.set(DISPATCH_DEPTH.get() - 1);
    }
}

// TODO-HUMAN-REVIEW(PR-148): Review signal-context tool allocation isolation.
pub(crate) fn enter_dispatch() -> DispatchAllocationScope {
    DISPATCH_DEPTH.set(DISPATCH_DEPTH.get() + 1);
    DispatchAllocationScope
}

fn dispatch_active() -> bool {
    DISPATCH_DEPTH.get() != 0
}

pub(crate) struct PatchAllocator;

// SAFETY: normal allocations delegate to System. Installation allocations use
// process-lifetime storage, and dispatch allocations use serialized reusable
// storage independent of the interrupted guest allocator.
unsafe impl GlobalAlloc for PatchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if installation_active() {
            PATCH_HEAP.allocate(layout)
        } else if dispatch_active() {
            TOOL_HEAP.allocate(layout)
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
        if TOOL_HEAP.contains(pointer) {
            // SAFETY: the pointer was allocated by TOOL_HEAP.
            unsafe { TOOL_HEAP.deallocate(pointer) };
        } else if PATCH_HEAP.contains(pointer) {
            // Installation allocations remain valid for the process lifetime.
        } else if dispatch_active() {
            // A tool may drop state allocated before the filter was installed.
            // Leaking it is preferable to reentering an interrupted allocator.
        } else {
            // SAFETY: non-patch pointers came from System with this layout.
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        if TOOL_HEAP.contains(pointer) {
            let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
                return ptr::null_mut();
            };
            let replacement = TOOL_HEAP.allocate(new_layout);
            if !replacement.is_null() {
                // SAFETY: both allocations are valid and non-overlapping.
                unsafe {
                    ptr::copy_nonoverlapping(pointer, replacement, old.size().min(new_size));
                    TOOL_HEAP.deallocate(pointer);
                }
            }
            return replacement;
        }
        if !PATCH_HEAP.contains(pointer) && !dispatch_active() {
            // SAFETY: non-patch pointers came from System with this layout.
            return unsafe { System.realloc(pointer, old, new_size) };
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        let replacement = if PATCH_HEAP.contains(pointer) {
            PATCH_HEAP.allocate(new_layout)
        } else {
            TOOL_HEAP.allocate(new_layout)
        };
        if !replacement.is_null() {
            // SAFETY: the replacement is valid and does not overlap the source.
            unsafe {
                ptr::copy_nonoverlapping(pointer, replacement, old.size().min(new_size));
            }
        }
        replacement
    }
}

impl Drop for ToolHeapLock<'_> {
    fn drop(&mut self) {
        self.heap.locked.store(false, Ordering::Release);
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|address| address & !(alignment - 1))
}

static TOOL_HEAP: ToolHeap = ToolHeap::new();

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::MutexGuard;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn dispatch_heap_reuses_freed_blocks() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let layout = Layout::from_size_align(256, 64).unwrap();
        let _scope = enter_dispatch();

        // SAFETY: allocations and deallocations use the same allocator and layout.
        let first = unsafe { allocator.alloc(layout) };
        assert!(!first.is_null());
        // SAFETY: first is live and was allocated with layout.
        unsafe { allocator.dealloc(first, layout) };

        // SAFETY: layout is valid for this allocator.
        let second = unsafe { allocator.alloc(layout) };
        assert_eq!(second, first);
        // SAFETY: second is live and was allocated with layout.
        unsafe { allocator.dealloc(second, layout) };
    }

    #[test]
    fn dispatch_heap_honors_large_alignment() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let _scope = enter_dispatch();
        for alignment in [8, 64, 4096] {
            let layout = Layout::from_size_align(257, alignment).unwrap();
            // SAFETY: layout is valid for this allocator.
            let pointer = unsafe { allocator.alloc(layout) };
            assert!(!pointer.is_null());
            assert_eq!((pointer as usize) % alignment, 0);
            // SAFETY: pointer is live and was allocated with layout.
            unsafe { allocator.dealloc(pointer, layout) };
        }
    }

    #[test]
    fn dispatch_heap_realloc_preserves_bytes_when_growing_and_shrinking() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let small = Layout::from_size_align(64, 32).unwrap();
        let _scope = enter_dispatch();
        // SAFETY: small is valid for this allocator.
        let pointer = unsafe { allocator.alloc(small) };
        assert!(!pointer.is_null());
        for index in 0..small.size() {
            // SAFETY: index is within the live small allocation.
            unsafe { pointer.add(index).write(index as u8) };
        }

        // SAFETY: pointer is live and was allocated with small.
        let grown = unsafe { allocator.realloc(pointer, small, 512) };
        assert!(!grown.is_null());
        for index in 0..small.size() {
            // SAFETY: index is within the live grown allocation.
            assert_eq!(unsafe { grown.add(index).read() }, index as u8);
        }
        let grown_layout = Layout::from_size_align(512, small.align()).unwrap();
        // SAFETY: grown is live and was allocated with grown_layout.
        let shrunk = unsafe { allocator.realloc(grown, grown_layout, 16) };
        assert!(!shrunk.is_null());
        for index in 0..16 {
            // SAFETY: index is within the live shrunk allocation.
            assert_eq!(unsafe { shrunk.add(index).read() }, index as u8);
        }
        let shrunk_layout = Layout::from_size_align(16, small.align()).unwrap();
        // SAFETY: shrunk is live and was allocated with shrunk_layout.
        unsafe { allocator.dealloc(shrunk, shrunk_layout) };
    }

    #[test]
    fn failed_dispatch_realloc_keeps_the_source_live() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let layout = Layout::from_size_align(64, 16).unwrap();
        let _scope = enter_dispatch();
        // SAFETY: layout is valid for this allocator.
        let pointer = unsafe { allocator.alloc(layout) };
        assert!(!pointer.is_null());
        // SAFETY: pointer covers layout.size writable bytes.
        unsafe { pointer.write_bytes(0xa5, layout.size()) };

        // SAFETY: pointer is live; the requested size exceeds the bounded arena.
        let failed = unsafe { allocator.realloc(pointer, layout, TOOL_HEAP_BYTES + 1) };
        assert!(failed.is_null());
        for index in 0..layout.size() {
            // SAFETY: failed realloc leaves the original allocation live.
            assert_eq!(unsafe { pointer.add(index).read() }, 0xa5);
        }
        // SAFETY: pointer remains live with its original layout.
        unsafe { allocator.dealloc(pointer, layout) };
    }

    #[test]
    fn system_realloc_migrates_into_the_dispatch_heap() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let layout = Layout::from_size_align(64, 16).unwrap();
        // SAFETY: layout is valid for System.
        let original = unsafe { System.alloc(layout) };
        assert!(!original.is_null());
        // SAFETY: original covers layout.size writable bytes.
        unsafe { original.write_bytes(0x3c, layout.size()) };

        let scope = enter_dispatch();
        // SAFETY: original is live and was allocated with layout.
        let migrated = unsafe { allocator.realloc(original, layout, 128) };
        assert!(!migrated.is_null());
        assert!(TOOL_HEAP.contains(migrated));
        drop(scope);
        for index in 0..layout.size() {
            // SAFETY: migrated contains at least the copied original bytes.
            assert_eq!(unsafe { migrated.add(index).read() }, 0x3c);
        }
        let migrated_layout = Layout::from_size_align(128, layout.align()).unwrap();
        // SAFETY: migrated remains owned by TOOL_HEAP after dispatch ends.
        unsafe { allocator.dealloc(migrated, migrated_layout) };
    }

    #[test]
    fn dispatch_heap_supports_concurrent_allocate_free() {
        let _test_guard = test_guard();
        let threads: [_; 4] = std::array::from_fn(|thread_index| {
            std::thread::spawn(move || {
                let allocator = PatchAllocator;
                let _scope = enter_dispatch();
                for iteration in 0..1000 {
                    let size = 1 + (thread_index * 17 + iteration) % 1024;
                    let layout = Layout::from_size_align(size, 64).unwrap();
                    // SAFETY: layout is valid for this allocator.
                    let pointer = unsafe { allocator.alloc(layout) };
                    assert!(!pointer.is_null());
                    // SAFETY: pointer covers layout.size writable bytes.
                    unsafe { pointer.write_bytes(thread_index as u8, layout.size()) };
                    // SAFETY: pointer is live and was allocated with layout.
                    unsafe { allocator.dealloc(pointer, layout) };
                }
            })
        });
        for thread in threads {
            thread.join().unwrap();
        }
    }
}
