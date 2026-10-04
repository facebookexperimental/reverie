/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

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
//!
//! The host-runtime constructor window (Begin..Ready) uses a third, reclaiming
//! heap. The guest's own allocator must still be uninitialised when `main`
//! runs under LiteInst, as it is natively, so nothing the constructor allocates
//! may reach glibc malloc. The constructor frees and reallocates heavily (a
//! 2 MiB maps buffer inside liteinst2 per executable mapping, repeated
//! `/proc/self/maps` reads), so the never-freeing patch heap would leak about
//! 2 MiB per mapping. The constructor heap uses power-of-two size classes with
//! per-class free lists instead; objects that survive Ready stay in it.

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
    static INIT_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Routes this thread's allocations to the constructor heap while held.
pub(crate) struct InitAllocationScope;

impl Drop for InitAllocationScope {
    fn drop(&mut self) {
        INIT_DEPTH.set(INIT_DEPTH.get() - 1);
    }
}

/// Enters the host-runtime constructor window; see the module documentation.
pub(crate) fn enter_init() -> InitAllocationScope {
    INIT_DEPTH.set(INIT_DEPTH.get() + 1);
    InitAllocationScope
}

fn init_active() -> bool {
    INIT_DEPTH.get() != 0
}

/// Bytes ever carved from the constructor heap (its bump cursor, a peak).
pub(crate) fn init_heap_high_water() -> usize {
    INIT_HEAP.high_water.load(Ordering::Acquire)
}

/// Whether any constructor-window allocation missed the constructor heap and
/// fell back to the system allocator. Sticky for the process lifetime.
pub(crate) fn init_heap_exhausted() -> bool {
    INIT_HEAP.exhausted.load(Ordering::Acquire)
}

/// The first request the constructor heap could not serve, why, and the
/// heap's capacity and high-water mark; meaningful once
/// [`init_heap_exhausted`] is true.
pub(crate) fn init_heap_first_miss() -> InitHeapMiss {
    INIT_HEAP.first_miss()
}

/// Clears the sticky exhausted flag and the recorded first miss.
///
/// Test-only: production never clears them. The library's unit tests share
/// one process, so a test that forces a miss must leave the flag as it found
/// it for the tests that assert it is clear.
#[cfg(test)]
pub(crate) fn clear_init_heap_exhaustion() {
    INIT_HEAP.first_miss_align.store(0, Ordering::Release);
    INIT_HEAP.first_miss_bytes.store(0, Ordering::Release);
    INIT_HEAP.exhausted.store(false, Ordering::Release);
}

/// Serializes unit tests that use the process-wide allocator state, including
/// the constructor heap's sticky exhausted flag.
#[cfg(test)]
pub(crate) fn allocator_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Whether `pointer` lies outside PATCH_HEAP, TOOL_HEAP and INIT_HEAP.
/// [`PatchAllocator`] serves every request from one of those three static heaps
/// or from the system allocator, so a non-null pointer it returned for which
/// this is true came from the system allocator.
#[cfg(test)]
pub(crate) fn served_by_system(pointer: *mut u8) -> bool {
    !PATCH_HEAP.contains(pointer) && !TOOL_HEAP.contains(pointer) && !INIT_HEAP.contains(pointer)
}

/// Fills a fresh 8 MiB constructor heap with two 4 MiB blocks, asks it for
/// 3 MiB aligned to 8 (a request of the 4 MiB class), and returns that miss.
#[cfg(test)]
pub(crate) fn capacity_miss_on_a_full_test_heap() -> InitHeapMiss {
    // SAFETY: every InitHeap field is valid as zero bytes, and zero bytes are
    // exactly `InitHeap::new()` (`init_heap_starts_zeroed`).
    let heap = unsafe { Box::<InitHeap<{ 8 << 20 }>>::new_zeroed().assume_init() };
    let block = Layout::from_size_align(4 << 20, 1).unwrap();
    let request = Layout::from_size_align(3 << 20, 8).unwrap();
    assert!(!heap.allocate(block).is_null());
    assert!(!heap.allocate(block).is_null());
    assert!(heap.allocate(request).is_null());
    heap.first_miss()
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
// storage independent of the interrupted guest allocator. Constructor-window
// allocations use serialized class storage that is frozen after the window.
unsafe impl GlobalAlloc for PatchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if installation_active() {
            PATCH_HEAP.allocate(layout)
        } else if dispatch_active() {
            // Checked before the constructor window: a dispatch nested in the
            // window must not spin on an INIT_HEAP lock it interrupted.
            TOOL_HEAP.allocate(layout)
        } else if init_active() {
            let pointer = INIT_HEAP.allocate(layout);
            if pointer.is_null() {
                // `allocate` set the sticky exhausted flag, which fails
                // initialization loudly after `prepare`. Falling back keeps an
                // infallible Rust allocation from aborting before that check
                // can report the cause.
                // SAFETY: forwarded to the process system allocator.
                unsafe { System.alloc(layout) }
            } else {
                pointer
            }
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
        } else if INIT_HEAP.contains(pointer) {
            if init_active() && !dispatch_active() {
                // SAFETY: the pointer was allocated by INIT_HEAP for this layout.
                unsafe { INIT_HEAP.deallocate(pointer, layout) };
            }
            // Outside the constructor window the heap's metadata is frozen, so
            // a later free (possibly from a signal handler) takes no lock and
            // the block is leaked.
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
        if INIT_HEAP.contains(pointer) {
            let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
                return ptr::null_mut();
            };
            let class = InitHeap::<INIT_HEAP_BYTES>::class_of(old);
            if class.is_some() && class == InitHeap::<INIT_HEAP_BYTES>::class_of(new_layout) {
                // The block already spans its whole class; no metadata changes.
                return pointer;
            }
            // SAFETY: new_layout is valid; `alloc` routes as for a fresh request.
            let replacement = unsafe { self.alloc(new_layout) };
            if !replacement.is_null() {
                // SAFETY: both allocations are valid and non-overlapping; dealloc
                // reclaims the source inside the window and leaks it outside.
                unsafe {
                    ptr::copy_nonoverlapping(pointer, replacement, old.size().min(new_size));
                    self.dealloc(pointer, old);
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

// INIT_HEAP starts as all zero bytes (checked by `init_heap_starts_zeroed`
// below), so it is placed in .bss: it adds nothing to the DSO file, and
// untouched pages cost no RSS. The predicted constructor peak is about
// 2.5 MiB: one reused 2 MiB liteinst2 maps buffer, the 192 KiB site registry
// (a 256 KiB class) and small objects. Peaks measured while reviewing
// https://github.com/rrnewton/reverie/pull/777 were 2,487,872 bytes with 24
// generated shared objects and 8,700,928 bytes with 1000, about 6.2 KiB more
// per shared object. Extending that straight line, 16 MiB would run out near
// 2,300 shared objects. That limit is extrapolated, not measured: the slope
// between neighbouring measurements ranged from 3.7 to 8.1 KiB, and
// power-of-two size classes can make it arrive sooner. A miss refuses
// initialization with OutOfMemory (`init_heap_exhausted`).
pub(crate) const INIT_HEAP_BYTES: usize = 16 * 1024 * 1024;
/// Size class k holds blocks of `16 << k` bytes: 16 B through 4 MiB.
const INIT_HEAP_CLASSES: usize = 19;
const INIT_HEAP_MIN_CLASS_SHIFT: u32 = 4;
/// The block size of the largest class, 4 MiB.
pub(crate) const INIT_HEAP_LARGEST_CLASS_BYTES: usize =
    1 << (INIT_HEAP_MIN_CLASS_SHIFT as usize + INIT_HEAP_CLASSES - 1);
/// Blocks are carved aligned to min(class size, this), so any layout whose
/// alignment is at most this fits its class without per-block headers.
pub(crate) const INIT_HEAP_MAX_ALIGN: usize = 4096;

#[repr(C, align(4096))]
struct InitHeapBytes<const N: usize>([u8; N]);

/// Reclaiming storage for the host-runtime constructor window.
///
/// Headerless: dealloc and realloc receive the layout, so a block's class is
/// recomputed rather than stored. Blocks never split or merge, so a freed
/// 2 MiB buffer is only ever reused by the next 2 MiB-class request. A free
/// block stores the address of the next free block of its class in its first
/// word, and null ends a list, so an empty heap is all zero bytes.
struct InitHeap<const N: usize> {
    bytes: UnsafeCell<InitHeapBytes<N>>,
    next: UnsafeCell<usize>,
    free_heads: UnsafeCell<[*mut u8; INIT_HEAP_CLASSES]>,
    locked: AtomicBool,
    high_water: AtomicUsize,
    exhausted: AtomicBool,
    first_miss_bytes: AtomicUsize,
    first_miss_align: AtomicUsize,
}

/// The first request a constructor heap could not serve, why it could not,
/// and the heap's capacity and high-water mark when this was read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InitHeapMiss {
    pub(crate) capacity: usize,
    pub(crate) high_water: usize,
    pub(crate) bytes: usize,
    pub(crate) align: usize,
    /// The block size of the request's class. None means no class holds the
    /// request (larger than [`INIT_HEAP_LARGEST_CLASS_BYTES`], or aligned
    /// above [`INIT_HEAP_MAX_ALIGN`]). Some means the class had no free block
    /// and the heap had no room left to carve one.
    pub(crate) class_bytes: Option<usize>,
}

// SAFETY: every cursor and free-list access is serialized by `locked`.
unsafe impl<const N: usize> Sync for InitHeap<N> {}

impl<const N: usize> InitHeap<N> {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new(InitHeapBytes([0; N])),
            next: UnsafeCell::new(0),
            free_heads: UnsafeCell::new([ptr::null_mut(); INIT_HEAP_CLASSES]),
            locked: AtomicBool::new(false),
            high_water: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
            first_miss_bytes: AtomicUsize::new(0),
            first_miss_align: AtomicUsize::new(0),
        }
    }

    fn base(&self) -> *mut u8 {
        // SAFETY: UnsafeCell::get returns the stable, non-null arena address.
        unsafe { ptr::addr_of_mut!((*self.bytes.get()).0).cast::<u8>() }
    }

    fn contains(&self, pointer: *mut u8) -> bool {
        let base = self.base() as usize;
        (base..base + N).contains(&(pointer as usize))
    }

    fn class_of(layout: Layout) -> Option<usize> {
        if layout.align() > INIT_HEAP_MAX_ALIGN {
            return None;
        }
        let bytes = layout
            .size()
            .max(layout.align())
            .max(1 << INIT_HEAP_MIN_CLASS_SHIFT)
            .checked_next_power_of_two()?;
        let class = (bytes.trailing_zeros() - INIT_HEAP_MIN_CLASS_SHIFT) as usize;
        (class < INIT_HEAP_CLASSES).then_some(class)
    }

    fn lock(&self) -> SpinGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard {
            locked: &self.locked,
        }
    }

    /// Records a request the heap cannot serve and returns null. The first
    /// miss's size and alignment are kept for the refusal message: only the
    /// miss that sets the size records the alignment. The flag is sticky.
    fn miss(&self, layout: Layout) -> *mut u8 {
        if self
            .first_miss_bytes
            .compare_exchange(0, layout.size(), Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.first_miss_align
                .store(layout.align(), Ordering::Release);
        }
        self.exhausted.store(true, Ordering::Release);
        ptr::null_mut()
    }

    /// The first missed request and why it missed. `allocate` misses either
    /// because `class_of` finds no class or because the class's list is empty
    /// and the heap has no room to carve a block, so the class of the recorded
    /// layout tells the two apart.
    fn first_miss(&self) -> InitHeapMiss {
        let bytes = self.first_miss_bytes.load(Ordering::Acquire);
        let align = self.first_miss_align.load(Ordering::Acquire);
        let class_bytes = Layout::from_size_align(bytes, align)
            .ok()
            .and_then(Self::class_of)
            .map(|class| 1usize << (class as u32 + INIT_HEAP_MIN_CLASS_SHIFT));
        InitHeapMiss {
            capacity: N,
            high_water: self.high_water.load(Ordering::Acquire),
            bytes,
            align,
            class_bytes,
        }
    }

    /// Returns null, and sets the sticky exhausted flag, when the layout has
    /// no class or the heap has no room for a fresh block of its class.
    fn allocate(&self, layout: Layout) -> *mut u8 {
        let Some(class) = Self::class_of(layout) else {
            return self.miss(layout);
        };
        let _guard = self.lock();
        // SAFETY: the heap lock serializes free-list access.
        let heads = unsafe { &mut *self.free_heads.get() };
        let head = heads[class];
        if !head.is_null() {
            // SAFETY: a free block's first word holds the next free block of
            // its class, or null.
            heads[class] = unsafe { head.cast::<*mut u8>().read() };
            return head;
        }
        let class_bytes = 1usize << (class as u32 + INIT_HEAP_MIN_CLASS_SHIFT);
        // SAFETY: the heap lock serializes bump-cursor access.
        let cursor = unsafe { *self.next.get() };
        let Some(end) = align_up(cursor, class_bytes.min(INIT_HEAP_MAX_ALIGN))
            .and_then(|offset| offset.checked_add(class_bytes))
            .filter(|end| *end <= N)
        else {
            return self.miss(layout);
        };
        // SAFETY: the heap lock serializes bump-cursor access.
        unsafe { *self.next.get() = end };
        self.high_water.store(end, Ordering::Release);
        self.base().wrapping_add(end - class_bytes)
    }

    /// # Safety
    ///
    /// `pointer` must be a live block returned by `allocate` for `layout`'s class.
    unsafe fn deallocate(&self, pointer: *mut u8, layout: Layout) {
        let Some(class) = Self::class_of(layout) else {
            return;
        };
        let _guard = self.lock();
        // SAFETY: the heap lock serializes free-list access; every block is at
        // least 16 bytes and 16-byte aligned, so its first word is writable.
        unsafe {
            let heads = &mut *self.free_heads.get();
            pointer.cast::<*mut u8>().write(heads[class]);
            heads[class] = pointer;
        }
    }
}

/// Whether an empty constructor heap is all zero bytes.
///
/// The linker places a static whose initial value is all zero in .bss, which
/// adds nothing to the DSO file. One nonzero field (a `usize::MAX` list end,
/// for example) moves the whole 16 MiB static into .data. The pattern lists
/// every field, so adding a field breaks the build until it is named here;
/// that forces the author to look, but binding it as `_` would compile
/// unchecked. `init_heap_is_placed_in_bss` is the backstop: it checks where
/// the linker actually put INIT_HEAP. The byte array is `[0; N]` for every N,
/// so a small N stands for all of them.
const fn init_heap_starts_zeroed() -> bool {
    let InitHeap {
        bytes,
        next,
        free_heads,
        locked,
        high_water,
        exhausted,
        first_miss_bytes,
        first_miss_align,
    } = InitHeap::<16>::new();
    let bytes = bytes.into_inner().0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    let free_heads = free_heads.into_inner();
    let mut class = 0;
    while class < free_heads.len() {
        if !free_heads[class].is_null() {
            return false;
        }
        class += 1;
    }
    next.into_inner() == 0
        && !locked.into_inner()
        && high_water.into_inner() == 0
        && !exhausted.into_inner()
        && first_miss_bytes.into_inner() == 0
        && first_miss_align.into_inner() == 0
}

const _: () = assert!(
    init_heap_starts_zeroed(),
    "INIT_HEAP must start as all zero bytes so that it is placed in .bss"
);

struct SpinGuard<'a> {
    locked: &'a AtomicBool,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.locked.store(false, Ordering::Release);
    }
}

static INIT_HEAP: InitHeap<INIT_HEAP_BYTES> = InitHeap::new();

#[cfg(test)]
mod tests {
    use std::sync::MutexGuard;

    use super::*;

    fn test_guard() -> MutexGuard<'static, ()> {
        allocator_test_guard()
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

    #[test]
    fn init_heap_reuses_a_freed_block_of_the_same_class() {
        static HEAP: InitHeap<{ 8 << 20 }> = InitHeap::new();
        let big = Layout::from_size_align(2 << 20, 1).unwrap();
        let small = Layout::from_size_align(64, 8).unwrap();
        let first = HEAP.allocate(big);
        assert!(!first.is_null());
        // SAFETY: first is live and was allocated for big.
        unsafe { HEAP.deallocate(first, big) };
        let small_block = HEAP.allocate(small);
        assert!(!small_block.is_null());
        let second = HEAP.allocate(big);
        // The freed 2 MiB block is not consumed by the small request.
        assert_eq!(second, first);
        // One 2 MiB block, then a 64 B block carved after it.
        assert_eq!(HEAP.high_water.load(Ordering::Acquire), (2 << 20) + 64);
        assert!(!HEAP.exhausted.load(Ordering::Acquire));
    }

    /// For every class, from 16 B (524,288 blocks) to 4 MiB (2 blocks), the
    /// free list chains all freed blocks, including the one at offset 0 and
    /// the last one before N, hands them back last in first out without
    /// carving, and ends in null. A chain that dropped or misfiled a block
    /// would leak it silently until the heap ran out.
    #[test]
    fn init_heap_free_lists_reissue_every_block_last_in_first_out() {
        const N: usize = 8 << 20;
        for class in 0..INIT_HEAP_CLASSES {
            // SAFETY: every InitHeap field (bytes, integers, bools, raw
            // pointers) is valid as zero bytes, and zero bytes are exactly
            // `InitHeap::new()` (`init_heap_starts_zeroed`), which is also how
            // the loader hands INIT_HEAP to the DSO.
            let heap = unsafe { Box::<InitHeap<N>>::new_zeroed().assume_init() };
            let class_bytes = 16usize << class;
            let layout = Layout::from_size_align(class_bytes, 1).unwrap();
            let count = N / class_bytes;
            let blocks: Vec<*mut u8> = (0..count).map(|_| heap.allocate(layout)).collect();
            // Fresh blocks are carved in address order and fill the heap.
            for (index, &block) in blocks.iter().enumerate() {
                let expected = heap.base().wrapping_add(index * class_bytes);
                assert_eq!(block, expected, "class {class}: block {index}");
            }
            assert!(heap.allocate(layout).is_null(), "class {class}: full");
            for &block in &blocks {
                // SAFETY: each block is live and was allocated for layout.
                unsafe { heap.deallocate(block, layout) };
            }
            // No block landed on another class's list: the heap is full, so
            // each of the other 18 classes misses unless its list holds a block.
            for other_class in (0..INIT_HEAP_CLASSES).filter(|&other| other != class) {
                let other = Layout::from_size_align(16usize << other_class, 1).unwrap();
                assert!(
                    heap.allocate(other).is_null(),
                    "class {class}: class {other_class}'s list is empty"
                );
            }
            for index in (0..count).rev() {
                assert_eq!(
                    heap.allocate(layout),
                    blocks[index],
                    "class {class}: block {index} is reissued last in first out"
                );
            }
            // Reissue carved nothing, and the drained list ends in null.
            assert_eq!(heap.high_water.load(Ordering::Acquire), N, "class {class}");
            assert!(heap.allocate(layout).is_null(), "class {class}: drained");
            // SAFETY: both blocks are live and were allocated for layout.
            unsafe {
                heap.deallocate(blocks[0], layout);
                heap.deallocate(blocks[count - 1], layout);
            }
            assert_eq!(heap.allocate(layout), blocks[count - 1], "class {class}");
            assert_eq!(heap.allocate(layout), blocks[0], "class {class}");
            assert!(heap.allocate(layout).is_null(), "class {class}");
        }
    }

    #[test]
    fn init_heap_classes_are_powers_of_two_from_16_bytes_to_4_mib() {
        type Heap = InitHeap<4096>;
        let class = |size, align| Heap::class_of(Layout::from_size_align(size, align).unwrap());
        assert_eq!(class(0, 1), Some(0));
        assert_eq!(class(16, 1), Some(0));
        assert_eq!(class(17, 1), Some(1));
        assert_eq!(class(8, 64), Some(2));
        assert_eq!(class(196_608, 8), Some(14));
        assert_eq!(class(2 << 20, 1), Some(17));
        assert_eq!(class(4 << 20, 1), Some(18));
        assert_eq!(class((4 << 20) + 1, 1), None);
        assert_eq!(class(16, 8192), None);
    }

    #[test]
    fn init_heap_exhaustion_is_sticky_and_returns_null() {
        static HEAP: InitHeap<{ 1 << 20 }> = InitHeap::new();
        let too_big = Layout::from_size_align(2 << 20, 1).unwrap();
        assert!(HEAP.allocate(too_big).is_null());
        assert!(HEAP.exhausted.load(Ordering::Acquire));
        let small = Layout::from_size_align(16, 1).unwrap();
        assert!(!HEAP.allocate(small).is_null());
        assert!(HEAP.exhausted.load(Ordering::Acquire));
        // A later miss (no class above 4 MiB) keeps the first one's size.
        let no_class = Layout::from_size_align(5 << 20, 1).unwrap();
        assert!(HEAP.allocate(no_class).is_null());
        assert_eq!(HEAP.first_miss_bytes.load(Ordering::Acquire), 2 << 20);
    }

    /// The first miss's size and alignment are recorded together, a later
    /// miss changes neither, and the recorded layout tells a class with no room
    /// left from a request that no class holds.
    #[test]
    fn init_heap_first_miss_records_the_request_and_why_it_missed() {
        assert_eq!(
            capacity_miss_on_a_full_test_heap(),
            InitHeapMiss {
                capacity: 8 << 20,
                high_water: 8 << 20,
                bytes: 3 << 20,
                align: 8,
                class_bytes: Some(4 << 20),
            }
        );
        // SAFETY: every InitHeap field is valid as zero bytes, and zero bytes
        // are exactly `InitHeap::new()` (`init_heap_starts_zeroed`).
        let heap = unsafe { Box::<InitHeap<{ 1 << 20 }>>::new_zeroed().assume_init() };
        // 64 bytes would fit the 64 B class, but no class is aligned above
        // 4096 bytes.
        let over_aligned = Layout::from_size_align(64, 8192).unwrap();
        assert!(heap.allocate(over_aligned).is_null());
        // A later miss, of a size no class holds, changes neither field.
        let no_class = Layout::from_size_align(5 << 20, 16).unwrap();
        assert!(heap.allocate(no_class).is_null());
        assert_eq!(
            heap.first_miss(),
            InitHeapMiss {
                capacity: 1 << 20,
                high_water: 0,
                bytes: 64,
                align: 8192,
                class_bytes: None,
            }
        );
    }

    #[test]
    fn init_heap_is_placed_in_bss() {
        // Defined by the linker around the zero-initialised sections, which
        // occupy no space in the file. This test executable compiles the same
        // static as the preload DSO.
        unsafe extern "C" {
            static __bss_start: u8;
            static _end: u8;
        }
        let bss = (&raw const __bss_start) as usize..(&raw const _end) as usize;
        let heap = (&raw const INIT_HEAP) as usize;
        let heap_end = heap + size_of::<InitHeap<INIT_HEAP_BYTES>>();
        assert!(
            bss.start <= heap && heap_end <= bss.end,
            "INIT_HEAP at {heap:#x}..{heap_end:#x} is outside .bss {:#x}..{:#x}",
            bss.start,
            bss.end
        );
    }

    #[test]
    fn init_scope_routes_to_the_reclaiming_heap_and_freezes_it_afterwards() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let layout = Layout::from_size_align(1000, 8).unwrap();
        let scope = enter_init();
        // SAFETY: layout is valid for this allocator.
        let first = unsafe { allocator.alloc(layout) };
        assert!(INIT_HEAP.contains(first));
        // SAFETY: first is live and was allocated with layout.
        unsafe { allocator.dealloc(first, layout) };
        // SAFETY: layout is valid for this allocator.
        let reused = unsafe { allocator.alloc(layout) };
        assert_eq!(reused, first);
        drop(scope);

        // Outside the window a free is a leak: the block is not reissued.
        // SAFETY: reused is live and was allocated with layout.
        unsafe { allocator.dealloc(reused, layout) };
        let scope = enter_init();
        // SAFETY: layout is valid for this allocator.
        let fresh = unsafe { allocator.alloc(layout) };
        assert!(INIT_HEAP.contains(fresh));
        assert_ne!(fresh, reused);
        // SAFETY: fresh is live and was allocated with layout.
        unsafe { allocator.dealloc(fresh, layout) };
        drop(scope);
        assert!(!init_heap_exhausted());
    }

    #[test]
    fn init_heap_realloc_is_in_place_within_a_class_and_copies_across() {
        let _test_guard = test_guard();
        let allocator = PatchAllocator;
        let small = Layout::from_size_align(40, 8).unwrap();
        let _scope = enter_init();
        // SAFETY: small is valid for this allocator.
        let pointer = unsafe { allocator.alloc(small) };
        assert!(INIT_HEAP.contains(pointer));
        for index in 0..small.size() {
            // SAFETY: index is within the live allocation.
            unsafe { pointer.add(index).write(index as u8) };
        }
        // 40 and 64 bytes share the 64 B class.
        // SAFETY: pointer is live and was allocated with small.
        let same = unsafe { allocator.realloc(pointer, small, 64) };
        assert_eq!(same, pointer);
        let mid = Layout::from_size_align(64, 8).unwrap();
        // SAFETY: same is live and was allocated with mid's class.
        let grown = unsafe { allocator.realloc(same, mid, 300) };
        assert!(INIT_HEAP.contains(grown));
        assert_ne!(grown, same);
        for index in 0..small.size() {
            // SAFETY: index is within the live grown allocation.
            assert_eq!(unsafe { grown.add(index).read() }, index as u8);
        }
        // The 64 B source was reclaimed inside the window.
        // SAFETY: mid is valid for this allocator.
        let reissued = unsafe { allocator.alloc(mid) };
        assert_eq!(reissued, same);
        let big = Layout::from_size_align(300, 8).unwrap();
        // SAFETY: both pointers are live with these layouts.
        unsafe {
            allocator.dealloc(reissued, mid);
            allocator.dealloc(grown, big);
        }
    }
}
