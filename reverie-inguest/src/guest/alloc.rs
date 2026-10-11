/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The allocator for code that runs a Tool inside the guest.
//!
//! Tool callbacks use a reusable arena separate from libc, because a callback
//! can interrupt the guest allocator itself. Its temporary and persistent
//! allocations are therefore isolated from libc until they are released or
//! the process exits.
//!
//! Legacy storage is zero-initialized and page-aligned, so the loader places it in
//! anonymous memory (`.bss`) rather than in a mapping of the file that holds
//! it. A backend that reads an object's file mappings for code addresses
//! (LiteInst's entry census) therefore never finds the runtime's own state
//! there, wherever the runtime is linked. Explicit fixed consumers instead use
//! already-published ToolRegion storage, with no allocator-triggered setup.

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::align_of;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use std::alloc::System;
use std::cell::Cell;

pub(crate) const TOOL_HEAP_BYTES: usize = 32 * 1024 * 1024;
/// Ends a free list. No block starts at offset 0 (the bump cursor starts past
/// it), so this can be 0 and the whole heap's initial value is zero.
const FREE_LIST_END: usize = 0;

#[repr(align(4096))]
struct ToolHeapBytes([u8; TOOL_HEAP_BYTES]);

#[repr(C)]
struct ToolHeapBlock {
    span: usize,
    next: usize,
}

// A remainder must hold a header, the payload's back-pointer and at least
// one byte, with its end aligned for the next block header.
const MIN_FREE_SPAN: usize = (size_of::<ToolHeapBlock>() + size_of::<usize>() + 1)
    .next_multiple_of(align_of::<ToolHeapBlock>());

/// Scalar state shared by the Legacy and Fixed reusable algorithms.
#[repr(C)]
pub(crate) struct ToolHeapMetadata {
    pub(crate) next: UnsafeCell<usize>,
    pub(crate) free_head: UnsafeCell<usize>,
    pub(crate) locked: AtomicBool,
}

// SAFETY: cursor/free-list accesses hold this metadata's own lock.
unsafe impl Sync for ToolHeapMetadata {}

impl ToolHeapMetadata {
    const fn new() -> Self {
        Self {
            next: UnsafeCell::new(0),
            free_head: UnsafeCell::new(FREE_LIST_END),
            locked: AtomicBool::new(false),
        }
    }

    /// Initialize only authenticated fresh, unpublished anonymous storage.
    pub(crate) unsafe fn initialize_at(address: *mut Self) {
        // SAFETY: the fresh owner exclusively owns writable aligned storage.
        // Individual scalar stores avoid constructing any arena/bitmap value.
        unsafe {
            ptr::addr_of_mut!((*address).next).write(UnsafeCell::new(0));
            ptr::addr_of_mut!((*address).free_head).write(UnsafeCell::new(FREE_LIST_END));
            ptr::addr_of_mut!((*address).locked).write(AtomicBool::new(false));
        }
    }
}

/// Legacy BSS ownership stays separate from the allocation algorithm.
struct ToolHeap {
    bytes: UnsafeCell<ToolHeapBytes>,
    metadata: ToolHeapMetadata,
}

// SAFETY: the shared span algorithm serializes this heap's scalar state.
unsafe impl Sync for ToolHeap {}

impl ToolHeap {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new(ToolHeapBytes([0; TOOL_HEAP_BYTES])),
            metadata: ToolHeapMetadata::new(),
        }
    }

    fn base(&self) -> *mut u8 {
        // SAFETY: UnsafeCell::get returns the stable, non-null arena address.
        unsafe { ptr::addr_of_mut!((*self.bytes.get()).0).cast::<u8>() }
    }

    fn span(&self) -> ToolHeapSpan<'_> {
        ToolHeapSpan {
            base: self.base(),
            bytes: TOOL_HEAP_BYTES,
            metadata: &self.metadata,
        }
    }

    fn allocate(&self, layout: Layout) -> *mut u8 {
        self.span().allocate(layout)
    }

    unsafe fn deallocate(&self, pointer: *mut u8) {
        // SAFETY: the caller supplies a live allocation from this heap.
        unsafe { self.span().deallocate(pointer) };
    }

    fn contains(&self, pointer: *mut u8) -> bool {
        self.span().contains(pointer)
    }
}

/// Borrowed storage and its scalar state; never owns/copies the byte arena.
pub(crate) struct ToolHeapSpan<'a> {
    pub(crate) base: *mut u8,
    pub(crate) bytes: usize,
    pub(crate) metadata: &'a ToolHeapMetadata,
}

impl ToolHeapSpan<'_> {
    fn lock(&self) -> ToolHeapLock<'_> {
        while self
            .metadata
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        ToolHeapLock {
            metadata: self.metadata,
        }
    }

    fn layout_end(&self, block_offset: usize, layout: Layout) -> Option<(*mut u8, usize)> {
        let base = self.base as usize;
        let block_address = base.checked_add(block_offset)?;
        let payload_start = block_address
            .checked_add(size_of::<ToolHeapBlock>())?
            .checked_add(size_of::<usize>())?;
        let payload_address = align_up(payload_start, layout.align().max(align_of::<usize>()))?;
        let payload_end = payload_address.checked_add(layout.size().max(1))?;
        let block_end = align_up(payload_end - base, align_of::<ToolHeapBlock>())?;
        Some((payload_address as *mut u8, block_end))
    }

    fn block(&self, offset: usize) -> *mut ToolHeapBlock {
        self.base.wrapping_add(offset).cast()
    }

    fn allocate(&self, layout: Layout) -> *mut u8 {
        let _guard = self.lock();
        let mut previous = FREE_LIST_END;
        // SAFETY: the heap lock serializes free-list access.
        let mut current = unsafe { *self.metadata.free_head.get() };

        while current != FREE_LIST_END {
            let block = self.block(current);
            // SAFETY: free-list offsets always point at initialized headers.
            let (span, next) = unsafe { ((*block).span, (*block).next) };
            let fits = current.checked_add(span).and_then(|block_end| {
                self.layout_end(current, layout)
                    .filter(|(_, end)| *end <= block_end)
                    .map(|(pointer, end)| (pointer, end, block_end))
            });
            if let Some((pointer, end, block_end)) = fits {
                // SAFETY: the heap lock serializes free-list mutation. The
                // aligned remainder starts beyond the live payload and has
                // enough room for its own header and minimum allocation.
                unsafe {
                    let replacement = if block_end - end >= MIN_FREE_SPAN {
                        self.block(end).write(ToolHeapBlock {
                            span: block_end - end,
                            next,
                        });
                        (*block).span = end - current;
                        end
                    } else {
                        // Retain an unusably short tail in the live span; it
                        // becomes reusable when this allocation is freed.
                        next
                    };
                    if previous == FREE_LIST_END {
                        *self.metadata.free_head.get() = replacement;
                    } else {
                        (*self.block(previous)).next = replacement;
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
        let cursor = unsafe { *self.metadata.next.get() };
        // Offset 0 stays unused: it is FREE_LIST_END.
        let Some(block_offset) = align_up(cursor.max(1), align_of::<ToolHeapBlock>()) else {
            return ptr::null_mut();
        };
        let Some((pointer, end)) = self.layout_end(block_offset, layout) else {
            return ptr::null_mut();
        };
        if end > self.bytes {
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
            *self.metadata.next.get() = end;
        }
        pointer
    }

    unsafe fn deallocate(&self, pointer: *mut u8) {
        // SAFETY: each tool-heap allocation records its block offset here.
        let block_offset = unsafe { pointer.sub(size_of::<usize>()).cast::<usize>().read() };
        let _guard = self.lock();
        // SAFETY: the block header remains reserved until this allocation is
        // freed. All list accesses are locked. Address ordering lets us merge
        // only the immediate free neighbors, never across a live allocation.
        unsafe {
            let mut previous = FREE_LIST_END;
            let mut next = *self.metadata.free_head.get();
            while next != FREE_LIST_END && next < block_offset {
                previous = next;
                next = (*self.block(next)).next;
            }
            let block = self.block(block_offset);
            (*block).next = next;
            if previous == FREE_LIST_END {
                *self.metadata.free_head.get() = block_offset;
            } else {
                (*self.block(previous)).next = block_offset;
            }

            let mut merged_offset = block_offset;
            if previous != FREE_LIST_END {
                let predecessor = self.block(previous);
                if previous.checked_add((*predecessor).span) == Some(block_offset)
                    && let Some(span) = (*predecessor).span.checked_add((*block).span)
                {
                    (*predecessor).span = span;
                    (*predecessor).next = next;
                    merged_offset = previous;
                }
            }
            let merged = self.block(merged_offset);
            if next != FREE_LIST_END && merged_offset.checked_add((*merged).span) == Some(next) {
                let successor = self.block(next);
                if let Some(span) = (*merged).span.checked_add((*successor).span) {
                    (*merged).span = span;
                    (*merged).next = (*successor).next;
                }
            }
        }
    }

    fn contains(&self, pointer: *mut u8) -> bool {
        let base = self.base as usize;
        (base..base + self.bytes).contains(&(pointer as usize))
    }
}

struct ToolHeapLock<'a> {
    metadata: &'a ToolHeapMetadata,
}

thread_local! {
    // Const, no-drop TLS is important here: the global allocator consults
    // this counter before it can choose a safe backing heap.
    static DISPATCH_DEPTH: Cell<usize> = const { Cell::new(0) };
}

// TODO-HUMAN-REVIEW(PR-148): Review the dispatch allocator scope API.
/// While alive, this thread's allocations come from the Tool heap; see
/// [`GuestAllocator`]. Only [`enter_dispatch`] creates one, and it cannot move
/// to another thread, so each drop undoes exactly the entry that made it.
pub struct DispatchAllocationScope {
    _same_thread: PhantomData<*mut ()>,
}

impl Drop for DispatchAllocationScope {
    fn drop(&mut self) {
        DISPATCH_DEPTH.set(DISPATCH_DEPTH.get() - 1);
    }
}

// TODO-HUMAN-REVIEW(PR-148): Review signal-context tool allocation isolation.
/// Routes this thread's allocations to the Tool heap until the returned scope
/// is dropped. A Tool callback runs inside one, because it can interrupt the
/// guest's own allocator.
pub fn enter_dispatch() -> DispatchAllocationScope {
    DISPATCH_DEPTH.set(DISPATCH_DEPTH.get() + 1);
    DispatchAllocationScope {
        _same_thread: PhantomData,
    }
}

/// Whether `pointer` is in the Tool heap. For tests of allocators built on
/// [`GuestAllocator`].
#[doc(hidden)]
pub fn tool_heap_contains(pointer: *const u8) -> bool {
    TOOL_HEAP.contains(pointer.cast_mut())
}

/// Actual dispatch nesting for the preload allocation regression.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_dispatch_depth() -> usize {
    DISPATCH_DEPTH.get()
}

/// Actual Legacy BSS bounds without allocation or region initialization.
#[doc(hidden)]
pub fn legacy_tool_heap_bounds() -> (usize, usize) {
    let base = TOOL_HEAP.base() as usize;
    (base, base + TOOL_HEAP_BYTES)
}

/// Half-open bounds of the backing storage used by the Legacy Tool allocator.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_tool_heap_bounds() -> (usize, usize) {
    legacy_tool_heap_bounds()
}

#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
#[allow(missing_docs)]
#[derive(Clone, Copy)]
pub struct ToolHeapFixtureState {
    pub base: usize,
    pub end: usize,
    pub next_address: usize,
    pub next: usize,
    pub free_head_address: usize,
    pub free_head: usize,
    pub lock_address: usize,
    pub lock_held: bool,
    pub head_address: usize,
    pub head_span: usize,
    pub head_next: usize,
}

/// Snapshot a real span without allocation, initialization or route changes.
/// Busy or malformed metadata refuses; only one validated head is read, under
/// this span's actual allocator lock. The lock sample includes this query.
#[cfg(feature = "allocator-fixture")]
fn fixture_span_state(heap: ToolHeapSpan<'_>) -> Option<ToolHeapFixtureState> {
    heap.metadata
        .locked
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()?;
    let _guard = ToolHeapLock {
        metadata: heap.metadata,
    };
    // SAFETY: this span's actual allocator lock serializes the scalar reads.
    let (next, free_head) = unsafe { (*heap.metadata.next.get(), *heap.metadata.free_head.get()) };
    let (mut head_address, mut head_span, mut head_next) = (0, 0, 0);
    if free_head != FREE_LIST_END {
        if free_head % align_of::<ToolHeapBlock>() != 0
            || free_head > heap.bytes.checked_sub(size_of::<ToolHeapBlock>())?
        {
            return None;
        }
        // SAFETY: exactly one real head header, under the selected allocator
        // lock, after checking its offset, alignment and complete header span.
        let block = heap.block(free_head);
        (head_span, head_next) = unsafe { ((*block).span, (*block).next) };
        let end = free_head.checked_add(head_span)?;
        if head_span < MIN_FREE_SPAN
            || end > heap.bytes
            || end % align_of::<ToolHeapBlock>() != 0
            || (head_next != FREE_LIST_END
                && (head_next < end
                    || head_next % align_of::<ToolHeapBlock>() != 0
                    || head_next > heap.bytes - size_of::<ToolHeapBlock>()))
        {
            return None;
        }
        head_address = block as usize;
    }
    let base = heap.base as usize;
    Some(ToolHeapFixtureState {
        base,
        end: base.checked_add(heap.bytes)?,
        next_address: heap.metadata.next.get() as usize,
        next,
        free_head_address: heap.metadata.free_head.get() as usize,
        free_head,
        lock_address: (&raw const heap.metadata.locked) as usize,
        lock_held: heap.metadata.locked.load(Ordering::Relaxed),
        head_address,
        head_span,
        head_next,
    })
}

/// Observe the actual Legacy BSS allocator state without selecting backing.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_tool_heap_state() -> Option<ToolHeapFixtureState> {
    fixture_span_state(TOOL_HEAP.span())
}

/// Observe Fixed state only after authentic completed owner publication.
/// No metadata address is guessed or dereferenced before readiness.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_fixed_tool_heap_state() -> Option<ToolHeapFixtureState> {
    fixture_span_state(super::tool_region::fixed_tool_heap()?)
}

fn dispatch_active() -> bool {
    DISPATCH_DEPTH.get() != 0
}

/// An allocator for a preload whose Rust allocations always belong to the Tool.
///
/// All operations use the reusable 32 MiB Tool arena, even outside dispatch.
/// Exhaustion returns null; there is no System allocation or arena growth.
/// This covers compiler-selected Rust allocation, not allocations made inside
/// foreign libraries, thread-local storage, or the guest's own allocator.
pub struct PrivateToolAllocator;

impl PrivateToolAllocator {
    /// Require an address within this allocator's backing storage.
    ///
    /// Accepts arbitrary addresses without dereferencing them. A mismatch exits
    /// with status 127 through the trusted syscall gate. Passing this check does
    /// not prove that an address names a live allocation: callers of GlobalAlloc
    /// must still satisfy its pointer and layout requirements.
    #[doc(hidden)]
    pub fn require_owned_address(address: usize) {
        if !TOOL_HEAP.contains(address as *mut u8) {
            refuse_foreign_allocation();
        }
    }
}

/// Terminate without allocating, invoking libc, or reading a foreign header.
fn refuse_foreign_allocation() -> ! {
    // SAFETY: exit_group consumes only the scalar exit status. If an outer
    // filter refuses it, UD2 terminates instead of returning or spinning.
    unsafe {
        crate::trap::raw_syscall6(libc::SYS_exit_group, [127, 0, 0, 0, 0, 0]);
        core::arch::asm!("ud2", options(noreturn, nostack));
    }
}

// SAFETY: the arena serializes metadata and honors Layout. Ownership is checked
// before any header access; valid-pointer obligations remain the caller's.
unsafe impl GlobalAlloc for PrivateToolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        TOOL_HEAP.allocate(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = TOOL_HEAP.allocate(layout);
        if !pointer.is_null() {
            // SAFETY: the allocation holds layout.size writable bytes.
            unsafe { pointer.write_bytes(0, layout.size()) };
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        Self::require_owned_address(pointer as usize);
        // SAFETY: the caller supplies a live allocation from this arena.
        unsafe { TOOL_HEAP.deallocate(pointer) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        Self::require_owned_address(pointer as usize);
        let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        let replacement = TOOL_HEAP.allocate(new_layout);
        if !replacement.is_null() {
            // SAFETY: the live allocations do not overlap. A failed allocation
            // leaves the original live as GlobalAlloc requires.
            unsafe {
                ptr::copy_nonoverlapping(pointer, replacement, old.size().min(new_size));
                TOOL_HEAP.deallocate(pointer);
            }
        }
        replacement
    }
}

/// Reusable allocation from an already-published fixed ToolRegion arena.
///
/// Allocation before completed publication or after exhaustion returns null.
/// This allocator never initializes a reservation or chooses BSS/System. Its
/// contents and scalar metadata inherit through COW on a quiescent plain fork;
/// an inherited held lock is not reset or advertised as supported.
pub struct FixedToolAllocator;

impl FixedToolAllocator {
    /// Refuse unready ownership or a foreign address before any header read.
    /// GlobalAlloc callers must still provide a live allocation and its layout.
    #[doc(hidden)]
    pub fn require_owned_address(address: usize) {
        let Some(heap) = super::tool_region::fixed_tool_heap() else {
            refuse_foreign_allocation();
        };
        if !heap.contains(address as *mut u8) {
            refuse_foreign_allocation();
        }
    }

    fn owned_heap(address: usize) -> ToolHeapSpan<'static> {
        let Some(heap) = super::tool_region::fixed_tool_heap() else {
            refuse_foreign_allocation();
        };
        if !heap.contains(address as *mut u8) {
            refuse_foreign_allocation();
        }
        heap
    }
}

/// Membership in the actual ready Fixed reusable span, without initialization.
#[doc(hidden)]
pub fn fixed_tool_heap_contains(pointer: *const u8) -> bool {
    super::tool_region::fixed_tool_heap().is_some_and(|heap| heap.contains(pointer.cast_mut()))
}

/// Clear a live Fixed allocation without an interposable libc memory call.
///
/// # Safety
/// `pointer` must cover `length` writable bytes. The caller must obey the
/// x86-64 SysV clear-direction-flag contract used by all Rust Tool entries.
#[doc(hidden)]
#[inline(never)]
pub unsafe fn fixed_zero_bytes(pointer: *mut u8, length: usize) {
    // SAFETY: the valid writable range and clear DF are caller requirements.
    // REP changes only the declared index/count registers, preserving flags.
    unsafe {
        core::arch::asm!(
            "rep stosb",
            in("al") 0_u8,
            inout("rdi") pointer => _,
            inout("rcx") length => _,
            options(nostack, preserves_flags),
        );
    }
}

/// Copy live disjoint Fixed allocations without an interposable libc call.
///
/// # Safety
/// `source` and `destination` must cover `length` readable and writable bytes,
/// respectively, and must not overlap. The caller must obey the x86-64 SysV
/// clear-direction-flag contract used by all Rust Tool entries.
#[doc(hidden)]
#[inline(never)]
pub unsafe fn fixed_copy_bytes(source: *const u8, destination: *mut u8, length: usize) {
    // SAFETY: the two valid disjoint ranges and clear DF are caller requirements.
    unsafe {
        core::arch::asm!(
            "rep movsb",
            inout("rsi") source => _,
            inout("rdi") destination => _,
            inout("rcx") length => _,
            options(nostack, preserves_flags),
        );
    }
}

// SAFETY: the same serialized span algorithm honors Layout, and every free or
// realloc authenticates ready backing/range before touching a block header.
unsafe impl GlobalAlloc for FixedToolAllocator {
    #[inline(never)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(heap) = super::tool_region::fixed_tool_heap() else {
            return ptr::null_mut();
        };
        heap.allocate(layout)
    }

    #[inline(never)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { self.alloc(layout) };
        if !pointer.is_null() {
            // SAFETY: pointer covers layout.size writable bytes.
            unsafe { fixed_zero_bytes(pointer, layout.size()) };
        }
        pointer
    }

    #[inline(never)]
    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        let heap = Self::owned_heap(pointer as usize);
        // SAFETY: the caller supplies a live allocation from this ready span.
        unsafe { heap.deallocate(pointer) };
    }

    #[inline(never)]
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new_size: usize) -> *mut u8 {
        let heap = Self::owned_heap(pointer as usize);
        let Ok(layout) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        let replacement = heap.allocate(layout);
        if !replacement.is_null() {
            // SAFETY: live allocations are disjoint. Failure leaves the source
            // live, exactly as in the Legacy reusable allocator.
            unsafe {
                fixed_copy_bytes(pointer, replacement, old.size().min(new_size));
                heap.deallocate(pointer);
            }
        }
        replacement
    }
}

/// The allocator for a library that hosts an in-guest Tool. Inside a
/// [`DispatchAllocationScope`] it allocates from the Tool heap, a
/// process-lifetime 32 MiB arena independent of libc; elsewhere it forwards to
/// the system allocator. A backend declares it (or wraps it) as the guest
/// library's `#[global_allocator]`.
pub struct GuestAllocator;

// SAFETY: normal allocations delegate to System, and dispatch allocations use
// serialized reusable storage independent of the interrupted guest allocator.
unsafe impl GlobalAlloc for GuestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if dispatch_active() {
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
        } else if dispatch_active() {
            // A tool may drop state allocated before the filter was installed.
            // Leaking it is preferable to reentering an interrupted allocator.
        } else {
            // SAFETY: other pointers came from System with this layout.
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
        if !dispatch_active() {
            // SAFETY: other pointers came from System with this layout.
            return unsafe { System.realloc(pointer, old, new_size) };
        }
        let Ok(new_layout) = Layout::from_size_align(new_size, old.align()) else {
            return ptr::null_mut();
        };
        // A system allocation reallocated during dispatch moves into the Tool
        // heap; the source is left live rather than freed through System.
        let replacement = TOOL_HEAP.allocate(new_layout);
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
        self.metadata.locked.store(false, Ordering::Release);
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|address| address & !(alignment - 1))
}

static TOOL_HEAP: ToolHeap = ToolHeap::new();

#[cfg(test)]
#[path = "alloc_fragmentation_tests.rs"]
mod fragmentation_tests;

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

    /// The heap must be anonymous memory, not part of any mapping of the file
    /// that holds it: a census of that file's mappings would otherwise read the
    /// runtime's own state (saved instruction pointers, function pointers) as
    /// code addresses of the object.
    #[test]
    fn tool_heap_is_anonymous_memory() {
        let start = TOOL_HEAP.base() as u64;
        assert_eq!(start % 4096, 0, "the Tool heap is not page-aligned");
        let last = start + TOOL_HEAP_BYTES as u64 - 1;
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for address in [start, last] {
            let line = maps
                .lines()
                .find(|line| {
                    let (start, end) = line
                        .split_whitespace()
                        .next()
                        .and_then(|range| range.split_once('-'))
                        .unwrap();
                    (u64::from_str_radix(start, 16).unwrap()..u64::from_str_radix(end, 16).unwrap())
                        .contains(&address)
                })
                .unwrap_or_else(|| panic!("{address:#x} is in no mapping:\n{maps}"));
            let inode = line.split_whitespace().nth(4).unwrap();
            assert_eq!(
                inode, "0",
                "the Tool heap at {address:#x} is file-backed: {line}"
            );
        }
    }

    #[test]
    fn dispatch_heap_reuses_freed_blocks() {
        let _test_guard = test_guard();
        let allocator = GuestAllocator;
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
        let allocator = GuestAllocator;
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
        let allocator = GuestAllocator;
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
        let allocator = GuestAllocator;
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
        let allocator = GuestAllocator;
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
                let allocator = GuestAllocator;
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
