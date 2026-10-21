//! Feature-only, scope-free observations of the final preload's Rust allocator.
//!
//! This module must be identical in baseline and candidate. It deliberately
//! calls std::alloc, never an allocator implementation or allocation scope.
//! The caller must supply writable output records and valid live payload access.
//! Returned allocations must be released through this same loaded module.

use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

const ABI_VERSION: u64 = 1;
const OK: u64 = 0;
const INVALID: u64 = 1;
const ALLOCATION_FAILED: u64 = 2;
const BUSY: u64 = 3;
const REGISTRY_FULL: u64 = 4;
const UNKNOWN_ALLOCATION: u64 = 5;
const NOT_READY: u64 = 6;
const SLOTS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct M1Result {
    pub abi_version: u64,
    pub status: u64,
    pub pointer: u64,
    pub size: u64,
    pub align: u64,
    pub installation_before: u64,
    pub dispatch_before: u64,
    pub installation_after: u64,
    pub dispatch_after: u64,
    pub private_member: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct M1Query {
    pub abi_version: u64,
    pub status: u64,
    pub installation_depth: u64,
    pub dispatch_depth: u64,
    pub tool_base: u64,
    pub tool_end: u64,
    pub patch_base: u64,
    pub patch_end: u64,
    pub live_allocations: u64,
}

#[derive(Clone, Copy)]
struct Live {
    pointer: *mut u8,
    size: usize,
    align: usize,
}

const EMPTY: Live = Live {
    pointer: ptr::null_mut(),
    size: 0,
    align: 0,
};

struct Registry(UnsafeCell<[Live; SLOTS]>);
// SAFETY: every registry access is protected by the nonblocking LOCK guard.
unsafe impl Sync for Registry {}
static LIVE: Registry = Registry(UnsafeCell::new([EMPTY; SLOTS]));
static LOCK: AtomicBool = AtomicBool::new(false);

struct Guard;
impl Guard {
    fn acquire() -> Option<Self> {
        LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}

fn depths() -> (u64, u64) {
    (
        crate::patch_alloc::fixture_installation_depth() as u64,
        reverie_inguest::guest::alloc::fixture_dispatch_depth() as u64,
    )
}

fn bounds() -> Option<((usize, usize), (usize, usize))> {
    crate::patch_alloc::fixture_selected_bounds()
}

fn private_member(address: usize) -> bool {
    bounds().is_some_and(|(tool, patch)| {
        (tool.0..tool.1).contains(&address) || (patch.0..patch.1).contains(&address)
    })
}

fn initial(size: usize, align: usize) -> M1Result {
    let (installation_before, dispatch_before) = depths();
    M1Result {
        abi_version: ABI_VERSION,
        status: OK,
        size: size as u64,
        align: align as u64,
        installation_before,
        dispatch_before,
        ..M1Result::default()
    }
}

unsafe fn finish(output: *mut M1Result, mut result: M1Result) -> u64 {
    let (installation_after, dispatch_after) = depths();
    result.installation_after = installation_after;
    result.dispatch_after = dispatch_after;
    result.private_member = u64::from(private_member(result.pointer as usize));
    let status = result.status;
    // SAFETY: this export's caller supplies a writable, properly aligned record.
    unsafe { output.write(result) };
    status
}

fn layout(size: usize, align: usize) -> Option<Layout> {
    if size == 0 {
        None
    } else {
        Layout::from_size_align(size, align).ok()
    }
}

/// Allocation-free diagnostics of actual counters and half-open backing ranges.
///
/// # Safety
/// `output` must point to a writable, aligned M1Query record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m1_query(output: *mut M1Query) -> u64 {
    if output.is_null() {
        return INVALID;
    }
    let (installation_depth, dispatch_depth) = depths();
    let Some((tool, patch)) = bounds() else {
        let result = M1Query {
            abi_version: ABI_VERSION,
            status: NOT_READY,
            installation_depth,
            dispatch_depth,
            ..M1Query::default()
        };
        // SAFETY: the caller supplies one complete writable query record.
        unsafe { output.write(result) };
        return NOT_READY;
    };
    let mut result = M1Query {
        abi_version: ABI_VERSION,
        installation_depth,
        dispatch_depth,
        tool_base: tool.0 as u64,
        tool_end: tool.1 as u64,
        patch_base: patch.0 as u64,
        patch_end: patch.1 as u64,
        ..M1Query::default()
    };
    if let Some(_guard) = Guard::acquire() {
        // SAFETY: the guard exclusively owns registry access.
        result.live_allocations = unsafe { &*LIVE.0.get() }
            .iter()
            .filter(|entry| !entry.pointer.is_null())
            .count() as u64;
    } else {
        result.status = BUSY;
    }
    let status = result.status;
    unsafe { output.write(result) };
    status
}

/// Numeric membership only: no dereference, allocator call or scope entry.
#[unsafe(no_mangle)]
pub extern "C" fn m1_probe_private(pointer: *const u8) -> u64 {
    u64::from(private_member(pointer as usize))
}

/// # Safety
/// `output` must point to a writable, aligned M1Result. Nonzero layouts only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m1_alloc(
    size: usize,
    align: usize,
    zeroed: u64,
    output: *mut M1Result,
) -> u64 {
    if output.is_null() {
        return INVALID;
    }
    let mut result = initial(size, align);
    let Some(layout) = layout(size, align).filter(|_| zeroed <= 1) else {
        result.status = INVALID;
        return unsafe { finish(output, result) };
    };
    let Some(_guard) = Guard::acquire() else {
        result.status = BUSY;
        return unsafe { finish(output, result) };
    };
    let entries = unsafe { &mut *LIVE.0.get() };
    let Some(slot) = entries.iter_mut().find(|entry| entry.pointer.is_null()) else {
        result.status = REGISTRY_FULL;
        return unsafe { finish(output, result) };
    };
    // SAFETY: layout is nonzero and valid. These are the final binary's
    // compiler-selected allocation shims, with no direct private allocator call.
    let pointer = unsafe {
        if zeroed == 1 {
            std::alloc::alloc_zeroed(layout)
        } else {
            std::alloc::alloc(layout)
        }
    };
    if pointer.is_null() {
        result.status = ALLOCATION_FAILED;
    } else {
        *slot = Live {
            pointer,
            size,
            align,
        };
        result.pointer = pointer as u64;
    }
    unsafe { finish(output, result) }
}

/// # Safety
/// `pointer` must be a live pointer returned by this module, with exactly the
/// recorded layout, not an arbitrary/interior pointer. `output` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m1_realloc(
    pointer: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
    output: *mut M1Result,
) -> u64 {
    if output.is_null() {
        return INVALID;
    }
    let mut result = initial(new_size, align);
    let Some(old) = layout(old_size, align).filter(|_| layout(new_size, align).is_some()) else {
        result.status = INVALID;
        return unsafe { finish(output, result) };
    };
    let Some(_guard) = Guard::acquire() else {
        result.status = BUSY;
        return unsafe { finish(output, result) };
    };
    let entries = unsafe { &mut *LIVE.0.get() };
    let Some(slot) = entries.iter_mut().find(|entry| {
        entry.pointer == pointer
            && !pointer.is_null()
            && entry.size == old_size
            && entry.align == align
    }) else {
        result.status = UNKNOWN_ALLOCATION;
        return unsafe { finish(output, result) };
    };
    // SAFETY: registry proves the allocation and exact original layout. The
    // old allocation remains live on null, as std::alloc::realloc requires.
    let replacement = unsafe { std::alloc::realloc(pointer, old, new_size) };
    if replacement.is_null() {
        result.status = ALLOCATION_FAILED;
        result.pointer = pointer as u64;
        result.size = old_size as u64;
    } else {
        *slot = Live {
            pointer: replacement,
            size: new_size,
            align,
        };
        result.pointer = replacement as u64;
    }
    unsafe { finish(output, result) }
}

/// # Safety
/// `pointer` must be live from this module with exactly its recorded layout;
/// `output` must be writable. Membership is recorded while the pointer is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m1_dealloc(
    pointer: *mut u8,
    size: usize,
    align: usize,
    output: *mut M1Result,
) -> u64 {
    if output.is_null() {
        return INVALID;
    }
    let mut result = initial(size, align);
    result.pointer = pointer as u64;
    let membership_while_live = u64::from(private_member(pointer as usize));
    let Some(layout) = layout(size, align) else {
        result.status = INVALID;
        return unsafe { finish(output, result) };
    };
    let Some(_guard) = Guard::acquire() else {
        result.status = BUSY;
        return unsafe { finish(output, result) };
    };
    let entries = unsafe { &mut *LIVE.0.get() };
    let Some(slot) = entries.iter_mut().find(|entry| {
        entry.pointer == pointer && !pointer.is_null() && entry.size == size && entry.align == align
    }) else {
        result.status = UNKNOWN_ALLOCATION;
        return unsafe { finish(output, result) };
    };
    // SAFETY: both baseline System and candidate private pointers are returned
    // to their original compiler-selected allocator with the valid layout.
    unsafe { std::alloc::dealloc(pointer, layout) };
    *slot = EMPTY;
    // No payload or allocation header is read after deallocation.
    let status = unsafe { finish(output, result) };
    // Numeric membership describes the live pre-call pointer, not its lifetime.
    unsafe { (*output).private_member = membership_while_live };
    status
}
