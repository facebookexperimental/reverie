//! Feature-only live allocator observations, separate from the frozen M1 ABI.
//! The same wrapper/probe is used for a measured Legacy baseline and Fixed
//! candidate. Backing observations never select or initialize an allocator.

use core::mem::align_of;
use core::mem::size_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;

use crate::allocator_fixture::M1Result;
use crate::allocator_fixture::m1_alloc;
use crate::allocator_fixture::m1_dealloc;
use crate::allocator_fixture::m1_realloc;

const NOT_READY: u64 = 1;
const UNAVAILABLE: u64 = 2;
const INVALID: u64 = 3;

/// Version-one, separate 31-word observation ABI. Metadata values describe the
/// actual objects, including the snapshot's own temporary heap-lock ownership.
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(missing_docs)]
pub struct AllocatorSnapshot {
    pub version: u64,
    pub status: u64,
    pub backing_kind: u64,
    pub region_published: u64,
    pub backing_ready: u64,
    pub installation_depth: u64,
    pub dispatch_depth: u64,
    pub tool_base: u64,
    pub tool_end: u64,
    pub patch_base: u64,
    pub patch_end: u64,
    pub tool_next_address: u64,
    pub tool_next_size: u64,
    pub tool_next_align: u64,
    pub tool_next: u64,
    pub tool_free_head_address: u64,
    pub tool_free_head_size: u64,
    pub tool_free_head_align: u64,
    pub tool_free_head: u64,
    pub tool_lock_address: u64,
    pub tool_lock_size: u64,
    pub tool_lock_align: u64,
    pub tool_lock_sample_held: u64,
    pub patch_next_address: u64,
    pub patch_next_size: u64,
    pub patch_next_align: u64,
    pub patch_next: u64,
    pub head_address: u64,
    pub head_span: u64,
    pub head_next: u64,
    pub reserved: u64,
}
const _: () = assert!(size_of::<AllocatorSnapshot>() == 31 * 8);
const _: () = assert!(align_of::<AllocatorSnapshot>() == 8);

/// Copy actual backing and metadata without allocation or initialization.
///
/// # Safety
/// `output` designates one aligned, writable record not aliasing Tool metadata.
/// The trusted fixture calls this quiescently, outside allocator operations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m5_allocator_snapshot(
    output: *mut AllocatorSnapshot,
    bytes: usize,
) -> u64 {
    if output.is_null()
        || bytes != size_of::<AllocatorSnapshot>()
        || !(output as usize).is_multiple_of(8)
    {
        return INVALID;
    }
    let mut result = AllocatorSnapshot {
        version: 1,
        region_published: u64::from(
            reverie_inguest::guest::tool_region::fixture_region_published(),
        ),
        installation_depth: crate::patch_alloc::fixture_installation_depth() as u64,
        dispatch_depth: reverie_inguest::guest::alloc::fixture_dispatch_depth() as u64,
        ..AllocatorSnapshot::default()
    };
    if let Some(state) = crate::patch_alloc::fixture_backing_state() {
        result.backing_kind = state.kind;
        result.backing_ready = u64::from(state.ready);
        if !state.ready {
            result.status = NOT_READY;
        } else if state.kind > 1 {
            result.status = INVALID;
        } else {
            let tool = state.tool;
            result.tool_base = tool.base as u64;
            result.tool_end = tool.end as u64;
            result.patch_base = state.patch_base as u64;
            result.patch_end = state.patch_end as u64;
            result.tool_next_address = tool.next_address as u64;
            result.tool_next_size = size_of::<usize>() as u64;
            result.tool_next_align = align_of::<usize>() as u64;
            result.tool_next = tool.next as u64;
            result.tool_free_head_address = tool.free_head_address as u64;
            result.tool_free_head_size = size_of::<usize>() as u64;
            result.tool_free_head_align = align_of::<usize>() as u64;
            result.tool_free_head = tool.free_head as u64;
            result.tool_lock_address = tool.lock_address as u64;
            result.tool_lock_size = size_of::<AtomicBool>() as u64;
            result.tool_lock_align = align_of::<AtomicBool>() as u64;
            result.tool_lock_sample_held = u64::from(tool.lock_held);
            result.patch_next_address = state.patch_next_address as u64;
            result.patch_next_size = size_of::<AtomicUsize>() as u64;
            result.patch_next_align = align_of::<AtomicUsize>() as u64;
            result.patch_next = state.patch_next as u64;
            result.head_address = tool.head_address as u64;
            result.head_span = tool.head_span as u64;
            result.head_next = tool.head_next as u64;
        }
    } else {
        result.status = UNAVAILABLE;
    }
    let status = result.status;
    // SAFETY: the caller supplies one complete writable observation record.
    unsafe { output.write(result) };
    status
}

/// Execute M1's compiler-selected operations inside explicit real scopes.
/// Operations 0/1 allocate/zero, 2 reallocates, and 3 frees.
/// Scope bits 1/2 enter real dispatch/installation guards, respectively.
/// No direct allocator implementation is called here or by the C fixture.
///
/// # Safety
/// Output and pointer/layout obligations are exactly the invoked M1 export's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m5_allocator_operation(
    operation: u64,
    scope: u64,
    pointer: *mut u8,
    old_size: usize,
    size: usize,
    align: usize,
    output: *mut M1Result,
) -> u64 {
    if operation > 3 || scope > 3 || output.is_null() {
        return 1;
    }
    let _dispatch = (scope & 1 != 0).then(reverie_inguest::guest::alloc::enter_dispatch);
    let _installation = (scope & 2 != 0).then(crate::patch_alloc::enter);
    // SAFETY: the trusted caller meets the selected M1 export's exact contract.
    unsafe {
        match operation {
            0 | 1 => m1_alloc(size, align, operation, output),
            2 => m1_realloc(pointer, old_size, align, size, output),
            3 => m1_dealloc(pointer, old_size, align, output),
            _ => unreachable!(),
        }
    }
}

/// Read raw maps through the existing trusted gate, since an active standalone
/// Tool deliberately refuses unpublished guest open/read syscall sites.
///
/// # Safety
/// `output` designates `capacity` writable bytes, not aliasing Tool metadata.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m5_allocator_maps(output: *mut u8, capacity: usize) -> i64 {
    use reverie_inguest::trap::raw_syscall6;
    if output.is_null() || capacity == 0 || capacity > 1024 * 1024 {
        return -i64::from(libc::EINVAL);
    }
    // SAFETY: constant NUL-terminated path and scalar kernel arguments.
    let fd = unsafe {
        raw_syscall6(
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                c"/proc/self/maps".as_ptr() as u64,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        )
    };
    if fd < 0 {
        return fd;
    }
    let mut used = 0;
    let result = loop {
        if used == capacity {
            break -i64::from(libc::EOVERFLOW);
        }
        // SAFETY: the caller supplies the full buffer and used stays below its
        // capacity; this gate bypasses the Tool without changing guest policy.
        let count = unsafe {
            raw_syscall6(
                libc::SYS_read,
                [
                    fd as u64,
                    output.add(used) as u64,
                    (capacity - used) as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if count == -i64::from(libc::EINTR) {
            continue;
        }
        if count < 0 {
            break count;
        }
        if count == 0 {
            break used as i64;
        }
        used += count as usize;
    };
    // SAFETY: fd is the live descriptor returned by this query's openat.
    let close = unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    if result >= 0 && close < 0 {
        close
    } else {
        result
    }
}
