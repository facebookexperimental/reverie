//! Dedicated private-image C allocator; only the explicit musl leaf includes it.
//!
//! Each C call must execute under this image's genuine initialized private FS
//! after the sole bootstrap leader publishes TLS. No guest/host allocator is a
//! valid source for a nonnull pointer. This module confers no image ownership.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "musl",
    feature = "loader-private-runtime",
))]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ffi::c_int;
use core::ffi::c_void;
use core::mem::align_of;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use crate::guest::alloc::FixedToolAllocator;
use crate::guest::alloc::fixed_copy_bytes;
use crate::guest::alloc::fixed_tool_heap_contains;
use crate::guest::alloc::fixed_zero_bytes;

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;
const MAX_REQUEST: usize = usize::MAX / 2 - 4096;
const MIN_ALIGNMENT: usize = 16;
const ALIGNED_LIMIT: usize = (1_usize << 31) * 16;
// This is startup publication, not a per-thread TLS or allocator-owner proof.
static PRIVATE_TLS_PUBLISHED: AtomicU8 = AtomicU8::new(0);
const PRE_TLS: u32 = 1;
const INVALID_ALLOCATION: u32 = 2;
const DUPLICATE_PUBLICATION: u32 = 3;

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
    // Link-required trusted leaf. This deliberately has a separate name from
    // TLSv2's enum-typed abort ABI: arbitrary reason values must not form an
    // invalid Rust enum. The final implementation may share its audited gate.
    fn hermit_loader_c_allocator_abort(reason: u32) -> !;
}

fn die(reason: u32) -> ! {
    // SAFETY: final link must supply the qualified no-TLS/nonalloc/no-unwind
    // terminal leaf. Missing implementation must fail the final image link.
    unsafe { hermit_loader_c_allocator_abort(reason) }
}

/// Publish only the genuine completed private-libc/TLS initialization.
///
/// # Safety
/// Sole stopped/bootstrap leader, correct private FS and initialized errno/
/// libc state, no asynchronous/reentrant C allocation during the transition.
/// Every later nontrivial adapter call, on every thread, must run with genuine
/// private FS. This scalar does not authenticate another thread's FS or arm
/// dispatch, adopt an image, reset a fork lock, or permit guest execution.
/// Publication is one-use and never reset/retried after an error.
#[inline(never)]
pub unsafe fn publish_private_tls_initialized() {
    if PRIVATE_TLS_PUBLISHED
        .compare_exchange(0, 1, Ordering::Release, Ordering::Relaxed)
        .is_err()
    {
        die(DUPLICATE_PUBLICATION);
    }
}

fn require_private_tls() {
    if PRIVATE_TLS_PUBLISHED.load(Ordering::Acquire) != 1 {
        die(PRE_TLS);
    }
}

fn error(error: c_int) {
    require_private_tls();
    // SAFETY: genuine initialized private TLS/errno is an explicit adapter
    // entry invariant, not inferred from an arbitrary caller-supplied pointer.
    unsafe { *__errno_location() = error };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Header {
    base: *mut u8,
    total: usize,
    alignment: usize,
    requested: usize,
}
const _: () = {
    assert!(size_of::<usize>() == 8);
    assert!(size_of::<Header>() == 32);
    assert!(align_of::<Header>() <= MIN_ALIGNMENT);
};

fn allocate(requested: usize, alignment: usize) -> *mut c_void {
    require_private_tls();
    if requested >= MAX_REQUEST {
        error(ENOMEM);
        return ptr::null_mut();
    }
    let alignment = alignment.max(MIN_ALIGNMENT);
    let Some(offset) = size_of::<Header>()
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
    else {
        error(ENOMEM);
        return ptr::null_mut();
    };
    let Some(total) = offset.checked_add(requested.max(1)) else {
        error(ENOMEM);
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, alignment) else {
        error(ENOMEM);
        return ptr::null_mut();
    };
    // SAFETY: validated nonzero Layout. Actual Fixed allocation returns null
    // before owner publication/exhaustion and never initializes/reserves it.
    let base = unsafe { FixedToolAllocator.alloc(layout) };
    if base.is_null() {
        error(ENOMEM);
        return ptr::null_mut();
    }
    // SAFETY: checked offset/total and allocated alignment cover header and
    // >=1 byte payload; no pointer is published until the header is complete.
    unsafe {
        let payload = base.add(offset);
        payload
            .sub(size_of::<Header>())
            .cast::<Header>()
            .write(Header {
                base,
                total,
                alignment,
                requested,
            });
        payload.cast()
    }
}

unsafe fn header(pointer: *mut c_void) -> Header {
    require_private_tls();
    let address = pointer as usize;
    let Some(first) = address.checked_sub(size_of::<Header>()) else {
        die(INVALID_ALLOCATION);
    };
    if address % MIN_ALIGNMENT != 0
        || !fixed_tool_heap_contains(pointer.cast())
        || !fixed_tool_heap_contains(first as *const u8)
        || !fixed_tool_heap_contains((address - 1) as *const u8)
    {
        die(INVALID_ALLOCATION);
    }
    // SAFETY: caller provides a live C allocation from this adapter. Membership
    // authenticates domain before access, not liveness or an arbitrary magic.
    unsafe {
        pointer
            .cast::<u8>()
            .sub(size_of::<Header>())
            .cast::<Header>()
            .read()
    }
}

unsafe fn release(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: propagated valid live allocation requirement.
    let metadata = unsafe { header(pointer) };
    FixedToolAllocator::require_owned_address(metadata.base as usize);
    let Ok(layout) = Layout::from_size_align(metadata.total, metadata.alignment) else {
        die(INVALID_ALLOCATION);
    };
    // SAFETY: header records the original allocation's exact base/Layout.
    unsafe { FixedToolAllocator.dealloc(metadata.base, layout) };
}

unsafe fn resize(pointer: *mut c_void, requested: usize) -> *mut c_void {
    require_private_tls();
    if pointer.is_null() {
        return allocate(requested, MIN_ALIGNMENT);
    }
    // SAFETY: propagated valid live allocation requirement.
    let old = unsafe { header(pointer) };
    let replacement = allocate(requested, old.alignment);
    if !replacement.is_null() {
        // SAFETY: replacement is a distinct live allocation; recorded requested
        // bytes are valid, including a zero-byte copy for requested_size=0.
        unsafe {
            fixed_copy_bytes(
                pointer.cast(),
                replacement.cast(),
                old.requested.min(requested),
            );
            release(pointer);
        }
    }
    replacement
}

fn zero_allocate(count: usize, size: usize) -> *mut c_void {
    require_private_tls();
    let Some(requested) = count.checked_mul(size) else {
        error(ENOMEM);
        return ptr::null_mut();
    };
    let pointer = allocate(requested, MIN_ALIGNMENT);
    if !pointer.is_null() {
        // SAFETY: allocate returned requested writable payload bytes.
        unsafe { fixed_zero_bytes(pointer.cast(), requested) };
    }
    pointer
}

fn aligned(alignment: usize, requested: usize) -> *mut c_void {
    require_private_tls();
    // Preserve musl 1.2.5's align=0 extension and lack of len%align rule.
    if alignment != 0 && !alignment.is_power_of_two() {
        error(EINVAL);
        return ptr::null_mut();
    }
    if alignment >= ALIGNED_LIMIT || requested.checked_add(alignment).is_none() {
        error(ENOMEM);
        return ptr::null_mut();
    }
    allocate(requested, alignment.max(MIN_ALIGNMENT))
}

// All exported pointer operations inherit the C live-allocation contract;
// no safe Rust entry accepts an arbitrary address or confers ownership.
macro_rules! allocation_alias {
    ($($name:ident),+ $(,)?) => { $(
        /// Allocate C bytes from the existing Fixed owner.
        /// # Safety
        /// The caller must satisfy this module's private TLS/startup contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(size: usize) -> *mut c_void {
            allocate(size, MIN_ALIGNMENT)
        }
    )+ };
}
allocation_alias!(malloc, __libc_malloc, __libc_malloc_impl);

macro_rules! calloc_alias {
    ($($name:ident),+ $(,)?) => { $(
        /// Checked, zeroed C allocation from the existing Fixed owner.
        /// # Safety
        /// The caller must satisfy this module's private TLS/startup contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(count: usize, size: usize) -> *mut c_void {
            zero_allocate(count, size)
        }
    )+ };
}
calloc_alias!(calloc, __libc_calloc);

macro_rules! free_alias {
    ($($name:ident),+ $(,)?) => { $(
        /// Free a C allocation, with NULL accepted.
        /// # Safety
        /// Nonnull pointer is live from this adapter, not a Rust allocation or
        /// another libc. All module private TLS/startup requirements apply.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(pointer: *mut c_void) {
            // SAFETY: forwarded caller requirements.
            unsafe { release(pointer) }
        }
    )+ };
}
free_alias!(free, __libc_free);

macro_rules! realloc_alias {
    ($($name:ident),+ $(,)?) => { $(
        /// Resize C bytes, retaining the original on failure.
        /// # Safety
        /// Nonnull pointer is a live allocation from this adapter. All module
        /// private TLS/startup requirements apply.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(pointer: *mut c_void, size: usize) -> *mut c_void {
            // SAFETY: forwarded caller requirements.
            unsafe { resize(pointer, size) }
        }
    )+ };
}
realloc_alias!(realloc, __libc_realloc);

/// Checked array resize; leaves the original live on multiplication overflow.
/// # Safety
/// Same pointer and private TLS requirements as realloc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reallocarray(
    pointer: *mut c_void,
    count: usize,
    size: usize,
) -> *mut c_void {
    require_private_tls();
    let Some(requested) = count.checked_mul(size) else {
        error(ENOMEM);
        return ptr::null_mut();
    };
    // SAFETY: forwarded caller requirements.
    unsafe { resize(pointer, requested) }
}

/// Aligned C allocation with musl's retained validation semantics.
/// # Safety
/// All module private TLS/startup requirements apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    aligned(alignment, size)
}

/// Legacy aligned allocation; same owner and validation as aligned_alloc.
/// # Safety
/// All module private TLS/startup requirements apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    aligned(alignment, size)
}

/// Page-aligned allocation for the qualified x86-64 4096-byte-page image.
/// # Safety
/// All module private TLS/startup requirements apply; final image's page-size
/// authority must be exactly 4096 (the same required TLS/image geometry).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    aligned(4096, size)
}

/// POSIX aligned allocation; the result pointer is untouched on failure.
/// # Safety
/// `result` is writable, and all module private TLS/startup requirements apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(
    result: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    require_private_tls();
    if alignment < size_of::<*mut c_void>() {
        return EINVAL;
    }
    let pointer = aligned(alignment, size);
    if pointer.is_null() {
        // SAFETY: require_private_tls and entry contract establish private errno.
        return unsafe { *__errno_location() };
    }
    // SAFETY: caller-provided result slot; only written on successful allocation.
    unsafe { result.write(pointer) };
    0
}

/// Requested payload size; no mallocng metadata is ever decoded.
/// # Safety
/// Nonnull pointer is a live allocation from this adapter; module TLS contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc_usable_size(pointer: *mut c_void) -> usize {
    if pointer.is_null() {
        return 0;
    }
    // SAFETY: forwarded caller requirements.
    unsafe { header(pointer).requested }
}

/// Conservative all-zero hint for retained musl calloc: always clear payload.
/// # Safety
/// The caller obeys the musl helper ABI; this implementation accesses no pointee.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __malloc_allzerop(_pointer: *mut c_void) -> c_int {
    0
}
