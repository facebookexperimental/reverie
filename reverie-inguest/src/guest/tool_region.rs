/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Fixed backing for explicitly selected in-guest runtime stacks.
//!
//! This reserves virtual address space, not a physically committed buffer.
//! Used interiors remain on protection key zero. Boundary guards do not stop
//! guest writes to an interior or destructive fixed mappings. This module
//! makes no all-entry, TLS, allocator-arena or permission-isolation claim.
//!
//! Reservation and leasing are ordinary setup operations only. They must not
//! run from a signal handler, an interrupted initializer, or a live callback.
//! Published stacks retain their leases for process lifetime. Plain fork
//! inherits the mappings, occupied pages and live contents through COW.

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;
use std::sync::OnceLock;

use super::support::raw_zero_result;
use crate::trap::raw_syscall6;

/// Version-one fixed Tool reservation: a four-GiB virtual-address resource.
pub const BASE: usize = 0x6000_0000_0000;
/// Size of the version-one reservation, including its control area and guards.
pub const BYTES: usize = 4 * 1024 * 1024 * 1024;
/// End of the half-open fixed reservation.
pub const END: usize = BASE + BYTES;
const PAGE: usize = 4096;
const CONTROL_BYTES: usize = 1024 * 1024;
const DATA_FIRST: usize = CONTROL_BYTES / PAGE;
const DATA_END: usize = BYTES / PAGE - 1;
const BITMAP_WORDS: usize = BYTES / PAGE / 64;

// The publication locator is deliberately outside the fixed-region claim.
// Only a successfully reserved, initialized region is published here.
static REGION: OnceLock<Result<ToolRegion, i32>> = OnceLock::new();
// Every path which can initialize REGION first owns this nonwaiting gate.
// OnceLock::get is nonblocking; set is uncontended under this gate. A handler
// interrupting ordinary initialization gets EAGAIN rather than waiting on it.
static INITIALIZING: AtomicBool = AtomicBool::new(false);

#[repr(C)]
struct Control {
    held: AtomicBool,
    occupied: UnsafeCell<[u64; BITMAP_WORDS]>,
    registered_alternate: RegisteredAltStack,
}

// Base is atomic even while length is still zero: a private reader may race
// the installing thread's publication. The guard extents are read only after
// observing nonzero release-published length, and are then immutable.
#[repr(C)]
pub(crate) struct RegisteredAltStack {
    pub(crate) base: AtomicUsize,
    pub(crate) length: AtomicUsize,
    extent: UnsafeCell<(usize, usize)>,
}

/// The exact successfully registered, retained ToolRegion alternate lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredAlternateStack {
    /// First byte of the registered writable interior.
    pub bottom: usize,
    /// End of the registered writable interior.
    pub top: usize,
    /// First byte of the lower guard.
    pub extent_start: usize,
    /// End of the upper guard.
    pub extent_end: usize,
}

const _: () = assert!(size_of::<Control>() <= CONTROL_BYTES - PAGE);
const _: () = assert!(align_of::<Control>() <= PAGE);

/// An explicit storage choice; generic callers keep their existing backing.
#[derive(Clone, Copy, Debug)]
pub enum StackBacking {
    /// The existing allocator/anonymous backing, without a fixed reservation.
    Legacy,
    /// Guarded leases from an already reserved Tool region.
    ToolRegion(&'static ToolRegion),
}

/// One runtime instance's process-lifetime, private fixed reservation.
#[derive(Debug)]
pub struct ToolRegion {
    control: *mut Control,
    bootstrap: Option<constructor::BootstrapOwner>,
}

// SAFETY: the mapping lives until process exit. Every bitmap access holds its
// own allocation lock. No pointer into mutable metadata is exposed to callers.
unsafe impl Send for ToolRegion {}
unsafe impl Sync for ToolRegion {}

impl ToolRegion {
    /// Reserve this runtime instance's fixed region once. Call during ordinary
    /// startup, before application threads or runtime signal handlers begin.
    ///
    /// A colliding independent instance is refused; it never attaches to an
    /// unrecognized mapping. Errors are retained, without relocated/heap
    /// fallback. Inert compatibility loads must not call this function.
    /// An interrupted or concurrent initialization returns EAGAIN without
    /// waiting. Successfully published owners and retained errors are reused.
    pub fn reserve() -> io::Result<&'static Self> {
        if REGION.get().is_none() {
            let _initializing = InitializationGuard::acquire()?;
            if REGION.get().is_none() {
                REGION
                    .set(Self::reserve_inner())
                    .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
            }
        }
        REGION
            .get()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EAGAIN))?
            .as_ref()
            .map_err(|errno| io::Error::from_raw_os_error(*errno))
    }

    fn reserve_inner() -> Result<Self, i32> {
        // Linux x86-64 has 4096-byte base pages, including huge-page hosts.
        // Do not reinterpret the fixed layout using a runtime-sized page.
        let result = unsafe {
            raw_syscall6(
                libc::SYS_mmap,
                [
                    BASE as u64,
                    BYTES as u64,
                    libc::PROT_NONE as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
            )
        };
        if result < 0 {
            return Err(-result as i32);
        }
        let mapping = result as usize;
        validate_reservation(mapping)?;
        let control = (BASE + PAGE) as *mut Control;
        let protect = unsafe {
            raw_syscall6(
                libc::SYS_mprotect,
                [
                    control as u64,
                    (CONTROL_BYTES - PAGE) as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if protect < 0 {
            unsafe { raw_syscall6(libc::SYS_munmap, [BASE as u64, BYTES as u64, 0, 0, 0, 0]) };
            return Err(-protect as i32);
        }
        // Anonymous pages are initially zero. Construct the scalar lock in
        // place, without putting the 128 KiB bitmap on the caller's stack.
        // The zero-filled u64 bitmap is valid and is not exposed before the
        // OnceLock publishes this owner. Control/outer guards are excluded
        // from the allocator's searchable interval rather than marked free.
        unsafe { core::ptr::addr_of_mut!((*control).held).write(AtomicBool::new(false)) };
        // Fresh anonymous storage also provides valid zeroed atomic scalar
        // representations for registered_alternate. Native constructor setup
        // obtains the same fresh zeroed control before typed adoption.
        Ok(Self {
            control,
            bootstrap: None,
        })
    }

    pub(crate) fn registered_altstack(&'static self) -> &'static RegisteredAltStack {
        // SAFETY: the control mapping is retained for this owner's lifetime.
        unsafe { &(*self.control).registered_alternate }
    }

    /// Read a successfully published actual alternate stack without allocating
    /// or initializing a reservation. An empty descriptor is not ownership.
    pub fn registered_alternate_stack(&'static self) -> Option<RegisteredAlternateStack> {
        let descriptor = self.registered_altstack();
        let length = descriptor.length.load(Ordering::Acquire);
        if length == 0 {
            return None;
        }
        let bottom = descriptor.base.load(Ordering::Relaxed);
        // SAFETY: nonzero acquire length observes the sole release publication
        // of these immutable diagnostic fields. They are never read at zero.
        let (extent_start, extent_end) = unsafe { *descriptor.extent.get() };
        Some(RegisteredAlternateStack {
            bottom,
            top: bottom + length,
            extent_start,
            extent_end,
        })
    }

    // Called only after this owner's one successful registration. Replacing a
    // live process-global descriptor is not a supported thread/stack protocol.
    // Use values already computed for the kernel stack_t, and wrapping scalar
    // arithmetic, so this adds only fixed stores after registration succeeds.
    pub(crate) unsafe fn publish_registered_altstack(&'static self, base: usize, length: usize) {
        let descriptor = self.registered_altstack();
        unsafe {
            descriptor.extent.get().write((
                base.wrapping_sub(PAGE),
                base.wrapping_add(length).wrapping_add(PAGE),
            ));
        }
        descriptor.base.store(base, Ordering::Relaxed);
        descriptor.length.store(length, Ordering::Release);
    }

    fn lock(&self) -> io::Result<ControlGuard<'_>> {
        // No handler ever enters the allocator. Refuse unexpected concurrent
        // setup instead of spinning behind an interrupted owner.
        let control = unsafe { &*self.control };
        control
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
        Ok(ControlGuard { region: self })
    }

    fn claim(&self, pages: usize) -> io::Result<usize> {
        if pages == 0 || pages > DATA_END - DATA_FIRST {
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }
        let mut guard = self.lock()?;
        let bitmap = guard.bitmap();
        let mut start = DATA_FIRST;
        let mut length = 0;
        for page in DATA_FIRST..DATA_END {
            if bitmap[page / 64] & (1 << (page % 64)) == 0 {
                length += 1;
                if length == pages {
                    for owned in start..start + pages {
                        bitmap[owned / 64] |= 1 << (owned % 64);
                    }
                    return Ok(start);
                }
            } else {
                start = page + 1;
                length = 0;
            }
        }
        Err(io::Error::from_raw_os_error(libc::ENOMEM))
    }

    /// Claim two boundary guards and a page-rounded writable interior.
    /// Allocation happens only during ordinary initialization, never on a
    /// signal or callback path. No allocation lock spans a VM syscall.
    pub(crate) fn stack(&'static self, usable: usize) -> io::Result<StackLease> {
        let usable = usable
            .checked_add(PAGE - 1)
            .map(|value| value & !(PAGE - 1))
            .filter(|&value| value != 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let pages = (usable / PAGE)
            .checked_add(2)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOMEM))?;
        let start = self.claim(pages)?;
        let lease = StackLease {
            region: self,
            start,
            pages,
        };
        // The claimed full extent is still PROT_NONE, either virgin or reset
        // by a successful unpublished drop. Its two guards remain untouched.
        raw_zero_result(unsafe {
            raw_syscall6(
                libc::SYS_mprotect,
                [
                    lease.base() as u64,
                    usable as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    0,
                    0,
                    0,
                ],
            )
        })?;
        Ok(lease)
    }

    fn release(&self, start: usize, pages: usize) {
        // Called only for an unpublished, uniquely owned lease. Keep every
        // page occupied throughout rollback, including any failed syscall.
        let base = BASE + start * PAGE;
        let bytes = pages * PAGE;
        let protected = unsafe {
            raw_syscall6(
                libc::SYS_mprotect,
                [base as u64, bytes as u64, libc::PROT_NONE as u64, 0, 0, 0],
            )
        };
        if protected != 0 {
            return; // Quarantined, never falsely reclaimed.
        }
        let discarded = unsafe {
            raw_syscall6(
                libc::SYS_madvise,
                [
                    (base + PAGE) as u64,
                    (bytes - 2 * PAGE) as u64,
                    libc::MADV_DONTNEED as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        if discarded != 0 {
            return; // Permissions are safe, but old contents are not reusable.
        }
        let Ok(mut guard) = self.lock() else {
            return; // Bounded unexpected contention also retains ownership.
        };
        let bitmap = guard.bitmap();
        for page in start..start + pages {
            bitmap[page / 64] &= !(1 << (page % 64));
        }
    }
}

struct InitializationGuard;

impl InitializationGuard {
    fn acquire() -> io::Result<Self> {
        INITIALIZING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
        Ok(Self)
    }
}

impl Drop for InitializationGuard {
    fn drop(&mut self) {
        INITIALIZING.store(false, Ordering::Release);
    }
}

#[path = "tool_region_constructor.rs"]
mod constructor;
pub use constructor::ConstructorStack;
#[cfg(feature = "allocator-fixture")]
pub use constructor::ConstructorStackRecord;
pub use constructor::constructor_entry;
pub use constructor::constructor_stack;
#[doc(hidden)]
pub use constructor::generic_entry;
#[cfg(feature = "allocator-fixture")]
pub use constructor::reverie_inguest_constructor_stack_query;
#[cfg(feature = "allocator-fixture")]
pub use constructor::reverie_inguest_generic_stack_query;

fn validate_reservation(mapping: usize) -> Result<(), i32> {
    if mapping == BASE {
        return Ok(());
    }
    // Older kernels may ignore NOREPLACE. Release only the mapping they
    // actually returned, never the requested occupied address.
    unsafe { raw_syscall6(libc::SYS_munmap, [mapping as u64, BYTES as u64, 0, 0, 0, 0]) };
    Err(libc::EOPNOTSUPP)
}

struct ControlGuard<'a> {
    region: &'a ToolRegion,
}

impl ControlGuard<'_> {
    fn bitmap(&mut self) -> &mut [u64; BITMAP_WORDS] {
        // SAFETY: this guard exclusively owns the control lock, and the
        // anonymous zero-filled mapping contains valid u64 values throughout.
        unsafe { &mut *(*self.region.control).occupied.get() }
    }
}

impl Drop for ControlGuard<'_> {
    fn drop(&mut self) {
        unsafe { &(*self.region.control).held }.store(false, Ordering::Release);
    }
}

/// An unpublished lease. Publication must retain this value for the complete
/// lifetime of any registered stack, including after a later setup failure.
#[derive(Debug)]
pub(crate) struct StackLease {
    region: &'static ToolRegion,
    start: usize,
    pages: usize,
}

impl StackLease {
    pub(crate) fn belongs_to(&self, region: &ToolRegion) -> bool {
        core::ptr::eq(self.region, region)
    }

    pub(crate) fn base(&self) -> usize {
        BASE + (self.start + 1) * PAGE
    }

    pub(crate) fn usable_bytes(&self) -> usize {
        (self.pages - 2) * PAGE
    }

    pub(crate) fn top(&self) -> usize {
        self.base() + self.usable_bytes()
    }
}

impl Drop for StackLease {
    fn drop(&mut self) {
        self.region.release(self.start, self.pages);
    }
}

#[cfg(test)]
#[path = "tool_region_tests.rs"]
mod tests;
