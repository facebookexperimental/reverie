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
//! makes no all-entry, TLS or permission-isolation claim. Explicit Fixed
//! allocators share the fresh owner's guarded payloads and scalar metadata.
//!
//! Reservation and leasing are ordinary setup operations only. They must not
//! run from a signal handler, an interrupted initializer, or a live callback.
//! Published stacks retain their leases for process lifetime. Plain fork
//! inherits the mappings, occupied pages and live contents through COW.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;

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

type RegionResult = Result<ToolRegion, i32>;

struct RegionPublication {
    published: AtomicBool,
    value: UnsafeCell<MaybeUninit<RegionResult>>,
}

// SAFETY: all writes require exclusive INITIALIZING ownership; the value is
// fully initialized before release publication and never overwritten/reset.
// Readers obtain the immutable reference only after acquire publication.
// ToolRegion is already Send + Sync and remains alive for process lifetime.
unsafe impl Sync for RegionPublication {}

impl RegionPublication {
    const fn new() -> Self {
        Self {
            published: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[inline(never)]
    fn get(&self) -> Option<&RegionResult> {
        if !self.published.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the release publication precedes this acquire observation;
        // there is no writer after publication. The cast uses MaybeUninit<T>'s
        // documented layout equivalence, not guessed Rust enum offsets.
        Some(unsafe { &*self.value.get().cast::<RegionResult>() })
    }

    /// # Safety
    /// The caller must exclusively own INITIALIZING for this image, not merely
    /// observe that its byte is true. No second publication writer may run.
    /// The input must be the actual ordinary reserve result or authenticated
    /// fresh native owner. The slot and its owner must outlive all references.
    #[inline(never)]
    unsafe fn set_under_gate(&self, value: RegionResult) -> Result<(), RegionResult> {
        if self.published.load(Ordering::Acquire) {
            return Err(value);
        }
        // SAFETY: exclusive gate ownership and unpublished state prevent any
        // competing writer or reader of this storage. No existing value drops.
        unsafe { self.value.get().cast::<RegionResult>().write(value) };
        self.published.store(true, Ordering::Release);
        Ok(())
    }
}

// The publication locator is deliberately outside the fixed-region claim.
// A complete owner or retained reservation error is published exactly once.
static REGION: RegionPublication = RegionPublication::new();
// Every path which can initialize REGION first owns this nonwaiting gate.
// Readers never wait, and publication requires this gate's exclusive owner.
// A handler interrupting initialization gets EAGAIN rather than waiting on it.
static INITIALIZING: AtomicBool = AtomicBool::new(false);

/// Feature-only publication observation; never initialize or select backing.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_region_published() -> bool {
    REGION.get().is_some_and(Result::is_ok)
}

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
                // SAFETY: _initializing owns INITIALIZING through this call,
                // including reserve_inner; the second get found no publication.
                // Publish the actual complete reservation result under that gate.
                unsafe { REGION.set_under_gate(Self::reserve_inner()) }
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
        // REGION publishes this owner. Control/outer guards are excluded
        // from the allocator's searchable interval rather than marked free.
        unsafe { core::ptr::addr_of_mut!((*control).held).write(AtomicBool::new(false)) };
        // Fresh anonymous storage also provides valid zeroed atomic scalar
        // representations for registered_alternate. Native constructor setup
        // obtains the same fresh zeroed control before typed adoption.
        // Complete all permanent arena/guard occupancy before publication,
        // even for Legacy owners which keep using their separate BSS heaps.
        // SAFETY: this path owns a fresh exact mapping and unpublished Control.
        if let Err(errno) = unsafe { arena::initialize_fixed_arenas(control) } {
            unsafe { raw_syscall6(libc::SYS_munmap, [BASE as u64, BYTES as u64, 0, 0, 0, 0]) };
            return Err(errno);
        }
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

#[path = "tool_region_arena.rs"]
mod arena;
#[doc(hidden)]
pub use arena::FixedArenaBacking;
#[doc(hidden)]
pub use arena::FixedArenaMetadataAddresses;
#[doc(hidden)]
pub use arena::fixed_arena_backing;
pub(crate) use arena::fixed_tool_heap;
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub use arena::fixture_fixed_arena_metadata;

#[path = "tool_region_keyed.rs"]
mod keyed;
pub use keyed::KeyedLeaseError;
pub use keyed::KeyedLeaseStage;
pub use keyed::KeyedPrepareError;
pub use keyed::KeyedPrepareKind;
pub use keyed::KeyedQuarantine;
pub use keyed::KeyedRegionSpans;
pub use keyed::KeyedSpan;
pub use keyed::KeyedStack;
pub use keyed::KeyedStackLease;
pub use keyed::KeyedToolRegion;
pub use keyed::OwnedKeyDescriptor;

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

/// Observe an already published owner without reserving, waiting or accessing
/// its mutable control pages. An initialization error is not ownership. Plain
/// fork inherits both this immutable publication and the reservation.
pub(crate) fn published_owner() -> Option<&'static ToolRegion> {
    REGION.get()?.as_ref().ok()
}

// Separate feature-only actions; no layout or existing stack API changes.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
#[path = "tool_region_mapping_fixture.rs"]
pub mod mapping_fixture;

// First-image adoption is separate from ordinary fresh reservation. The unsafe
// entry contract supplies physical provenance; these scalar checks do not.
// Keep its callers out of the ordinary preload; adoption belongs to the
// explicit loader runtime. Tests retain the scalar geometry controls.
#[cfg(any(feature = "loader-private-runtime", test))]
mod mapped_image {
    use super::*;

    /// One complete retained bootstrap mapping extent, including one unmapped
    /// guard page at each end. Its interior's actual protection is role-specific.
    #[derive(Debug)]
    #[repr(C)]
    pub struct MappedImageExtent {
        /// Page-aligned first byte of the lower guard.
        pub start: usize,
        /// Page-aligned byte immediately after the upper guard.
        pub end: usize,
    }

    /// Immutable joins to the host's retained qualified files and physical birth.
    /// These values provide no authority without the unsafe entry contract.
    #[derive(Debug)]
    #[repr(C)]
    pub struct MappedImageBinding {
        /// Discriminator joined to the retained actual TraceeGeneration, not PID.
        pub launch: [u8; 32],
        /// SHA256 of the exact qualified sealed loader bytes actually mapped.
        pub loader: [u8; 32],
        /// SHA256 of the exact qualified sealed genuine runtime actually mapped.
        pub runtime: [u8; 32],
        /// Independently qualified compiled source/feature closure identity.
        pub sources: [u8; 32],
        /// Exact qualified bootstrap layout and registration contract identity.
        pub layout: [u8; 32],
    }

    /// Retained first-image layout from the trusted host mapping transaction.
    ///
    /// This is a Rust integration record, not a new cross-process wire ABI or a
    /// decoder for untrusted bytes. Every extent is in the fixed low free band
    /// before the tool arena; all five complete extents must be disjoint. They
    /// come from the qualified linked image/TLS layout, never Config or env.
    /// The two image windows retain the existing IMAGE_BAND exclusion instead.
    #[derive(Debug)]
    #[repr(C)]
    pub struct MappedImageLayout {
        /// Exact host/image/source/birth joins retained for the process lifetime.
        pub binding: MappedImageBinding,
        /// Guarded writable bootstrap stack on which adoption is executing.
        pub stack: MappedImageExtent,
        /// Guarded private TLS/TCB/libc backing containing the actual Tool FS.
        pub tls: MappedImageExtent,
        /// Guarded actual bootstrap signal-stack backing; not a runtime lease.
        pub signal_stack: MappedImageExtent,
        /// Guarded read-only storage containing this entire immutable record.
        pub handoff: MappedImageExtent,
        /// Guarded private mutable bootstrap/registration/continuation scratch.
        pub state: MappedImageExtent,
        /// Independently retained original leader TID for this physical birth.
        pub owner_tid: i32,
    }

    const _: () = {
        assert!(size_of::<usize>() == 8);
        assert!(size_of::<MappedImageExtent>() == 16);
        assert!(size_of::<MappedImageBinding>() == 160);
        assert!(size_of::<MappedImageLayout>() == 248);
        assert!(align_of::<MappedImageLayout>() == 8);
    };

    impl MappedImageLayout {
        fn role(&self, index: usize) -> &MappedImageExtent {
            match index {
                0 => &self.stack,
                1 => &self.tls,
                2 => &self.signal_stack,
                3 => &self.handoff,
                _ => &self.state,
            }
        }
    }

    // Private and affine. Only the unsafe physical-entry boundary below can
    // create this permit. Its existence is not inferred from any digest, address
    // match, nonce, maps observation or nonzero generation field.
    struct MappedImagePermit<'a> {
        layout: &'a MappedImageLayout,
    }

    fn interior_contains(extent: &MappedImageExtent, start: usize, bytes: usize) -> bool {
        start >= extent.start + PAGE
            && start
                .checked_add(bytes)
                .is_some_and(|end| end <= extent.end - PAGE)
    }

    fn validate_geometry(layout: &MappedImageLayout) -> Result<(), i32> {
        let first = BASE + DATA_FIRST * PAGE;
        let limit = BASE + arena::TOOL_BAND.0 * PAGE;
        let mut index = 0;
        while index < 5 {
            let extent = layout.role(index);
            if extent.start < first
                || extent.end > limit
                || !extent.start.is_multiple_of(PAGE)
                || !extent.end.is_multiple_of(PAGE)
                || extent
                    .start
                    .checked_add(3 * PAGE)
                    .is_none_or(|end| end > extent.end)
            {
                return Err(libc::EINVAL);
            }
            let mut earlier = 0;
            while earlier < index {
                let other = layout.role(earlier);
                if extent.start < other.end && other.start < extent.end {
                    return Err(libc::EINVAL);
                }
                earlier = earlier.wrapping_add(1);
            }
            index = index.wrapping_add(1);
        }
        Ok(())
    }

    pub(crate) fn validate_layout(layout: &MappedImageLayout, address: usize) -> Result<(), i32> {
        validate_geometry(layout)?;
        if !interior_contains(&layout.handoff, address, size_of::<MappedImageLayout>()) {
            return Err(libc::EINVAL);
        }
        Ok(())
    }

    #[cfg(all(
        feature = "loader-private-runtime",
        any(target_env = "musl", feature = "exec-stop")
    ))]
    pub(crate) fn scalar_free_band() -> reverie_loader::handoff::Extent {
        reverie_loader::handoff::Extent {
            start: (BASE + DATA_FIRST * PAGE) as u64,
            end: (BASE + arena::TOOL_BAND.0 * PAGE) as u64,
        }
    }

    /// Existing allocator's fresh metadata storage. The physical loader maps
    /// exactly this prefix RW inside its successful no-replace reservation;
    /// the first page and the gap before the free band remain inaccessible.
    #[cfg(all(feature = "loader-private-runtime", feature = "exec-stop"))]
    pub(crate) fn scalar_control_prefix() -> reverie_loader::handoff::Extent {
        reverie_loader::handoff::Extent {
            start: (BASE + PAGE) as u64,
            end: (arena::METADATA_ADDRESS + PAGE) as u64,
        }
    }

    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    pub(crate) fn validate_scalar_layout(
        view: reverie_loader::handoff::View<'_>,
    ) -> Result<(), i32> {
        view.validate_roles(scalar_free_band())
            .map_err(|_| libc::EINVAL)?;
        let source = view.bytes();
        if source.as_ptr() as u64 != view.address() {
            return Err(libc::EINVAL);
        }
        // Every role/digest/register/table remains in this immutable source;
        // validation never substitutes a pointer to a native projection.
        Ok(())
    }

    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    pub(crate) fn scalar_layout(
        view: reverie_loader::handoff::View<'_>,
    ) -> Result<MappedImageLayout, i32> {
        validate_scalar_layout(view)?;
        let role = |i| -> Result<MappedImageExtent, i32> {
            let value = view.role(i).map_err(|_| libc::EINVAL)?;
            Ok(MappedImageExtent {
                start: usize::try_from(value.start).map_err(|_| libc::EINVAL)?,
                end: usize::try_from(value.end).map_err(|_| libc::EINVAL)?,
            })
        };
        let digest = |i| -> Result<[u8; 32], i32> {
            let words = view.binding(i).map_err(|_| libc::EINVAL)?;
            let mut bytes = [0; 32];
            for (j, word) in words.into_iter().enumerate() {
                bytes[j * 8..j * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            Ok(bytes)
        };
        let layout = MappedImageLayout {
            binding: MappedImageBinding {
                launch: digest(0)?,
                loader: digest(1)?,
                runtime: digest(2)?,
                sources: digest(3)?,
                layout: digest(4)?,
            },
            stack: role(0)?,
            tls: role(1)?,
            signal_stack: role(2)?,
            handoff: role(3)?,
            state: role(4)?,
            owner_tid: i32::try_from(view.scalar(0).map_err(|_| libc::EINVAL)?)
                .map_err(|_| libc::EINVAL)?,
        };
        validate_geometry(&layout)?;
        Ok(layout)
    }

    pub(super) fn validate_context(
        layout: &MappedImageLayout,
        rsp: usize,
        fs: usize,
        tid: i64,
        pid: i64,
    ) -> Result<(), i32> {
        if tid <= 0
            || tid != pid
            || tid != i64::from(layout.owner_tid)
            || !interior_contains(&layout.stack, rsp, 1)
            || !interior_contains(&layout.tls, fs, 1)
        {
            return Err(libc::EINVAL);
        }
        Ok(())
    }

    // Byte reads are valid only under already established fresh anonymous
    // mapping provenance. Volatile scalar reads avoid hidden memcmp/TLS use;
    // this routine does not inspect uninitialized Rust object padding.
    pub(super) unsafe fn pristine(bytes: *const u8, length: usize) -> bool {
        let mut index = 0;
        while index < length {
            if unsafe { bytes.add(index).read_volatile() } != 0 {
                return false;
            }
            index = index.wrapping_add(1);
        }
        true
    }

    impl<'a> MappedImagePermit<'a> {
        /// # Safety
        /// The complete contract of adopt_mapped_image must already hold. The
        /// caller exclusively owns INITIALIZING and found REGION unpublished.
        unsafe fn from_trusted_entry(
            layout: &'a MappedImageLayout,
            source: &LayoutSource,
        ) -> Result<Self, i32> {
            match source {
                LayoutSource::Native(_) => {
                    validate_layout(layout, core::ptr::from_ref(layout) as usize)?
                }
                #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
                LayoutSource::Scalar(view) => {
                    // Validate the ACTUAL retained scalar source, not the address
                    // of this short-lived native value projection.
                    validate_scalar_layout(*view)?;
                    validate_geometry(layout)?;
                }
            }
            let rsp: usize;
            unsafe {
                core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags))
            };
            let mut fs = 0_usize;
            let fs_result = unsafe {
                raw_syscall6(
                    libc::SYS_arch_prctl,
                    [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
                )
            };
            if fs_result != 0 {
                return Err(libc::EINVAL);
            }
            let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
            let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
            validate_context(layout, rsp, fs, tid, pid)?;
            // Control, both unused native constructor records, and the fixed
            // arena metadata page must all be kernel-zeroed pristine storage.
            // No live handoff/stack/TLS data may be put in this prefix. Read it
            // before any typed Control/arena references or mutations exist.
            let prefix = BASE + PAGE;
            let length = arena::METADATA_ADDRESS + PAGE - prefix;
            if !unsafe { pristine(prefix as *const u8, length) } {
                return Err(libc::EINVAL);
            }
            Ok(Self { layout })
        }

        unsafe fn initialize(self) -> RegionResult {
            let control = (BASE + PAGE) as *mut Control;
            // SAFETY: complete raw-storage preflight proved fresh initialized
            // zero bytes, including the u64 bitmap, scalar extent tuple and
            // atomics. Initialize the scalar atomic objects in place; never wipe
            // an image, reset a bitmap or form a live lease with a releasing Drop.
            unsafe {
                core::ptr::addr_of_mut!((*control).held).write(AtomicBool::new(false));
                core::ptr::addr_of_mut!((*control).registered_alternate.base)
                    .write(AtomicUsize::new(0));
                core::ptr::addr_of_mut!((*control).registered_alternate.length)
                    .write(AtomicUsize::new(0));
                arena::initialize_fixed_arenas(control)?;
            }
            // Exactly the existing three permanent bands are initialized above.
            // Add the five actual retained bootstrap extents, guards included,
            // before the sole publication. All bounds/nonoverlap checks precede
            // any arena protection, cursor, bitmap or Control write.
            let bitmap = unsafe { (*control).occupied.get().cast::<u64>() };
            let mut role = 0;
            while role < 5 {
                let extent = self.layout.role(role);
                let mut page = (extent.start - BASE) / PAGE;
                let end = (extent.end - BASE) / PAGE;
                while page < end {
                    let cell = unsafe { bitmap.add(page / 64) };
                    let mask = 1_u64.wrapping_shl((page % 64) as u32);
                    unsafe { cell.write(cell.read() | mask) };
                    page = page.wrapping_add(1);
                }
                role = role.wrapping_add(1);
            }
            Ok(ToolRegion {
                control,
                bootstrap: None,
            })
        }
    }

    /// Adopt an already mapped genuine first image into the sole ToolRegion.
    ///
    /// This never calls reserve_inner, unmaps, decommits or wipes live storage.
    /// Additional structural checks do not establish physical mapping authority.
    /// Failure after acquiring an unpublished slot retains Err under the same
    /// gate; future ordinary reserve observes that error, rather than retrying.
    /// Existing publication or contention is refused without changing its owner.
    /// No Config/RPC admission, libc startup, installed Tool or readiness results.
    ///
    /// # Safety
    /// Invoke once, only from the independently qualified trusted private entry,
    /// before any guest instruction, allocator use, runtime callback or concurrent
    /// entry. Actual private stack/TLS/libc and the bounded raw syscall/terminal
    /// route must already work, with asynchronous entry excluded or owned.
    /// The original host must retain its actual stopped-birth TraceeGeneration,
    /// ChildOwner, original EntryContext, sealed qualified loader/runtime FDs,
    /// complete mapped-role/protection ledger and terminal kill/wait ownership.
    /// Its one-use transition is spent BEFORE entering this exact trusted symbol.
    /// Original EntryContext is physical provenance only: production handover
    /// must retain real Detcore policy writes (including AT_RANDOM) and must not
    /// invoke or relax the mechanics probe restore to erase those writes.
    /// That transaction must have obtained exact BASE..END via successful fresh
    /// MAP_FIXED_NOREPLACE, then replaced pages only inside its owned reservation.
    /// No scalar address, launch discriminator, seal, hash or maps resemblance
    /// alone discharges these obligations.
    ///
    /// The complete immutable layout and binding must match that independent
    /// qualified source/ELF/TLS/layout and physical birth. It must live read-only
    /// inside handoff for process lifetime. Five role extents describe ALL live
    /// bootstrap stack, private TLS/TCB/libc, bootstrap altstack, handoff and
    /// mutable state/registration/scratch storage outside the existing image
    /// windows. Their guards are actually PROT_NONE; interiors have their exact
    /// qualified protections and backing. No hidden external TLS/brk/stack or
    /// second physical map in an image hole is accepted. Image mappings preserve
    /// exact qualified PT_LOAD/BSS/gate protections in the fixed loader/runtime
    /// windows, with IMAGE_BAND exterior guards still PROT_NONE. The remaining
    /// reservation is untouched PROT_NONE except writable fresh zeroed allocator
    /// control through METADATA_ADDRESS+PAGE. No arena or native constructor has
    /// initialized; no references alias this fresh raw storage.
    ///
    /// On EVERY Err the caller must immediately enter its genuine nonallocating,
    /// nonunwinding owned terminal path and retain all mappings/FDs until actual
    /// host terminal wait; returning to Guest, retry, fallback, reset and rollback
    /// unmapping are forbidden. Panic/unwind/nonlocal escape is forbidden too.
    /// The host retains ownership on unconfirmed cancellation. A later real
    /// Config/RPC/Detcore installation and finish protocol remains mandatory.
    pub unsafe fn adopt_mapped_image(
        layout: &'static MappedImageLayout,
    ) -> Result<&'static ToolRegion, i32> {
        // SAFETY: unchanged native caller contract; identical common lifecycle.
        unsafe { adopt_inner(LayoutSource::Native(layout)) }
    }

    /// Adopt the same physically owned image from permanent scalar records.
    /// # Safety
    /// The complete adopt_mapped_image contract applies to the original scalar
    /// blob and its qualified byte/ELF/source/layout/generation/protection joins.
    /// Keep the host owner and actual immutable backing through process death;
    /// no decode success or numeric address substitutes for physical authority.
    /// Every error remains terminal; no reference to a projection may escape.
    // Scalar adapter has no separate gate, owner, bitmap or publication slot.
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    pub(crate) unsafe fn adopt_mapped_scalar(
        view: reverie_loader::handoff::View<'static>,
    ) -> Result<&'static ToolRegion, i32> {
        // SAFETY: same full adopt_mapped_image physical contract. Its native
        // projection is consumed under the common gate; no reference escapes.
        unsafe { adopt_inner(LayoutSource::Scalar(view)) }
    }

    enum LayoutSource {
        Native(&'static MappedImageLayout),
        #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
        Scalar(reverie_loader::handoff::View<'static>),
    }

    /// Produce the complete retained result without publishing or releasing the gate.
    ///
    /// # Safety
    /// The complete adopt_mapped_image physical contract holds for this source.
    /// The caller exclusively owns INITIALIZING and found REGION unpublished;
    /// it must retain and publish this Result under that same gate. No projected
    /// layout reference escapes: initialization returns an owned ToolRegion.
    unsafe fn initialize_under_owned_gate(source: &LayoutSource) -> RegionResult {
        #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
        let projection;
        let layout = match source {
            LayoutSource::Native(layout) => *layout,
            #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
            LayoutSource::Scalar(view) => {
                projection = scalar_layout(*view)?;
                &projection
            }
        };
        match unsafe { MappedImagePermit::from_trusted_entry(layout, source) } {
            Ok(permit) => unsafe { permit.initialize() },
            Err(errno) => Err(errno),
        }
    }

    unsafe fn adopt_inner(source: LayoutSource) -> Result<&'static ToolRegion, i32> {
        INITIALIZING
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| libc::EAGAIN)?;
        if REGION.get().is_some() {
            INITIALIZING.store(false, Ordering::Release);
            return Err(libc::EEXIST);
        }
        // SAFETY: the caller supplies the physical contract above; this exact
        // successful CAS owns the existing gate, not merely its observed byte.
        let result = unsafe { initialize_under_owned_gate(&source) };
        // Includes retained failures; no cleanup destructor exists on this path.
        // An impossible competing publication keeps the gate held until terminal
        // exit rather than resetting another writer or retrying initialization.
        if unsafe { REGION.set_under_gate(result) }.is_err() {
            return Err(libc::EAGAIN);
        }
        let published = match REGION.get() {
            Some(Ok(region)) => Ok(region),
            Some(Err(errno)) => Err(*errno),
            None => return Err(libc::EAGAIN),
        };
        INITIALIZING.store(false, Ordering::Release);
        published
    }
}

#[cfg(any(feature = "loader-private-runtime", test))]
pub use mapped_image::MappedImageBinding;
#[cfg(any(feature = "loader-private-runtime", test))]
pub use mapped_image::MappedImageExtent;
#[cfg(any(feature = "loader-private-runtime", test))]
pub use mapped_image::MappedImageLayout;
#[cfg(any(feature = "loader-private-runtime", test))]
pub use mapped_image::adopt_mapped_image;
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(crate) use mapped_image::adopt_mapped_scalar;
#[cfg(all(feature = "loader-private-runtime", feature = "exec-stop"))]
pub(crate) use mapped_image::scalar_control_prefix;
#[cfg(all(
    feature = "loader-private-runtime",
    any(target_env = "musl", feature = "exec-stop")
))]
pub(crate) use mapped_image::scalar_free_band;
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(crate) use mapped_image::scalar_layout;
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(crate) use mapped_image::validate_scalar_layout as validate_mapped_scalar_layout;

#[cfg(test)]
mod mapped_image_validation_tests {
    use super::mapped_image::*;
    use super::*;

    // Only validation inputs: this does not mint physical provenance, invoke
    // production adoption, or pretend these addresses were actually mapped.
    fn layout() -> MappedImageLayout {
        let first = BASE + DATA_FIRST * PAGE;
        let extent = |index: usize| MappedImageExtent {
            start: first + index * 4 * PAGE,
            end: first + (index + 1) * 4 * PAGE,
        };
        MappedImageLayout {
            binding: MappedImageBinding {
                launch: [0; 32],
                loader: [0; 32],
                runtime: [0; 32],
                sources: [0; 32],
                layout: [0; 32],
            },
            stack: extent(0),
            tls: extent(1),
            signal_stack: extent(2),
            handoff: extent(3),
            state: extent(4),
            owner_tid: 42,
        }
    }

    fn extent_mut(layout: &mut MappedImageLayout, role: usize) -> &mut MappedImageExtent {
        match role {
            0 => &mut layout.stack,
            1 => &mut layout.tls,
            2 => &mut layout.signal_stack,
            3 => &mut layout.handoff,
            _ => &mut layout.state,
        }
    }

    #[test]
    fn geometry_accepts_only_complete_disjoint_guarded_low_band_roles() {
        let value = layout();
        let address = value.handoff.start + PAGE;
        assert_eq!(
            super::mapped_image::validate_layout(&value, address),
            Ok(())
        );
        assert_eq!(
            super::mapped_image::validate_context(
                &value,
                value.stack.start + PAGE,
                value.tls.start + PAGE,
                42,
                42
            ),
            Ok(())
        );
        // Zero digest bytes are deliberately not authentication or a magic
        // ownership test. The unsafe physical caller contract is indispensable.
    }

    #[test]
    fn geometry_refuses_every_pair_overlap_including_guards() {
        for left in 0..5 {
            for right in left + 1..5 {
                let mut value = layout();
                let address = value.handoff.start + PAGE;
                let end = extent_mut(&mut value, left).end;
                let other = extent_mut(&mut value, right);
                other.start = end - PAGE;
                other.end = end + 3 * PAGE;
                assert_eq!(
                    super::mapped_image::validate_layout(&value, address),
                    Err(libc::EINVAL)
                );
            }
        }
    }

    #[test]
    fn geometry_refuses_each_role_overflow_alignment_and_fixed_band_escape() {
        for role in 0..5 {
            for (start, end) in [
                (BASE, BASE + 4 * PAGE),
                (BASE + DATA_FIRST * PAGE + 1, BASE + (DATA_FIRST + 5) * PAGE),
                (BASE + DATA_FIRST * PAGE, BASE + (DATA_FIRST + 4) * PAGE - 1),
                (usize::MAX - PAGE + 1, usize::MAX),
                (BASE + DATA_FIRST * PAGE, BASE + (DATA_FIRST + 2) * PAGE),
                (
                    BASE + arena::TOOL_BAND.0 * PAGE - 3 * PAGE,
                    BASE + arena::TOOL_BAND.0 * PAGE + PAGE,
                ),
                (
                    BASE + arena::IMAGE_BAND.0 * PAGE,
                    BASE + arena::IMAGE_BAND.1 * PAGE,
                ),
            ] {
                let mut value = layout();
                let address = value.handoff.start + PAGE;
                *extent_mut(&mut value, role) = MappedImageExtent { start, end };
                assert_eq!(
                    super::mapped_image::validate_layout(&value, address),
                    Err(libc::EINVAL)
                );
            }
        }
    }

    #[test]
    fn geometry_refuses_descriptor_in_guard_or_crossing_readonly_interior() {
        let value = layout();
        for address in [
            value.handoff.start,
            value.handoff.start + PAGE - 1,
            value.handoff.end - PAGE,
            value.handoff.end - PAGE - size_of::<MappedImageLayout>() + 1,
            usize::MAX,
        ] {
            assert_eq!(
                super::mapped_image::validate_layout(&value, address),
                Err(libc::EINVAL)
            );
        }
    }

    #[test]
    fn context_refuses_foreign_birth_or_outside_stack_and_tls() {
        let value = layout();
        let rsp = value.stack.start + PAGE;
        let fs = value.tls.start + PAGE;
        for (stack, tls, tid, pid) in [
            (rsp, fs, 0, 0),
            (rsp, fs, 42, 43),
            (rsp, fs, 43, 43),
            (value.stack.start, fs, 42, 42),
            (value.stack.end - PAGE, fs, 42, 42),
            (rsp, value.tls.start, 42, 42),
            (rsp, value.tls.end - PAGE, 42, 42),
        ] {
            assert_eq!(
                super::mapped_image::validate_context(&value, stack, tls, tid, pid),
                Err(libc::EINVAL)
            );
        }
    }

    #[test]
    fn pristine_checks_dirty_boundaries_without_changing_any_byte() {
        let length = arena::METADATA_ADDRESS + PAGE - (BASE + PAGE);
        let mut bytes = vec![0_u8; length];
        assert!(unsafe { super::mapped_image::pristine(bytes.as_ptr(), bytes.len()) });
        for index in [
            0,
            1,
            PAGE - 1,
            size_of::<Control>() - 1,
            constructor::RECORD_ADDRESS - (BASE + PAGE),
            constructor::GENERIC_RECORD_ADDRESS - (BASE + PAGE),
            arena::METADATA_ADDRESS - (BASE + PAGE),
            length - 1,
        ] {
            bytes[index] = 1;
            let before = bytes.clone();
            assert!(!unsafe { super::mapped_image::pristine(bytes.as_ptr(), bytes.len()) });
            assert_eq!(bytes, before);
            bytes[index] = 0;
        }
    }
}
