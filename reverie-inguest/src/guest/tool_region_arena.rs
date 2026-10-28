/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Fixed byte spans and scalar metadata, initialized only by a fresh owner.
//! Payloads remain on key zero; guards do not protect interiors from the guest.

use core::mem::offset_of;

use super::super::alloc::ToolHeapMetadata;
use super::super::alloc::ToolHeapSpan;
use super::*;

pub(super) const ARENA_BYTES: usize = 32 * 1024 * 1024;
pub(super) const TOOL_BOTTOM: usize = BASE + 0x1000_0000;
pub(super) const PATCH_BOTTOM: usize = BASE + 0x1400_0000;
pub(super) const METADATA_ADDRESS: usize = BASE + 0x23000;
pub(super) const TOOL_BAND: (usize, usize) = (
    (TOOL_BOTTOM - BASE) / PAGE - 1,
    (TOOL_BOTTOM + ARENA_BYTES - BASE) / PAGE + 1,
);
pub(super) const PATCH_BAND: (usize, usize) = (
    (PATCH_BOTTOM - BASE) / PAGE - 1,
    (PATCH_BOTTOM + ARENA_BYTES - BASE) / PAGE + 1,
);

/// Permanent page envelope for both loader/runtime windows and their two
/// exterior guards. This excludes claims; it neither maps images nor adopts
/// a loader-owned region. The adjacent windows have no separate inner guard.
/// Test-only checks bind these literal bounds to reverie-loader's layout.
pub(super) const IMAGE_BAND: (usize, usize) = (917503, 1044481);

#[repr(C)]
struct FixedArenaMetadata {
    tool: ToolHeapMetadata,
    patch_cursor: AtomicUsize,
}

const _: () = {
    assert!(ARENA_BYTES == super::super::alloc::TOOL_HEAP_BYTES);
    assert!(METADATA_ADDRESS.is_multiple_of(PAGE));
    assert!(size_of::<ToolHeapMetadata>() == 24 && align_of::<ToolHeapMetadata>() == 8);
    assert!(offset_of!(ToolHeapMetadata, next) == 0);
    assert!(offset_of!(ToolHeapMetadata, free_head) == 8);
    assert!(offset_of!(ToolHeapMetadata, locked) == 16);
    assert!(size_of::<AtomicBool>() == 1);
    assert!(size_of::<AtomicUsize>() == 8);
    assert!(size_of::<UnsafeCell<usize>>() == 8);
    assert!(offset_of!(Control, occupied) == 8);
    assert!(TOOL_BAND.0 < TOOL_BAND.1 && PATCH_BAND.0 < PATCH_BAND.1);
    assert!(IMAGE_BAND.1 <= BITMAP_WORDS * 64);
    assert!(IMAGE_BAND.1 <= i32::MAX as usize);
    assert!(size_of::<FixedArenaMetadata>() == 32 && align_of::<FixedArenaMetadata>() == 8);
    assert!(size_of::<FixedArenaMetadata>() <= PAGE);
    assert!(METADATA_ADDRESS >= BASE + PAGE + size_of::<Control>());
    assert!(METADATA_ADDRESS + PAGE <= BASE + CONTROL_BYTES);
    assert!(TOOL_BOTTOM.is_multiple_of(PAGE) && PATCH_BOTTOM.is_multiple_of(PAGE));
    assert!(TOOL_BAND.0 == 65535 && TOOL_BAND.1 == 73729);
    assert!(PATCH_BAND.0 == 81919 && PATCH_BAND.1 == 90113);
    assert!(TOOL_BAND.0 >= DATA_FIRST && TOOL_BAND.1 <= PATCH_BAND.0);
    assert!(PATCH_BAND.1 <= DATA_END);
    assert!(IMAGE_BAND.0 < IMAGE_BAND.1 && IMAGE_BAND.1 <= DATA_END);
    assert!(PATCH_BAND.1 <= IMAGE_BAND.0);
    assert!(constructor::STACK_EXTENT_END <= BASE + IMAGE_BAND.0 * PAGE);
    assert!((BASE + IMAGE_BAND.0 * PAGE).is_multiple_of(PAGE));
    assert!((BASE + IMAGE_BAND.1 * PAGE).is_multiple_of(PAGE));
    assert!(BASE + IMAGE_BAND.0 * PAGE == 0x6000_dfff_f000);
    assert!(BASE + IMAGE_BAND.1 * PAGE == 0x6000_ff00_1000);
    assert!(offset_of!(FixedArenaMetadata, tool) == 0);
    assert!(offset_of!(FixedArenaMetadata, patch_cursor) == 24);
    assert!(size_of::<FixedArenaBacking>() == 40 && align_of::<FixedArenaBacking>() == 8);
    assert!(offset_of!(FixedArenaBacking, tool_bottom) == 0);
    assert!(offset_of!(FixedArenaBacking, tool_top) == 8);
    assert!(offset_of!(FixedArenaBacking, patch_bottom) == 16);
    assert!(offset_of!(FixedArenaBacking, patch_top) == 24);
    assert!(offset_of!(FixedArenaBacking, patch_cursor) == 32);
};

/// Ready, exact byte spans and the actual patch allocator cursor.
///
/// This hidden integration API never reserves, allocates, reads a descriptor
/// or supplies Legacy spans. It is available only after completed publication.
#[doc(hidden)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FixedArenaBacking {
    pub tool_bottom: usize,
    pub tool_top: usize,
    pub patch_bottom: usize,
    pub patch_top: usize,
    /// Actual cursor address. Dereferencing it requires the integration caller
    /// to preserve the allocator's monotonic reservation invariant; safe users
    /// cannot reset the live allocator through this observation API.
    pub patch_cursor: *const AtomicUsize,
}

// SAFETY: this immutable descriptor contains only bounds and a raw address.
// It neither mutates nor dereferences the cursor. Safe readers cannot turn it
// into mutable access, and publication is checked before exposing the record.
unsafe impl Sync for FixedArenaBacking {}

static FIXED_BACKING: FixedArenaBacking = FixedArenaBacking {
    tool_bottom: TOOL_BOTTOM,
    tool_top: TOOL_BOTTOM + ARENA_BYTES,
    patch_bottom: PATCH_BOTTOM,
    patch_top: PATCH_BOTTOM + ARENA_BYTES,
    patch_cursor: (METADATA_ADDRESS + offset_of!(FixedArenaMetadata, patch_cursor))
        as *const AtomicUsize,
};

/// Actual scalar cells used by the Fixed allocator algorithms.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct FixedArenaMetadataAddresses {
    pub tool_cursor: usize,
    pub tool_free_head: usize,
    pub tool_lock: usize,
    pub patch_cursor: usize,
}

/// Inspect or mark one statically bounded band of the fresh owner's bitmap.
///
/// The only callers below supply TOOL_BAND, PATCH_BAND or IMAGE_BAND. Their
/// compile-time bounds keep every scalar access inside Control. Iterating over
/// aggregate descriptors can copy through libc in native preparation, before the
/// Tool is ready; keep this path scalar in every supported build profile.
/// Its explicit C ABI is consumed by the source-owned setup assembly: mark is
/// exactly 0/1 in CL and the boolean result is read only from AL. C ABI also
/// forbids an unwind across that assembly boundary.
#[inline(never)]
unsafe extern "C" fn fixed_bitmap_range(
    control: *mut Control,
    start: usize,
    end: usize,
    mark: bool,
) -> bool {
    // SAFETY: the fresh unpublished owner exclusively owns Control; all three
    // statically checked bands contain only valid bitmap indices.
    let bitmap = unsafe { (*control).occupied.get().cast::<u64>() };
    let mut page = start;
    while page < end {
        // SAFETY: page is in one of the statically bounded bands above.
        let cell = unsafe { bitmap.add(page / 64) };
        let mask = 1_u64.wrapping_shl((page % 64) as u32);
        // SAFETY: no reader or other writer can observe unpublished ownership.
        let value = unsafe { cell.read() };
        if mark {
            // SAFETY: this scalar cell belongs to the same exclusive owner.
            unsafe { cell.write(value | mask) };
        } else if value & mask != 0 {
            return false;
        }
        // end is strictly below the address-space page count, so this bounded
        // increment cannot wrap; avoid an unused panic path during preparation.
        page = page.wrapping_add(1);
    }
    true
}

/// Complete three permanent extents using authenticated fresh ownership only.
///
/// The caller owns an exact fresh reservation with writable pristine Control,
/// acquired by ordinary/native no-replace reservation or by the unsafe trusted
/// mapped-image adoption boundary. Production publication is serialized by
/// INITIALIZING. No live
/// allocators or general leases occupy any of the three bands. Native callers
/// have already authenticated their
/// origin, record, owned stack and complete bootstrap occupancy. This function
/// neither publishes nor cleans up its caller's mapping/live native stack.
/// Preflight all bands before changing protections, metadata or bitmap cells.
/// Ordinary/native fresh owners retain initial PROT_NONE in the image envelope.
/// An authenticated mapped-image owner may already have exact qualified images
/// there: this function never changes any image or guard protection. Initializing
/// permanent occupancy is not itself mapping ownership or runtime readiness.
#[inline(always)]
pub(super) unsafe fn initialize_fixed_arenas(control: *mut Control) -> Result<(), i32> {
    // SAFETY: the caller supplies the fresh, exclusively owned control area.
    // A scalar status crosses the separately qualified boundary; Rust Result's
    // discriminant representation must not become its calling convention.
    let status = unsafe { initialize_fixed_arenas_opaque(black_box(control.cast())) };
    if status == 0 { Ok(()) } else { Err(status) }
}

// The assembly entry calls only explicit C-ABI helpers. This bridge preserves
// raw_syscall3's selected legacy/fixed-gate mechanism; it does not create a new
// gate, call libc, or use a Rust calling convention from assembly.
#[inline(never)]
unsafe extern "C" fn fixed_arena_mprotect(address: usize) -> i64 {
    // SAFETY: the setup entry supplies one exact fresh owned payload interior.
    unsafe {
        crate::trap::raw_syscall3(
            libc::SYS_mprotect,
            address as u64,
            ARENA_BYTES as u64,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
        )
    }
}

/// Complete the fresh owner's arenas through one source-owned scalar entry.
///
/// # Safety
/// Same fresh, exclusive Control/reservation contract as initialize_fixed_arenas.
/// The caller supplies SysV x86-64 state with DF clear. Every callee uses an
/// explicit C ABI and cannot unwind into this naked frame. Zero means all
/// protections, metadata and permanent occupancy are complete; any nonzero
/// status retains the caller's ownership and any completed protection change.
/// This entry never publishes, releases INITIALIZING, or unmaps anything.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn initialize_fixed_arenas_opaque(_control: *mut c_void) -> i32 {
    // SAFETY: RBX alone retains Control across calls. Saving it aligns RSP to
    // 16 before every CALL and it is restored on every return; other callee-saved
    // registers are untouched. The three preflight calls precede every write.
    // Both raw results are checked as signed 64-bit values before metadata is
    // initialized. NEG EAX is the exact low 32-bit wrapping negation of the
    // kernel error, matching the former wrapping_neg() as i32 conversion.
    // The metadata stores preserve the former initializer's field order and do
    // not write padding. All occupancy calls mark the same preflighted bands.
    core::arch::naked_asm!(
        "push rbx",
        "mov rbx, rdi",
        // Read-only preflight; stop on the first occupied band.
        "mov esi, {tool_first}",
        "mov edx, {tool_end}",
        "xor ecx, ecx",
        "call {bitmap}",
        "test al, al",
        "jz 90f",
        "mov rdi, rbx",
        "mov esi, {patch_first}",
        "mov edx, {patch_end}",
        "xor ecx, ecx",
        "call {bitmap}",
        "test al, al",
        "jz 90f",
        "mov rdi, rbx",
        "mov esi, {image_first}",
        "mov edx, {image_end}",
        "xor ecx, ecx",
        "call {bitmap}",
        "test al, al",
        "jz 90f",
        // Only the two payload interiors become RW; every guard and the
        // image envelope keep their original caller-owned protections.
        "movabs rdi, {tool_bottom}",
        "call {mprotect}",
        "test rax, rax",
        "js 91f",
        "movabs rdi, {patch_bottom}",
        "call {mprotect}",
        "test rax, rax",
        "js 91f",
        // Match the former ToolHeapMetadata initializer, then patch_cursor. The
        // fresh aligned scalar fields are not visible before publication.
        "movabs rax, {metadata}",
        "mov qword ptr [rax + {next}], 0",
        "mov qword ptr [rax + {free_head}], 0",
        "mov byte ptr [rax + {locked}], 0",
        "mov qword ptr [rax + {patch_cursor}], 0",
        // Marking returns true and cannot refuse under the same exclusive
        // fresh-owner contract. As before, no mark result changes the order.
        "mov rdi, rbx",
        "mov esi, {tool_first}",
        "mov edx, {tool_end}",
        "mov ecx, 1",
        "call {bitmap}",
        "mov rdi, rbx",
        "mov esi, {patch_first}",
        "mov edx, {patch_end}",
        "mov ecx, 1",
        "call {bitmap}",
        "mov rdi, rbx",
        "mov esi, {image_first}",
        "mov edx, {image_end}",
        "mov ecx, 1",
        "call {bitmap}",
        "xor eax, eax",
        "jmp 92f",
        "90:",
        "mov eax, {invalid}",
        "jmp 92f",
        "91:",
        "neg eax",
        "92:",
        "pop rbx",
        "ret",
        tool_first = const TOOL_BAND.0,
        tool_end = const TOOL_BAND.1,
        patch_first = const PATCH_BAND.0,
        patch_end = const PATCH_BAND.1,
        image_first = const IMAGE_BAND.0,
        image_end = const IMAGE_BAND.1,
        bitmap = sym fixed_bitmap_range,
        tool_bottom = const TOOL_BOTTOM,
        patch_bottom = const PATCH_BOTTOM,
        mprotect = sym fixed_arena_mprotect,
        metadata = const METADATA_ADDRESS,
        next = const offset_of!(FixedArenaMetadata, tool) + offset_of!(ToolHeapMetadata, next),
        free_head = const offset_of!(FixedArenaMetadata, tool)
            + offset_of!(ToolHeapMetadata, free_head),
        locked = const offset_of!(FixedArenaMetadata, tool) + offset_of!(ToolHeapMetadata, locked),
        patch_cursor = const offset_of!(FixedArenaMetadata, patch_cursor),
        invalid = const libc::EINVAL,
    );
}

#[inline(always)]
fn published_metadata() -> Option<&'static FixedArenaMetadata> {
    // Do not expose REGION during the publication-to-READY interval or while
    // the ordinary initialization guard is still held. No guessed pointer is
    // dereferenced until a successful authentic owner is already published.
    if INITIALIZING.load(Ordering::Acquire) {
        return None;
    }
    let _owner = REGION.get()?.as_ref().ok()?;
    // SAFETY: all publication paths completed fresh arena setup first. The
    // mapping/metadata are process-lifetime and are never reset on plain fork.
    Some(unsafe { &*(METADATA_ADDRESS as *const FixedArenaMetadata) })
}

#[doc(hidden)]
#[inline(never)]
pub fn fixed_arena_backing() -> Option<&'static FixedArenaBacking> {
    let backing = published_metadata().map(|_| &FIXED_BACKING);
    // Keep the complete scalar pointer result opaque, including None. A
    // non-inlined getter alone need not hide its fixed successful return value.
    // No large aggregate copy or interposable memory helper is needed here.
    black_box(backing)
}

#[inline(never)]
extern "C" fn fixed_tool_heap_metadata() -> *const c_void {
    let metadata = match published_metadata() {
        Some(metadata) => core::ptr::from_ref(&metadata.tool).cast::<c_void>(),
        None => core::ptr::null(),
    };
    // Expose one scalar ABI, not a Rust Option<Span> whose fields may migrate
    // into callers during interprocedural optimization. Both returns are opaque.
    black_box(metadata)
}

#[inline(always)]
pub(crate) fn fixed_tool_heap() -> Option<ToolHeapSpan<'static>> {
    let metadata = fixed_tool_heap_metadata().cast::<ToolHeapMetadata>();
    // SAFETY: the scalar getter returns null or the actual metadata only after
    // completed arena setup and publication; that mapping lives until exit.
    let metadata = unsafe { metadata.as_ref() }?;
    Some(ToolHeapSpan {
        base: TOOL_BOTTOM as *mut u8,
        bytes: ARENA_BYTES,
        metadata,
    })
}

#[cfg(any(test, feature = "allocator-fixture"))]
pub(super) fn metadata_addresses() -> Option<FixedArenaMetadataAddresses> {
    let metadata = published_metadata()?;
    Some(FixedArenaMetadataAddresses {
        tool_cursor: metadata.tool.next.get() as usize,
        tool_free_head: metadata.tool.free_head.get() as usize,
        tool_lock: core::ptr::addr_of!(metadata.tool.locked) as usize,
        patch_cursor: core::ptr::addr_of!(metadata.patch_cursor) as usize,
    })
}

/// Addresses only: diagnostics do not choose backing or initialize ownership.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_fixed_arena_metadata() -> Option<FixedArenaMetadataAddresses> {
    metadata_addresses()
}
