/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Per-thread Tool TLS slot layout: one record/TCB/altstack stride per
//! Tool thread plus a pool of preclaimed continuation stacks.
//!
//! B1 is geometry and publication only. Nothing here admits a thread:
//! the layout is claimed during private install finish (ordinary init,
//! never a callback path) only when thread admission was requested
//! before finish, and a failed claim degrades later births to `-EAGAIN`
//! without failing install. With no layout published, every B2 path
//! keeps today's leader record exactly.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;
use std::sync::OnceLock;

use super::NativeControl;
use super::tool_tls_registry::MAX_PRIVATE_TOOL_THREADS;
use crate::guest::tool_region::BASE;
use crate::guest::tool_region::PAGE;
use crate::guest::tool_region::PreclaimedStack;
use crate::guest::tool_region::ToolRegion;

/// Slots that can hold a born thread (slot 0 is the leader).
pub(crate) const NONLEADER_SLOTS: usize = MAX_PRIVATE_TOOL_THREADS - 1;

const RECORD_OFFSET: usize = PAGE;
const TSD_OFFSET: usize = 2 * PAGE;
const STACK_T_OFFSET: usize = 256;

/// One slot's FS-swap control record. The first five words deliberately
/// match `NativeControl` so the entry/leaf assembly can treat either
/// pointer identically for the phase/FS swap; the rest is slot-only.
#[repr(C)]
pub(crate) struct SlotRecord {
    magic: u64,
    slot_index: u64,
    /// Offset 16, as `NativeControl.phase`.
    pub(crate) phase: u64,
    /// Offset 24, as `NativeControl.guest_fs`. The only home of the
    /// guest FS a birth resumes with.
    pub(crate) guest_fs: u64,
    /// Offset 32, as `NativeControl.tool_fs`: this slot's Tool thread
    /// pointer (the FS base on x86_64, TPIDR_EL0 on aarch64).
    pub(crate) tool_fs: u64,
    pub(crate) tid: u64,
    pub(crate) kernel_mask: u64,
    pub(crate) guest_resume_mask: u64,
    pub(crate) guest_pkru: u64,
    pub(crate) kernel_tsc: u64,
    pub(crate) guest_tsc: u64,
    pub(crate) guest_clear_tid: u64,
    pub(crate) guest_robust_head: u64,
    pub(crate) guest_robust_len: u64,
    pub(crate) private_clear_tid: u64,
    pub(crate) private_robust_head: u64,
    pub(crate) private_robust_len: u64,
    pub(crate) relay_busy: AtomicU64,
    _reserved_to_stack_t: [u64; 14],
    /// Prebuilt `stack_t` (`ss_sp`, flags+pad, `ss_size`) the birth
    /// preamble passes to sigaltstack without touching its stack.
    pub(crate) altstack_ss: [u64; 3],
    _reserved: [u64; 477],
}

pub(crate) const SLOT_RECORD_MAGIC: u64 = 0x5454_4c53_5245_4331; // "TTLSREC1"

const _: () = {
    assert!(size_of::<SlotRecord>() == PAGE);
    assert!(core::mem::offset_of!(SlotRecord, phase) == 16);
    assert!(core::mem::offset_of!(SlotRecord, guest_fs) == 24);
    assert!(core::mem::offset_of!(SlotRecord, tool_fs) == 32);
    assert!(core::mem::offset_of!(SlotRecord, altstack_ss) == STACK_T_OFFSET);
    // The NativeControl words the shared assembly reads at the same
    // offsets (exec_private.rs asserts its own full layout).
    assert!(core::mem::offset_of!(NativeControl, phase) == 16);
    assert!(core::mem::offset_of!(NativeControl, guest_fs) == 24);
    assert!(core::mem::offset_of!(NativeControl, tool_fs) == 32);
};

/// Claim one slot record's relay-busy word (Stage C per-slot busy).
/// Returns false when this same slot's relay is already running;
/// distinct slots never exclude each other. Slot 0 keeps the relay's
/// own global busy word and never uses this.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn acquire_relay_busy(word: &AtomicU64) -> bool {
    word.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

/// Release a slot relay-busy word claimed by `acquire_relay_busy`.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn release_relay_busy(word: &AtomicU64) {
    word.store(0, Ordering::Release);
}

/// Numeric geometry of the published blocks. All offsets are byte
/// offsets within one slot stride.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotLayout {
    pub(crate) block_base: usize,
    pub(crate) stride_log2: u32,
    pub(crate) stride: usize,
    pub(crate) record_offset: usize,
    pub(crate) tsd_offset: usize,
    pub(crate) altstack_offset: usize,
    pub(crate) altstack_bytes: usize,
    pub(crate) backing_offset: usize,
    pub(crate) tp_offset: usize,
    pub(crate) callback_base: usize,
    pub(crate) callback_stride: usize,
    pub(crate) leader_altstacks: [(usize, usize); 2],
}

/// Where a stack pointer or thread pointer resolves. First
/// production readers are the B2 entry/leaf derivations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum RecordRef {
    Leader,
    Slot(usize),
    Terminal,
}

#[allow(dead_code)] // derivation readers land in B2/B3
impl SlotLayout {
    pub(crate) fn slot_base(&self, index: usize) -> usize {
        self.block_base + index * self.stride
    }

    pub(crate) fn record_addr(&self, index: usize) -> usize {
        self.slot_base(index) + self.record_offset
    }

    pub(crate) fn backing(&self, index: usize) -> usize {
        self.slot_base(index) + self.backing_offset
    }

    pub(crate) fn tool_fs_for_slot(&self, index: usize) -> usize {
        self.backing(index) + self.tp_offset
    }

    pub(crate) fn altstack_for_slot(&self, index: usize) -> (usize, usize) {
        let bottom = self.slot_base(index) + self.altstack_offset;
        (bottom, bottom + self.altstack_bytes)
    }

    pub(crate) fn callback_stack_for_slot(
        &self,
        region: &'static ToolRegion,
        index: usize,
        usable_bytes: usize,
    ) -> Option<PreclaimedStack> {
        if index == 0 || index >= MAX_PRIVATE_TOOL_THREADS {
            return None;
        }
        if usable_bytes > self.callback_stride - 2 * PAGE {
            return None;
        }
        let extent_start = self.callback_base + (index - 1) * self.callback_stride;
        region
            .preclaimed_stack(extent_start + PAGE, usable_bytes)
            .ok()
    }

    /// Resolve an interrupted stack pointer (signal-entry context).
    /// No fallback: with a layout published, only a slot altstack or a
    /// published leader altstack range maps anywhere.
    pub(crate) fn record_for_rsp(&self, sp: usize) -> RecordRef {
        if sp >= self.block_base {
            let delta = sp - self.block_base;
            let index = delta >> self.stride_log2;
            if index < MAX_PRIVATE_TOOL_THREADS && index != 0 {
                let within = delta & (self.stride - 1);
                if within >= self.altstack_offset
                    && within < self.altstack_offset + self.altstack_bytes
                {
                    return RecordRef::Slot(index);
                }
                return RecordRef::Terminal;
            }
            if index >= MAX_PRIVATE_TOOL_THREADS {
                // Fall through: an address past the block may still be a
                // leader altstack if a synthetic test placed it there.
            } else {
                return RecordRef::Terminal;
            }
        }
        for (low, high) in self.leader_altstacks {
            if low != 0 && sp >= low && sp < high {
                return RecordRef::Leader;
            }
        }
        RecordRef::Terminal
    }

    /// Resolve a thread pointer (call-leaf/ordinary context): the TP
    /// must be exactly a slot's expected TP, or the caller's leader
    /// comparison decides slot 0 before this is consulted.
    pub(crate) fn record_for_tp(&self, tp: usize) -> RecordRef {
        if tp < self.block_base {
            return RecordRef::Terminal;
        }
        let delta = tp - self.block_base;
        let index = delta >> self.stride_log2;
        if index == 0 || index >= MAX_PRIVATE_TOOL_THREADS {
            return RecordRef::Terminal;
        }
        if tp == self.tool_fs_for_slot(index) {
            RecordRef::Slot(index)
        } else {
            RecordRef::Terminal
        }
    }
}

/// Why a layout does not fit, by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayoutError {
    Overflow,
    BadTemplate,
    NoAlignedSpan,
}

impl LayoutError {
    pub(crate) fn name(self) -> &'static str {
        match self {
            LayoutError::Overflow => "slot layout arithmetic overflow",
            LayoutError::BadTemplate => "sealed TLS template unusable for slots",
            LayoutError::NoAlignedSpan => "no aligned free span fits the slot blocks",
        }
    }
}

/// Page positions the first-fit allocator will take for both blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClaimFit {
    pub(crate) slot_start_page: usize,
    pub(crate) slot_pages: usize,
    pub(crate) callback_start_page: usize,
    pub(crate) callback_pages: usize,
    pub(crate) stride: usize,
    pub(crate) stride_log2: u32,
    pub(crate) altstack_offset: usize,
    pub(crate) altstack_bytes: usize,
    pub(crate) backing_offset: usize,
    pub(crate) callback_stride: usize,
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// First aligned start at or after each free span's start with `pages`
/// contiguous free pages — the same selection `claim_at` then verifies.
/// The two claims are selected against one span snapshot, the second
/// excluding the first claim's pages.
fn select_aligned(
    spans: &[(usize, usize)],
    taken: &[(usize, usize)],
    pages: usize,
    align_pages: usize,
) -> Option<usize> {
    'spans: for &(start, len) in spans {
        let mut candidate = align_up(start, align_pages)?;
        while candidate + pages <= start + len {
            let clash = taken.iter().find(|&&(t_start, t_len)| {
                candidate < t_start + t_len && t_start < candidate + pages
            });
            match clash {
                None => return Some(candidate),
                Some(&(t_start, t_len)) => {
                    candidate = align_up(t_start + t_len, align_pages)?;
                    if candidate < start {
                        continue 'spans;
                    }
                }
            }
        }
    }
    None
}

/// Pure fit computation over a free-span snapshot (first-fit
/// aligned-span semantics of the allocator). No claiming happens here.
pub(crate) fn compute_layout(
    plan_total_bytes: usize,
    tls_align: usize,
    altstack_bytes: usize,
    callback_usable_bytes: usize,
    free_spans: &[(usize, usize)],
) -> Result<ClaimFit, LayoutError> {
    if plan_total_bytes == 0
        || tls_align == 0
        || tls_align > PAGE
        || !tls_align.is_power_of_two()
        || altstack_bytes == 0
        || callback_usable_bytes == 0
        || !callback_usable_bytes.is_multiple_of(PAGE)
    {
        return Err(LayoutError::BadTemplate);
    }
    let altstack_bytes = align_up(altstack_bytes, PAGE).ok_or(LayoutError::Overflow)?;
    let altstack_offset = 4 * PAGE;
    let backing_offset = altstack_offset
        .checked_add(altstack_bytes)
        .and_then(|v| v.checked_add(PAGE))
        .ok_or(LayoutError::Overflow)?;
    // Slot backings are page-aligned (stride-aligned base plus a
    // page-multiple offset), which dominates any tls_align <= PAGE:
    // the per-slot TP offset then depends only on total_bytes, exactly
    // as for a leader backing that is a multiple of tls_align (the
    // claim checks that separately).
    let stride_needed = backing_offset
        .checked_add(plan_total_bytes)
        .and_then(|v| v.checked_add(PAGE))
        .ok_or(LayoutError::Overflow)?;
    let stride = stride_needed
        .checked_next_power_of_two()
        .ok_or(LayoutError::Overflow)?
        .max(64 * 1024);
    let stride_log2 = stride.trailing_zeros();
    let slot_pages = (stride / PAGE)
        .checked_mul(MAX_PRIVATE_TOOL_THREADS)
        .ok_or(LayoutError::Overflow)?;
    let callback_stride = callback_usable_bytes + 2 * PAGE;
    let callback_pages = (callback_stride / PAGE)
        .checked_mul(NONLEADER_SLOTS)
        .ok_or(LayoutError::Overflow)?;
    let slot_start = select_aligned(free_spans, &[], slot_pages, stride / PAGE)
        .ok_or(LayoutError::NoAlignedSpan)?;
    let callback_start = select_aligned(free_spans, &[(slot_start, slot_pages)], callback_pages, 1)
        .ok_or(LayoutError::NoAlignedSpan)?;
    Ok(ClaimFit {
        slot_start_page: slot_start,
        slot_pages,
        callback_start_page: callback_start,
        callback_pages,
        stride,
        stride_log2,
        altstack_offset,
        altstack_bytes,
        backing_offset,
        callback_stride,
    })
}

// ---------------------------------------------------------------------------
// Admission request bit: the install-time PatchHost selector records
// its value here on every install (true or false), and the finish-time
// claim reads only this copy.
// ---------------------------------------------------------------------------

static ADMISSION_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Record (or clear) a test-only private thread admission request.
// The only production caller (tool_install) is compiled only
// with coordinator-rpc and rcb-clock, and calls this only with
// test-thread-admission and exec-private-init: declare the writer
// under exactly that caller cfg, plus tests.
#[cfg(any(
    test,
    all(
        feature = "test-thread-admission",
        feature = "exec-private-init",
        feature = "rcb-clock",
        feature = "coordinator-rpc"
    )
))]
pub(crate) fn note_thread_admission_requested(requested: bool) {
    ADMISSION_REQUESTED.store(requested, Ordering::Release);
}

pub(crate) fn thread_admission_requested() -> bool {
    ADMISSION_REQUESTED.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Publication state. The no-mangle words are the assembly's view (B2);
// SLOT_BASE is stored last with Release and read first with Acquire.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
static reverie_inguest_private_slot_stride_log2: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_record_offset: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_altstack_offset: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_altstack_bytes: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_leader_alt0: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_leader_alt1: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_leader_alt2: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_leader_alt3: AtomicUsize = AtomicUsize::new(0);
#[unsafe(no_mangle)]
static reverie_inguest_private_slot_base: AtomicUsize = AtomicUsize::new(0);
core::arch::global_asm!(
    ".hidden reverie_inguest_private_slot_stride_log2\n.hidden reverie_inguest_private_slot_record_offset\n.hidden reverie_inguest_private_slot_altstack_offset\n.hidden reverie_inguest_private_slot_altstack_bytes\n.hidden reverie_inguest_private_slot_leader_alt0\n.hidden reverie_inguest_private_slot_leader_alt1\n.hidden reverie_inguest_private_slot_leader_alt2\n.hidden reverie_inguest_private_slot_leader_alt3\n.hidden reverie_inguest_private_slot_base"
);

static SLOT_LAYOUT: OnceLock<SlotLayout> = OnceLock::new();
static EVER_CLAIMED_NONLEADER: AtomicBool = AtomicBool::new(false);

const STATUS_NOT_ATTEMPTED: u8 = 0;
const STATUS_READY: u8 = 1;
const STATUS_CLAIM_FAILED: u8 = 2;
static SLOT_STATUS: AtomicU8 = AtomicU8::new(STATUS_NOT_ATTEMPTED);
static SLOT_FAILURE_REASON: OnceLock<ClaimFailure> = OnceLock::new();

/// A named finish-time claim failure with the errno that caused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClaimFailure {
    pub(crate) reason: &'static str,
    pub(crate) errno: i32,
}

impl ClaimFailure {
    fn new(reason: &'static str, errno: i32) -> Self {
        Self { reason, errno }
    }
    fn io(reason: &'static str, error: &io::Error) -> Self {
        Self::new(reason, error.raw_os_error().unwrap_or(libc::EIO))
    }
}

impl From<LayoutError> for ClaimFailure {
    fn from(error: LayoutError) -> Self {
        let errno = match error {
            LayoutError::Overflow => libc::EOVERFLOW,
            LayoutError::BadTemplate => libc::EINVAL,
            LayoutError::NoAlignedSpan => libc::ENOMEM,
        };
        Self::new(error.name(), errno)
    }
}

/// The published layout, if one was claimed at finish. The base word
/// the assembly reads is the single source of truth for "published":
/// until it is stored (last, Release), this returns None even though
/// the OnceLock above was just populated.
pub(crate) fn layout() -> Option<SlotLayout> {
    if reverie_inguest_private_slot_base.load(Ordering::Acquire) == 0 {
        return None;
    }
    SLOT_LAYOUT.get().copied()
}

/// True once a birth has ever claimed a non-leader slot (B3 sets it).
#[allow(dead_code)]
pub(crate) fn ever_claimed_nonleader() -> bool {
    EVER_CLAIMED_NONLEADER.load(Ordering::Acquire)
}

/// B3: record that a non-leader slot was claimed at least once.
#[allow(dead_code)]
pub(crate) fn note_nonleader_claimed() {
    EVER_CLAIMED_NONLEADER.store(true, Ordering::Release);
}

fn fail_claim(failure: ClaimFailure) {
    let _ = SLOT_FAILURE_REASON.set(failure);
    SLOT_STATUS.store(STATUS_CLAIM_FAILED, Ordering::Release);
    // Allocation-free diagnostic on the in-guest stage stream (which
    // itself is a no-op unless enabled); never eprintln from finish.
    let mut line = crate::guest::support::StackLine::new();
    line.push_bytes(b"tool-tls-claim-failed reason=");
    line.push_bytes(failure.reason.as_bytes());
    line.push_bytes(b" errno=");
    line.push_signed(i64::from(failure.errno));
    crate::guest::support::emit_in_guest_stage(line.as_bytes());
}

/// Named reason a finish-time claim degraded births, if it did.
#[allow(dead_code)]
pub(crate) fn claim_failure_reason() -> Option<ClaimFailure> {
    SLOT_FAILURE_REASON.get().copied()
}

/// Test-only view of the claim status word.
#[cfg(test)]
pub(crate) fn claim_status_for_test() -> &'static str {
    match SLOT_STATUS.load(Ordering::Acquire) {
        STATUS_READY => "ready",
        STATUS_CLAIM_FAILED => "claim-failed",
        _ => "not-attempted",
    }
}

/// Test-only view of the published assembly base word.
#[cfg(test)]
pub(crate) fn published_slot_base_for_test() -> usize {
    reverie_inguest_private_slot_base.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Build-input capture + finish-time claim.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct GeometryInputs {
    plan_total_bytes: usize,
    tls_align: usize,
    tp_offset: usize,
    leader_backing_start: usize,
    mapped_signal_stack_usable: usize,
}

// Plain atomics in the relay's own INSTALLED style: the capture runs
// pre-libc, where no OnceLock (futex/panic paths) may execute.
static GEOMETRY_PLAN_TOTAL: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_TLS_ALIGN: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_TP_OFFSET: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_LEADER_BACKING: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_SIGNAL_STACK: AtomicUsize = AtomicUsize::new(0);
static GEOMETRY_PRESENT: AtomicBool = AtomicBool::new(false);

fn geometry_inputs() -> Option<GeometryInputs> {
    if !GEOMETRY_PRESENT.load(Ordering::Acquire) {
        return None;
    }
    Some(GeometryInputs {
        plan_total_bytes: GEOMETRY_PLAN_TOTAL.load(Ordering::Relaxed),
        tls_align: GEOMETRY_TLS_ALIGN.load(Ordering::Relaxed),
        tp_offset: GEOMETRY_TP_OFFSET.load(Ordering::Relaxed),
        leader_backing_start: GEOMETRY_LEADER_BACKING.load(Ordering::Relaxed),
        mapped_signal_stack_usable: GEOMETRY_SIGNAL_STACK.load(Ordering::Relaxed),
    })
}

/// Capture the authenticated leader geometry the finish-time claim
/// needs. Called once by the mapped musl relay install, which has
/// already recomputed and checked the leader plan.
#[allow(dead_code)] // caller is musl-only (mapped relay install)
pub(crate) fn capture_geometry_inputs(
    plan_total_bytes: usize,
    tls_align: usize,
    tp_offset: usize,
    leader_backing_start: usize,
    mapped_signal_stack_usable: usize,
) {
    GEOMETRY_PLAN_TOTAL.store(plan_total_bytes, Ordering::Relaxed);
    GEOMETRY_TLS_ALIGN.store(tls_align, Ordering::Relaxed);
    GEOMETRY_TP_OFFSET.store(tp_offset, Ordering::Relaxed);
    GEOMETRY_LEADER_BACKING.store(leader_backing_start, Ordering::Relaxed);
    GEOMETRY_SIGNAL_STACK.store(mapped_signal_stack_usable, Ordering::Relaxed);
    GEOMETRY_PRESENT.store(true, Ordering::Release);
}

/// Claim and publish the slot layout at private finish, if admission
/// was requested. Never fails the finish: every failure records a
/// named ClaimFailed status and leaves the leader untouched.
pub(crate) fn claim_and_publish_if_requested(
    region: &'static ToolRegion,
    control: *const NativeControl,
) {
    if !thread_admission_requested() || SLOT_LAYOUT.get().is_some() {
        return;
    }
    let Some(inputs) = geometry_inputs() else {
        return; // No musl geometry: births refuse by name (no layout).
    };
    if let Err(reason) = claim_inner(region, control, inputs) {
        fail_claim(reason);
    }
}

fn claim_inner(
    region: &'static ToolRegion,
    control: *const NativeControl,
    inputs: GeometryInputs,
) -> Result<(), ClaimFailure> {
    let callback_bytes = crate::guest::continuation::CALLBACK_STACK_BYTES;
    let altstack_floor = libc::SIGSTKSZ.max(64 * 1024);
    let altstack_bytes = altstack_floor.max(inputs.mapped_signal_stack_usable);
    let spans = region
        .free_spans()
        .map_err(|error| ClaimFailure::io("tool region span snapshot failed", &error))?;
    let fit = compute_layout(
        inputs.plan_total_bytes,
        inputs.tls_align,
        altstack_bytes,
        callback_bytes,
        &spans,
    )
    .map_err(ClaimFailure::from)?;
    if inputs.tls_align != 0 && !inputs.leader_backing_start.is_multiple_of(inputs.tls_align) {
        return Err(ClaimFailure::new(
            "leader backing is not a multiple of tls_align",
            libc::EINVAL,
        ));
    }
    let slot_base = BASE + fit.slot_start_page * PAGE;
    let callback_base = BASE + fit.callback_start_page * PAGE;
    // RW interiors per slot: record page, tsd page, altstack, backing.
    let mut writable = Vec::with_capacity(MAX_PRIVATE_TOOL_THREADS * 4);
    for index in 1..MAX_PRIVATE_TOOL_THREADS {
        let base = slot_base + index * fit.stride;
        writable.push((base + RECORD_OFFSET, PAGE));
        writable.push((base + TSD_OFFSET, PAGE));
        writable.push((base + fit.altstack_offset, fit.altstack_bytes));
        writable.push((base + fit.backing_offset, inputs.plan_total_bytes));
    }
    let lease = region
        .slot_blocks(
            fit.slot_start_page,
            fit.slot_pages,
            fit.callback_start_page,
            fit.callback_pages,
            &writable,
        )
        .map_err(|error| ClaimFailure::io("tool region slot claim failed", &error))?;
    // SAFETY: finish validated this control and it stays published for
    // the process lifetime; only its two sealed stack scalars are read.
    let (bootstrap_low, bootstrap_high) = unsafe {
        (
            (&raw const (*control).bootstrap_stack_base).read_volatile() as usize,
            (&raw const (*control).bootstrap_stack_end).read_volatile() as usize,
        )
    };
    let final_alt = region
        .registered_alternate_stack()
        .map(|stack| (stack.bottom, stack.top))
        .unwrap_or((0, 0));
    let layout = SlotLayout {
        block_base: slot_base,
        stride_log2: fit.stride_log2,
        stride: fit.stride,
        record_offset: RECORD_OFFSET,
        tsd_offset: TSD_OFFSET,
        altstack_offset: fit.altstack_offset,
        altstack_bytes: fit.altstack_bytes,
        backing_offset: fit.backing_offset,
        tp_offset: inputs.tp_offset,
        callback_base,
        callback_stride: fit.callback_stride,
        leader_altstacks: [(bootstrap_low, bootstrap_high), final_alt],
    };
    // Stamp each record's identity before the layout is observable.
    for index in 1..MAX_PRIVATE_TOOL_THREADS {
        let record = (slot_base + index * fit.stride + RECORD_OFFSET) as *mut u64;
        // SAFETY: record pages of this unpublished claim are RW and ours.
        unsafe {
            record.write_volatile(SLOT_RECORD_MAGIC);
            record.add(1).write_volatile(index as u64);
        }
    }
    if SLOT_LAYOUT.set(layout).is_err() {
        return Ok(()); // Another finish raced us; lease drops and rolls back.
    }
    let _ = lease.publish();
    publish_statics(&layout);
    Ok(())
}

fn publish_statics(layout: &SlotLayout) {
    reverie_inguest_private_slot_stride_log2.store(layout.stride_log2 as usize, Ordering::Relaxed);
    reverie_inguest_private_slot_record_offset.store(layout.record_offset, Ordering::Relaxed);
    reverie_inguest_private_slot_altstack_offset.store(layout.altstack_offset, Ordering::Relaxed);
    reverie_inguest_private_slot_altstack_bytes.store(layout.altstack_bytes, Ordering::Relaxed);
    reverie_inguest_private_slot_leader_alt0.store(layout.leader_altstacks[0].0, Ordering::Relaxed);
    reverie_inguest_private_slot_leader_alt1.store(layout.leader_altstacks[0].1, Ordering::Relaxed);
    reverie_inguest_private_slot_leader_alt2.store(layout.leader_altstacks[1].0, Ordering::Relaxed);
    reverie_inguest_private_slot_leader_alt3.store(layout.leader_altstacks[1].1, Ordering::Relaxed);
    SLOT_STATUS.store(STATUS_READY, Ordering::Release);
    reverie_inguest_private_slot_base.store(layout.block_base, Ordering::Release);
}

/// Test-only layout publication over synthetic blocks (isolated
/// processes only; publication is one-way like the real claim).
#[cfg(test)]
pub(crate) fn install_layout_for_test(layout: SlotLayout) {
    assert!(SLOT_LAYOUT.set(layout).is_ok(), "layout already installed");
    publish_statics(&layout);
}

/// Test-only: populates the OnceLock without publishing the assembly
/// base word, so `layout()` must still report None (one source of truth).
#[cfg(test)]
pub(crate) fn install_layout_without_base_for_test(layout: SlotLayout) {
    assert!(SLOT_LAYOUT.set(layout).is_ok(), "layout already installed");
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BASE: usize = 0x6000_1000_0000;
    const STRIDE: usize = 128 * 1024;

    fn test_layout() -> SlotLayout {
        SlotLayout {
            block_base: TEST_BASE,
            stride_log2: STRIDE.trailing_zeros(),
            stride: STRIDE,
            record_offset: RECORD_OFFSET,
            tsd_offset: TSD_OFFSET,
            altstack_offset: 4 * PAGE,
            altstack_bytes: 64 * 1024,
            backing_offset: 4 * PAGE + 64 * 1024 + PAGE,
            tp_offset: 96,
            callback_base: TEST_BASE + 0x4000_0000,
            callback_stride: 8 * 1024 * 1024 + 2 * PAGE,
            leader_altstacks: [(0x5000_0000, 0x5001_0000), (0x5100_0000, 0x5101_0000)],
        }
    }

    #[test]
    fn rsp_derivation_honours_every_guard_boundary() {
        let layout = test_layout();
        // Slot 1 and last slot interiors, edges inclusive/exclusive.
        for index in [1usize, 63] {
            let (lo, hi) = layout.altstack_for_slot(index);
            assert_eq!(layout.record_for_rsp(lo), RecordRef::Slot(index));
            assert_eq!(layout.record_for_rsp(hi - 1), RecordRef::Slot(index));
            assert_eq!(layout.record_for_rsp(lo - 1), RecordRef::Terminal);
            assert_eq!(layout.record_for_rsp(hi), RecordRef::Terminal);
            // Record/backing pages inside the block are never altstacks.
            assert_eq!(
                layout.record_for_rsp(layout.record_addr(index)),
                RecordRef::Terminal
            );
            assert_eq!(
                layout.record_for_rsp(layout.backing(index)),
                RecordRef::Terminal
            );
        }
        // Slot 0's stride is never a slot; leader ranges still win only
        // for their own addresses, and outside everything is terminal.
        assert_eq!(
            layout.record_for_rsp(TEST_BASE + 4 * PAGE),
            RecordRef::Terminal
        );
        assert_eq!(layout.record_for_rsp(0x5000_8000), RecordRef::Leader);
        assert_eq!(layout.record_for_rsp(0x5100_0000), RecordRef::Leader);
        assert_eq!(layout.record_for_rsp(0x5101_0000), RecordRef::Terminal);
        assert_eq!(layout.record_for_rsp(0x1234_0000), RecordRef::Terminal);
    }

    #[test]
    fn tp_derivation_requires_the_exact_slot_tp() {
        let layout = test_layout();
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(1)),
            RecordRef::Slot(1)
        );
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(63)),
            RecordRef::Slot(63)
        );
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(1) + 1),
            RecordRef::Terminal
        );
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(1) - 1),
            RecordRef::Terminal
        );
        assert_eq!(layout.record_for_tp(TEST_BASE), RecordRef::Terminal);
        assert_eq!(layout.record_for_tp(0x5000_8000), RecordRef::Terminal);
        // The slot-0 and idx-64 TPs are exact geometry hits: only the
        // index bounds refuse them.
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(0)),
            RecordRef::Terminal
        );
        assert_eq!(
            layout.record_for_tp(layout.tool_fs_for_slot(64)),
            RecordRef::Terminal
        );
    }

    #[test]
    fn fit_uses_first_aligned_free_span() {
        let callback = 8 * 1024 * 1024usize;
        let spans = [
            (256usize, 1000usize),        // too small for either claim
            (100_001usize, 200_000usize), // unaligned start; first-fit wins
            (500_000usize, 400_000usize),
        ];
        let fit = compute_layout(4096, 16, 64 * 1024, callback, &spans).unwrap();
        assert_eq!(fit.stride, 128 * 1024);
        // The first fitting span starts unaligned at 100_001, so the
        // slot claim must round up to the next 32-page stride multiple.
        assert_eq!(fit.slot_start_page, 100_032);
        assert_eq!(fit.slot_pages, 64 * 32);
        assert_eq!(fit.callback_pages, 63 * (2048 + 2));
        assert!(fit.callback_start_page >= fit.slot_start_page + fit.slot_pages);
        // A span set with room in total but no single aligned span for
        // the callback pool refuses by name — total free pages do not
        // certify the claim.
        let fragmented = [(256usize, 70_000usize), (200_000usize, 70_000usize)];
        assert_eq!(
            compute_layout(4096, 16, 64 * 1024, callback, &fragmented),
            Err(LayoutError::NoAlignedSpan)
        );
        assert_eq!(
            compute_layout(0, 16, 64 * 1024, callback, &spans),
            Err(LayoutError::BadTemplate)
        );
        // A slot backing is only page-aligned, so a larger TLS alignment
        // could shift the per-slot TP offset: refuse by name.
        assert_eq!(
            compute_layout(4096, 2 * PAGE, 64 * 1024, callback, &spans),
            Err(LayoutError::BadTemplate)
        );
    }

    #[test]
    fn admission_bit_clears_on_false() {
        note_thread_admission_requested(true);
        assert!(thread_admission_requested());
        note_thread_admission_requested(false);
        assert!(!thread_admission_requested());
    }

    #[test]
    fn relay_busy_is_per_slot() {
        // Two slots' relay windows overlap without excluding each
        // other; the same slot cannot re-enter its own window.
        let slot_a = AtomicU64::new(0);
        let slot_b = AtomicU64::new(0);
        assert!(acquire_relay_busy(&slot_a));
        assert!(acquire_relay_busy(&slot_b));
        assert!(!acquire_relay_busy(&slot_a));
        assert!(!acquire_relay_busy(&slot_b));
        release_relay_busy(&slot_a);
        assert!(acquire_relay_busy(&slot_a));
        release_relay_busy(&slot_a);
        release_relay_busy(&slot_b);
    }

    #[test]
    fn layout_gate_requires_published_base_word() {
        // Run in a forked child (the isolated pattern from
        // exec_private::tests): installing into the process-global
        // OnceLock in the parent would leak a set layout into every
        // later forked test child, whose own installs and None
        // assertions assume a fresh one. The assertions are
        // unchanged; only their process changed.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(|| {
                // The OnceLock alone does not publish: the base word the assembly
                // reads is the single source of truth.
                install_layout_without_base_for_test(test_layout());
                assert_eq!(layout(), None);
            })
            .is_ok()
            {
                0
            } else {
                125
            };
            unsafe {
                libc::_exit(status);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
