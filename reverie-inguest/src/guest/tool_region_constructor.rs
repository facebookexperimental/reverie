/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Scalar fresh-entry placement. No PKRU, mask or handler transition.

use core::mem::offset_of;
use core::sync::atomic::AtomicUsize;

use super::*;

pub(super) const STACK_BYTES: usize = 8 * 1024 * 1024;
pub(super) const STACK_PAGES: usize = STACK_BYTES / PAGE + 2;
pub(super) const STACK_BOTTOM: usize = BASE + (DATA_FIRST + 1) * PAGE;
pub(super) const STACK_TOP: usize = STACK_BOTTOM + STACK_BYTES;
pub(super) const STACK_EXTENT_END: usize = BASE + (DATA_FIRST + STACK_PAGES) * PAGE;
pub(super) const RECORD_ADDRESS: usize = BASE + PAGE + ((size_of::<Control>() + 15) & !15);
pub(super) const GENERIC_RECORD_ADDRESS: usize =
    (RECORD_ADDRESS + size_of::<NativeRecord>() + 15) & !15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum BootstrapOrigin {
    Constructor = 1,
    ExplicitGeneric = 2,
}

impl BootstrapOrigin {
    const fn record_address(self) -> usize {
        match self {
            Self::Constructor => RECORD_ADDRESS,
            Self::ExplicitGeneric => GENERIC_RECORD_ADDRESS,
        }
    }

    fn adoption_entry(self) -> usize {
        match self {
            Self::Constructor => reverie_inguest_constructor_adopt_entry as *const () as usize,
            Self::ExplicitGeneric => reverie_inguest_generic_adopt_entry as *const () as usize,
        }
    }
}

/// Private locator only; the record remains owned by the original reservation.
#[derive(Clone, Copy, Debug)]
pub(super) struct BootstrapOwner {
    origin: BootstrapOrigin,
    address: usize,
}

const VERSION: usize = 1;
const NATIVE: usize = 1;
const ADOPTING: usize = 2;
const READY: usize = 3;
pub(super) const RETURNED: usize = 4;
// Private scalar prepare ABI. Native accepts zero only and terminates on any
// other return value; neither a status nor READY creates fresh ownership.
const PREPARED: u32 = 0;
const PREPARE_REFUSED: u32 = 1;

#[repr(C)]
struct NativeRecord {
    caller_rsp: usize,
    rbx: usize,
    rbp: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    body: usize,
    owner_tid: usize,
    phase: AtomicUsize,
    version: usize,
    first_rust_sample_rsp: AtomicUsize,
    body_call_sample_rsp: AtomicUsize,
}

const _: () = {
    assert!(DATA_FIRST & 63 == 0);
    assert!(STACK_PAGES == 2050);
    assert!(size_of::<AtomicBool>() == 1);
    assert!(size_of::<AtomicUsize>() == size_of::<usize>());
    assert!(offset_of!(Control, held) == 0);
    assert!(RECORD_ADDRESS & (align_of::<NativeRecord>() - 1) == 0);
    assert!(RECORD_ADDRESS + size_of::<NativeRecord>() <= BASE + CONTROL_BYTES);
    assert!(STACK_TOP & 15 == 0);
    assert!(size_of::<Control>() == 0x20028 && align_of::<Control>() == 8);
    assert!(size_of::<NativeRecord>() == 104 && align_of::<NativeRecord>() == 8);
    assert!(offset_of!(NativeRecord, caller_rsp) == 0);
    assert!(offset_of!(NativeRecord, rbx) == 8);
    assert!(offset_of!(NativeRecord, rbp) == 16);
    assert!(offset_of!(NativeRecord, r12) == 24);
    assert!(offset_of!(NativeRecord, r13) == 32);
    assert!(offset_of!(NativeRecord, r14) == 40);
    assert!(offset_of!(NativeRecord, r15) == 48);
    assert!(offset_of!(NativeRecord, body) == 56);
    assert!(offset_of!(NativeRecord, owner_tid) == 64);
    assert!(offset_of!(NativeRecord, phase) == 72);
    assert!(offset_of!(NativeRecord, version) == 80);
    assert!(offset_of!(NativeRecord, first_rust_sample_rsp) == 88);
    assert!(offset_of!(NativeRecord, body_call_sample_rsp) == 96);
    assert!(RECORD_ADDRESS == BASE + 0x21030);
    assert!(GENERIC_RECORD_ADDRESS == BASE + 0x210a0);
    assert!(RECORD_ADDRESS >= BASE + PAGE + size_of::<Control>());
    assert!(RECORD_ADDRESS + size_of::<NativeRecord>() <= GENERIC_RECORD_ADDRESS);
    assert!(GENERIC_RECORD_ADDRESS & 15 == 0);
    assert!(GENERIC_RECORD_ADDRESS + size_of::<NativeRecord>() <= BASE + CONTROL_BYTES);
    assert!(GENERIC_RECORD_ADDRESS + size_of::<NativeRecord>() <= arena::METADATA_ADDRESS);
    assert!(STACK_EXTENT_END <= arena::TOOL_BOTTOM - PAGE);
    assert!(BASE + CONTROL_BYTES <= BASE + DATA_FIRST * PAGE);
    assert!(STACK_BOTTOM == BASE + 0x101000 && STACK_TOP == BASE + 0x901000);
    assert!(STACK_EXTENT_END == BASE + 0x902000);
};

/// Placement diagnostics for a successfully adopted native constructor stack.
/// The first sample is inside Rust preparation; the second is immediately
/// before native body dispatch. Neither observes the actual body entry.
#[derive(Clone, Copy, Debug)]
pub struct ConstructorStack {
    /// First page of the allocation, including its lower guard.
    pub extent_start: usize,
    /// End of the allocation, including its upper guard.
    pub extent_end: usize,
    /// Readable/writable key-zero interior.
    pub bottom: usize,
    /// End of that interior, followed by the upper guard.
    pub top: usize,
    /// Scalar caller stack address retained by the native entry.
    pub caller_rsp: usize,
    /// Kernel TID which made this fresh reservation.
    pub owner_tid: u32,
    /// Address of the first Rust prepare entry, for external observation.
    pub adoption_entry: usize,
    /// Address supplied by the unsafe native caller.
    pub body_entry: usize,
    /// RSP sampled after the prepare function's Rust prologue.
    pub first_rust_sample_rsp: usize,
    /// Native RSP sampled immediately before the real C-ABI body call.
    pub body_call_sample_rsp: usize,
    /// Whether that body has returned normally.
    pub returned: bool,
}

/// Query an adopted bootstrap without allocating or initializing a region.
/// Ordinary reservations and inert compatibility loads have no bootstrap.
pub fn constructor_stack() -> Option<ConstructorStack> {
    bootstrap_stack(BootstrapOrigin::Constructor)
}

fn bootstrap_stack(origin: BootstrapOrigin) -> Option<ConstructorStack> {
    let region = REGION.get()?.as_ref().ok()?;
    let owner = region.bootstrap?;
    if owner.origin != origin || owner.address != origin.record_address() {
        return None;
    }
    let address = owner.address;
    // SAFETY: only typed fresh adoption publishes this process-lifetime record.
    let record = unsafe { &*(address as *const NativeRecord) };
    let phase = record.phase.load(Ordering::Acquire);
    if phase != READY && phase != RETURNED {
        return None;
    }
    Some(ConstructorStack {
        extent_start: BASE + DATA_FIRST * PAGE,
        extent_end: STACK_EXTENT_END,
        bottom: STACK_BOTTOM,
        top: STACK_TOP,
        caller_rsp: record.caller_rsp,
        owner_tid: record.owner_tid as u32,
        adoption_entry: origin.adoption_entry(),
        body_entry: record.body,
        first_rust_sample_rsp: record.first_rust_sample_rsp.load(Ordering::Acquire),
        body_call_sample_rsp: record.body_call_sample_rsp.load(Ordering::Acquire),
        returned: phase == RETURNED,
    })
}

/// Fixed scalar ABI for the separate constructor-placement diagnostic.
/// This never changes or substitutes for the allocator or region-stack oracle.
#[cfg(feature = "allocator-fixture")]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ConstructorStackRecord {
    /// Version one of this sixteen-word scalar record.
    pub layout_version: u64,
    /// Three while ready and four after ordinary body return.
    pub phase: u64,
    /// Kernel TID of the fresh native reservation, retained through COW.
    pub owner_tid: u64,
    /// Beginning of the full extent, including its lower guard.
    pub extent_start: u64,
    /// End of the full extent, including its upper guard.
    pub extent_end: u64,
    /// Beginning of the writable bootstrap interior.
    pub bottom: u64,
    /// End of the writable interior and beginning of the upper guard.
    pub top: u64,
    /// Native caller's original RSP.
    pub caller_rsp: u64,
    /// Stable first Rust prepare entry address.
    pub adoption_entry: u64,
    /// Supplied actual C-ABI body entry address.
    pub body_entry: u64,
    /// Post-prologue RSP sampled inside Rust preparation.
    pub first_rust_sample_rsp: u64,
    /// Native RSP sampled immediately before the genuine body call.
    pub body_call_sample_rsp: u64,
    /// Address of the fresh region's existing control structure.
    pub control_address: u64,
    /// Address of this native invocation's private owned record.
    pub record_address: u64,
    /// Literal fixed reservation beginning.
    pub region_base: u64,
    /// Literal fixed reservation end.
    pub region_end: u64,
}

/// Write a read-only constructor placement snapshot. Return zero on success;
/// return -1 without writing for null output or an absent/unpublished owner.
///
/// # Safety
/// A non-null output must point to writable storage for one complete record.
#[cfg(feature = "allocator-fixture")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_inguest_constructor_stack_query(
    output: *mut ConstructorStackRecord,
) -> i32 {
    if output.is_null() {
        return -1;
    }
    let Some(stack) = constructor_stack() else {
        return -1;
    };
    let record = ConstructorStackRecord {
        layout_version: VERSION as u64,
        phase: if stack.returned { RETURNED } else { READY } as u64,
        owner_tid: u64::from(stack.owner_tid),
        extent_start: stack.extent_start as u64,
        extent_end: stack.extent_end as u64,
        bottom: stack.bottom as u64,
        top: stack.top as u64,
        caller_rsp: stack.caller_rsp as u64,
        adoption_entry: stack.adoption_entry as u64,
        body_entry: stack.body_entry as u64,
        first_rust_sample_rsp: stack.first_rust_sample_rsp as u64,
        body_call_sample_rsp: stack.body_call_sample_rsp as u64,
        control_address: (BASE + PAGE) as u64,
        record_address: RECORD_ADDRESS as u64,
        region_base: BASE as u64,
        region_end: END as u64,
    };
    unsafe { output.write(record) };
    0
}

/// Write a read-only explicit generic placement snapshot. Return zero on success;
/// return -1 without writing for null output or an absent/unpublished owner.
///
/// # Safety
/// A non-null output must point to writable storage for one complete record.
#[cfg(feature = "allocator-fixture")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_inguest_generic_stack_query(
    output: *mut ConstructorStackRecord,
) -> i32 {
    if output.is_null() {
        return -1;
    }
    let Some(stack) = bootstrap_stack(BootstrapOrigin::ExplicitGeneric) else {
        return -1;
    };
    let record = ConstructorStackRecord {
        layout_version: VERSION as u64,
        phase: if stack.returned { RETURNED } else { READY } as u64,
        owner_tid: u64::from(stack.owner_tid),
        extent_start: stack.extent_start as u64,
        extent_end: stack.extent_end as u64,
        bottom: stack.bottom as u64,
        top: stack.top as u64,
        caller_rsp: stack.caller_rsp as u64,
        adoption_entry: stack.adoption_entry as u64,
        body_entry: stack.body_entry as u64,
        first_rust_sample_rsp: stack.first_rust_sample_rsp as u64,
        body_call_sample_rsp: stack.body_call_sample_rsp as u64,
        control_address: (BASE + PAGE) as u64,
        record_address: GENERIC_RECORD_ADDRESS as u64,
        region_base: BASE as u64,
        region_end: END as u64,
    };
    unsafe { output.write(record) };
    0
}
#[cfg(not(feature = "fixed-syscall-gates"))]
unsafe extern "C" {
    #[link_name = "reverie_inguest_trusted_syscall_ip"]
    fn native_gate();
}

// One compile-time native sequence, with independent fresh-owner origins.
macro_rules! native_bootstrap {
    ($documentation:literal, $entry:ident, $symbol:literal, $prefix:literal, $record:expr, $adopt:path,
     [$($terminal:expr),* $(,)?], [$($extra_name:ident = $extra_kind:ident $extra_value:expr),* $(,)?]) => {
        #[doc = $documentation]
        #[unsafe(naked)]
        #[unsafe(export_name = $symbol)]
        pub unsafe extern "C" fn $entry(_body: unsafe extern "C" fn()) {
            core::arch::naked_asm!(

        "endbr64",
        "movq xmm0, rsp",
        "movq xmm1, rbx",
        "movq xmm2, rbp",
        "movq xmm3, r12",
        "movq xmm4, r13",
        "movq xmm5, r14",
        "movq xmm6, r15",
        "movq xmm7, rdi",
        // A scalar BSS locator is explicitly outside the region claim. No
        // contender spins or starts publication while this gate is occupied.
        "xor eax, eax",
        "mov dl, 1",
        "lock cmpxchg byte ptr [rip + {initializing}], dl",
        concat!("jne .L", $prefix, "_fatal"),
        "mov eax, {mmap}",
        "movabs rdi, {base}",
        "movabs rsi, {bytes}",
        "xor edx, edx",
        "mov r10d, {map_flags}",
        "mov r8, -1",
        "xor r9d, r9d",
        concat!("lea r12, [rip + .L", $prefix, "_mapped]"),
        "jmp {gate}",
        concat!(".L", $prefix, "_mapped:"),
        "endbr64",
        "test rax, rax",
        concat!("js .L", $prefix, "_fatal"),
        "movabs r13, {base}",
        "cmp rax, r13",
        concat!("je .L", $prefix, "_exact"),
        // Old kernels can ignore NOREPLACE. Clean only the actual return.
        "mov rdi, rax",
        "movabs rsi, {bytes}",
        "mov eax, {munmap}",
        concat!("lea r12, [rip + .L", $prefix, "_wrong_unmapped]"),
        "jmp {gate}",
        concat!(".L", $prefix, "_wrong_unmapped:"),
        "endbr64",
        concat!("jmp .L", $prefix, "_fatal"),
        concat!(".L", $prefix, "_exact:"),
        "movabs rdi, {control}",
        "mov esi, {control_bytes}",
        "mov edx, {rw}",
        "mov eax, {mprotect}",
        concat!("lea r12, [rip + .L", $prefix, "_control]"),
        "jmp {gate}",
        concat!(".L", $prefix, "_control:"),
        "endbr64",
        "test rax, rax",
        concat!("jne .L", $prefix, "_fatal"),
        "movabs r13, {control}",
        "mov byte ptr [r13 + {held}], 0",
        // Anonymous fresh ownership establishes zero-filled metadata. Reserve
        // all 2050 pages, including both guards, before exposing any Rust API.
        "lea rdi, [r13 + {bitmap} + {first_word}]",
        "mov ecx, {full_words}",
        concat!(".L", $prefix, "_bitmap:"),
        "mov qword ptr [rdi], -1",
        "add rdi, 8",
        "dec ecx",
        concat!("jne .L", $prefix, "_bitmap"),
        "mov qword ptr [rdi], {last_bits}",
        "movabs r14, {record}",
        "movq rax, xmm0",
        "mov [r14 + {caller_rsp}], rax",
        "movq rax, xmm1",
        "mov [r14 + {rbx}], rax",
        "movq rax, xmm2",
        "mov [r14 + {rbp}], rax",
        "movq rax, xmm3",
        "mov [r14 + {r12}], rax",
        "movq rax, xmm4",
        "mov [r14 + {r13}], rax",
        "movq rax, xmm5",
        "mov [r14 + {r14}], rax",
        "movq rax, xmm6",
        "mov [r14 + {r15}], rax",
        "movq rax, xmm7",
        "mov [r14 + {body}], rax",
        "mov qword ptr [r14 + {version}], {version_value}",
        "mov qword ptr [r14 + {phase}], {native}",
        "mov eax, {gettid}",
        concat!("lea r12, [rip + .L", $prefix, "_tid]"),
        "jmp {gate}",
        concat!(".L", $prefix, "_tid:"),
        "endbr64",
        "test rax, rax",
        concat!("jle .L", $prefix, "_fatal"),
        "mov [r14 + {owner_tid}], rax",
        "movabs rdi, {bottom}",
        "mov esi, {stack_bytes}",
        "mov edx, {rw}",
        "mov eax, {mprotect}",
        concat!("lea r12, [rip + .L", $prefix, "_stack]"),
        "jmp {gate}",
        concat!(".L", $prefix, "_stack:"),
        "endbr64",
        "test rax, rax",
        concat!("jne .L", $prefix, "_fatal"),
        // The guest's original R15 is already in its owned record. Retain the
        // original supplied RDI across scalar SysV Rust preparation in R15.
        "movq r15, xmm7",
        "movabs rsp, {top}",
        "mov rdi, r14",
        "call {adopt}",
        "test eax, eax",
        concat!("jne .L", $prefix, "_fatal"),
        // Refuse a bad scalar return rather than resetting the owned RSP.
        "movabs rax, {top}",
        "cmp rsp, rax",
        concat!("jne .L", $prefix, "_fatal"),
        "movabs r14, {record}",
        "cmp qword ptr [r14 + {version}], {version_value}",
        concat!("jne .L", $prefix, "_fatal"),
        "cmp qword ptr [r14 + {phase}], {ready}",
        concat!("jne .L", $prefix, "_fatal"),
        "cmp byte ptr [rip + {initializing}], 0",
        concat!("jne .L", $prefix, "_fatal"),
        "test r15, r15",
        concat!("je .L", $prefix, "_fatal"),
        "cmp qword ptr [r14 + {body}], r15",
        concat!("jne .L", $prefix, "_fatal"),
        // The genuine call sample stays strictly inside the lease. On x86-64
        // these aligned MOV stores retain release ordering for the atomics.
        "sub rsp, 16",
        "mov qword ptr [r14 + {body_call_sample_rsp}], rsp",
        "call r15",
        // This is the body's distinct real return, still in READY phase.
        "movabs rax, {body_call_top}",
        "cmp rsp, rax",
        concat!("jne .L", $prefix, "_fatal"),
        "add rsp, 16",
        "movabs r14, {record}",
        "mov qword ptr [r14 + {phase}], {returned}",
        // Reload only from owned control storage. No Tool access follows the
        // exact caller-RSP restoration, and RET discharges the loader CALL.
        "movabs rax, {record}",
        "mov rbx, [rax + {rbx}]",
        "mov rbp, [rax + {rbp}]",
        "mov r12, [rax + {r12}]",
        "mov r13, [rax + {r13}]",
        "mov r14, [rax + {r14}]",
        "mov r15, [rax + {r15}]",
        "mov rsp, [rax + {caller_rsp}]",
        "ret",
        concat!(".L", $prefix, "_fatal:"),
        $($terminal,)*
        initializing = sym INITIALIZING,
        gate = sym native_gate,
        adopt = sym $adopt,
        mmap = const libc::SYS_mmap,
        munmap = const libc::SYS_munmap,
        mprotect = const libc::SYS_mprotect,
        gettid = const libc::SYS_gettid,
        exit_group = const libc::SYS_exit_group,
        map_flags = const libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
        rw = const libc::PROT_READ | libc::PROT_WRITE,
        base = const BASE,
        bytes = const BYTES,
        control = const BASE + PAGE,
        control_bytes = const CONTROL_BYTES - PAGE,
        held = const offset_of!(Control, held),
        bitmap = const offset_of!(Control, occupied),
        first_word = const DATA_FIRST / 64 * size_of::<u64>(),
        full_words = const STACK_PAGES / 64,
        last_bits = const (1_u64 << (STACK_PAGES % 64)) - 1,
        record = const $record,
        caller_rsp = const offset_of!(NativeRecord, caller_rsp),
        rbx = const offset_of!(NativeRecord, rbx),
        rbp = const offset_of!(NativeRecord, rbp),
        r12 = const offset_of!(NativeRecord, r12),
        r13 = const offset_of!(NativeRecord, r13),
        r14 = const offset_of!(NativeRecord, r14),
        r15 = const offset_of!(NativeRecord, r15),
        body = const offset_of!(NativeRecord, body),
        owner_tid = const offset_of!(NativeRecord, owner_tid),
        phase = const offset_of!(NativeRecord, phase),
        version = const offset_of!(NativeRecord, version),
        version_value = const VERSION,
        native = const NATIVE,
        ready = const READY,
        returned = const RETURNED,
        body_call_sample_rsp = const offset_of!(NativeRecord, body_call_sample_rsp),
        bottom = const STACK_BOTTOM,
        top = const STACK_TOP,
        body_call_top = const STACK_TOP - 16,
        stack_bytes = const STACK_BYTES,
        $($extra_name = $extra_kind $extra_value,)*
            );
        }
    };
}

native_bootstrap!(
    "Reserve and adopt a fresh fixed guarded stack before the first Rust call.\n\nOnly the supplied zero-argument scalar body runs on this bootstrap. The\ncomplete lease remains occupied for process lifetime and through plain fork\nCOW. Setup failure exits 127 without a guest-stack or allocator fallback.\nThis is key-zero placement, not protected interiors, whole caller-window\nequality, standalone activation, TLS isolation or arbitrary state capture.\nIt adds no mask, disposition, CPUID, PKRU or seccomp policy.\n\n# Safety\n\nCall once per image during single-threaded trusted startup, with no active\nruntime filter, using the scalar SysV ABI (including clear DF). The body must\nbe a valid C-ABI function which preserves its callee-saved state and does not\nunwind across this stack switch. A loader root may tail-jump here with the\nbody in RDI, retaining its genuine CALL/RET pair. Earlier handlers retain\ncurrent behavior and may access the unprotected interior; no signal-frame\nbyte-isolation or denied-key access guarantee is supplied.",
    constructor_entry,
    "reverie_inguest_constructor_entry",
    "constructor",
    RECORD_ADDRESS,
    reverie_inguest_constructor_adopt_entry,
    [
        "mov eax, {write}",
        "mov edi, 2",
        "lea rsi, [rip + .Lconstructor_message]",
        "mov edx, {message_bytes}",
        "lea r12, [rip + .Lconstructor_exit]",
        "jmp {gate}",
        ".Lconstructor_exit:",
        "endbr64",
        "mov eax, {exit_group}",
        "mov edi, 127",
        "lea r12, [rip + .Lconstructor_exit_failed]",
        "jmp {gate}",
        ".Lconstructor_exit_failed:",
        "endbr64",
        "ud2",
        ".Lconstructor_message:",
        ".ascii \"reverie constructor bootstrap failed\\n\"",
    ],
    [write = const libc::SYS_write,
     message_bytes = const b"reverie constructor bootstrap failed\n".len()]
);

// Same fresh-only scalar entry, with a separate typed origin and an immediate
// terminal attempt: unlike the retained constructor failure, no stderr write.
native_bootstrap!(
    "Reserve a fresh generic startup stack before its first Rust call.\n\nThe permanent scalar lease is separate from constructor-origin diagnostics.\nA collision or second invocation attempts exit127 without a stderr write;\nthere is no relocated, ordinary-region or guest-stack fallback. The body\nruns on key-zero pages; this adds no signal, PKRU or clock policy.\n\n# Safety\nCall once per image in single-threaded trusted startup with clear DF and\nno active runtime filter. The valid zero-argument body must obey scalar\nSysV and return normally without unwinding or a nonlocal transfer. Earlier\nhandlers may access the unprotected interior; this is placement only.",
    generic_entry,
    "reverie_inguest_generic_entry",
    "generic",
    GENERIC_RECORD_ADDRESS,
    reverie_inguest_generic_adopt_entry,
    [
        "mov eax, {exit_group}",
        "mov edi, 127",
        "lea r12, [rip + .Lgeneric_exit_failed]",
        "jmp {gate}",
        ".Lgeneric_exit_failed:",
        "endbr64",
        "ud2",
    ],
    []
);

// Keep stable hidden prepare entries for hardware observation of the first
// real Rust instruction. These are not constructors or public adoption APIs.
core::arch::global_asm!(
    ".hidden reverie_inguest_constructor_entry",
    ".hidden reverie_inguest_constructor_adopt_entry",
    ".hidden reverie_inguest_generic_entry",
    ".hidden reverie_inguest_generic_adopt_entry",
);

// The private scalar owner entry writes these two fields into caller-owned
// MaybeUninit storage. Give that output an explicit layout rather than relying
// on Rust's field ordering; padding is neither an input nor an ownership token.
#[repr(C)]
struct NativeFreshOwner {
    record: *mut NativeRecord,
    origin: BootstrapOrigin,
}

const _: () = {
    assert!(size_of::<NativeFreshOwner>() == 16);
    assert!(align_of::<NativeFreshOwner>() == 8);
    assert!(offset_of!(NativeFreshOwner, record) == 0);
    assert!(offset_of!(NativeFreshOwner, origin) == 8);
    assert!(size_of::<BootstrapOrigin>() == 1);
    assert!(offset_of!(Control, occupied) == 8);
    assert!(DATA_FIRST + STACK_PAGES <= BITMAP_WORDS * 64);
    assert!(DATA_FIRST + STACK_PAGES < i32::MAX as usize);
};

// The naked owner must not call a Rust-ABI function by assuming its current
// lowering. This zero-argument C bridge retains raw_syscall3's existing choice
// of legacy versus published fixed gates; it introduces no new syscall route.
#[inline(never)]
unsafe extern "C" fn native_owner_gettid() -> i64 {
    // SAFETY: gettid has no pointer arguments and does not change stack owner.
    unsafe { crate::trap::raw_syscall3(libc::SYS_gettid, 0, 0, 0) }
}

impl NativeFreshOwner {
    // This constructor is private. Only the native prefix's successful exact
    // NOREPLACE mapping supplies provenance; record magic never supplies it.
    #[inline(always)]
    unsafe fn from_native(
        record: *mut NativeRecord,
        adoption_rsp: usize,
        origin: BootstrapOrigin,
    ) -> Result<Self, i32> {
        let mut owner = MaybeUninit::<Self>::uninit();
        // SAFETY: retain the native prefix's exclusive ownership. The output
        // is aligned, disjoint, uninitialized storage owned by this call. Only
        // a zero status initializes it; no Rust enum crosses the ABI boundary.
        let status = unsafe {
            Self::from_native_opaque(
                black_box(record.cast()),
                black_box(adoption_rsp),
                black_box(origin as usize),
                black_box(owner.as_mut_ptr().cast()),
            )
        };
        if status == 0 {
            // SAFETY: the qualified scalar callee writes exactly one owner
            // before returning zero; nonzero returns never reach this read.
            Ok(unsafe { owner.assume_init() })
        } else {
            Err(status)
        }
    }

    /// The caller retains the native prefix's exclusive initialization lease.
    /// The output is disjoint, aligned storage for one NativeFreshOwner, which
    /// is initialized only on zero. Other statuses leave the output untouched.
    ///
    /// # Safety
    /// The native prefix owns the exact fresh reservation and INITIALIZING;
    /// matching scalar ticket fields alone never provide mapping authority.
    /// The caller supplies valid output storage and obeys scalar SysV with DF
    /// clear. Every called helper has an explicit C ABI and may not unwind.
    #[unsafe(naked)]
    unsafe extern "C" fn from_native_opaque(
        _record: *mut c_void,
        _adoption_rsp: usize,
        _origin: usize,
        _owner: *mut c_void,
    ) -> i32 {
        // SAFETY: preserve the original validation and side-effect order.
        // Five saved registers align RSP to 16 bytes before each C call; all
        // SysV callee-saved registers are restored on every returning path.
        // x86 loads implement the acquire observations, and LOCK CMPXCHG
        // implements the AcqRel/Acquire phase transition. No nomem/readonly
        // promise lets a Rust caller move memory effects across this call.
        // After a successful CAS, every refusal retains ADOPTING, INITIALIZING
        // and the live owned stack. This function never publishes or unmaps.
        core::arch::naked_asm!(
            "push rbx",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "mov rbx, rdi",
            "mov r12, rcx",
            "mov r13, rdx",
            // Select the exact ticket before touching any ticket memory.
            "cmp rdx, {constructor_origin}",
            "je 2f",
            "cmp rdx, {generic_origin}",
            "jne 90f",
            "movabs rax, {generic_record}",
            "jmp 3f",
            "2:",
            "movabs rax, {constructor_record}",
            "3:",
            "cmp rbx, rax",
            "jne 90f",
            "cmp byte ptr [rip + {initializing}], 0",
            "je 90f",
            "movabs rax, {stack_bottom}",
            "cmp rsi, rax",
            "jb 90f",
            "movabs rax, {stack_top}",
            "cmp rsi, rax",
            "jae 90f",
            "call {gettid}",
            "test rax, rax",
            "jle 90f",
            "cmp qword ptr [rbx + {owner_tid}], rax",
            "jne 90f",
            "cmp qword ptr [rbx + {version_offset}], {version}",
            "jne 90f",
            "cmp qword ptr [rbx + {body}], 0",
            "je 90f",
            "mov rax, [rbx + {caller_rsp}]",
            "and eax, 15",
            "cmp eax, 8",
            "jne 90f",
            "lea rdi, [rip + {region}]",
            "call {get_region}",
            "test rax, rax",
            "jne 90f",
            "mov eax, {native}",
            "mov edx, {adopting}",
            "lock cmpxchg qword ptr [rbx + {phase}], rdx",
            "jne 90f",
            "movabs r14, {control}",
            "cmp byte ptr [r14 + {held}], 0",
            "jne 91f",
            // Read every page in the exact complete bootstrap extent. The
            // register BT masks its bit index to 0..63; the explicit /64
            // address calculation selects the corresponding occupied word.
            "mov eax, {first_page}",
            "4:",
            "mov rcx, rax",
            "shr rcx, 6",
            "mov rdx, [r14 + rcx*8 + {occupied}]",
            "bt rdx, rax",
            "jnc 90f",
            "inc rax",
            "cmp rax, {end_page}",
            "jb 4b",
            // Complete all permanent bands before initializing the output.
            // Preserve the setup helper's exact full nonzero errno in EAX.
            "mov rdi, r14",
            "call {setup}",
            "test eax, eax",
            "jne 92f",
            "mov [r12 + {output_record}], rbx",
            "mov byte ptr [r12 + {output_origin}], r13b",
            "xor eax, eax",
            "jmp 92f",
            "90:",
            "mov eax, {invalid}",
            "jmp 92f",
            "91:",
            "mov eax, {again}",
            "92:",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "ret",
            constructor_origin = const BootstrapOrigin::Constructor as usize,
            generic_origin = const BootstrapOrigin::ExplicitGeneric as usize,
            constructor_record = const RECORD_ADDRESS,
            generic_record = const GENERIC_RECORD_ADDRESS,
            initializing = sym INITIALIZING,
            stack_bottom = const STACK_BOTTOM,
            stack_top = const STACK_TOP,
            gettid = sym native_owner_gettid,
            owner_tid = const offset_of!(NativeRecord, owner_tid),
            version_offset = const offset_of!(NativeRecord, version),
            version = const VERSION,
            body = const offset_of!(NativeRecord, body),
            caller_rsp = const offset_of!(NativeRecord, caller_rsp),
            region = sym REGION,
            get_region = sym RegionPublication::get_opaque,
            native = const NATIVE,
            adopting = const ADOPTING,
            phase = const offset_of!(NativeRecord, phase),
            control = const BASE + PAGE,
            held = const offset_of!(Control, held),
            first_page = const DATA_FIRST,
            end_page = const DATA_FIRST + STACK_PAGES,
            occupied = const offset_of!(Control, occupied),
            setup = sym arena::initialize_fixed_arenas_opaque,
            output_record = const offset_of!(Self, record),
            output_origin = const offset_of!(Self, origin),
            invalid = const libc::EINVAL,
            again = const libc::EAGAIN,
        );
    }

    // Keep this transaction in each complete qualified prepare entry.
    #[inline(always)]
    fn publish(self) -> Result<&'static ToolRegion, i32> {
        // SAFETY: self retains the native prefix's exclusive INITIALIZING
        // ownership from its successful CAS. from_native authenticated this
        // fresh owner and completed arena setup without releasing that gate.
        unsafe {
            REGION.set_under_gate(Ok(ToolRegion {
                control: (BASE + PAGE) as *mut Control,
                bootstrap: Some(BootstrapOwner {
                    origin: self.origin,
                    address: self.record as usize,
                }),
            }))
        }
        .map_err(|_| libc::EAGAIN)?;
        unsafe { &(*self.record).phase }.store(READY, Ordering::Release);
        INITIALIZING.store(false, Ordering::Release);
        REGION
            .get()
            .and_then(|result| result.as_ref().ok())
            .ok_or(libc::EAGAIN)
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn reverie_inguest_constructor_adopt_entry(record: *mut NativeRecord) -> u32 {
    let rsp: usize;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags)) };
    let fresh = unsafe { NativeFreshOwner::from_native(record, rsp, BootstrapOrigin::Constructor) };
    let Ok(fresh) = fresh else {
        return PREPARE_REFUSED;
    };
    unsafe { &(*record).first_rust_sample_rsp }.store(rsp, Ordering::Release);
    match fresh.publish() {
        Ok(_) => PREPARED,
        Err(_) => PREPARE_REFUSED,
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn reverie_inguest_generic_adopt_entry(record: *mut NativeRecord) -> u32 {
    let rsp: usize;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags)) };
    let fresh =
        unsafe { NativeFreshOwner::from_native(record, rsp, BootstrapOrigin::ExplicitGeneric) };
    let Ok(fresh) = fresh else {
        return PREPARE_REFUSED;
    };
    unsafe { &(*record).first_rust_sample_rsp }.store(rsp, Ordering::Release);
    match fresh.publish() {
        Ok(_) => PREPARED,
        Err(_) => PREPARE_REFUSED,
    }
}

#[cfg(test)]
pub(super) fn malformed_ticket_control() {
    // Real fresh control mapping, but deliberately malformed private tickets.
    // These reject-only controls are not native constructor execution credit.
    let region = ToolRegion::reserve_inner().unwrap();
    let _guard = InitializationGuard::acquire().unwrap();
    // Rejection must not manufacture an initialized owner or alter the
    // caller's output storage. Unknown scalar origins reject before any record
    // access, and a wrong record address rejects before ticket dereference.
    let mut output = MaybeUninit::<NativeFreshOwner>::uninit();
    let output_bytes = output.as_mut_ptr().cast::<u8>();
    // SAFETY: writing/observing the MaybeUninit storage as bytes does not read
    // a NativeFreshOwner. Neither refused call may initialize it.
    unsafe { output_bytes.write_bytes(0xa5, size_of::<NativeFreshOwner>()) };
    for origin in [0, 3, usize::MAX, BootstrapOrigin::Constructor as usize] {
        // SAFETY: the current test owns INITIALIZING. The output is aligned,
        // exclusive storage; these inputs must reject before record access.
        let status = unsafe {
            NativeFreshOwner::from_native_opaque(
                core::ptr::null_mut(),
                STACK_TOP - 16,
                origin,
                output.as_mut_ptr().cast(),
            )
        };
        assert_eq!(status, libc::EINVAL);
        // SAFETY: every byte was initialized above and the result was refused.
        assert!(
            unsafe { core::slice::from_raw_parts(output_bytes, size_of::<NativeFreshOwner>()) }
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) } as usize;
    let pointer = RECORD_ADDRESS as *mut NativeRecord;
    let value = NativeRecord {
        caller_rsp: 8,
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        body: malformed_ticket_control as *const () as usize,
        owner_tid: tid,
        phase: AtomicUsize::new(NATIVE),
        version: VERSION,
        first_rust_sample_rsp: AtomicUsize::new(0),
        body_call_sample_rsp: AtomicUsize::new(0),
    };
    unsafe { pointer.write(value) };
    let attempt = move || {
        unsafe {
            NativeFreshOwner::from_native(pointer, STACK_TOP - 16, BootstrapOrigin::Constructor)
        }
        .err()
        .unwrap()
    };
    // Cross-origin addresses reject before any ticket dereference. These
    // malformed-ticket controls establish no actual-entry/placement credit.
    assert_eq!(
        unsafe {
            NativeFreshOwner::from_native(pointer, STACK_TOP - 16, BootstrapOrigin::ExplicitGeneric)
        }
        .err()
        .unwrap(),
        libc::EINVAL,
    );
    assert_eq!(
        unsafe {
            NativeFreshOwner::from_native(
                GENERIC_RECORD_ADDRESS as *mut NativeRecord,
                STACK_TOP - 16,
                BootstrapOrigin::Constructor,
            )
        }
        .err()
        .unwrap(),
        libc::EINVAL,
    );
    assert_eq!(
        unsafe {
            NativeFreshOwner::from_native(
                (RECORD_ADDRESS + 8) as *mut NativeRecord,
                STACK_TOP - 16,
                BootstrapOrigin::Constructor,
            )
        }
        .err()
        .unwrap(),
        libc::EINVAL
    );
    assert_eq!(
        unsafe { NativeFreshOwner::from_native(pointer, 8, BootstrapOrigin::Constructor) }
            .err()
            .unwrap(),
        libc::EINVAL
    );
    unsafe { (*pointer).owner_tid = tid + 1 };
    assert_eq!(attempt(), libc::EINVAL);
    unsafe {
        (*pointer).owner_tid = tid;
        (*pointer).version = VERSION + 1
    };
    assert_eq!(attempt(), libc::EINVAL);
    unsafe {
        (*pointer).version = VERSION;
        (*pointer).phase.store(RETURNED, Ordering::Release)
    };
    assert_eq!(attempt(), libc::EINVAL);
    unsafe { (*pointer).phase.store(NATIVE, Ordering::Release) };
    // The complete bootstrap extent is still unoccupied: refuse, not publish.
    assert_eq!(attempt(), libc::EINVAL);
    assert!(REGION.get().is_none());
    let start = region.claim(STACK_PAGES).unwrap();
    assert_eq!(start, DATA_FIRST);
    unsafe {
        (*pointer).phase.store(NATIVE, Ordering::Release);
        (*pointer).body = 0
    };
    assert_eq!(attempt(), libc::EINVAL);
    assert!(REGION.get().is_none());
    // Consume no legitimate owner and publish no partial failure.
    assert_eq!(unsafe { (*pointer).body }, 0);

    // Exercise the scalar entry's later refusals with independently poisoned
    // output storage. No refused path may manufacture even part of an owner.
    let refused_output = move || {
        let mut output = MaybeUninit::<NativeFreshOwner>::uninit();
        let bytes = output.as_mut_ptr().cast::<u8>();
        // SAFETY: the test owns both the fresh reservation and INITIALIZING;
        // output is aligned, disjoint storage initialized as bytes, not Self.
        unsafe { bytes.write_bytes(0xa5, size_of::<NativeFreshOwner>()) };
        let status = unsafe {
            NativeFreshOwner::from_native_opaque(
                pointer.cast(),
                STACK_TOP - 16,
                BootstrapOrigin::Constructor as usize,
                output.as_mut_ptr().cast(),
            )
        };
        assert_ne!(status, 0);
        // SAFETY: the sentinel initializes every byte, including padding.
        assert!(
            unsafe { core::slice::from_raw_parts(bytes, size_of::<NativeFreshOwner>()) }
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert!(INITIALIZING.load(Ordering::Acquire));
        assert!(REGION.get().is_none());
        status
    };
    // Ticket alignment must fail before the NATIVE -> ADOPTING transition.
    unsafe {
        (*pointer).body = malformed_ticket_control as *const () as usize;
        (*pointer).caller_rsp = 0;
        (*pointer).phase.store(NATIVE, Ordering::Release);
    }
    assert_eq!(refused_output(), libc::EINVAL);
    assert_eq!(unsafe { (*pointer).phase.load(Ordering::Acquire) }, NATIVE);
    unsafe { (*pointer).caller_rsp = 8 };
    // A held control preserves its distinct EAGAIN and the acquired phase.
    let control = unsafe { &*((BASE + PAGE) as *const Control) };
    control.held.store(true, Ordering::Release);
    assert_eq!(refused_output(), libc::EAGAIN);
    assert_eq!(
        unsafe { (*pointer).phase.load(Ordering::Acquire) },
        ADOPTING
    );
    assert!(control.held.load(Ordering::Acquire));
    control.held.store(false, Ordering::Release);
    // Check both edges and an interior bit of the full bootstrap extent.
    for page in [
        DATA_FIRST,
        DATA_FIRST + STACK_PAGES / 2,
        DATA_FIRST + STACK_PAGES - 1,
    ] {
        // SAFETY: INITIALIZING exclusively owns this unpublished bitmap; the
        // claim above occupied every page, and each mutation is restored.
        let cell = unsafe { control.occupied.get().cast::<u64>().add(page / 64) };
        let value = unsafe { cell.read() };
        let mask = 1_u64 << (page % 64);
        assert_ne!(value & mask, 0);
        unsafe {
            cell.write(value & !mask);
            (*pointer).phase.store(NATIVE, Ordering::Release);
        }
        assert_eq!(refused_output(), libc::EINVAL);
        assert_eq!(
            unsafe { (*pointer).phase.load(Ordering::Acquire) },
            ADOPTING
        );
        unsafe { cell.write(value) };
    }
    // reserve_inner already initialized the permanent arena bands. Repeating
    // setup must propagate its preflight EINVAL without writing the output or
    // releasing the live stack/initialization lease after the successful CAS.
    unsafe { (*pointer).phase.store(NATIVE, Ordering::Release) };
    assert_eq!(refused_output(), libc::EINVAL);
    assert_eq!(
        unsafe { (*pointer).phase.load(Ordering::Acquire) },
        ADOPTING
    );
}

#[cfg(feature = "fixed-syscall-gates")]
unsafe extern "C" {
    #[link_name = "reverie_inguest_trusted_syscall_ip"]
    fn legacy_native_gate();
    // The core gate owner publishes this aligned eight-byte word only after
    // the complete page is validated and sealed RX. It never returns to zero.
    #[link_name = "reverie_inguest_fixed_gates_published"]
    static FIXED_GATES_PUBLISHED: usize;
}

// Bootstrap starts before the fixed page exists; a body may publish it before
// returning or taking a native terminal path. Select before either gate's
// memory-free interval, without touching the caller's stack or Linux operands.
// The default artifact keeps its original direct gate operand and bytes.
#[cfg(feature = "fixed-syscall-gates")]
#[unsafe(naked)]
unsafe extern "C" fn native_gate() {
    core::arch::naked_asm!(
        "endbr64",
        // MOV/JRCXZ preserves incoming flags; SYSCALL already clobbers RCX/R11.
        "mov rcx, [rip + {published}]",
        "jrcxz 2f",
        "movabs r11, {fixed_entry}",
        "jmp r11",
        "2:",
        "jmp {legacy_gate}",
        published = sym FIXED_GATES_PUBLISHED,
        fixed_entry = const crate::trap::FIXED_NATIVE_ENTRY,
        legacy_gate = sym legacy_native_gate,
    );
}

#[cfg(all(test, feature = "fixed-syscall-gates"))]
mod fixed_gate_tests {
    use super::*;

    unsafe extern "C" fn unexpected_sigsys(_: i32, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        let _ = unsafe { crate::trap::raw_syscall6(libc::SYS_exit_group, [91, 0, 0, 0, 0, 0]) };
    }

    unsafe extern "C" fn install_fixed_filter() {
        unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
        unsafe { crate::signal::install_runtime_handler(libc::SIGSYS, unexpected_sigsys, 0) }
            .unwrap();
        let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates_with_signal_return(
            crate::trap::trusted_gate(),
            crate::trap::guest_syscall_gate(),
            Some(crate::signal::signal_restorer_return_ip()),
        )
        .unwrap();
        unsafe { filter.install() }.unwrap();
    }

    unsafe extern "C" fn forbidden_second_body() {
        let _ = unsafe { crate::trap::raw_syscall6(libc::SYS_exit_group, [92, 0, 0, 0, 0, 0]) };
    }

    fn repeat_after_publication(
        name: &str,
        bootstrap: unsafe extern "C" fn(unsafe extern "C" fn()),
    ) {
        const CHILD: &str = "REVERIE_FIXED_BOOTSTRAP_TERMINAL_CHILD";
        if std::env::var(CHILD).ok().as_deref() == Some(name) {
            assert!(!crate::trap::fixed_gates_published());
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            // The first real cold prefix uses the legacy gate before its body
            // publishes fixed gates. The repeat's mmap collision and terminal
            // must use the fixed gate; the installed filter excludes legacy.
            unsafe { bootstrap(install_fixed_filter) };
            assert!(crate::trap::fixed_gates_published());
            unsafe { bootstrap(forbidden_second_body) };
            unreachable!("native repeated-entry terminal unexpectedly returned");
        }
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!("{module}::{name}");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, name)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(127), "{output:?}");
    }

    #[test]
    fn published_constructor_repeat_exits_through_the_fixed_native_gate() {
        repeat_after_publication(
            "published_constructor_repeat_exits_through_the_fixed_native_gate",
            constructor_entry,
        );
    }

    #[test]
    fn published_generic_repeat_exits_through_the_fixed_native_gate() {
        repeat_after_publication(
            "published_generic_repeat_exits_through_the_fixed_native_gate",
            generic_entry,
        );
    }
}
