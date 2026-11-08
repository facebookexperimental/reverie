/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The syscall trap: trusted gate, SIGSYS handler, and dispatcher registration.
//!
//! Flow of one trapped syscall:
//!
//! 1. The guest issues a syscall; seccomp returns `SECCOMP_RET_TRAP`.
//! 2. The kernel delivers a thread-directed `SIGSYS`; `sigsys_handler` runs.
//! 3. The handler reconstructs a [`SyscallEvent`] from the `ucontext` registers
//!    and calls the registered [`SyscallDispatcher`].
//! 4. The dispatcher may forward through [`SyscallEvent::forward`], using an
//!    exact trusted syscall site and the interrupted protection-key rights.
//!    Runtime-private calls use [`raw_syscall6`]. Neither site re-traps.
//! 5. The handler writes the result into `RAX` and returns, resuming the guest.

#![allow(
    unexpected_cfgs,
    reason = "`fbcode_build` is supplied by the internal Buck build"
)]

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;
use std::cell::Cell;
use std::io;
use std::ptr;

use crate::dispatch::SyscallDispatcher;
use crate::dispatch::SyscallEvent;
use crate::seccomp::TrustedGate;
use crate::signal;
#[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
mod fixed_gates;
#[cfg(all(
    feature = "loader-private-runtime",
    target_env = "musl",
    target_arch = "x86_64"
))]
pub use fixed_gates::mapped_initial_gate_reference;
#[cfg(target_arch = "x86_64")]
pub mod frame;
#[cfg(not(target_arch = "x86_64"))]
#[path = "trap/frame_aarch64.rs"]
pub mod frame;
mod panic_report;
#[cfg(target_arch = "x86_64")]
mod pkru;

/// Frozen optional gate ABI. These constants emit no default-path code.
/// The explicit musl private-loader artifact selects its reserved runtime page;
/// this coordinate selection does not authenticate or publish that mapping.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
#[doc(hidden)]
pub const FIXED_GATE_BASE: u64 = 0x6000_e100_1000;
/// Legacy gate ABI, including GNU builds with all features enabled.
#[cfg(not(all(feature = "loader-private-runtime", target_env = "musl")))]
#[doc(hidden)]
pub const FIXED_GATE_BASE: u64 = 0x5000_0000_0000;
#[doc(hidden)]
pub const FIXED_GATE_BYTES: u64 = 4096;
#[doc(hidden)]
pub const FIXED_NATIVE_ENTRY: u64 = FIXED_GATE_BASE + 0x7c;
#[doc(hidden)]
pub const FIXED_GUEST_ENTRY: u64 = FIXED_GATE_BASE + 0x100;
#[doc(hidden)]
pub const FIXED_SIGNAL_RESTORER_ENTRY: u64 = FIXED_GATE_BASE + 0x300;
#[doc(hidden)]
pub const FIXED_SIGNAL_RESTORER_RETURN_IP: u64 = FIXED_GATE_BASE + 0x30b;

/// Whether this process permanently selected the fully sealed fixed gate page.
pub fn fixed_gates_published() -> bool {
    #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
    {
        fixed_gates::published()
    }
    #[cfg(not(all(feature = "fixed-syscall-gates", target_arch = "x86_64")))]
    {
        false
    }
}

/// The exact dedicated owned range after publication, including page padding.
pub fn fixed_gate_region() -> Option<(u64, u64)> {
    fixed_gates_published().then_some((FIXED_GATE_BASE, FIXED_GATE_BASE + FIXED_GATE_BYTES))
}

/// The exact runtime instruction addresses [`is_runtime_text`]
/// denies, before page-granular cover. Split out so tests can
/// assert membership independent of link layout (a page-rule-only
/// test passes by accident whenever the link happens to co-locate
/// the restorer with a gate).
pub(crate) fn runtime_text_ips() -> [u64; 8] {
    [
        trusted_gate().syscall_ip,
        trusted_gate().return_ip,
        guest_syscall_gate().syscall_ip,
        guest_syscall_gate().return_ip,
        sigsys_handler as *const () as usize as u64,
        FIXED_SIGNAL_RESTORER_ENTRY,
        // The private (non-fixed-gate) signal restorer actually in
        // use when fixed gates are unpublished, and its reported
        // return IP: patching either breaks every signal return.
        crate::signal::signal_restorer(),
        crate::signal::signal_restorer_return_ip(),
    ]
}

/// Whether `addr` lies in runtime-owned text a lazy promoter must
/// never patch: the published fixed-gate region (when sealed), the
/// pages holding the trusted and guest syscall gate instructions,
/// the fixed signal-restorer entry, and the SIGSYS handler entry.
/// Flipping any of these would break the runtime's own syscall
/// path, including the promoter's store path itself.
pub fn is_runtime_text(addr: u64) -> bool {
    if let Some((lo, hi)) = fixed_gate_region()
        && addr >= lo
        && addr < hi
    {
        return true;
    }
    let ips = runtime_text_ips();
    if ips.contains(&addr) {
        return true;
    }
    // Page-granular cover: gate/handler text shares pages with the
    // exact instruction addresses above; deny the whole pages so a
    // site a few bytes into the same page cannot slip through.
    if let Ok(page) = crate::arch::page_size()
        && page.is_power_of_two()
    {
        let page_base = addr & !(page - 1);
        return ips.iter().any(|ip| ip & !(page - 1) == page_base);
    }
    false
}

/// Prepare the optional page using legacy bootstrap syscalls, RW then RX.
/// Collision refuses; no existing mapping is adopted. Publication is permanent.
///
/// # Safety
/// The owner must call at its single FullTool installation boundary, before
/// ANY runtime handler/action/filter is published and while no other thread
/// can prepare or alter the mapping. No inherited/foreign filter is admitted.
/// Later installation failure must terminate through the selected gate; the
/// page must never be unmapped or reverted after successful publication.
pub unsafe fn prepare_fixed_gates() -> io::Result<()> {
    #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
    {
        unsafe { fixed_gates::prepare() }
    }
    #[cfg(not(all(feature = "fixed-syscall-gates", target_arch = "x86_64")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed syscall gates are not compiled",
        ))
    }
}

/// Whether the runtime's installation found OSPKE enabled (RDPKRU and WRPKRU
/// run); false before installation.
pub fn pkru_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        pkru::present()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // This implementation does not use protection keys off x86-64
        // (aarch64 POE rights are not observed yet), so none is present.
        false
    }
}

#[cfg(all(feature = "exec-private-init", target_arch = "x86_64"))]
pub(crate) fn prepare_private_signal_features() -> io::Result<bool> {
    frame::initialize()?;
    pkru::initialize()
}

#[cfg(all(feature = "exec-private-init", not(target_arch = "x86_64")))]
pub(crate) fn prepare_private_signal_features() -> io::Result<bool> {
    frame::initialize()?;
    Ok(false)
}
const SYS_SECCOMP_CODE: libc::c_int = 1;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .pushsection .text.reverie_inguest_trusted_syscall,"ax",@progbits
    .p2align 4
    .global reverie_inguest_trusted_syscall
    .hidden reverie_inguest_trusted_syscall
    .type reverie_inguest_trusted_syscall,@function
reverie_inguest_trusted_syscall:
    // Ordinary seven-scalar SysV entry: preserve the caller's R12 and frame.
    push r12
    lea r12, [rip + .Lreverie_inguest_trusted_return]
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, [rsp + 16]
    .global reverie_inguest_trusted_syscall_ip
    .hidden reverie_inguest_trusted_syscall_ip
reverie_inguest_trusted_syscall_ip:
    // Native assembly entry: Linux syscall registers, R12 = continuation.
    // This interval neither reads nor writes caller memory. Native callers
    // own R12 preservation; this entry is NOT a C function or unwind frame.
    syscall
    .global reverie_inguest_trusted_syscall_return_ip
    .hidden reverie_inguest_trusted_syscall_return_ip
reverie_inguest_trusted_syscall_return_ip:
    jmp r12
.Lreverie_inguest_trusted_return:
    endbr64
    pop r12
    ret
    .size reverie_inguest_trusted_syscall, .-reverie_inguest_trusted_syscall
    .popsection

    .text
    .p2align 4
    .global reverie_inguest_guest_syscall
    .hidden reverie_inguest_guest_syscall
    .type reverie_inguest_guest_syscall,@function
reverie_inguest_guest_syscall:
    // SysV arguments: number, pointer to six arguments, interrupted PKRU.
    // Save all stack state and load all memory while caller access is intact.
    push r12
    push r13
    push r14
    push r15
    mov r12d, edx
    mov r13, rdi
    mov r14, [rsi + 16]
    mov rdi, [rsi]
    mov rdx, [rsi + 8]
    mov r10, [rsi + 24]
    mov r8, [rsi + 32]
    mov r9, [rsi + 40]
    mov rsi, rdx
    xor ecx, ecx
    rdpkru
    mov r15d, eax
    mov eax, r12d
    xor edx, edx
    wrpkru
    lfence
    mov rax, r13
    mov rdx, r14
    .global reverie_inguest_guest_syscall_ip
    .hidden reverie_inguest_guest_syscall_ip
reverie_inguest_guest_syscall_ip:
    syscall
    .global reverie_inguest_guest_syscall_return_ip
    .hidden reverie_inguest_guest_syscall_return_ip
reverie_inguest_guest_syscall_return_ip:
    // The guest may deny this very stack. Restore caller rights entirely in
    // registers before any stack/global/TLS access, also in a COW fork child.
    mov r12, rax
    // Capture Linux's actual returned rights even when RAX is negative. A
    // syscall error does not prove that the operation had no partial effects.
    xor ecx, ecx
    rdpkru
    mov r14d, eax
    mov eax, r15d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rax, r12
    mov edx, r14d
    pop r15
    pop r14
    pop r13
    pop r12
    ret
    .size reverie_inguest_guest_syscall, .-reverie_inguest_guest_syscall
"#
);

// The aarch64 gates keep the same symbols and Rust signatures. Differences
// from x86-64, all forced by the architecture: `svc` preserves x30, so no
// continuation register is needed (the native entry takes kernel registers
// with x30 as its continuation, as a plain `bl` leaves it); each entry
// starts with the `bti c` landing pad a BTI-guarded indirect call requires;
// and there is no PKRU, so the guest gate performs no permission switch
// and its result's rights word is zero (callers on this architecture never
// observe it: see `raw_syscall6_with_result`).
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
    .pushsection .text.reverie_inguest_trusted_syscall,"ax",@progbits
    .p2align 4
    .global reverie_inguest_trusted_syscall
    .hidden reverie_inguest_trusted_syscall
    .type reverie_inguest_trusted_syscall,@function
reverie_inguest_trusted_syscall:
    // AAPCS64 entry: x0 = number, x1..x6 = args. Shuffle to kernel regs.
    bti c
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    .global reverie_inguest_trusted_syscall_ip
    .hidden reverie_inguest_trusted_syscall_ip
reverie_inguest_trusted_syscall_ip:
    // Native assembly entry: Linux syscall registers, x30 = continuation.
    svc #0
    .global reverie_inguest_trusted_syscall_return_ip
    .hidden reverie_inguest_trusted_syscall_return_ip
reverie_inguest_trusted_syscall_return_ip:
    ret
    .size reverie_inguest_trusted_syscall, .-reverie_inguest_trusted_syscall
    .popsection

    .text
    .p2align 4
    .global reverie_inguest_guest_syscall
    .hidden reverie_inguest_guest_syscall
    .type reverie_inguest_guest_syscall,@function
reverie_inguest_guest_syscall:
    // AAPCS64: x0 = number, x1 = args pointer, w2 = rights (none here).
    bti c
    mov x8, x0
    mov x9, x1
    ldr x0, [x9]
    ldr x1, [x9, #8]
    ldr x2, [x9, #16]
    ldr x3, [x9, #24]
    ldr x4, [x9, #32]
    ldr x5, [x9, #40]
    .global reverie_inguest_guest_syscall_ip
    .hidden reverie_inguest_guest_syscall_ip
reverie_inguest_guest_syscall_ip:
    svc #0
    .global reverie_inguest_guest_syscall_return_ip
    .hidden reverie_inguest_guest_syscall_return_ip
reverie_inguest_guest_syscall_return_ip:
    mov x1, xzr
    ret
    .size reverie_inguest_guest_syscall, .-reverie_inguest_guest_syscall
"#
);

// SysV classifies this concrete 16-byte integer pair into RAX and RDX. Rust's
// Option layout never crosses the assembly boundary.
#[repr(C)]
struct GuestSyscallResult {
    result: i64,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pkru: u64,
}

const _: () = {
    assert!(std::mem::size_of::<GuestSyscallResult>() == 16);
    assert!(std::mem::align_of::<GuestSyscallResult>() == 8);
    assert!(std::mem::offset_of!(GuestSyscallResult, result) == 0);
    assert!(std::mem::offset_of!(GuestSyscallResult, pkru) == 8);
};

unsafe extern "C" {
    fn reverie_inguest_trusted_syscall(
        number: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> i64;
    static reverie_inguest_trusted_syscall_ip: u8;
    static reverie_inguest_trusted_syscall_return_ip: u8;
    fn reverie_inguest_guest_syscall(
        number: i64,
        args: *const u64,
        pkru: u32,
    ) -> GuestSyscallResult;
    static reverie_inguest_guest_syscall_ip: u8;
    static reverie_inguest_guest_syscall_return_ip: u8;
}

/// The registered dispatcher, as a leaked thin pointer to a boxed trait object.
static DISPATCHER: AtomicPtr<Box<dyn SyscallDispatcher>> = AtomicPtr::new(ptr::null_mut());

thread_local! {
    /// Per-thread reentrancy guard. The const initializer and no-drop `Cell`
    /// select native TLS without Rust's lazy-initialization state machine.
    /// The panic hook in [`panic_report`] also reads it, to recognize a panic
    /// raised inside the handler.
    static IN_HANDLER: Cell<bool> = const { Cell::new(false) };
}

/// Maximum number of distinct lazy-promotion candidates retained as known
/// for the process lifetime; draining advances a cursor and frees no slots
/// in this slice. Overflow attempts are counted (including repeats of an
/// address that was never retained) and the affected sites remain on the
/// ordinary trap path; capacity never changes syscall forwarding behavior,
/// and a full table does not imply promotion coverage.
#[cfg(target_arch = "aarch64")]
pub const PENDING_PROMOTION_CAPACITY: usize = 64;

/// Result of attempting to record one first-seen trapped `svc` site.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingPromotionRecord {
    /// This is the first observation of the site and it is now pending.
    NewSite,
    /// This site has already been recorded, whether or not it has drained.
    AlreadyKnown,
    /// The fixed table is full; this candidate was not retained.
    TableFull,
    /// Ordinary-context code held the table when the handler ran. The
    /// handler does not spin or wait; this candidate was not retained.
    Contended,
}

/// Snapshot of lazy-promotion candidate accounting.
///
/// Known sites are retained after drain so an unflipped site that traps
/// again is recognized rather than repeatedly queued for the promoter.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingPromotionStats {
    /// Distinct candidates currently waiting to be drained.
    pub pending: usize,
    /// Distinct known candidates accepted since process start, including
    /// drained candidates retained for de-duplication.
    pub recorded_new: u64,
    /// Record attempts rejected because the fixed table was full. This
    /// counts attempts, including repeats of an address never retained,
    /// not distinct dropped sites.
    pub capacity_dropped: u64,
    /// Record attempts dropped because the handler could not immediately
    /// acquire the table without waiting.
    pub contended_dropped: u64,
}

#[cfg(target_arch = "aarch64")]
struct PendingPromotionData {
    sites: [u64; PENDING_PROMOTION_CAPACITY],
    known_len: usize,
    drained_len: usize,
    capacity_dropped: u64,
}

#[cfg(target_arch = "aarch64")]
struct PendingPromotions {
    /// Owner word: 0 = unowned, a plain pid = that process owns the
    /// contents, pid | PENDING_OWNER_RESETTING = that pid is resetting.
    /// Tagging the resetting state with its pid lets a fork child tell a
    /// live same-process reset (wait or drop) from a copied marker whose
    /// resetter vanished with the parent (steal and complete it).
    owner: core::sync::atomic::AtomicU64,
    locked: core::sync::atomic::AtomicBool,
    data: core::cell::UnsafeCell<PendingPromotionData>,
    contended_dropped: core::sync::atomic::AtomicU64,
}

// SAFETY: data is accessed only under `locked`, or by the single thread
// performing a post-fork reset while every other accessor either spins on
// the resetting owner word or (handler path) drops its record attempt.
#[cfg(target_arch = "aarch64")]
unsafe impl Sync for PendingPromotions {}

#[cfg(target_arch = "aarch64")]
const PENDING_OWNER_RESETTING: u64 = 1 << 63;

// No thread-local owner cache exists, by design: a fork copies the
// parent thread's TLS, so any cached pid would falsely match the copied
// owner word in the child and the handler fast path would trust the
// parent's ownership. Every record revalidates by getpid instead.

#[cfg(target_arch = "aarch64")]
impl PendingPromotions {
    const fn new() -> Self {
        Self {
            owner: core::sync::atomic::AtomicU64::new(0),
            locked: core::sync::atomic::AtomicBool::new(false),
            data: core::cell::UnsafeCell::new(PendingPromotionData {
                sites: [0; PENDING_PROMOTION_CAPACITY],
                known_len: 0,
                drained_len: 0,
                capacity_dropped: 0,
            }),
            contended_dropped: core::sync::atomic::AtomicU64::new(0),
        }
    }

    fn gate_getpid() -> u64 {
        // SAFETY: scalar getpid through the trusted gate.
        unsafe { raw_syscall6_gate(libc::SYS_getpid, [0; 6]) as u64 }
    }

    /// The reset body shared by both reset paths. Caller guarantees no
    /// other accessor can hold or race the table (owner-word protocol
    /// for ensure_owner, sole-survivor for the fork-child path).
    fn reset_contents(&self, pid: u64) {
        use core::sync::atomic::Ordering;
        // SAFETY: exclusive by the caller's guarantee above.
        unsafe {
            *self.data.get() = PendingPromotionData {
                sites: [0; PENDING_PROMOTION_CAPACITY],
                known_len: 0,
                drained_len: 0,
                capacity_dropped: 0,
            };
        }
        self.contended_dropped.store(0, Ordering::Relaxed);
        self.locked.store(false, Ordering::Relaxed);
        self.owner.store(pid, Ordering::Release);
    }

    /// Establish this process as table owner, resetting inherited fork
    /// state without ever acquiring the inherited lock bit. The resetting
    /// owner word carries its pid: a same-process reset is waited out
    /// (or, with `wait == false` on the handler path, reported
    /// not-established), while a copied marker naming another pid is a
    /// dead parent's interrupted reset and is stolen and completed here.
    fn ensure_owner(&self, wait: bool) -> bool {
        use core::sync::atomic::Ordering;
        let pid = Self::gate_getpid();
        loop {
            let word = self.owner.load(Ordering::Acquire);
            let tagged = word & PENDING_OWNER_RESETTING != 0;
            let owner_pid = word & !PENDING_OWNER_RESETTING;
            if !tagged && owner_pid == pid {
                return true;
            }
            if tagged && owner_pid == pid {
                // A live reset by another thread of THIS process.
                if !wait {
                    return false;
                }
                core::hint::spin_loop();
                continue;
            }
            if !tagged && owner_pid == 0 {
                // First establishment in this process: the table has
                // no previous owner, so its lock and contents are
                // legitimate and must not be reset.
                if self
                    .owner
                    .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    return true;
                }
                continue;
            }
            // A different pid owns it, settled or mid-reset: that process
            // is gone from this address space (fresh start or fork), and
            // its threads cannot hold the lock here. Claim the reset.
            if self
                .owner
                .compare_exchange(
                    word,
                    pid | PENDING_OWNER_RESETTING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.reset_contents(pid);
                return true;
            }
        }
    }

    /// Reset after a physically proven fork (see the handler): the
    /// kernel returned 0 for a fork-family call AND this process's TGID
    /// differs from the table owner. A dispatcher-synthesized zero in
    /// the parent (TGID still the owner's) and a clone-thread return
    /// (same TGID) both fail the second conjunct, so neither can clear
    /// a live parent's lock or contents. In a proven child this thread
    /// is the sole survivor and guest code has not run yet.
    fn reset_if_physical_child(&self) {
        use core::sync::atomic::Ordering;
        let pid = Self::gate_getpid();
        let owner_pid = self.owner.load(Ordering::Acquire) & !PENDING_OWNER_RESETTING;
        if owner_pid == pid {
            return;
        }
        self.reset_contents(pid);
    }

    fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
    }

    fn lock(&self) {
        while !self.try_lock() {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.locked
            .store(false, core::sync::atomic::Ordering::Release);
    }

    fn try_record(&self, site: u64) -> PendingPromotionRecord {
        use core::sync::atomic::Ordering;
        // The promoter's own island SVCs are not candidates: they
        // are already "known" by construction, and recording them
        // would burn lifetime table capacity on every flip.
        if promotion_island_denied(site) {
            return PendingPromotionRecord::AlreadyKnown;
        }
        if !self.ensure_owner(false) {
            self.contended_dropped.fetch_add(1, Ordering::Relaxed);
            return PendingPromotionRecord::Contended;
        }
        if !self.try_lock() {
            self.contended_dropped.fetch_add(1, Ordering::Relaxed);
            return PendingPromotionRecord::Contended;
        }
        // SAFETY: lock held; see Sync impl.
        let state = unsafe { &mut *self.data.get() };
        let result = if state.sites[..state.known_len].contains(&site) {
            PendingPromotionRecord::AlreadyKnown
        } else if state.known_len == PENDING_PROMOTION_CAPACITY {
            state.capacity_dropped += 1;
            PendingPromotionRecord::TableFull
        } else {
            let insertion = state.known_len;
            state.sites[insertion] = site;
            state.known_len += 1;
            PendingPromotionRecord::NewSite
        };
        self.unlock();
        result
    }

    fn drain(&self, out: &mut [u64]) -> usize {
        self.ensure_owner(true);
        self.lock();
        // SAFETY: lock held; see Sync impl.
        let state = unsafe { &mut *self.data.get() };
        let available = state.known_len - state.drained_len;
        let count = available.min(out.len());
        let start = state.drained_len;
        out[..count].copy_from_slice(&state.sites[start..start + count]);
        state.drained_len += count;
        self.unlock();
        count
    }

    fn stats(&self) -> PendingPromotionStats {
        self.ensure_owner(true);
        self.lock();
        // SAFETY: lock held; see Sync impl.
        let state = unsafe { &*self.data.get() };
        let stats = PendingPromotionStats {
            pending: state.known_len - state.drained_len,
            recorded_new: state.known_len as u64,
            capacity_dropped: state.capacity_dropped,
            contended_dropped: self
                .contended_dropped
                .load(core::sync::atomic::Ordering::Relaxed),
        };
        self.unlock();
        stats
    }
}

#[cfg(target_arch = "aarch64")]
static PENDING_PROMOTIONS: PendingPromotions = PendingPromotions::new();

/// Island ranges whose trapped SVCs must never consume a pending
/// slot. The current island shape re-executes SVC on every promoted
/// call, so without this denylist each flip would permanently burn
/// table capacity on its own island. Ranges live outside the
/// fork-reset table contents: island mappings survive fork at the
/// same addresses, so the denylist stays correct in the child.
#[cfg(target_arch = "aarch64")]
const PROMOTION_ISLAND_CAPACITY: usize = 64;
#[cfg(target_arch = "aarch64")]
static PROMOTION_ISLANDS: [core::sync::atomic::AtomicU64; PROMOTION_ISLAND_CAPACITY * 2] =
    [const { core::sync::atomic::AtomicU64::new(0) }; PROMOTION_ISLAND_CAPACITY * 2];
#[cfg(target_arch = "aarch64")]
static PROMOTION_ISLAND_LEN: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[cfg(target_arch = "aarch64")]
fn promotion_island_denied(site: u64) -> bool {
    use core::sync::atomic::Ordering;
    let len = PROMOTION_ISLAND_LEN.load(Ordering::Acquire);
    for i in 0..len {
        let lo = PROMOTION_ISLANDS[i * 2].load(Ordering::Acquire);
        let hi = PROMOTION_ISLANDS[i * 2 + 1].load(Ordering::Acquire);
        if site >= lo && site < hi {
            return true;
        }
    }
    false
}

/// Register one island payload range `[lo, hi)` whose SVCs are the
/// promoter's own, never promotion candidates. Ordinary context
/// only (called by the promoter after admission, before the flip
/// that makes the island reachable). Returns false when the fixed
/// range table is full; the caller must then refuse the flip rather
/// than let the island burn pending-table slots.
///
/// Publication is safe against the handler's lock-free scan: the
/// slot is claimed by CAS on its (nonzero) lo word, hi is stored
/// next, and only then is the visible length published with
/// `fetch_max`. The handler therefore never indexes past the
/// claimed array and never sees a half-written range as live
/// (lo == 0 marks an unclaimed slot; hi == 0 an empty range).
#[cfg(target_arch = "aarch64")]
pub fn register_pending_promotion_island(lo: u64, hi: u64) -> bool {
    use core::sync::atomic::Ordering;
    if lo >= hi || lo == 0 {
        return false;
    }
    for idx in 0..PROMOTION_ISLAND_CAPACITY {
        let seen_lo = PROMOTION_ISLANDS[idx * 2].load(Ordering::Acquire);
        if seen_lo == lo && PROMOTION_ISLANDS[idx * 2 + 1].load(Ordering::Acquire) == hi {
            return true; // exact range already registered
        }
        if seen_lo != 0 {
            continue;
        }
        if PROMOTION_ISLANDS[idx * 2]
            .compare_exchange(0, lo, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue; // lost the claim; scan on (may now be our dup)
        }
        PROMOTION_ISLANDS[idx * 2 + 1].store(hi, Ordering::Release);
        PROMOTION_ISLAND_LEN.fetch_max(idx + 1, Ordering::AcqRel);
        return true;
    }
    false
}

/// Remove one previously registered island range (exact match).
/// The promoter calls this when an admitted flip attempt is
/// refused before its branch lands, so refused attempts never
/// burn lifetime range slots and a stale range cannot hide real
/// guest SVC sites later mapped at the same address. Returns
/// false when the exact range was not registered.
#[cfg(target_arch = "aarch64")]
pub fn unregister_pending_promotion_island(lo: u64, hi: u64) -> bool {
    use core::sync::atomic::Ordering;
    let len = PROMOTION_ISLAND_LEN.load(Ordering::Acquire);
    for i in 0..len {
        if PROMOTION_ISLANDS[i * 2].load(Ordering::Acquire) == lo
            && PROMOTION_ISLANDS[i * 2 + 1].load(Ordering::Acquire) == hi
        {
            // Empty this slot first (hi := lo makes the range
            // empty), then swap the last range in and only then
            // shrink the visible length. This is NOT torn-free: a
            // racing handler can observe the transient range
            // [llo, lo_i) (new lo, not-yet-stored hi) or miss the
            // moving range entirely, because the reader also loads
            // lo and hi separately. The consequence is liveness
            // only, never safety: a guest SVC inside the transient
            // span can be spuriously reported AlreadyKnown once
            // (it was not inserted, so its next trap records it),
            // or one island SVC can burn a pending-table slot (the
            // promoter later refuses it: shared island mappings
            // are not windowable). No torn range can make a real
            // site silently patchable or hide one for good, and
            // the length protocol still bounds every index.
            let last = len - 1;
            PROMOTION_ISLANDS[i * 2 + 1].store(lo, Ordering::Release);
            if i != last {
                let llo = PROMOTION_ISLANDS[last * 2].load(Ordering::Acquire);
                let lhi = PROMOTION_ISLANDS[last * 2 + 1].load(Ordering::Acquire);
                PROMOTION_ISLANDS[i * 2].store(llo, Ordering::Release);
                PROMOTION_ISLANDS[i * 2 + 1].store(lhi, Ordering::Release);
                PROMOTION_ISLANDS[last * 2].store(0, Ordering::Release);
                PROMOTION_ISLANDS[last * 2 + 1].store(0, Ordering::Release);
            } else {
                PROMOTION_ISLANDS[i * 2].store(0, Ordering::Release);
                PROMOTION_ISLANDS[i * 2 + 1].store(0, Ordering::Release);
            }
            PROMOTION_ISLAND_LEN.store(last, Ordering::Release);
            return true;
        }
    }
    false
}

/// Record the first observation of a candidate lazy-promotion site without
/// allocating or waiting in signal context.
///
/// This is record-only plumbing for a future patch promoter. It does not
/// inspect, patch, or otherwise alter guest code.
#[cfg(target_arch = "aarch64")]
pub fn record_pending_promotion_site(site: u64) -> PendingPromotionRecord {
    PENDING_PROMOTIONS.try_record(site)
}

/// Remove up to `out.len()` pending sites in first-observed order and
/// return how many were copied. Intended for ordinary runtime context; this
/// function may briefly spin if a handler currently holds the table.
#[cfg(target_arch = "aarch64")]
pub fn drain_pending_promotion_sites(out: &mut [u64]) -> usize {
    PENDING_PROMOTIONS.drain(out)
}

/// Snapshot pending-site accounting from ordinary runtime context.
#[cfg(target_arch = "aarch64")]
pub fn pending_promotion_stats() -> PendingPromotionStats {
    PENDING_PROMOTIONS.stats()
}

/// Execute a real syscall through the trusted gate.
///
/// The gate's `syscall` instruction is whitelisted in the seccomp filter, so
/// this does not re-trap. Runtime-private buffers use this gate; forwarding a
/// guest event uses [`SyscallEvent::forward`] to retain interrupted permissions.
///
/// # Safety
///
/// Issues a raw syscall with caller-supplied arguments.
/// The call must return through its original stack; this is not an ordinary
/// wrapper for `rt_sigreturn` or `clone` with a replaced child stack.
pub unsafe fn raw_syscall6(number: i64, args: [u64; 6]) -> i64 {
    // Fixed-VL envelope (aarch64): never issue a VL-changing prctl from
    // inside the SIGSYS handler, whatever entry a dispatcher took.
    #[cfg(target_arch = "aarch64")]
    if IN_HANDLER.get() && vl_change_refused(number, args) {
        return refuse_vl_change();
    }
    unsafe { raw_syscall6_gate(number, args) }
}

/// The trusted-gate call itself, without the fixed-VL boundary check
/// (the boundary's own VL probe must not recurse into it).
///
/// # Safety
/// As [`raw_syscall6`].
unsafe fn raw_syscall6_gate(number: i64, args: [u64; 6]) -> i64 {
    #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
    if fixed_gates_published() {
        return unsafe { fixed_gates::scalar(number, args) };
    }
    unsafe {
        reverie_inguest_trusted_syscall(
            number as u64,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
        )
    }
}

/// Scalar entry used while constructing unpublished Tool state. Keeping the
/// arguments separate avoids compiler-generated aggregate copies through libc
/// before the Tool is ready. This reaches the same trusted syscall gate.
///
/// # Safety
/// The syscall arguments and original return stack must remain valid, exactly
/// as for `raw_syscall6`; unused syscall arguments are zero.
#[inline(never)]
pub(crate) unsafe fn raw_syscall3(number: i64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    #[cfg(target_arch = "aarch64")]
    if IN_HANDLER.get() && vl_change_refused(number, [arg0, arg1, arg2, 0, 0, 0]) {
        return refuse_vl_change();
    }
    #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
    if fixed_gates_published() {
        return unsafe { fixed_gates::scalar3_or6(number, arg0, arg1, arg2, 0, 0, 0) };
    }
    unsafe { reverie_inguest_trusted_syscall(number as u64, arg0, arg1, arg2, 0, 0, 0) }
}

/// Execute a guest syscall with its interrupted protection-key permissions.
///
/// The kernel performs the actual copies, including partial transfers and real
/// errno results. Caller permissions are restored before any return-stack
/// access. Runtime-private scratch must continue to use [`raw_syscall6`].
///
/// # Safety
///
/// OSPKE must be enabled, both trusted gates must be permitted by any installed
/// filter, and the raw syscall arguments must obey the caller's contract.
/// Like the ordinary gate, this cannot resume a clone with a different stack
/// and must not be used as an ordinary wrapper around rt_sigreturn.
pub unsafe fn raw_syscall6_with_pkru(number: i64, args: [u64; 6], pkru: u32) -> i64 {
    #[cfg(target_arch = "aarch64")]
    if IN_HANDLER.get() && vl_change_refused(number, args) {
        return refuse_vl_change();
    }
    #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
    if fixed_gates_published() {
        return unsafe { fixed_gates::guest(number, &args, pkru).result };
    }
    unsafe { reverie_inguest_guest_syscall(number, args.as_ptr(), pkru).result }
}

/// The scalar result and, when requested, permissions returned by one physical
/// syscall. This does not update a dispatcher, signal frame or guest context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeSyscallResult {
    pub result: i64,
    /// Actual PKRU immediately after the syscall, including an error result.
    /// `None` means the caller selected the scalar gate without a permission
    /// observation; it does not independently certify hardware absence.
    pub pkru: Option<u32>,
}

/// Execute one native syscall with its original arguments and observe its
/// returned permissions before restoring the caller's permissions.
///
/// `Some(pkru)` selects the existing exact guest gate. `None` selects the
/// existing scalar gate and executes no PKRU instructions, including on a CPU
/// without OSPKE. Capability-aware callers establish support before selecting
/// `Some`; this function performs no CPUID operation during interception.
///
/// # Safety
///
/// The caller must uphold the safety of successful kernel writes, mapping
/// changes and other operation effects. Invalid or denied original pointers
/// with a kernel-defined error such as EFAULT remain admitted. `Some` requires
/// OSPKE, and the selected exact trusted gate must be allowed by any
/// installed syscall filter. Caller permissions must allow this helper's call
/// and return storage before and after the syscall. The operation must not
/// unmap or revoke that storage, resume a clone on a different stack, or use
/// ordinary wrapper return for rt_sigreturn. These are internal raw-helper
/// requirements, not restrictions on guest syscalls: an integrating runtime
/// must own surviving callback/return storage before forwarding such calls.
/// Original guest pointers are passed unchanged and checked by Linux under the
/// supplied guest permissions. Caller permissions are restored before the first
/// return-side memory access, even if Linux changes PKRU or returns an error.
pub unsafe fn raw_syscall6_with_result(
    number: i64,
    args: [u64; 6],
    guest_pkru: Option<u32>,
) -> NativeSyscallResult {
    // Fixed-VL boundary at the forwarding issue point: a dispatcher that
    // rewrote a forwarded event into a VL change is refused here, with
    // the caller's observed rights unchanged (nothing was issued).
    #[cfg(target_arch = "aarch64")]
    if IN_HANDLER.get() && vl_change_refused(number, args) {
        return NativeSyscallResult {
            result: refuse_vl_change(),
            pkru: guest_pkru,
        };
    }
    match guest_pkru {
        Some(pkru) => {
            #[cfg(all(feature = "fixed-syscall-gates", target_arch = "x86_64"))]
            let result = if fixed_gates_published() {
                unsafe { fixed_gates::guest(number, &args, pkru) }
            } else {
                unsafe { reverie_inguest_guest_syscall(number, args.as_ptr(), pkru) }
            };
            #[cfg(not(all(feature = "fixed-syscall-gates", target_arch = "x86_64")))]
            let result = unsafe { reverie_inguest_guest_syscall(number, args.as_ptr(), pkru) };
            // This implementation observes no protection-key rights off
            // x86-64 (aarch64 POE is not observed yet):
            // the guest gate executes with caller rights and reports none.
            #[cfg(target_arch = "x86_64")]
            let observed_pkru = Some(result.pkru as u32);
            #[cfg(not(target_arch = "x86_64"))]
            let observed_pkru = None;
            NativeSyscallResult {
                result: result.result,
                pkru: observed_pkru,
            }
        }
        None => NativeSyscallResult {
            result: unsafe { raw_syscall6(number, args) },
            pkru: None,
        },
    }
}

/// Execute a physical guest operation using the guest's native thread state.
/// Bookkeeping syscalls keep using [`raw_syscall6`] and retain Tool FS.
///
/// # Safety
/// The same storage, operation and PKRU requirements as
/// [`raw_syscall6_with_result`] apply. An authenticated private-loader runtime
/// additionally requires its ordinary Tool callback phase.
pub unsafe fn physical_guest_syscall6(
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
) -> NativeSyscallResult {
    #[cfg(all(feature = "exec-private-init", target_arch = "x86_64"))]
    if crate::guest::exec_private::active() {
        return unsafe { crate::guest::exec_private::physical_syscall(number, args, pkru) };
    }
    unsafe { raw_syscall6_with_result(number, args, pkru) }
}

/// The address range of the trusted gate, for building the seccomp filter.
pub fn trusted_gate() -> TrustedGate {
    #[cfg(feature = "fixed-syscall-gates")]
    if fixed_gates_published() {
        return TrustedGate {
            syscall_ip: FIXED_GATE_BASE + 0x80,
            return_ip: FIXED_GATE_BASE + 0x82,
        };
    }
    TrustedGate {
        syscall_ip: ptr::addr_of!(reverie_inguest_trusted_syscall_ip) as usize as u64,
        return_ip: ptr::addr_of!(reverie_inguest_trusted_syscall_return_ip) as usize as u64,
    }
}

/// The second exact gate, used only for guest forwarding on OSPKE machines.
/// Its addresses can be allowlisted on any CPU; unsupported CPUs never execute
/// its RDPKRU/WRPKRU instructions.
pub fn guest_syscall_gate() -> TrustedGate {
    #[cfg(feature = "fixed-syscall-gates")]
    if fixed_gates_published() {
        return TrustedGate {
            syscall_ip: FIXED_GATE_BASE + 0x200,
            return_ip: FIXED_GATE_BASE + 0x202,
        };
    }
    TrustedGate {
        syscall_ip: ptr::addr_of!(reverie_inguest_guest_syscall_ip) as usize as u64,
        return_ip: ptr::addr_of!(reverie_inguest_guest_syscall_return_ip) as usize as u64,
    }
}

/// Register the process-wide syscall dispatcher.
///
/// Must be called before [`crate::seccomp::SeccompFilter::install`]. The boxed
/// dispatcher is leaked and lives for the process lifetime.
pub fn set_dispatcher(dispatcher: Box<dyn SyscallDispatcher>) {
    // Double-box to get a thin pointer we can store atomically.
    let leaked: *mut Box<dyn SyscallDispatcher> = Box::into_raw(Box::new(dispatcher));
    DISPATCHER.store(leaked, Ordering::Release);
}

/// Whether a process-wide dispatcher has already been published.
///
/// Publication precedes seccomp installation and is not rolled back on an
/// installation error. This reports that state, not successful activation.
pub fn has_dispatcher() -> bool {
    !DISPATCHER.load(Ordering::Acquire).is_null()
}

fn dispatcher() -> Option<&'static (dyn SyscallDispatcher + 'static)> {
    let ptr = DISPATCHER.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // Safety: set_dispatcher leaked this box for the process lifetime.
        Some(unsafe { &**ptr })
    }
}

fn dispatch_event(event: &mut SyscallEvent) {
    match dispatcher() {
        Some(dispatcher) => dispatcher.dispatch(event),
        None => {
            // No dispatcher registered: fail closed with ENOSYS rather than
            // silently allowing the call.
            event.set_result(-i64::from(libc::ENOSYS));
        }
    }
}

// TODO-HUMAN-REVIEW(PR-264): Review direct invocation of the registered
// dispatcher by ahead-of-time instrumentation trampolines.
// AUTONOMOUS-BOT-IMPLEMENTED
/// Dispatch a syscall from an instrumentation trampoline in ordinary context.
///
/// This enters the exact process-wide [`SyscallDispatcher`] registered for the
/// shared preload runtime, but does not install or interact with a signal
/// frame. It is intended for ahead-of-time rewriting backends such as e9patch;
/// runtime patchers continue to enter through `SIGSYS` and
/// [`SyscallEvent::defer_to`]. A dispatcher that requests deferred signal-frame
/// resumption is rejected with `-ENOTSUP` because no signal frame exists here.
pub fn dispatch_direct(number: i64, args: [u64; 6], instruction_pointer: u64) -> i64 {
    let mut event = SyscallEvent::direct(number, args, instruction_pointer);
    dispatch_event(&mut event);
    if event.resume_address().is_some() {
        -i64::from(libc::ENOTSUP)
    } else {
        event.resolved_result()
    }
}

unsafe fn exit_now(code: i32) -> ! {
    let _ = unsafe { raw_syscall6(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop();
    }
}

/// The exit status when the guest performs its own `rt_sigreturn` while the
/// filter admits it only at the runtime's private restorer
/// ([`crate::lifecycle::RuntimeConfig::restrict_signal_return`]).
pub const GUEST_SIGNAL_RETURN_STATUS: i32 = 119;

static SIGNAL_RETURN_RESTRICTED: AtomicBool = AtomicBool::new(false);

/// Whether a syscall-number register asks Linux for `rt_sigreturn`. Linux
/// reads only the register's low 32 bits as the number (as the seccomp
/// filter does), so `0x1_0000_000f` is `rt_sigreturn` too.
pub fn is_rt_sigreturn(number: i64) -> bool {
    number as u32 == libc::SYS_rt_sigreturn as u32
}

/// Record that the installed filter admits `rt_sigreturn` only at the
/// runtime's private restorer.
pub(crate) fn set_signal_return_restricted() {
    SIGNAL_RETURN_RESTRICTED.store(true, Ordering::Release);
}

/// Whether the installed filter admits `rt_sigreturn` only at the runtime's
/// private restorer. A backend that reaches the dispatcher without a trap
/// (a patched site's hook) must then refuse a guest `rt_sigreturn` itself,
/// with [`refuse_guest_signal_return`].
pub fn signal_return_restricted() -> bool {
    SIGNAL_RETURN_RESTRICTED.load(Ordering::Acquire)
}

/// End the process for a guest `rt_sigreturn` while
/// [`signal_return_restricted`]. The runtime never performs that return: the
/// frame it would restore (and the signal mask in it) is one the runtime did
/// not build, so the run is no longer one the runtime can follow.
///
/// # Safety
///
/// Ends the process at once; no destructor runs.
pub unsafe fn refuse_guest_signal_return() -> ! {
    const MESSAGE: &[u8] = b"reverie-inguest: the guest made its own rt_sigreturn; \
only the runtime's signal restorer may return from a signal, so the process ends\n";
    let _ = unsafe {
        raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                MESSAGE.as_ptr() as u64,
                MESSAGE.len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    unsafe { exit_now(GUEST_SIGNAL_RETURN_STATUS) }
}

/// The `SA_SIGINFO` handler for `SIGSYS`.
///
/// # Safety
///
/// Only the kernel calls this, on a real `SIGSYS`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe extern "C" fn sigsys_handler(
    signal_number: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-133): Review fail-closed SIGSYS provenance validation.
    if signal_number != libc::SIGSYS
        || info.is_null()
        || context.is_null()
        || unsafe { (*info).si_code } != SYS_SECCOMP_CODE
    {
        unsafe { exit_now(126) };
    }

    #[cfg(feature = "exec-private-init")]
    if unsafe { crate::guest::exec_private::relay_private_signal(signal_number, info, context) } {
        return;
    }

    // Reentrancy guard: a trapped syscall inside the handler is a bug (the
    // dispatcher must use the trusted gate). Fail closed rather than recurse.
    if IN_HANDLER.get() {
        unsafe { exit_now(125) };
    }
    IN_HANDLER.set(true);

    let mut frame = match unsafe { frame::SignalFrame::from_raw(context, info) } {
        Ok(frame) => frame,
        Err(_) => unsafe { exit_now(126) },
    };
    // The filter traps `rt_sigreturn` only when it admits it at the
    // runtime's restorer alone, so a trapped one is never the runtime's.
    if is_rt_sigreturn(frame.register(libc::REG_RAX as usize)) {
        unsafe { refuse_guest_signal_return() };
    }
    if dispatcher().is_some_and(|dispatcher| dispatcher.dispatch_private_signal(&mut frame)) {
        IN_HANDLER.set(false);
        return;
    }
    let guest_pkru = match frame.pkru() {
        Ok(value) => value,
        Err(_) => unsafe { exit_now(126) },
    };
    let mut event = SyscallEvent::new(
        frame.register(libc::REG_RAX as usize),
        [
            frame.register(libc::REG_RDI as usize) as u64,
            frame.register(libc::REG_RSI as usize) as u64,
            frame.register(libc::REG_RDX as usize) as u64,
            frame.register(libc::REG_R10 as usize) as u64,
            frame.register(libc::REG_R8 as usize) as u64,
            frame.register(libc::REG_R9 as usize) as u64,
        ],
        frame.register(libc::REG_RIP as usize) as u64,
    );
    event.set_guest_pkru(guest_pkru);

    if let Some(dispatcher) = dispatcher() {
        dispatcher.dispatch_signal(&mut event, &mut frame);
    } else {
        event.fail(libc::ENOSYS);
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    if let Some(resume_address) = event.resume_address() {
        // Preserve the syscall-number register so the replacement callback
        // observes the original entry state after sigreturn.
        frame.set_register(libc::REG_RIP as usize, resume_address as i64);
    } else {
        frame.set_register(libc::REG_RAX as usize, event.resolved_result());
        if frame.set_pkru(event.guest_pkru()).is_err() {
            unsafe { exit_now(126) };
        }
    }
    IN_HANDLER.set(false);
}

/// Fixed-VL admission envelope decision, pure over the kernel-effective
/// classification: Linux takes the syscall number and the prctl option as
/// `int`, so both are classified at that width — a register value whose
/// low 32 bits name the call IS that call, whatever its high bits carry.
/// `current` is the queried current length, or `None` when the query
/// failed: a denied GET is not evidence a SET cannot change state (a
/// filter or hook can deny them independently), so an unestablishable
/// current length refuses rather than forwards. Requests naming the
/// current length, an ONEXEC-deferred change, or a zero length (the
/// kernel rejects it itself before changing state) are not refused.
#[cfg(target_arch = "aarch64")]
fn vl_change_decision(number: i64, args: [u64; 6], current: Option<u64>) -> bool {
    const PR_SVE_SET_VL: i32 = 50;
    const PR_SME_SET_VL: i32 = 63;
    const VL_LEN_MASK: u64 = 0xffff;
    const VL_ONEXEC: u64 = 1 << 18;
    if number as i32 != libc::SYS_prctl as i32 {
        return false;
    }
    if !matches!(args[0] as i32, PR_SVE_SET_VL | PR_SME_SET_VL) {
        return false;
    }
    if args[1] & VL_ONEXEC != 0 {
        return false;
    }
    let requested = args[1] & VL_LEN_MASK;
    if requested == 0 {
        return false;
    }
    match current {
        Some(current) => requested != (current & VL_LEN_MASK),
        None => true,
    }
}

/// Whether this call, issued from inside the SIGSYS handler, would change
/// the thread's vector length under a live frame. The current length is
/// read through the unchecked gate entry, so the probe itself never traps
/// and the boundary cannot recurse into itself.
#[cfg(target_arch = "aarch64")]
fn vl_change_refused(number: i64, args: [u64; 6]) -> bool {
    const PR_SVE_SET_VL: i32 = 50;
    const PR_SVE_GET_VL: u64 = 51;
    const PR_SME_SET_VL: i32 = 63;
    const PR_SME_GET_VL: u64 = 64;
    if number as i32 != libc::SYS_prctl as i32 {
        return false;
    }
    let get_op = match args[0] as i32 {
        PR_SVE_SET_VL => PR_SVE_GET_VL,
        PR_SME_SET_VL => PR_SME_GET_VL,
        _ => return false,
    };
    // Pass-through shapes decide without a query (deferred, or the
    // kernel's own zero rejection): only a would-be change probes.
    if args[1] & (1 << 18) != 0 || args[1] & 0xffff == 0 {
        return false;
    }
    // SAFETY: a scalar prctl query through the trusted gate.
    let queried = unsafe { raw_syscall6_gate(libc::SYS_prctl, [get_op, 0, 0, 0, 0, 0]) };
    let current = (queried >= 0).then_some(queried as u64);
    vl_change_decision(number, args, current)
}

/// Issue the fixed-VL refusal: the guest sees the kernel-faithful EINVAL,
/// and the host stderr gets the envelope's name at the refusal site, so a
/// synthetic errno is never indistinguishable from a kernel decision.
#[cfg(target_arch = "aarch64")]
fn refuse_vl_change() -> i64 {
    const MESSAGE: &[u8] =
        b"reverie-inguest: fixed-VL envelope: refusing VL-changing prctl while a signal frame is live\n";
    // SAFETY: a scalar write of a static buffer through the trusted gate.
    unsafe {
        raw_syscall6_gate(
            libc::SYS_write,
            [2, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64, 0, 0, 0],
        )
    };
    -i64::from(libc::EINVAL)
}

/// The `SA_SIGINFO` handler for `SIGSYS` on aarch64: same provenance,
/// reentry, and dispatch flow as the x86-64 handler, over the aarch64
/// frame (number in x8, arguments in x0-x5, result in x0, resume at pc).
/// This implementation preserves no protection-key rights here yet
/// (aarch64 POE rights are a later stage, not an architecture claim).
///
/// # Safety
///
/// Only the kernel calls this, on a real `SIGSYS`.
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe extern "C" fn sigsys_handler(
    signal_number: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-133): Review fail-closed SIGSYS provenance validation.
    if signal_number != libc::SIGSYS
        || info.is_null()
        || context.is_null()
        || unsafe { (*info).si_code } != SYS_SECCOMP_CODE
    {
        unsafe { exit_now(126) };
    }

    // Reentrancy guard: a trapped syscall inside the handler is a bug (the
    // dispatcher must use the trusted gate). Fail closed rather than recurse.
    if IN_HANDLER.get() {
        unsafe { exit_now(125) };
    }
    IN_HANDLER.set(true);

    let mut frame = match unsafe { frame::SignalFrame::from_raw(context, info) } {
        Ok(frame) => frame,
        Err(_) => unsafe { exit_now(126) },
    };
    // The filter traps `rt_sigreturn` only when it admits it at the
    // runtime's restorer alone, so a trapped one is never the runtime's.
    if is_rt_sigreturn(frame.register(8)) {
        unsafe { refuse_guest_signal_return() };
    }
    // Record-only lazy-promotion evidence: the validated frame's PC is the
    // instruction after the 4-byte `svc`. Recording neither examines nor
    // changes the instruction and never changes whether this call is
    // dispatched or forwarded.
    if let Some(site) = (frame.register(32) as u64).checked_sub(4) {
        let _ = record_pending_promotion_site(site);
    }
    if dispatcher().is_some_and(|dispatcher| dispatcher.dispatch_private_signal(&mut frame)) {
        IN_HANDLER.set(false);
        return;
    }
    let mut event = SyscallEvent::new(
        frame.register(8),
        [
            frame.register(0) as u64,
            frame.register(1) as u64,
            frame.register(2) as u64,
            frame.register(3) as u64,
            frame.register(4) as u64,
            frame.register(5) as u64,
        ],
        frame.register(32) as u64,
    );
    event.set_guest_pkru(None);

    // Admission is a fixed-VL envelope (see vl_change_refused): a guest
    // prctl that would change the vector length under this live frame is
    // refused by name before any dispatcher can forward it.
    if vl_change_refused(event.number(), event.args()) {
        frame.set_register(0, refuse_vl_change());
        IN_HANDLER.set(false);
        return;
    }

    if let Some(dispatcher) = dispatcher() {
        dispatcher.dispatch_signal(&mut event, &mut frame);
    } else {
        event.fail(libc::ENOSYS);
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    if let Some(resume_address) = event.resume_address() {
        // Preserve the syscall-number register so the replacement callback
        // observes the original entry state after sigreturn.
        frame.set_register(32, resume_address as i64);
    } else {
        frame.set_register(0, event.resolved_result());
    }
    // In the fork child (result register 0) this thread is the sole
    // survivor and guest code has not run yet: reset the pending-site
    // table it inherited (possibly locked by a vanished parent thread)
    // before returning. Forks the handler never mediated are healed by
    // the table's PID-ownership check on first access instead.
    if crate::arch::is_fork_family(event.number()) && frame.register(0) == 0 {
        PENDING_PROMOTIONS.reset_if_physical_child();
    }
    IN_HANDLER.set(false);
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .text
    .global reverie_inguest_sigsys_pkru
    .hidden reverie_inguest_sigsys_pkru
    .type reverie_inguest_sigsys_pkru,@function
reverie_inguest_sigsys_pkru:
    // Linux enters with default PKRU, which may deny the key of the signal
    // stack itself. No stack, global, TLS, siginfo or ucontext access is safe
    // until permissions are opened. RDI/RSI/RDX are the SA_SIGINFO arguments;
    // preserve RDX in a caller-saved register across WRPKRU's fixed operands.
    mov r8, rdx
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rdx, r8
    jmp {handler}
    .size reverie_inguest_sigsys_pkru, .-reverie_inguest_sigsys_pkru
    "#,
    handler = sym sigsys_handler,
);

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn reverie_inguest_sigsys_pkru(
        signal_number: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    );
}

/// Install the SIGSYS handler (and, optionally, an alternate signal stack).
///
/// Selects the PKRU entry only when CPUID reports OSPKE and installation has
/// validated the standard XSAVE PKRU component layout. Selection happens
/// during installation, before syscall interception or CPUID faulting; the
/// signal entry itself performs no feature detection or memory access before
/// opening permissions. It then enters the unchanged provenance/reentry
/// checks. Guest registers and PKRU remain in the kernel's signal frame;
/// ordinary signal return restores them, including after deferred dispatch.
/// Signal events also retain the saved rights for actual guest forwarding;
/// opening handler access must not authorize a guest's denied syscall buffer.
/// Handler permissions stay open through return so a nondefault-key signal
/// stack remains accessible. This does not change guest signal policy.
///
/// It first installs a panic hook so that a panic inside the handler prints
/// its message and ends the process with SIGABRT instead of a bare SIGSYS
/// kill; see `trap/panic_report.rs`.
///
/// # Safety
///
/// Installs process-global signal disposition; call once during init while
/// CPUID is available, before enabling instruction faulting.
pub unsafe fn install_handler(use_alt_stack: bool) -> io::Result<()> {
    unsafe {
        install_handler_with_backing(
            use_alt_stack,
            crate::guest::tool_region::StackBacking::Legacy,
        )
    }
}

/// Install the same trap with explicitly selected alternate-stack backing.
/// Signal actions, feature qualification and permissions are unchanged.
///
/// # Safety
/// See [`install_handler`]; the selected region must already be reserved.
pub unsafe fn install_handler_with_backing(
    use_alt_stack: bool,
    backing: crate::guest::tool_region::StackBacking,
) -> io::Result<()> {
    let prepared = prepare_handler()?;
    let handler = prepared.entry();
    if use_alt_stack {
        unsafe { signal::install_alt_stack_with_backing(backing)? };
    }
    unsafe { signal::install_sigsys_handler(handler, use_alt_stack) }
}

/// Prepared real syscall-handler entry. This token owns no frontend or mapping.
pub(crate) struct PreparedHandler {
    entry: unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
}
impl PreparedHandler {
    /// The selected existing generic/private bridge after real frame/PKRU preparation.
    pub(crate) fn entry(
        &self,
    ) -> unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) {
        self.entry
    }
}
/// Finish possibly allocating/trapping preparation before an owned frontend
/// replacement interval. This does not register a stack or change a disposition.
#[cfg(target_arch = "x86_64")]
pub(crate) fn prepare_handler() -> io::Result<PreparedHandler> {
    panic_report::install();
    frame::initialize()?;
    let ospke = pkru::initialize()?;
    let handler = if ospke {
        reverie_inguest_sigsys_pkru
    } else {
        sigsys_handler
    };
    #[cfg(feature = "exec-private-init")]
    let handler = if crate::guest::exec_private::active() {
        crate::guest::exec_private::signal_entry(false, ospke)
    } else {
        handler
    };
    Ok(PreparedHandler { entry: handler })
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn prepare_handler() -> io::Result<PreparedHandler> {
    panic_report::install();
    frame::initialize()?;
    Ok(PreparedHandler {
        entry: sigsys_handler,
    })
}

#[cfg(all(feature = "exec-private-init", target_arch = "x86_64"))]
pub(crate) unsafe fn adopt_authenticated_initial_gate() -> io::Result<()> {
    unsafe { fixed_gates::adopt_authenticated_initial_page() }
}

/// Adopt the same fixed gate before mapped ToolRegion publication.
///
/// # Safety
/// The actual retained mapped first-image producer owns the complete immutable
/// RX page and inherited qualified filter at the compiled layout coordinates,
/// excludes concurrent/async/guest entry and spends its transition before this
/// call. Bytes alone never authenticate that physical ownership. Every error
/// requires immediate owned nonallocating terminal refusal with host kill/wait
/// and live mappings retained; no retry, fallback or scalar-ready activation.
/// Private TLS/kernel readbacks and subsequent region adoption remain separate.
/// `expected` satisfies the independent immutable same-source reference contract
/// of fixed_gates::adopt_mapped_initial_page; it is not an executed-page snapshot.
#[cfg(all(
    feature = "exec-private-init",
    feature = "loader-private-runtime",
    target_env = "musl",
    target_arch = "x86_64"
))]
pub(crate) unsafe fn adopt_mapped_initial_gate(expected: &'static [u8; 4096]) -> Result<(), i32> {
    // SAFETY: forwarded complete physical-producer contract.
    unsafe { fixed_gates::adopt_mapped_initial_page(expected) }
}

/// Verify the controlled native bootstrap's physical page without publication.
///
/// # Safety
/// The caller owns the actual inherited qualified gate/filter and excludes
/// Guest execution, workers and mapping changes. This proves neither admission
/// nor permission to publish a Tool or native control.
#[cfg(all(
    feature = "exec-private-init",
    feature = "coordinator-rpc",
    target_arch = "x86_64"
))]
pub(crate) unsafe fn verify_native_io_gate() -> io::Result<()> {
    unsafe { fixed_gates::verify_initial_page() }
}

/// Use the inherited scalar mechanism even while its selector is unpublished.
///
/// # Safety
/// A checked native I/O scope must retain the real qualified RX page/filter,
/// original task/private FS and valid scalar arguments/return stack. No Guest
/// may invoke this mechanism, and it supplies no image admission authority.
#[cfg(all(
    feature = "exec-private-init",
    feature = "coordinator-rpc",
    target_arch = "x86_64"
))]
pub(crate) unsafe fn native_io_syscall(number: i64, args: [u64; 6]) -> i64 {
    unsafe { fixed_gates::scalar(number, args) }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    /// Proof that a re-exec child actually ran its one selected
    /// test: a wrong `--exact` path makes libtest print
    /// "running 0 tests" and exit 0, which a status-only parent
    /// assert reads as success (the island-registry bug class).
    fn assert_child_ran(output: &std::process::Output) {
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "re-exec child ran no test (wrong --exact path?): {output:?}"
        );
    }

    #[test]
    fn runtime_text_covers_gates_and_handler() {
        assert!(is_runtime_text(trusted_gate().syscall_ip));
        assert!(is_runtime_text(trusted_gate().return_ip));
        assert!(is_runtime_text(guest_syscall_gate().syscall_ip));
        assert!(is_runtime_text(sigsys_handler as *const () as usize as u64));
        assert!(is_runtime_text(crate::signal::signal_restorer()));
        assert!(is_runtime_text(crate::signal::signal_restorer_return_ip()));
        assert!(!is_runtime_text(0x1000));
    }

    #[test]
    fn trusted_gate_addresses_are_populated_and_ordered() {
        let gate = trusted_gate();
        assert_ne!(gate.syscall_ip, 0);
        assert_ne!(gate.return_ip, 0);
        // The return site is a few bytes after the syscall instruction.
        assert!(gate.return_ip > gate.syscall_ip);
    }

    #[test]
    fn no_dispatcher_registered_by_default() {
        assert!(dispatcher().is_none());
    }

    #[test]
    fn rt_sigreturn_is_recognized_by_its_low_32_bits() {
        assert!(is_rt_sigreturn(libc::SYS_rt_sigreturn));
        assert!(is_rt_sigreturn(0x1_0000_0000 | libc::SYS_rt_sigreturn));
        assert!(is_rt_sigreturn(-0x1_0000_0000 | libc::SYS_rt_sigreturn));
        assert!(!is_rt_sigreturn(libc::SYS_rt_sigaction));
        assert!(!is_rt_sigreturn(0x4000_0000 | libc::SYS_rt_sigreturn));
    }

    #[test]
    fn sigsys_rejects_user_generated_signals_on_both_stacks() {
        const CHILD: &str = "REVERIE_TEST_SIGSYS_PROVENANCE";
        if let Some(value) = std::env::var_os(CHILD) {
            unsafe {
                install_handler(value == "1").unwrap();
                libc::raise(libc::SIGSYS);
            }
            panic!("a user-generated SIGSYS returned from the handler");
        }
        for on_alt_stack in ["0", "1"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trap::tests::sigsys_rejects_user_generated_signals_on_both_stacks",
                    "--nocapture",
                ])
                .env(CHILD, on_alt_stack)
                .output()
                .unwrap();
            assert_child_ran(&output);
            assert_eq!(output.status.code(), Some(126), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
        }
    }

    /// The line of the `panic!` in [`deliberate_panic`].
    const DELIBERATE_PANIC_LINE: u32 = line!() + 2;
    fn deliberate_panic() -> ! {
        panic!("deliberate panic inside the SIGSYS handler")
    }

    /// Forwards every syscall except `getppid`, which panics.
    struct PanicOnGetppid;

    impl SyscallDispatcher for PanicOnGetppid {
        fn dispatch(&self, event: &mut SyscallEvent) {
            if event.number() == libc::SYS_getppid {
                deliberate_panic();
            }
            crate::dispatch::PassthroughDispatcher::new().dispatch(event);
        }
    }

    #[cfg_attr(
        fbcode_build,
        ignore = "fbsource-disabled: jemalloc background thread is killed by the SIGSYS filter (intermittent exit 31); https://github.com/rrnewton/reverie/issues/867"
    )]
    #[test]
    fn a_panic_inside_the_handler_is_reported_and_aborts() {
        use std::os::unix::process::ExitStatusExt;

        const CHILD: &str = "REVERIE_TEST_SIGSYS_PANIC";
        if let Some(value) = std::env::var_os(CHILD) {
            // The child aborts on purpose. A non-dumpable process writes no
            // core and does not start the host's core-dump helper.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let config = crate::lifecycle::RuntimeConfig {
                use_alt_stack: value == "1",
                restrict_signal_return: false,
            };
            unsafe {
                crate::install(
                    Box::new(PanicOnGetppid),
                    &crate::lifecycle::InProcessSeccomp,
                    &config,
                )
                .unwrap();
                libc::syscall(libc::SYS_getppid);
            }
            panic!("the trapped getppid returned from the handler");
        }
        let expected = format!(
            "reverie-inguest: panic in the SIGSYS handler at {}:{DELIBERATE_PANIC_LINE}:9: \
             deliberate panic inside the SIGSYS handler\n",
            file!()
        );
        for on_alt_stack in ["0", "1"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trap::tests::a_panic_inside_the_handler_is_reported_and_aborts",
                    "--nocapture",
                ])
                .env(CHILD, on_alt_stack)
                .output()
                .unwrap();
            assert_child_ran(&output);
            assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{output:?}");
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                expected,
                "{output:?}"
            );
        }
    }

    #[test]
    fn a_panic_inside_the_handler_with_a_closed_stderr_pipe_still_aborts() {
        use std::os::fd::FromRawFd;
        use std::os::fd::OwnedFd;
        use std::os::unix::process::ExitStatusExt;

        const CHILD: &str = "REVERIE_TEST_SIGSYS_PANIC_EPIPE";
        if std::env::var_os(CHILD).is_some() {
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            // Rust programs ignore SIGPIPE; a C program takes the default
            // action, which kills the process.
            assert_ne!(
                unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                libc::SIG_ERR
            );
            let config = crate::lifecycle::RuntimeConfig {
                use_alt_stack: false,
                restrict_signal_return: false,
            };
            unsafe {
                crate::install(
                    Box::new(PanicOnGetppid),
                    &crate::lifecycle::InProcessSeccomp,
                    &config,
                )
                .unwrap();
                libc::syscall(libc::SYS_getppid);
            }
            panic!("the trapped getppid returned from the handler");
        }
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 returned two new descriptors that nothing else owns.
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // With no reader left, every write to the child's stderr fails.
        drop(reader);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::tests::a_panic_inside_the_handler_with_a_closed_stderr_pipe_still_aborts",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stderr(writer)
            .output()
            .unwrap();
        assert_child_ran(&output);
        assert_eq!(output.status.signal(), Some(libc::SIGABRT), "{output:?}");
    }

    static RESTRICTED_HANDLER_RAN: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn note_restricted_signal(
        _signal: libc::c_int,
        _info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        RESTRICTED_HANDLER_RAN.store(true, Ordering::SeqCst);
    }

    /// A signal frame captured from a real delivery, copied out of the
    /// kernel's frame by [`capture_signal_frame`].
    struct CapturedFrame(core::cell::UnsafeCell<core::mem::MaybeUninit<libc::ucontext_t>>);
    // SAFETY: written once by the capturing handler, then read by the same
    // single-threaded child process.
    unsafe impl Sync for CapturedFrame {}
    static CAPTURED_FRAME: CapturedFrame =
        CapturedFrame(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));

    unsafe extern "C" fn capture_signal_frame(
        _signal: libc::c_int,
        _info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                context.cast::<libc::ucontext_t>(),
                (*CAPTURED_FRAME.0.get()).as_mut_ptr(),
                1,
            )
        };
    }

    /// Where a performed forged return lands: it reports and exits 0.
    extern "C" fn forged_return_target() -> ! {
        let marker = b"forged return performed\n";
        unsafe {
            libc::write(1, marker.as_ptr().cast(), marker.len());
            libc::_exit(0)
        }
    }

    #[repr(C, align(16))]
    struct ForgeryStack([u8; 256 * 1024]);
    struct ForgeryArea(core::cell::UnsafeCell<ForgeryStack>);
    // SAFETY: used only by the single-threaded child process.
    unsafe impl Sync for ForgeryArea {}
    static FORGERY_AREA: ForgeryArea =
        ForgeryArea(core::cell::UnsafeCell::new(ForgeryStack([0; 256 * 1024])));

    /// The coordinator's check of the Tool-mode rule (msg1683): a forged
    /// signal frame, valid enough that Linux performs it when the filter
    /// admits `rt_sigreturn` from anywhere (the control: the process jumps to
    /// [`forged_return_target`] and exits 0), is never performed from any
    /// address but the restorer under `restrict_signal_return`: the process
    /// ends with [`GUEST_SIGNAL_RETURN_STATUS`] and the target never runs, on
    /// either signal stack.
    #[test]
    fn a_forged_signal_return_from_another_address_is_never_performed() {
        const CHILD: &str = "REVERIE_TEST_FORGED_SIGNAL_RETURN";
        if let Some(value) = std::env::var_os(CHILD) {
            let value = value.into_string().unwrap();
            let (policy, stack) = value.split_once(':').unwrap();
            let config = crate::lifecycle::RuntimeConfig {
                use_alt_stack: stack == "alt",
                restrict_signal_return: policy == "restricted",
            };
            unsafe {
                crate::install(
                    Box::new(crate::dispatch::PassthroughDispatcher::new()),
                    &crate::lifecycle::InProcessSeccomp,
                    &config,
                )
                .unwrap();
                // A genuine frame from a runtime handler's delivery.
                signal::install_runtime_handler(libc::SIGURG, capture_signal_frame, 0).unwrap();
                signal::raw_raise(libc::SIGURG).unwrap();
                let area = (*FORGERY_AREA.0.get()).0.as_mut_ptr();
                let area_len = 256 * 1024;
                let mut frame = (*CAPTURED_FRAME.0.get()).assume_init_read();
                // Resume at the target, on a fresh stack top as at a call.
                frame.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    forged_return_target as *const () as i64;
                frame.uc_mcontext.gregs[libc::REG_RSP as usize] = area.add(area_len / 2 - 8) as i64;
                // No saved FPU state: Linux then resets it.
                frame.uc_mcontext.fpregs = core::ptr::null_mut();
                // The frame sits near the area's top; Linux reads it at the
                // stack pointer plus 8 (after the restorer's return slot), so
                // the stack pointer at rt_sigreturn is the frame's address.
                let frame_at = area.add(area_len - 8192).cast::<libc::ucontext_t>();
                frame_at.write(frame);
                let marker = b"forging\n";
                assert_eq!(
                    libc::write(1, marker.as_ptr().cast(), marker.len()),
                    marker.len() as isize
                );
                core::arch::asm!(
                    "mov rsp, {frame}",
                    "mov eax, 15",
                    "syscall",
                    "ud2",
                    frame = in(reg) frame_at,
                    options(noreturn),
                );
            }
        }
        let expected = "reverie-inguest: the guest made its own rt_sigreturn; \
                        only the runtime's signal restorer may return from a signal, \
                        so the process ends\n";
        for value in ["unrestricted:main", "restricted:main", "restricted:alt"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trap::tests::a_forged_signal_return_from_another_address_is_never_performed",
                    "--nocapture",
                ])
                .env(CHILD, value)
                .output()
                .unwrap();
            assert_child_ran(&output);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("forging\n"), "{value} {output:?}");
            if value == "unrestricted:main" {
                // The forged frame is one Linux performs.
                assert_eq!(output.status.code(), Some(0), "{value} {output:?}");
                assert!(
                    stdout.contains("forged return performed\n"),
                    "{value} {output:?}"
                );
            } else {
                assert_eq!(
                    output.status.code(),
                    Some(GUEST_SIGNAL_RETURN_STATUS),
                    "{value} {output:?}"
                );
                assert!(
                    !stdout.contains("forged return performed"),
                    "{value} {output:?}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr).ends_with(expected),
                    "{value} {output:?}"
                );
            }
        }
    }

    /// With `restrict_signal_return`, the SIGSYS handler and any runtime
    /// handler return through the private restorer and the process runs on,
    /// on either stack; a signal return from anywhere else, by a handler
    /// glibc installed or by a raw `rt_sigreturn`, ends the process with
    /// [`GUEST_SIGNAL_RETURN_STATUS`] and never performs the return.
    #[test]
    fn a_restricted_signal_return_admits_only_the_runtime_restorer() {
        const CHILD: &str = "REVERIE_TEST_RESTRICTED_SIGNAL_RETURN";
        if let Some(value) = std::env::var_os(CHILD) {
            let value = value.into_string().unwrap();
            let (stack, foreign) = value.split_once(':').unwrap();
            let config = crate::lifecycle::RuntimeConfig {
                use_alt_stack: stack == "alt",
                restrict_signal_return: true,
            };
            unsafe {
                crate::install(
                    Box::new(crate::dispatch::PassthroughDispatcher::new()),
                    &crate::lifecycle::InProcessSeccomp,
                    &config,
                )
                .unwrap();
                // Trapped syscalls: each SIGSYS frame returns through the
                // restorer.
                for _ in 0..100 {
                    assert!(libc::syscall(libc::SYS_getppid) > 0);
                }
                signal::install_runtime_handler(libc::SIGURG, note_restricted_signal, 0).unwrap();
                signal::raw_raise(libc::SIGURG).unwrap();
                assert!(RESTRICTED_HANDLER_RAN.load(Ordering::SeqCst));
                let marker = b"runtime returns ran\n";
                assert_eq!(
                    libc::write(1, marker.as_ptr().cast(), marker.len()),
                    marker.len() as isize
                );
                match foreign {
                    "glibc" => {
                        // glibc's sigaction installs its own restorer.
                        RESTRICTED_HANDLER_RAN.store(false, Ordering::SeqCst);
                        let mut action: libc::sigaction = std::mem::zeroed();
                        action.sa_sigaction = note_restricted_signal as *const () as usize;
                        action.sa_flags = libc::SA_SIGINFO;
                        assert_eq!(
                            libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut()),
                            0
                        );
                        // Sent through the trusted gate, so it arrives in
                        // ordinary context; glibc's raise() would unblock it
                        // inside the SIGSYS handler, where SIGSYS is blocked
                        // and the trapped return is a fatal forced SIGSYS.
                        signal::raw_raise(libc::SIGUSR2).unwrap();
                        // The handler ran; its return through glibc's
                        // restorer is what ends the process.
                    }
                    "raw" => {
                        libc::syscall(libc::SYS_rt_sigreturn);
                    }
                    "alias" => {
                        // Linux takes the number's low 32 bits.
                        libc::syscall(0x1_0000_0000 | libc::SYS_rt_sigreturn);
                    }
                    other => panic!("unknown mode {other}"),
                }
            }
            panic!("a foreign signal return was performed");
        }
        let expected = "reverie-inguest: the guest made its own rt_sigreturn; \
                        only the runtime's signal restorer may return from a signal, \
                        so the process ends\n";
        for stack in ["alt", "main"] {
            for foreign in ["glibc", "raw", "alias"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "trap::tests::a_restricted_signal_return_admits_only_the_runtime_restorer",
                        "--nocapture",
                    ])
                    .env(CHILD, format!("{stack}:{foreign}"))
                    .output()
                    .unwrap();
                assert_child_ran(&output);
                assert_eq!(
                    output.status.code(),
                    Some(GUEST_SIGNAL_RETURN_STATUS),
                    "{stack}:{foreign} {output:?}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("runtime returns ran\n"),
                    "{stack}:{foreign} {output:?}"
                );
                assert!(
                    String::from_utf8_lossy(&output.stderr).ends_with(expected),
                    "{stack}:{foreign} {output:?}"
                );
            }
        }
    }

    /// The line of the `panic!` in [`deliberate_panic_outside_the_handler`].
    const OUTSIDE_PANIC_LINE: u32 = line!() + 2;
    fn deliberate_panic_outside_the_handler() -> ! {
        panic!("deliberate panic outside the SIGSYS handler")
    }

    #[cfg_attr(
        fbcode_build,
        ignore = "fbsource-disabled: jemalloc background thread is killed by the SIGSYS filter; https://github.com/rrnewton/reverie/issues/867"
    )]
    #[test]
    fn a_panic_outside_the_handler_reaches_the_previous_hook() {
        const CHILD: &str = "REVERIE_TEST_SIGSYS_PANIC_OUTSIDE";
        if std::env::var_os(CHILD).is_some() {
            let config = crate::lifecycle::RuntimeConfig {
                use_alt_stack: false,
                restrict_signal_return: false,
            };
            unsafe {
                crate::install(
                    Box::new(PanicOnGetppid),
                    &crate::lifecycle::InProcessSeccomp,
                    &config,
                )
                .unwrap();
            }
            deliberate_panic_outside_the_handler();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::tests::a_panic_outside_the_handler_reaches_the_previous_hook",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&output);
        // The test harness reports the child's test as failed and exits 101.
        assert_eq!(output.status.code(), Some(101), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let report = format!(
            "panicked at {}:{OUTSIDE_PANIC_LINE}:9:\n\
             deliberate panic outside the SIGSYS handler\n",
            file!()
        );
        assert!(stderr.contains(&report), "{output:?}");
        assert!(
            !stderr.contains("panic in the SIGSYS handler"),
            "{output:?}"
        );
    }
}

/// Real-architecture proof for the aarch64 gates: the trusted gate executes
/// a syscall through an installed filter, a nearby non-gate site traps, and
/// the guest gate executes with caller rights. The handler here is test
/// scaffolding only — it proves gate/filter semantics, not runtime
/// admission, which waits for signal-frame support.
#[cfg(all(test, target_arch = "aarch64"))]
mod aarch64_gate_tests {
    use super::*;

    /// Proof that a re-exec child actually ran its one selected
    /// test: a wrong `--exact` path makes libtest print
    /// "running 0 tests" and exit 0, which a status-only parent
    /// assert reads as success (the island-registry bug class).
    fn assert_child_ran(output: &std::process::Output) {
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "re-exec child ran no test (wrong --exact path?): {output:?}"
        );
    }
    use core::sync::atomic::AtomicU64;

    static ENTRIES: AtomicU64 = AtomicU64::new(0);

    unsafe extern "C" fn spoofing_handler(
        _signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        ENTRIES.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the kernel built this SA_SIGINFO frame for this call.
        unsafe {
            if (*info).si_code != SYS_SECCOMP_CODE {
                raw_syscall6(libc::SYS_exit_group, [44, 0, 0, 0, 0, 0]);
                core::hint::unreachable_unchecked()
            }
            let uc = &mut *context.cast::<libc::ucontext_t>();
            if uc.uc_mcontext.regs[8] != libc::SYS_getpid as u64 {
                raw_syscall6(libc::SYS_exit_group, [45, 0, 0, 0, 0, 0]);
                core::hint::unreachable_unchecked()
            }
            uc.uc_mcontext.regs[0] = 424_242;
        }
    }

    fn gate_child() -> ! {
        let pid = std::process::id() as i64;
        // The spoof sentinel must be provably distinct from the real pid,
        // or an untrapped getpid could satisfy the interception check.
        assert_ne!(pid, 424_242, "spoof sentinel collides with child pid");
        // SAFETY: single-threaded child before any filter exists.
        unsafe {
            if crate::signal::install_sigsys_handler(spoofing_handler, false).is_err() {
                raw_syscall6(libc::SYS_exit_group, [52, 0, 0, 0, 0, 0]);
            }
            let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates(
                trusted_gate(),
                guest_syscall_gate(),
            )
            .unwrap();
            if filter.install().is_err() {
                raw_syscall6(libc::SYS_exit_group, [51, 0, 0, 0, 0, 0]);
            }
            // Through the gate: executes, no trap.
            let via_gate = raw_syscall6(libc::SYS_getpid, [0; 6]);
            if via_gate != pid || ENTRIES.load(Ordering::Relaxed) != 0 {
                raw_syscall6(libc::SYS_exit_group, [61, 0, 0, 0, 0, 0]);
            }
            // Through the guest gate: executes, no trap.
            let via_guest = raw_syscall6_with_pkru(libc::SYS_getpid, [0; 6], 0);
            if via_guest != pid || ENTRIES.load(Ordering::Relaxed) != 0 {
                raw_syscall6(libc::SYS_exit_group, [62, 0, 0, 0, 0, 0]);
            }
            // Nearby non-gate site (libc's own syscall stub): must trap.
            let direct = libc::syscall(libc::SYS_getpid);
            if direct != 424_242 || ENTRIES.load(Ordering::Relaxed) != 1 {
                raw_syscall6(libc::SYS_exit_group, [63, 0, 0, 0, 0, 0]);
            }
            raw_syscall6(libc::SYS_exit_group, [0, 0, 0, 0, 0, 0]);
        }
        unreachable!("exit_group through the gate returned")
    }

    #[test]
    fn pending_promotions_skip_registered_island_ranges() {
        assert!(register_pending_promotion_island(0x9000_0000, 0x9000_1000));
        // Re-registration of the same range is idempotent.
        assert!(register_pending_promotion_island(0x9000_0000, 0x9000_1000));
        assert!(!register_pending_promotion_island(0x1000, 0x1000));
        let table = PendingPromotions::new();
        // Island-interior SVCs consume no slot and count as known.
        assert_eq!(
            table.try_record(0x9000_0040),
            PendingPromotionRecord::AlreadyKnown
        );
        assert_eq!(table.stats().pending, 0);
        assert_eq!(table.stats().recorded_new, 0);
        // Range bounds: lo inclusive, hi exclusive, outside unaffected.
        assert_eq!(
            table.try_record(0x9000_0000),
            PendingPromotionRecord::AlreadyKnown
        );
        assert_eq!(
            table.try_record(0x9000_1000),
            PendingPromotionRecord::NewSite
        );
        assert_eq!(
            table.try_record(0x8fff_fffc),
            PendingPromotionRecord::NewSite
        );
    }

    #[test]
    fn island_registry_unregisters_middle_last_and_refuses_when_full() {
        // Re-exec child: the registry is process-global and its
        // capacity is a lifetime budget, so the full-table leg
        // needs a fresh process.
        const CHILD: &str = "REVERIE_S5B_ISLAND_REGISTRY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let table = PendingPromotions::new();
            let range = |i: u64| {
                (
                    0xb000_0000 + i * 0x1_0000,
                    0xb000_0000 + i * 0x1_0000 + 0x8000,
                )
            };
            // Middle-slot unregister (swap-remove): register three,
            // remove the middle; the last range must survive the
            // swap, the removed one must record as new.
            for i in 0..3 {
                let (lo, hi) = range(i);
                assert!(register_pending_promotion_island(lo, hi));
            }
            let (mlo, mhi) = range(1);
            assert!(unregister_pending_promotion_island(mlo, mhi));
            assert_eq!(
                table.try_record(mlo),
                PendingPromotionRecord::NewSite,
                "unregistered middle range must record again"
            );
            let (llo, lhi) = range(2);
            assert_eq!(
                table.try_record(llo),
                PendingPromotionRecord::AlreadyKnown,
                "swapped-in last range must stay denylisted"
            );
            // Removing it again (not registered) is false.
            assert!(!unregister_pending_promotion_island(mlo, mhi));
            // Last-slot unregister: only ranges 0 and 2 remain, and
            // 2 now sits in the swapped slot; remove range 0, then
            // range 2 as the final remaining slot.
            let (flo, fhi) = range(0);
            assert!(unregister_pending_promotion_island(flo, fhi));
            assert!(unregister_pending_promotion_island(llo, lhi));
            assert_eq!(
                table.try_record(llo),
                PendingPromotionRecord::NewSite,
                "last-slot unregister must release the range"
            );
            // Capacity: all 64 slots accept, the 65th refuses.
            for i in 0..64u64 {
                let (lo, hi) = range(16 + i);
                assert!(
                    register_pending_promotion_island(lo, hi),
                    "slot {i} must accept"
                );
            }
            let (lo, hi) = range(16 + 64);
            assert!(
                !register_pending_promotion_island(lo, hi),
                "65th distinct range must refuse at capacity"
            );
            std::process::exit(0);
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::aarch64_gate_tests::island_registry_unregisters_middle_last_and_refuses_when_full",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&output);
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn pending_promotions_dedup_drain_in_order_and_count_capacity() {
        let table = PendingPromotions::new();
        assert_eq!(table.try_record(0x1000), PendingPromotionRecord::NewSite);
        assert_eq!(
            table.try_record(0x1000),
            PendingPromotionRecord::AlreadyKnown
        );
        assert_eq!(table.try_record(0x2000), PendingPromotionRecord::NewSite);

        let mut first = [0_u64; 1];
        assert_eq!(table.drain(&mut first), 1);
        assert_eq!(first, [0x1000]);
        assert_eq!(
            table.stats(),
            PendingPromotionStats {
                pending: 1,
                recorded_new: 2,
                capacity_dropped: 0,
                contended_dropped: 0,
            }
        );

        // A drained site remains known, so a later trap at that site does
        // not repeatedly queue the same candidate before promotion.
        assert_eq!(
            table.try_record(0x1000),
            PendingPromotionRecord::AlreadyKnown
        );
        let mut rest = [0_u64; PENDING_PROMOTION_CAPACITY];
        assert_eq!(table.drain(&mut rest), 1);
        assert_eq!(&rest[..1], &[0x2000]);

        let capacity_table = PendingPromotions::new();
        for index in 0..PENDING_PROMOTION_CAPACITY {
            let site = 0x4000 + index as u64 * 4;
            assert_eq!(
                capacity_table.try_record(site),
                PendingPromotionRecord::NewSite
            );
        }
        assert_eq!(
            capacity_table.try_record(0x9000),
            PendingPromotionRecord::TableFull
        );
        let mut drained = [0_u64; PENDING_PROMOTION_CAPACITY];
        assert_eq!(
            capacity_table.drain(&mut drained),
            PENDING_PROMOTION_CAPACITY
        );
        // Retained known-site identity still occupies the bounded table
        // after drain; capacity is a lifetime-known bound in this slice.
        assert_eq!(
            capacity_table.try_record(0x9000),
            PendingPromotionRecord::TableFull
        );
        assert_eq!(capacity_table.stats().capacity_dropped, 2);
    }

    #[test]
    fn pending_promotions_never_spin_from_handler_context() {
        let table = PendingPromotions::new();
        table.lock();
        let result = table.try_record(0x3000);
        table.unlock();
        assert_eq!(result, PendingPromotionRecord::Contended);
        assert_eq!(table.stats().contended_dropped, 1);
    }

    /// Bounded fork witness: with the table lock held across fork, the
    /// child (whose locking thread vanished) must still record, drain,
    /// and report stats — self-healed by PID ownership — instead of
    /// spinning on the inherited held bit. The child's alarm(1) turns
    /// any hang into a SIGALRM death the parent asserts against, so the
    /// test is bounded either way. The parent's own table is untouched
    /// by the child's reset (separate address spaces after fork).
    #[test]
    fn pending_table_self_heals_in_fork_child_with_lock_held() {
        let table = Box::leak(Box::new(PendingPromotions::new()));
        assert_eq!(table.try_record(0x1000), PendingPromotionRecord::NewSite);
        table.lock();
        // SAFETY: the child below runs only table calls and _exit.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {child}");
        if child == 0 {
            // SAFETY: async-signal-safe calls only in the fork child.
            unsafe {
                libc::alarm(1);
                // Record FIRST, before any stats/drain slow path can heal
                // ownership: a copied thread-local cache must not let the
                // handler path trust the parent's owner word.
                if table.try_record(0x2000) != PendingPromotionRecord::NewSite {
                    libc::_exit(82);
                }
                if table.stats().pending != 1 {
                    libc::_exit(81);
                }
                let mut out = [0_u64; 4];
                if table.drain(&mut out) != 1 || out[0] != 0x2000 {
                    libc::_exit(83);
                }
                libc::_exit(0);
            }
        }
        table.unlock();
        let mut status = 0;
        // SAFETY: reaping the exact child forked above.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child);
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
        // The parent's table kept its own entry across the child's reset.
        let mut out = [0_u64; 4];
        assert_eq!(table.drain(&mut out), 1);
        assert_eq!(out[0], 0x1000);
    }

    #[test]
    fn pending_table_recovers_copied_resetting_owner() {
        // A fork that copies the owner word mid-reset leaves a resetting
        // marker whose owner thread vanished with the parent. Ordinary
        // access must steal and complete the reset, never spin on the
        // dead resetter; if it spins, the test harness timeout is the
        // failure signal.
        let table = PendingPromotions::new();
        table.owner.store(
            PENDING_OWNER_RESETTING | 0x7fff_fffe,
            core::sync::atomic::Ordering::Relaxed,
        );
        table
            .locked
            .store(true, core::sync::atomic::Ordering::Relaxed);
        let stats = table.stats();
        assert_eq!(stats.pending, 0);
        assert_eq!(table.try_record(0x4000), PendingPromotionRecord::NewSite);
    }

    #[test]
    fn aarch64_gate_executes_and_nearby_site_traps() {
        const CHILD: &str = "REVERIE_TEST_AARCH64_GATE";
        if std::env::var_os(CHILD).is_some() {
            gate_child();
        }
        // Gate geometry: the reported return IP follows the 4-byte svc.
        for gate in [trusted_gate(), guest_syscall_gate()] {
            assert_eq!(gate.return_ip, gate.syscall_ip + 4);
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::aarch64_gate_tests::aarch64_gate_executes_and_nearby_site_traps",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&output);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }

    /// Admission evidence: the real handler reconstructs events from
    /// aarch64 frames, a dispatcher captures/restores the frame and
    /// mutates one result, and another syscall forwards untouched.
    struct CaptureSpoofGetpid;

    thread_local! {
        static CAPTURE: core::cell::RefCell<Option<frame::SavedState>> =
            const { core::cell::RefCell::new(None) };
    }

    // Two distinct local SVC sites for pending-promotion evidence. A libc
    // variadic syscall wrapper would make distinct guest calls share its one
    // internal SVC address, so it cannot prove site identity by itself.
    #[unsafe(naked)]
    unsafe extern "C" fn local_svc_getpid_a() -> i64 {
        core::arch::naked_asm!("mov x8, #172", "svc #0", "ret")
    }

    #[unsafe(naked)]
    unsafe extern "C" fn local_svc_getpid_b() -> i64 {
        core::arch::naked_asm!("nop", "mov x8, #172", "svc #0", "ret")
    }

    static SYNTH_FORK_ARMED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static VL_ATTEMPT_ARMED: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    static VL_DIRECT_RESULT: core::sync::atomic::AtomicI64 =
        core::sync::atomic::AtomicI64::new(i64::MIN);
    static VL_ATTEMPT_TO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    impl SyscallDispatcher for CaptureSpoofGetpid {
        fn dispatch(&self, event: &mut SyscallEvent) {
            event.forward();
        }

        fn dispatch_signal(&self, event: &mut SyscallEvent, frame: &mut frame::SignalFrame<'_>) {
            if event.number() == libc::SYS_clone
                && SYNTH_FORK_ARMED.swap(false, core::sync::atomic::Ordering::Relaxed)
            {
                // Synthesize a fork-child zero in the PARENT: no fork
                // happened, so the pending table must not reset. Only a
                // physical TGID change may prove a fork child.
                event.set_result(0);
                return;
            }
            if event.number() == libc::SYS_gettid
                && VL_ATTEMPT_ARMED.swap(false, core::sync::atomic::Ordering::Relaxed)
            {
                // Direct gate issue from inside dispatch, bypassing the
                // handler's own pre-check: the forwarding boundary in the
                // gate helpers must still refuse the VL change.
                // SAFETY: scalar prctl through the trusted gate.
                let result = unsafe {
                    raw_syscall6(
                        libc::SYS_prctl,
                        [
                            50,
                            VL_ATTEMPT_TO.load(core::sync::atomic::Ordering::Relaxed),
                            0,
                            0,
                            0,
                            0,
                        ],
                    )
                };
                VL_DIRECT_RESULT.store(result, core::sync::atomic::Ordering::Relaxed);
                event.forward();
                return;
            }
            if event.number() != libc::SYS_getpid {
                event.forward();
                return;
            }
            CAPTURE.with(|slot| {
                let mut slot = slot.borrow_mut();
                let saved = slot.as_mut().expect("capture storage prepared");
                if frame.capture(saved).is_err() {
                    // SAFETY: exit through the gate; libc exit would trap.
                    unsafe { raw_syscall6(libc::SYS_exit_group, [71, 0, 0, 0, 0, 0]) };
                }
                frame.set_register(0, -999);
                if frame.restore(saved).is_err() || frame.register(0) as u64 != saved.registers[0] {
                    // SAFETY: as above.
                    unsafe { raw_syscall6(libc::SYS_exit_group, [72, 0, 0, 0, 0, 0]) };
                }
            });
            event.set_result(424_243);
        }
    }

    fn admission_child() -> ! {
        let pid = std::process::id() as i64;
        let ppid: i64 = std::env::var("REVERIE_TEST_AARCH64_ADMISSION_PPID")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(pid, 424_243, "spoof sentinel collides with child pid");
        CAPTURE.with(|slot| *slot.borrow_mut() = Some(frame::SavedState::new().unwrap()));
        set_dispatcher(Box::new(CaptureSpoofGetpid));
        // SAFETY: single-threaded child; handler before filter, as the
        // lifecycle install orders them.
        unsafe {
            if install_handler(false).is_err() {
                raw_syscall6(libc::SYS_exit_group, [51, 0, 0, 0, 0, 0]);
            }
            let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates(
                trusted_gate(),
                guest_syscall_gate(),
            )
            .unwrap();
            if filter.install().is_err() {
                raw_syscall6(libc::SYS_exit_group, [52, 0, 0, 0, 0, 0]);
            }
            // Trapped and spoofed, with capture/restore in between. The two
            // local SVC sites prove pending recording is by exact trapped
            // instruction address, not merely syscall number.
            if local_svc_getpid_a() != 424_243 {
                raw_syscall6(libc::SYS_exit_group, [61, 0, 0, 0, 0, 0]);
            }
            let mut first_sites = [0_u64; PENDING_PROMOTION_CAPACITY];
            if drain_pending_promotion_sites(&mut first_sites) != 1
                || first_sites[0] != local_svc_getpid_a as *const () as u64 + 4
                || pending_promotion_stats().pending != 0
                || pending_promotion_stats().recorded_new != 1
            {
                raw_syscall6(libc::SYS_exit_group, [75, 0, 0, 0, 0, 0]);
            }
            if local_svc_getpid_a() != 424_243 {
                raw_syscall6(libc::SYS_exit_group, [61, 0, 0, 0, 0, 0]);
            }
            let mut repeated_sites = [0_u64; PENDING_PROMOTION_CAPACITY];
            let repeated_count = drain_pending_promotion_sites(&mut repeated_sites);
            if repeated_count != 0 {
                let diagnostic = if repeated_count == 1 && repeated_sites[0] == first_sites[0] {
                    76
                } else {
                    79
                };
                raw_syscall6(libc::SYS_exit_group, [diagnostic, 0, 0, 0, 0, 0]);
            }
            if local_svc_getpid_b() != 424_243 {
                raw_syscall6(libc::SYS_exit_group, [77, 0, 0, 0, 0, 0]);
            }
            let mut second_sites = [0_u64; PENDING_PROMOTION_CAPACITY];
            let pending_stats = pending_promotion_stats();
            if drain_pending_promotion_sites(&mut second_sites) != 1
                || second_sites[0] != local_svc_getpid_b as *const () as u64 + 8
                || pending_stats.recorded_new != 2
                || pending_stats.capacity_dropped != 0
                || pending_stats.contended_dropped != 0
            {
                raw_syscall6(libc::SYS_exit_group, [78, 0, 0, 0, 0, 0]);
            }
            // Trapped and forwarded: the real parent pid comes back.
            if libc::syscall(libc::SYS_getppid) != ppid {
                raw_syscall6(libc::SYS_exit_group, [62, 0, 0, 0, 0, 0]);
            }
            // Through the gate, untrapped: still the real pid.
            if raw_syscall6(libc::SYS_getpid, [0; 6]) != pid {
                raw_syscall6(libc::SYS_exit_group, [63, 0, 0, 0, 0, 0]);
            }
            // Fixed-VL envelope witness, only where SVE VL exists: a
            // trapped SET_VL naming the current length forwards, one
            // naming a different length is refused EINVAL by the handler
            // (VL unchanged after), and the same request through the gate
            // reaches the kernel (native control). Last, since the
            // native control may round the length it reports.
            const PR_SVE_SET_VL: i64 = 50;
            const PR_SVE_GET_VL: u64 = 51;
            let current = raw_syscall6(libc::SYS_prctl, [PR_SVE_GET_VL, 0, 0, 0, 0, 0]);
            if current >= 0 {
                let cur_vl = current as u64 & 0xffff;
                if libc::syscall(libc::SYS_prctl, PR_SVE_SET_VL, cur_vl as i64) < 0 {
                    raw_syscall6(libc::SYS_exit_group, [64, 0, 0, 0, 0, 0]);
                }
                // The handler writes -EINVAL into the frame; libc's
                // syscall wrapper surfaces that as -1 with errno set.
                let refused = libc::syscall(libc::SYS_prctl, PR_SVE_SET_VL, (cur_vl + 16) as i64);
                if refused != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                {
                    raw_syscall6(libc::SYS_exit_group, [65, 0, 0, 0, 0, 0]);
                }
                // Kernel-effective aliases of the same call (Linux takes
                // the syscall number and the prctl option as int) must be
                // refused identically, never forwarded by truncation.
                for (number, option, code) in [
                    (0x1_0000_00a7_i64, PR_SVE_SET_VL, 73_u64),
                    (libc::SYS_prctl, 0x1_0000_0032, 74),
                ] {
                    let refused = libc::syscall(number, option, (cur_vl + 16) as i64);
                    if refused != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
                    {
                        raw_syscall6(libc::SYS_exit_group, [code, 0, 0, 0, 0, 0]);
                    }
                }
                // The same change attempted directly through the gate
                // from inside dispatch (trapped gettid as the carrier)
                // hits the forwarding boundary, not just the handler's.
                VL_ATTEMPT_TO.store(cur_vl + 16, core::sync::atomic::Ordering::Relaxed);
                VL_ATTEMPT_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
                // This child body runs on a libtest thread, whose tid is
                // not the pid: the forwarded gettid must match the tid
                // observed directly through the gate, not the pid.
                let tid = raw_syscall6(libc::SYS_gettid, [0; 6]);
                if libc::syscall(libc::SYS_gettid) != tid {
                    raw_syscall6(libc::SYS_exit_group, [68, 0, 0, 0, 0, 0]);
                }
                if VL_DIRECT_RESULT.load(core::sync::atomic::Ordering::Relaxed)
                    != -i64::from(libc::EINVAL)
                {
                    raw_syscall6(libc::SYS_exit_group, [69, 0, 0, 0, 0, 0]);
                }
                let after = raw_syscall6(libc::SYS_prctl, [PR_SVE_GET_VL, 0, 0, 0, 0, 0]);
                if after as u64 & 0xffff != cur_vl {
                    raw_syscall6(libc::SYS_exit_group, [66, 0, 0, 0, 0, 0]);
                }
                if raw_syscall6(
                    libc::SYS_prctl,
                    [PR_SVE_SET_VL as u64, cur_vl + 16, 0, 0, 0, 0],
                ) < 0
                {
                    raw_syscall6(libc::SYS_exit_group, [67, 0, 0, 0, 0, 0]);
                }
            }
            // Synthesized fork-child zero (dispatcher sets result 0 for a
            // clone it never forwards): the table must retain everything
            // recorded so far — a result register alone is not physical
            // proof of a fork child.
            let recorded_before_synth = pending_promotion_stats().recorded_new;
            SYNTH_FORK_ARMED.store(true, core::sync::atomic::Ordering::Relaxed);
            if libc::syscall(
                libc::SYS_clone,
                libc::SIGCHLD as i64,
                0_i64,
                0_i64,
                0_i64,
                0_i64,
            ) != 0
            {
                raw_syscall6(libc::SYS_exit_group, [70, 0, 0, 0, 0, 0]);
            }
            // The clone reuses the libc wrapper site already recorded
            // by the VL phase, so the count may stay equal; a reset
            // would drop it below the pre-synth value.
            if pending_promotion_stats().recorded_new < recorded_before_synth {
                raw_syscall6(libc::SYS_exit_group, [71, 0, 0, 0, 0, 0]);
            }
            raw_syscall6(libc::SYS_exit_group, [0, 0, 0, 0, 0, 0]);
        }
        unreachable!("exit_group through the gate returned")
    }

    #[test]
    fn aarch64_handler_admits_dispatches_and_restores() {
        const CHILD: &str = "REVERIE_TEST_AARCH64_ADMISSION";
        if std::env::var_os(CHILD).is_some() {
            admission_child();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::aarch64_gate_tests::aarch64_handler_admits_dispatches_and_restores",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(
                "REVERIE_TEST_AARCH64_ADMISSION_PPID",
                std::process::id().to_string(),
            )
            .output()
            .unwrap();
        assert_child_ran(&output);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }

    /// S6b witness: the fallback continuation itself runs on aarch64.
    /// A trapped svc is captured, resumed at the aarch64 fallback
    /// entry on the owned stack, answered by the ordinary-context
    /// handler, and completed through the completion svc — twice.
    struct ContinuationSpoof;

    static CONTINUATION_CALLBACKS: AtomicU64 = AtomicU64::new(0);

    unsafe fn continuation_syscall(
        context: *mut crate::guest::context::RegisterContext,
        _guest_pkru: &mut Option<u32>,
    ) {
        use crate::guest::isa::Isa as _;
        use crate::guest::isa::NativeIsa;
        let local = 0_usize;
        if !crate::guest::continuation::on_owned_stack(&local as *const usize as usize) {
            // SAFETY: exit through the gate from callback context.
            unsafe { raw_syscall6(libc::SYS_exit_group, [84, 0, 0, 0, 0, 0]) };
        }
        // SAFETY: the continuation owns this live context for the callback.
        let context = unsafe { &mut *context };
        if NativeIsa::syscall_number(context) != libc::SYS_getpid {
            unsafe { raw_syscall6(libc::SYS_exit_group, [85, 0, 0, 0, 0, 0]) };
        }
        CONTINUATION_CALLBACKS.fetch_add(1, Ordering::Relaxed);
        NativeIsa::finish_syscall(context, 424_244);
    }

    unsafe fn continuation_instruction(
        _context: *mut crate::guest::context::RegisterContext,
        _kind: crate::guest::event::InstructionEventKind,
    ) {
        // SAFETY: no instruction event can be admitted in this child.
        unsafe { raw_syscall6(libc::SYS_exit_group, [86, 0, 0, 0, 0, 0]) };
    }

    impl SyscallDispatcher for ContinuationSpoof {
        fn dispatch(&self, event: &mut SyscallEvent) {
            event.forward();
        }

        fn dispatch_private_signal(&self, frame: &mut frame::SignalFrame<'_>) -> bool {
            match crate::guest::continuation::complete(frame) {
                Ok(handled) => handled,
                Err(_) => unsafe {
                    raw_syscall6(libc::SYS_exit_group, [87, 0, 0, 0, 0, 0]);
                    core::hint::unreachable_unchecked()
                },
            }
        }

        fn dispatch_signal(&self, event: &mut SyscallEvent, frame: &mut frame::SignalFrame<'_>) {
            use crate::guest::isa::Isa as _;
            use crate::guest::isa::NativeIsa;
            if event.number() != libc::SYS_getpid {
                event.forward();
                return;
            }
            let instruction = NativeIsa::syscall_site(event.instruction_pointer());
            // SAFETY: this is the SIGSYS handler for the trapped svc
            // at `instruction`; the entry is deferred to below.
            match unsafe { crate::guest::continuation::prepare_signal(instruction, frame) } {
                Ok(Some(entry)) => event.defer_to(entry),
                Ok(None) => unsafe {
                    raw_syscall6(libc::SYS_exit_group, [88, 0, 0, 0, 0, 0]);
                },
                Err(_) => unsafe {
                    raw_syscall6(libc::SYS_exit_group, [89, 0, 0, 0, 0, 0]);
                },
            }
        }
    }

    fn continuation_child() -> ! {
        let pid = std::process::id() as i64;
        assert_ne!(pid, 424_244, "spoof sentinel collides with child pid");
        // SAFETY: single-threaded child; handlers and continuation are
        // installed before the filter, as lifecycle orders them.
        unsafe {
            if crate::guest::continuation::register_handlers(
                crate::guest::continuation::ContinuationHandlers {
                    syscall: continuation_syscall,
                    instruction: continuation_instruction,
                },
            )
            .is_err()
                || crate::guest::continuation::initialize().is_err()
            {
                raw_syscall6(libc::SYS_exit_group, [80, 0, 0, 0, 0, 0]);
            }
            set_dispatcher(Box::new(ContinuationSpoof));
            if install_handler(false).is_err() {
                raw_syscall6(libc::SYS_exit_group, [81, 0, 0, 0, 0, 0]);
            }
            let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates(
                trusted_gate(),
                guest_syscall_gate(),
            )
            .unwrap();
            if filter.install().is_err() {
                raw_syscall6(libc::SYS_exit_group, [82, 0, 0, 0, 0, 0]);
            }
            for expected in 1..=2 {
                if local_svc_getpid_a() != 424_244
                    || CONTINUATION_CALLBACKS.load(Ordering::Relaxed) != expected
                {
                    raw_syscall6(libc::SYS_exit_group, [83, 0, 0, 0, 0, 0]);
                }
            }
            // Through the gate, untrapped: the real pid, no callback.
            if raw_syscall6(libc::SYS_getpid, [0; 6]) != pid
                || CONTINUATION_CALLBACKS.load(Ordering::Relaxed) != 2
            {
                raw_syscall6(libc::SYS_exit_group, [90, 0, 0, 0, 0, 0]);
            }
            raw_syscall6(libc::SYS_exit_group, [0, 0, 0, 0, 0, 0]);
        }
        unreachable!("exit_group through the gate returned")
    }

    #[test]
    fn aarch64_fallback_continuation_runs_on_owned_stack() {
        const CHILD: &str = "REVERIE_TEST_AARCH64_CONTINUATION";
        if std::env::var_os(CHILD).is_some() {
            continuation_child();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trap::aarch64_gate_tests::aarch64_fallback_continuation_runs_on_owned_stack",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }

    #[test]
    fn aarch64_runtime_page_geometry_is_usable() {
        let page = crate::arch::page_size().unwrap() as usize;
        assert!(page.is_power_of_two() && page >= 4096);
        // SAFETY: one anonymous page, unmapped below on every path.
        unsafe {
            let base = libc::mmap(
                core::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(base, libc::MAP_FAILED);
            base.cast::<u8>().add(page - 1).write(0xa5);
            assert_eq!(base.cast::<u8>().add(page - 1).read(), 0xa5);
            assert_eq!(
                libc::mprotect(base, page, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            assert_eq!(libc::munmap(base, page), 0);
        }
    }
}

#[cfg(test)]
mod runtime_text_tests {
    use super::*;

    #[test]
    fn restorer_and_gates_are_exact_denied_ips() {
        // Layout-independent: exact membership, not page cover.
        let ips = runtime_text_ips();
        assert!(ips.contains(&crate::signal::signal_restorer()));
        assert!(ips.contains(&crate::signal::signal_restorer_return_ip()));
        assert!(ips.contains(&trusted_gate().syscall_ip));
        assert!(ips.contains(&guest_syscall_gate().syscall_ip));
        assert!(is_runtime_text(crate::signal::signal_restorer()));
        assert!(!is_runtime_text(0x1000));
    }
}
