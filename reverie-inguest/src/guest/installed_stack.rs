/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Occupied stacks for explicitly selected FullTool installed callbacks.
//!
//! This is a C-ABI placement boundary after LiteInst has captured the guest
//! state. It does not isolate that earlier capture, guest TLS, foreign
//! allocation, or the writable key-zero interiors. Native Strace/Compat and
//! generic backends do not select this entry. Plain fork retains ownership
//! through COW; neither fork nor a nonlocal escape resets the occupied bitmap.

use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;

use super::tool_region::RegisteredAltStack;
use super::tool_region::StackLease;
use super::tool_region::ToolRegion;

/// Maximum number of simultaneously live or escaped pool activations.
pub const CAPACITY: usize = 64;
/// Writable bytes per pool activation, excluding its two page guards.
pub const STACK_BYTES: usize = 8 * 1024 * 1024;
const PAGE: usize = 4096;

// This discovery cell and the ordinary setup guard below remain globals
// outside fixed Tool storage. The runtime bitmap/descriptors are owned by the
// retained metadata lease. Publish only after every field is initialized.
#[unsafe(export_name = "reverie_inguest_installed_callback_pool_locator")]
static LOCATOR: AtomicUsize = AtomicUsize::new(0);
static PREPARING: AtomicBool = AtomicBool::new(false);

/// One immutable, guard-inclusive stack descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct StackDescriptor {
    /// First readable/writable byte of the key-zero interior.
    pub bottom: usize,
    /// End of the interior and beginning of its upper guard.
    pub top: usize,
    /// First byte of the lower guard.
    pub extent_start: usize,
    /// End of the upper guard.
    pub extent_end: usize,
}

impl StackDescriptor {
    fn from_lease(lease: &StackLease) -> Self {
        Self {
            bottom: lease.base(),
            top: lease.top(),
            extent_start: lease.base() - PAGE,
            extent_end: lease.top() + PAGE,
        }
    }
}

#[repr(C, align(64))]
struct Pool {
    occupied: AtomicU64,
    alternate: *const RegisteredAltStack,
    metadata: StackDescriptor,
    slots: [StackDescriptor; CAPACITY],
}

// SAFETY: after release publication, the descriptors and alternate pointer
// never change. The only mutable pool word is an aligned AtomicU64. Its exact
// bit claims/releases are native atomic operations, not a setup lock.
unsafe impl Sync for Pool {}

const _: () = {
    assert!(CAPACITY == u64::BITS as usize);
    assert!(size_of::<usize>() == 8);
    assert!(size_of::<AtomicU64>() == 8);
    assert!(size_of::<StackDescriptor>() == 32);
    assert!(offset_of!(Pool, occupied) == 0);
    assert!(size_of::<Pool>() <= PAGE);
    assert!(align_of::<Pool>() <= PAGE);
    assert!(STACK_BYTES & 15 == 0);
};

/// Proof that the complete process-lifetime callback pool was published.
///
/// This has no destructor or later initialization work. Copy it through the
/// runtime's pre-clock preparation seam; do not prepare lazily from a hook.
#[derive(Clone, Copy, Debug)]
pub struct PreparedCallbacks {
    _published: (),
}

struct PreparationGuard;

impl Drop for PreparationGuard {
    fn drop(&mut self) {
        PREPARING.store(false, Ordering::Release);
    }
}

/// Prepare all 64 guarded stacks and metadata before binding the guest clock.
///
/// A clean ordinary setup process may initialize ToolRegion here. There is no
/// System allocation: lease handles are a fixed local array and backing comes
/// solely from the reserved region. Partial failures drop only unpublished
/// leases through ToolRegion's protect/discard/quarantine protocol. Successful
/// publication retains every lease through later setup errors and plain fork.
/// Unexpected concurrent/interrupted preparation returns EAGAIN, never waits.
pub fn prepare() -> io::Result<PreparedCallbacks> {
    if LOCATOR.load(Ordering::Acquire) != 0 {
        return Ok(PreparedCallbacks { _published: () });
    }
    PREPARING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
    let _preparing = PreparationGuard;
    if LOCATOR.load(Ordering::Acquire) != 0 {
        return Ok(PreparedCallbacks { _published: () });
    }
    let region = ToolRegion::reserve()?;
    let metadata = region.stack(size_of::<Pool>())?;
    let pointer = metadata.base() as *mut Pool;
    let mut leases: [Option<StackLease>; CAPACITY] = core::array::from_fn(|_| None);
    // SAFETY: this exclusively held unpublished metadata lease is writable;
    // raw field writes do not create references to an uninitialized Pool.
    unsafe {
        core::ptr::addr_of_mut!((*pointer).occupied).write(AtomicU64::new(0));
        core::ptr::addr_of_mut!((*pointer).alternate)
            .write(region.registered_altstack() as *const RegisteredAltStack);
        core::ptr::addr_of_mut!((*pointer).metadata).write(StackDescriptor::from_lease(&metadata));
    }
    for (index, slot) in leases.iter_mut().enumerate() {
        let lease = region.stack(STACK_BYTES)?;
        // SAFETY: each descriptor is written once before publication.
        unsafe {
            core::ptr::addr_of_mut!((*pointer).slots)
                .cast::<StackDescriptor>()
                .add(index)
                .write(StackDescriptor::from_lease(&lease));
        }
        *slot = Some(lease);
    }
    // No fallible operation follows retention/publication. Callback addresses
    // are not selected by this function; the owning FullTool setup does that
    // only after receiving this proof, before initialize_rcb_clock.
    for lease in leases.into_iter().flatten() {
        core::mem::forget(lease);
    }
    core::mem::forget(metadata);
    LOCATOR.store(pointer as usize, Ordering::Release);
    Ok(PreparedCallbacks { _published: () })
}

/// Read-only ownership snapshot; it never reserves or initializes anything.
///
/// The occupied word is an instantaneous atomic sample. Region membership or
/// a descriptor alone does not prove that a hardware-observed entry owns a
/// live slot. That claim must bind the sampled RSP and its exact occupied bit.
#[derive(Clone, Copy, Debug)]
pub struct CallbackPoolSnapshot {
    /// Address of the fixed metadata interior and occupied word.
    pub address: usize,
    /// Instantaneous live/escaped activation bits.
    pub occupied: u64,
    /// Exact guarded metadata lease.
    pub metadata: StackDescriptor,
    /// All 64 immutable, distinct guarded activation leases.
    pub slots: [StackDescriptor; CAPACITY],
}

/// Query a published pool without allocation, TLS access or initialization.
pub fn snapshot() -> Option<CallbackPoolSnapshot> {
    let address = LOCATOR.load(Ordering::Acquire);
    if address == 0 {
        return None;
    }
    // SAFETY: publication retains a fully initialized Pool for process life.
    let pool = unsafe { &*(address as *const Pool) };
    Some(CallbackPoolSnapshot {
        address,
        occupied: pool.occupied.load(Ordering::Acquire),
        metadata: pool.metadata,
        slots: pool.slots,
    })
}

#[cfg(not(feature = "fixed-syscall-gates"))]
unsafe extern "C" {
    #[link_name = "reverie_inguest_trusted_syscall_ip"]
    fn native_gate();
}

#[cfg(feature = "fixed-syscall-gates")]
unsafe extern "C" {
    #[link_name = "reverie_inguest_trusted_syscall_ip"]
    fn legacy_native_gate();
    // Eight-byte, one-way publication after validation and RX sealing.
    #[link_name = "reverie_inguest_fixed_gates_published"]
    static FIXED_GATES_PUBLISHED: usize;
}

// A native failure may precede pool preparation or follow filter admission.
// Preserve Linux operands and R12, selecting before the memory-free gate.
// This adds no selector instructions to the ordinary callback recipe.
#[cfg(feature = "fixed-syscall-gates")]
#[unsafe(naked)]
unsafe extern "C" fn native_gate() {
    core::arch::naked_asm!(
        "endbr64",
        // MOV/JRCXZ preserves flags and uses only native syscall clobbers.
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

/// Enter an occupied pool stack, or retain the exact registered alternate
/// stack's current position, before calling an installed C-ABI callback.
///
/// Successful prefixes, claim retries and epilogues have no conditional
/// branches. A full occupied snapshot, absent preparation, or insufficient
/// alternate-frame headroom is terminal, with no incoming-stack fallback.
/// No new syscall site, signal policy, PKRU change or per-thread TLS is used.
/// The three named fatal routes attempt immediate native exit_group(127),
/// without writing a diagnostic. An externally denied, fabricated, trapped,
/// delegated or held terminal syscall has no bounded-death guarantee. If it
/// actually returns, a native UD2 is an attempted fail-stop, not a guarantee
/// against an external signal handler or supervisor.
///
/// # Safety
///
/// The caller supplies a valid SysV C-ABI context and body, with clear DF and
/// an incoming genuine CALL/RET slot. The body preserves callee-saved state
/// and does not unwind across this switch. Successful entry requires this
/// FullTool pool to have been prepared/published during ordinary setup;
/// absent preparation instead takes the specified terminal route. Only the
/// existing supported execution scope is supplied, not new guest pthread/
/// CLONE_VM/vfork or arbitrary Tool reentrancy. Nonlocal escape conservatively
/// leaks its exact claim.
#[unsafe(naked)]
#[unsafe(export_name = "reverie_inguest_installed_callback_entry")]
pub unsafe extern "C" fn entry(
    _context: *mut libc::c_void,
    _body: unsafe extern "C" fn(*mut libc::c_void),
) {
    core::arch::naked_asm!(
        "endbr64",
        "mov r8, rsp",
        "mov r9, [rip + {locator}]",
        "lea r10, [rip + .Linstalled_ready]",
        "lea r11, [rip + .Linstalled_unprepared]",
        "test r9, r9",
        "cmovz r10, r11",
        "jmp r10",
        ".Linstalled_ready:",
        "endbr64",
        "mov rax, [r9 + {alternate}]",
        // x86-64 plain MOV supplies these aligned atomic acquire/relaxed
        // loads. Load published usable length FIRST, even when it is zero.
        "mov rcx, [rax + {alt_length}]",
        "mov rdx, [rax + {alt_base}]",
        "mov rax, r8",
        "sub rax, rdx",
        "lea r10, [rip + .Linstalled_claim]",
        "lea r11, [rip + .Linstalled_borrowed]",
        "cmp rax, rcx",
        "cmovb r10, r11",
        "jmp r10",
        ".Linstalled_claim:",
        "endbr64",
        ".global reverie_inguest_installed_callback_preclaim",
        ".hidden reverie_inguest_installed_callback_preclaim",
        "reverie_inguest_installed_callback_preclaim:",
        "mov rax, [r9 + {occupied}]",
        "not rax",
        "bsf rcx, rax",
        // Zero input's undefined BSF index is replaced in registers, never
        // used as a bit or descriptor operand on the capacity-fatal path.
        "mov edx, 0",
        "test rax, rax",
        "cmovz rcx, rdx",
        "lea r10, [rip + .Linstalled_try_claim]",
        "lea r11, [rip + .Linstalled_capacity]",
        "cmovz r10, r11",
        "jmp r10",
        ".Linstalled_try_claim:",
        "endbr64",
        "lock bts qword ptr [r9 + {occupied}], rcx",
        "lea r10, [rip + .Linstalled_claimed]",
        "lea r11, [rip + .Linstalled_claim]",
        "cmovc r10, r11",
        "jmp r10",
        ".Linstalled_claimed:",
        "endbr64",
        ".global reverie_inguest_installed_callback_postclaim",
        ".hidden reverie_inguest_installed_callback_postclaim",
        "reverie_inguest_installed_callback_postclaim:",
        "mov r10, 1",
        "shl r10, cl",
        "not r10",
        "mov rax, rcx",
        "shl rax, 5",
        "mov rdx, [r9 + rax + {slots} + {bottom}]",
        "mov rsp, [r9 + rax + {slots} + {top}]",
        "sub rsp, 32",
        "jmp .Linstalled_frame",
        ".Linstalled_borrowed:",
        "endbr64",
        "mov r10, r8",
        "and r10, -16",
        "sub r10, 32",
        "lea rax, [r10 - 8]",
        "lea rcx, [rip + .Linstalled_borrowed_ready]",
        "lea r11, [rip + .Linstalled_alt_exhausted]",
        "cmp rax, rdx",
        "cmovb rcx, r11",
        "jmp rcx",
        ".Linstalled_borrowed_ready:",
        "endbr64",
        "mov rsp, r10",
        "mov r10, -1",
        ".Linstalled_frame:",
        "mov [rsp], r8",
        "mov [rsp + 8], r9",
        "mov [rsp + 16], r10",
        "mov [rsp + 24], rsi",
        "call rsi",
        // Load every operand before release; none is read from the released
        // frame after restoring incoming RSP. Preserve all callee-saved GPRs.
        "mov r8, [rsp]",
        "mov r9, [rsp + 8]",
        "mov r10, [rsp + 16]",
        "mov rsp, r8",
        ".global reverie_inguest_installed_callback_postrestore",
        ".hidden reverie_inguest_installed_callback_postrestore",
        "reverie_inguest_installed_callback_postrestore:",
        "lock and qword ptr [r9 + {occupied}], r10",
        "ret",
        ".Linstalled_unprepared:",
        "endbr64",
        ".global reverie_inguest_installed_callback_unprepared",
        ".hidden reverie_inguest_installed_callback_unprepared",
        "reverie_inguest_installed_callback_unprepared:",
        "jmp .Linstalled_fatal",
        ".Linstalled_capacity:",
        "endbr64",
        ".global reverie_inguest_installed_callback_capacity",
        ".hidden reverie_inguest_installed_callback_capacity",
        "reverie_inguest_installed_callback_capacity:",
        "jmp .Linstalled_fatal",
        ".Linstalled_alt_exhausted:",
        "endbr64",
        ".global reverie_inguest_installed_callback_alt_exhausted",
        ".hidden reverie_inguest_installed_callback_alt_exhausted",
        "reverie_inguest_installed_callback_alt_exhausted:",
        ".Linstalled_fatal:",
        "mov eax, {exit_group}",
        "mov edi, 127",
        "lea r12, [rip + .Linstalled_exit_failed]",
        "jmp {gate}",
        ".Linstalled_exit_failed:",
        "endbr64",
        "ud2",
        ".global reverie_inguest_installed_callback_entry_end",
        ".hidden reverie_inguest_installed_callback_entry_end",
        "reverie_inguest_installed_callback_entry_end:",
        locator = sym LOCATOR,
        gate = sym native_gate,
        occupied = const offset_of!(Pool, occupied),
        alternate = const offset_of!(Pool, alternate),
        slots = const offset_of!(Pool, slots),
        bottom = const offset_of!(StackDescriptor, bottom),
        top = const offset_of!(StackDescriptor, top),
        alt_base = const offset_of!(RegisteredAltStack, base),
        alt_length = const offset_of!(RegisteredAltStack, length),
        exit_group = const libc::SYS_exit_group,
    );
}

core::arch::global_asm!(
    ".hidden reverie_inguest_installed_callback_entry",
    ".hidden reverie_inguest_installed_callback_pool_locator",
);

#[cfg(test)]
#[path = "installed_stack_tests.rs"]
mod tests;

#[cfg(all(test, not(feature = "fixed-syscall-gates")))]
mod ordinary_gate_byte_controls {
    use super::*;

    unsafe extern "C" {
        #[link_name = "reverie_inguest_trusted_syscall"]
        fn legacy_scalar_gate(
            number: u64,
            arg0: u64,
            arg1: u64,
            arg2: u64,
            arg3: u64,
            arg4: u64,
            arg5: u64,
        ) -> i64;
        // A static, as `tests` declares this symbol: two declarations of one
        // symbol with different types made LLVM rename the second to
        // `reverie_inguest_installed_callback_entry_end.1`, which nothing
        // defines, so the lib tests failed to link without
        // fixed-syscall-gates, the feature that compiles this module out.
        #[link_name = "reverie_inguest_installed_callback_entry_end"]
        static installed_entry_end: u8;
    }

    #[test]
    fn ordinary_gate_bytes_and_terminal_operand_remain_the_qualified_recipe() {
        // Literal complete legacy body from the independent artifact checker;
        // read the emitted mapped text, not a second assembly string.
        let expected = [
            0x41, 0x54, 0x4c, 0x8d, 0x25, 0x1c, 0, 0, 0, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48,
            0x89, 0xd6, 0x48, 0x89, 0xca, 0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x4c, 0x8b, 0x4c,
            0x24, 0x10, 0x0f, 0x05, 0x41, 0xff, 0xe4, 0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x5c, 0xc3,
        ];
        let owner = legacy_scalar_gate as *const () as usize;
        // SAFETY: these hidden symbols name retained runtime RX text, with the
        // complete 44-byte owner and terminal interval defined by naked_asm.
        let actual = unsafe { core::slice::from_raw_parts(owner as *const u8, expected.len()) };
        assert_eq!(actual, expected);
        assert_eq!(native_gate as *const () as usize - owner, 0x20);
        let end = (&raw const installed_entry_end) as usize;
        let jump = unsafe { core::slice::from_raw_parts((end - 11) as *const u8, 5) };
        assert_eq!(jump[0], 0xe9);
        let displacement = i32::from_le_bytes(jump[1..].try_into().unwrap());
        assert_eq!(
            (end as i64 - 6 + i64::from(displacement)) as usize,
            owner + 0x20
        );
        let tail = unsafe { core::slice::from_raw_parts((end - 6) as *const u8, 6) };
        assert_eq!(tail, [0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x0b]);
    }
}

#[cfg(all(test, feature = "fixed-syscall-gates"))]
mod fixed_gate_tests {
    use super::*;

    unsafe extern "C" fn unexpected_sigsys(_: i32, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        let _ = unsafe { crate::trap::raw_syscall6(libc::SYS_exit_group, [91, 0, 0, 0, 0, 0]) };
    }

    unsafe extern "C" fn unexpected_callback(_: *mut libc::c_void) {
        let _ = unsafe { crate::trap::raw_syscall6(libc::SYS_exit_group, [92, 0, 0, 0, 0, 0]) };
    }

    #[test]
    fn published_unprepared_installed_callback_exits_through_the_fixed_native_gate() {
        const CHILD: &str = "REVERIE_FIXED_INSTALLED_TERMINAL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            assert!(snapshot().is_none());
            assert!(!crate::trap::fixed_gates_published());
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
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
            unsafe { entry(core::ptr::null_mut(), unexpected_callback) };
            unreachable!("native terminal unexpectedly returned");
        }
        let module = module_path!().split_once("::").unwrap().1;
        let test = format!(
            "{module}::published_unprepared_installed_callback_exits_through_the_fixed_native_gate"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(127), "{output:?}");
    }
}
