/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */
//! Native private-loader state for the opt-in InitialImage experiment.
//!
//! The control page is a mechanism, not authentication. Only an initializer
//! that has redeemed its one-use coordinator admission may publish this state.
//! Existing constructors and exec refusals do not consume it.
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub mod mapped_initial;

#[cfg(all(
    feature = "loader-private-runtime",
    target_env = "musl",
    not(target_arch = "x86_64")
))]
compile_error!(
    "the mapped musl Running relay (mapped_initial) is x86_64-only today: its signal-frame, register and altstack paths name x86_64 registers; this is the named aarch64 refusal for that leg until those paths are ported"
);

pub(crate) mod tool_tls_registry;
pub(crate) mod tool_tls_slots;

#[cfg(feature = "coordinator-rpc")]
mod native_io;
#[cfg(feature = "coordinator-rpc")]
pub(crate) use native_io::NativeGateIoBinding;
#[cfg(feature = "coordinator-rpc")]
pub use native_io::NativeInitializationIoGuard;

#[cfg(test)]
pub(crate) use super::support::BirthSignalGuard;
#[cfg(test)]
pub(crate) use super::support::birth_block_mask;

/// Native control ABI shared with the private GNU runner.
#[repr(C, align(64))]
pub struct NativeControl {
    abi_version: u64,
    byte_len: u64,
    phase: u64,
    guest_fs: u64,
    tool_fs: u64,
    guest_rsp: u64,
    guest_ld_entry: u64,
    init_input: u64,
    init_input_len: u64,
    runtime_ready: u64,
    kernel_mask: u64,
    // Initially captured by the private loader, then updated only after an
    // actual successful guest registration syscall. Tool setters are refused.
    kernel_robust_head: u64,
    kernel_robust_len: u64,
    kernel_clear_tid: u64,
    kernel_brk: u64,
    native_tid: u64,
    private_brk_base: u64,
    private_brk_current: u64,
    private_brk_end: u64,
    private_stack_base: u64,
    private_stack_end: u64,
    tool_ld_entry: u64,
    tool_ld_bias: u64,
    runner_entry: u64,
    runner_phdr: u64,
    runner_phnum: u64,
    runner_phent: u64,
    runner_bias: u64,
    guest_ld_lo: u64,
    guest_ld_hi: u64,
    bootstrap_handler: u64,
    bootstrap_restorer: u64,
    bootstrap_stack_base: u64,
    bootstrap_stack_end: u64,
    native_traps: u64,
    private_map_count: u64,
    private_code_count: u64,
    private_clear_tid: u64,
    private_robust_head: u64,
    private_robust_len: u64,
    failure_code: u64,
    init_input_fd: u64,
    input_mapping_base: u64,
    input_mapping_end: u64,
    guest_resume_mask: u64,
    guest_pkru: u64,
    native_state: u64,
    native_config: u64,
    maps: [PrivateMap; 64],
    code: [PrivateCode; 64],
    // Real fresh-image mode, and the once-selected policy for guest resume.
    // Trusted private startup temporarily runs with PR_TSC_ENABLE.
    kernel_tsc: u64,
    guest_tsc: u64,
}
#[repr(C)]
struct PrivateMap {
    lo: u64,
    hi: u64,
    prot: u64,
    flags: u64,
}
#[repr(C)]
struct PrivateCode {
    lo: u64,
    hi: u64,
}
/// Frozen native control phase, shared with private-control.h.
pub const TOOL_LIFECYCLE_PHASE: u64 = 6;
const _: () = {
    assert!(TOOL_LIFECYCLE_PHASE == 6);
    assert!(size_of::<NativeControl>() == 3520);
    assert!(size_of::<NativeControl>() <= 4096);
    assert!(align_of::<NativeControl>() == 64);
    assert!(core::mem::offset_of!(NativeControl, phase) == 16);
    assert!(core::mem::offset_of!(NativeControl, guest_fs) == 24);
    assert!(core::mem::offset_of!(NativeControl, tool_fs) == 32);
    assert!(core::mem::offset_of!(NativeControl, guest_resume_mask) == 352);
    assert!(core::mem::offset_of!(NativeControl, maps) == 384);
    assert!(core::mem::offset_of!(NativeControl, code) == 2432);
    assert!(core::mem::offset_of!(NativeControl, kernel_tsc) == 3456);
    assert!(core::mem::offset_of!(NativeControl, guest_tsc) == 3464);
};

#[unsafe(no_mangle)]
static reverie_inguest_private_exec_control: AtomicUsize = AtomicUsize::new(0);
core::arch::global_asm!(".hidden reverie_inguest_private_exec_control");

/// Whether the authenticated initializer has published a private control.
pub fn active() -> bool {
    reverie_inguest_private_exec_control.load(Ordering::Acquire) != 0
}

/// The actual ready InitialImage thread while its Tool callback is active.
/// This is a read-only admission check for the experimental observation sink,
/// not authorization to change phase, registrations, FS or guest state.
pub fn callback_native_tid() -> Option<i32> {
    let control = control_pointer();
    if control.is_null() {
        return None;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 4
        || read(unsafe { &raw const (*control).runtime_ready }) != 1
    {
        return None;
    }
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let mut fs = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if tid <= 0
        || pid != tid
        || tid as u64 != read(unsafe { &raw const (*control).native_tid })
        || rc != 0
        || fs == 0
        || fs != read(unsafe { &raw const (*control).tool_fs })
    {
        return None;
    }
    i32::try_from(tid).ok()
}

/// Current guest registrations in the calling native thread.
///
/// Addresses are recorded kernel arguments, never dereferenced Tool pointers.
/// This value does not authorize an exec or a change to either registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestKernelRegistrations {
    /// Last successful guest clear-child-TID registration.
    pub clear_tid: u64,
    /// Last successful guest robust-list registration, checked against Linux.
    pub robust_head: u64,
    /// Kernel robust-list ABI length.
    pub robust_len: u64,
}

/// Inspect registrations only in the actual ready native Tool callback.
///
/// The robust-list query must agree with the success-only guest ledger. Linux
/// does not provide a generally available clear-TID query; its value comes
/// from the initial loader capture and every successful guest setter. This
/// check never uses a destructive setter as a query. A caller needing an exec
/// cut must repeat it at its final edge, without intervening guest execution.
pub fn callback_kernel_registrations() -> Option<GuestKernelRegistrations> {
    callback_native_tid()?;
    let control = control_pointer();
    let read = |p: *const u64| unsafe { p.read_volatile() };
    let recorded = GuestKernelRegistrations {
        clear_tid: read(unsafe { &raw const (*control).kernel_clear_tid }),
        robust_head: read(unsafe { &raw const (*control).kernel_robust_head }),
        robust_len: read(unsafe { &raw const (*control).kernel_robust_len }),
    };
    let mut head = 0_u64;
    let mut length = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_get_robust_list,
            [0, (&raw mut head) as u64, (&raw mut length) as u64, 0, 0, 0],
        )
    };
    (rc == 0 && head == recorded.robust_head && length == recorded.robust_len).then_some(recorded)
}

/// This thread's Tool thread pointer (the FS base on x86_64, TPIDR_EL0
/// on aarch64), or None where it cannot be read. Stage C derives the
/// callback slot from this value, never from the stack pointer:
/// callbacks run on the continuation stack, not the slot altstack.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
fn current_thread_pointer() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut tp = 0_u64;
        // SAFETY: ARCH_GET_FS writes one word to the owned out slot.
        let rc = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut tp) as u64, 0, 0, 0, 0],
            )
        };
        return (rc == 0 && tp != 0).then_some(tp);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let tp: u64;
        // SAFETY: reading TPIDR_EL0 has no memory effect.
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack));
        }
        return (tp != 0).then_some(tp);
    }
    #[allow(unreachable_code)]
    None
}

/// Which record a thread pointer resolves to: the leader's
/// NativeControl, or one slot's record. Shared by the Stage C
/// callback predicate and the musl Running relay.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
#[derive(Clone, Copy)]
pub(crate) enum CurrentCallbackRecord {
    Leader,
    Slot {
        index: usize,
        record: *mut tool_tls_slots::SlotRecord,
    },
}

/// Resolve a thread pointer to its callback record. The leader is
/// decided by exact equality with the control's tool thread pointer,
/// as today; a slot requires the exact slot thread pointer under a
/// published layout. Anything else resolves nowhere.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn current_callback_record(
    tp: u64,
    control: *mut NativeControl,
) -> Option<CurrentCallbackRecord> {
    if tp != 0 && tp == unsafe { (&raw const (*control).tool_fs).read_volatile() } {
        return Some(CurrentCallbackRecord::Leader);
    }
    let layout = tool_tls_slots::layout()?;
    match layout.record_for_tp(tp as usize) {
        tool_tls_slots::RecordRef::Slot(index) => Some(CurrentCallbackRecord::Slot {
            index,
            record: layout.record_addr(index) as *mut tool_tls_slots::SlotRecord,
        }),
        _ => None,
    }
}

/// The actual ready Tool thread while its callback is active (Stage
/// C predicate split): slot 0 is the leader exactly as
/// `callback_native_tid`, and a non-leader slot must additionally be
/// the registry's Ready holder of this tid. Read-only, like
/// `callback_native_tid`; registrations, exec facts and execve
/// routing keep using that leader-only predicate unchanged.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn callback_tool_tid() -> Option<i32> {
    let control = control_pointer();
    if control.is_null() {
        return None;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).runtime_ready }) != 1
    {
        return None;
    }
    let tp = current_thread_pointer()?;
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    if tid <= 0 {
        return None;
    }
    let tid = i32::try_from(tid).ok()?;
    let (slot, phase) = match current_callback_record(tp, control)? {
        CurrentCallbackRecord::Leader => {
            let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
            if pid != i64::from(tid)
                || u64::try_from(tid).ok()? != read(unsafe { &raw const (*control).native_tid })
            {
                return None;
            }
            (0, read(unsafe { &raw const (*control).phase }))
        }
        CurrentCallbackRecord::Slot { index, record } => {
            // The geometry already required the exact slot thread
            // pointer; re-check the record's own word rather than
            // trusting the geometry alone (as the ledger write does).
            if read(unsafe { &raw const (*record).tool_fs }) != tp {
                return None;
            }
            (index, read(unsafe { &raw const (*record).phase }))
        }
    };
    if phase != 4 {
        return None;
    }
    (tool_tls_registry::TOOL_TLS_REGISTRY.lookup_ready(tid) == Some(slot)).then_some(tid)
}

/// Current guest registrations against one slot record's ledger: the
/// slot beside the leader-only `callback_kernel_registrations`. The
/// robust-list query must agree with the slot's success-only guest
/// ledger, exactly as the leader check requires of NativeControl.
/// Unlike its leader sibling this does not authenticate the caller:
/// the caller must already have established that the current thread
/// owns `record` (thread-pointer, phase and registry checks, as
/// `verify_slot_owner` does before calling it).
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn callback_slot_registrations(
    record: *mut tool_tls_slots::SlotRecord,
) -> Option<GuestKernelRegistrations> {
    if record.is_null() {
        return None;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    let recorded = GuestKernelRegistrations {
        clear_tid: read(unsafe { &raw const (*record).guest_clear_tid }),
        robust_head: read(unsafe { &raw const (*record).guest_robust_head }),
        robust_len: read(unsafe { &raw const (*record).guest_robust_len }),
    };
    let mut head = 0_u64;
    let mut length = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_get_robust_list,
            [0, (&raw mut head) as u64, (&raw mut length) as u64, 0, 0, 0],
        )
    };
    (rc == 0 && head == recorded.robust_head && length == recorded.robust_len).then_some(recorded)
}

/// Why a non-leader mapping-class syscall is refused by name during a
/// mapped relay callback: mapping, break and mapping-tracking state
/// are process-global and leader-owned (restorer owner-mapping
/// bookkeeping and the nested trackers assume the leader is the only
/// thread mutating mappings), so a physical mapping change from an
/// admitted non-leader would race that accounting. Tracked for
/// lifting by minibeads dh-gpxse, which owns per-slot mapping
/// accounting.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) const NON_LEADER_MAPPING_CLASS_REASON: &str =
    "non-leader mapping-class syscall during mapped relay (dh-gpxse)";

/// The refusal result for [`NON_LEADER_MAPPING_CLASS_REASON`]: the
/// same `-EPERM` the owner-mapping guard on this forwarding path
/// already returns for refused mapping changes.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) const NON_LEADER_MAPPING_CLASS_ERRNO: i64 = -(libc::EPERM as i64);

/// How a non-leader mapping-class syscall is refused during a mapped
/// relay callback, preserving each syscall's raw ABI.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonLeaderMappingRefusal {
    /// Return this raw result (a negative errno) without executing.
    Errno(i64),
    /// `brk` has no errno return: answer with the unchanged current
    /// break, as the owner-mapping guard does for a denied change.
    UnchangedBreak,
}

/// Classify the non-leader mapping-class refusal set. None means the
/// syscall is not mapping-class and forwards normally. The set is a
/// superset of every syscall the owner-mapping guard classifies as a
/// mapping change (restorer.rs `mapping_change_refused_with_fixed_
/// region`), plus `shmdt`, which also unmaps: the stated reason --
/// a physical mapping change races leader-owned accounting -- covers
/// all of them, argument shapes aside.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn non_leader_mapping_refusal(number: i64) -> Option<NonLeaderMappingRefusal> {
    match number {
        libc::SYS_brk => Some(NonLeaderMappingRefusal::UnchangedBreak),
        libc::SYS_mmap
        | libc::SYS_mprotect
        | libc::SYS_munmap
        | libc::SYS_mremap
        | libc::SYS_madvise
        | libc::SYS_pkey_mprotect
        | libc::SYS_remap_file_pages
        | libc::SYS_mseal
        | libc::SYS_process_madvise
        | libc::SYS_shmat
        | libc::SYS_shmdt => Some(NonLeaderMappingRefusal::Errno(
            NON_LEADER_MAPPING_CLASS_ERRNO,
        )),
        _ => None,
    }
}

/// The resolved refusal outcome: the raw result to answer with, or a
/// failed break query, which has no honest brk-shaped answer and is
/// fatal at the relay.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NonLeaderMappingOutcome {
    Result(i64),
    BreakQueryFailed,
}

/// The one refusal outcome seam shared by the musl relay and the gnu
/// witnesses: classifier plus result value, including the brk(0)
/// answer. `query_current_break` is the caller's own physical
/// brk(0) query (the relay's kernel gate; a trap handler's
/// pre-queried break), issued only for `brk`.
#[cfg(any(test, all(feature = "loader-private-runtime", target_env = "musl")))]
pub(crate) fn non_leader_mapping_outcome(
    number: i64,
    query_current_break: impl FnOnce() -> i64,
) -> Option<NonLeaderMappingOutcome> {
    match non_leader_mapping_refusal(number)? {
        NonLeaderMappingRefusal::Errno(errno) => Some(NonLeaderMappingOutcome::Result(errno)),
        NonLeaderMappingRefusal::UnchangedBreak => {
            let current = query_current_break();
            Some(if current > 0 {
                NonLeaderMappingOutcome::Result(current)
            } else {
                NonLeaderMappingOutcome::BreakQueryFailed
            })
        }
    }
}

/// Read-only actual callback observations, not native exec admission authority.
#[cfg(feature = "exec-native-injection")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExecCallbackFacts {
    /// Published protected control mapping, never a guest-provided address.
    pub control_address: usize,
    /// Actual same-main-thread native owner.
    pub native_tid: i32,
    /// Verified ToolCallback phase, always4.
    pub phase: u64,
    /// Actual current Tool FS, independently read with ARCH_GET_FS.
    pub tool_fs: u64,
    /// Actual guest FS captured by the existing owned native transitions.
    pub guest_fs: u64,
    /// Current physical mask. The driver must independently prove that this
    /// is the desired guest resume mask, rather than reuse a startup mask or
    /// assume that a SIGSYS handler's blocked mask is the guest's mask.
    pub physical_mask: u64,
    /// Current success-only guest ledger and actual robust query agreement.
    pub registrations: GuestKernelRegistrations,
}

/// Inspect only the actual ready native owner; repeat at the final exec cut.
/// No setter is used to discover FS, clear-TID or robust registrations.
#[cfg(feature = "exec-native-injection")]
pub(crate) fn native_exec_callback_facts() -> Option<NativeExecCallbackFacts> {
    let native_tid = callback_native_tid()?;
    let registrations = callback_kernel_registrations()?;
    let control = control_pointer();
    let mut fs = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    let mut mask = 0_u64;
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }.ok()?;
    if rc != 0 || callback_native_tid()? != native_tid {
        return None;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).native_state }) != 3
        || fs != read(unsafe { &raw const (*control).tool_fs })
    {
        return None;
    }
    Some(NativeExecCallbackFacts {
        control_address: control as usize,
        native_tid,
        phase: 4,
        tool_fs: fs,
        guest_fs: read(unsafe { &raw const (*control).guest_fs }),
        physical_mask: mask,
        registrations,
    })
}

/// One-use physical leaf for a genuinely issued native exec transaction.
/// Observations do not authorize it; only the unsafe installed driver may
/// construct it. It is neither Clone nor transferable to another thread.
#[cfg(feature = "exec-native-injection")]
pub struct IssuedNativeExecLeaf {
    cut: super::native_exec::ExecCut,
    resume: super::continuation::NativeExecResumeReceipt,
    _same_thread: core::marker::PhantomData<*mut ()>,
}

#[cfg(feature = "exec-native-injection")]
impl IssuedNativeExecLeaf {
    /// Bind the actual fallback cut after successful authenticated Issue.
    ///
    /// # Safety
    /// The caller owns the same live PreparedNativeExec cancellation guard
    /// and genuine one-use Issued authority for this exact retained watched
    /// main thread, old/prepared Tool state, original operation and immutable
    /// native target/interpreter/namespace/bootstrap. All original pointer
    /// arguments remain immutable and accessible under the actual guest PKRU.
    /// The protected reserved FD/OFD bootstrap leases are exact, installed and
    /// retained until kernel exec or authenticated cancellation. No request ID,
    /// receipt or digest creates that authority. This may be constructed only
    /// once for that Issue; on any refusal or returned errno the caller must
    /// cancel the owned transaction/leases before resuming the old guest. Drop
    /// of the surrounding transaction must terminate rather than abandon Issue.
    /// No staged signals, guest signal/filter mode, fork state, concurrent
    /// guest work or guest mutation is allowed. The PKRU-aware gate must be
    /// independently qualified when OriginalExec has Some(PKRU); None grants
    /// no claim of absent hardware or permission isolation.
    pub unsafe fn after_issue(
        cut: &super::native_exec::ExecCut,
    ) -> Result<Self, super::native_exec::NativeExecFailure> {
        let resume = cut.resume_mask_receipt().ok_or_else(|| {
            native_leaf_refusal(
                "reverie-inguest: exec lacks an actual running fallback resume mask",
            )
        })?;
        let leaf = Self {
            cut: *cut,
            resume,
            _same_thread: core::marker::PhantomData,
        };
        leaf.preflight()?;
        Ok(leaf)
    }

    fn preflight(&self) -> Result<(), super::native_exec::NativeExecFailure> {
        let original = self.cut.original();
        if !self.cut.is_fallback()
            || !super::native_exec::is_exec(original.number())
            || !self.resume.recheck(&self.cut.original_event())
            || self.resume.signal_mask() & (1_u64 << (libc::SIGSYS - 1)) != 0
            || self.cut.native().physical_mask != self.resume.signal_mask()
            || native_exec_callback_facts().as_ref() != Some(self.cut.native())
        {
            return Err(native_leaf_refusal(
                "reverie-inguest: exec fallback owner, physical state or resume mask changed",
            ));
        }
        Ok(())
    }

    /// Execute the exact original operation; success replaces this image.
    ///
    /// # Safety
    /// All after_issue obligations still hold. `final_check` is mandatory and
    /// must recheck the actual sealed Tool/runtime/sequence/empty-forwarding
    /// cut, protected FD/OFD and immutable target/bootstrap against the genuine
    /// Issue after the latest control acknowledgment and all raw I/O (including
    /// this leaf's preflight queries). It must finish with the allocation-free
    /// exact counter/state check, make no physical state mutation and leave no
    /// further work before this leaf. It cannot be an always-success callback
    /// in an admitted driver. The operation is only attempted once; returned
    /// errno/refusal still requires cancellation, preserving returned PKRU and
    /// the restored FS/mask/registration state. Terminal failure cannot resume.
    pub unsafe fn call(
        self,
        final_check: impl FnOnce() -> Result<(), super::native_exec::NativeExecFailure>,
    ) -> Result<super::native_exec::ReturnedNativeExec, super::native_exec::NativeExecFailure> {
        self.preflight()?;
        final_check()?;
        let original = self.cut.original();
        let args = original.args();
        let raw = unsafe {
            // Distinct exec leaf: ordinary physical_syscall's refusal and its
            // admitted scalar domain are unchanged. The existing assembly
            // selects guest FS, executes all six original registers, captures
            // actual PKRU/guest FS, and restores Tool FS before Rust resumes.
            reverie_inguest_private_leader_guest_call(
                original.number(),
                args.as_ptr(),
                u64::from(original.pkru().unwrap_or(0)),
                u64::from(original.pkru().is_some()),
            )
        };
        if !(-4095..=-1).contains(&raw.result)
            || native_exec_callback_facts().as_ref() != Some(self.cut.native())
            || !self.resume.recheck(&self.cut.original_event())
        {
            return Err(native_leaf_terminal(
                "reverie-inguest: returned exec changed physical state or returned a non-errno",
            ));
        }
        let pkru = match original.pkru() {
            Some(_) => Some(u32::try_from(raw.pkru).map_err(|_| {
                native_leaf_terminal("reverie-inguest: returned exec PKRU is not exact")
            })?),
            None if raw.pkru == 0 => None,
            None => {
                return Err(native_leaf_terminal(
                    "reverie-inguest: scalar exec leaf returned an unexpected permission result",
                ));
            }
        };
        Ok(super::native_exec::ReturnedNativeExec {
            errno: reverie::syscalls::Errno::new((-raw.result) as i32),
            pkru,
        })
    }
}

#[cfg(feature = "exec-native-injection")]
fn native_leaf_refusal(diagnostic: &'static str) -> super::native_exec::NativeExecFailure {
    super::native_exec::NativeExecFailure::Refused(reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::NativeExec,
        reverie::syscalls::Errno::EOPNOTSUPP,
        diagnostic,
    ))
}
#[cfg(feature = "exec-native-injection")]
fn native_leaf_terminal(diagnostic: &'static str) -> super::native_exec::NativeExecFailure {
    super::native_exec::NativeExecFailure::Terminal(super::native_exec::TerminalExecFailure {
        diagnostic,
    })
}

#[cfg(all(test, feature = "exec-native-injection"))]
pub(super) fn native_exec_mock_callback() -> Box<NativeControl> {
    // Model callback only: no watched birth, immutable launch or kernel exec.
    let (mut native, _owner, _entry) = successor_test_owner();
    native.phase = 4;
    native.runtime_ready = 1;
    native.native_state = 3; // Modeled ready callback after kernel restoration.
    let mut head = 0_u64;
    let mut length = 0_u64;
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_get_robust_list,
                [0, (&raw mut head) as u64, (&raw mut length) as u64, 0, 0, 0],
            )
        },
        0
    );
    native.kernel_robust_head = head;
    native.kernel_robust_len = length;
    native
}

/// Transition an InitialImage lifecycle fixture control (phase 2,
/// already published by `lifecycle_test_owner`) to the callback-ready
/// state `native_exec_mock_callback` models on its successor control,
/// so one stable control can serve both lifecycle and exec-callback
/// facts in a single fixture process. The caller must have completed
/// InitialImage lifecycle initialization on this control first.
#[cfg(all(test, feature = "exec-native-injection"))]
pub(super) fn native_exec_test_make_callback_ready(control: &mut NativeControl) {
    // Component fixture only; Issue/installer authority remains modeled.
    assert_eq!(control.phase, 2);
    assert_eq!(control.runtime_ready, 0);
    control.phase = 4;
    control.runtime_ready = 1;
    control.native_state = 3; // Modeled ready callback after kernel restoration.
    control.guest_fs = control.tool_fs;
    let mut head = 0_u64;
    let mut length = 0_u64;
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_get_robust_list,
                [0, (&raw mut head) as u64, (&raw mut length) as u64, 0, 0, 0],
            )
        },
        0
    );
    control.kernel_robust_head = head;
    control.kernel_robust_len = length;
}

#[cfg(all(test, feature = "exec-native-injection"))]
pub(super) fn native_exec_test_enter_guest(control: &mut NativeControl) {
    // Component fixture only; protected installer/Issue authority is modeled.
    assert_eq!(control.phase, 4);
    assert_eq!(control.runtime_ready, 1);
    control.phase = 3;
}

/// Read the bounded, immutable native input packet before coordinator redemption.
/// This validates placement and ABI only; request contents confer no authority.
///
/// # Safety
/// The controlled runner must own the fixed native control and read-only input
/// mapping, with Tool FS/stack active and the authenticated filter/gates live.
/// No guest code may have run and neither mapping may change while borrowed.
pub unsafe fn initial_packet(control: *const NativeControl) -> io::Result<&'static [u8]> {
    unsafe {
        checked_initial_control(control)?;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    let address = read(unsafe { &raw const (*control).init_input });
    let length = read(unsafe { &raw const (*control).init_input_len });
    if address != 0x5300_0000_1000
        || length == 0
        || length > 4096
        || read(unsafe { &raw const (*control).input_mapping_base }) != address
        || read(unsafe { &raw const (*control).input_mapping_end }) != address + 4096
        || read(unsafe { &raw const (*control).init_input_fd }) != 201
    {
        return Err(io::Error::other(
            "invalid bounded native initialization packet",
        ));
    }
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length as usize) })
}

/// The actual single native process/thread before InitialImage redemption.
///
/// # Safety
/// The control must satisfy the owned-mapping contract of [`initial_packet`].
pub unsafe fn native_tid(control: *const NativeControl) -> io::Result<i32> {
    unsafe {
        checked_initial_control(control)?;
    }
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    if tid <= 0
        || tid != pid
        || tid as u64 != unsafe { (&raw const (*control).native_tid).read_volatile() }
    {
        return Err(io::Error::other(
            "InitialImage native process identity differs",
        ));
    }
    Ok(tid as i32)
}

/// Capture actual private mappings before the admitted native installation.
/// The result is an address exclusion list, not mapping/launch authority.
///
/// # Safety
/// The controlled private runner exclusively owns this exact control and all
/// listed mappings. The actual host has authenticated the native image before
/// this call, no Guest code ran, and no mapping can change during the capture.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn native_protected_mappings(
    control: *const NativeControl,
) -> io::Result<Vec<(u64, u64)>> {
    unsafe {
        native_tid(control)?;
    }
    let count = unsafe { (&raw const (*control).private_map_count).read_volatile() } as usize;
    if count == 0 || count > 64 {
        return Err(io::Error::other("native private map inventory differs"));
    }
    let mut ranges = Vec::with_capacity(count + 2);
    for index in 0..count {
        let map = unsafe { (*control).maps.as_ptr().add(index).read_volatile() };
        if map.lo == 0 || map.lo >= map.hi || map.lo % 4096 != 0 || map.hi % 4096 != 0 {
            return Err(io::Error::other("native private map range differs"));
        }
        ranges.push((map.lo, map.hi));
    }
    // Reservation success is actual ownership, not an address constant alone.
    super::tool_region::ToolRegion::reserve()?;
    ranges.push((
        super::tool_region::BASE as u64,
        super::tool_region::END as u64,
    ));
    ranges.push((
        crate::trap::FIXED_GATE_BASE,
        crate::trap::FIXED_GATE_BASE + 4096,
    ));
    Ok(ranges)
}

/// Retire the authenticated sealed bootstrap input before Guest publication.
/// The read-only input mapping remains owned; the regular FD lease must end.
///
/// # Safety
/// The same real native initializer exclusively owns descriptor 201 and this
/// control, has already decoded/redeemed its protected packet, and has verified
/// the actual immutable input role. No second owner may close or reuse it.
#[cfg(feature = "exec-native-injection")]
pub unsafe fn retire_native_input(control: *mut NativeControl) -> io::Result<()> {
    unsafe {
        native_tid(control)?;
    }
    if unsafe { (&raw const (*control).init_input_fd).read_volatile() } != 201 {
        return Err(io::Error::other("native bootstrap input already retired"));
    }
    let result = unsafe { crate::trap::raw_syscall6(libc::SYS_close, [201, 0, 0, 0, 0, 0]) };
    if result != 0 {
        return Err(io::Error::other("native bootstrap input retirement failed"));
    }
    unsafe {
        (&raw mut (*control).init_input_fd).write_volatile(u64::MAX);
    }
    Ok(())
}

unsafe fn checked_initial_control(control: *const NativeControl) -> io::Result<()> {
    if control as usize != 0x5300_0000_0000 {
        return Err(io::Error::other(
            "InitialImage control is outside its owned page",
        ));
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 2
        || read(unsafe { &raw const (*control).runtime_ready }) != 0
        || read(unsafe { &raw const (*control).native_state }) != 1
    {
        return Err(io::Error::other(
            "InitialImage native startup state differs",
        ));
    }
    Ok(())
}

/// End an explicit initialization failure without allocation, TLS or output.
/// This goes directly to the inherited fixed gate even before its Rust owner
/// is published. It never returns or attempts the legacy local syscall site.
///
/// # Safety
/// Only the controlled private runner may call this, with the exact inherited
/// fixed native gate already mapped and allowed by its initial filter.
pub unsafe fn initialization_failed(_control: *mut NativeControl) -> ! {
    unsafe { initial_terminal() }
}

#[unsafe(naked)]
unsafe extern "C" fn initial_terminal() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "2:",
        "mov eax, 231",
        "mov edi, 127",
        "lea r12, [rip + 2b]",
        "movabs r11, {native_gate}",
        "jmp r11",
        native_gate = const crate::trap::FIXED_NATIVE_ENTRY,
    );
}

/// Publish the one-thread native FS control after genuine coordinator admission.
///
/// # Safety
/// The caller must have authenticated this InitialImage against the launching
/// coordinator and verified the owned fixed gate, handler, filter and all
/// control extents. `control` must remain mapped, unaliased by Rust references,
/// and protected from guest mapping changes for the process lifetime. Native
/// entry must already use the private Tool FS. No guest code may have run.
/// This function does not establish any of those external facts. An armed
/// [`InitialImageAbortGuard`] must span this call through verified readiness;
/// errors after gate adoption cannot return to an unguarded initializer.
pub unsafe fn publish_authenticated_control(
    control: *mut NativeControl,
) -> io::Result<InitialImageControl> {
    unsafe {
        publish_native_control(control)?;
    }
    Ok(InitialImageControl::new(control as usize))
}

// Common physical adoption. The two public callers have distinct unsafe
// admission contracts and never infer image kind from packet contents.
unsafe fn publish_native_control(control: *mut NativeControl) -> io::Result<()> {
    if control.is_null() || (control as usize) & 63 != 0 {
        return Err(io::Error::other("unaligned native private control"));
    }
    // Raw reads: native signal entry owns disjoint mutable fields afterwards.
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 2
        || read(unsafe { &raw const (*control).runtime_ready }) != 0
        || read(unsafe { &raw const (*control).tool_fs }) == 0
    {
        return Err(io::Error::other(
            "invalid private Tool initialization phase",
        ));
    }
    // Caller-context queries must use the qualified inherited gate. A query
    // relayed through bootstrap SIGSYS sees the handler mask and SS_ONSTACK.
    unsafe {
        crate::trap::adopt_authenticated_initial_gate()?;
        verify_bootstrap_signal(control)?;
    }
    publish_control_slot(control)
}

// Same write-once physical pointer for both authenticated image origins.
// Neither this helper nor the pointer value supplies coordinator admission.
// This is also the one place slot 0 of the per-thread Tool TLS registry is
// registered: the mapped musl image publishes through here directly, so
// registering in a caller would leave its leader unregistered.
fn publish_control_slot(control: *mut NativeControl) -> io::Result<()> {
    // Validate the sealed leader tid before publishing anything: a tid that
    // is not a positive kernel tid can never be the registry leader.
    let leader_tid = i32::try_from(unsafe { (&raw const (*control).native_tid).read_volatile() })
        .ok()
        .filter(|tid| *tid > 0)
        .ok_or_else(|| io::Error::other("private Tool leader slot registration failed"))?;
    reverie_inguest_private_exec_control
        .compare_exchange(0, control as usize, Ordering::Release, Ordering::Relaxed)
        .map_err(|_| io::Error::other("private Tool control published twice"))?;
    // Registration cannot fail after the successful write-once publication
    // above (slot 0 registers exactly once, here); both publication callers
    // already treat an error at this point as terminal.
    tool_tls_registry::register_leader(leader_tid)
        .map_err(|_| io::Error::other("private Tool leader slot registration failed"))
}

/// Returned-error stage of the still-armed InitialImage refusal path.
#[derive(Clone, Copy)]
pub enum InitialRefusalStage {
    /// The installed Tool's initial lifecycle returned an error.
    Lifecycle,
    /// The existing final frontend/readiness check returned an error.
    FinalFrontend,
}

/// Send one terminal diagnostic without waiting or changing the output owner.
///
/// # Safety
/// The caller retains the installed trusted syscall gate, private Tool stack
/// and protected output owner, with Guest and concurrent FD mutation excluded.
unsafe fn send_terminal_packet(message: &[u8]) {
    let Some(socket) = super::protect::tool_output_fd() else {
        return;
    };
    // Exactly one nonblocking attempt, including EINTR and short sends. Its
    // outcome changes neither the returned error nor the armed fatal owner.
    unsafe {
        let _ = crate::trap::raw_syscall6(
            libc::SYS_sendto,
            [
                socket as u64,
                message.as_ptr() as u64,
                message.len() as u64,
                (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64,
                0,
                0,
            ],
        );
    }
}

/// Report an exact static terminal reason before an armed transaction drops.
/// A reason that cannot fit in full is replaced by an explicit overflow marker.
/// This untagged ERROR remains unhealthy to the existing output receiver; it
/// supplies neither an INFO record nor completion or native-exec authority.
///
/// # Safety
/// The caller retains the installed trusted syscall gate, valid private Tool
/// stack and protected output owner, excluding Guest and concurrent FD mutation.
/// The same error propagation and armed fatal ownership must remain in force.
pub unsafe fn report_native_terminal_reason(reason: &'static str) {
    const PREFIX: &[u8] = b"ERROR native exec terminal: ";
    const OVERFLOW: &[u8] = b"[reason exceeds diagnostic bound]";
    let mut packet = [0_u8; 256];
    let reason = if reason.len() > packet.len() - PREFIX.len() - 1 {
        OVERFLOW
    } else {
        reason.as_bytes()
    };
    packet[..PREFIX.len()].copy_from_slice(PREFIX);
    let end = PREFIX.len() + reason.len();
    packet[PREFIX.len()..end].copy_from_slice(reason);
    packet[end] = b'\n';
    unsafe { send_terminal_packet(&packet[..end + 1]) };
}

/// Best-effort terminal diagnostic on the current protected Tool output socket.
/// This untagged ERROR packet deliberately remains unhealthy to the existing
/// receiver; it is neither a counted INFO record nor completion evidence. Only
/// the stored raw errno is read: no formatting, allocation, TLS or libc occurs.
/// A missing/full/closed socket omits the packet without delaying refusal.
///
/// # Safety
/// The caller retains the actual installed trusted syscall gate, valid private
/// stack and protected output owner. Native InitialImage callers must retain
/// the qualified inherited gate and their still-armed fatal image ownership.
/// This measurement supplies no admission and must not replace the same error
/// propagation or fatal guard. No guest code or concurrent FD mutation may run.
pub unsafe fn report_initial_refusal(stage: InitialRefusalStage, error: &io::Error) {
    let mut message =
        *b"ERROR native initial refusal stage=L errno_present=0 errno_bits=00000000\n";
    const STAGE: usize = b"ERROR native initial refusal stage=".len();
    const PRESENT: usize = b"ERROR native initial refusal stage=L errno_present=".len();
    const HEX: usize = b"ERROR native initial refusal stage=L errno_present=0 errno_bits=".len();
    message[STAGE] = match stage {
        InitialRefusalStage::Lifecycle => b'L',
        InitialRefusalStage::FinalFrontend => b'F',
    };
    let errno = error.raw_os_error();
    message[PRESENT] = if errno.is_some() { b'1' } else { b'0' };
    let bits = errno.unwrap_or(0) as u32;
    for (index, digit) in message[HEX..HEX + 8].iter_mut().enumerate() {
        *digit = b"0123456789abcdef"[((bits >> (28 - 4 * index)) & 15) as usize];
    }
    unsafe { send_terminal_packet(&message) };
}

/// Fatal ownership from authenticated gate adoption until verified readiness.
/// Destruction writes no diagnostics before its terminal syscall.
pub struct InitialImageAbortGuard {
    active: bool,
}

impl InitialImageAbortGuard {
    /// Arm before adopting the inherited gate and retain through initialization.
    ///
    /// # Safety
    /// The caller must have redeemed actual InitialImage authorization and own
    /// the native bootstrap's fixed terminal gate/phase. No Guest may run until
    /// the same control completes the existing full frontend/lifecycle checks.
    pub unsafe fn arm() -> Self {
        Self { active: true }
    }

    /// Disarm only after the actual control verifies and publishes readiness.
    /// Any error leaves the guard live, so destruction terminates this image.
    pub fn finish(mut self, control: &InitialImageControl) -> io::Result<()> {
        if let Err(error) = control.finish() {
            // The same fatal owner remains armed during this bounded attempt.
            unsafe { report_initial_refusal(InitialRefusalStage::FinalFrontend, &error) };
            return Err(error);
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for InitialImageAbortGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe { initial_terminal() }
        }
    }
}

/// Native syscall answer; permissions are meaningful only for the PKRU gate.
#[repr(C)]
pub struct PhysicalResult {
    /// The actual kernel return, including negative errno.
    pub result: i64,
    /// Actual post-syscall rights when a guest PKRU was supplied.
    pub pkru: u64,
}

unsafe extern "C" {
    fn reverie_inguest_private_guest_call(
        number: i64,
        args: *const u64,
        guest_pkru: u64,
        use_pkru: u64,
    ) -> PhysicalResult;
    // The only production caller is IssuedNativeExecLeaf::call,
    // compiled only with exec-native-injection; declare the leaf
    // exactly where it can be called (tests call it directly).
    #[cfg(any(test, feature = "exec-native-injection"))]
    fn reverie_inguest_private_leader_guest_call(
        number: i64,
        args: *const u64,
        guest_pkru: u64,
        use_pkru: u64,
    ) -> PhysicalResult;
    #[cfg(any(
        feature = "exec-private-successor",
        all(feature = "exec-private-init", feature = "coordinator-rpc")
    ))]
    fn reverie_inguest_private_lifecycle_call(
        number: i64,
        args: *const u64,
        guest_pkru: u64,
        use_pkru: u64,
    ) -> PhysicalResult;
}

/// Execute a physical guest operation with its FS, restoring Tool FS before Rust.
/// Private bookkeeping must continue to use the ordinary trusted raw gate.
///
/// # Safety
/// Requires published, authenticated control in ToolCallback, owned surviving
/// stack/argument storage, and the same operation/PKRU constraints as
/// `trap::raw_syscall6_with_result`. Threads, exec, and user signal returns are
/// not admitted by this leaf. The caller must apply their existing guards.
pub unsafe fn physical_syscall(
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
) -> crate::trap::NativeSyscallResult {
    let result = unsafe {
        reverie_inguest_private_guest_call(
            number,
            args.as_ptr(),
            u64::from(pkru.unwrap_or(0)),
            u64::from(pkru.is_some()),
        )
    };
    // The assembly leaf has restored Tool FS and callback phase before any
    // Rust executes. Preserve actual failed-call state; do not infer success
    // merely from the requested address or a Detcore-emulated return value.
    // The registration ledger is per-record: with a slot layout published,
    // these two syscalls (and only these two) re-derive the caller's
    // record from its thread pointer; every other call writes nothing.
    let control = control_pointer();
    let is_registration =
        number == libc::SYS_set_tid_address || number == libc::SYS_set_robust_list;
    let slot_record = if is_registration {
        current_slot_record_for_ledger(control)
    } else {
        None
    };
    unsafe {
        if number == libc::SYS_set_tid_address && result.result > 0 {
            match slot_record {
                Some(record) => (&raw mut (*record).guest_clear_tid).write_volatile(args[0]),
                None => (&raw mut (*control).kernel_clear_tid).write_volatile(args[0]),
            }
        } else if number == libc::SYS_set_robust_list && result.result == 0 {
            match slot_record {
                Some(record) => {
                    (&raw mut (*record).guest_robust_head).write_volatile(args[0]);
                    (&raw mut (*record).guest_robust_len).write_volatile(args[1]);
                }
                None => {
                    (&raw mut (*control).kernel_robust_head).write_volatile(args[0]);
                    (&raw mut (*control).kernel_robust_len).write_volatile(args[1]);
                }
            }
        }
    }
    crate::trap::NativeSyscallResult {
        result: result.result,
        pkru: pkru.map(|_| result.pkru as u32),
    }
}

// No Rust, TLS, libc or errno access is permitted between the two FS switches.
// All kernel transitions use the frozen fixed gate. GET_FS after the operation
// captures actual state even when ARCH_SET_FS returned an error.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_inguest_private_guest_call
    .hidden reverie_inguest_private_guest_call
    .type reverie_inguest_private_guest_call,@function
reverie_inguest_private_guest_call:
    endbr64
    mov r11d, 4
    jmp .Lprivate_call_common
    .size reverie_inguest_private_guest_call, .-reverie_inguest_private_guest_call
    .p2align 4
    .global reverie_inguest_private_leader_guest_call
    .hidden reverie_inguest_private_leader_guest_call
    .type reverie_inguest_private_leader_guest_call,@function
reverie_inguest_private_leader_guest_call:
    endbr64
    mov r11d, 0x104
    jmp .Lprivate_call_common
    .size reverie_inguest_private_leader_guest_call, .-reverie_inguest_private_leader_guest_call
    .p2align 4
    .global reverie_inguest_private_lifecycle_call
    .hidden reverie_inguest_private_lifecycle_call
    .type reverie_inguest_private_lifecycle_call,@function
reverie_inguest_private_lifecycle_call:
    endbr64
    mov r11d, 0x106
.Lprivate_call_common:
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub rsp, 48
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    // Entry label establishes expected phase, never a caller/guest argument.
    mov [rsp + 40], r11
    mov r13, [rip + reverie_inguest_private_exec_control]
    test r13, r13
    jz .Lprivate_terminal
    // Record derivation (B2): the leaf finds its own record from the
    // thread pointer, read with ARCH_GET_FS through the fixed gate
    // (zone-B option 1: no FS-relative operand in this leaf); no
    // caller supplies it. With no slot layout published the leader
    // record is used exactly as before.
    mov rax, [rip + reverie_inguest_private_slot_base]
    test rax, rax
    jz .Lprivate_call_have_record
    mov eax, 158
    mov edi, 0x1003
    lea rsi, [rsp + 32]
    lea r12, [rip + .Lprivate_got_tool_fs]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_got_tool_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    mov rax, [rip + reverie_inguest_private_slot_base]
    mov rcx, [rsp + 32]
    cmp rcx, [r13 + 32]
    je .Lprivate_call_leader_record
    cmp rcx, rax
    jb .Lprivate_terminal
    mov r10, rcx
    sub r10, rax
    mov rcx, [rip + reverie_inguest_private_slot_stride_log2]
    mov r11, r10
    shr r11, cl
    test r11, r11
    jz .Lprivate_terminal
    cmp r11, {max_threads}
    jae .Lprivate_terminal
    shl r11, cl
    add rax, r11
    add rax, [rip + reverie_inguest_private_slot_record_offset]
    mov rcx, [rsp + 32]
    cmp [rax + 32], rcx
    jne .Lprivate_terminal
    mov r13, rax
    // Leader-only entries (lifecycle/exec) refuse any slot record here.
    test qword ptr [rsp + 40], 0x100
    jnz .Lprivate_terminal
    jmp .Lprivate_call_have_record
.Lprivate_call_leader_record:
    // TP is the leader's: NativeControl is the record.
.Lprivate_call_have_record:
    mov rax, [rsp + 40]
    and rax, 0xff
    cmp [r13 + 16], rax
    jne .Lprivate_terminal
    mov qword ptr [r13 + 16], 5
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 24]
    lea r12, [rip + .Lprivate_fs_guest_ready]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_fs_guest_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    cmp qword ptr [rsp + 24], 0
    je .Lprivate_guest_scalar
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    movabs r11, {guest_gate}
    call r11
    mov r14, rax
    mov r15, rdx
    jmp .Lprivate_capture_guest_fs
.Lprivate_guest_scalar:
    mov rax, [rsp]
    mov rbx, [rsp + 8]
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    mov rdx, [rbx + 16]
    mov r10, [rbx + 24]
    mov r8, [rbx + 32]
    mov r9, [rbx + 40]
    lea r12, [rip + .Lprivate_guest_scalar_return]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_guest_scalar_return:
    endbr64
    mov r14, rax
    xor r15d, r15d
.Lprivate_capture_guest_fs:
    mov eax, 158
    mov edi, 0x1003
    lea rsi, [rsp + 32]
    lea r12, [rip + .Lprivate_captured_guest_fs]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_captured_guest_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 32]
    lea r12, [rip + .Lprivate_restored_tool_fs]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_restored_tool_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    mov rax, [rsp + 32]
    mov [r13 + 24], rax
    cmp qword ptr [r13 + 16], 5
    jne .Lprivate_terminal
    mov rax, [rsp + 40]
    and rax, 0xff
    mov [r13 + 16], rax
    mov rax, r14
    mov rdx, r15
    add rsp, 48
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.Lprivate_terminal:
    mov eax, 231
    mov edi, 127
    lea r12, [rip + .Lprivate_terminal]
    movabs r11, {native_gate}
    jmp r11
    .size reverie_inguest_private_lifecycle_call, .-reverie_inguest_private_lifecycle_call
"#,
    native_gate = const crate::trap::FIXED_NATIVE_ENTRY,
    max_threads = const tool_tls_registry::MAX_PRIVATE_TOOL_THREADS,
    guest_gate = const crate::trap::FIXED_GUEST_ENTRY,
);

pub(crate) type SignalHandler = unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void);
unsafe extern "C" {
    fn private_sigsys_plain(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_sigsys_pkru(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_instruction_plain(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_instruction_pkru(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
}
pub(crate) fn signal_entry(instruction: bool, pkru: bool) -> SignalHandler {
    match (instruction, pkru) {
        (false, false) => private_sigsys_plain,
        (false, true) => private_sigsys_pkru,
        (true, false) => private_instruction_plain,
        (true, true) => private_instruction_pkru,
    }
}
fn control_pointer() -> *mut NativeControl {
    reverie_inguest_private_exec_control.load(Ordering::Acquire) as *mut NativeControl
}
fn terminal() -> ! {
    unsafe {
        crate::trap::raw_syscall6(libc::SYS_exit_group, [127, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// The caller's current stack pointer, for slot-record derivation in
/// signal-handler context (the current frame lives on the signal stack).
fn current_stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reading rsp has no memory effect; the value is only
    // range-checked against the published layout.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
    }
    sp
}

/// Phase word of the record this thread is running under: the slot
/// record when a layout is published and the current stack is a slot
/// altstack, NativeControl for the leader ranges, terminal otherwise.
/// With no layout published this is exactly the pre-B2 leader word.
fn current_phase_word(control: *mut NativeControl) -> *mut u64 {
    let Some(layout) = tool_tls_slots::layout() else {
        return unsafe { &raw mut (*control).phase };
    };
    match layout.record_for_rsp(current_stack_pointer()) {
        tool_tls_slots::RecordRef::Leader => unsafe { &raw mut (*control).phase },
        tool_tls_slots::RecordRef::Slot(index) => {
            let record = layout.record_addr(index) as *mut tool_tls_slots::SlotRecord;
            unsafe { &raw mut (*record).phase }
        }
        tool_tls_slots::RecordRef::Terminal => terminal(),
    }
}

/// The caller's slot record for the two guest-registration syscalls
/// only (called solely from physical_syscall's ledger write, only
/// when a layout is published). `None` is the leader/system record.
/// A thread pointer resolving nowhere is terminal, mirroring the leaf.
fn current_slot_record_for_ledger(
    control: *mut NativeControl,
) -> Option<*mut tool_tls_slots::SlotRecord> {
    let layout = tool_tls_slots::layout()?;
    let mut fs = 0_u64;
    // SAFETY: ARCH_GET_FS writes one word to the owned out slot.
    let result = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if result != 0 {
        terminal();
    }
    // SAFETY: the published control stays valid for the process lifetime.
    if fs == unsafe { (&raw const (*control).tool_fs).read_volatile() } {
        return None;
    }
    match layout.record_for_tp(fs as usize) {
        tool_tls_slots::RecordRef::Slot(index) => {
            let record = layout.record_addr(index) as *mut tool_tls_slots::SlotRecord;
            // The leaf already checked this in assembly; the ledger write
            // re-checks it rather than trusting the geometry alone.
            if unsafe { (&raw const (*record).tool_fs).read_volatile() } != fs {
                terminal();
            }
            Some(record)
        }
        _ => terminal(),
    }
}
pub(crate) fn callback_prepared() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    let phase = current_phase_word(control);
    unsafe {
        if phase.read_volatile() != 3 {
            terminal();
        }
        phase.write_volatile(4);
    }
}
pub(crate) fn guest_completed() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    let phase = current_phase_word(control);
    unsafe {
        if phase.read_volatile() != 4 {
            terminal();
        }
        phase.write_volatile(3);
    }
}
pub(crate) fn private_instruction(address: u64) -> bool {
    let control = control_pointer();
    if control.is_null() {
        return false;
    }
    let phase = current_phase_word(control);
    unsafe {
        if !matches!(phase.read_volatile(), 2 | 4 | 6) {
            return false;
        }
        let count = (&raw const (*control).private_code_count).read_volatile();
        if count > 64 {
            terminal();
        }
        for i in 0..count as usize {
            let item = (&raw const (*control).code).cast::<PrivateCode>().add(i);
            let lo = (&raw const (*item).lo).read_volatile();
            let hi = (&raw const (*item).hi).read_volatile();
            if address >= lo && address < hi {
                return true;
            }
        }
    }
    false
}

// Classification only. A present mapped relay never grants callback authority;
// its downstream validator requires the actual Running installed Tool scope.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(super) fn mapped_callback_origin() -> bool {
    mapped_initial::libc_relay::callback::present()
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(super) fn mapped_callback_candidate() -> bool {
    let c = control_pointer();
    if !mapped_callback_origin() || c.is_null() {
        return false;
    }
    // The current record's phase (slot altstack -> that slot's record,
    // leader ranges -> NativeControl): a sibling in phase 4 no longer
    // classifies a leader-phase trap as a callback. Classification
    // only, so an event on no known altstack is simply not a
    // candidate here; the terminal derivation stays with the entry
    // helpers that own admission.
    let Some(layout) = tool_tls_slots::layout() else {
        return unsafe { (&raw const (*c).phase).read_volatile() } == 4;
    };
    match layout.record_for_rsp(current_stack_pointer()) {
        tool_tls_slots::RecordRef::Leader => {
            (unsafe { (&raw const (*c).phase).read_volatile() }) == 4
        }
        tool_tls_slots::RecordRef::Slot(index) => {
            let record = layout.record_addr(index) as *mut tool_tls_slots::SlotRecord;
            (unsafe { (&raw const (*record).phase).read_volatile() }) == 4
        }
        tool_tls_slots::RecordRef::Terminal => false,
    }
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(super) unsafe fn forward_mapped_callback(
    event: &mut super::event::SyscallEvent,
    frame: &mut crate::trap::frame::SignalFrame<'_>,
    observe: impl FnOnce(&super::event::SyscallEvent),
) {
    // SAFETY: called only with the actual exclusive decoded SIGSYS frame.
    unsafe { mapped_initial::libc_relay::callback::forward(event, frame, observe) };
}

// Only called after the normal SIGSYS provenance checks. Private libc has its
// own physical effects; it does not recursively enter Detcore. The genuine
// completion remains owned by continuation::complete, even inside Tool code.
pub(crate) unsafe fn relay_private_signal(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) -> bool {
    let ip = unsafe {
        (*context.cast::<libc::ucontext_t>()).uc_mcontext.gregs[libc::REG_RIP as usize] as u64
    };
    if super::continuation::is_completion_address(ip) || !private_instruction(ip.saturating_sub(2))
    {
        return false;
    }
    // Phase4 mapped traps must reach the normal genuine frame/reentry and
    // completion dispatcher, then the callback-only validator. Never call the
    // retired startup handler or authorize this IP solely from a code range.
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    if mapped_callback_candidate() {
        return false;
    }
    let control = control_pointer();
    let address = unsafe { (&raw const (*control).bootstrap_handler).read_volatile() };
    if address == 0 {
        terminal();
    }
    let handler: SignalHandler = unsafe { core::mem::transmute(address as usize) };
    unsafe {
        handler(signal, info, context);
    }
    true
}

// Native SA_SIGINFO bridges. The optional PKRU opening occurs before the first
// stack/global access. FS switches use only the fixed native gate. Rust sees
// only Tool FS, and no Rust/TLS access occurs after restoring guest FS.
core::arch::global_asm!(r#"
    .text
    .macro PRIVATE_SIGNAL_ENTRY name, handler, pkru
    .p2align 4
    .global \name
    .hidden \name
    .type \name,@function
\name:
    endbr64
    .if \pkru
    mov r8, rdx
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rdx, r8
    .endif
    lea rcx, [rip + \handler]
    jmp .Lprivate_signal_common
    .size \name, .-\name
    .endm
    PRIVATE_SIGNAL_ENTRY private_sigsys_plain, {syscall_handler}, 0
    PRIVATE_SIGNAL_ENTRY private_sigsys_pkru, {syscall_handler}, 1
    PRIVATE_SIGNAL_ENTRY private_instruction_plain, {instruction_handler}, 0
    PRIVATE_SIGNAL_ENTRY private_instruction_pkru, {instruction_handler}, 1
    .purgem PRIVATE_SIGNAL_ENTRY
.Lprivate_signal_common:
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    sub rsp, 16
    mov r14, rcx
    mov r13, [rip + reverie_inguest_private_exec_control]
    test r13, r13
    jz .Lprivate_signal_terminal
    // Record derivation (B2): with no slot layout published the leader
    // record is used exactly as before. With one published, the entry
    // RSP (rsp + 72 after the pushes above) selects the record: a slot
    // altstack interior gives that slot's record, a published leader
    // altstack range gives NativeControl, anything else is terminal.
    mov rax, [rip + reverie_inguest_private_slot_base]
    test rax, rax
    jz .Lprivate_signal_have_record
    lea rcx, [rsp + 72]
    cmp rcx, rax
    jb .Lprivate_signal_leader_check
    mov r10, rcx
    sub r10, rax
    mov rcx, [rip + reverie_inguest_private_slot_stride_log2]
    mov r11, r10
    shr r11, cl
    cmp r11, {max_threads}
    jae .Lprivate_signal_leader_check
    test r11, r11
    jz .Lprivate_signal_terminal
    mov r8, 1
    shl r8, cl
    dec r8
    and r10, r8
    cmp r10, [rip + reverie_inguest_private_slot_altstack_offset]
    jb .Lprivate_signal_terminal
    sub r10, [rip + reverie_inguest_private_slot_altstack_offset]
    cmp r10, [rip + reverie_inguest_private_slot_altstack_bytes]
    jae .Lprivate_signal_terminal
    shl r11, cl
    add rax, r11
    add rax, [rip + reverie_inguest_private_slot_record_offset]
    mov r13, rax
    jmp .Lprivate_signal_have_record
.Lprivate_signal_leader_check:
    lea rcx, [rsp + 72]
    mov rax, [rip + reverie_inguest_private_slot_leader_alt0]
    test rax, rax
    jz .Lprivate_signal_leader_check2
    cmp rcx, rax
    jb .Lprivate_signal_leader_check2
    cmp rcx, [rip + reverie_inguest_private_slot_leader_alt1]
    jb .Lprivate_signal_have_record
.Lprivate_signal_leader_check2:
    mov rax, [rip + reverie_inguest_private_slot_leader_alt2]
    test rax, rax
    jz .Lprivate_signal_terminal
    cmp rcx, rax
    jb .Lprivate_signal_terminal
    cmp rcx, [rip + reverie_inguest_private_slot_leader_alt3]
    jae .Lprivate_signal_terminal
.Lprivate_signal_have_record:
    mov eax, 158
    mov edi, 0x1003
    mov rsi, rsp
    lea r12, [rip + .Lprivate_signal_have_fs]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_signal_have_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
    mov r15, [r13 + 16]
    cmp r15, 3
    je .Lprivate_signal_from_guest
    cmp r15, 2
    je .Lprivate_signal_from_tool
    cmp r15, 4
    je .Lprivate_signal_from_tool
    cmp r15, 6
    jne .Lprivate_signal_terminal
.Lprivate_signal_from_tool:
    mov rax, [rsp]
    cmp rax, [r13 + 32]
    jne .Lprivate_signal_terminal
    jmp .Lprivate_signal_set_tool
.Lprivate_signal_from_guest:
    mov rax, [rsp]
    mov [r13 + 24], rax
.Lprivate_signal_set_tool:
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 32]
    lea r12, [rip + .Lprivate_signal_tool_ready]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_signal_tool_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
    mov rdi, [rsp + 32]
    mov rsi, [rsp + 24]
    mov rdx, [rsp + 16]
    call r14
    mov rax, [r13 + 16]
    cmp r15, 6
    jne .Lprivate_signal_non_lifecycle_return
    cmp rax, 6
    jne .Lprivate_signal_terminal
    jmp .Lprivate_signal_return
.Lprivate_signal_non_lifecycle_return:
    cmp rax, 3
    je .Lprivate_signal_return_guest
    cmp rax, 2
    je .Lprivate_signal_return
    cmp rax, 4
    jne .Lprivate_signal_terminal
    jmp .Lprivate_signal_return
.Lprivate_signal_return_guest:
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 24]
    lea r12, [rip + .Lprivate_signal_guest_ready]
    movabs r11, {native_gate}
    jmp r11
.Lprivate_signal_guest_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
.Lprivate_signal_return:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.Lprivate_signal_terminal:
    mov eax, 231
    mov edi, 127
    lea r12, [rip + .Lprivate_signal_terminal]
    movabs r11, {native_gate}
    jmp r11
"#,
    native_gate = const crate::trap::FIXED_NATIVE_ENTRY,
    max_threads = const tool_tls_registry::MAX_PRIVATE_TOOL_THREADS,
    syscall_handler = sym crate::trap::sigsys_handler,
    instruction_handler = sym super::instruction::instruction_sigsegv_handler,
);

#[cfg(all(test, feature = "exec-private-successor"))]
pub(super) fn set_mapped_successor_test_entry(
    owner: &InitialImageControl,
    entry: &MappedSuccessorEntry,
) {
    let control = owner.control as *mut NativeControl;
    unsafe {
        (&raw mut (*control).guest_rsp).write_volatile(entry.regs.rsp);
        (&raw mut (*control).guest_ld_entry).write_volatile(entry.regs.rip);
        (&raw mut (*control).guest_fs).write_volatile(entry.regs.fs_base);
        (&raw mut (*control).guest_pkru).write_volatile(entry.pkru.map(u64::from).unwrap_or(0));
    }
}

#[cfg(test)]
pub(super) fn lifecycle_test_owner() -> (Box<NativeControl>, InitialImageControl) {
    // Component fixture only: this does not install a signal frontend, redeem
    // a coordinator authorization or authenticate a native launch. Run only
    // in the isolated child used by the lifecycle tests.
    unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
    let mut fs = 0_u64;
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        },
        0
    );
    let mut native: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
    native.abi_version = 1;
    native.byte_len = size_of::<NativeControl>() as u64;
    native.phase = 2;
    native.tool_fs = fs;
    native.native_tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
    let address = core::ptr::from_mut(native.as_mut()) as usize;
    // Publish through the one physical publication so slot 0 exists in
    // the registry, exactly as the authenticated origins leave it. A
    // later call in the same isolated child (some tests rebuild the
    // owner per mutation, one even unpublishes mid-loop) keeps the
    // direct store instead: slot 0 is already registered for this
    // same child tid.
    match publish_control_slot(core::ptr::from_mut(native.as_mut())) {
        Ok(()) => {}
        Err(_)
            if tool_tls_registry::TOOL_TLS_REGISTRY.leader()
                == i32::try_from(native.native_tid).ok() =>
        {
            reverie_inguest_private_exec_control.store(address, Ordering::Release);
        }
        Err(error) => panic!("fixture control publication failed: {error}"),
    }
    (native, InitialImageControl::new(address))
}

#[cfg(test)]
pub(super) fn mark_lifecycle_test_frontend_installed(owner: &InitialImageControl) {
    assert_eq!(owner.installation.load(Ordering::Acquire), 0);
    // Exercises the lifecycle gate independently of the native installer;
    // finish's genuine kernel/frontend validation is never bypassed.
    owner.installation.store(2, Ordering::Release);
}

// Extents describe private native mappings, not guest ld.so or guest DSOs.
// Reuse the existing complete effective-range operation inventory, including
// huge-page rounding and Linux brk return semantics, through owner_overlaps.
pub(crate) fn overlaps_private(start: u64, length: u64) -> bool {
    let control = control_pointer();
    if control.is_null() || length == 0 {
        return false;
    }
    let lo = start & !4095;
    let hi = start.saturating_add(length);
    let overlaps = |first, end| lo < end && first < hi;
    if overlaps(0x5000_0000_0000, 0x5000_0008_0000)
        || overlaps(0x5300_0000_0000, 0x5300_0012_0000)
        || overlaps(0x5400_0000_0000, 0x5400_0080_0000)
    {
        return true;
    }
    unsafe {
        let count = (&raw const (*control).private_map_count).read_volatile();
        if count > 64 {
            terminal();
        }
        for i in 0..count as usize {
            let item = (&raw const (*control).maps).cast::<PrivateMap>().add(i);
            let first = (&raw const (*item).lo).read_volatile();
            let end = (&raw const (*item).hi).read_volatile();
            if overlaps(first, end) {
                return true;
            }
        }
    }
    false
}

/// One authenticated InitialImage's native handover. Not constructible from a
/// configuration flag, memfd seal or filter count alone.
pub struct InitialImageControl {
    control: usize,
    // 0 fresh, 1 installation attempted, 2 actual installation completed,
    // 3 final verification attempted, 4 ready. Failure never reopens a state.
    installation: AtomicUsize,
    region: core::sync::atomic::AtomicPtr<super::tool_region::ToolRegion>,
    installed_host: AtomicUsize,
    // 0 not started, 1 permit live, 2 callbacks completed, 3 refused/abandoned.
    // Neither a returned error nor dropping a permit reopens initialization.
    lifecycle: AtomicUsize,
    // 0 fresh-image lifecycle, 1 selected-state restore live, 2 restore
    // completed, 3 refused/abandoned.
    selected_restore: AtomicUsize,
}
impl InitialImageControl {
    fn new(control: usize) -> Self {
        Self {
            control,
            installation: AtomicUsize::new(0),
            region: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            installed_host: AtomicUsize::new(0),
            lifecycle: AtomicUsize::new(0),
            selected_restore: AtomicUsize::new(0),
        }
    }

    /// Check the authenticated initial Tool context before and after its one
    /// bounded vDSO rewrite, before any frontend or installed host is published.
    /// This grants no mapping or syscall exemption.
    pub fn check_initial_vdso_context(&self) -> io::Result<()> {
        if self.installation.load(Ordering::Acquire) != 0
            || self.installed_host.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            return Err(io::Error::other(
                "InitialImage vDSO rewrite is outside initial installation",
            ));
        }
        self.check_initial_thread()
    }

    /// Bind the actual stable installed ToolHost, before frontend installation.
    /// Only the backend's installed-handler bridge may supply this address.
    #[cfg(any(feature = "coordinator-rpc", test))]
    pub(super) fn bind_lifecycle_host(&self, host: usize) -> io::Result<()> {
        if host == 0 || self.installation.load(Ordering::Acquire) != 0 {
            return Err(io::Error::other(
                "InitialImage host binding is out of order",
            ));
        }
        self.check_initial_thread()?;
        self.installed_host
            .compare_exchange(0, host, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("InitialImage host was bound twice"))?;
        Ok(())
    }

    #[cfg(any(feature = "coordinator-rpc", test))]
    pub(super) fn begin_lifecycle(&self, host: usize) -> io::Result<InitialLifecyclePermit<'_>> {
        self.begin_lifecycle_with_selected_restore(host, 0)
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn begin_mapped_successor_lifecycle(
        &self,
        host: usize,
    ) -> io::Result<InitialLifecyclePermit<'_>> {
        self.begin_lifecycle_with_selected_restore(host, 2)
    }

    #[cfg(any(feature = "coordinator-rpc", test))]
    fn begin_lifecycle_with_selected_restore(
        &self,
        host: usize,
        expected_selected_restore: usize,
    ) -> io::Result<InitialLifecyclePermit<'_>> {
        if self
            .lifecycle
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.lifecycle.store(3, Ordering::Release);
            return Err(io::Error::other(
                "InitialImage lifecycle was attempted twice",
            ));
        }
        let permit = InitialLifecyclePermit {
            owner: self,
            host,
            completed: false,
            #[cfg(feature = "coordinator-rpc")]
            selected: expected_selected_restore == 2,
            _same_thread: core::marker::PhantomData,
        };
        if self.installation.load(Ordering::Acquire) != 2
            || host == 0
            || self.installed_host.load(Ordering::Acquire) != host
            || self.selected_restore.load(Ordering::Acquire) != expected_selected_restore
        {
            return Err(io::Error::other(
                "InitialImage lifecycle lacks its installed host/frontend",
            ));
        }
        self.check_initial_thread()?;
        Ok(permit)
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn begin_mapped_successor_restore(&self, host: usize) -> io::Result<()> {
        if self
            .selected_restore
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.lifecycle.store(3, Ordering::Release);
            return Err(io::Error::other(
                "InitialImage selected-state restoration attempted twice",
            ));
        }
        if host == 0
            || self.installed_host.load(Ordering::Acquire) != host
            || self.installation.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            self.mapped_successor_restore_failed();
            return Err(io::Error::other(
                "InitialImage selected-state restoration lacks its installed host",
            ));
        }
        if let Err(error) = self.check_initial_thread() {
            self.mapped_successor_restore_failed();
            return Err(error);
        }
        Ok(())
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn mapped_successor_restore_completed(&self) {
        self.selected_restore.store(2, Ordering::Release);
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn verify_mapped_successor_entry(
        &self,
        entry: &MappedSuccessorEntry,
    ) -> io::Result<()> {
        let control = self.control as *const NativeControl;
        if entry.regs.rsp != unsafe { (&raw const (*control).guest_rsp).read_volatile() }
            || entry.regs.rip != unsafe { (&raw const (*control).guest_ld_entry).read_volatile() }
            || entry.regs.fs_base != unsafe { (&raw const (*control).guest_fs).read_volatile() }
            || entry.pkru.map(u64::from).unwrap_or(0)
                != unsafe { (&raw const (*control).guest_pkru).read_volatile() }
            || entry.regs.rsp == 0
            || entry.regs.rip == 0
        {
            return Err(io::Error::other("mapped successor resume entry differs"));
        }
        Ok(())
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn mapped_successor_restore_failed(&self) {
        self.selected_restore.store(3, Ordering::Release);
        self.lifecycle.store(3, Ordering::Release);
    }

    fn check_initial_thread(&self) -> io::Result<()> {
        if self.control == 0
            || reverie_inguest_private_exec_control.load(Ordering::Acquire) != self.control
        {
            return Err(io::Error::other("InitialImage native owner differs"));
        }
        let control = self.control as *const NativeControl;
        let read = |p: *const u64| unsafe { p.read_volatile() };
        let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
        let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
        let mut fs = 0_u64;
        let rc = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        };
        if read(unsafe { &raw const (*control).phase }) != 2
            || read(unsafe { &raw const (*control).runtime_ready }) != 0
            || tid <= 0
            || pid != tid
            || tid as u64 != read(unsafe { &raw const (*control).native_tid })
            || rc != 0
            || fs == 0
            || fs != read(unsafe { &raw const (*control).tool_fs })
        {
            return Err(io::Error::other(
                "InitialImage lifecycle Tool FS/process/phase differs",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn terminate_lifecycle(&self) -> ! {
        self.lifecycle.store(3, Ordering::Release);
        // The private constructor has already authenticated and adopted the
        // surviving fixed gate. No diagnostic I/O can precede this exit.
        unsafe { initialization_failed(self.control as *mut NativeControl) }
    }
    /// Select the already installed filter while replacing its owned frontend.
    /// The backing must belong to this initializer's fixed Tool region.
    pub fn controller(
        &self,
        backing: super::tool_region::StackBacking,
    ) -> impl crate::lifecycle::LifecycleController {
        InitialImageController {
            owner: self,
            backing,
        }
    }
    /// Select the guest TSC policy once and save the real guest resume mask;
    /// keep bootstrap SIGSYS usable and inherited asynchronous signals blocked
    /// until native final resume.
    pub fn prepare_signal_state(
        &self,
        instructions: super::instruction::InstructionSubscriptions,
    ) -> io::Result<()> {
        self.check_initial_thread()?;
        if self.installation.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            return Err(io::Error::other(
                "InitialImage signal setup is out of order",
            ));
        }
        let control = self.control as *mut NativeControl;
        unsafe {
            verify_bootstrap_signal(control)?;
            select_guest_tsc(control, instructions)?;
        }
        let mut reserved = 1_u64 << (libc::SIGSYS - 1);
        if instructions.cpuid || instructions.rdtsc {
            reserved |= 1_u64 << (libc::SIGSEGV - 1);
        }
        unsafe {
            let mask = (&raw const (*control).kernel_mask).read_volatile() & !reserved;
            (&raw mut (*control).guest_resume_mask).write_volatile(mask);
        }
        for signal in 1..=64 {
            if matches!(signal, libc::SIGKILL | libc::SIGSTOP | libc::SIGSYS) {
                continue;
            }
            let mut action = crate::signal::KernelSigaction::default();
            unsafe { crate::signal::raw_sigaction(signal, None, Some(&mut action)) }
                .map_err(io::Error::from_raw_os_error)?;
            if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
                unsafe {
                    crate::signal::raw_sigaction(
                        signal,
                        Some(&crate::signal::KernelSigaction::default()),
                        None,
                    )
                }
                .map_err(io::Error::from_raw_os_error)?;
            }
        }
        Ok(())
    }
    /// Mark genuine Detcore installation complete. This does not itself enter
    /// Guest; only the native runner restores registrations, FS, mask and RSP.
    pub fn finish(&self) -> io::Result<()> {
        self.installation
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("private frontend installation did not complete once"))?;
        if self.installed_host.load(Ordering::Acquire) == 0
            || self.lifecycle.load(Ordering::Acquire) != 2
            || !matches!(self.selected_restore.load(Ordering::Acquire), 0 | 2)
        {
            self.lifecycle.store(3, Ordering::Release);
            return Err(io::Error::other(
                "InitialImage installed-host lifecycle did not complete",
            ));
        }
        let control = self.control as *mut NativeControl;
        if !crate::trap::has_dispatcher()
            || !crate::trap::signal_return_restricted()
            || unsafe { (&raw const (*control).phase).read_volatile() } != 2
            || unsafe { (&raw const (*control).runtime_ready).read_volatile() } != 0
        {
            return Err(io::Error::other("private Tool frontend is incomplete"));
        }
        let region = self.region.load(Ordering::Acquire);
        let region = unsafe { region.as_ref() }
            .ok_or_else(|| io::Error::other("private frontend has no owned signal stack"))?;
        unsafe { verify_final_frontend(control, region)? };
        // Per-thread Tool TLS slot layout (B1): claimed only when thread
        // admission was requested before finish; failure degrades births
        // and never fails this finish.
        tool_tls_slots::claim_and_publish_if_requested(region, control);
        #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
        unsafe {
            // Retire startup authority BEFORE genuine Ready; never carry it
            // into Guest, phase-4 callbacks or successor/lifecycle domains.
            mapped_initial::libc_relay::frontend::retire_if_mapped(self, region);
        }
        unsafe {
            (&raw mut (*control).runtime_ready).write_volatile(1);
        }
        self.installation.store(4, Ordering::Release);
        Ok(())
    }
}

/// A single synchronous lifecycle attempt on the installed host and native
/// thread. Not exported: only the core host can mark successful completion.
#[cfg(any(feature = "coordinator-rpc", test))]
pub(super) struct InitialLifecyclePermit<'a> {
    owner: &'a InitialImageControl,
    host: usize,
    completed: bool,
    #[cfg(feature = "coordinator-rpc")]
    selected: bool,
    _same_thread: core::marker::PhantomData<*mut ()>,
}

// SAFETY: every shared mapped-injection operation revalidates the
// actual initial thread, installed host, lifecycle phase, and
// selected-restore state before touching the published control.
#[cfg(feature = "coordinator-rpc")]
unsafe impl Sync for InitialLifecyclePermit<'_> {}

#[cfg(any(feature = "coordinator-rpc", test))]
impl InitialLifecyclePermit<'_> {
    #[cfg(feature = "coordinator-rpc")]
    fn check_mapped_injection(&self) -> io::Result<()> {
        if !self.selected
            || self.completed
            || self.owner.lifecycle.load(Ordering::Acquire) != 1
            || self.owner.installation.load(Ordering::Acquire) != 2
            || self.owner.installed_host.load(Ordering::Acquire) != self.host
            || self.owner.selected_restore.load(Ordering::Acquire) != 2
        {
            return Err(io::Error::other(
                "mapped successor injection permit differs",
            ));
        }
        self.owner.check_initial_thread()
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn validate_mapped_injection(&self) -> io::Result<()> {
        let result = self.check_mapped_injection();
        if result.is_err() {
            self.owner.lifecycle.store(3, Ordering::Release);
        }
        result
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn regs(&self, entry: &MappedSuccessorEntry) -> libc::user_regs_struct {
        if self.check_mapped_injection().is_err()
            || self.owner.verify_mapped_successor_entry(entry).is_err()
        {
            self.owner.terminate_lifecycle();
        }
        let mut regs = entry.regs;
        regs.fs_base = unsafe {
            (&raw const (*(self.owner.control as *const NativeControl)).guest_fs).read_volatile()
        };
        regs
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn pkru(&self, entry: &MappedSuccessorEntry) -> Option<u32> {
        entry.pkru
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn terminate(&self) -> ! {
        self.owner.terminate_lifecycle()
    }

    pub(super) fn complete(mut self) -> io::Result<()> {
        if self.owner.installation.load(Ordering::Acquire) != 2
            || self.owner.installed_host.load(Ordering::Acquire) != self.host
        {
            return Err(io::Error::other("InitialImage lifecycle owner changed"));
        }
        self.owner.check_initial_thread()?;
        self.owner
            .lifecycle
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("InitialImage lifecycle was refused"))?;
        self.completed = true;
        Ok(())
    }
}

#[cfg(any(feature = "coordinator-rpc", test))]
impl Drop for InitialLifecyclePermit<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.lifecycle.store(3, Ordering::Release);
        }
    }
}

struct InitialImageController<'a> {
    owner: &'a InitialImageControl,
    backing: super::tool_region::StackBacking,
}
impl crate::lifecycle::LifecycleController for InitialImageController<'_> {
    fn name(&self) -> &'static str {
        "authenticated-initial-image"
    }
    unsafe fn install(&self, config: &crate::lifecycle::RuntimeConfig) -> io::Result<()> {
        self.owner
            .installation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("private frontend installation attempted twice"))?;
        let super::tool_region::StackBacking::ToolRegion(region) = self.backing else {
            return Err(io::Error::other(
                "private frontend requires owned signal stack backing",
            ));
        };
        if !config.use_alt_stack || !config.restrict_signal_return || !crate::trap::has_dispatcher()
        {
            return Err(io::Error::other("invalid private frontend handover"));
        }
        unsafe {
            verify_bootstrap_signal(self.owner.control as *mut NativeControl)?;
        }
        #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
        if unsafe { mapped_initial::libc_relay::frontend::install_if_mapped(self.owner, region)? } {
            // Same controller publications are completed under the relay's
            // exclusive raw replacement interval. No second owner is created.
            return Ok(());
        }
        // Prepare frame/PKRU/owned stack before the final single raw action
        // replacement. Bootstrap SIGSYS remains usable throughout preparation.
        unsafe {
            crate::trap::install_handler_with_backing(true, self.backing)?;
        }
        crate::trap::set_signal_return_restricted();
        // No new seccomp filter: the authenticated inherited one is the owner.
        let unblocked = super::signal::reserved_signal_mask();
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&unblocked), None) }
            .map_err(io::Error::from_raw_os_error)?;
        self.owner
            .region
            .store(core::ptr::from_ref(region).cast_mut(), Ordering::Release);
        self.owner.installation.store(2, Ordering::Release);
        Ok(())
    }
}
unsafe fn verify_final_frontend(
    control: *mut NativeControl,
    region: &'static super::tool_region::ToolRegion,
) -> io::Result<()> {
    let mut fs = 0_u64;
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0
        || fs != unsafe { (&raw const (*control).tool_fs).read_volatile() }
        || tid <= 0
        || tid != pid
        || tid as u64 != unsafe { (&raw const (*control).native_tid).read_volatile() }
        || unsafe { super::sigalrm::seccomp_filter_count() } != Some(1)
    {
        return Err(io::Error::other(
            "private final Tool FS/process/filter differs",
        ));
    }
    let reserved = super::signal::reserved_signal_mask();
    let unmaskable = (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1));
    let mut mask = 0_u64;
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
        .map_err(io::Error::from_raw_os_error)?;
    if mask != !(reserved | unmaskable) {
        return Err(io::Error::other(
            "private final startup signal mask differs",
        ));
    }
    for (signal, instruction) in [(libc::SIGSYS, false), (libc::SIGSEGV, true)] {
        if reserved & (1_u64 << (signal - 1)) == 0 {
            continue;
        }
        let mut action = crate::signal::KernelSigaction::default();
        unsafe { crate::signal::raw_sigaction(signal, None, Some(&mut action)) }
            .map_err(io::Error::from_raw_os_error)?;
        if action.handler
            != signal_entry(instruction, crate::trap::pkru_present()) as *const () as u64
            || action.restorer != crate::trap::FIXED_SIGNAL_RESTORER_ENTRY
            || action.flags
                != (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
            || action.mask != 0
        {
            return Err(io::Error::other(
                "private final runtime signal action differs",
            ));
        }
    }
    let owned = region
        .registered_alternate_stack()
        .ok_or_else(|| io::Error::other("private final owned signal stack is unpublished"))?;
    let mut stack: libc::stack_t = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0
        || stack.ss_flags != 0
        || stack.ss_sp as usize != owned.bottom
        || owned.top.checked_sub(owned.bottom) != Some(stack.ss_size)
    {
        return Err(io::Error::other(
            "private final runtime alternate stack differs",
        ));
    }
    Ok(())
}
// The caller has checked its actual published owner, thread, FS and startup
// phase. This page describes physical state; it grants no admission itself.
unsafe fn select_guest_tsc(
    control: *mut NativeControl,
    instructions: super::instruction::InstructionSubscriptions,
) -> io::Result<()> {
    let read = |field: *const u64| unsafe { field.read_volatile() };
    // Validate the old fixed prefix before accessing either appended field.
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).native_state }) != 1
    {
        return Err(io::Error::other("private TSC control layout/state differs"));
    }
    let captured = read(unsafe { &raw const (*control).kernel_tsc });
    if !matches!(captured, 1 | 2) || read(unsafe { &raw const (*control).guest_tsc }) != 0 {
        return Err(io::Error::other(
            "private TSC policy is missing or already selected",
        ));
    }
    let selected = if instructions.rdtsc {
        libc::PR_TSC_SIGSEGV as u64
    } else {
        captured
    };
    unsafe { (&raw mut (*control).guest_tsc).write_volatile(selected) };
    Ok(())
}

unsafe fn verify_bootstrap_signal(control: *mut NativeControl) -> io::Result<()> {
    let read = |field: *const u64| unsafe { field.read_volatile() };
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    if tid <= 0
        || tid != pid
        || tid as u64 != read(unsafe { &raw const (*control).native_tid })
        || read(unsafe { &raw const (*control).phase }) != 2
        || unsafe { super::sigalrm::seccomp_filter_count() } != Some(1)
    {
        return Err(io::Error::other(
            "private bootstrap process/filter identity differs",
        ));
    }
    let mut fs = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0 || fs != read(unsafe { &raw const (*control).tool_fs }) {
        return Err(io::Error::other("private Tool FS differs at handover"));
    }
    let mut mask = 0_u64;
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
        .map_err(io::Error::from_raw_os_error)?;
    let forced = 1_u64 << (libc::SIGSYS - 1);
    let unmaskable = (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1));
    if mask != !(forced | unmaskable) {
        return Err(io::Error::other("private bootstrap startup mask differs"));
    }
    let mut action = crate::signal::KernelSigaction::default();
    unsafe { crate::signal::raw_sigaction(libc::SIGSYS, None, Some(&mut action)) }
        .map_err(io::Error::from_raw_os_error)?;
    if action.handler != read(unsafe { &raw const (*control).bootstrap_handler })
        || action.restorer != crate::trap::FIXED_SIGNAL_RESTORER_ENTRY
        || action.restorer != read(unsafe { &raw const (*control).bootstrap_restorer })
        || action.mask != 0
        || action.flags != (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
    {
        return Err(io::Error::other(
            "private bootstrap SIGSYS ownership differs",
        ));
    }
    let mut stack: libc::stack_t = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0],
        )
    };
    let first = read(unsafe { &raw const (*control).bootstrap_stack_base });
    let end = read(unsafe { &raw const (*control).bootstrap_stack_end });
    if rc != 0
        || stack.ss_flags != 0
        || stack.ss_sp as u64 != first
        || end.checked_sub(first) != Some(stack.ss_size as u64)
    {
        return Err(io::Error::other("private bootstrap signal stack differs"));
    }
    Ok(())
}

/// Exact protected-admission identity supplied by the successor installer.
/// These bytes name a verified ticket/state/config; they are not authentication
/// by themselves, and the generation is only an accidental-reuse discriminator.
#[cfg(feature = "exec-private-successor")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorBinding {
    /// Native image generation from the retained watched-birth authority.
    pub generation: u64,
    /// Digest of the redeemed ticket.
    pub ticket: [u8; 32],
    /// Digest of the admitted composite state.
    pub state: [u8; 32],
    /// Digest of the unchanged canonical Config.
    pub config: [u8; 32],
}

/// Exact fixed native loader-resume record mapped and filled by the actual
/// bootstrap, then loaded register-for-register by private_runner_resume.
#[cfg(feature = "exec-private-successor")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NativeLoaderResume {
    magic: u64,
    abi_version: u64,
    byte_len: u64,
    native_tid: u64,
    regs: libc::user_regs_struct,
    pkru: u64,
}
#[cfg(feature = "exec-private-successor")]
const _: () = {
    assert!(size_of::<NativeLoaderResume>() == 256);
    assert!(core::mem::offset_of!(NativeLoaderResume, regs) == 32);
    assert!(core::mem::offset_of!(NativeLoaderResume, pkru) == 248);
};
#[cfg(feature = "exec-private-successor")]
impl NativeLoaderResume {
    /// Fixed address is an ABI coordinate only, never admission authority.
    pub const ADDRESS: usize = 0x5300_0000_3000;
    /// Entire owned mapping size, including the zero-filled tail.
    pub const MAPPING_BYTES: usize = 4096;
    /// Capture and verify the actual protected record before loader progress.
    ///
    /// # Safety
    /// The genuine native initializer owns this complete aligned mapping and
    /// control, real bootstrap/filter/private FS and same watched physical
    /// leader. It authenticated HLNEXEC1 and the immutable namespace; no Guest
    /// or competing writer may run. The complete page is key0, read-only and
    /// listed in this control's actual protected map inventory. The final
    /// qualified runner must load this exact immutable record after restoring
    /// FS/mask/PKRU. This accessor checks data but supplies no such authority.
    pub unsafe fn capture(control: *const NativeControl) -> io::Result<Self> {
        unsafe { checked_initial_control(control)? };
        let read = |p: *const u64| unsafe { p.read_volatile() };
        let count = read(unsafe { &raw const (*control).private_map_count });
        if count == 0 || count > 64 {
            return Err(io::Error::other("native resume map count"));
        }
        let mut covered = false;
        for index in 0..count as usize {
            let map = unsafe { (*control).maps.as_ptr().add(index).read_volatile() };
            if map.lo == Self::ADDRESS as u64
                && map.hi == (Self::ADDRESS + Self::MAPPING_BYTES) as u64
                && map.prot == libc::PROT_READ as u64
                && map.flags == (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64
            {
                covered = true;
            }
        }
        if !covered {
            return Err(io::Error::other(
                "native resume lacks actual protected mapping",
            ));
        }
        let value = unsafe { (Self::ADDRESS as *const Self).read_volatile() };
        if value.magic != 0x3130_4745_5258_4c48
            || value.abi_version != 1
            || value.byte_len != 256
            || value.native_tid != read(unsafe { &raw const (*control).native_tid })
            || value.regs.rip != read(unsafe { &raw const (*control).guest_ld_entry })
            || value.regs.rsp != read(unsafe { &raw const (*control).guest_rsp })
            || value.regs.fs_base != read(unsafe { &raw const (*control).guest_fs })
            || value.pkru != read(unsafe { &raw const (*control).guest_pkru })
            || value.pkru > u32::MAX as u64
            || value.pkru & 1 != 0
            || value.regs.orig_rax != u64::MAX
            || value.regs.eflags != 0x202
        {
            return Err(io::Error::other("native resume actual binding differs"));
        }
        Ok(value)
    }
    /// Actual fixed native loader projection, not a saved syscall frame.
    pub fn registers(&self) -> libc::user_regs_struct {
        self.regs
    }
    /// Actual guest PKRU that the final runner restores.
    pub fn pkru(&self) -> u32 {
        self.pkru as u32
    }
    /// Build the lifecycle view from this same final assembly record.
    ///
    /// # Safety
    /// Keep capture's real owner and writer exclusion alive until the final
    /// runner consumes this unchanged mapping. No fabricated record is valid.
    pub unsafe fn image_entry(&self) -> ImageGuestEntry {
        unsafe { ImageGuestEntry::from_native_resume(self.regs, Some(self.pkru())) }
    }
}

/// Genuine native loader-resume registers and PKRU, with no SyscallEvent.
/// The unsafe owner supplies the real resume projection, including all GPRs;
/// this component never invents a syscall number or obtains a fake event.
#[cfg(feature = "exec-private-successor")]
pub struct ImageGuestEntry {
    regs: libc::user_regs_struct,
    pkru: Option<u32>,
}
/// Exact mapped-image resume registers and PKRU projected from
/// the retained mapped prelude, with no SyscallEvent.
#[cfg(feature = "exec-private-init")]
#[derive(Clone, Copy)]
pub struct MappedSuccessorEntry {
    regs: libc::user_regs_struct,
    pkru: Option<u32>,
}
#[cfg(feature = "exec-private-init")]
impl MappedSuccessorEntry {
    /// # Safety
    /// Capture the actual registers and PKRU that this mapped
    /// image's runner will use to resume its loader. Their
    /// storage must be owned and immutable until lifecycle/finish;
    /// no guest code may run or mutate them in between.
    pub unsafe fn from_mapped_resume(regs: libc::user_regs_struct, pkru: Option<u32>) -> Self {
        Self { regs, pkru }
    }

    /// Exact mapped loader-resume registers captured for this entry.
    pub fn registers(&self) -> libc::user_regs_struct {
        self.regs
    }

    /// Exact mapped loader-resume PKRU captured for this entry.
    pub fn pkru(&self) -> Option<u32> {
        self.pkru
    }
}

#[cfg(feature = "exec-private-successor")]
impl ImageGuestEntry {
    /// # Safety
    /// Capture the actual registers that this image's native runner will use
    /// to resume its loader, under the trusted native-launch contract. Their
    /// storage must be owned, not a destroyed old-image frame. No guest code
    /// may run before lifecycle/finish, nor may another owner mutate them.
    pub unsafe fn from_native_resume(regs: libc::user_regs_struct, pkru: Option<u32>) -> Self {
        Self { regs, pkru }
    }
}

/// A successor has its own controller and one-use post-exec authorization.
/// It cannot be constructed through an InitialImage client or lifecycle.
#[cfg(feature = "exec-private-successor")]
pub struct SuccessorImageControl {
    control: usize,
    binding: SuccessorBinding,
    owner_tid: u64,
    tool_fs: u64,
    installation: AtomicUsize,
    region: core::sync::atomic::AtomicPtr<super::tool_region::ToolRegion>,
    installed_host: AtomicUsize,
    restoration: AtomicUsize,
    lifecycle: AtomicUsize,
}

/// Publish only after an exact, same-watched-birth successor redemption.
///
/// # Safety
/// The installer must consume the actual SuccessorClient and validate exact
/// typed restore/Config/runtime/allocator/backing identities before invoking
/// this seam. It must vouch for the real successful kernel exec, immutable
/// loader namespace, fresh control/TLS, fixed gates and protected mappings.
/// The nonzero digests/generation are independently authenticated inputs, not
/// guest input or evidence that exec occurred. The calling PID=TID must own
/// Tool FS; no guest loader progress is allowed. The caller must retain fatal
/// ownership until finish succeeds; any error after exec is terminal.
/// This component does not implement an installer or a complete exec driver.
#[cfg(feature = "exec-private-successor")]
pub unsafe fn publish_authenticated_successor_control(
    control: *mut NativeControl,
    binding: SuccessorBinding,
) -> io::Result<SuccessorImageControl> {
    if binding.generation == 0
        || binding.ticket == [0; 32]
        || binding.state == [0; 32]
        || binding.config == [0; 32]
    {
        return Err(io::Error::other(
            "successor lacks its protected admission identity",
        ));
    }
    unsafe { publish_native_control(control)? };
    let owner = SuccessorImageControl {
        control: control as usize,
        binding,
        owner_tid: unsafe { (&raw const (*control).native_tid).read_volatile() },
        tool_fs: unsafe { (&raw const (*control).tool_fs).read_volatile() },
        installation: AtomicUsize::new(0),
        region: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        installed_host: AtomicUsize::new(0),
        restoration: AtomicUsize::new(0),
        lifecycle: AtomicUsize::new(0),
    };
    owner.check_thread(2)?;
    Ok(owner)
}

#[cfg(feature = "exec-private-successor")]
impl SuccessorImageControl {
    /// Check the actual fresh successor owner around its bounded vDSO rewrite.
    /// No frontend, host restoration or lifecycle may have started. This
    /// grants no mapping exemption and leaves the original signal mask intact.
    pub fn check_successor_vdso_context(&self) -> io::Result<()> {
        if self.installation.load(Ordering::Acquire) != 0
            || self.installed_host.load(Ordering::Acquire) != 0
            || self.restoration.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            return Err(io::Error::other(
                "successor vDSO rewrite is outside fresh installation",
            ));
        }
        self.check_thread(2)
    }

    /// Exact identity to send to the genuine CompleteNativeExec driver.
    pub fn binding(&self) -> SuccessorBinding {
        self.binding
    }

    fn poison(&self) {
        self.lifecycle.store(3, Ordering::Release);
    }

    fn check_thread(&self, expected_phase: u64) -> io::Result<()> {
        if self.control == 0
            || control_pointer() as usize != self.control
            || self.owner_tid == 0
            || self.tool_fs == 0
        {
            return Err(io::Error::other("successor native owner differs"));
        }
        let control = self.control as *const NativeControl;
        let read = |p: *const u64| unsafe { p.read_volatile() };
        let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
        let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
        let mut fs = 0_u64;
        let rc = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        };
        if read(unsafe { &raw const (*control).abi_version }) != 1
            || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
            || read(unsafe { &raw const (*control).phase }) != expected_phase
            || read(unsafe { &raw const (*control).runtime_ready }) != 0
            || read(unsafe { &raw const (*control).native_state }) != 1
            || tid <= 0
            || pid != tid
            || tid as u64 != self.owner_tid
            || read(unsafe { &raw const (*control).native_tid }) != self.owner_tid
            || rc != 0
            || fs != self.tool_fs
            || read(unsafe { &raw const (*control).tool_fs }) != self.tool_fs
        {
            return Err(io::Error::other("successor Tool FS/process/phase differs"));
        }
        Ok(())
    }

    pub(super) fn bind_lifecycle_host(&self, host: usize) -> io::Result<()> {
        if host == 0
            || self.installation.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            self.poison();
            return Err(io::Error::other("successor host binding is out of order"));
        }
        if let Err(error) = self.check_thread(2) {
            self.poison();
            return Err(error);
        }
        if self
            .installed_host
            .compare_exchange(0, host, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.poison();
            return Err(io::Error::other("successor host was bound twice"));
        }
        Ok(())
    }

    pub(super) fn begin_restore(&self, host: usize) -> io::Result<()> {
        if self
            .restoration
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.poison();
            return Err(io::Error::other(
                "successor state restoration attempted twice",
            ));
        }
        if host == 0
            || self.installed_host.load(Ordering::Acquire) != host
            || self.installation.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            self.poison();
            return Err(io::Error::other(
                "successor restoration lacks installed host",
            ));
        }
        if let Err(error) = self.check_thread(2) {
            self.poison();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn restore_completed(&self) {
        self.restoration.store(2, Ordering::Release);
    }
    pub(super) fn restore_failed(&self) {
        self.poison();
    }

    pub(super) fn begin_post_exec(
        &self,
        host: usize,
        entry: &ImageGuestEntry,
    ) -> io::Result<PostExecPermit<'_>> {
        if self
            .lifecycle
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.poison();
            return Err(io::Error::other("successor post-exec was attempted twice"));
        }
        let permit = PostExecPermit {
            inner: LifecyclePermit {
                owner: self,
                host,
                owner_tid: self.owner_tid,
                native_generation: self.binding.generation,
                running: true,
            },
            _same_thread: core::marker::PhantomData,
        };
        if host == 0
            || self.installed_host.load(Ordering::Acquire) != host
            || self.installation.load(Ordering::Acquire) != 2
            || self.restoration.load(Ordering::Acquire) != 2
        {
            return Err(io::Error::other(
                "successor post-exec lacks restored installed host/frontend",
            ));
        }
        self.check_thread(2)?;
        let control = self.control as *const NativeControl;
        if entry.regs.rsp != unsafe { (&raw const (*control).guest_rsp).read_volatile() }
            || entry.regs.rip != unsafe { (&raw const (*control).guest_ld_entry).read_volatile() }
            || entry.regs.fs_base != unsafe { (&raw const (*control).guest_fs).read_volatile() }
            || entry.pkru.map(u64::from).unwrap_or(0)
                != unsafe { (&raw const (*control).guest_pkru).read_volatile() }
            || entry.regs.rsp == 0
            || entry.regs.rip == 0
        {
            return Err(io::Error::other("successor native resume entry differs"));
        }
        unsafe { (&raw mut (*(self.control as *mut NativeControl)).phase).write_volatile(6) };
        Ok(permit)
    }

    pub(super) fn terminate_lifecycle(&self) -> ! {
        self.poison();
        unsafe { initialization_failed(self.control as *mut NativeControl) }
    }

    /// Select the guest TSC policy once and preserve the actual new image's
    /// desired mask while keeping private bootstrap SIGSYS usable and
    /// asynchronous signals blocked.
    pub fn prepare_signal_state(
        &self,
        instructions: super::instruction::InstructionSubscriptions,
    ) -> io::Result<()> {
        self.check_thread(2)?;
        if self.installation.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            self.poison();
            return Err(io::Error::other("successor signal setup is out of order"));
        }
        let control = self.control as *mut NativeControl;
        unsafe {
            verify_bootstrap_signal(control)?;
            select_guest_tsc(control, instructions)?;
        }
        let mut reserved = 1_u64 << (libc::SIGSYS - 1);
        if instructions.cpuid || instructions.rdtsc {
            reserved |= 1_u64 << (libc::SIGSEGV - 1);
        }
        unsafe {
            let mask = (&raw const (*control).kernel_mask).read_volatile() & !reserved;
            (&raw mut (*control).guest_resume_mask).write_volatile(mask);
        }
        for signal in 1..=64 {
            if matches!(signal, libc::SIGKILL | libc::SIGSTOP | libc::SIGSYS) {
                continue;
            }
            let mut action = crate::signal::KernelSigaction::default();
            unsafe { crate::signal::raw_sigaction(signal, None, Some(&mut action)) }
                .map_err(io::Error::from_raw_os_error)?;
            if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
                unsafe {
                    crate::signal::raw_sigaction(
                        signal,
                        Some(&crate::signal::KernelSigaction::default()),
                        None,
                    )
                }
                .map_err(io::Error::from_raw_os_error)?;
            }
        }
        Ok(())
    }
    /// Replace the inherited frontend without installing another filter.
    pub fn controller(
        &self,
        backing: super::tool_region::StackBacking,
    ) -> impl crate::lifecycle::LifecycleController {
        SuccessorImageController {
            owner: self,
            backing,
        }
    }

    /// Verify every existing physical finish proof, then invoke completion once
    /// and publish readiness only after its exact acknowledgment. The driver
    /// must return the same protected binding, not a synthesized local receipt.
    /// No closure is invoked when an earlier proof fails. Any attempt consumes
    /// finish; an error or panic never permits a retry.
    ///
    /// # Safety
    /// The caller must send genuine CompleteNativeExec on this admitted live
    /// connection and return the acknowledged binding. A closure returning
    /// matching bytes by itself is not protocol or kernel-exec evidence.
    pub unsafe fn finish(
        &self,
        complete: impl FnOnce(SuccessorBinding) -> io::Result<SuccessorBinding>,
    ) -> io::Result<()> {
        if self
            .installation
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.poison();
            return Err(io::Error::other(
                "successor frontend finish attempted twice",
            ));
        }
        // State4 is a distinct in-progress finish. A duplicate attempt poisons
        // state3, so even a completion closure ignoring that error cannot make
        // the outer attempt publish readiness. The guard poisons on unwind.
        let mut attempt = SuccessorFinishAttempt {
            owner: self,
            complete: false,
        };
        if self
            .lifecycle
            .compare_exchange(2, 4, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
            || self.installed_host.load(Ordering::Acquire) == 0
            || self.restoration.load(Ordering::Acquire) != 2
        {
            return Err(io::Error::other(
                "successor installed-host lifecycle did not complete",
            ));
        }
        self.check_thread(2)?;
        if !crate::trap::has_dispatcher() || !crate::trap::signal_return_restricted() {
            return Err(io::Error::other("successor Tool frontend is incomplete"));
        }
        let region = self.region.load(Ordering::Acquire);
        let region = unsafe { region.as_ref() }
            .ok_or_else(|| io::Error::other("successor frontend has no owned signal stack"))?;
        unsafe { verify_final_frontend(self.control as *mut NativeControl, region)? };
        if complete(self.binding)? != self.binding {
            return Err(io::Error::other(
                "successor completion acknowledgment differs",
            ));
        }
        if self.installation.load(Ordering::Acquire) != 3
            || self.lifecycle.load(Ordering::Acquire) != 4
        {
            return Err(io::Error::other(
                "successor finish was poisoned during completion",
            ));
        }
        // Completion transport cannot silently damage the proven frontend.
        self.check_thread(2)?;
        unsafe { verify_final_frontend(self.control as *mut NativeControl, region)? };
        unsafe {
            (&raw mut (*(self.control as *mut NativeControl)).runtime_ready).write_volatile(1)
        };
        self.lifecycle.store(2, Ordering::Release);
        self.installation.store(4, Ordering::Release);
        attempt.complete = true;
        Ok(())
    }
}

#[cfg(feature = "exec-private-successor")]
struct SuccessorFinishAttempt<'a> {
    owner: &'a SuccessorImageControl,
    complete: bool,
}
#[cfg(feature = "exec-private-successor")]
impl Drop for SuccessorFinishAttempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.poison();
        }
    }
}

/// Affine phase6 owner. Private construction, no Clone/Copy/Send/Sync.
/// Only the real host can consume it after its genuine post-exec hook succeeds.
#[cfg(feature = "exec-private-successor")]
pub struct PostExecPermit<'a> {
    inner: LifecyclePermit<'a>,
    _same_thread: core::marker::PhantomData<*mut ()>,
}

/// Borrowed injection capability inside the affine post-exec permit. Guest's
/// trait requires Send+Sync, but every operation verifies actual owner TID/FS;
/// it grants no ability to complete, clone or construct a lifecycle permit.
#[cfg(feature = "exec-private-successor")]
pub struct LifecyclePermit<'a> {
    owner: &'a SuccessorImageControl,
    host: usize,
    owner_tid: u64,
    native_generation: u64,
    running: bool,
}
#[cfg(feature = "exec-private-successor")]
impl LifecyclePermit<'_> {
    fn check(&self) -> io::Result<()> {
        if !self.running
            || self.owner.lifecycle.load(Ordering::Acquire) != 1
            || self.owner.installation.load(Ordering::Acquire) != 2
            || self.owner.installed_host.load(Ordering::Acquire) != self.host
            || self.owner.owner_tid != self.owner_tid
            || self.owner.binding.generation != self.native_generation
        {
            return Err(io::Error::other("successor lifecycle permit differs"));
        }
        self.owner.check_thread(6)
    }
    pub(super) fn validate(&self) -> io::Result<()> {
        let result = self.check();
        if result.is_err() {
            self.owner.poison();
        }
        result
    }
    pub(super) fn regs(&self, entry: &ImageGuestEntry) -> libc::user_regs_struct {
        if self.check().is_err() {
            self.owner.terminate_lifecycle();
        }
        let mut regs = entry.regs;
        regs.fs_base = unsafe {
            (&raw const (*(self.owner.control as *const NativeControl)).guest_fs).read_volatile()
        };
        regs
    }
    pub(super) fn pkru(&self, entry: &ImageGuestEntry) -> Option<u32> {
        entry.pkru
    }
    pub(super) fn terminate(&self) -> ! {
        self.owner.terminate_lifecycle()
    }
}
#[cfg(feature = "exec-private-successor")]
impl PostExecPermit<'_> {
    pub(super) fn injection_permit(&self) -> &LifecyclePermit<'_> {
        &self.inner
    }
    pub(super) fn complete(mut self) -> io::Result<()> {
        self.inner.check()?;
        self.inner
            .owner
            .lifecycle
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("successor lifecycle was refused"))?;
        unsafe {
            (&raw mut (*(self.inner.owner.control as *mut NativeControl)).phase).write_volatile(2)
        };
        self.inner.running = false;
        Ok(())
    }
}
#[cfg(feature = "exec-private-successor")]
impl Drop for PostExecPermit<'_> {
    fn drop(&mut self) {
        if self.inner.running {
            self.inner.owner.poison();
        }
    }
}

/// Execute only a guarded lifecycle operation, exact 6->5->6. This never
/// exposes the ordinary callback leaf as a phase6 fallback.
///
/// # Safety
/// The core host must apply all process/signal/mapping/descriptor guards first.
/// Arguments/storage must survive the physical leaf; no thread creation, exec,
/// tail/ending transition or callable guest signal delivery is admitted.
#[cfg(feature = "exec-private-successor")]
pub unsafe fn physical_lifecycle_syscall(
    permit: &LifecyclePermit<'_>,
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
) -> io::Result<crate::trap::NativeSyscallResult> {
    if let Err(error) = permit.check() {
        permit.owner.poison();
        return Err(error);
    }
    let result = unsafe {
        reverie_inguest_private_lifecycle_call(
            number,
            args.as_ptr(),
            u64::from(pkru.unwrap_or(0)),
            u64::from(pkru.is_some()),
        )
    };
    // The leaf restores Tool FS/phase before Rust touches the same success-only
    // registration ledger used by ordinary physical guest injections.
    let control = permit.owner.control as *mut NativeControl;
    unsafe {
        if number == libc::SYS_set_tid_address && result.result > 0 {
            (&raw mut (*control).kernel_clear_tid).write_volatile(args[0]);
        } else if number == libc::SYS_set_robust_list && result.result == 0 {
            (&raw mut (*control).kernel_robust_head).write_volatile(args[0]);
            (&raw mut (*control).kernel_robust_len).write_volatile(args[1]);
        }
    }
    if let Err(error) = permit.check() {
        permit.owner.poison();
        return Err(error);
    }
    Ok(crate::trap::NativeSyscallResult {
        result: result.result,
        pkru: pkru.map(|_| result.pkru as u32),
    })
}

/// Execute only a guarded mapped lifecycle operation. The phase
/// is bracketed 2 -> 6 -> leaf -> 2 for this one call, so Tool
/// libc calls before and after it use the mapped relay's phase 2.
/// This never exposes the ordinary callback leaf as a fallback.
///
/// # Safety
/// The core host must apply all process/signal/mapping/descriptor
/// guards first. Arguments/storage must survive the physical leaf;
/// no thread creation, exec, tail/ending transition or callable
/// guest signal delivery is admitted.
#[cfg(all(feature = "exec-private-init", feature = "coordinator-rpc"))]
pub(super) unsafe fn physical_mapped_lifecycle_syscall(
    permit: &InitialLifecyclePermit<'_>,
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
) -> io::Result<crate::trap::NativeSyscallResult> {
    permit.validate_mapped_injection()?;
    let control = permit.owner.control as *mut NativeControl;
    // SAFETY: validate_mapped_injection has just required phase 2
    // on this same initial thread and stable installed host.
    unsafe { (&raw mut (*control).phase).write_volatile(6) };
    let result = unsafe {
        reverie_inguest_private_lifecycle_call(
            number,
            args.as_ptr(),
            u64::from(pkru.unwrap_or(0)),
            u64::from(pkru.is_some()),
        )
    };
    // The leaf restored Tool FS and its expected phase (6). Restore
    // phase 2 before any other Rust or libc work in this function.
    unsafe { (&raw mut (*control).phase).write_volatile(2) };
    unsafe {
        if number == libc::SYS_set_tid_address && result.result > 0 {
            (&raw mut (*control).kernel_clear_tid).write_volatile(args[0]);
        } else if number == libc::SYS_set_robust_list && result.result == 0 {
            (&raw mut (*control).kernel_robust_head).write_volatile(args[0]);
            (&raw mut (*control).kernel_robust_len).write_volatile(args[1]);
        }
    }
    permit.validate_mapped_injection()?;
    Ok(crate::trap::NativeSyscallResult {
        result: result.result,
        pkru: pkru.map(|_| result.pkru as u32),
    })
}

#[cfg(feature = "exec-private-successor")]
struct SuccessorImageController<'a> {
    owner: &'a SuccessorImageControl,
    backing: super::tool_region::StackBacking,
}
#[cfg(feature = "exec-private-successor")]
impl crate::lifecycle::LifecycleController for SuccessorImageController<'_> {
    fn name(&self) -> &'static str {
        "authenticated-successor-image"
    }
    unsafe fn install(&self, config: &crate::lifecycle::RuntimeConfig) -> io::Result<()> {
        if self
            .owner
            .installation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.owner.poison();
            return Err(io::Error::other(
                "successor frontend installation attempted twice",
            ));
        }
        // A failed install, including unwind, can never enable lifecycle.
        self.owner.check_thread(2)?;
        if self.owner.installed_host.load(Ordering::Acquire) == 0
            || self.owner.restoration.load(Ordering::Acquire) != 2
            || self.owner.lifecycle.load(Ordering::Acquire) != 0
        {
            self.owner.poison();
            return Err(io::Error::other(
                "successor frontend lacks restored installed host",
            ));
        }
        let super::tool_region::StackBacking::ToolRegion(region) = self.backing else {
            return Err(io::Error::other(
                "private frontend requires owned signal stack backing",
            ));
        };
        if !config.use_alt_stack || !config.restrict_signal_return || !crate::trap::has_dispatcher()
        {
            return Err(io::Error::other("invalid private frontend handover"));
        }
        unsafe { verify_bootstrap_signal(self.owner.control as *mut NativeControl)? };
        unsafe { crate::trap::install_handler_with_backing(true, self.backing)? };
        crate::trap::set_signal_return_restricted();
        let unblocked = super::signal::reserved_signal_mask();
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&unblocked), None) }
            .map_err(io::Error::from_raw_os_error)?;
        self.owner
            .region
            .store(core::ptr::from_ref(region).cast_mut(), Ordering::Release);
        self.owner.installation.store(2, Ordering::Release);
        Ok(())
    }
}

#[cfg(all(test, feature = "exec-private-successor"))]
impl NativeControl {
    pub(super) fn successor_test_phase(&self) -> u64 {
        self.phase
    }

    pub(super) fn successor_test_runtime_ready(&self) -> u64 {
        self.runtime_ready
    }
}

#[cfg(all(test, feature = "exec-private-successor"))]
pub(super) fn successor_test_owner() -> (Box<NativeControl>, SuccessorImageControl, ImageGuestEntry)
{
    // Isolated native leaf fixture. No coordinator redemption, filter,
    // frontend installation, loader entry or kernel exec is claimed.
    unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
    let mut fs = 0_u64;
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        },
        0
    );
    let mut native: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
    native.abi_version = 1;
    native.byte_len = size_of::<NativeControl>() as u64;
    native.phase = 2;
    native.native_state = 1;
    native.tool_fs = fs;
    native.guest_fs = fs;
    native.guest_rsp = 0x1234_0000; // Component projection, never resumed.
    native.guest_ld_entry = 0x5678_0000;
    native.native_tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
    let address = core::ptr::from_mut(native.as_mut()) as usize;
    // Publish through the one physical publication so slot 0 exists in
    // the registry, exactly as the authenticated origins leave it. A
    // later call in the same isolated child (some tests rebuild the
    // owner per mutation, one even unpublishes mid-loop) keeps the
    // direct store instead: slot 0 is already registered for this
    // same child tid.
    match publish_control_slot(core::ptr::from_mut(native.as_mut())) {
        Ok(()) => {}
        Err(_)
            if tool_tls_registry::TOOL_TLS_REGISTRY.leader()
                == i32::try_from(native.native_tid).ok() =>
        {
            reverie_inguest_private_exec_control.store(address, Ordering::Release);
        }
        Err(error) => panic!("fixture control publication failed: {error}"),
    }
    let owner = SuccessorImageControl {
        control: address,
        binding: SuccessorBinding {
            generation: 7,
            ticket: [0x11; 32],
            state: [0x22; 32],
            config: [0x33; 32],
        },
        owner_tid: native.native_tid,
        tool_fs: fs,
        installation: AtomicUsize::new(0),
        region: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        installed_host: AtomicUsize::new(0),
        restoration: AtomicUsize::new(0),
        lifecycle: AtomicUsize::new(0),
    };
    let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    regs.rsp = native.guest_rsp;
    regs.rip = native.guest_ld_entry;
    regs.fs_base = native.guest_fs;
    let entry = unsafe { ImageGuestEntry::from_native_resume(regs, None) };
    (native, owner, entry)
}
#[cfg(all(test, feature = "exec-private-successor"))]
pub(super) fn mark_successor_test_frontend_installed(owner: &SuccessorImageControl) {
    assert_eq!(owner.installation.load(Ordering::Acquire), 0);
    assert_eq!(owner.restoration.load(Ordering::Acquire), 2);
    // Lifecycle-only fixture. Genuine finish still checks all real frontend,
    // signal mask, altstack, filter and same-owner proofs; none is bypassed.
    owner.installation.store(2, Ordering::Release);
}

#[cfg(all(test, feature = "exec-private-successor"))]
mod successor_tests {
    use super::*;
    thread_local! { static SENTINEL: core::cell::Cell<u64> = const { core::cell::Cell::new(0) }; }

    fn isolated(body: impl FnOnce() + std::panic::UnwindSafe, expected: i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
                0
            } else {
                125
            };
            unsafe { libc::_exit(status) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }
    fn ready(owner: &SuccessorImageControl) {
        owner.bind_lifecycle_host(1).unwrap();
        owner.begin_restore(1).unwrap();
        owner.restore_completed();
        mark_successor_test_frontend_installed(owner);
    }
    fn mask() -> u64 {
        let mut value = 0_u64;
        assert_eq!(
            unsafe {
                crate::trap::raw_syscall6(
                    libc::SYS_rt_sigprocmask,
                    [
                        libc::SIG_SETMASK as u64,
                        0,
                        (&raw mut value) as u64,
                        8,
                        0,
                        0,
                    ],
                )
            },
            0
        );
        value
    }
    #[test]
    fn successor_vdso_context_checks_actual_owner_and_refuses_started_stages() {
        // Actual fixed gate, PID=TID and FS queries; admission/loader/restore
        // stage authority remains a component fixture, never kernel-exec proof.
        for mode in 0..10 {
            isolated(
                move || {
                    let (mut native, owner, _entry) = successor_test_owner();
                    let native_mask = native.kernel_mask;
                    let physical_mask = mask();
                    owner.check_successor_vdso_context().unwrap();
                    owner.check_successor_vdso_context().unwrap();
                    assert_eq!(native.kernel_mask, native_mask);
                    assert_eq!(mask(), physical_mask);
                    match mode {
                        0 => native.phase = 3,
                        1 => native.native_tid += 1,
                        2 => native.tool_fs += 8,
                        3 => native.runtime_ready = 1,
                        4 => native.abi_version = 2,
                        5 => {
                            owner.bind_lifecycle_host(1).unwrap();
                        }
                        6 => {
                            owner.restoration.store(1, Ordering::Release);
                        }
                        7 => {
                            owner.installation.store(1, Ordering::Release);
                        }
                        8 => {
                            owner.lifecycle.store(1, Ordering::Release);
                        }
                        9 => {
                            native.native_state = 0;
                        }
                        _ => unreachable!(),
                    }
                    assert!(owner.check_successor_vdso_context().is_err());
                    assert_eq!(native.kernel_mask, native_mask);
                    assert_eq!(mask(), physical_mask);
                },
                0,
            );
        }
    }

    #[test]
    fn successor_phase6_injection_captures_actual_fs_errno_mask_and_restores_tool_tls() {
        isolated(
            || {
                let (native, owner, entry) = successor_test_owner();
                ready(&owner);
                let permit = owner.begin_post_exec(1, &entry).unwrap();
                assert_eq!(native.phase, 6);
                let original_mask = mask();
                SENTINEL.set(0xfeed_1234);
                unsafe {
                    *libc::__errno_location() = libc::ENOMSG;
                }
                let mut guest_tls = [0_u64; 32];
                let selected_fs = guest_tls.as_mut_ptr() as u64;
                let result = unsafe {
                    physical_lifecycle_syscall(
                        permit.injection_permit(),
                        libc::SYS_arch_prctl,
                        [0x1002, selected_fs, 0, 0, 0, 0],
                        None,
                    )
                }
                .unwrap();
                assert_eq!(result.result, 0);
                assert_eq!(native.guest_fs, selected_fs);
                assert_eq!(native.phase, 6);
                assert_eq!(SENTINEL.get(), 0xfeed_1234);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                let mut observed = 0_u64;
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            permit.injection_permit(),
                            libc::SYS_arch_prctl,
                            [0x1003, (&raw mut observed) as u64, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    0
                );
                assert_eq!(observed, selected_fs);
                let expected = unsafe {
                    crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, u64::MAX, 0, 0, 0, 0])
                };
                assert!(expected < 0);
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            permit.injection_permit(),
                            libc::SYS_arch_prctl,
                            [0x1002, u64::MAX, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    expected
                );
                assert_eq!(native.guest_fs, selected_fs);
                assert_eq!(permit.injection_permit().regs(&entry).fs_base, selected_fs);
                assert_eq!(native.phase, 6);
                assert_eq!(mask(), original_mask);
                assert_eq!(SENTINEL.get(), 0xfeed_1234);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                permit.complete().unwrap();
                assert_eq!(native.phase, 2);
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 2);
                assert!(owner.begin_post_exec(1, &entry).is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
            },
            0,
        );
    }
    #[test]
    fn successor_leaf_phase_is_selected_by_entry_label_and_cannot_borrow_callback() {
        for phase in [2, 4] {
            isolated(
                move || {
                    let (mut native, _owner, _entry) = successor_test_owner();
                    native.phase = phase;
                    let args = [73, 0, 0, 0, 0, 0];
                    unsafe {
                        reverie_inguest_private_lifecycle_call(
                            libc::SYS_exit_group,
                            args.as_ptr(),
                            0,
                            0,
                        );
                    }
                    panic!("wrong phase reached return");
                },
                127,
            );
        }
        isolated(
            || {
                let (native, owner, entry) = successor_test_owner();
                ready(&owner);
                let _permit = owner.begin_post_exec(1, &entry).unwrap();
                assert_eq!(native.phase, 6);
                unsafe {
                    physical_syscall(libc::SYS_exit_group, [73, 0, 0, 0, 0, 0], None);
                }
                panic!("ordinary callback accepted lifecycle phase");
            },
            127,
        );
    }
    #[test]
    fn successor_permit_refuses_changed_phase_control_tid_fs_readiness_and_abi() {
        for mutation in 0..7 {
            isolated(
                move || {
                    let (mut native, owner, entry) = successor_test_owner();
                    ready(&owner);
                    let permit = owner.begin_post_exec(1, &entry).unwrap();
                    match mutation {
                        0 => native.phase = 4,
                        1 => native.native_tid += 1,
                        2 => native.tool_fs += 8,
                        3 => native.runtime_ready = 1,
                        4 => native.byte_len -= 1,
                        5 => native.native_state = 3,
                        6 => reverie_inguest_private_exec_control.store(0, Ordering::Release),
                        _ => unreachable!(),
                    }
                    // This must return an error before the deliberately fatal
                    // syscall; a mistaken admission exits73, not expected0.
                    assert!(
                        unsafe {
                            physical_lifecycle_syscall(
                                permit.injection_permit(),
                                libc::SYS_exit_group,
                                [73, 0, 0, 0, 0, 0],
                                None,
                            )
                        }
                        .is_err()
                    );
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                    drop(permit);
                    assert!(owner.begin_post_exec(1, &entry).is_err());
                },
                0,
            );
        }
    }
    #[test]
    fn successor_entry_restore_host_and_duplicate_attempts_poison_before_hook() {
        for mutation in 0..6 {
            isolated(
                move || {
                    let (native, owner, mut entry) = successor_test_owner();
                    owner.bind_lifecycle_host(1).unwrap();
                    if mutation != 0 {
                        owner.begin_restore(1).unwrap();
                        owner.restore_completed();
                    }
                    if mutation != 1 {
                        owner.installation.store(2, Ordering::Release);
                    }
                    match mutation {
                        2 => entry.regs.rsp += 8,
                        3 => entry.regs.rip += 1,
                        4 => entry.regs.fs_base += 8,
                        5 => entry.pkru = Some(1),
                        _ => {}
                    }
                    assert!(owner.begin_post_exec(1, &entry).is_err());
                    assert_eq!(native.phase, 2);
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                    assert!(owner.begin_post_exec(1, &entry).is_err());
                },
                0,
            );
        }
        isolated(
            || {
                let (_native, owner, entry) = successor_test_owner();
                ready(&owner);
                assert!(owner.begin_post_exec(2, &entry).is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
            },
            0,
        );
        isolated(
            || {
                let (_native, owner, entry) = successor_test_owner();
                ready(&owner);
                let permit = owner.begin_post_exec(1, &entry).unwrap();
                assert!(owner.begin_post_exec(1, &entry).is_err());
                assert!(permit.complete().is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
            },
            0,
        );
    }
    #[test]
    fn successor_finish_requires_lifecycle_and_real_frontend_before_completion_callback() {
        for complete_lifecycle in [false, true] {
            isolated(
                move || {
                    let (native, owner, entry) = successor_test_owner();
                    ready(&owner);
                    if complete_lifecycle {
                        owner
                            .begin_post_exec(1, &entry)
                            .unwrap()
                            .complete()
                            .unwrap();
                    }
                    let count = core::cell::Cell::new(0);
                    let attempt = unsafe {
                        owner.finish(|binding| {
                            count.set(count.get() + 1);
                            Ok(binding)
                        })
                    };
                    assert!(attempt.is_err()); // no genuine native frontend fixture
                    assert_eq!(count.get(), 0);
                    assert_eq!(native.runtime_ready, 0);
                    assert!(
                        unsafe {
                            owner.finish(|binding| {
                                count.set(count.get() + 1);
                                Ok(binding)
                            })
                        }
                        .is_err()
                    );
                    assert_eq!(count.get(), 0);
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                },
                0,
            );
        }
    }
    #[test]
    fn successor_private_classifier_accepts_phase6_and_callback_entry_stays_exact3() {
        isolated(
            || {
                let (mut native, owner, entry) = successor_test_owner();
                native.private_code_count = 1;
                native.code[0] = PrivateCode {
                    lo: 0x1000,
                    hi: 0x2000,
                };
                ready(&owner);
                let permit = owner.begin_post_exec(1, &entry).unwrap();
                assert!(private_instruction(0x1234));
                assert!(!private_instruction(0x2000));
                permit.complete().unwrap();
                assert!(private_instruction(0x1234));
                native.phase = 3;
                assert!(!private_instruction(0x1234));
            },
            0,
        );
        isolated(
            || {
                let (_native, owner, entry) = successor_test_owner();
                ready(&owner);
                let _permit = owner.begin_post_exec(1, &entry).unwrap();
                callback_prepared();
                panic!("callback admitted lifecycle as guest");
            },
            127,
        );
    }
    #[test]
    fn isolated_successor_assertion_panic_is_a_nonzero_child_failure() {
        isolated(
            || panic!("fixture confirms catch_unwind cannot hide failure"),
            125,
        );
    }
    #[test]
    fn successor_borrowed_injection_capability_checks_actual_calling_thread() {
        isolated(
            || {
                let (_native, owner, entry) = successor_test_owner();
                ready(&owner);
                let permit = owner.begin_post_exec(1, &entry).unwrap();
                let inner = permit.injection_permit();
                std::thread::scope(|scope| {
                    scope
                        .spawn(move || {
                            assert!(
                                unsafe {
                                    physical_lifecycle_syscall(
                                        inner,
                                        libc::SYS_exit_group,
                                        [73, 0, 0, 0, 0, 0],
                                        None,
                                    )
                                }
                                .is_err()
                            );
                        })
                        .join()
                        .unwrap();
                });
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert!(permit.complete().is_err());
            },
            0,
        );
    }
    #[test]
    fn successor_lifecycle_registration_tracks_kernel_success_and_private_setters_stay_refused() {
        isolated(
            || {
                let (native, owner, entry) = successor_test_owner();
                ready(&owner);
                let permit = owner.begin_post_exec(1, &entry).unwrap();
                let inner = permit.injection_permit();
                let mut clear_tid = 73_i32;
                let clear_address = (&raw mut clear_tid) as u64;
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            inner,
                            libc::SYS_set_tid_address,
                            [clear_address, 0, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    native.native_tid as i64
                );
                assert_eq!(native.kernel_clear_tid, clear_address);
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let length = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            inner,
                            libc::SYS_set_robust_list,
                            [robust_address, length, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    0
                );
                assert_eq!(
                    (native.kernel_robust_head, native.kernel_robust_len),
                    (robust_address, length)
                );
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            inner,
                            libc::SYS_set_robust_list,
                            [0, length - 1, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    -i64::from(libc::EINVAL)
                );
                assert_eq!(
                    (native.kernel_robust_head, native.kernel_robust_len),
                    (robust_address, length)
                );
                for number in [libc::SYS_set_tid_address, libc::SYS_set_robust_list] {
                    let mut event = crate::guest::event::SyscallEvent {
                        number,
                        args: [0; 6],
                        instruction_pointer: 0,
                        result: i64::MIN,
                        context: 0,
                        dispatch: crate::guest::event::SyscallDispatch::Trap,
                        guest_pkru: None,
                        unsupported_refusal: None,
                    };
                    let mut observed = false;
                    unsafe {
                        crate::guest::trap_dispatch::forward_nested_tool_syscall(&mut event, |_| {
                            observed = true
                        })
                    };
                    assert_eq!(event.result, -i64::from(libc::EPERM));
                    assert!(!observed);
                    assert_eq!(native.kernel_clear_tid, clear_address);
                    assert_eq!(native.kernel_robust_head, robust_address);
                }
                let mut actual_head = 0_u64;
                let mut actual_length = 0_u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut actual_head) as u64,
                                (&raw mut actual_length) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                assert_eq!((actual_head, actual_length), (robust_address, length));
                assert_eq!(clear_tid, 73);
                // Fixture cleanup while local registration buffers still exist.
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(
                            inner,
                            libc::SYS_set_robust_list,
                            [0, length, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .unwrap()
                    .result,
                    0
                );
                assert_eq!(
                    unsafe {
                        physical_lifecycle_syscall(inner, libc::SYS_set_tid_address, [0; 6], None)
                    }
                    .unwrap()
                    .result,
                    native.native_tid as i64
                );
                assert_eq!(native.kernel_clear_tid, 0);
                permit.complete().unwrap();
                assert_eq!(native.phase, 2);
            },
            0,
        );
    }
    #[test]
    fn successor_finish_poison_during_in_progress_attempt_cannot_be_hidden_by_matching_bytes() {
        isolated(
            || {
                let (_native, owner, entry) = successor_test_owner();
                ready(&owner);
                owner
                    .begin_post_exec(1, &entry)
                    .unwrap()
                    .complete()
                    .unwrap();
                owner.installation.store(3, Ordering::Release);
                owner.lifecycle.store(4, Ordering::Release);
                let guard = SuccessorFinishAttempt {
                    owner: &owner,
                    complete: false,
                };
                let calls = core::cell::Cell::new(0);
                assert!(
                    unsafe {
                        owner.finish(|binding| {
                            calls.set(calls.get() + 1);
                            Ok(binding)
                        })
                    }
                    .is_err()
                );
                assert_eq!(calls.get(), 0);
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                drop(guard);
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
            },
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    thread_local! { static TOOL_SENTINEL: core::cell::Cell<u64> = const { core::cell::Cell::new(0) }; }
    fn isolated(body: fn(), expected: i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
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
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }
    #[cfg(feature = "coordinator-rpc")]
    fn mapped_permit_test_owner() -> (
        Box<NativeControl>,
        InitialImageControl,
        MappedSuccessorEntry,
    ) {
        let (mut native, owner) = lifecycle_test_owner();
        owner.bind_lifecycle_host(1).unwrap();
        owner.begin_mapped_successor_restore(1).unwrap();
        owner.mapped_successor_restore_completed();
        mark_lifecycle_test_frontend_installed(&owner);
        let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
        regs.rsp = 0x1234_0000;
        regs.rip = 0x5678_0000;
        regs.fs_base = native.tool_fs;
        native.guest_rsp = regs.rsp;
        native.guest_ld_entry = regs.rip;
        native.guest_fs = regs.fs_base;
        native.guest_pkru = 0;
        let entry = unsafe { MappedSuccessorEntry::from_mapped_resume(regs, None) };
        (native, owner, entry)
    }

    // These component controls install the actual fixed gate and reserve real
    // seqpacket FDs. They establish reporter mechanics, not native admission.
    fn refusal_socket() -> (i32, i32) {
        unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
        let mut pair = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        let output =
            unsafe { super::super::protect::reserve_tool_output_fd(pair[0], b"retired") }.unwrap();
        assert_eq!(super::super::protect::tool_output_fd(), Some(output));
        (output, pair[1])
    }

    #[test]
    fn initial_refusal_reporter_retains_actual_stage_and_errno_on_real_seqpacket() {
        isolated(
            || {
                let (_output, peer) = refusal_socket();
                for (stage, error, expected) in [
                    (
                        InitialRefusalStage::Lifecycle,
                        io::Error::from_raw_os_error(libc::EFAULT),
                        b"ERROR native initial refusal stage=L errno_present=1 errno_bits=0000000e\n",
                    ),
                    (
                        InitialRefusalStage::FinalFrontend,
                        io::Error::other("not serialized"),
                        b"ERROR native initial refusal stage=F errno_present=0 errno_bits=00000000\n",
                    ),
                ] {
                    unsafe { report_initial_refusal(stage, &error) };
                    let mut bytes = [0_u8; 128];
                    let size = unsafe {
                        libc::recv(peer, bytes.as_mut_ptr().cast(), bytes.len(), libc::MSG_DONTWAIT)
                    };
                    assert_eq!(size, expected.len() as isize);
                    assert_eq!(&bytes[..size as usize], expected);
                }
                assert_eq!(unsafe { libc::close(peer) }, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_refusal_reporter_omits_full_socket_without_changing_ofd_flags() {
        isolated(
            || {
                let (output, peer) = refusal_socket();
                let flags = unsafe { libc::fcntl(output, libc::F_GETFL) };
                assert!(flags >= 0);
                assert_eq!(flags & libc::O_NONBLOCK, 0);
                let size = 4096_i32;
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            output,
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            (&raw const size).cast(),
                            size_of::<i32>() as libc::socklen_t,
                        )
                    },
                    0
                );
                let bytes = [0xa5_u8; 1024];
                let mut queued = 0;
                loop {
                    let sent = unsafe {
                        libc::send(
                            output,
                            bytes.as_ptr().cast(),
                            bytes.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                    if sent < 0 {
                        assert_eq!(
                            io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        break;
                    }
                    assert_eq!(sent, bytes.len() as isize);
                    queued += 1;
                    assert!(queued < 64, "small socket did not reach pressure bound");
                }
                assert!(queued > 0);
                unsafe {
                    report_initial_refusal(
                        InitialRefusalStage::Lifecycle,
                        &io::Error::from_raw_os_error(libc::EFAULT),
                    )
                };
                assert_eq!(unsafe { libc::fcntl(output, libc::F_GETFL) }, flags);
                for _ in 0..queued {
                    let mut received = [0_u8; 1024];
                    assert_eq!(
                        unsafe {
                            libc::recv(
                                peer,
                                received.as_mut_ptr().cast(),
                                received.len(),
                                libc::MSG_DONTWAIT,
                            )
                        },
                        received.len() as isize
                    );
                    assert_eq!(received, bytes);
                }
                let mut byte = 0_u8;
                assert_eq!(
                    unsafe { libc::recv(peer, (&raw mut byte).cast(), 1, libc::MSG_DONTWAIT) },
                    -1
                );
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                assert_eq!(unsafe { libc::close(peer) }, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_refusal_reporter_omits_closed_peer_without_sigpipe_or_fd_retirement() {
        isolated(
            || {
                let (output, peer) = refusal_socket();
                assert_ne!(
                    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                    libc::SIG_ERR
                );
                assert_eq!(unsafe { libc::close(peer) }, 0);
                let flags = unsafe { libc::fcntl(output, libc::F_GETFL) };
                assert!(flags >= 0);
                unsafe {
                    report_initial_refusal(
                        InitialRefusalStage::FinalFrontend,
                        &io::Error::other("not serialized"),
                    )
                };
                assert_eq!(super::super::protect::tool_output_fd(), Some(output));
                assert_eq!(unsafe { libc::fcntl(output, libc::F_GETFL) }, flags);
            },
            0,
        );
    }

    #[test]
    fn native_terminal_reporter_retains_exact_reason_and_marks_overflow_on_real_seqpacket() {
        isolated(
            || {
                let (_output, peer) = refusal_socket();
                let receive = |expected: &[u8]| {
                    let mut bytes = [0_u8; 257];
                    let size = unsafe {
                        libc::recv(
                            peer,
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                        )
                    };
                    assert_eq!(size, expected.len() as isize);
                    assert_eq!(&bytes[..size as usize], expected);
                };
                unsafe {
                    report_native_terminal_reason("native exec final exact Tool snapshot changed")
                };
                receive(
                    b"ERROR native exec terminal: native exec final exact Tool snapshot changed\n",
                );

                const REASON_BYTES: usize = 256 - b"ERROR native exec terminal: ".len() - 1;
                static EXACT: [u8; REASON_BYTES] = [b'x'; REASON_BYTES];
                static TOO_LONG: [u8; REASON_BYTES + 1] = [b'y'; REASON_BYTES + 1];
                let reason = std::str::from_utf8(&EXACT).unwrap();
                let mut expected = [b'x'; 256];
                expected[..b"ERROR native exec terminal: ".len()]
                    .copy_from_slice(b"ERROR native exec terminal: ");
                expected[255] = b'\n';
                unsafe { report_native_terminal_reason(reason) };
                receive(&expected);
                unsafe { report_native_terminal_reason(std::str::from_utf8(&TOO_LONG).unwrap()) };
                receive(b"ERROR native exec terminal: [reason exceeds diagnostic bound]\n");
                assert_eq!(unsafe { libc::close(peer) }, 0);
            },
            0,
        );
    }

    #[test]
    fn native_terminal_reporter_omits_full_socket_without_changing_ofd_flags() {
        isolated(
            || {
                let (output, peer) = refusal_socket();
                let flags = unsafe { libc::fcntl(output, libc::F_GETFL) };
                assert!(flags >= 0);
                assert_eq!(flags & libc::O_NONBLOCK, 0);
                let size = 4096_i32;
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            output,
                            libc::SOL_SOCKET,
                            libc::SO_SNDBUF,
                            (&raw const size).cast(),
                            size_of::<i32>() as libc::socklen_t,
                        )
                    },
                    0
                );
                // A one-byte packet costs no more queue space than the ERROR
                // packet, so EAGAIN here also excludes the larger diagnostic.
                let byte = 0xa5_u8;
                let mut queued = 0;
                loop {
                    let sent = unsafe {
                        libc::send(
                            output,
                            (&raw const byte).cast(),
                            1,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                    if sent < 0 {
                        assert_eq!(
                            io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        break;
                    }
                    assert_eq!(sent, 1);
                    queued += 1;
                    assert!(queued < 64, "small socket did not reach pressure bound");
                }
                assert!(queued > 0);
                unsafe {
                    report_native_terminal_reason("native exec final runtime counters changed")
                };
                assert_eq!(super::super::protect::tool_output_fd(), Some(output));
                assert_eq!(unsafe { libc::fcntl(output, libc::F_GETFL) }, flags);
                for _ in 0..queued {
                    let mut received = 0_u8;
                    assert_eq!(
                        unsafe {
                            libc::recv(
                                peer,
                                (&raw mut received).cast(),
                                1,
                                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                            )
                        },
                        1
                    );
                    assert_eq!(received, byte);
                }
                let mut received = 0_u8;
                assert_eq!(
                    unsafe { libc::recv(peer, (&raw mut received).cast(), 1, libc::MSG_DONTWAIT) },
                    -1
                );
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                assert_eq!(unsafe { libc::close(peer) }, 0);
            },
            0,
        );
    }

    #[test]
    fn native_terminal_reporter_omits_closed_peer_without_sigpipe_or_fd_retirement() {
        isolated(
            || {
                let (output, peer) = refusal_socket();
                assert_ne!(
                    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                    libc::SIG_ERR
                );
                let mut mask = unsafe { core::mem::zeroed::<libc::sigset_t>() };
                assert_eq!(unsafe { libc::sigemptyset(&raw mut mask) }, 0);
                assert_eq!(unsafe { libc::sigaddset(&raw mut mask, libc::SIGPIPE) }, 0);
                assert_eq!(
                    unsafe {
                        libc::sigprocmask(libc::SIG_UNBLOCK, &raw const mask, core::ptr::null_mut())
                    },
                    0
                );
                assert_eq!(unsafe { libc::close(peer) }, 0);
                let flags = unsafe { libc::fcntl(output, libc::F_GETFL) };
                assert!(flags >= 0);
                unsafe { report_native_terminal_reason("native exec one-use provider failed") };
                assert_eq!(super::super::protect::tool_output_fd(), Some(output));
                assert_eq!(unsafe { libc::fcntl(output, libc::F_GETFL) }, flags);
            },
            0,
        );
    }

    // Physical transport component fixture, not native admission or actual
    // kernel restoration. Each isolated child owns these fixed mappings until
    // exit; production verifies the complete compiled RX page on connection.
    #[cfg(feature = "exec-native-injection")]
    fn native_rpc_stream_fixture() -> (
        &'static mut NativeControl,
        crate::guest::rpc::GuestRpcStream,
        std::os::unix::net::UnixStream,
    ) {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixListener;

        unsafe extern "C" {
            static reverie_inguest_fixed_gate_template: u8;
            static reverie_inguest_fixed_gate_template_end: u8;
        }
        let template = core::ptr::addr_of!(reverie_inguest_fixed_gate_template);
        assert_eq!(
            core::ptr::addr_of!(reverie_inguest_fixed_gate_template_end) as usize
                - template as usize,
            4096
        );
        let map = |address: usize| {
            let result = unsafe {
                libc::mmap(
                    address as *mut libc::c_void,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            assert_eq!(result as usize, address);
            result
        };
        let gate = map(0x5000_0000_0000);
        unsafe { core::ptr::copy_nonoverlapping(template, gate.cast::<u8>(), 4096) };
        assert_eq!(
            unsafe { libc::mprotect(gate, 4096, libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        let control = unsafe { &mut *map(0x5300_0000_0000).cast::<NativeControl>() };
        control.abi_version = 1;
        control.byte_len = size_of::<NativeControl>() as u64;
        control.phase = 2;
        control.native_state = 1;
        control.native_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003, &raw mut control.tool_fs) },
            0
        );
        assert_ne!(control.tool_fs, 0);
        assert!(!active());
        assert!(!crate::trap::fixed_gates_published());

        // Retain an owned directory while using the bounded procfd spelling
        // for AF_UNIX. No ambient TMPDIR length assumption or shared pathname.
        let directory_path =
            std::env::temp_dir().join(format!("hermit-native-rpc-state-{}", std::process::id()));
        std::fs::create_dir(&directory_path).unwrap();
        let directory = std::fs::File::open(&directory_path).unwrap();
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}/rpc", directory.as_raw_fd()));
        let listener = UnixListener::bind(&path).unwrap();
        // This fixture models exclusive protected ownership. There is no guest
        // execution/filter or authenticated initializer in this component test.
        let stream =
            unsafe { crate::guest::rpc::GuestRpcStream::connect_native(&path, control) }.unwrap();
        let (peer, _) = listener.accept().unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        drop(directory);
        std::fs::remove_dir(directory_path).unwrap();
        (control, stream, peer)
    }

    #[cfg(feature = "exec-native-injection")]
    fn native_rpc_exchange(
        stream: &mut crate::guest::rpc::GuestRpcStream,
        peer: &mut std::os::unix::net::UnixStream,
        sent: &[u8],
    ) {
        use std::io::Read;
        use std::io::Write;
        let mut received = vec![0; sent.len()];
        stream.write_all(sent).unwrap();
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, sent);
        peer.write_all(b"ack").unwrap();
        let mut ack = [0; 3];
        stream.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ack");
    }

    #[cfg(feature = "exec-native-injection")]
    fn publish_native_rpc_fixture(control: &mut NativeControl) {
        // Model publication only; the production adoption still verifies every
        // actual RX template byte. This is not a coordinator admission receipt.
        reverie_inguest_private_exec_control.store(control as *mut _ as usize, Ordering::Release);
        unsafe { crate::trap::adopt_authenticated_initial_gate() }.unwrap();
    }

    #[cfg(feature = "exec-native-injection")]
    #[test]
    fn native_rpc_stream_preserves_socket_across_restored_kernel_state() {
        isolated(
            || {
                use std::os::fd::AsRawFd;
                let (control, mut stream, mut peer) = native_rpc_stream_fixture();
                let fd = stream.as_raw_fd();
                native_rpc_exchange(&mut stream, &mut peer, b"captured-bootstrap");
                publish_native_rpc_fixture(control);
                // Primitive phase6 coverage models the surrounding lifecycle
                // owner; numeric state does not supply a LifecyclePermit.
                control.phase = 6;
                native_rpc_exchange(&mut stream, &mut peer, b"captured-lifecycle");
                control.phase = 4;
                control.runtime_ready = 1;
                control.native_state = 3; // Modeled post-restoration observation.
                assert_eq!(stream.as_raw_fd(), fd);
                native_rpc_exchange(&mut stream, &mut peer, b"restored-callback");
                assert_eq!(stream.as_raw_fd(), fd);
                drop(stream);
            },
            0,
        );
    }

    #[cfg(feature = "exec-native-injection")]
    fn refuse_native_rpc_state(phase: u64, ready: u64, state: u64, publish: bool) {
        use std::io::Write;
        let (control, mut stream, mut peer) = native_rpc_stream_fixture();
        native_rpc_exchange(&mut stream, &mut peer, b"valid-preflight");
        if publish {
            publish_native_rpc_fixture(control);
        }
        control.phase = phase;
        control.runtime_ready = ready;
        control.native_state = state;
        let _ = stream.write_all(b"must-refuse");
        // If a forbidden transfer returns, exit before any invalid-state Drop
        // can turn an accepted transfer into a misleading terminal success.
        unsafe { libc::_exit(73) }
    }

    #[cfg(feature = "exec-native-injection")]
    #[test]
    fn native_rpc_stream_refuses_wrong_kernel_state_triples() {
        isolated(|| refuse_native_rpc_state(2, 0, 3, false), 127);
        isolated(|| refuse_native_rpc_state(2, 0, 3, true), 127);
        isolated(|| refuse_native_rpc_state(6, 0, 3, true), 127);
        isolated(|| refuse_native_rpc_state(4, 1, 1, true), 127);
        isolated(|| refuse_native_rpc_state(4, 1, 2, true), 127);
        isolated(|| refuse_native_rpc_state(4, 1, 7, true), 127);
        isolated(|| refuse_native_rpc_state(4, 1, u64::MAX, true), 127);
        isolated(|| refuse_native_rpc_state(3, 1, 3, true), 127);
        isolated(|| refuse_native_rpc_state(4, 0, 3, true), 127);
        isolated(|| refuse_native_rpc_state(2, 1, 1, true), 127);
    }

    #[cfg(feature = "exec-native-injection")]
    #[test]
    fn native_exec_callback_facts_requires_restored_kernel_state() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                control.runtime_ready = 1;
                control.native_state = 3;
                // Query the actual existing registration; do not mutate the
                // kernel to manufacture agreement with the modeled ledger.
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut control.kernel_robust_head) as u64,
                                (&raw mut control.kernel_robust_len) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let facts = native_exec_callback_facts().expect("actual ready restored callback");
                assert_eq!(facts.control_address, (&raw const control) as usize);
                assert_eq!(facts.native_tid as u64, control.native_tid);
                assert_eq!(facts.phase, 4);
                assert_eq!(facts.tool_fs, control.tool_fs);
                assert_eq!(facts.guest_fs, control.guest_fs);
                assert_eq!(
                    facts.registrations,
                    GuestKernelRegistrations {
                        clear_tid: 0, // Explicit modeled capture; Linux has no query.
                        robust_head: control.kernel_robust_head,
                        robust_len: control.kernel_robust_len,
                    }
                );
                let mut mask = 0;
                unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
                    .unwrap();
                assert_eq!(facts.physical_mask, mask);
                for state in [0, 1, 2, 4, 7, u64::MAX] {
                    unsafe { (&raw mut control.native_state).write_volatile(state) };
                    assert_eq!(native_exec_callback_facts(), None, "native_state={state}");
                }
                unsafe { (&raw mut control.native_state).write_volatile(3) };
                assert_eq!(native_exec_callback_facts(), Some(facts));
                unsafe { (&raw mut control.phase).write_volatile(3) };
                assert_eq!(native_exec_callback_facts(), None);
                unsafe { (&raw mut control.phase).write_volatile(4) };
                unsafe { (&raw mut control.runtime_ready).write_volatile(0) };
                assert_eq!(native_exec_callback_facts(), None);
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                assert_eq!(native_exec_callback_facts(), Some(facts));
            },
            0,
        );
    }

    unsafe fn scalar_control() -> NativeControl {
        unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
        let mut fs = 0_u64;
        assert_eq!(
            unsafe {
                crate::trap::raw_syscall6(
                    libc::SYS_arch_prctl,
                    [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
                )
            },
            0
        );
        let mut control: NativeControl = unsafe { core::mem::zeroed() };
        control.abi_version = 1;
        control.byte_len = size_of::<NativeControl>() as u64;
        control.phase = 4;
        control.tool_fs = fs;
        control.guest_fs = 0;
        control
    }
    #[test]
    fn physical_guest_set_fs_preserves_tool_tls_and_keeps_actual_success_or_error() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                // A native-leaf-only fixture. This assignment is NOT initializer,
                // coordinator, filter adoption or guest-launch authentication.
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                TOOL_SENTINEL.set(0x54_4f_4f_4c);
                unsafe {
                    *libc::__errno_location() = libc::ENOMSG;
                }
                let mut guest_tls = [0_u64; 32];
                let selected_fs = guest_tls.as_mut_ptr() as u64;
                let result = unsafe {
                    physical_syscall(
                        libc::SYS_arch_prctl,
                        [0x1002, selected_fs, 0, 0, 0, 0],
                        None,
                    )
                };
                assert_eq!(result.result, 0);
                assert_eq!(control.guest_fs, selected_fs);
                assert_eq!(TOOL_SENTINEL.get(), 0x54_4f_4f_4c);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                let mut observed = 0_u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_arch_prctl,
                            [0x1003, (&raw mut observed) as u64, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(observed, selected_fs);
                let expected = unsafe {
                    crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, u64::MAX, 0, 0, 0, 0])
                };
                assert!(expected < 0);
                let error = unsafe {
                    physical_syscall(libc::SYS_arch_prctl, [0x1002, u64::MAX, 0, 0, 0, 0], None)
                };
                assert_eq!(error.result, expected);
                assert_eq!(control.guest_fs, selected_fs);
                assert_eq!(TOOL_SENTINEL.get(), 0x54_4f_4f_4c);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                assert_eq!(control.phase, 4);
            },
            0,
        );
    }
    #[test]
    fn birth_block_mask_excludes_reserved_unblockable_and_faults() {
        let bit = |signal: i32| 1_u64 << (signal - 1);
        // SIGALRM is in neither the fault nor the unblockable set, so
        // only the reserved argument can keep it unblocked.
        let reserved = bit(libc::SIGSYS) | bit(libc::SIGSEGV) | bit(libc::SIGALRM);
        let mask = birth_block_mask(reserved);
        assert_ne!(mask & bit(libc::SIGUSR1), 0);
        assert_eq!(mask & bit(libc::SIGALRM), 0);
        for signal in [
            libc::SIGKILL,
            libc::SIGSTOP,
            libc::SIGILL,
            libc::SIGTRAP,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGSEGV,
            libc::SIGSYS,
        ] {
            assert_eq!(mask & bit(signal), 0, "signal {signal} must stay unblocked");
        }
        // With nothing reserved, the fault set itself must still keep
        // every synchronous fault signal (SIGSYS included) unblocked.
        let bare = birth_block_mask(0);
        assert_ne!(bare & bit(libc::SIGUSR1), 0);
        for signal in [
            libc::SIGILL,
            libc::SIGTRAP,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGSEGV,
            libc::SIGSYS,
        ] {
            assert_eq!(
                bare & bit(signal),
                0,
                "fault signal {signal} must stay unblocked with no reserved set"
            );
        }
    }

    #[test]
    fn birth_signal_guard_is_not_send() {
        // Ambiguous-impl pattern (as in static_assertions'
        // assert_not_impl_any): if BirthSignalGuard were Send, both
        // impls would apply and the check call would not compile.
        // Dropping the guard on another thread would restore the
        // mask there, so Send must stay off.
        trait AmbiguousIfSend<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSend<()> for T {}
        struct Invalid;
        impl<T: ?Sized + Send> AmbiguousIfSend<Invalid> for T {}
        <BirthSignalGuard as AmbiguousIfSend<_>>::check();
    }

    #[test]
    fn birth_signal_guard_round_trips_the_exact_mask() {
        isolated(
            || {
                fn query_mask() -> u64 {
                    let mut current = 0_u64;
                    let result = unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_rt_sigprocmask,
                            [0, 0, (&raw mut current) as u64, 8, 0, 0],
                        )
                    };
                    assert_eq!(result, 0);
                    current
                }
                // Seed a mask the guard must neither clear (SIGBUS is a
                // fault signal the birth set skips) nor invent bits over.
                let seeded_bits: u64 = (1 << (libc::SIGUSR2 - 1)) | (1 << (libc::SIGBUS - 1));
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_rt_sigprocmask,
                            [0, (&raw const seeded_bits) as u64, 0, 8, 0, 0],
                        )
                    },
                    0
                );
                let before = query_mask();
                assert_eq!(before & seeded_bits, seeded_bits);
                {
                    let guard = BirthSignalGuard::arm(1 << (libc::SIGALRM - 1)).unwrap();
                    assert_eq!(guard.saved_mask(), before);
                    let during = query_mask();
                    assert_ne!(during & (1 << (libc::SIGUSR1 - 1)), 0);
                    assert_ne!(during & (1 << (libc::SIGBUS - 1)), 0);
                    assert_eq!(during & (1 << (libc::SIGALRM - 1)), 0);
                    assert_eq!(during & (1 << (libc::SIGSEGV - 1)), 0);
                }
                assert_eq!(query_mask(), before);
            },
            0,
        );
    }

    #[test]
    fn physical_call_on_slot_record_writes_slot_ledger() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let real_fs = control.tool_fs;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                // Synthetic two-stride block; slot 1 carries a minimal TCB
                // whose canary word copies this thread's, so Rust frames
                // between the FS switches still validate.
                let stride = 128 * 1024usize;
                let total = 3 * stride;
                let raw = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        total,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(raw, libc::MAP_FAILED);
                let base = (raw as usize + stride - 1) & !(stride - 1);
                let layout = tool_tls_slots::SlotLayout {
                    block_base: base,
                    stride_log2: 17,
                    stride,
                    record_offset: 4096,
                    tsd_offset: 8192,
                    altstack_offset: 16384,
                    altstack_bytes: 65536,
                    backing_offset: 16384 + 65536 + 4096,
                    tp_offset: 4096,
                    callback_base: 0,
                    callback_stride: 8 * 1024 * 1024 + 8192,
                    leader_altstacks: [(0, 0), (0, 0)],
                };
                let tp = layout.tool_fs_for_slot(1);
                let backing = layout.backing(1) as *mut u64;
                let mut guest_tls = [0_u64; 16];
                let guest_fs = guest_tls.as_mut_ptr() as u64;
                let clear_word = Box::into_raw(Box::new(0_u64));
                let record = layout.record_addr(1) as *mut u64;
                unsafe {
                    *backing = 1;
                    *backing.add(1) = backing as u64;
                    *(tp as *mut u64) = tp as u64;
                    *((tp + 8) as *mut u64) = backing as u64;
                    *((tp + 0x28) as *mut u64) = *((real_fs + 0x28) as *const u64);
                    *record.add(2) = 4; // phase
                    *record.add(3) = guest_fs;
                    *record.add(4) = tp as u64;
                }
                tool_tls_slots::install_layout_for_test(layout);
                // No TLS, errno or allocation access between the switches:
                // only raw gate calls and the leaf itself.
                let codes = unsafe {
                    let set = crate::trap::raw_syscall6(
                        libc::SYS_arch_prctl,
                        [0x1002, tp as u64, 0, 0, 0, 0],
                    );
                    let got_tid = physical_syscall(libc::SYS_gettid, [0; 6], None).result;
                    let settid = physical_syscall(
                        libc::SYS_set_tid_address,
                        [clear_word as u64, 0, 0, 0, 0, 0],
                        None,
                    )
                    .result;
                    let robust =
                        physical_syscall(libc::SYS_set_robust_list, [0x5000, 24, 0, 0, 0, 0], None)
                            .result;
                    let back = crate::trap::raw_syscall6(
                        libc::SYS_arch_prctl,
                        [0x1002, real_fs, 0, 0, 0, 0],
                    );
                    (set, got_tid, settid, robust, back)
                };
                assert_eq!(codes, (0, tid, tid, 0, 0));
                unsafe {
                    // The slot ledger took the registration; the leader's
                    // did not. Guest FS was captured into the slot record.
                    assert_eq!(*record.add(11), clear_word as u64); // guest_clear_tid
                    assert_eq!(*record.add(12), 0x5000); // guest_robust_head
                    assert_eq!(*record.add(13), 24); // guest_robust_len
                    assert_eq!(*record.add(3), guest_fs);
                    assert_eq!(*record.add(2), 4);
                }
                assert_eq!(control.kernel_clear_tid, 0);
                assert_eq!(control.kernel_robust_head, 0);
                assert_eq!(control.kernel_robust_len, 0);
                assert_eq!(control.guest_fs, 0);
            },
            0,
        );
    }
    static SLOT_OVERLAP_ARRIVED: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    static SLOT_OVERLAP_PHASES: [core::sync::atomic::AtomicU64; 2] = [
        core::sync::atomic::AtomicU64::new(0),
        core::sync::atomic::AtomicU64::new(0),
    ];

    extern "C" fn slot_overlap_handler(_signal: i32) {
        // Runs on this thread's slot altstack (SA_ONSTACK delivery).
        callback_prepared();
        // Record the phase this thread's own record shows at the barrier,
        // not only the end state after completion.
        if let Some(layout) = tool_tls_slots::layout()
            && let tool_tls_slots::RecordRef::Slot(index) =
                layout.record_for_rsp(current_stack_pointer())
            && (1..=2).contains(&index)
        {
            let phase = current_phase_word(control_pointer());
            SLOT_OVERLAP_PHASES[index - 1].store(
                unsafe { phase.read_volatile() },
                core::sync::atomic::Ordering::SeqCst,
            );
        }
        SLOT_OVERLAP_ARRIVED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        while SLOT_OVERLAP_ARRIVED.load(core::sync::atomic::Ordering::SeqCst) < 2 {
            // SAFETY: scalar yield through libc; no TLS state is touched.
            unsafe {
                libc::syscall(libc::SYS_sched_yield);
            }
        }
        guest_completed();
    }

    fn synthetic_two_slot_layout(record_words: bool) -> (usize, tool_tls_slots::SlotLayout) {
        let stride = 128 * 1024usize;
        // One extra stride of slack so the stride-aligned base plus two
        // full slots (slot index 2's altstack top included) always stays
        // inside the mapping.
        let total = 4 * stride;
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let base = (raw as usize + stride - 1) & !(stride - 1);
        let layout = tool_tls_slots::SlotLayout {
            block_base: base,
            stride_log2: 17,
            stride,
            record_offset: 4096,
            tsd_offset: 8192,
            altstack_offset: 16384,
            altstack_bytes: 65536,
            backing_offset: 16384 + 65536 + 4096,
            tp_offset: 4096,
            callback_base: 0,
            callback_stride: 8 * 1024 * 1024 + 8192,
            leader_altstacks: [(0, 0), (0, 0)],
        };
        if record_words {
            for index in 1..=2usize {
                let record = layout.record_addr(index) as *mut u64;
                unsafe {
                    *record.add(2) = 3; // phase: guest
                    *record.add(3) = 0; // guest_fs
                    *record.add(4) = layout.tool_fs_for_slot(index) as u64;
                }
            }
        }
        (raw as usize, layout)
    }

    fn run_on_altstack(altstack: (usize, usize)) {
        let stack = libc::stack_t {
            ss_sp: altstack.0 as *mut libc::c_void,
            ss_flags: 0,
            ss_size: altstack.1 - altstack.0,
        };
        unsafe {
            assert_eq!(
                libc::sigaltstack(&raw const stack, core::ptr::null_mut()),
                0
            );
            let tid = libc::syscall(libc::SYS_gettid);
            assert_eq!(
                libc::syscall(libc::SYS_tgkill, std::process::id(), tid, libc::SIGURG,),
                0
            );
        }
    }

    #[test]
    fn slot_phase_helpers_overlap_on_slot_altstacks() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let (_raw, layout) = synthetic_two_slot_layout(true);
                SLOT_OVERLAP_ARRIVED.store(0, core::sync::atomic::Ordering::SeqCst);
                let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
                action.sa_sigaction = slot_overlap_handler as *const () as usize;
                action.sa_flags = libc::SA_ONSTACK;
                unsafe {
                    assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                    assert_eq!(
                        libc::sigaction(libc::SIGURG, &raw const action, core::ptr::null_mut()),
                        0
                    );
                }
                tool_tls_slots::install_layout_for_test(layout);
                let threads: Vec<_> = (1..=2usize)
                    .map(|index| {
                        let altstack = layout.altstack_for_slot(index);
                        std::thread::spawn(move || run_on_altstack(altstack))
                    })
                    .collect();
                for thread in threads {
                    thread.join().unwrap();
                }
                // Both records were at phase 4 *at the barrier* (not only
                // back at 3 afterwards); the leader word is untouched.
                assert_eq!(
                    SLOT_OVERLAP_PHASES[0].load(core::sync::atomic::Ordering::SeqCst),
                    4
                );
                assert_eq!(
                    SLOT_OVERLAP_PHASES[1].load(core::sync::atomic::Ordering::SeqCst),
                    4
                );
                for index in 1..=2usize {
                    let record = layout.record_addr(index) as *const u64;
                    assert_eq!(unsafe { *record.add(2) }, 3);
                }
                assert_eq!(control.phase, 4);
            },
            0,
        );
        // Negative control, same body (SIGURG on slot-shaped altstacks)
        // with no layout published: both helpers resolve to the single
        // global phase word and the second entrant takes the terminal
        // exactly as today's code does. Spawning is sequential so the
        // first entrant is already at phase 4, parked in the handler,
        // when the second is delivered — no read/write race.
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.phase = 3;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let (_raw, layout) = synthetic_two_slot_layout(true);
                SLOT_OVERLAP_ARRIVED.store(0, core::sync::atomic::Ordering::SeqCst);
                let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
                action.sa_sigaction = slot_overlap_handler as *const () as usize;
                action.sa_flags = libc::SA_ONSTACK;
                unsafe {
                    assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                    assert_eq!(
                        libc::sigaction(libc::SIGURG, &raw const action, core::ptr::null_mut()),
                        0
                    );
                }
                let first = {
                    let altstack = layout.altstack_for_slot(1);
                    std::thread::spawn(move || run_on_altstack(altstack))
                };
                while SLOT_OVERLAP_ARRIVED.load(core::sync::atomic::Ordering::SeqCst) < 1 {
                    std::thread::yield_now();
                }
                let second = {
                    let altstack = layout.altstack_for_slot(2);
                    std::thread::spawn(move || run_on_altstack(altstack))
                };
                let _ = first.join();
                let _ = second.join();
            },
            127,
        );
    }

    fn wide_synthetic_layout() -> (usize, tool_tls_slots::SlotLayout) {
        // 68 strides: one slack stride below the aligned base and room
        // for an idx-64 TP/altstack above the 64 published slots.
        let stride = 128 * 1024usize;
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                68 * stride,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let base = ((raw as usize + stride - 1) & !(stride - 1)) + stride;
        (
            raw as usize,
            tool_tls_slots::SlotLayout {
                block_base: base,
                stride_log2: 17,
                stride,
                record_offset: 4096,
                tsd_offset: 8192,
                altstack_offset: 16384,
                altstack_bytes: 65536,
                backing_offset: 16384 + 65536 + 4096,
                tp_offset: 4096,
                callback_base: 0,
                callback_stride: 8 * 1024 * 1024 + 8192,
                leader_altstacks: [(0, 0), (0, 0)],
            },
        )
    }

    fn install_private_sigsys_entry() {
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction =
            signal_entry(false, crate::trap::pkru_present()) as *const () as usize;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        unsafe {
            assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
            assert_eq!(
                libc::sigaction(libc::SIGSYS, &raw const action, core::ptr::null_mut()),
                0
            );
        }
    }

    fn install_altstack_and_raise_sigsys(stack: Option<(usize, usize)>) {
        if let Some((lo, hi)) = stack {
            let alt = libc::stack_t {
                ss_sp: lo as *mut libc::c_void,
                ss_flags: 0,
                ss_size: hi - lo,
            };
            assert_eq!(
                unsafe { libc::sigaltstack(&raw const alt, core::ptr::null_mut()) },
                0
            );
        }
        unsafe {
            let tid = crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]);
            crate::trap::raw_syscall6(
                libc::SYS_tgkill,
                [
                    std::process::id() as u64,
                    tid as u64,
                    libc::SIGSYS as u64,
                    0,
                    0,
                    0,
                ],
            );
        }
    }

    // kind: 0 slot, 1 tool_fs mismatch, 2 ordinary stack, 3 in-block
    // non-altstack, 4 slot 0, 5 idx >= 64, 6 leader range, 7 no layout,
    // 8 invalid slot phase (control phase is a valid 2).
    fn signal_entry_arm(kind: u8) {
        let mut control = unsafe { scalar_control() };
        control.phase = 2;
        let real_fs = control.tool_fs;
        reverie_inguest_private_exec_control.store((&raw mut control) as usize, Ordering::Release);
        let (_raw, mut layout) = wide_synthetic_layout();
        let leader_stack = vec![0_u8; 65536].leak();
        layout.leader_altstacks[0] = (
            leader_stack.as_ptr() as usize,
            leader_stack.as_ptr() as usize + leader_stack.len(),
        );
        let record = layout.record_addr(1) as *mut u64;
        unsafe {
            *record.add(2) = if kind == 8 { 9 } else { 2 }; // phase
            *record.add(3) = 0;
            *record.add(4) = if kind == 1 {
                real_fs + 0x1_0000
            } else {
                real_fs
            };
            // Decoys at indices 0 and 64 are fully valid records, so the
            // index bound is the ONLY thing that can refuse arms 4/5.
            for decoy in [0usize, 64] {
                let decoy_record = layout.record_addr(decoy) as *mut u64;
                *decoy_record.add(2) = 2;
                *decoy_record.add(3) = 0;
                *decoy_record.add(4) = real_fs;
            }
        }
        if kind != 7 {
            tool_tls_slots::install_layout_for_test(layout);
        }
        install_private_sigsys_entry();
        let stack = match kind {
            0 | 1 | 8 => Some(layout.altstack_for_slot(1)),
            2 | 7 => None,
            3 => Some((layout.record_addr(1), layout.record_addr(1) + 4096)),
            4 => Some((
                layout.block_base + layout.altstack_offset,
                layout.block_base + layout.altstack_offset + layout.altstack_bytes,
            )),
            5 => {
                let lo = layout.block_base + 64 * layout.stride + layout.altstack_offset;
                Some((lo, lo + layout.altstack_bytes))
            }
            _ => Some(layout.leader_altstacks[0]),
        };
        install_altstack_and_raise_sigsys(stack);
        panic!("signal entry returned");
    }

    #[test]
    fn signal_entry_record_derivation_arms() {
        // A non-seccomp SIGSYS reaches the handler and exits 126; a
        // terminal in the entry derivation exits 127. The pair pins
        // which record the assembly selected.
        isolated(|| signal_entry_arm(0), 126); // slot altstack, slot record
        isolated(|| signal_entry_arm(1), 127); // record tool_fs != FS
        isolated(|| signal_entry_arm(2), 127); // ordinary stack (test j)
        isolated(|| signal_entry_arm(3), 127); // in block, not an altstack
        isolated(|| signal_entry_arm(4), 127); // slot 0 stride
        isolated(|| signal_entry_arm(5), 127); // idx >= 64
        isolated(|| signal_entry_arm(6), 126); // leader altstack range
        isolated(|| signal_entry_arm(7), 126); // no layout: today's code
        isolated(|| signal_entry_arm(8), 127); // invalid slot phase
    }

    // kind: 0 tool_fs mismatch, 1 TP below block, 2 slot-0 TP,
    // 3 idx-64 TP, 4 leader-only guest entry, 5 lifecycle entry (0x106),
    // both on a good slot TP (record at phase 6 for kind 5).
    fn leaf_refusal_arm(kind: u8) {
        let mut control = unsafe { scalar_control() };
        reverie_inguest_private_exec_control.store((&raw mut control) as usize, Ordering::Release);
        let real_fs = control.tool_fs;
        let canary = unsafe { *((real_fs + 0x28) as *const u64) };
        let (_raw, layout) = wide_synthetic_layout();
        let tp = match kind {
            1 => layout.block_base - 2048,
            2 => layout.backing(0) + layout.tp_offset,
            3 => layout.backing(64) + layout.tp_offset,
            _ => layout.tool_fs_for_slot(1),
        };
        let record = layout.record_addr(1) as *mut u64;
        unsafe {
            *(tp as *mut u64) = tp as u64;
            *((tp + 8) as *mut u64) = tp as u64;
            *((tp + 0x28) as *mut u64) = canary;
            *record.add(2) = if kind == 5 { 6 } else { 4 }; // phase
            *record.add(3) = 0;
            *record.add(4) = if kind == 0 {
                tp as u64 + 0x1_0000
            } else {
                tp as u64
            };
            // Decoys at indices 0 and 64 pass the phase and [rec+32]
            // checks for their own TPs, so only the index bound refuses.
            for decoy in [0usize, 64] {
                let decoy_record = layout.record_addr(decoy) as *mut u64;
                *decoy_record.add(2) = 4;
                *decoy_record.add(3) = 0;
                *decoy_record.add(4) = layout.tool_fs_for_slot(decoy) as u64;
            }
        }
        tool_tls_slots::install_layout_for_test(layout);
        let args = [0_u64; 6];
        unsafe {
            crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, tp as u64, 0, 0, 0, 0]);
            if kind == 4 {
                reverie_inguest_private_leader_guest_call(libc::SYS_gettid, args.as_ptr(), 0, 0);
            } else if kind == 5 {
                #[cfg(feature = "exec-private-successor")]
                reverie_inguest_private_lifecycle_call(libc::SYS_gettid, args.as_ptr(), 0, 0);
                #[cfg(not(feature = "exec-private-successor"))]
                physical_syscall(libc::SYS_gettid, args, None);
            } else {
                physical_syscall(libc::SYS_gettid, args, None);
            }
        }
        panic!("call leaf returned");
    }

    #[test]
    fn call_leaf_refusal_arms_are_terminal() {
        isolated(|| leaf_refusal_arm(0), 127); // [record+32] != FS base
        isolated(|| leaf_refusal_arm(1), 127); // TP below the block
        isolated(|| leaf_refusal_arm(2), 127); // slot-0 TP
        isolated(|| leaf_refusal_arm(3), 127); // idx >= 64 TP
        isolated(|| leaf_refusal_arm(4), 127); // leader-only entry, slot TP
        #[cfg(feature = "exec-private-successor")]
        isolated(|| leaf_refusal_arm(5), 127); // lifecycle 0x106, slot TP at phase 6
    }

    // The leaf's identity source is the FS base (read with
    // ARCH_GET_FS), never the TCB self word: with slot 1's self word
    // pointing at slot 2's TP (or zero), a call made on slot 1's TP
    // still derives slot 1's record, restores slot 1's TP, and
    // leaves slot 2 and the leader control untouched.
    fn leaf_decoy_self_word_arm(self_word_zero: bool) {
        let mut control = unsafe { scalar_control() };
        reverie_inguest_private_exec_control.store((&raw mut control) as usize, Ordering::Release);
        let real_fs = control.tool_fs;
        let canary = unsafe { *((real_fs + 0x28) as *const u64) };
        let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
        let (_raw, layout) = synthetic_two_slot_layout(false);
        let tp1 = layout.tool_fs_for_slot(1);
        let tp2 = layout.tool_fs_for_slot(2);
        let mut guest_tls1 = [0_u64; 16];
        let mut guest_tls2 = [0_u64; 16];
        let guest_fs1 = guest_tls1.as_mut_ptr() as u64;
        let guest_fs2 = guest_tls2.as_mut_ptr() as u64;
        for (index, tp, guest_fs) in [(1usize, tp1, guest_fs1), (2, tp2, guest_fs2)] {
            let backing = layout.backing(index) as *mut u64;
            let record = layout.record_addr(index) as *mut u64;
            unsafe {
                *backing = 1;
                *backing.add(1) = backing as u64;
                *(tp as *mut u64) = tp as u64;
                *((tp + 8) as *mut u64) = backing as u64;
                *((tp + 0x28) as *mut u64) = canary;
                *record.add(2) = 4; // phase
                *record.add(3) = guest_fs;
                *record.add(4) = tp as u64;
            }
        }
        // The decoy: slot 1's TCB self word names slot 2 (or nothing).
        unsafe {
            *(tp1 as *mut u64) = if self_word_zero { 0 } else { tp2 as u64 };
        }
        tool_tls_slots::install_layout_for_test(layout);
        let mut after_fs = 0_u64;
        // No TLS, errno or allocation access between the switches:
        // only raw gate calls and the leaf itself.
        let codes = unsafe {
            let set =
                crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, tp1 as u64, 0, 0, 0, 0]);
            let got = physical_syscall(libc::SYS_gettid, [0; 6], None).result;
            let get = crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut after_fs) as u64, 0, 0, 0, 0],
            );
            let back =
                crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, real_fs, 0, 0, 0, 0]);
            (set, got, get, back)
        };
        assert_eq!(codes, (0, tid, 0, 0));
        assert_eq!(after_fs, tp1 as u64, "leaf restored the wrong tool FS");
        let r1 = layout.record_addr(1) as *const u64;
        let r2 = layout.record_addr(2) as *const u64;
        unsafe {
            assert_eq!((*r1.add(2), *r1.add(3)), (4, guest_fs1));
            assert_eq!(
                (*r2.add(2), *r2.add(3), *r2.add(4)),
                (4, guest_fs2, tp2 as u64)
            );
            for word in 11..=13 {
                assert_eq!(*r1.add(word), 0);
                assert_eq!(*r2.add(word), 0);
            }
        }
        assert_eq!((control.phase, control.guest_fs), (4, 0));
    }

    #[test]
    fn call_leaf_derives_record_from_fs_base_not_tcb_self_word() {
        isolated(|| leaf_decoy_self_word_arm(false), 0);
        isolated(|| leaf_decoy_self_word_arm(true), 0);
    }

    #[test]
    fn call_leaf_leader_path_positive_with_layout_published() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                let (_raw, layout) = synthetic_two_slot_layout(false);
                for index in 1..=2usize {
                    let record = layout.record_addr(index) as *mut u64;
                    unsafe {
                        *record.add(2) = 4; // phase
                        *record.add(3) = 0x1111 * index as u64; // guest_fs sentinel
                        *record.add(4) = layout.tool_fs_for_slot(index) as u64;
                    }
                }
                tool_tls_slots::install_layout_for_test(layout);
                // FS stays the leader's tool_fs: the call must take the
                // leader record even with a layout published.
                let mut guest_tls = [0_u64; 16];
                let selected = guest_tls.as_mut_ptr() as u64;
                let got = unsafe { physical_syscall(libc::SYS_gettid, [0; 6], None) }.result;
                assert_eq!(got, tid);
                let set = unsafe {
                    physical_syscall(libc::SYS_arch_prctl, [0x1002, selected, 0, 0, 0, 0], None)
                }
                .result;
                assert_eq!(set, 0);
                assert_eq!(control.phase, 4);
                assert_eq!(control.guest_fs, selected);
                for index in 1..=2usize {
                    let record = layout.record_addr(index) as *const u64;
                    unsafe {
                        assert_eq!(
                            (*record.add(2), *record.add(3), *record.add(4)),
                            (
                                4,
                                0x1111 * index as u64,
                                layout.tool_fs_for_slot(index) as u64
                            )
                        );
                    }
                }
            },
            0,
        );
    }

    #[test]
    fn slot_phase_helper_from_unknown_stack_is_terminal_with_layout() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                // A leader fallback would find phase 3 here and succeed;
                // the published layout must refuse this unknown stack.
                control.phase = 3;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let (_raw, layout) = synthetic_two_slot_layout(true);
                tool_tls_slots::install_layout_for_test(layout);
                callback_prepared();
                panic!("unknown stack fell back to the leader record");
            },
            127,
        );
    }

    #[test]
    fn ledger_lookup_refuses_when_record_tool_fs_differs() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let real_fs = control.tool_fs;
                let canary = unsafe { *((real_fs + 0x28) as *const u64) };
                let (_raw, layout) = wide_synthetic_layout();
                let tp = layout.tool_fs_for_slot(1);
                let record = layout.record_addr(1) as *mut u64;
                unsafe {
                    *(tp as *mut u64) = tp as u64;
                    *((tp + 0x28) as *mut u64) = canary;
                    *record.add(4) = tp as u64 + 0x1_0000; // not ARCH_GET_FS
                }
                tool_tls_slots::install_layout_for_test(layout);
                // Switch to the slot TP, then ask the ledger lookup to
                // resolve: geometry finds slot 1, the tool_fs re-check kills.
                unsafe {
                    crate::trap::raw_syscall6(
                        libc::SYS_arch_prctl,
                        [0x1002, tp as u64, 0, 0, 0, 0],
                    );
                    let _ = current_slot_record_for_ledger(control_pointer());
                }
                panic!("ledger lookup accepted a mismatched record tool_fs");
            },
            127,
        );
    }

    #[test]
    fn guest_injection_outside_its_callback_ends_before_the_syscall() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.phase = 3;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let _ =
                    unsafe { physical_syscall(libc::SYS_exit_group, [73, 0, 0, 0, 0, 0], None) };
            },
            127,
        );
    }
    #[test]
    fn physical_guest_registration_keeps_the_current_successful_kernel_values() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 41_i32;
                let clear_address = (&raw mut clear_tid) as u64;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_tid_address,
                            [clear_address, 0, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    tid
                );
                assert_eq!(control.kernel_clear_tid, clear_address);

                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [robust_address, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(control.kernel_robust_head, robust_address);
                assert_eq!(control.kernel_robust_len, robust_len);
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len - 1, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    -i64::from(libc::EINVAL)
                );
                assert_eq!(control.kernel_robust_head, robust_address);
                assert_eq!(control.kernel_robust_len, robust_len);
                let mut actual_head = 0_u64;
                let mut actual_len = 0_u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut actual_head) as u64,
                                (&raw mut actual_len) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                assert_eq!((actual_head, actual_len), (robust_address, robust_len));
                assert_eq!(clear_tid, 41);
                // Remove only this isolated native-leaf fixture's registrations
                // before its local buffers go out of scope. This is not exec.
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(
                    unsafe { physical_syscall(libc::SYS_set_tid_address, [0; 6], None) }.result,
                    tid
                );
                assert_eq!(control.kernel_clear_tid, 0);
                assert_eq!(control.kernel_robust_head, 0);
            },
            0,
        );
    }

    #[test]
    fn native_nested_tool_registration_setters_are_refused_before_forwarding() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 73_i32;
                let mut robust = [0_u64; 3];
                robust[0] = robust.as_mut_ptr() as u64;
                for (number, args) in [
                    (
                        libc::SYS_set_tid_address,
                        [(&raw mut clear_tid) as u64, 0, 0, 0, 0, 0],
                    ),
                    (
                        libc::SYS_set_robust_list,
                        [
                            robust.as_ptr() as u64,
                            size_of_val(&robust) as u64,
                            0,
                            0,
                            0,
                            0,
                        ],
                    ),
                ] {
                    let mut event = crate::guest::event::SyscallEvent {
                        number,
                        args,
                        instruction_pointer: 0,
                        result: i64::MIN,
                        context: 0,
                        dispatch: crate::guest::event::SyscallDispatch::Trap,
                        guest_pkru: None,
                        unsupported_refusal: None,
                    };
                    let mut observed = false;
                    unsafe {
                        crate::guest::trap_dispatch::forward_nested_tool_syscall(
                            &mut event,
                            |_| observed = true,
                        );
                    }
                    assert_eq!(event.result, -i64::from(libc::EPERM));
                    assert!(!observed);
                }
            },
            0,
        );
    }

    #[test]
    fn callback_kernel_registrations_requires_actual_owner_and_current_robust_list() {
        isolated(
            || {
                assert_eq!(callback_kernel_registrations(), None);
                let mut control = unsafe { scalar_control() };
                control.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 73_i32;
                let clear_address = (&raw mut clear_tid) as u64;
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_tid_address,
                            [clear_address, 0, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    control.native_tid as i64
                );
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [robust_address, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(callback_kernel_registrations(), None); // not ready
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                let expected = Some(GuestKernelRegistrations {
                    clear_tid: clear_address,
                    robust_head: robust_address,
                    robust_len,
                });
                assert_eq!(callback_kernel_registrations(), expected);
                assert_eq!(callback_kernel_registrations(), expected);
                assert_eq!(clear_tid, 73);
                assert_eq!(control.kernel_clear_tid, clear_address);
                unsafe { (&raw mut control.kernel_robust_head).write_volatile(0) };
                assert_eq!(callback_kernel_registrations(), None);
                unsafe {
                    (&raw mut control.kernel_robust_head).write_volatile(robust_address);
                    (&raw mut control.phase).write_volatile(3);
                }
                assert_eq!(callback_kernel_registrations(), None);
                unsafe { (&raw mut control.phase).write_volatile(4) };
                assert_eq!(callback_kernel_registrations(), expected);
                // Test-only cleanup before the stack buffers are dropped.
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(
                    unsafe { physical_syscall(libc::SYS_set_tid_address, [0; 6], None) }.result,
                    control.native_tid as i64
                );
            },
            0,
        );
    }

    #[test]
    fn ordinary_nested_registration_setters_keep_their_existing_forwarding() {
        isolated(
            || {
                assert!(!active());
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                let mut clear_tid = 73_i32;
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                for (number, args, expected) in [
                    (
                        libc::SYS_set_tid_address,
                        [(&raw mut clear_tid) as u64, 0, 0, 0, 0, 0],
                        tid,
                    ),
                    (
                        libc::SYS_set_robust_list,
                        [robust_address, robust_len, 0, 0, 0, 0],
                        0,
                    ),
                ] {
                    let mut event = crate::guest::event::SyscallEvent {
                        number,
                        args,
                        instruction_pointer: 0,
                        result: i64::MIN,
                        context: 0,
                        dispatch: crate::guest::event::SyscallDispatch::Trap,
                        guest_pkru: None,
                        unsupported_refusal: None,
                    };
                    let mut observed = false;
                    unsafe {
                        crate::guest::trap_dispatch::forward_nested_tool_syscall(
                            &mut event,
                            |_| observed = true,
                        );
                    }
                    assert_eq!(event.result, expected);
                    assert!(observed);
                }
                let mut actual_head = 0_u64;
                let mut actual_len = 0_u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut actual_head) as u64,
                                (&raw mut actual_len) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                assert_eq!((actual_head, actual_len), (robust_address, robust_len));
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe { crate::trap::raw_syscall6(libc::SYS_set_tid_address, [0; 6]) },
                    tid
                );
            },
            0,
        );
    }
    #[test]
    fn finish_refuses_software_flags_without_a_completed_native_frontend() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.phase = 2;
                crate::trap::set_dispatcher(
                    Box::new(crate::dispatch::PassthroughDispatcher::new()),
                );
                crate::trap::set_signal_return_restricted();
                // Deliberately only the old software prerequisites. This is
                // not an authenticated native owner or installed frontend.
                let owner = InitialImageControl::new((&raw mut control) as usize);
                assert!(owner.finish().is_err());
                assert_eq!(control.runtime_ready, 0);
            },
            0,
        );
    }
    #[test]
    fn isolated_assertion_failure_is_a_nonzero_child_exit() {
        isolated(|| panic!("deliberate child assertion failure"), 125);
    }

    #[test]
    fn initial_abort_owner_drop_never_returns_or_writes_to_full_stderr() {
        isolated(
            || {
                // Component fixture owns a real fixed terminal gate. It does
                // not claim coordinator authorization or a completed image.
                unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                let mut pipe = [-1; 2];
                assert_eq!(
                    unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK) },
                    0
                );
                let bytes = [0_u8; 4096];
                loop {
                    let result =
                        unsafe { libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len()) };
                    if result < 0 {
                        assert_eq!(
                            io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        break;
                    }
                }
                assert_eq!(unsafe { libc::fcntl(pipe[1], libc::F_SETFL, 0) }, 0);
                assert_eq!(unsafe { libc::dup2(pipe[1], 2) }, 2);
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                drop(fatal);
                unsafe { libc::_exit(91) };
            },
            127,
        );
    }

    #[test]
    fn initial_abort_owner_refuses_invalid_publication_and_failed_finish() {
        isolated(
            || {
                unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                assert!(unsafe { publish_authenticated_control(core::ptr::null_mut()) }.is_err());
                drop(fatal);
                unsafe { libc::_exit(92) };
            },
            127,
        );
        isolated(
            || {
                let mut native = unsafe { scalar_control() };
                native.phase = 2;
                let owner = InitialImageControl::new((&raw mut native) as usize);
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                // No real frontend/lifecycle was installed. The existing
                // readiness checks must fail and fatal ownership must survive.
                let _ = fatal.finish(&owner);
                unsafe { libc::_exit(93) };
            },
            127,
        );
    }

    #[test]
    fn control_slot_publication_registers_leader_slot() {
        isolated(
            || {
                // publish_control_slot is the one physical publication both
                // authenticated origins funnel through (the GNU path via
                // publish_native_control, the mapped musl image directly),
                // so slot-0 registration must happen there, not in a caller
                // the mapped path bypasses.
                let mut control: NativeControl = unsafe { core::mem::zeroed() };
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
                assert!(tid > 0);
                control.native_tid = tid as u64;
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.leader(), None);
                publish_control_slot(&raw mut control).unwrap();
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.leader(), Some(tid));
                assert_eq!(
                    tool_tls_registry::TOOL_TLS_REGISTRY.lookup_ready(tid),
                    Some(0)
                );
                // A second publication still refuses and changes nothing.
                assert!(publish_control_slot(&raw mut control).is_err());
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.leader(), Some(tid));
            },
            0,
        );
        isolated(
            || {
                // A sealed tid that is not a positive kernel tid refuses
                // the publication itself: no control, no leader slot.
                let mut control: NativeControl = unsafe { core::mem::zeroed() };
                assert!(publish_control_slot(&raw mut control).is_err());
                assert!(!active());
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.leader(), None);
            },
            0,
        );
    }

    fn maps_perms(address: usize) -> String {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let Some(range) = fields.next() else { continue };
            let Some(perms) = fields.next() else { continue };
            let Some((lo, hi)) = range.split_once('-') else {
                continue;
            };
            let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            else {
                continue;
            };
            if address >= lo && address < hi {
                return perms.to_owned();
            }
        }
        panic!("address {address:#x} is unmapped");
    }

    fn capture_test_geometry() {
        capture_test_geometry_with(0x6000_0000);
    }

    fn capture_test_geometry_with(leader_backing_start: usize) {
        tool_tls_slots::capture_geometry_inputs(4096, 16, 96, leader_backing_start, 64 * 1024);
    }

    #[test]
    fn slot_claim_admission_off_on_and_forced_failure() {
        // Admission off: finish-time claim must not claim anything.
        isolated(
            || {
                let region = crate::guest::tool_region::ToolRegion::reserve().unwrap();
                let mut control: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
                capture_test_geometry();
                tool_tls_slots::note_thread_admission_requested(false);
                let before = region.free_spans().unwrap();
                tool_tls_slots::claim_and_publish_if_requested(region, &raw mut *control);
                assert_eq!(region.free_spans().unwrap(), before);
                assert_eq!(tool_tls_slots::layout(), None);
                assert_eq!(tool_tls_slots::claim_status_for_test(), "not-attempted");
            },
            0,
        );
        // Admission on: layout published, records stamped, guards sealed.
        isolated(
            || {
                let region = crate::guest::tool_region::ToolRegion::reserve().unwrap();
                let mut control: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
                capture_test_geometry();
                tool_tls_slots::note_thread_admission_requested(true);
                tool_tls_slots::claim_and_publish_if_requested(region, &raw mut *control);
                let layout = tool_tls_slots::layout().expect("layout published");
                assert_eq!(tool_tls_slots::claim_status_for_test(), "ready");
                assert_eq!(
                    tool_tls_slots::published_slot_base_for_test(),
                    layout.block_base
                );
                assert_eq!(layout.block_base % layout.stride, 0);
                for index in [1usize, 63] {
                    let record = layout.record_addr(index) as *const u64;
                    assert_eq!(
                        unsafe { record.read_volatile() },
                        tool_tls_slots::SLOT_RECORD_MAGIC
                    );
                    assert_eq!(unsafe { record.add(1).read_volatile() }, index as u64);
                    let (alt_lo, alt_hi) = layout.altstack_for_slot(index);
                    for guard in [
                        layout.slot_base(index),
                        layout.slot_base(index) + 3 * 4096,
                        alt_hi,
                    ] {
                        assert_eq!(maps_perms(guard), "---p", "guard {guard:#x}");
                    }
                    assert_eq!(maps_perms(layout.record_addr(index)), "rw-p");
                    assert_eq!(maps_perms(alt_lo), "rw-p");
                }
                let pool_end = layout.callback_base + 63 * layout.callback_stride;
                for address in [
                    layout.callback_base,
                    layout.callback_base + (pool_end - layout.callback_base) / 2,
                    pool_end - 1,
                ] {
                    assert_eq!(maps_perms(address), "---p", "pool {address:#x}");
                }
                // Callback stack views: bounds and exact slot extents.
                let usable = crate::guest::continuation::CALLBACK_STACK_BYTES;
                assert!(layout.callback_stack_for_slot(region, 0, usable).is_none());
                assert!(layout.callback_stack_for_slot(region, 64, usable).is_none());
                assert!(
                    layout
                        .callback_stack_for_slot(region, 1, usable + 4096)
                        .is_none()
                );
                for index in [1usize, 63] {
                    let view = layout
                        .callback_stack_for_slot(region, index, usable)
                        .expect("slot callback stack");
                    let extent = layout.callback_base + (index - 1) * layout.callback_stride;
                    assert_eq!(view.extent(), (extent, extent + layout.callback_stride));
                    assert_eq!(view.base(), extent + 4096);
                    assert_eq!(view.top(), extent + 4096 + usable);
                }
            },
            0,
        );
        // Forced failure: fragment the largest free span below the pool's
        // contiguous need; the claim must degrade by name, not panic.
        isolated(
            || {
                let region = crate::guest::tool_region::ToolRegion::reserve().unwrap();
                let mut control: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
                let spans = region.free_spans().unwrap();
                let &(start, len) = spans.iter().max_by_key(|&(_, len)| len).unwrap();
                let mut page = start + 100_000;
                while page < start + len {
                    region.claim_at(page, 1).unwrap();
                    page += 100_000;
                }
                capture_test_geometry();
                tool_tls_slots::note_thread_admission_requested(true);
                let before = region.free_spans().unwrap();
                tool_tls_slots::claim_and_publish_if_requested(region, &raw mut *control);
                assert_eq!(region.free_spans().unwrap(), before);
                assert_eq!(tool_tls_slots::layout(), None);
                assert_eq!(tool_tls_slots::claim_status_for_test(), "claim-failed");
                let failure = tool_tls_slots::claim_failure_reason().expect("named claim failure");
                assert_eq!(failure.errno, libc::ENOMEM);
                assert_eq!(
                    failure.reason,
                    tool_tls_slots::LayoutError::NoAlignedSpan.name()
                );
            },
            0,
        );
        // Leader backing not a multiple of tls_align: named EINVAL refusal.
        isolated(
            || {
                let region = crate::guest::tool_region::ToolRegion::reserve().unwrap();
                let mut control: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
                capture_test_geometry_with(8);
                tool_tls_slots::note_thread_admission_requested(true);
                tool_tls_slots::claim_and_publish_if_requested(region, &raw mut *control);
                assert_eq!(tool_tls_slots::layout(), None);
                let failure =
                    tool_tls_slots::claim_failure_reason().expect("named leader-backing refusal");
                assert_eq!(failure.errno, libc::EINVAL);
                assert_eq!(
                    failure.reason,
                    "leader backing is not a multiple of tls_align"
                );
            },
            0,
        );
    }

    #[test]
    fn initial_vdso_context_requires_same_fresh_native_owner() {
        isolated(
            || {
                for mutation in 0..9 {
                    let (mut native, mut owner) = lifecycle_test_owner();
                    owner.check_initial_vdso_context().unwrap();
                    owner.check_initial_vdso_context().unwrap();
                    assert_eq!(native.runtime_ready, 0);
                    match mutation {
                        0 => native.phase = 3,
                        1 => native.runtime_ready = 1,
                        2 => native.native_tid += 1,
                        3 => native.tool_fs ^= 1,
                        4 => reverie_inguest_private_exec_control.store(0, Ordering::Release),
                        5 => owner.installation.store(1, Ordering::Release),
                        6 => owner.installed_host.store(1, Ordering::Release),
                        7 => owner.lifecycle.store(1, Ordering::Release),
                        8 => owner.control = 0,
                        _ => unreachable!(),
                    }
                    assert!(
                        owner.check_initial_vdso_context().is_err(),
                        "context mutation {mutation}"
                    );
                }
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_is_affine_and_abandonment_prevents_finish() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let permit = owner.begin_lifecycle(1).unwrap();
                drop(permit);
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert!(owner.begin_lifecycle(1).is_err());
                let error = owner.finish().unwrap_err();
                assert!(error.to_string().contains("lifecycle did not complete"));
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_requires_completed_frontend_and_same_host() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                assert!(owner.begin_lifecycle(1).is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let error = owner.begin_lifecycle(2).err().unwrap();
                assert!(error.to_string().contains("installed host/frontend"));
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_revalidates_tid_fs_phase_and_never_reopens() {
        for mutation in 0..4 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let status = if std::panic::catch_unwind(|| {
                    let (mut native, owner) = lifecycle_test_owner();
                    owner.bind_lifecycle_host(1).unwrap();
                    mark_lifecycle_test_frontend_installed(&owner);
                    let permit = owner.begin_lifecycle(1).unwrap();
                    match mutation {
                        0 => native.native_tid += 1,
                        1 => native.tool_fs ^= 8,
                        2 => native.phase = 4,
                        3 => native.runtime_ready = 1,
                        _ => unreachable!(),
                    }
                    let error = permit.complete().unwrap_err();
                    assert!(error.to_string().contains("FS/process/phase differs"));
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                    assert!(owner.begin_lifecycle(1).is_err());
                })
                .is_ok()
                {
                    0
                } else {
                    125
                };
                unsafe { libc::_exit(status) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    #[test]
    fn duplicate_initial_lifecycle_attempt_poison_is_not_a_completion_flag() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let permit = owner.begin_lifecycle(1).unwrap();
                assert!(owner.begin_lifecycle(1).is_err());
                assert!(permit.complete().is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[cfg(feature = "coordinator-rpc")]
    #[test]
    fn mapped_injection_permit_revalidates_every_issuance_field() {
        for mutation in 0..6 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let status = if std::panic::catch_unwind(|| {
                    let (_native, owner, entry) = mapped_permit_test_owner();
                    let mut permit = owner.begin_mapped_successor_lifecycle(1).unwrap();
                    permit.validate_mapped_injection().unwrap();
                    assert_eq!(permit.regs(&entry).rsp, 0x1234_0000);
                    match mutation {
                        0 => permit.selected = false,
                        1 => permit.completed = true,
                        2 => owner.lifecycle.store(2, Ordering::Release),
                        3 => owner.installation.store(1, Ordering::Release),
                        4 => owner.installed_host.store(2, Ordering::Release),
                        5 => owner.selected_restore.store(1, Ordering::Release),
                        _ => unreachable!(),
                    }
                    let error = permit.validate_mapped_injection().unwrap_err();
                    assert_eq!(
                        error.to_string(),
                        "mapped successor injection permit differs",
                        "permit mutation {mutation}"
                    );
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                })
                .is_ok()
                {
                    0
                } else {
                    125
                };
                unsafe { libc::_exit(status) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0, "permit mutation {mutation}");
        }
    }

    #[cfg(feature = "coordinator-rpc")]
    #[test]
    fn mapped_regs_reverify_entry_after_control_mutation() {
        for mutation in 0..4 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let status = if std::panic::catch_unwind(|| {
                    let (mut native, owner, entry) = mapped_permit_test_owner();
                    let permit = owner.begin_mapped_successor_lifecycle(1).unwrap();
                    assert_eq!(permit.regs(&entry).rsp, 0x1234_0000);
                    match mutation {
                        0 => native.guest_rsp += 8,
                        1 => native.guest_ld_entry += 8,
                        2 => native.guest_fs += 8,
                        3 => native.guest_pkru = 2,
                        _ => unreachable!(),
                    }
                    let _ = permit.regs(&entry);
                    panic!("mapped regs returned after entry mutation {mutation}");
                })
                .is_ok()
                {
                    0
                } else {
                    125
                };
                unsafe { libc::_exit(status) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(
                libc::WEXITSTATUS(status),
                127,
                "entry mutation {mutation} must terminate at regs"
            );
        }
    }

    #[test]
    fn callback_native_tid_requires_actual_ready_callback_identity() {
        isolated(
            || {
                assert_eq!(callback_native_tid(), None);
                let mut native = unsafe { scalar_control() };
                native.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                reverie_inguest_private_exec_control
                    .store((&raw mut native) as usize, Ordering::Release);
                assert_eq!(callback_native_tid(), None); // ready is still zero
                unsafe { (&raw mut native.runtime_ready).write_volatile(1) };
                assert_eq!(callback_native_tid(), Some(native.native_tid as i32));
                unsafe { (&raw mut native.phase).write_volatile(2) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.phase).write_volatile(4) };
                unsafe { (&raw mut native.native_tid).write_volatile(native.native_tid + 1) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.native_tid).write_volatile(native.native_tid - 1) };
                unsafe { (&raw mut native.tool_fs).write_volatile(native.tool_fs ^ 8) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.tool_fs).write_volatile(native.tool_fs ^ 8) };
                unsafe { (&raw mut native.abi_version).write_volatile(2) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.abi_version).write_volatile(1) };
                unsafe { (&raw mut native.byte_len).write_volatile(native.byte_len - 8) };
                assert_eq!(callback_native_tid(), None);
            },
            0,
        );
    }

    #[test]
    fn callback_tool_tid_leader_requires_registered_ready_slot_zero() {
        isolated(
            || {
                assert_eq!(callback_tool_tid(), None);
                let mut native = unsafe { scalar_control() };
                native.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                reverie_inguest_private_exec_control
                    .store((&raw mut native) as usize, Ordering::Release);
                unsafe { (&raw mut native.runtime_ready).write_volatile(1) };
                // The leader identity is ready, but slot 0 is not in
                // the registry: an unpublished-registry control is
                // refused by the split predicate (named, not passed).
                assert_eq!(callback_native_tid(), Some(native.native_tid as i32));
                assert_eq!(callback_tool_tid(), None);
                tool_tls_registry::register_leader(native.native_tid as i32).unwrap();
                assert_eq!(callback_tool_tid(), Some(native.native_tid as i32));
                unsafe { (&raw mut native.phase).write_volatile(3) };
                assert_eq!(callback_tool_tid(), None);
            },
            0,
        );
    }

    #[test]
    fn callback_tool_tid_slot_requires_bound_ready_and_phase_four() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let real_fs = control.tool_fs;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as i32;
                control.native_tid = (tid + 1000) as u64;
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                // Synthetic slot-1 block (the B2 ledger pattern): the
                // slot TCB copies this thread's canary so Rust frames
                // between the FS switches still validate.
                let stride = 128 * 1024usize;
                let total = 3 * stride;
                let raw = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        total,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(raw, libc::MAP_FAILED);
                let base = (raw as usize + stride - 1) & !(stride - 1);
                let layout = tool_tls_slots::SlotLayout {
                    block_base: base,
                    stride_log2: 17,
                    stride,
                    record_offset: 4096,
                    tsd_offset: 8192,
                    altstack_offset: 16384,
                    altstack_bytes: 65536,
                    backing_offset: 16384 + 65536 + 4096,
                    tp_offset: 4096,
                    callback_base: 0,
                    callback_stride: 8 * 1024 * 1024 + 8192,
                    leader_altstacks: [(0, 0), (0, 0)],
                };
                let tp = layout.tool_fs_for_slot(1);
                let backing = layout.backing(1) as *mut u64;
                let record = layout.record_addr(1) as *mut u64;
                unsafe {
                    *backing = 1;
                    *backing.add(1) = backing as u64;
                    *(tp as *mut u64) = tp as u64;
                    *((tp + 8) as *mut u64) = backing as u64;
                    *((tp + 0x28) as *mut u64) = *((real_fs + 0x28) as *const u64);
                    *record.add(2) = 4; // phase
                    *record.add(4) = tp as u64; // tool thread pointer
                }
                tool_tls_slots::install_layout_for_test(layout);
                // Claimed but not yet bound: lookup_ready has no slot
                // for this tid, so the Building arm must refuse.
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.claim(), Some(1));
                // No TLS, errno or allocation access between the
                // switches: only raw gate calls and the predicate.
                let on_slot = |phase: u64| {
                    unsafe { *record.add(2) = phase };
                    let (set, result, back) = unsafe {
                        let set = crate::trap::raw_syscall6(
                            libc::SYS_arch_prctl,
                            [0x1002, tp as u64, 0, 0, 0, 0],
                        );
                        let result = callback_tool_tid();
                        let back = crate::trap::raw_syscall6(
                            libc::SYS_arch_prctl,
                            [0x1002, real_fs, 0, 0, 0, 0],
                        );
                        (set, result, back)
                    };
                    assert_eq!((set, back), (0, 0));
                    result
                };
                assert_eq!(on_slot(4), None); // Building: not Ready
                assert!(tool_tls_registry::TOOL_TLS_REGISTRY.bind_ready(1, tid));
                assert_eq!(on_slot(4), Some(tid));
                assert_eq!(on_slot(3), None); // record not in callback phase
                // The record's own thread-pointer word must agree with
                // the geometry thread pointer, not just resolve to it.
                unsafe { *record.add(4) ^= 8 };
                assert_eq!(on_slot(4), None);
                unsafe { *record.add(4) ^= 8 };
            },
            0,
        );
    }

    /// Install a synthetic two-slot layout whose slot TCBs copy this
    /// thread's canary (the B2 ledger pattern) and return both slots'
    /// thread pointers. Records start at phase 4.
    fn install_two_slot_test_layout(real_fs: u64) -> [usize; 2] {
        let stride = 128 * 1024usize;
        let total = 5 * stride;
        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(raw, libc::MAP_FAILED);
        let base = (raw as usize + stride - 1) & !(stride - 1);
        let layout = tool_tls_slots::SlotLayout {
            block_base: base,
            stride_log2: 17,
            stride,
            record_offset: 4096,
            tsd_offset: 8192,
            altstack_offset: 16384,
            altstack_bytes: 65536,
            backing_offset: 16384 + 65536 + 4096,
            tp_offset: 4096,
            callback_base: 0,
            callback_stride: 8 * 1024 * 1024 + 8192,
            leader_altstacks: [(0, 0), (0, 0)],
        };
        let mut tps = [0usize; 2];
        for (slot, index) in [(0usize, 1usize), (1, 2)] {
            let tp = layout.tool_fs_for_slot(index);
            let backing = layout.backing(index) as *mut u64;
            let record = layout.record_addr(index) as *mut u64;
            unsafe {
                *backing = 1;
                *backing.add(1) = backing as u64;
                *(tp as *mut u64) = tp as u64;
                *((tp + 8) as *mut u64) = backing as u64;
                *((tp + 0x28) as *mut u64) = *((real_fs + 0x28) as *const u64);
                *record.add(2) = 4; // phase
                *record.add(4) = tp as u64; // tool thread pointer
            }
            tps[slot] = tp;
        }
        tool_tls_slots::install_layout_for_test(layout);
        tps
    }

    /// Run `callback_tool_tid` on the given synthetic thread pointer:
    /// no TLS, errno or allocation access between the FS switches.
    fn tool_tid_on_tp(tp: usize, real_fs: u64) -> Option<i32> {
        let (set, result, back) = unsafe {
            let set =
                crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, tp as u64, 0, 0, 0, 0]);
            let result = callback_tool_tid();
            let back =
                crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, real_fs, 0, 0, 0, 0]);
            (set, result, back)
        };
        assert_eq!((set, back), (0, 0));
        result
    }

    #[test]
    fn callback_tool_tid_refuses_ready_tid_on_other_slot_thread_pointer() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let real_fs = control.tool_fs;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as i32;
                control.native_tid = (tid + 1000) as u64;
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                let tps = install_two_slot_test_layout(real_fs);
                // This tid is Ready in slot 1 only; slot 2 stays
                // Building with its record at phase 4.
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.claim(), Some(1));
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.claim(), Some(2));
                assert!(tool_tls_registry::TOOL_TLS_REGISTRY.bind_ready(1, tid));
                assert_eq!(
                    tool_tls_registry::TOOL_TLS_REGISTRY.lookup_ready(tid),
                    Some(1)
                );
                // Ready in a different slot never admits this TP.
                assert_eq!(tool_tid_on_tp(tps[1], real_fs), None);
                assert_eq!(tool_tid_on_tp(tps[0], real_fs), Some(tid));
            },
            0,
        );
    }

    #[test]
    fn callback_tool_tid_refuses_slot_one_tp_when_tid_ready_in_slot_two() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let real_fs = control.tool_fs;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as i32;
                control.native_tid = (tid + 1000) as u64;
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                let tps = install_two_slot_test_layout(real_fs);
                // Mirror image of the cross-slot negative above: this
                // tid is Ready in slot 2 only, so slot 1's thread
                // pointer must not admit it either.
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.claim(), Some(1));
                assert_eq!(tool_tls_registry::TOOL_TLS_REGISTRY.claim(), Some(2));
                assert!(tool_tls_registry::TOOL_TLS_REGISTRY.bind_ready(2, tid));
                assert_eq!(
                    tool_tls_registry::TOOL_TLS_REGISTRY.lookup_ready(tid),
                    Some(2)
                );
                assert_eq!(tool_tid_on_tp(tps[0], real_fs), None);
                assert_eq!(tool_tid_on_tp(tps[1], real_fs), Some(tid));
            },
            0,
        );
    }

    #[test]
    fn callback_slot_registrations_agree_with_slot_ledger() {
        isolated(
            || {
                let page = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(page, libc::MAP_FAILED);
                let record = page as *mut tool_tls_slots::SlotRecord;
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_set_robust_list,
                            [robust_address, robust_len, 0, 0, 0, 0],
                        )
                    },
                    0
                );
                unsafe {
                    (*record).guest_clear_tid = 0x7000;
                    (*record).guest_robust_head = robust_address;
                    (*record).guest_robust_len = robust_len;
                }
                assert_eq!(
                    callback_slot_registrations(record),
                    Some(GuestKernelRegistrations {
                        clear_tid: 0x7000,
                        robust_head: robust_address,
                        robust_len,
                    })
                );
                unsafe { (*record).guest_robust_len = robust_len + 8 };
                assert_eq!(callback_slot_registrations(record), None);
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                        )
                    },
                    0
                );
            },
            0,
        );
    }

    #[test]
    fn non_leader_mapping_class_refusal_pins_errno_and_break_shape() {
        // Classifier-level pin only: every errno-shaped member of the
        // set resolves through the shared outcome seam to the raw
        // -EPERM result (in the kernel error range an mmap caller
        // reads as MAP_FAILED), and brk resolves to the queried
        // unchanged break. A real caller consuming those outcomes is
        // exercised by the seccomp witness below, not here.
        for number in [
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_pkey_mprotect,
            libc::SYS_remap_file_pages,
            libc::SYS_mseal,
            libc::SYS_process_madvise,
            libc::SYS_shmat,
            libc::SYS_shmdt,
        ] {
            let Some(NonLeaderMappingRefusal::Errno(result)) = non_leader_mapping_refusal(number)
            else {
                panic!("syscall {number} must refuse with an errno");
            };
            assert_eq!(result, -i64::from(libc::EPERM), "syscall {number}");
            assert_eq!(result, NON_LEADER_MAPPING_CLASS_ERRNO);
            assert!((-4095..=-1).contains(&result), "syscall {number}");
            assert_eq!(
                non_leader_mapping_outcome(number, || 0x5000),
                Some(NonLeaderMappingOutcome::Result(result)),
                "syscall {number}"
            );
        }
        // brk has no errno return: a denied change answers with the
        // unchanged current break instead.
        assert_eq!(
            non_leader_mapping_refusal(libc::SYS_brk),
            Some(NonLeaderMappingRefusal::UnchangedBreak)
        );
        assert_eq!(
            non_leader_mapping_outcome(libc::SYS_brk, || 0x5000),
            Some(NonLeaderMappingOutcome::Result(0x5000))
        );
        assert_eq!(
            non_leader_mapping_outcome(libc::SYS_brk, || 0),
            Some(NonLeaderMappingOutcome::BreakQueryFailed)
        );
        for number in [
            libc::SYS_read,
            libc::SYS_gettid,
            libc::SYS_futex,
            libc::SYS_clone,
        ] {
            assert_eq!(non_leader_mapping_refusal(number), None, "syscall {number}");
            assert_eq!(non_leader_mapping_outcome(number, || 0x5000), None);
        }
        assert!(NON_LEADER_MAPPING_CLASS_REASON.contains("dh-gpxse"));
        // Derived cross-check: probe the owner-mapping guard itself
        // (restorer.rs) for every syscall number it classifies as a
        // mapping change, and require the refusal set to cover each
        // one. A copied list could not see the guard grow.
        let derived: Vec<i64> = (0..1024)
            .filter(|&number| crate::guest::restorer::owner_mapping_guard_classifies(number))
            .collect();
        assert!(
            derived.contains(&libc::SYS_mmap) && derived.contains(&libc::SYS_shmat),
            "derived guard set {derived:?} must reach the argument-dependent arms"
        );
        // Lower bound: the probe must still reach every syscall the
        // guard classifies today, so an arm narrowing (or a probe
        // change) cannot silently shrink the derived set. Growth is
        // still detected through the derivation itself below.
        for expected in [
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_pkey_mprotect,
            libc::SYS_remap_file_pages,
            libc::SYS_mseal,
            libc::SYS_process_madvise,
            libc::SYS_shmat,
        ] {
            assert!(
                derived.contains(&expected),
                "probe lost guard syscall {expected}"
            );
        }
        for number in derived {
            assert!(
                non_leader_mapping_refusal(number).is_some(),
                "derived guard syscall {number} not refused"
            );
        }
    }

    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_TRAP_CURRENT_BREAK: core::sync::atomic::AtomicI64 =
        core::sync::atomic::AtomicI64::new(0);
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_TRAPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_TRAP_BRK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_TRAP_ERRNO: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0);
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_WORKER_DONE: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    static MAPPING_WORKER_NULL: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    extern "C" fn mapping_trap_handler(
        _signal: i32,
        _info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        let context = unsafe { &mut *(context as *mut libc::ucontext_t) };
        let number = context.uc_mcontext.gregs[libc::REG_RAX as usize];
        MAPPING_TRAPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match non_leader_mapping_refusal(number) {
            Some(NonLeaderMappingRefusal::UnchangedBreak) => {
                MAPPING_TRAP_BRK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Some(NonLeaderMappingRefusal::Errno(_)) => {
                MAPPING_TRAP_ERRNO.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            None => {}
        }
        let result = match non_leader_mapping_outcome(number, || {
            MAPPING_TRAP_CURRENT_BREAK.load(core::sync::atomic::Ordering::Relaxed)
        }) {
            Some(NonLeaderMappingOutcome::Result(result)) => result,
            _ => -i64::from(libc::ENOSYS),
        };
        context.uc_mcontext.gregs[libc::REG_RAX as usize] = result;
        // SECCOMP_RET_TRAP does not execute the syscall, and the
        // signal frame already resumes after the syscall instruction:
        // only the result register is replaced.
    }

    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    #[test]
    fn non_leader_mapping_outcome_lets_worker_malloc_fail_not_crash() {
        isolated(
            || {
                unsafe extern "C" {
                    fn mallopt(param: i32, value: i32) -> i32;
                    fn malloc_trim(pad: usize) -> i32;
                }
                // One arena (M_ARENA_MAX): the worker shares the main
                // arena, so a large allocation that cannot mmap
                // reaches glibc's sbrk fallback and both refusal
                // shapes meet a real consumer. Trim first so no
                // retained top chunk can serve the request silently.
                assert_eq!(unsafe { mallopt(-8, 1) }, 1);
                unsafe { malloc_trim(0) };
                let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
                action.sa_sigaction = mapping_trap_handler as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO;
                unsafe {
                    assert_eq!(libc::sigemptyset(&raw mut action.sa_mask), 0);
                    assert_eq!(
                        libc::sigaction(libc::SIGSYS, &raw const action, core::ptr::null_mut()),
                        0
                    );
                }
                let worker = std::thread::spawn(|| {
                    // The break query cannot run inside the handler
                    // (brk itself is trapped), so record the unchanged
                    // break before installing the filter.
                    let current = unsafe { libc::syscall(libc::SYS_brk, 0_i64) };
                    assert!(current > 0);
                    MAPPING_TRAP_CURRENT_BREAK
                        .store(current, core::sync::atomic::Ordering::Relaxed);
                    // Thread-scoped filter (no TSYNC) trapping exactly
                    // the production classifier's set.
                    const BPF_LD_W_ABS: u16 = 0x20;
                    const BPF_JMP_JEQ_K: u16 = 0x15;
                    const BPF_RET_K: u16 = 0x06;
                    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
                    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
                    let filter =
                        |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
                    let mut prog = vec![filter(BPF_LD_W_ABS, 0, 0, 0)];
                    for number in [
                        libc::SYS_brk,
                        libc::SYS_mmap,
                        libc::SYS_mprotect,
                        libc::SYS_munmap,
                        libc::SYS_mremap,
                        libc::SYS_madvise,
                        libc::SYS_pkey_mprotect,
                        libc::SYS_remap_file_pages,
                        libc::SYS_mseal,
                        libc::SYS_process_madvise,
                        libc::SYS_shmat,
                        libc::SYS_shmdt,
                    ] {
                        if non_leader_mapping_refusal(number).is_some() {
                            prog.push(filter(BPF_JMP_JEQ_K, 0, 1, number as u32));
                            prog.push(filter(BPF_RET_K, 0, 0, SECCOMP_RET_TRAP));
                        }
                    }
                    prog.push(filter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));
                    assert_eq!(
                        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                        0
                    );
                    let mut fprog = libc::sock_fprog {
                        len: prog.len() as u16,
                        filter: prog.as_mut_ptr(),
                    };
                    assert_eq!(
                        unsafe { libc::syscall(libc::SYS_seccomp, 1_i64, 0_i64, &raw mut fprog) },
                        0
                    );
                    // Above glibc's 128 KiB mmap threshold: mmap is
                    // refused -EPERM, the sbrk fallback gets the
                    // unchanged break, and malloc must fail cleanly.
                    let ptr = unsafe { libc::malloc(1024 * 1024) };
                    MAPPING_WORKER_NULL.store(ptr.is_null(), core::sync::atomic::Ordering::Release);
                    MAPPING_WORKER_DONE.store(true, core::sync::atomic::Ordering::Release);
                    // Raw thread exit: pthread teardown would issue its
                    // own stack munmap back through this same filter,
                    // which is harness machinery, not the allocation
                    // under test. The result is already recorded above.
                    unsafe { libc::syscall(libc::SYS_exit, 0_i64) };
                    loop {
                        core::hint::spin_loop();
                    }
                });
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while !MAPPING_WORKER_DONE.load(core::sync::atomic::Ordering::Acquire) {
                    if worker.is_finished() || std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::yield_now();
                }
                drop(worker);
                assert!(
                    MAPPING_WORKER_DONE.load(core::sync::atomic::Ordering::Acquire),
                    "worker finished without recording a result"
                );
                assert!(
                    MAPPING_WORKER_NULL.load(core::sync::atomic::Ordering::Acquire),
                    "refused worker malloc must return NULL"
                );
                assert!(
                    MAPPING_TRAPS.load(core::sync::atomic::Ordering::Relaxed) >= 1,
                    "the allocation never reached the refusal outcome"
                );
                // Both refusal shapes must meet the consumer: at
                // least one errno-class trap (mmap and friends) and
                // at least one brk trap answered with the unchanged
                // break, not just whichever the allocator tries first.
                assert!(
                    MAPPING_TRAP_ERRNO.load(core::sync::atomic::Ordering::Relaxed) >= 1,
                    "no errno-class refusal reached the worker"
                );
                assert!(
                    MAPPING_TRAP_BRK.load(core::sync::atomic::Ordering::Relaxed) >= 1,
                    "no brk refusal reached the worker"
                );
            },
            0,
        );
    }
}

#[cfg(all(test, feature = "exec-private-successor"))]
mod tsc_tests {
    use super::*;
    use crate::guest::instruction::InstructionSubscriptions;

    enum Owner {
        Initial(InitialImageControl),
        Successor(SuccessorImageControl),
    }
    impl Owner {
        fn prepare(&self, rdtsc: bool) -> io::Result<()> {
            let instructions = InstructionSubscriptions {
                cpuid: false,
                rdtsc,
            };
            match self {
                Self::Initial(owner) => owner.prepare_signal_state(instructions),
                Self::Successor(owner) => owner.prepare_signal_state(instructions),
            }
        }
        fn start_installation(&self) {
            match self {
                Self::Initial(owner) => owner.installation.store(1, Ordering::Release),
                Self::Successor(owner) => owner.installation.store(1, Ordering::Release),
            }
        }
        fn start_lifecycle(&self) {
            match self {
                Self::Initial(owner) => owner.lifecycle.store(1, Ordering::Release),
                Self::Successor(owner) => owner.lifecycle.store(1, Ordering::Release),
            }
        }
    }
    fn isolated(body: impl FnOnce() + std::panic::UnwindSafe) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
                0
            } else {
                125
            };
            unsafe { libc::_exit(status) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    extern "C" fn unexpected_signal(
        _signal: i32,
        _info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        unsafe { libc::_exit(73) }
    }
    fn fixture(successor: bool, captured: u64) -> (Box<NativeControl>, Owner) {
        // Component ownership/capture are explicitly modeled. The checks below
        // query actual TID/FS, signal action/mask/stack and one real filter.
        // No coordinator admission, kernel exec or guest handoff is claimed.
        let (mut control, owner) = if successor {
            let (control, owner, _) = successor_test_owner();
            (control, Owner::Successor(owner))
        } else {
            let (control, owner) = lifecycle_test_owner();
            (control, Owner::Initial(owner))
        };
        control.native_state = 1;
        control.kernel_tsc = captured;
        let mut mask = 0;
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
            .unwrap();
        control.kernel_mask = mask;
        let stack = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                65536,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(stack, libc::MAP_FAILED);
        let alternate = libc::stack_t {
            ss_sp: stack,
            ss_flags: 0,
            ss_size: 65536,
        };
        assert_eq!(
            unsafe { libc::sigaltstack(&alternate, core::ptr::null_mut()) },
            0
        );
        control.bootstrap_stack_base = stack as u64;
        control.bootstrap_stack_end = stack as u64 + 65536;
        control.bootstrap_handler = unexpected_signal as *const () as u64;
        control.bootstrap_restorer = crate::trap::FIXED_SIGNAL_RESTORER_ENTRY;
        let action = crate::signal::KernelSigaction {
            handler: control.bootstrap_handler,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64,
            restorer: control.bootstrap_restorer,
            mask: 0,
        };
        unsafe { crate::signal::raw_sigaction(libc::SIGSYS, Some(&action), None) }.unwrap();
        let startup_mask = !(1_u64 << (libc::SIGSYS - 1));
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&startup_mask), None) }
            .unwrap();
        assert_eq!(
            unsafe { crate::guest::sigalrm::seccomp_filter_count() },
            Some(0)
        );
        // The filter is a real allow-all component fixture, not the production
        // interception filter. It satisfies only the counted-kernel-state seam.
        let filter = libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        };
        let program = libc::sock_fprog {
            len: 1,
            filter: (&raw const filter).cast_mut(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    0,
                    &program,
                )
            },
            0
        );
        (control, owner)
    }
    #[test]
    fn initial_and_successor_tsc_policy_preserves_inheritance_and_subscription() {
        for successor in [false, true] {
            for captured in [1, 2] {
                for subscribed in [false, true] {
                    isolated(move || {
                        let (control, owner) = fixture(successor, captured);
                        owner.prepare(subscribed).unwrap();
                        let expected = if subscribed { 2 } else { captured };
                        assert_eq!(
                            unsafe { (&raw const control.guest_tsc).read_volatile() },
                            expected
                        );
                        assert_eq!(
                            unsafe { (&raw const control.kernel_tsc).read_volatile() },
                            captured
                        );
                        assert_eq!(control.runtime_ready, 0);
                        assert_eq!(
                            control.guest_resume_mask,
                            control.kernel_mask
                                & !(1_u64 << (libc::SIGSYS - 1))
                                & if subscribed {
                                    !(1_u64 << (libc::SIGSEGV - 1))
                                } else {
                                    u64::MAX
                                }
                        );
                        assert!(
                            owner.prepare(subscribed).is_err(),
                            "selection must be once-only"
                        );
                        assert_eq!(
                            unsafe { (&raw const control.guest_tsc).read_volatile() },
                            expected
                        );
                    });
                }
            }
        }
    }
    #[test]
    fn initial_and_successor_tsc_policy_refuses_wrong_owner_phase_layout_and_state() {
        for successor in [false, true] {
            for mutation in 0..14 {
                isolated(move || {
                    let (mut control, owner) = fixture(successor, 1);
                    unsafe {
                        match mutation {
                            0 => (&raw mut control.phase).write_volatile(3),
                            1 => {
                                (&raw mut control.native_tid).write_volatile(control.native_tid + 1)
                            }
                            2 => (&raw mut control.tool_fs).write_volatile(control.tool_fs + 8),
                            3 => (&raw mut control.runtime_ready).write_volatile(1),
                            4 => reverie_inguest_private_exec_control.store(0, Ordering::Release),
                            5 => owner.start_installation(),
                            6 => owner.start_lifecycle(),
                            7 => (&raw mut control.abi_version).write_volatile(2),
                            8 => (&raw mut control.byte_len).write_volatile(3456),
                            9 => (&raw mut control.native_state).write_volatile(3),
                            10 => (&raw mut control.kernel_tsc).write_volatile(0),
                            11 => (&raw mut control.kernel_tsc).write_volatile(3),
                            12 => (&raw mut control.guest_tsc).write_volatile(1),
                            13 => (&raw mut control.guest_tsc).write_volatile(3),
                            _ => unreachable!(),
                        }
                    }
                    let before = unsafe { (&raw const control.guest_tsc).read_volatile() };
                    assert!(
                        owner.prepare(true).is_err(),
                        "mutation {mutation} successor {successor}"
                    );
                    assert_eq!(
                        unsafe { (&raw const control.guest_tsc).read_volatile() },
                        before
                    );
                    assert_eq!(control.runtime_ready, u64::from(mutation == 3));
                });
            }
        }
    }
    #[test]
    fn tsc_policy_refuses_old_layout_before_reading_appended_fields() {
        isolated(|| {
            let pages = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    8192,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(pages, libc::MAP_FAILED);
            assert_eq!(
                unsafe {
                    libc::mprotect(pages.cast::<u8>().add(4096).cast(), 4096, libc::PROT_NONE)
                },
                0
            );
            // Only the old 3456-byte prefix is accessible; either appended read
            // reaches PROT_NONE. Never construct a reference to the new struct.
            let control = unsafe { pages.cast::<u8>().add(4096 - 3456).cast::<NativeControl>() };
            unsafe {
                (&raw mut (*control).abi_version).write_volatile(1);
                (&raw mut (*control).byte_len).write_volatile(3456);
                (&raw mut (*control).native_state).write_volatile(1);
                assert!(
                    select_guest_tsc(
                        control,
                        InstructionSubscriptions {
                            cpuid: false,
                            rdtsc: true
                        }
                    )
                    .is_err()
                );
            }
            assert_eq!(unsafe { libc::munmap(pages, 8192) }, 0);
        });
    }
}
