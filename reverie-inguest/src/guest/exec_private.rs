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

#[cfg(feature = "coordinator-rpc")]
mod native_io;
#[cfg(feature = "coordinator-rpc")]
pub(crate) use native_io::NativeGateIoBinding;
#[cfg(feature = "coordinator-rpc")]
pub use native_io::NativeInitializationIoGuard;

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
            reverie_inguest_private_guest_call(
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
fn publish_control_slot(control: *mut NativeControl) -> io::Result<()> {
    reverie_inguest_private_exec_control
        .compare_exchange(0, control as usize, Ordering::Release, Ordering::Relaxed)
        .map_err(|_| io::Error::other("private Tool control published twice"))?;
    Ok(())
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
    #[cfg(feature = "exec-private-successor")]
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
    let control = control_pointer();
    unsafe {
        if number == libc::SYS_set_tid_address && result.result > 0 {
            (&raw mut (*control).kernel_clear_tid).write_volatile(args[0]);
        } else if number == libc::SYS_set_robust_list && result.result == 0 {
            (&raw mut (*control).kernel_robust_head).write_volatile(args[0]);
            (&raw mut (*control).kernel_robust_len).write_volatile(args[1]);
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
    .global reverie_inguest_private_lifecycle_call
    .hidden reverie_inguest_private_lifecycle_call
    .type reverie_inguest_private_lifecycle_call,@function
reverie_inguest_private_lifecycle_call:
    endbr64
    mov r11d, 6
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
    mov rax, [rsp + 40]
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
pub(crate) fn callback_prepared() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    unsafe {
        if (&raw const (*control).phase).read_volatile() != 3 {
            terminal();
        }
        (&raw mut (*control).phase).write_volatile(4);
    }
}
pub(crate) fn guest_completed() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    unsafe {
        if (&raw const (*control).phase).read_volatile() != 4 {
            terminal();
        }
        (&raw mut (*control).phase).write_volatile(3);
    }
}
pub(crate) fn private_instruction(address: u64) -> bool {
    let control = control_pointer();
    if control.is_null() {
        return false;
    }
    unsafe {
        if !matches!((&raw const (*control).phase).read_volatile(), 2 | 4 | 6) {
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
    mapped_callback_origin()
        && !c.is_null()
        && unsafe { (&raw const (*c).phase).read_volatile() } == 4
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
    syscall_handler = sym crate::trap::sigsys_handler,
    instruction_handler = sym super::instruction::instruction_sigsegv_handler,
);

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
    reverie_inguest_private_exec_control.store(address, Ordering::Release);
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
}
impl InitialImageControl {
    fn new(control: usize) -> Self {
        Self {
            control,
            installation: AtomicUsize::new(0),
            region: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            installed_host: AtomicUsize::new(0),
            lifecycle: AtomicUsize::new(0),
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
            _same_thread: core::marker::PhantomData,
        };
        if self.installation.load(Ordering::Acquire) != 2
            || host == 0
            || self.installed_host.load(Ordering::Acquire) != host
        {
            return Err(io::Error::other(
                "InitialImage lifecycle lacks its installed host/frontend",
            ));
        }
        self.check_initial_thread()?;
        Ok(permit)
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
    _same_thread: core::marker::PhantomData<*mut ()>,
}

#[cfg(any(feature = "coordinator-rpc", test))]
impl InitialLifecyclePermit<'_> {
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
    reverie_inguest_private_exec_control.store(address, Ordering::Release);
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
