/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Instruction control for the in-guest trap path. When the Tool subscribes
//! to a faulting instruction, the native [`Isa`] implementation turns on
//! its faulting control so the instruction raises `SIGSEGV`. This module
//! holds the process's subscriptions and the generic handler control flow:
//! it asks the backend (through an [`InstructionFaultSeam`]) where a fault
//! lies and whether its site can be patched, and hands unpatched faults to
//! the fallback continuation for emulation. Every arch mechanism
//! (controls, decoding, native execution) lives behind [`Isa`].

use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;
use std::io;

use crate::guest::context::RegisterContext;
use crate::guest::event::InstructionEventKind;
use crate::guest::isa::Isa;
use crate::guest::isa::NativeIsa;
use crate::guest::support::IN_GUEST_STAGE_WRITE_FAILURE_STATUS;
use crate::guest::support::KernelSigaction;
use crate::guest::support::StackLine;
use crate::guest::support::emit_in_guest_stage;
use crate::guest::support::exit_now;
use crate::guest::support::mapping_name_at;
use crate::guest::support::read_own_bytes;
use crate::guest::support::stage_stream_enabled;
use crate::guest::support::tool_callback_active;
use crate::trap::raw_syscall6;

const INSTRUCTION_CPUID: u8 = 1;
const INSTRUCTION_RDTSC: u8 = 2;
static INSTRUCTION_SUBSCRIPTIONS: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, Debug, Default)]
/// Which faulting instructions the Tool subscribes to.
pub struct InstructionSubscriptions {
    /// CPUID, trapped by CPUID faulting.
    pub cpuid: bool,
    /// RDTSC and RDTSCP, trapped by the native TSC faulting control.
    pub rdtsc: bool,
}

/// Records the subscribed instructions for this process and returns whether
/// any is subscribed.
pub fn set_instruction_subscriptions(subscriptions: InstructionSubscriptions) -> bool {
    let mut bits = 0;
    if subscriptions.cpuid {
        bits |= INSTRUCTION_CPUID;
    }
    if subscriptions.rdtsc {
        bits |= INSTRUCTION_RDTSC;
    }
    INSTRUCTION_SUBSCRIPTIONS.store(bits, Ordering::Release);
    bits != 0
}

/// Whether any instruction is subscribed in this process.
pub fn any_instruction_subscribed() -> bool {
    INSTRUCTION_SUBSCRIPTIONS.load(Ordering::Acquire) != 0
}

/// Whether CPUID is subscribed in this process.
pub fn cpuid_interception_enabled() -> bool {
    INSTRUCTION_SUBSCRIPTIONS.load(Ordering::Acquire) & INSTRUCTION_CPUID != 0
}

/// Whether RDTSC and RDTSCP are subscribed in this process.
pub fn rdtsc_interception_enabled() -> bool {
    INSTRUCTION_SUBSCRIPTIONS.load(Ordering::Acquire) & INSTRUCTION_RDTSC != 0
}

/// Whether `kind` is subscribed in this process.
pub fn instruction_is_subscribed(kind: InstructionEventKind) -> bool {
    let bits = INSTRUCTION_SUBSCRIPTIONS.load(Ordering::Acquire);
    match kind {
        InstructionEventKind::Cpuid => bits & INSTRUCTION_CPUID != 0,
        InstructionEventKind::Rdtsc | InstructionEventKind::Rdtscp => bits & INSTRUCTION_RDTSC != 0,
    }
}

/// Recognize a faulting instruction encoding at the start of `bytes`,
/// through the native architecture's decoder.
pub fn decode_instruction(bytes: &[u8]) -> Option<(InstructionEventKind, &'static [u8])> {
    NativeIsa::decode_instruction(bytes)
}

/// Checks that this thread can turn on the faulting each subscribed
/// instruction needs, through the native architecture's admission
/// probe. Fails with `Unsupported` when the architecture, kernel or
/// CPU lacks the control.
pub fn preflight_instruction_faulting(subscriptions: InstructionSubscriptions) -> io::Result<()> {
    NativeIsa::admit_instruction_subscriptions(subscriptions)
}

/// Turns on this thread's faulting controls for the subscribed
/// instructions, through the native architecture.
pub fn enable_instruction_faulting(subscriptions: InstructionSubscriptions) -> io::Result<()> {
    NativeIsa::enable_instruction_faulting(subscriptions)
}

/// Lets `kind` execute natively on this thread (`enabled`), or makes it
/// fault again, through the native architecture.
///
/// # Safety
///
/// The caller must turn faulting back on (`enabled == false`) before guest
/// code runs again on this thread, or the guest executes the instruction
/// natively and the Tool never sees it.
pub unsafe fn set_instruction_native(kind: InstructionEventKind, enabled: bool) -> io::Result<()> {
    unsafe { NativeIsa::set_instruction_native(kind, enabled) }
}

/// [`set_instruction_native`] for every subscribed instruction.
///
/// # Safety
///
/// The caller must turn faulting back on (`enabled == false`) before guest
/// code runs again on this thread, or the guest executes the instruction
/// natively and the Tool never sees it.
pub unsafe fn set_all_instruction_native(enabled: bool) -> io::Result<()> {
    if cpuid_interception_enabled() {
        unsafe { set_instruction_native(InstructionEventKind::Cpuid, enabled) }?;
    }
    if rdtsc_interception_enabled() {
        unsafe { set_instruction_native(InstructionEventKind::Rdtsc, enabled) }?;
    }
    Ok(())
}

/// Executes `kind` natively with `context`'s registers as input and
/// writes its results back into `context`, through the native
/// architecture.
///
/// # Safety
///
/// Native execution of `kind` must be enabled on this thread
/// ([`set_instruction_native`]); otherwise the helper faults.
pub unsafe fn execute_native_instruction(
    kind: InstructionEventKind,
    context: &mut RegisterContext,
) {
    unsafe { NativeIsa::execute_native_instruction(kind, context) };
}

/// Executes `kind` natively with the frame's registers as input,
/// writes its results into the frame and advances its resume
/// address past the instruction, through the native architecture.
///
/// # Safety
///
/// `context` must be a kernel fault frame for a `kind` instruction,
/// and native execution of `kind` must be enabled on this thread
/// ([`set_instruction_native`]); otherwise the helper faults again.
pub unsafe fn execute_native_fault_instruction(
    kind: InstructionEventKind,
    context: &mut libc::ucontext_t,
    instruction_len: usize,
) {
    unsafe { NativeIsa::execute_native_fault_instruction(kind, context, instruction_len) };
}

/// Execute a faulting instruction reached from inside an active Tool callback
/// at the private native helper, in signal context, and advance past it.
/// Re-entering the Tool would deadlock on its already-held lock.
///
/// # Safety
///
/// Call only from the runtime's `SIGSEGV` handler, with `context` its own
/// kernel frame, whose RIP is at a `kind` instruction of `instruction_len`
/// bytes.
pub unsafe fn execute_nested_fault_natively(
    kind: InstructionEventKind,
    context: &mut libc::ucontext_t,
    instruction_len: usize,
) {
    emit_in_guest_stage(match kind {
        InstructionEventKind::Cpuid => b"nested-instruction-fault-native-cpuid",
        InstructionEventKind::Rdtsc => b"nested-instruction-fault-native-rdtsc",
        InstructionEventKind::Rdtscp => b"nested-instruction-fault-native-rdtscp",
    });
    if unsafe { set_instruction_native(kind, true) }.is_err() {
        emit_in_guest_stage(b"instruction-sigsegv-enable-native-failed");
        unsafe { deliver_default_sigsegv() };
    }
    unsafe { execute_native_fault_instruction(kind, context, instruction_len) };
    if unsafe { set_instruction_native(kind, false) }.is_err() {
        emit_in_guest_stage(b"instruction-sigsegv-disable-native-failed");
        unsafe { deliver_default_sigsegv() };
    }
}

/// Redirect this kernel `SIGSEGV` frame to the owned fallback continuation,
/// which runs the Tool's instruction callback in ordinary context after
/// sigreturn and resumes the guest after the instruction, with the Tool's
/// result, through the same completion as an unpatched syscall.
///
/// # Safety
///
/// Call only from the runtime's `SIGSEGV` handler, with `info` and
/// `raw_context` coming directly from its own kernel-created `SA_SIGINFO`
/// frame, for the faulting `kind` instruction at `address`, and with runtime
/// memory access already enabled (the contract of
/// [`SignalFrame::from_instruction_fault`](crate::trap::frame::SignalFrame::from_instruction_fault)).
/// No reference may alias the frame's context prefix or its FP state from
/// this call until the handler returns: the call rewrites saved registers
/// through the frame. When it returns, the frame resumes at the fallback
/// continuation, and the handler must return without changing the frame's
/// RIP or resuming the guest any other way. On every other outcome the call
/// does not return.
pub unsafe fn emulate_through_continuation(
    info: *const libc::siginfo_t,
    raw_context: *mut libc::c_void,
    address: u64,
    kind: InstructionEventKind,
) {
    // SAFETY: both pointers are this invocation's kernel frame. No reference
    // into the context prefix is live past this point.
    let mut frame =
        match unsafe { crate::trap::frame::SignalFrame::from_instruction_fault(raw_context, info) }
        {
            Ok(frame) => frame,
            Err(_) => {
                emit_in_guest_stage(b"instruction-sigsegv-not-a-kernel-fault");
                unsafe { deliver_default_sigsegv() };
            }
        };
    // SAFETY: this is the SIGSEGV handler and `frame` is the fault's own frame
    // for the `kind` instruction at `address`; on Ok(Some) the RIP is set to
    // the entry below, and on Err the process ends.
    match unsafe {
        crate::guest::continuation::prepare_instruction_signal(address, kind, &mut frame)
    } {
        Ok(Some(entry)) => {
            emit_in_guest_stage(match kind {
                InstructionEventKind::Cpuid => b"instruction-fault-continuation-cpuid",
                InstructionEventKind::Rdtsc => b"instruction-fault-continuation-rdtsc",
                InstructionEventKind::Rdtscp => b"instruction-fault-continuation-rdtscp",
            });
            NativeIsa::set_frame_resume(&mut frame, entry);
        }
        Ok(None) => {
            emit_in_guest_stage(b"instruction-sigsegv-continuation-unavailable");
            unsafe { deliver_default_sigsegv() };
        }
        // Same integrity failure as the SIGSYS fallback: the continuation
        // was reserved but the frame could not be captured faithfully.
        Err(_) => unsafe { exit_now(126) },
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-late-code-cpuid): Review genuine SIGSEGV death from the handler.
/// End the process by a real, default-action `SIGSEGV` from inside the
/// runtime's own `SIGSEGV` handler, so the parent observes a signal death (and
/// a core where the limits allow one) rather than an ordinary exit status.
///
/// The handler runs with `SIGSEGV` blocked (no `SA_NODEFER`), so a `tgkill`
/// alone would only leave the signal pending. Reset the disposition to
/// `SIG_DFL`, unblock it, then send it to this thread: the kernel acts on it
/// when `tgkill` returns. The final exit is reached only if both controls
/// failed.
///
/// It works the same from the runtime's SIGSYS dispatch (where `SIGSEGV` may
/// or may not be blocked), which ends the guest this way when a backend's
/// failed site installation may have left part of a jump in the guest's code.
///
/// # Safety
///
/// Call only from the runtime's `SIGSEGV` handler or its SIGSYS dispatch. The
/// process ends; no destructor runs.
pub unsafe fn deliver_default_sigsegv() -> ! {
    let default_action = KernelSigaction::default();
    let _ = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigaction,
            [
                libc::SIGSEGV as u64,
                (&raw const default_action) as u64,
                0,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    let unblock = 1_u64 << (libc::SIGSEGV - 1);
    let _ = unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_UNBLOCK as u64,
                (&raw const unblock) as u64,
                0,
                core::mem::size_of::<u64>() as u64,
                0,
                0,
            ],
        )
    };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let _ = unsafe {
        raw_syscall6(
            libc::SYS_tgkill,
            [pid as u64, tid as u64, libc::SIGSEGV as u64, 0, 0, 0],
        )
    };
    unsafe { exit_now(128 + libc::SIGSEGV) }
}

/// Where a faulting instruction lies, as the backend's seam reports it.
pub enum FaultSite {
    /// In code the backend can patch; the decoded instruction at the fault.
    Patchable {
        /// The instruction.
        kind: InstructionEventKind,
        /// Its exact encoding, as `decode_instruction` returns it.
        encoding: &'static [u8],
    },
    /// Outside all code the backend can patch: emulated if the bytes are
    /// exactly a subscribed instruction and the fault is kernel-raised.
    Unpatchable,
    /// In code the backend can patch, but not a recognized instruction. The
    /// backend has reported it; the process ends by default `SIGSEGV`.
    Refused,
}

/// What the backend did with a subscribed instruction's patchable site.
pub enum PatchOutcome {
    /// Resume at this address (the hook's trampoline), which runs the Tool's
    /// callback and continues after the instruction.
    Resume(u64),
    /// Nothing at the site changed: emulate the instruction through the
    /// fallback continuation.
    Emulate,
    /// The site may be partly patched, so the code after the instruction is no
    /// longer known; the process ends by default `SIGSEGV`.
    Failed,
}

/// The backend's part of instruction fault handling. Both functions are
/// called only from the `SIGSEGV` handler installed by
/// [`install_instruction_signal_handler`], for a fault at `address` (the
/// frame's RIP), and must be async-signal-safe.
pub struct InstructionFaultSeam {
    /// Classifies the fault. `info` may be null; `context` is the handler's
    /// kernel frame, valid for reads during the call.
    pub locate: unsafe fn(
        address: u64,
        info: *const libc::siginfo_t,
        context: *const libc::ucontext_t,
    ) -> FaultSite,
    /// Patches the site of a subscribed instruction reported as
    /// [`FaultSite::Patchable`]; never called inside a Tool callback.
    pub patch: unsafe fn(
        address: u64,
        kind: InstructionEventKind,
        encoding: &'static [u8],
    ) -> PatchOutcome,
}

static INSTRUCTION_FAULT_SEAM: AtomicPtr<InstructionFaultSeam> = AtomicPtr::new(ptr::null_mut());

/// Records `subscriptions` and, when any instruction is subscribed, installs
/// the instruction fault handler as this process's `SIGSEGV` action, using
/// `seam` for the backend's part (on the alternate signal stack when
/// `on_alt_stack`).
///
/// # Safety
///
/// `seam`'s functions must meet [`InstructionFaultSeam`]'s contract. The
/// handler replaces any `SIGSEGV` action the process had.
pub unsafe fn install_instruction_signal_handler(
    seam: &'static InstructionFaultSeam,
    subscriptions: InstructionSubscriptions,
    on_alt_stack: bool,
) -> io::Result<()> {
    if !set_instruction_subscriptions(subscriptions) {
        return Ok(());
    }
    INSTRUCTION_FAULT_SEAM.store(ptr::from_ref(seam).cast_mut(), Ordering::Release);

    #[cfg(feature = "exec-private-init")]
    let handler = if super::exec_private::active() {
        // Discover PKRU before selecting either private bridge. SIGSEGV is
        // installed before SIGSYS; the latter's discovery would be too late.
        super::exec_private::signal_entry(true, crate::trap::prepare_private_signal_features()?)
    } else {
        instruction_sigsegv_handler
    };
    #[cfg(not(feature = "exec-private-init"))]
    let handler = instruction_sigsegv_handler;
    // Through the runtime's private restorer, like the SIGSYS handler, and
    // with the same mask (`guest::runtime_mask`).
    unsafe {
        crate::signal::install_masked_runtime_handler(
            libc::SIGSEGV,
            handler,
            if on_alt_stack { libc::SA_ONSTACK } else { 0 },
            crate::guest::runtime_mask::runtime_action_mask(),
        )
    }
}

pub(crate) unsafe extern "C" fn instruction_sigsegv_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    if signal != libc::SIGSEGV || context.is_null() {
        emit_in_guest_stage(b"instruction-sigsegv-invalid-context");
        unsafe { deliver_default_sigsegv() };
    }
    // SAFETY: stored from a &'static before the handler was installed.
    let Some(seam) = (unsafe { INSTRUCTION_FAULT_SEAM.load(Ordering::Acquire).as_ref() }) else {
        emit_in_guest_stage(b"instruction-sigsegv-no-seam");
        unsafe { deliver_default_sigsegv() };
    };
    // Keep the raw kernel pointer: the fallback continuation borrows the same
    // frame through `SignalFrame`, which must not alias a live reference.
    let raw_context = context;
    let address =
        NativeIsa::fault_instruction_pointer(unsafe { &*raw_context.cast::<libc::ucontext_t>() });
    let (kind, expected) =
        match unsafe { (seam.locate)(address, info, raw_context.cast::<libc::ucontext_t>()) } {
            FaultSite::Patchable { kind, encoding } => (kind, encoding),
            FaultSite::Refused => unsafe { deliver_default_sigsegv() },
            FaultSite::Unpatchable => {
                unsafe { emulate_unpatchable_instruction(info, raw_context, address) };
                return;
            }
        };
    if !instruction_is_subscribed(kind) {
        emit_in_guest_stage(b"instruction-sigsegv-unsubscribed");
        unsafe { deliver_default_sigsegv() };
    }

    // An unpatched instruction reached from an active Tool callback must not
    // allocate a trampoline. After fork, the arena cursor is process-private
    // but its backing pages are shared; child publication would let the parent
    // reuse and overwrite the same slot. Execute at the private native helper
    // and advance the faulting context instead.
    #[cfg(feature = "exec-private-init")]
    let private = super::exec_private::private_instruction(address);
    #[cfg(not(feature = "exec-private-init"))]
    let private = false;
    if tool_callback_active() || private {
        let context = unsafe { &mut *raw_context.cast::<libc::ucontext_t>() };
        unsafe { execute_nested_fault_natively(kind, context, expected.len()) };
        return;
    }

    match unsafe { (seam.patch)(address, kind, expected) } {
        PatchOutcome::Resume(entry) => {
            let context = unsafe { &mut *raw_context.cast::<libc::ucontext_t>() };
            NativeIsa::set_fault_instruction_pointer(context, entry);
        }
        PatchOutcome::Emulate => unsafe {
            emulate_through_continuation(info, raw_context, address, kind)
        },
        PatchOutcome::Failed => unsafe { deliver_default_sigsegv() },
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-late-code-cpuid): Review emulation of instructions outside every arena.
/// Handle an instruction fault at `address`, which lies outside all code the
/// backend can patch (for LiteInst, every arena recorded at startup), so no
/// hook can ever be published there.
///
/// Only a kernel-raised fault (`SI_KERNEL` from the native instruction
/// faulting controls) whose bytes, read without risking a nested fault,
/// decode as a subscribed instruction is emulated. Everything else keeps the
/// default `SIGSEGV` the guest would have received without the runtime.
unsafe fn emulate_unpatchable_instruction(
    info: *const libc::siginfo_t,
    raw_context: *mut libc::c_void,
    address: u64,
) {
    let mut bytes = [0_u8; 8];
    let available = unsafe { read_own_bytes(address, &mut bytes) };
    let kernel_fault = !info.is_null() && unsafe { (*info).si_code } == libc::SI_KERNEL;
    let decoded = kernel_fault
        .then(|| decode_instruction(&bytes[..available]))
        .flatten();
    let Some((kind, expected)) = decoded else {
        emit_unarenaed_refusal_stage(
            b"instruction-sigsegv-no-reachable-arena",
            address,
            &bytes[..available],
        );
        unsafe { deliver_default_sigsegv() };
    };
    if !instruction_is_subscribed(kind) {
        emit_in_guest_stage(b"instruction-sigsegv-unsubscribed");
        unsafe { deliver_default_sigsegv() };
    }
    #[cfg(feature = "exec-private-init")]
    let private = super::exec_private::private_instruction(address);
    #[cfg(not(feature = "exec-private-init"))]
    let private = false;
    if tool_callback_active() || private {
        let context = unsafe { &mut *raw_context.cast::<libc::ucontext_t>() };
        unsafe { execute_nested_fault_natively(kind, context, expected.len()) };
        return;
    }
    unsafe { emulate_through_continuation(info, raw_context, address, kind) };
}

/// Emit the refusal of a fault outside every arena with its absolute RIP, the
/// `/proc/self/maps` path of the mapping containing it (`[anon]` when the
/// mapping has none, `[unmapped]` when no mapping contains it), and the bytes
/// that could be read there. Allocation-free and signal-safe; it reads the
/// maps file only when the stage stream is enabled.
fn emit_unarenaed_refusal_stage(stage: &[u8], address: u64, bytes: &[u8]) {
    if !stage_stream_enabled() {
        return;
    }
    let mut name = [0_u8; 256];
    let name = match unsafe { mapping_name_at(address, &mut name) } {
        Some(0) => b"[anon]".as_slice(),
        Some(len) => &name[..len],
        None => b"[unmapped]".as_slice(),
    };
    let mut line = StackLine::new();
    line.push_bytes(b"INFO reverie_liteinst::tool_host: [in-guest pid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) });
    line.push_bytes(b" tid=");
    line.push_signed(unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) });
    line.push_bytes(b"] stage=");
    line.push_bytes(stage);
    line.push_bytes(b" rip=0x");
    line.push_hex(address);
    line.push_bytes(b" bytes=");
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            line.push_bytes(b"-");
        }
        line.push_hex_byte(*byte);
    }
    line.push_bytes(b" map=");
    line.push_bytes(name);
    line.push_bytes(b"\n");
    let written = unsafe {
        raw_syscall6(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                line.as_bytes().as_ptr() as u64,
                line.as_bytes().len() as u64,
                0,
                0,
                0,
            ],
        )
    };
    if written != line.as_bytes().len() as i64 {
        unsafe { exit_now(IN_GUEST_STAGE_WRITE_FAILURE_STATUS) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_recognizes_only_the_faulting_instruction_encodings() {
        let decoded =
            |bytes: &[u8]| decode_instruction(bytes).map(|(kind, expected)| (kind, expected.len()));
        assert_eq!(
            decoded(&[0x0f, 0xa2]),
            Some((InstructionEventKind::Cpuid, 2))
        );
        assert_eq!(
            decoded(&[0x0f, 0xa2, 0xc3]),
            Some((InstructionEventKind::Cpuid, 2))
        );
        assert_eq!(
            decoded(&[0x0f, 0x31, 0xc3]),
            Some((InstructionEventKind::Rdtsc, 2))
        );
        assert_eq!(
            decoded(&[0x0f, 0x01, 0xf9]),
            Some((InstructionEventKind::Rdtscp, 3))
        );
        assert_eq!(
            decoded(&[0x0f, 0x01, 0xf9, 0xc3]),
            Some((InstructionEventKind::Rdtscp, 3))
        );
        for kind in [
            InstructionEventKind::Cpuid,
            InstructionEventKind::Rdtsc,
            InstructionEventKind::Rdtscp,
        ] {
            assert_eq!(
                decoded(match kind {
                    InstructionEventKind::Cpuid => &[0x0f, 0xa2],
                    InstructionEventKind::Rdtsc => &[0x0f, 0x31],
                    InstructionEventKind::Rdtscp => &[0x0f, 0x01, 0xf9],
                })
                .map(|(_, len)| len as u64),
                Some(kind.encoded_len())
            );
        }
        // A truncated RDTSCP, a different 0f 01 group member (rdpid is not),
        // syscall, ud2 and a load are not emulated.
        for bytes in [
            &[0x0f, 0x01][..],
            &[0x0f, 0x01, 0xf8],
            &[0x0f, 0x05],
            &[0x0f, 0x0b],
            &[0x48, 0x8b, 0x00],
            &[0x0f],
            &[],
        ] {
            assert_eq!(decoded(bytes), None, "{bytes:02x?}");
        }
    }
}
