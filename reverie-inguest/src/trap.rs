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
#[cfg(feature = "fixed-syscall-gates")]
mod fixed_gates;
pub mod frame;
mod panic_report;
mod pkru;

/// Frozen optional gate ABI. These constants emit no default-path code.
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
    #[cfg(feature = "fixed-syscall-gates")]
    {
        fixed_gates::published()
    }
    #[cfg(not(feature = "fixed-syscall-gates"))]
    {
        false
    }
}

/// The exact dedicated owned range after publication, including page padding.
pub fn fixed_gate_region() -> Option<(u64, u64)> {
    fixed_gates_published().then_some((FIXED_GATE_BASE, FIXED_GATE_BASE + FIXED_GATE_BYTES))
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
    #[cfg(feature = "fixed-syscall-gates")]
    {
        unsafe { fixed_gates::prepare() }
    }
    #[cfg(not(feature = "fixed-syscall-gates"))]
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
    pkru::present()
}

#[cfg(feature = "exec-private-init")]
pub(crate) fn prepare_private_signal_features() -> io::Result<bool> {
    frame::initialize()?;
    pkru::initialize()
}
const SYS_SECCOMP_CODE: libc::c_int = 1;

core::arch::global_asm!(
    r#"
    .text
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

// SysV classifies this concrete 16-byte integer pair into RAX and RDX. Rust's
// Option layout never crosses the assembly boundary.
#[repr(C)]
struct GuestSyscallResult {
    result: i64,
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
    #[cfg(feature = "fixed-syscall-gates")]
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
    #[cfg(feature = "fixed-syscall-gates")]
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
    #[cfg(feature = "fixed-syscall-gates")]
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
    match guest_pkru {
        Some(pkru) => {
            #[cfg(feature = "fixed-syscall-gates")]
            let result = if fixed_gates_published() {
                unsafe { fixed_gates::guest(number, &args, pkru) }
            } else {
                unsafe { reverie_inguest_guest_syscall(number, args.as_ptr(), pkru) }
            };
            #[cfg(not(feature = "fixed-syscall-gates"))]
            let result = unsafe { reverie_inguest_guest_syscall(number, args.as_ptr(), pkru) };
            NativeSyscallResult {
                result: result.result,
                pkru: Some(result.pkru as u32),
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
    #[cfg(feature = "exec-private-init")]
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
    if use_alt_stack {
        unsafe { signal::install_alt_stack_with_backing(backing)? };
    }
    unsafe { signal::install_sigsys_handler(handler, use_alt_stack) }
}

#[cfg(feature = "exec-private-init")]
pub(crate) unsafe fn adopt_authenticated_initial_gate() -> io::Result<()> {
    unsafe { fixed_gates::adopt_authenticated_initial_page() }
}

/// Verify the controlled native bootstrap's physical page without publication.
///
/// # Safety
/// The caller owns the actual inherited qualified gate/filter and excludes
/// Guest execution, workers and mapping changes. This proves neither admission
/// nor permission to publish a Tool or native control.
#[cfg(all(feature = "exec-private-init", feature = "coordinator-rpc"))]
pub(crate) unsafe fn verify_native_io_gate() -> io::Result<()> {
    unsafe { fixed_gates::verify_initial_page() }
}

/// Use the inherited scalar mechanism even while its selector is unpublished.
///
/// # Safety
/// A checked native I/O scope must retain the real qualified RX page/filter,
/// original task/private FS and valid scalar arguments/return stack. No Guest
/// may invoke this mechanism, and it supplies no image admission authority.
#[cfg(all(feature = "exec-private-init", feature = "coordinator-rpc"))]
pub(crate) unsafe fn native_io_syscall(number: i64, args: [u64; 6]) -> i64 {
    unsafe { fixed_gates::scalar(number, args) }
}

#[cfg(test)]
mod tests {
    use super::*;

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
