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
//! 2. The kernel delivers a thread-directed `SIGSYS`; [`sigsys_handler`] runs.
//! 3. The handler reconstructs a [`SyscallEvent`] from the `ucontext` registers
//!    and calls the registered [`SyscallDispatcher`].
//! 4. The dispatcher may forward through [`SyscallEvent::forward`], using an
//!    exact trusted syscall site and the interrupted protection-key rights.
//!    Runtime-private calls use [`raw_syscall6`]. Neither site re-traps.
//! 5. The handler writes the result into `RAX` and returns, resuming the guest.

use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;
use std::cell::Cell;
use std::io;
use std::ptr;

use crate::dispatch::SyscallDispatcher;
use crate::dispatch::SyscallEvent;
use crate::seccomp::TrustedGate;
use crate::signal;
pub mod frame;
mod panic_report;
mod pkru;
const SYS_SECCOMP_CODE: libc::c_int = 1;

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_preload_trusted_syscall
    .hidden reverie_preload_trusted_syscall
    .type reverie_preload_trusted_syscall,@function
reverie_preload_trusted_syscall:
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, [rsp + 8]
    .global reverie_preload_trusted_syscall_ip
    .hidden reverie_preload_trusted_syscall_ip
reverie_preload_trusted_syscall_ip:
    syscall
    .global reverie_preload_trusted_syscall_return_ip
    .hidden reverie_preload_trusted_syscall_return_ip
reverie_preload_trusted_syscall_return_ip:
    ret
    .size reverie_preload_trusted_syscall, .-reverie_preload_trusted_syscall

    .p2align 4
    .global reverie_preload_guest_syscall
    .hidden reverie_preload_guest_syscall
    .type reverie_preload_guest_syscall,@function
reverie_preload_guest_syscall:
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
    .global reverie_preload_guest_syscall_ip
    .hidden reverie_preload_guest_syscall_ip
reverie_preload_guest_syscall_ip:
    syscall
    .global reverie_preload_guest_syscall_return_ip
    .hidden reverie_preload_guest_syscall_return_ip
reverie_preload_guest_syscall_return_ip:
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
    .size reverie_preload_guest_syscall, .-reverie_preload_guest_syscall
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
    fn reverie_preload_trusted_syscall(
        number: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> i64;
    static reverie_preload_trusted_syscall_ip: u8;
    static reverie_preload_trusted_syscall_return_ip: u8;
    fn reverie_preload_guest_syscall(
        number: i64,
        args: *const u64,
        pkru: u32,
    ) -> GuestSyscallResult;
    static reverie_preload_guest_syscall_ip: u8;
    static reverie_preload_guest_syscall_return_ip: u8;
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
pub unsafe fn raw_syscall6(number: i64, args: [u64; 6]) -> i64 {
    unsafe {
        reverie_preload_trusted_syscall(
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
    unsafe { reverie_preload_guest_syscall(number, args.as_ptr(), pkru).result }
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
            let result = unsafe { reverie_preload_guest_syscall(number, args.as_ptr(), pkru) };
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

/// The address range of the trusted gate, for building the seccomp filter.
pub fn trusted_gate() -> TrustedGate {
    TrustedGate {
        syscall_ip: ptr::addr_of!(reverie_preload_trusted_syscall_ip) as usize as u64,
        return_ip: ptr::addr_of!(reverie_preload_trusted_syscall_return_ip) as usize as u64,
    }
}

/// The second exact gate, used only for guest forwarding on OSPKE machines.
/// Its addresses can be allowlisted on any CPU; unsupported CPUs never execute
/// its RDPKRU/WRPKRU instructions.
pub fn guest_syscall_gate() -> TrustedGate {
    TrustedGate {
        syscall_ip: ptr::addr_of!(reverie_preload_guest_syscall_ip) as usize as u64,
        return_ip: ptr::addr_of!(reverie_preload_guest_syscall_return_ip) as usize as u64,
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
    .global reverie_preload_sigsys_pkru
    .hidden reverie_preload_sigsys_pkru
    .type reverie_preload_sigsys_pkru,@function
reverie_preload_sigsys_pkru:
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
    .size reverie_preload_sigsys_pkru, .-reverie_preload_sigsys_pkru
    "#,
    handler = sym sigsys_handler,
);

unsafe extern "C" {
    fn reverie_preload_sigsys_pkru(
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
    panic_report::install();
    frame::initialize()?;
    let ospke = pkru::initialize()?;
    let handler = if ospke {
        reverie_preload_sigsys_pkru
    } else {
        sigsys_handler
    };
    if use_alt_stack {
        unsafe { signal::install_alt_stack()? };
    }
    unsafe { signal::install_sigsys_handler(handler, use_alt_stack) }
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
            "reverie-preload: panic in the SIGSYS handler at {}:{DELIBERATE_PANIC_LINE}:9: \
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
