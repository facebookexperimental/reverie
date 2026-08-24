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
//! 4. The dispatcher may forward the syscall through the **trusted gate**
//!    ([`raw_syscall6`]) — a single `syscall` instruction at a whitelisted
//!    address, so it does not re-trap — then sets a result.
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
"#
);

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
}

/// The registered dispatcher, as a leaked thin pointer to a boxed trait object.
static DISPATCHER: AtomicPtr<Box<dyn SyscallDispatcher>> = AtomicPtr::new(ptr::null_mut());

thread_local! {
    /// Per-thread reentrancy guard. The const initializer and no-drop `Cell`
    /// select native TLS without Rust's lazy-initialization state machine.
    static IN_HANDLER: Cell<bool> = const { Cell::new(false) };
}

/// Execute a real syscall through the trusted gate.
///
/// The gate's `syscall` instruction is whitelisted in the seccomp filter, so
/// this does not re-trap. This is the only syscall path a dispatcher may use.
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

/// The address range of the trusted gate, for building the seccomp filter.
pub fn trusted_gate() -> TrustedGate {
    TrustedGate {
        syscall_ip: ptr::addr_of!(reverie_preload_trusted_syscall_ip) as usize as u64,
        return_ip: ptr::addr_of!(reverie_preload_trusted_syscall_return_ip) as usize as u64,
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

    let context = unsafe { &mut *context.cast::<libc::ucontext_t>() };
    let registers = &mut context.uc_mcontext.gregs;
    let mut event = SyscallEvent::new(
        registers[libc::REG_RAX as usize],
        [
            registers[libc::REG_RDI as usize] as u64,
            registers[libc::REG_RSI as usize] as u64,
            registers[libc::REG_RDX as usize] as u64,
            registers[libc::REG_R10 as usize] as u64,
            registers[libc::REG_R8 as usize] as u64,
            registers[libc::REG_R9 as usize] as u64,
        ],
        registers[libc::REG_RIP as usize] as u64,
    );

    dispatch_event(&mut event);

    // AUTONOMOUS-BOT-IMPLEMENTED
    if let Some(resume_address) = event.resume_address() {
        // Preserve the syscall-number register so the replacement callback
        // observes the original entry state after sigreturn.
        registers[libc::REG_RIP as usize] = resume_address as i64;
    } else {
        registers[libc::REG_RAX as usize] = event.resolved_result();
    }
    IN_HANDLER.set(false);
}

/// Install the SIGSYS handler (and, optionally, an alternate signal stack).
///
/// # Safety
///
/// Installs process-global signal disposition; call once during init.
pub unsafe fn install_handler(use_alt_stack: bool) -> io::Result<()> {
    if use_alt_stack {
        unsafe { signal::install_alt_stack()? };
    }
    unsafe { signal::install_sigsys_handler(sigsys_handler, use_alt_stack) }
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
}
