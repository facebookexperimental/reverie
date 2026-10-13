/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Signal multiplexing between the runtime and the guest.
//!
//! The runtime reserves `SIGSYS` for its own syscall trap. The guest must not
//! be able to change the disposition, mask, or alternate stack of a reserved
//! signal, or it could displace the trap and either crash (default `SIGSYS`
//! action) or blind the runtime. The dispatcher enforces this via
//! [`is_reserved`]; the runtime installs the handler here.
//!
//! All other signals belong to the guest and flow through untouched. When the
//! runtime later gains a hosted tool that itself wants signal events, this is
//! the single place that decides which signals are runtime-private.

use std::io;

use crate::trap::raw_syscall6;

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_inguest_signal_restorer
    .hidden reverie_inguest_signal_restorer
    .type reverie_inguest_signal_restorer,@function
reverie_inguest_signal_restorer:
    mov eax, 15
    syscall
    .global reverie_inguest_signal_restorer_return_ip
    .hidden reverie_inguest_signal_restorer_return_ip
reverie_inguest_signal_restorer_return_ip:
    ud2
    .size reverie_inguest_signal_restorer, .-reverie_inguest_signal_restorer
"#
);

unsafe extern "C" {
    fn reverie_inguest_signal_restorer();
    fn reverie_inguest_signal_restorer_return_ip();
}

/// The runtime's private signal restorer: `rt_sigreturn` (15), then `ud2`.
///
/// Every runtime signal handler returns through it (`SA_RESTORER`), so a
/// syscall filter can admit `rt_sigreturn` only at
/// [`signal_restorer_return_ip`] (signal phase 1, design section 3).
pub fn signal_restorer() -> u64 {
    #[cfg(feature = "fixed-syscall-gates")]
    if crate::trap::fixed_gates_published() {
        return crate::trap::FIXED_SIGNAL_RESTORER_ENTRY;
    }
    reverie_inguest_signal_restorer as *const () as u64
}

/// The instruction pointer Linux reports for the restorer's `rt_sigreturn`:
/// the address after its `syscall` instruction.
pub fn signal_restorer_return_ip() -> u64 {
    #[cfg(feature = "fixed-syscall-gates")]
    if crate::trap::fixed_gates_published() {
        return crate::trap::FIXED_SIGNAL_RESTORER_RETURN_IP;
    }
    reverie_inguest_signal_restorer_return_ip as *const () as u64
}

/// The kernel's `SA_RESTORER` flag on x86-64 (the libc crate does not export
/// it for glibc targets).
pub const SA_RESTORER: i32 = 0x0400_0000;

pub use crate::guest::support::KernelSigaction;

/// Raw `rt_sigaction(signal, new, old)` through the trusted gate, usable
/// before and after the syscall filter is installed, and async-signal-safe.
///
/// # Safety
///
/// Changes process-global signal disposition when `new` is given.
pub unsafe fn raw_sigaction(
    signal: i32,
    new: Option<&KernelSigaction>,
    old: Option<&mut KernelSigaction>,
) -> Result<(), i32> {
    let new = new.map_or(0, |action| action as *const KernelSigaction as u64);
    let old = old.map_or(0, |action| action as *mut KernelSigaction as u64);
    let result =
        unsafe { raw_syscall6(libc::SYS_rt_sigaction, [signal as u64, new, old, 8, 0, 0]) };
    if result < 0 {
        Err(-result as i32)
    } else {
        Ok(())
    }
}

/// Raw `rt_sigprocmask(how, set, old)` for the calling thread, through the
/// trusted gate; async-signal-safe.
///
/// # Safety
///
/// Changes the calling thread's signal mask when `set` is given.
pub unsafe fn raw_sigprocmask(
    how: i32,
    set: Option<&u64>,
    old: Option<&mut u64>,
) -> Result<(), i32> {
    let set = set.map_or(0, |set| set as *const u64 as u64);
    let old = old.map_or(0, |old| old as *mut u64 as u64);
    let result = unsafe { raw_syscall6(libc::SYS_rt_sigprocmask, [how as u64, set, old, 8, 0, 0]) };
    if result < 0 {
        Err(-result as i32)
    } else {
        Ok(())
    }
}

/// Raw `tgkill(getpid(), gettid(), signal)` through the trusted gate;
/// async-signal-safe.
///
/// # Safety
///
/// Sends `signal` to the calling thread.
pub unsafe fn raw_raise(signal: i32) -> Result<(), i32> {
    unsafe {
        let pid = raw_syscall6(libc::SYS_getpid, [0; 6]);
        let tid = raw_syscall6(libc::SYS_gettid, [0; 6]);
        let result = raw_syscall6(
            libc::SYS_tgkill,
            [pid as u64, tid as u64, signal as u64, 0, 0, 0],
        );
        if result < 0 {
            Err(-result as i32)
        } else {
            Ok(())
        }
    }
}

/// Install a runtime-owned `SA_SIGINFO` handler for `signal`, returning
/// through the private [`signal_restorer`], with no other signal blocked by
/// the action. `extra_flags` adds flags such as `SA_ONSTACK`.
///
/// # Safety
///
/// `handler` must be a valid `SA_SIGINFO` handler. Changes process-global
/// signal disposition.
pub unsafe fn install_runtime_handler(
    signal: i32,
    handler: unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
    extra_flags: i32,
) -> io::Result<()> {
    let action = KernelSigaction {
        handler: handler as *const () as u64,
        flags: (libc::SA_SIGINFO | SA_RESTORER | extra_flags) as u64,
        restorer: signal_restorer(),
        mask: 0,
    };
    unsafe { raw_sigaction(signal, Some(&action), None) }.map_err(io::Error::from_raw_os_error)
}

/// Signals the runtime reserves for itself. The guest may not reconfigure these.
pub const RESERVED_SIGNALS: &[i32] = &[libc::SIGSYS];

/// Whether `signal` is reserved by the runtime.
pub fn is_reserved(signal: i32) -> bool {
    RESERVED_SIGNALS.contains(&signal)
}

/// Install `handler` for `SIGSYS` with `SA_SIGINFO`.
///
/// `on_alt_stack` requests `SA_ONSTACK`, so the handler runs on the alternate
/// signal stack configured with [`install_alt_stack`]. That keeps the trap
/// working even when the guest's own stack is nearly exhausted.
///
/// # Safety
///
/// `handler` must be a valid `SA_SIGINFO` signal handler that is
/// async-signal-safe. Installs process-global disposition.
pub unsafe fn install_sigsys_handler(
    handler: unsafe extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void),
    on_alt_stack: bool,
) -> io::Result<()> {
    // Through the private restorer, so a filter can admit `rt_sigreturn` only
    // there ([`install_runtime_handler`]).
    unsafe {
        install_runtime_handler(
            libc::SIGSYS,
            handler,
            if on_alt_stack { libc::SA_ONSTACK } else { 0 },
        )
    }
}

/// Allocate and register an alternate signal stack for the current thread.
///
/// Returns the leaked stack memory's base pointer (kept alive for process
/// lifetime). Using an alternate stack means a trapped syscall issued near the
/// guest's stack limit still has room for the handler frame.
///
/// # Safety
///
/// Registers process/thread signal-stack state; call before installing the
/// handler on a thread.
pub unsafe fn install_alt_stack() -> io::Result<*mut libc::c_void> {
    let size = (libc::SIGSTKSZ).max(64 * 1024);
    // Leak a Vec as the stack backing store; it lives for the process lifetime.
    let mut backing = vec![0_u8; size].into_boxed_slice();
    let base = backing.as_mut_ptr().cast::<libc::c_void>();
    core::mem::forget(backing);
    let stack = libc::stack_t {
        ss_sp: base,
        ss_flags: 0,
        ss_size: size,
    };
    // The raw syscall, not libc's interposable sigaltstack.
    crate::guest::support::raw_zero_result(unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_sigaltstack,
            [(&raw const stack) as u64, 0, 0, 0, 0, 0],
        )
    })?;
    Ok(base)
}

/// Register a stack from an explicit storage choice, retaining it immediately
/// after successful kernel registration even if later handler setup fails.
/// Generic [`install_alt_stack`] callers keep their existing backing.
///
/// # Safety
/// Same thread/setup requirements as [`install_alt_stack`]. For ToolRegion
/// backing, the caller must additionally perform at most one successful
/// registration for that runtime owner in the entire process, before its
/// runtime handlers or filter are enabled. The owner publishes one immutable
/// process-wide descriptor; registering a replacement or another thread's
/// stack is not a supported multi-thread stack-ownership protocol. Legacy
/// backing retains [`install_alt_stack`]'s existing per-thread contract.
pub unsafe fn install_alt_stack_with_backing(
    backing: crate::guest::tool_region::StackBacking,
) -> io::Result<*mut libc::c_void> {
    let crate::guest::tool_region::StackBacking::ToolRegion(region) = backing else {
        return unsafe { install_alt_stack() };
    };
    let lease = region.stack(libc::SIGSTKSZ.max(64 * 1024))?;
    let base = lease.base() as *mut libc::c_void;
    let stack = libc::stack_t {
        ss_sp: base,
        ss_flags: 0,
        ss_size: lease.usable_bytes(),
    };
    crate::guest::support::raw_zero_result(unsafe {
        raw_syscall6(
            libc::SYS_sigaltstack,
            [(&raw const stack) as u64, 0, 0, 0, 0, 0],
        )
    })?;
    // The kernel now owns a live pointer. Later setup failure cannot free it.
    // Publish its exact usable range/guards, length last. This is the existing
    // selected ToolRegion branch, with no new allocation, syscall or condition.
    unsafe { region.publish_registered_altstack(base as usize, stack.ss_size) };
    core::mem::forget(lease);
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    static RESTORER_HANDLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    unsafe extern "C" fn note_signal(
        _signal: libc::c_int,
        _info: *mut libc::siginfo_t,
        _context: *mut libc::c_void,
    ) {
        RESTORER_HANDLED.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// A runtime handler installed through `install_runtime_handler` records
    /// the private restorer with `SA_RESTORER`, and its frame returns through
    /// that restorer: the thread runs on after the handler.
    #[test]
    fn a_runtime_handler_returns_through_the_private_restorer() {
        // SIGURG, which no test or runtime component handles.
        let signal = libc::SIGURG;
        unsafe { install_runtime_handler(signal, note_signal, 0) }.unwrap();
        let mut installed = KernelSigaction::default();
        unsafe { raw_sigaction(signal, None, Some(&mut installed)) }.unwrap();
        assert_eq!(installed.restorer, signal_restorer());
        assert_ne!(installed.flags & SA_RESTORER as u64, 0);
        assert_ne!(installed.flags & libc::SA_SIGINFO as u64, 0);
        unsafe { raw_raise(signal) }.unwrap();
        assert!(RESTORER_HANDLED.load(std::sync::atomic::Ordering::SeqCst));
        let default = KernelSigaction {
            handler: libc::SIG_DFL as u64,
            ..KernelSigaction::default()
        };
        unsafe { raw_sigaction(signal, Some(&default), None) }.unwrap();
        // The restorer's syscall is `mov eax, 15` (5 bytes) then `syscall` (2).
        assert_eq!(signal_restorer_return_ip(), signal_restorer() + 7);
    }

    #[test]
    fn sigsys_is_reserved_but_others_are_not() {
        assert!(is_reserved(libc::SIGSYS));
        assert!(!is_reserved(libc::SIGINT));
        assert!(!is_reserved(libc::SIGTERM));
        assert!(!is_reserved(libc::SIGCHLD));
    }
}
