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
use std::ptr;

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
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO | if on_alt_stack { libc::SA_ONSTACK } else { 0 };
    action.sa_sigaction = handler as *const () as usize;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::sigaction(libc::SIGSYS, &action, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    if unsafe { libc::sigaltstack(&stack, ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigsys_is_reserved_but_others_are_not() {
        assert!(is_reserved(libc::SIGSYS));
        assert!(!is_reserved(libc::SIGINT));
        assert!(!is_reserved(libc::SIGTERM));
        assert!(!is_reserved(libc::SIGCHLD));
    }
}
