/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reporting a panic raised inside the SIGSYS handler.
//!
//! The handler runs with SIGSYS blocked. Seccomp traps every syscall that does
//! not come from a trusted gate, and a trap while SIGSYS is blocked makes the
//! kernel kill the process with SIGSYS. The standard panic hook writes through
//! libc, so a panic inside the handler used to end as a bare SIGSYS kill (wait
//! status 159) with nothing on stderr. The hook installed here writes the
//! message and location through the trusted gate instead, then kills the
//! process with SIGABRT, again through the gate. A panic anywhere else goes to
//! the hook that was installed before, unchanged.

use std::panic::PanicHookInfo;
use std::ptr;
use std::sync::Once;

use super::IN_HANDLER;
use super::exit_now;
use super::raw_syscall6;
use crate::fmt::StackLine;

/// Exit status if the process survives its own SIGABRT, for example because a
/// ptrace tracer suppressed the signal. Rust exits 101 when `main` panics.
const SURVIVED_ABORT_EXIT_CODE: i32 = 101;

static INSTALL: Once = Once::new();

/// Install the hook once. The hook belongs to this crate's copy of std; a
/// program that links its own std keeps its own hook. Call before the seccomp
/// filter traps anything: setting a hook allocates and takes a lock.
pub(super) fn install() {
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if IN_HANDLER.get() {
                // SAFETY: a panic inside the handler cannot continue; the
                // report and the abort use only trusted-gate syscalls.
                unsafe { report_and_abort(info) }
            }
            previous(info);
        }));
    });
}

/// Write the panic's location and message to fd 2, then kill the process with
/// SIGABRT. Every syscall goes through the trusted gate, and nothing here
/// allocates or panics.
///
/// # Safety
///
/// Ends the process.
unsafe fn report_and_abort(info: &PanicHookInfo<'_>) -> ! {
    unsafe { block_sigpipe() };
    write_stderr(b"reverie-preload: panic in the SIGSYS handler");
    if let Some(location) = info.location() {
        write_stderr(b" at ");
        write_stderr(location.file().as_bytes());
        let mut position = StackLine::new();
        position.push_bytes(b":");
        position.push_unsigned(location.line().into());
        position.push_bytes(b":");
        position.push_unsigned(location.column().into());
        write_stderr(position.as_bytes());
    }
    write_stderr(b": ");
    write_stderr(info.payload_as_str().unwrap_or("Box<dyn Any>").as_bytes());
    write_stderr(b"\n");
    unsafe { abort() }
}

/// Block SIGPIPE on this thread. If fd 2 is a pipe whose reader has gone, the
/// writes below then fail with `EPIPE` instead of killing the process with
/// SIGPIPE before it reaches the abort.
///
/// # Safety
///
/// Changes this thread's signal mask; only the abort path calls it.
unsafe fn block_sigpipe() {
    let pipe_set: u64 = 1 << (libc::SIGPIPE - 1);
    unsafe {
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_BLOCK as u64,
                ptr::addr_of!(pipe_set) as u64,
                0,
                8,
                0,
                0,
            ],
        );
    }
}

/// Write all of `bytes` to fd 2 through the trusted gate. Gives up on the
/// first error other than `EINTR`; there is nowhere left to report it.
fn write_stderr(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is a live buffer of the given length.
        let written = unsafe {
            raw_syscall6(
                libc::SYS_write,
                [2, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0, 0],
            )
        };
        if written == -i64::from(libc::EINTR) {
            continue;
        }
        if written <= 0 {
            return;
        }
        match bytes.get(written as usize..) {
            Some(rest) => bytes = rest,
            None => return,
        }
    }
}

/// Kill the process with SIGABRT, like the last stage of `abort(3)`: restore
/// the default action, unblock the signal and send it to this thread. Unlike
/// `abort(3)`, a SIGABRT handler the program installed does not run first; it
/// would run with SIGSYS blocked and die on its first libc syscall. The default
/// action dumps core, as an ordinary Rust abort does.
///
/// # Safety
///
/// Ends the process.
unsafe fn abort() -> ! {
    let signal = libc::SIGABRT as u64;
    // The kernel's `struct sigaction`: handler, flags, restorer, mask.
    let default_action: [u64; 4] = [libc::SIG_DFL as u64, 0, 0, 0];
    let abort_set: u64 = 1 << (libc::SIGABRT - 1);
    unsafe {
        raw_syscall6(
            libc::SYS_rt_sigaction,
            [signal, default_action.as_ptr() as u64, 0, 8, 0, 0],
        );
        raw_syscall6(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_UNBLOCK as u64,
                ptr::addr_of!(abort_set) as u64,
                0,
                8,
                0,
                0,
            ],
        );
        let process = raw_syscall6(libc::SYS_getpid, [0; 6]);
        let thread = raw_syscall6(libc::SYS_gettid, [0; 6]);
        raw_syscall6(
            libc::SYS_tgkill,
            [process as u64, thread as u64, signal, 0, 0, 0],
        );
        exit_now(SURVIVED_ABORT_EXIT_CODE)
    }
}
