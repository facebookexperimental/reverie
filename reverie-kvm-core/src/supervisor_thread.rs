/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host threads that drive guest processes and guest threads, and their
//! stack size.
//!
//! A supervisor thread runs one guest process's or one guest thread's whole
//! loop: its vCPU entries, LinuxEmu's syscall emulation and the Tool's
//! callbacks, under one `futures::executor::block_on`. Its stack holds that
//! loop's future and every frame a Tool callback needs. The supervisor threads
//! are the forked-process threads (`reverie-kvm-process-<pid>`) and the guest
//! thread workers (`reverie-kvm-guest-<tid>`), Tool-owned or host-owned.
//!
//! A thread spawned without an explicit size gets `RUST_MIN_STACK`, or Rust's
//! 2 MiB default, and a debug build overflows 2 MiB on these threads. So every
//! supervisor thread is spawned with [`stack_bytes`] of stack.
//!
//! The rule goes further: outside tests, reverie-kvm-core, reverie-kvm and
//! reverie-linuxemu create every Rust thread with [`builder`], so every thread
//! gets that stack, helpers included. A thread that runs no Tool code can
//! still destroy Tool or executor state, whose destructor can be as deep as a
//! Tool callback, and which threads can is easy to misjudge:
//! - `reverie-kvm-reaper` drops a dropped run's executors, and with them any
//!   Tool future they retained unpolled;
//! - `reverie-kvm-join` receives each guest worker's result and panic payload;
//! - `kvm-task-file-exit` wakes a guest waiter's registered waker, and after
//!   that waiter is cancelled, its wake drops the last reference to whatever
//!   the waker owns.
//!
//! Clippy checks the rule. Each of the three crates has a `clippy.toml` that
//! disallows `std::thread::spawn`, `std::thread::scope`,
//! `std::thread::Builder::new`, `std::thread::Builder::stack_size`,
//! `std::thread::Builder::spawn_scoped`, `std::thread::Scope::spawn` and
//! libc's `fork`, `vfork`, `clone` and `pthread_create`. Clippy matches
//! resolved paths, so a type alias or a re-export does not escape it. Outside
//! tests and test support, only [`builder`] calls them, under an `allow`. A
//! raw syscall cannot be told apart from other syscalls there, so the rule's
//! exceptions, none of them a Rust thread, are reviewed by hand:
//! - the native exit broker, a separate process that reverie-linuxemu's
//!   `native_exit_broker` makes with a raw `SYS_clone`, and the job workers
//!   that the broker makes with a raw `SYS_fork`;
//! - the terminal reader in reverie-linuxemu's `terminal_read.c`, a pthread
//!   that runs only C and drops no Rust state.
//!
//! The run's first process is not on a supervisor thread. It runs on whichever
//! embedder thread polls the run, and needs about as much stack there: 2,092
//! KiB below the run's entry frame in a debug build, 247 KiB in a release
//! build, in the measurements below. An embedder should poll a run from a
//! thread with at least [`KVM_SUPERVISOR_THREAD_STACK_BYTES`] of stack.

use std::ffi::OsStr;
use std::sync::OnceLock;

/// The stack every supervisor thread is spawned with, unless `RUST_MIN_STACK`
/// asks for more (see [`stack_bytes`]).
///
/// Measured high-water marks (the lowest stack page a thread touched, below
/// its entry frame) over the KVM integration tests of a large production Tool
/// (fork trees, nested signal handlers, POSIX and interval timers, exec and
/// waits) and over Reverie's own KVM suites:
///
/// | build   | forked-process thread | guest thread | Reverie's own Tools |
/// |---------|-----------------------|--------------|---------------------|
/// | debug   | 2,054 KiB             | 2,029 KiB    | 974 KiB             |
/// | release | 235 KiB               | 230 KiB      | 159 KiB             |
///
/// Spawned with exactly 2,176 KiB, 12 of the 25 debug runs that use these
/// threads overflowed; with 2,240 KiB none did. In release, 256 KiB overflowed
/// all 25 and 320 KiB none. 16 MiB is about seven times the debug minimum,
/// enough for a Tool to grow without changing this. It is reserved address
/// space: physical memory is allocated only for the pages a thread touches
/// (about 2.2 MiB in a debug build and 300 KiB in a release build). Two host
/// settings change that. With transparent huge pages set to `always`, the
/// touched top of the stack can be backed by 2 MiB pages. With strict
/// overcommit (`vm.overcommit_memory=2`), the whole reservation counts against
/// the commit limit.
///
/// It is defined as reverie-process's clone stack,
/// [`CHILD_STACK_SIZE`](reverie::process::CHILD_STACK_SIZE), 16 MiB: an
/// embedder that runs the KVM backend in a reverie-process container polls a
/// run's first process on that stack, which needs as much as these threads,
/// so one number sizes both. `RUST_MIN_STACK` can raise these threads (see
/// [`stack_bytes`]) but not that stack, so a Tool that needs more than 16 MiB
/// on its first process needs this constant raised.
pub const KVM_SUPERVISOR_THREAD_STACK_BYTES: usize = reverie::process::CHILD_STACK_SIZE;

/// The stack size to spawn a supervisor thread with
/// (`std::thread::Builder::stack_size`).
///
/// It is the larger of [`KVM_SUPERVISOR_THREAD_STACK_BYTES`] and
/// `RUST_MIN_STACK`, read once, as Rust's standard library reads it. An
/// explicit size replaces `RUST_MIN_STACK` for the thread it is given to, so
/// taking the larger keeps that variable able to raise the stack for a Tool
/// that needs more, and never lets it shrink the stack below what the backend
/// needs.
pub fn stack_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| stack_bytes_for(std::env::var_os("RUST_MIN_STACK").as_deref()))
}

/// A thread builder with [`stack_bytes`] of stack, for a host thread of the
/// KVM backend.
///
/// Outside tests, reverie-kvm-core, reverie-kvm and reverie-linuxemu make
/// every Rust thread from one of these builders (see the module
/// documentation).
// The one place the thread rule (each crate's clippy.toml) lets a builder be
// made and sized.
#[allow(clippy::disallowed_methods)]
pub fn builder() -> std::thread::Builder {
    std::thread::Builder::new().stack_size(stack_bytes())
}

/// [`stack_bytes`] for a given `RUST_MIN_STACK` value. As in the standard
/// library, a value that is not a decimal byte count is ignored.
fn stack_bytes_for(rust_min_stack: Option<&OsStr>) -> usize {
    rust_min_stack
        .and_then(|value| value.to_str()?.parse::<usize>().ok())
        .map_or(KVM_SUPERVISOR_THREAD_STACK_BYTES, |bytes| {
            bytes.max(KVM_SUPERVISOR_THREAD_STACK_BYTES)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_min_stack_can_raise_the_supervisor_stack_but_not_lower_it() {
        let size = |value: Option<&str>| stack_bytes_for(value.map(OsStr::new));
        assert_eq!(size(None), KVM_SUPERVISOR_THREAD_STACK_BYTES);
        assert_eq!(size(Some("33554432")), 32 << 20);
        assert_eq!(size(Some("1048576")), KVM_SUPERVISOR_THREAD_STACK_BYTES);
        assert_eq!(size(Some("")), KVM_SUPERVISOR_THREAD_STACK_BYTES);
        assert_eq!(size(Some("16M")), KVM_SUPERVISOR_THREAD_STACK_BYTES);
    }

    #[test]
    fn a_supervisor_thread_gets_at_least_the_supervisor_stack() {
        let handle = builder()
            .name("supervisor-stack-test".to_owned())
            .spawn(|| {
                // SAFETY: pthread_getattr_np initializes `attr`, which is
                // destroyed before this returns.
                unsafe {
                    let mut attr = std::mem::zeroed::<libc::pthread_attr_t>();
                    assert_eq!(libc::pthread_getattr_np(libc::pthread_self(), &mut attr), 0);
                    let mut size = 0;
                    assert_eq!(libc::pthread_attr_getstacksize(&attr, &mut size), 0);
                    libc::pthread_attr_destroy(&mut attr);
                    (std::thread::current().name().map(str::to_owned), size)
                }
            })
            .unwrap();
        let (name, size) = handle.join().unwrap();
        assert_eq!(name.as_deref(), Some("supervisor-stack-test"));
        assert!(
            size >= KVM_SUPERVISOR_THREAD_STACK_BYTES,
            "a supervisor thread got {size} bytes of stack"
        );
    }
}
