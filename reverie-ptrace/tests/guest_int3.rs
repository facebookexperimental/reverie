/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest that executes its own `int3` gets the SIGTRAP Linux raises for it
//! (<https://github.com/rrnewton/hermit/issues/1715>). Before, Reverie resumed
//! every SIGTRAP that none of its own mechanisms claimed without delivering
//! it, so the guest ran past its own breakpoint: no handler ran, and a guest
//! with the default disposition exited normally where Linux kills it.
//!
//! Both observables are checked, each with the case it must not be confused
//! with: a handler runs and sees Linux's `si_code` (`SI_KERNEL`), and with no
//! handler the guest dies of SIGTRAP rather than running on.

#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::Guest;
use reverie::Signal;
use reverie::Tool;
use reverie::syscalls::Syscall;
use test_case::test_case;

/// Passes every syscall through, so the test observes the backend's signal
/// handling rather than a Tool's.
#[derive(Debug, Default, Clone)]
struct PassthroughTool;

#[reverie::tool]
impl Tool for PassthroughTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(syscall).await
    }
}

/// `SI_KERNEL`, which `libc` does not export: Linux's `do_int3_user` raises the
/// SIGTRAP of an `int3` with `force_sig`, which stamps it.
const SI_KERNEL: libc::c_int = 0x80;

static TRAP_HITS: AtomicUsize = AtomicUsize::new(0);
static TRAP_CODE: AtomicI32 = AtomicI32::new(i32::MIN);

extern "C" fn on_trap(
    _signum: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let code = unsafe { (*info).si_code };
    TRAP_CODE.store(code, Ordering::SeqCst);
    TRAP_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Sets the soft `RLIMIT_CORE` to 1 where the hard limit allows: the kernel
/// writes no core at that limit (see `tests/fatal_signal_exit_hook.rs`).
fn refuse_core_files() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain rlimit calls on this process.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut limit), 0);
        limit.rlim_cur = limit.rlim_max.min(1);
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
    }
}

/// The two encodings of the trap, which Linux reports alike.
#[derive(Debug, Clone, Copy)]
enum Encoding {
    /// `int3`, `0xcc`.
    Int3,
    /// `int $3`, `0xcd 0x03`.
    Int3Long,
}

impl Encoding {
    /// Executes the trap.
    fn trap(self) {
        // SAFETY: raises `#BP`; with a handler installed, execution continues
        // after the instruction, as natively.
        match self {
            Encoding::Int3 => unsafe { std::arch::asm!("int3") },
            Encoding::Int3Long => unsafe { std::arch::asm!(".byte 0xcd, 0x03") },
        }
    }
}

/// The guest's handler runs once for its `int3`, with `SI_KERNEL`, and the
/// guest continues after the instruction, as it does natively.
#[test_case(Encoding::Int3; "int3")]
#[test_case(Encoding::Int3Long; "int 3")]
fn a_guest_int3_reaches_the_guests_handler(encoding: Encoding) {
    reverie_ptrace::testing::check_fn::<PassthroughTool, _>(move || {
        // SAFETY: installs a handler for the signal this thread raises next.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_trap as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()),
                0
            );
        }
        encoding.trap();
        assert_eq!(
            TRAP_HITS.load(Ordering::SeqCst),
            1,
            "the guest's SIGTRAP handler must run once for its {encoding:?}"
        );
        assert_eq!(
            TRAP_CODE.load(Ordering::SeqCst),
            SI_KERNEL,
            "the handler must see Linux's si_code for an int3"
        );
    });
}

/// With the default disposition the `int3` kills the guest with SIGTRAP. An
/// exit with status 99 is the guest running past its own breakpoint.
#[test_case(Encoding::Int3; "int3")]
#[test_case(Encoding::Int3Long; "int 3")]
fn an_unhandled_guest_int3_kills_the_guest(encoding: Encoding) {
    let (output, _) = reverie_ptrace::testing::test_fn::<PassthroughTool, _>(move || {
        refuse_core_files();
        encoding.trap();
        std::process::exit(99);
    })
    .unwrap();
    match output.status {
        ExitStatus::Signaled(Signal::SIGTRAP, _) => {}
        ExitStatus::Exited(99) => panic!(
            "the guest ran past its own {encoding:?} (https://github.com/rrnewton/hermit/issues/1715)"
        ),
        other => panic!("expected death by SIGTRAP, got {other:?}"),
    }
}
