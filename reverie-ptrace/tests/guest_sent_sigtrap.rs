/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A SIGTRAP that a guest sends (`raise`, `kill`, `sigqueue`) is delivered as
//! Linux delivers it. Before, Reverie resumed every SIGTRAP stop that none of
//! its own mechanisms claimed without delivering the signal, so a guest that
//! raised SIGTRAP to die ran on: a gtest death test whose statement ends in
//! `raise(SIGTRAP)` then never died, and its parent waited for it forever.
//!
//! Both observables are checked for each sender: a handler runs once and sees
//! the sender's `si_code`, and with the default disposition the guest dies of
//! SIGTRAP rather than running on.

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

/// How the guest sends itself SIGTRAP, each with the `si_code` Linux stamps.
#[derive(Debug, Clone, Copy)]
enum Sender {
    /// `raise`, which glibc implements with `tgkill`: `SI_TKILL`.
    Raise,
    /// `kill` of the guest's own process: `SI_USER`.
    Kill,
    /// `sigqueue` to the guest's own process: `SI_QUEUE`.
    Sigqueue,
}

impl Sender {
    /// Sends SIGTRAP to this process; the call returns once the signal is
    /// handled.
    fn send(self) {
        // SAFETY: plain signal-sending calls on this process.
        let ret = unsafe {
            match self {
                Sender::Raise => libc::raise(libc::SIGTRAP),
                Sender::Kill => libc::kill(libc::getpid(), libc::SIGTRAP),
                Sender::Sigqueue => libc::sigqueue(
                    libc::getpid(),
                    libc::SIGTRAP,
                    libc::sigval {
                        sival_ptr: std::ptr::null_mut(),
                    },
                ),
            }
        };
        assert_eq!(ret, 0, "sending SIGTRAP with {self:?}");
    }

    fn si_code(self) -> libc::c_int {
        match self {
            Sender::Raise => libc::SI_TKILL,
            Sender::Kill => libc::SI_USER,
            Sender::Sigqueue => libc::SI_QUEUE,
        }
    }
}

/// The guest's handler runs once for the SIGTRAP it sent, with the sender's
/// `si_code`, and the guest continues after the call, as it does natively.
#[test_case(Sender::Raise; "raise")]
#[test_case(Sender::Kill; "kill")]
#[test_case(Sender::Sigqueue; "sigqueue")]
fn a_guest_sent_sigtrap_reaches_the_guests_handler(sender: Sender) {
    reverie_ptrace::testing::check_fn::<PassthroughTool, _>(move || {
        // SAFETY: installs a handler for the signal this thread sends next.
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
        sender.send();
        assert_eq!(
            TRAP_HITS.load(Ordering::SeqCst),
            1,
            "the guest's SIGTRAP handler must run once for its {sender:?}"
        );
        assert_eq!(
            TRAP_CODE.load(Ordering::SeqCst),
            sender.si_code(),
            "the handler must see the sender's si_code"
        );
    });
}

/// With the default disposition the SIGTRAP kills the guest. An exit with
/// status 99 is the guest running on past the signal it sent.
#[test_case(Sender::Raise; "raise")]
#[test_case(Sender::Kill; "kill")]
#[test_case(Sender::Sigqueue; "sigqueue")]
fn an_unhandled_guest_sent_sigtrap_kills_the_guest(sender: Sender) {
    let (output, _) = reverie_ptrace::testing::test_fn::<PassthroughTool, _>(move || {
        refuse_core_files();
        sender.send();
        std::process::exit(99);
    })
    .unwrap();
    match output.status {
        ExitStatus::Signaled(Signal::SIGTRAP, _) => {}
        ExitStatus::Exited(99) => {
            panic!("the guest ran on past the SIGTRAP it sent with {sender:?}")
        }
        other => panic!("expected death by SIGTRAP, got {other:?}"),
    }
}

/// A SIGTRAP one process sends another kills the target, whose default action
/// it is, as on Linux. The target waits in `read` on a pipe; the sender's
/// `kill` reaches it there, and the sender then closes the pipe, so a target
/// that never got the signal exits 0 instead of hanging. This Tool passes
/// every syscall through with `tail_inject`, so it never enters the two
/// windows where a sent SIGTRAP is still taken for the step's own trap (a
/// syscall skip, a private injection's `syscall`; see task.rs and
/// https://github.com/rrnewton/hermit/issues/4555).
#[test]
fn a_sigtrap_from_another_process_kills_its_target() {
    reverie_ptrace::testing::check_fn::<PassthroughTool, _>(|| {
        let mut fds = [0; 2];
        // SAFETY: plain pipe, fork, kill and wait calls; the child only reads
        // and exits.
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            let child = libc::fork();
            assert!(child >= 0, "fork");
            if child == 0 {
                refuse_core_files();
                libc::close(fds[1]);
                let mut byte = 0u8;
                libc::read(fds[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
            libc::close(fds[0]);
            // Let the child reach its `read`; a signal sent sooner kills it
            // just the same.
            libc::usleep(50_000);
            assert_eq!(libc::kill(child, libc::SIGTRAP), 0);
            libc::close(fds[1]);
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert!(
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTRAP,
                "the target must die of the SIGTRAP it was sent, status {status:#x}"
            );
        }
    });
}
