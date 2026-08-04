/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Backend-agnostic driver core for the in-guest Reverie tool hosts.
//!
//! The e9patch and liteinst backends both host a concrete Reverie
//! [`Tool`](reverie::Tool) in the guest address space and drive its `async`
//! handlers to completion with a
//! no-op waker (there is no async executor inside a `SIGSYS`-driven guest). That
//! driver — the poll loop, the tail-injection rendezvous, and the syscall
//! *restart* protocol required by Detcore's `wait4` scheduler poll — was
//! previously written twice, once per backend. This module factors the part
//! that does **not** depend on either backend's concrete syscall-event or
//! `Guest` type so it is written and reviewed **once**.
//!
//! # What lives here
//!
//! * [`TailResult`] / [`TailAction`] / [`SyscallOutcome`] — the async-signal-safe
//!   rendezvous a `tail_inject`/`inject` future uses to hand a result (or an
//!   exit / fork-child transition) back to the synchronous driver.
//! * [`drive_ready`] — poll a `Future` to completion with a no-op waker.
//! * [`drive_syscall`] — poll a single Tool `handle_syscall_event` future,
//!   consulting the [`TailResult`] when it parks on a tail inject.
//! * [`drive_tool_syscall`] — the full per-syscall loop, carrying the
//!   **`ERESTARTSYS` restart protocol** (see below). This is the piece the two
//!   backends must share so the protocol cannot drift between them.
//!
//! # The `ERESTARTSYS` restart protocol (Reverie #362)
//!
//! A Tool such as Detcore uses `wait4` as a *restartable* scheduler poll: it
//! returns `ERESTARTSYS` to mean "re-run me once a sibling has made progress".
//! Under the ptrace backend the kernel's syscall-restart frame consumes this
//! private errno transparently. An in-guest `SIGSYS` dispatcher writes the
//! syscall result directly and has no such frame, so it must repeat the Tool
//! callback itself; otherwise the private `ERESTARTSYS` (512) leaks out as an
//! application-visible errno. [`drive_tool_syscall`] owns that loop so both
//! ld-preload backends inherit identical semantics.
//!
//! # Not yet here (deferred to the wiring increments)
//!
//! This module is the shared *driver*; it is intentionally **not wired** to any
//! backend yet, and each backend still carries its own copy of this logic. The
//! backend seam traits (`HostSyscallEvent`, `HostBackend`, and the slow-path
//! counter) are co-designed with the first backend that adopts the driver,
//! where a real implementor validates their shape. When that seam lands, the
//! host-backend's slow-path counter accessor must be **non-`Option`** so a
//! converging backend cannot silently drop per-path (fastpath vs slowpath)
//! counts — that invariant is a hard requirement, recorded here so the wiring
//! increment honors it.

use core::future::Future;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use core::task::Context;
use core::task::Poll;
use core::task::Waker;

use reverie::Error;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;

const TAIL_NONE: u8 = 0;
const TAIL_RESULT: u8 = 1;
const TAIL_EXIT: u8 = 2;
const TAIL_FORK_CHILD: u8 = 3;

/// Poll a `Future` to completion with a no-op waker.
///
/// The in-guest host has no async executor: every Tool handler is expected to
/// make progress on each poll (blocking work happens through synchronous
/// trusted syscalls / RPC, not by yielding to a runtime). A handler that parks
/// waiting on an unrelated executor would spin here forever, by design — see
/// [`drive_syscall`] for the tail-inject rendezvous that lets a handler hand
/// back a result instead of resolving its own future.
pub fn drive_ready<F, T>(future: F) -> T
where
    F: Future<Output = T>,
{
    let mut future = core::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

/// The resolved outcome of driving a single Tool syscall future.
pub enum SyscallOutcome {
    /// The future resolved to a syscall result (`Ok`) or a Tool error (`Err`).
    Return(Result<i64, Error>),
    /// The Tool tail-injected a process/thread exit; the host must run the
    /// exit-lifecycle callbacks and perform `number(args)`.
    Exit { number: i64, args: [u64; 6] },
    /// The Tool's injected plain fork returned in the child; the host must
    /// re-seed per-thread state for the child.
    ForkChild {
        parent_tid: Pid,
        parent_pid: Pid,
        child_tid: Pid,
        child_pid: Pid,
    },
}

/// A pending tail transition parked in a [`TailResult`].
enum TailAction {
    Result(i64),
    Exit {
        number: i64,
        args: [u64; 6],
    },
    ForkChild {
        parent_tid: Pid,
        parent_pid: Pid,
        child_tid: Pid,
        child_pid: Pid,
    },
}

/// Poll one Tool `handle_syscall_event` future, consulting `tail` when it parks.
///
/// A `tail_inject` (or a fork/exit inject) resolves the guest's syscall by
/// storing the outcome in `tail` and then returning `Pending` forever. When the
/// future parks, this reads `tail`: if a tail action was staged it is returned
/// as the outcome; otherwise the driver keeps spinning (the handler is expected
/// to make progress on the next poll).
pub fn drive_syscall<F>(future: F, tail: &TailResult) -> SyscallOutcome
where
    F: Future<Output = Result<i64, Error>>,
{
    let mut future = core::pin::pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return SyscallOutcome::Return(value),
            Poll::Pending => match tail.take() {
                Some(TailAction::Result(value)) => {
                    return SyscallOutcome::Return(Ok(value));
                }
                Some(TailAction::Exit { number, args }) => {
                    return SyscallOutcome::Exit { number, args };
                }
                Some(TailAction::ForkChild {
                    parent_tid,
                    parent_pid,
                    child_tid,
                    child_pid,
                }) => {
                    return SyscallOutcome::ForkChild {
                        parent_tid,
                        parent_pid,
                        child_tid,
                        child_pid,
                    };
                }
                None => core::hint::spin_loop(),
            },
        }
    }
}

/// The resolved outcome of driving a subscribed syscall through the Tool,
/// after the shared restart protocol has been applied.
///
/// The host maps each variant onto its own per-backend state: [`Result`] is
/// written into the syscall event; [`Exit`] and [`ForkChild`] run the backend's
/// lifecycle callbacks; [`Fatal`] triggers the backend's fatal path (the fatal
/// *message* is backend-specific, so the error is surfaced rather than logged
/// here).
///
/// [`Result`]: DrivenSyscall::Result
/// [`Exit`]: DrivenSyscall::Exit
/// [`ForkChild`]: DrivenSyscall::ForkChild
/// [`Fatal`]: DrivenSyscall::Fatal
pub enum DrivenSyscall {
    /// A final result to store into the syscall event (already negated for the
    /// errno case).
    Result(i64),
    /// The Tool tail-injected a process/thread exit.
    Exit { number: i64, args: [u64; 6] },
    /// The Tool's injected plain fork returned in the child.
    ForkChild {
        parent_tid: Pid,
        parent_pid: Pid,
        child_tid: Pid,
        child_pid: Pid,
    },
    /// The Tool future returned a non-errno error. The host must invoke its own
    /// fatal path with this error.
    Fatal(Error),
}

/// Drive a subscribed syscall's Tool handler to a terminal outcome, applying
/// the `ERESTARTSYS` restart protocol (Reverie #362).
///
/// The Tool's `handle_syscall_event` future is recreated — by reborrowing
/// `guest` — each time the Tool asks to restart the syscall (Detcore's `wait4`
/// scheduler poll). Taking `tool`/`guest`/`syscall` by reference rather than a
/// caller-supplied `FnMut() -> Future` closure is deliberate: a closure that
/// returned a future borrowing `guest` cannot satisfy `FnMut` (the borrow would
/// escape the closure body), so the restart loop must own the re-invocation.
/// `number` is the subscribed syscall so [`classify_outcome`] can decide — in
/// exactly one place — which syscalls are restartable.
///
/// The restart policy is intentionally narrow: only `wait4` restarts on a
/// private `ERESTARTSYS`. Every other Tool/syscall — including Chaos Tool read
/// injection — preserves an explicit `ERESTARTSYS` result to the guest.
pub fn drive_tool_syscall<T, G>(
    tool: &T,
    guest: &mut G,
    syscall: Syscall,
    number: Sysno,
    tail: &TailResult,
) -> DrivenSyscall
where
    T: Tool,
    G: Guest<T>,
{
    loop {
        // Reborrow `guest` for a fresh future each restart; the future is
        // consumed (and its borrow of `guest` released) inside `drive_syscall`.
        let outcome = drive_syscall(tool.handle_syscall_event(guest, syscall), tail);
        if let Some(driven) = classify_outcome(number, outcome) {
            return driven;
        }
    }
}

/// Map a single driven [`SyscallOutcome`] onto a terminal [`DrivenSyscall`], or
/// `None` when the shared restart protocol requires re-running the Tool callback
/// (a private `ERESTARTSYS` from Detcore's restartable `wait4` poll).
///
/// This isolates the whole restart *policy* in one pure, directly testable
/// place; [`drive_tool_syscall`] owns only the re-invocation loop around it.
fn classify_outcome(number: Sysno, outcome: SyscallOutcome) -> Option<DrivenSyscall> {
    match outcome {
        SyscallOutcome::Return(Ok(value)) => Some(DrivenSyscall::Result(value)),
        SyscallOutcome::Return(Err(error)) => match error.into_errno() {
            // Detcore uses wait4 as a restartable scheduler poll. The ptrace
            // backend consumes this private errno through its kernel restart
            // frame; a SIGSYS dispatcher must repeat the callback itself.
            // Preserve explicit ERESTARTSYS results for other Tools/syscalls.
            Ok(Errno::ERESTARTSYS) if number == Sysno::wait4 => None,
            Ok(errno) => Some(DrivenSyscall::Result(-(errno.into_raw() as i64))),
            Err(error) => Some(DrivenSyscall::Fatal(error)),
        },
        SyscallOutcome::Exit { number, args } => Some(DrivenSyscall::Exit { number, args }),
        SyscallOutcome::ForkChild {
            parent_tid,
            parent_pid,
            child_tid,
            child_pid,
        } => Some(DrivenSyscall::ForkChild {
            parent_tid,
            parent_pid,
            child_tid,
            child_pid,
        }),
    }
}

/// Async-signal-safe rendezvous for a parked tail-inject.
///
/// A Tool handler that resolves the guest syscall through `tail_inject` (or an
/// injected fork/exit) stores the outcome here and then returns `Pending`
/// forever; the synchronous driver reads it back in [`drive_syscall`]. All
/// fields are lock-free atomics so the rendezvous is usable from the same
/// async-signal context as the rest of the in-guest host.
#[derive(Default)]
pub struct TailResult {
    action: AtomicU8,
    value: AtomicI64,
    number: AtomicI64,
    args: [AtomicU64; 6],
}

impl TailResult {
    /// Stage a plain syscall result for the driver to return.
    pub fn set_result(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
        self.action.store(TAIL_RESULT, Ordering::Release);
    }

    /// Stage a tail-injected process/thread exit (`number(args)`).
    pub fn set_exit(&self, number: i64, args: [u64; 6]) {
        self.number.store(number, Ordering::Relaxed);
        for (destination, value) in self.args.iter().zip(args) {
            destination.store(value, Ordering::Relaxed);
        }
        self.action.store(TAIL_EXIT, Ordering::Release);
    }

    /// Stage a fork-child transition observed after an injected plain fork.
    pub fn set_fork_child(&self, parent_tid: Pid, parent_pid: Pid, child_tid: Pid, child_pid: Pid) {
        self.number
            .store(i64::from(parent_tid.as_raw()), Ordering::Relaxed);
        self.value
            .store(i64::from(parent_pid.as_raw()), Ordering::Relaxed);
        self.args[0].store(child_tid.as_raw() as u64, Ordering::Relaxed);
        self.args[1].store(child_pid.as_raw() as u64, Ordering::Relaxed);
        self.action.store(TAIL_FORK_CHILD, Ordering::Release);
    }

    /// Consume any staged action, resetting the rendezvous to empty.
    fn take(&self) -> Option<TailAction> {
        match self.action.swap(TAIL_NONE, Ordering::AcqRel) {
            TAIL_RESULT => Some(TailAction::Result(self.value.load(Ordering::Relaxed))),
            TAIL_EXIT => Some(TailAction::Exit {
                number: self.number.load(Ordering::Relaxed),
                args: core::array::from_fn(|index| self.args[index].load(Ordering::Relaxed)),
            }),
            TAIL_FORK_CHILD => Some(TailAction::ForkChild {
                parent_tid: Pid::from_raw(self.number.load(Ordering::Relaxed) as i32),
                parent_pid: Pid::from_raw(self.value.load(Ordering::Relaxed) as i32),
                child_tid: Pid::from_raw(self.args[0].load(Ordering::Relaxed) as i32),
                child_pid: Pid::from_raw(self.args[1].load(Ordering::Relaxed) as i32),
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_ready_polls_to_completion() {
        assert_eq!(drive_ready(async { 42_i64 }), 42);
    }

    #[test]
    fn drive_syscall_returns_a_ready_result() {
        let tail = TailResult::default();
        match drive_syscall(async { Ok::<i64, Error>(7) }, &tail) {
            SyscallOutcome::Return(Ok(value)) => assert_eq!(value, 7),
            _ => panic!("expected a ready Ok result"),
        }
    }

    #[test]
    fn drive_syscall_reads_a_parked_tail_result() {
        let tail = TailResult::default();
        tail.set_result(11);
        match drive_syscall(core::future::pending::<Result<i64, Error>>(), &tail) {
            SyscallOutcome::Return(Ok(value)) => assert_eq!(value, 11),
            _ => panic!("expected the parked tail result"),
        }
    }

    #[test]
    fn drive_syscall_reads_a_parked_exit() {
        let tail = TailResult::default();
        tail.set_exit(libc::SYS_exit_group, [3, 0, 0, 0, 0, 0]);
        match drive_syscall(core::future::pending::<Result<i64, Error>>(), &tail) {
            SyscallOutcome::Exit { number, args } => {
                assert_eq!(number, libc::SYS_exit_group);
                assert_eq!(args[0], 3);
            }
            _ => panic!("expected the parked exit"),
        }
    }

    #[test]
    fn tail_result_round_trips_a_fork_child() {
        let tail = TailResult::default();
        tail.set_fork_child(
            Pid::from_raw(10),
            Pid::from_raw(11),
            Pid::from_raw(12),
            Pid::from_raw(13),
        );
        match tail.take() {
            Some(TailAction::ForkChild {
                parent_tid,
                parent_pid,
                child_tid,
                child_pid,
            }) => {
                assert_eq!(parent_tid.as_raw(), 10);
                assert_eq!(parent_pid.as_raw(), 11);
                assert_eq!(child_tid.as_raw(), 12);
                assert_eq!(child_pid.as_raw(), 13);
            }
            _ => panic!("expected a fork-child action"),
        }
        // The rendezvous is empty after a take.
        assert!(tail.take().is_none());
    }

    // The restart *policy* lives in `classify_outcome`; `drive_tool_syscall`'s
    // signature (`tool`/`guest`/`syscall` by reference) needs a real Tool+Guest
    // to exercise, so its restart loop is verified through this pure helper.

    #[test]
    fn classify_outcome_returns_a_ready_result() {
        match classify_outcome(Sysno::read, SyscallOutcome::Return(Ok(5))) {
            Some(DrivenSyscall::Result(value)) => assert_eq!(value, 5),
            _ => panic!("expected a driven result"),
        }
    }

    #[test]
    fn classify_outcome_restarts_wait4_on_erestartsys() {
        // A private ERESTARTSYS from wait4 asks the driver to re-run the
        // callback: no terminal outcome, so the loop restarts.
        let outcome = SyscallOutcome::Return(Err(Error::from(Errno::ERESTARTSYS)));
        assert!(classify_outcome(Sysno::wait4, outcome).is_none());
    }

    #[test]
    fn classify_outcome_preserves_erestartsys_for_non_wait4() {
        let outcome = SyscallOutcome::Return(Err(Error::from(Errno::ERESTARTSYS)));
        match classify_outcome(Sysno::read, outcome) {
            Some(DrivenSyscall::Result(value)) => {
                assert_eq!(value, -(Errno::ERESTARTSYS.into_raw() as i64));
            }
            _ => panic!("expected ERESTARTSYS surfaced to the guest"),
        }
    }

    #[test]
    fn classify_outcome_surfaces_an_errno() {
        let outcome = SyscallOutcome::Return(Err(Error::from(Errno::ENOSYS)));
        match classify_outcome(Sysno::read, outcome) {
            Some(DrivenSyscall::Result(value)) => {
                assert_eq!(value, -(Errno::ENOSYS.into_raw() as i64));
            }
            _ => panic!("expected the errno negated into the result"),
        }
    }

    #[test]
    fn classify_outcome_passes_through_an_exit() {
        let outcome = SyscallOutcome::Exit {
            number: libc::SYS_exit_group,
            args: [3, 0, 0, 0, 0, 0],
        };
        match classify_outcome(Sysno::exit_group, outcome) {
            Some(DrivenSyscall::Exit { number, args }) => {
                assert_eq!(number, libc::SYS_exit_group);
                assert_eq!(args[0], 3);
            }
            _ => panic!("expected the exit passed through"),
        }
    }

    #[test]
    fn classify_outcome_passes_through_a_fork_child() {
        let outcome = SyscallOutcome::ForkChild {
            parent_tid: Pid::from_raw(1),
            parent_pid: Pid::from_raw(2),
            child_tid: Pid::from_raw(3),
            child_pid: Pid::from_raw(4),
        };
        match classify_outcome(Sysno::clone, outcome) {
            Some(DrivenSyscall::ForkChild { child_pid, .. }) => assert_eq!(child_pid.as_raw(), 4),
            _ => panic!("expected a fork-child transition"),
        }
    }
}
