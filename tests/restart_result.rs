/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool that answers a guest syscall with a restart code (`-ERESTART*`)
//! while a signal is pending gets Linux's restart semantics: `-EINTR` or a
//! restart once the signal is delivered, never the raw code.
//!
//! The outcomes are the same on every architecture, though Linux decides
//! them at different points: x86-64 after the tracer's last stop
//! (`handle_signal` and `arch_do_signal_or_restart`,
//! arch/x86/kernel/signal.c:263-281 and :344-361 at v6.12.9), arm64 before
//! its signal-delivery stops (`do_signal`, arch/arm64/kernel/signal.c:1395-1464).
//! A signal the Tool drops is one the tracer suppresses: no handler runs, and
//! the call restarts, `-ERESTART_RESTARTBLOCK` through `restart_syscall`.

#[cfg(all(not(sanitized), test))]
use std::sync::Arc;
#[cfg(all(not(sanitized), test))]
use std::sync::atomic::AtomicI32;
#[cfg(all(not(sanitized), test))]
use std::sync::atomic::Ordering as AtomicOrdering;

#[cfg(all(not(sanitized), test))]
use reverie::Error;
#[cfg(all(not(sanitized), test))]
use reverie::GlobalRPC;
#[cfg(all(not(sanitized), test))]
use reverie::GlobalTool;
#[cfg(all(not(sanitized), test))]
use reverie::Guest;
#[cfg(all(not(sanitized), test))]
use reverie::Pid;
#[cfg(all(not(sanitized), test))]
use reverie::Tool;
#[cfg(all(not(sanitized), test))]
use reverie::UnreportedSignal;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Errno;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Getpid;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Syscall;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallArgs;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallInfo;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Sysno;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Tgkill;
#[cfg(all(not(sanitized), test))]
use serde::Deserialize;
#[cfg(all(not(sanitized), test))]
use serde::Serialize;

/// What the Tool returns for the probe, or for `restart_syscall` or a
/// `ppoll`, once the guest restarted it.
#[cfg(all(not(sanitized), test))]
const RESTARTED: i64 = 4242;

/// The probe: `getppid`, whose arguments Linux ignores, carries the restart
/// code to return (a positive errno), the signal to send first, and how the
/// Tool sends it (`SENT_BY_*`, `HELD_*`), or `CONFIGURE_PPOLL`.
#[cfg(all(not(sanitized), test))]
const PROBE: Sysno = Sysno::getppid;

/// The tracer sends the signal, which stays pending in the kernel.
#[cfg(all(not(sanitized), test))]
const SENT_BY_TRACER: i64 = 0;

/// An injected `tgkill` sends the signal.
#[cfg(all(not(sanitized), test))]
const SENT_BY_INJECTION: i64 = 1;

/// The tracer sends the signal, then the Tool injects a syscall, which the
/// pending signal stops: the signal is then held for the guest's resume.
#[cfg(all(not(sanitized), test))]
const HELD_OVER_INJECTION: i64 = 2;

/// As `HELD_OVER_INJECTION`, and then the tracer sends the signal again to
/// the whole process, where it stays pending: the guest takes both.
#[cfg(all(not(sanitized), test))]
const HELD_AND_PENDING_FOR_THE_PROCESS: i64 = 3;

/// As `HELD_OVER_INJECTION`, and the Tool drops the held signal
/// (`Tool::handle_signal_event` or `Tool::filter_unreported_signal`).
#[cfg(all(not(sanitized), test))]
const HELD_AND_DROPPED: i64 = 4;

/// For `ppoll`: as `HELD_OVER_INJECTION`, and then the tracer sends SIGUSR1,
/// which the guest handles, so that it is pending too.
#[cfg(all(not(sanitized), test))]
const HELD_WITH_SIGUSR1_PENDING: i64 = 5;

/// For `ppoll` or `rt_sigsuspend`: the Tool returns the interrupted
/// injection's own result, with the signal where the injection left it.
#[cfg(all(not(sanitized), test))]
const PLAIN: i64 = 6;

/// For `ppoll`: as `HELD_OVER_INJECTION`, and then an injected
/// `rt_sigprocmask` blocks the held signal (the probe's fifth argument points
/// at the set).
#[cfg(all(not(sanitized), test))]
const HELD_THEN_BLOCKED: i64 = 7;

/// For `ppoll`: the Tool runs the guest's call with a first argument of its
/// own (no descriptors), and returns the interrupted call's result as for
/// `PLAIN`. A restart must then run the guest's call with the guest's first
/// argument.
#[cfg(all(not(sanitized), test))]
const PLAIN_WITH_ANOTHER_FIRST_ARGUMENT: i64 = 8;

/// For the probe: as `HELD_OVER_INJECTION`, and then the tracer sends every
/// realtime signal from 34 to 64, which the guest blocks, so that each stays
/// pending for the thread.
#[cfg(all(not(sanitized), test))]
const HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING: i64 = 9;

/// For `ppoll` of no descriptors: as `PLAIN`, with the Tool's call given a
/// first argument the call never reads (the timeout's address), so the
/// guest sees no difference unless a restart runs with it.
#[cfg(all(not(sanitized), test))]
const PLAIN_WITH_AN_UNREAD_FIRST_ARGUMENT: i64 = 10;

/// As `PLAIN_WITH_AN_UNREAD_FIRST_ARGUMENT`, with the signal sent to the
/// process, and the Tool's answer held until another thread of the guest has
/// taken it (`kill` and the process's shared pending set).
#[cfg(all(not(sanitized), test))]
const TAKEN_BY_ANOTHER_THREAD: i64 = 11;

/// Why this Tool refuses a restart code under a pending temporary mask's
/// restore: the two cases whose Linux outcome it cannot decide.
#[cfg(all(not(sanitized), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Undecidable {
    /// `-ERESTARTSYS` with a handler: the outcome hangs on the handler's
    /// `SA_RESTART`, which procfs does not show.
    ErestartsysWithHandler,
    /// A delivered signal the mask in effect blocks: the kernel would queue
    /// it again rather than deliver it.
    DeliveredSignalBlocked,
}

/// This Tool's refusal of a restart code (`Undecidable`), which ends the run.
#[cfg(all(not(sanitized), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("restart code refused by the test Tool ({reason:?}): {syscall} was answered with {code}")]
struct RestartRefused {
    syscall: Sysno,
    code: Errno,
    reason: Undecidable,
}

/// The probe's arguments are the code, the signal, the mode (fourth
/// argument) and a signal set (fifth) for the thread's next `ppoll` or
/// `rt_sigsuspend`, which the Tool runs itself while the tracer sends the
/// signal, and answers with the code (or, for `PLAIN`, the call's result).
#[cfg(all(not(sanitized), test))]
const CONFIGURE_PPOLL: i64 = 100;

/// The Tool's global state, which holds nothing. Its configuration says
/// whether the Tool declares serialized execution
/// (`Tool::enforces_serialized_execution`), under which the backend runs a
/// mask-swapping injection between syscall stops on aarch64.
#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default)]
struct Global;

#[cfg(all(not(sanitized), test))]
#[reverie::global_tool]
impl GlobalTool for Global {
    type Request = ();
    type Response = ();
    type Config = bool;

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct RestartResult {
    /// A signal the Tool drops once, or 0.
    drop_next: Arc<AtomicI32>,
}

#[cfg(all(not(sanitized), test))]
impl RestartResult {
    fn drops(&self, signal: i32) -> bool {
        self.drop_next
            .compare_exchange(signal, 0, AtomicOrdering::SeqCst, AtomicOrdering::SeqCst)
            .is_ok()
    }
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Serialize, Deserialize)]
struct ThreadState {
    interrupted: bool,
    /// The first argument of the guest's `ppoll` or `rt_sigsuspend` the Tool
    /// interrupted: a call with it is that call restarted, any other a new
    /// one (such as a handler's), which is run.
    interrupted_arg0: Option<usize>,
    /// The code, signal, mode and set for the next `ppoll` or
    /// `rt_sigsuspend` (`CONFIGURE_PPOLL`).
    ppoll: Option<(i32, i32, i64, usize)>,
}

#[cfg(all(not(sanitized), test))]
#[reverie::tool]
impl Tool for RestartResult {
    type GlobalState = Global;
    type ThreadState = ThreadState;

    /// As configured: only the tests of the syscall-stop transport declare
    /// it. The one with two guest threads breaks the contract on purpose.
    fn enforces_serialized_execution(serialized: &bool) -> bool {
        *serialized
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let interrupted = guest.thread_state().interrupted;
        match syscall.number() {
            // The kernel's own restart block describes no call of this Tool's.
            Sysno::restart_syscall => {
                if interrupted {
                    return Ok(RESTARTED);
                }
            }
            Sysno::ppoll | Sysno::rt_sigsuspend
                if interrupted
                    && guest
                        .thread_state()
                        .interrupted_arg0
                        .is_none_or(|arg0| arg0 == syscall.into_parts().1.arg0) =>
            {
                return Ok(RESTARTED);
            }
            Sysno::ppoll | Sysno::rt_sigsuspend if interrupted => {
                return guest.tail_inject(syscall).await;
            }
            Sysno::ppoll | Sysno::rt_sigsuspend => {
                if let Some((code, sig, mode, set)) = guest.thread_state_mut().ppoll.take() {
                    guest.thread_state_mut().interrupted = true;
                    guest.thread_state_mut().interrupted_arg0 = Some(syscall.into_parts().1.arg0);
                    return self
                        .interrupt_ppoll(guest, syscall, code, sig, mode, set)
                        .await;
                }
                return guest.tail_inject(syscall).await;
            }
            nr if nr != PROBE => return guest.tail_inject(syscall).await,
            _ => {}
        }
        let (_, args) = syscall.into_parts();
        let (code, sig, sent_by) = (args.arg0 as i32, args.arg1 as i32, args.arg2 as i64);
        if sent_by == CONFIGURE_PPOLL {
            guest.thread_state_mut().ppoll = Some((code, sig, args.arg3 as i64, args.arg4));
            return Ok(0);
        }
        if interrupted {
            return Ok(RESTARTED);
        }
        guest.thread_state_mut().interrupted = true;
        let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
        if sent_by == SENT_BY_INJECTION {
            guest
                .inject(Tgkill::new().with_tgid(pid).with_tid(tid).with_sig(sig))
                .await?;
        } else {
            // SAFETY: tgkill takes three integers and touches no memory.
            let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, sig) };
            assert_eq!(sent, 0, "tgkill from the tracer");
        }
        if matches!(
            sent_by,
            HELD_OVER_INJECTION
                | HELD_AND_PENDING_FOR_THE_PROCESS
                | HELD_AND_DROPPED
                | HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING
        ) {
            assert!(
                guest.inject(Getpid::new()).await.is_err(),
                "the pending signal interrupts the injection, and is held"
            );
        }
        if sent_by == HELD_AND_PENDING_FOR_THE_PROCESS {
            // SAFETY: kill takes two integers and touches no memory.
            assert_eq!(unsafe { libc::kill(pid, sig) }, 0, "kill from the tracer");
        }
        if sent_by == HELD_AND_DROPPED {
            self.drop_next.store(sig, AtomicOrdering::SeqCst);
        }
        if sent_by == HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING {
            for realtime in 34..=64 {
                // SAFETY: tgkill takes three integers and touches no memory.
                let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, realtime) };
                assert_eq!(sent, 0, "tgkill {realtime} from the tracer");
            }
        }
        Err(Errno::new(code).into())
    }

    /// The outcome Linux's `do_signal` takes for a restart code under a
    /// pending temporary mask's restore, decided here because the backend
    /// and Reverie's default decide none (arch/arm64/kernel/signal.c:1395-1464
    /// at v6.12.9): `get_signal` takes the delivered signal, then, while none
    /// has a handler, the pending signals the mask in effect lets through.
    /// With a handler `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK` give
    /// `-EINTR` and `ERESTARTNOINTR` restarts; with none every code restarts.
    /// `ERESTARTSYS` with a handler (it hangs on `SA_RESTART`, which procfs
    /// does not show) and a delivered signal the mask in effect blocks are
    /// refused, with this Tool's own reason (`RestartRefused`).
    async fn resolve_restart_under_pending_mask_restore<R: reverie::GlobalRPC<Global>>(
        &self,
        _rpc: &R,
        facts: reverie::PendingMaskRestore,
    ) -> Result<reverie::MaskRestoreOutcome, Error> {
        let bit = |signal: i32| 1u64 << (signal - 1);
        let refuse = |reason| {
            Err(Error::Tool(anyhow::Error::new(RestartRefused {
                syscall: facts.syscall,
                code: facts.code,
                reason,
            })))
        };
        let runs_a_handler = |signal: i32| {
            signal != libc::SIGKILL && signal != libc::SIGSTOP && facts.caught & bit(signal) != 0
        };
        if facts
            .delivered
            .is_some_and(|signal| facts.mask_in_effect & bit(signal) != 0)
        {
            return refuse(Undecidable::DeliveredSignalBlocked);
        }
        let handler_runs = facts.delivered.is_some_and(runs_a_handler)
            || (1..=64)
                .filter(|&signal| facts.pending & !facts.mask_in_effect & bit(signal) != 0)
                .any(runs_a_handler);
        match facts.code {
            Errno::ERESTARTNOHAND | Errno::ERESTART_RESTARTBLOCK if handler_runs => {
                Ok(reverie::MaskRestoreOutcome::Interrupted { handler_runs })
            }
            Errno::ERESTARTSYS if handler_runs => refuse(Undecidable::ErestartsysWithHandler),
            _ => Ok(reverie::MaskRestoreOutcome::Restart { handler_runs }),
        }
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        _guest: &mut T,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        Ok((!self.drops(signal as i32)).then_some(signal))
    }

    async fn filter_unreported_signal<R: GlobalRPC<Self::GlobalState>>(
        &self,
        _rpc: &R,
        signal: UnreportedSignal,
    ) -> bool {
        !self.drops(signal.number())
    }
}

#[cfg(all(not(sanitized), test))]
impl RestartResult {
    /// Runs the guest's `ppoll` or `rt_sigsuspend` while the tracer sends
    /// `sig` 200 ms in, which the guest blocks and the call's temporary mask
    /// lets through: the call returns `-ERESTARTNOHAND` with that mask's
    /// restore pending. For `PLAIN` the Tool returns that result. Otherwise
    /// the next injection takes the still pending signal, which is held for
    /// the guest's resume (dropped for `HELD_AND_DROPPED`), and the Tool
    /// answers with `code`.
    async fn interrupt_ppoll<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
        code: i32,
        sig: i32,
        mode: i64,
        set: usize,
    ) -> Result<i64, Error> {
        let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
        let to_the_process = mode == TAKEN_BY_ANOTHER_THREAD;
        let sender = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if to_the_process {
                // SAFETY: kill takes two integers and touches no memory.
                unsafe { libc::kill(pid, sig) as libc::c_long }
            } else {
                // SAFETY: tgkill takes three integers and touches no memory.
                unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, sig) }
            }
        });
        let (nr, args) = syscall.into_parts();
        let syscall = match mode {
            PLAIN_WITH_ANOTHER_FIRST_ARGUMENT => Syscall::from_raw(
                nr,
                SyscallArgs::new(0, 0, args.arg2, args.arg3, args.arg4, args.arg5),
            ),
            PLAIN_WITH_AN_UNREAD_FIRST_ARGUMENT | TAKEN_BY_ANOTHER_THREAD => Syscall::from_raw(
                nr,
                SyscallArgs::new(
                    args.arg2, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                ),
            ),
            _ => syscall,
        };
        let injected = guest.inject(syscall).await;
        assert_eq!(sender.join().unwrap(), 0, "the signal from the tracer");
        if to_the_process {
            wait_until_taken_from_the_process(pid, sig).await;
        }
        if matches!(
            mode,
            PLAIN
                | PLAIN_WITH_ANOTHER_FIRST_ARGUMENT
                | PLAIN_WITH_AN_UNREAD_FIRST_ARGUMENT
                | TAKEN_BY_ANOTHER_THREAD
        ) {
            return injected.map_err(Into::into);
        }
        assert!(injected.is_err(), "the signal interrupts the injected call");
        assert!(
            guest.inject(Getpid::new()).await.is_err(),
            "the pending signal interrupts the next injection, and is held"
        );
        if mode == HELD_AND_DROPPED {
            self.drop_next.store(sig, AtomicOrdering::SeqCst);
        }
        if mode == HELD_WITH_SIGUSR1_PENDING {
            // SAFETY: tgkill takes three integers and touches no memory.
            let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) };
            assert_eq!(sent, 0, "tgkill from the tracer");
        }
        if mode == HELD_THEN_BLOCKED {
            let block = Syscall::from_raw(
                Sysno::rt_sigprocmask,
                SyscallArgs::new(libc::SIG_BLOCK as usize, set, 0, 8, 0, 0),
            );
            assert_eq!(guest.inject(block).await, Ok(0), "block the held signal");
        }
        Err(Errno::new(code).into())
    }
}

/// Waits until `sig` has left the shared pending set of process `pid`
/// (`ShdPnd` in its procfs status), taken by one of its threads.
#[cfg(all(not(sanitized), test))]
async fn wait_until_taken_from_the_process(pid: i32, sig: i32) {
    let bit = 1u64 << (sig - 1);
    for _ in 0..500 {
        let status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read the status");
        let shared = status
            .lines()
            .find_map(|line| line.strip_prefix("ShdPnd:"))
            .map(|hex| u64::from_str_radix(hex.trim(), 16).expect("ShdPnd is hexadecimal"))
            .expect("the status has ShdPnd");
        if shared & bit == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("signal {sig} still pending for process {pid} after 5 s");
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use nix::sys::signal::SaFlags;
    use nix::sys::signal::SigAction;
    use nix::sys::signal::SigHandler;
    use nix::sys::signal::SigSet;
    use nix::sys::signal::Signal;
    use nix::sys::signal::sigaction;
    use reverie_ptrace::testing::check_fn;
    use reverie_ptrace::testing::check_fn_with_config;
    use test_case::test_case;

    use super::*;

    // The restart codes (include/linux/errno.h), which libc does not name.
    const ERESTARTSYS: i32 = 512;
    const ERESTARTNOINTR: i32 = 513;
    const ERESTARTNOHAND: i32 = 514;
    const ERESTART_RESTARTBLOCK: i32 = 516;

    static HANDLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_signal(_: libc::c_int) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    /// What the handler's own `ppoll` returned (`on_signal_polling`).
    static HANDLER_POLL: AtomicI64 = AtomicI64::new(i64::MIN);

    /// Runs a `ppoll` of its own through the same `syscall` wrapper, so the
    /// same `svc`, as the guest's interrupted call: one ignored descriptor and
    /// a zero timeout, which returns 0 at once.
    extern "C" fn on_signal_polling(_: libc::c_int) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
        let mut ignored = libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ppoll reads one descriptor entry and the timeout.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut ignored as *mut libc::pollfd,
                1,
                &zero as *const libc::timespec,
                std::ptr::null::<libc::sigset_t>(),
                std::mem::size_of::<u64>(),
            )
        };
        HANDLER_POLL.store(ret, Ordering::SeqCst);
    }

    /// Handles `sig` under `flags`, or leaves it at its default action
    /// without `flags`.
    fn handle(sig: Signal, flags: Option<SaFlags>) {
        if let Some(flags) = flags {
            let action = SigAction::new(SigHandler::Handler(on_signal), flags, SigSet::empty());
            // SAFETY: the handler only increments an atomic.
            unsafe { sigaction(sig, &action) }.expect("install the handler");
        }
    }

    /// Runs the probe in the guest with `sig` handled under `flags` (or left
    /// at its default action without `flags`), and returns its result and
    /// errno and the number of handler runs.
    fn probe(code: i32, sig: Signal, flags: Option<SaFlags>, sent_by: i64) -> (i64, i32, usize) {
        handle(sig, flags);
        // SAFETY: the probe syscall takes integers and touches no memory.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_getppid,
                code as libc::c_long,
                sig as libc::c_long,
                sent_by as libc::c_long,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        (
            ret,
            if ret == -1 { errno } else { 0 },
            HANDLED.load(Ordering::SeqCst),
        )
    }

    fn check(
        code: i32,
        sig: Signal,
        flags: Option<SaFlags>,
        sent_by: i64,
        want: (i64, i32, usize),
    ) {
        check_fn::<RestartResult, _>(move || {
            let got = probe(code, sig, flags, sent_by);
            assert_eq!(got, want, "(result, errno, handler runs)");
        });
    }

    #[test_case(SENT_BY_TRACER, 1; "sent by the tracer")]
    #[test_case(SENT_BY_INJECTION, 1; "sent by an injection")]
    #[test_case(HELD_OVER_INJECTION, 1; "held over an injection")]
    #[test_case(HELD_AND_PENDING_FOR_THE_PROCESS, 2; "held and pending for the process")]
    fn erestartnohand_with_a_handler_is_eintr(sent_by: i64, runs: usize) {
        let flags = Some(SaFlags::SA_RESTART);
        check(
            ERESTARTNOHAND,
            Signal::SIGUSR1,
            flags,
            sent_by,
            (-1, libc::EINTR, runs),
        );
    }

    #[test_case(SENT_BY_TRACER, 1; "sent by the tracer")]
    #[test_case(SENT_BY_INJECTION, 1; "sent by an injection")]
    #[test_case(HELD_OVER_INJECTION, 1; "held over an injection")]
    #[test_case(HELD_AND_PENDING_FOR_THE_PROCESS, 2; "held and pending for the process")]
    fn erestart_restartblock_with_a_handler_is_eintr(sent_by: i64, runs: usize) {
        let flags = Some(SaFlags::SA_RESTART);
        check(
            ERESTART_RESTARTBLOCK,
            Signal::SIGUSR1,
            flags,
            sent_by,
            (-1, libc::EINTR, runs),
        );
    }

    #[test_case(SENT_BY_TRACER, 1; "sent by the tracer")]
    #[test_case(SENT_BY_INJECTION, 1; "sent by an injection")]
    #[test_case(HELD_OVER_INJECTION, 1; "held over an injection")]
    #[test_case(HELD_AND_PENDING_FOR_THE_PROCESS, 2; "held and pending for the process")]
    fn erestartsys_without_sa_restart_is_eintr(sent_by: i64, runs: usize) {
        let flags = Some(SaFlags::empty());
        check(
            ERESTARTSYS,
            Signal::SIGUSR1,
            flags,
            sent_by,
            (-1, libc::EINTR, runs),
        );
    }

    #[test_case(SENT_BY_TRACER, 1; "sent by the tracer")]
    #[test_case(SENT_BY_INJECTION, 1; "sent by an injection")]
    #[test_case(HELD_OVER_INJECTION, 1; "held over an injection")]
    #[test_case(HELD_AND_PENDING_FOR_THE_PROCESS, 2; "held and pending for the process")]
    fn erestartsys_with_sa_restart_restarts(sent_by: i64, runs: usize) {
        let flags = Some(SaFlags::SA_RESTART);
        check(
            ERESTARTSYS,
            Signal::SIGUSR1,
            flags,
            sent_by,
            (RESTARTED, 0, runs),
        );
    }

    #[test_case(SENT_BY_TRACER, 1; "sent by the tracer")]
    #[test_case(SENT_BY_INJECTION, 1; "sent by an injection")]
    #[test_case(HELD_OVER_INJECTION, 1; "held over an injection")]
    #[test_case(HELD_AND_PENDING_FOR_THE_PROCESS, 2; "held and pending for the process")]
    fn erestartnointr_with_a_handler_restarts(sent_by: i64, runs: usize) {
        let flags = Some(SaFlags::empty());
        check(
            ERESTARTNOINTR,
            Signal::SIGUSR1,
            flags,
            sent_by,
            (RESTARTED, 0, runs),
        );
    }

    /// SIGWINCH's default action ignores it; a traced thread still queues it
    /// and takes it at the resume, with no handler, so every code restarts,
    /// `-ERESTART_RESTARTBLOCK` through `restart_syscall`.
    #[test_case(ERESTARTSYS, SENT_BY_TRACER; "erestartsys sent by the tracer")]
    #[test_case(ERESTARTSYS, SENT_BY_INJECTION; "erestartsys sent by an injection")]
    #[test_case(ERESTARTSYS, HELD_OVER_INJECTION; "erestartsys held over an injection")]
    #[test_case(ERESTARTSYS, HELD_AND_PENDING_FOR_THE_PROCESS; "erestartsys held and pending for the process")]
    #[test_case(ERESTARTNOINTR, SENT_BY_TRACER; "erestartnointr sent by the tracer")]
    #[test_case(ERESTARTNOINTR, SENT_BY_INJECTION; "erestartnointr sent by an injection")]
    #[test_case(ERESTARTNOINTR, HELD_OVER_INJECTION; "erestartnointr held over an injection")]
    #[test_case(ERESTARTNOINTR, HELD_AND_PENDING_FOR_THE_PROCESS; "erestartnointr held and pending for the process")]
    #[test_case(ERESTARTNOHAND, SENT_BY_TRACER; "erestartnohand sent by the tracer")]
    #[test_case(ERESTARTNOHAND, SENT_BY_INJECTION; "erestartnohand sent by an injection")]
    #[test_case(ERESTARTNOHAND, HELD_OVER_INJECTION; "erestartnohand held over an injection")]
    #[test_case(ERESTARTNOHAND, HELD_AND_PENDING_FOR_THE_PROCESS; "erestartnohand held and pending for the process")]
    #[test_case(ERESTART_RESTARTBLOCK, SENT_BY_TRACER; "erestart_restartblock sent by the tracer")]
    #[test_case(ERESTART_RESTARTBLOCK, SENT_BY_INJECTION; "erestart_restartblock sent by an injection")]
    #[test_case(ERESTART_RESTARTBLOCK, HELD_OVER_INJECTION; "erestart_restartblock held over an injection")]
    #[test_case(ERESTART_RESTARTBLOCK, HELD_AND_PENDING_FOR_THE_PROCESS; "erestart_restartblock held and pending for the process")]
    fn without_a_handler_restarts(code: i32, sent_by: i64) {
        check(code, Signal::SIGWINCH, None, sent_by, (RESTARTED, 0, 0));
    }

    /// A held signal the Tool drops runs no handler, as one a tracer
    /// suppresses at its signal-delivery stop, so every code restarts.
    #[test_case(ERESTARTSYS; "erestartsys")]
    #[test_case(ERESTARTNOINTR; "erestartnointr")]
    #[test_case(ERESTARTNOHAND; "erestartnohand")]
    #[test_case(ERESTART_RESTARTBLOCK; "erestart_restartblock")]
    fn a_dropped_signal_restarts(code: i32) {
        let flags = Some(SaFlags::empty());
        check(
            code,
            Signal::SIGUSR1,
            flags,
            HELD_AND_DROPPED,
            (RESTARTED, 0, 0),
        );
    }

    /// A held SIGCONT is delivered as any other signal: its handler runs, and
    /// `-ERESTARTSYS` without `SA_RESTART` is `-EINTR`.
    #[test_case(SENT_BY_TRACER; "sent by the tracer")]
    #[test_case(HELD_OVER_INJECTION; "held over an injection")]
    fn a_sigcont_with_a_handler_is_eintr(sent_by: i64) {
        let flags = Some(SaFlags::empty());
        check(
            ERESTARTSYS,
            Signal::SIGCONT,
            flags,
            sent_by,
            (-1, libc::EINTR, 1),
        );
    }

    /// A SIGSTOP, which no mask blocks, stops the thread on its way back to
    /// the call and runs no handler, so the call restarts once the thread
    /// goes on (`do_signal_stop`, kernel/signal.c).
    #[test_case(ERESTARTSYS, SENT_BY_TRACER; "erestartsys sent by the tracer")]
    #[test_case(ERESTARTNOINTR, SENT_BY_TRACER; "erestartnointr sent by the tracer")]
    #[test_case(ERESTARTNOHAND, SENT_BY_TRACER; "erestartnohand sent by the tracer")]
    #[test_case(ERESTART_RESTARTBLOCK, SENT_BY_TRACER; "erestart_restartblock sent by the tracer")]
    #[test_case(ERESTARTSYS, SENT_BY_INJECTION; "erestartsys sent by an injection")]
    #[test_case(ERESTARTSYS, HELD_OVER_INJECTION; "erestartsys held over an injection")]
    fn a_stop_signal_restarts(code: i32, sent_by: i64) {
        check(code, Signal::SIGSTOP, None, sent_by, (RESTARTED, 0, 0));
    }

    /// Negative: an ordinary error is returned as it is, whatever is
    /// pending; the handler of the pending signal runs.
    #[test_case(libc::EINTR, SENT_BY_TRACER; "eintr sent by the tracer")]
    #[test_case(libc::EINTR, HELD_OVER_INJECTION; "eintr held over an injection")]
    #[test_case(libc::EAGAIN, SENT_BY_TRACER; "eagain sent by the tracer")]
    #[test_case(libc::EAGAIN, HELD_OVER_INJECTION; "eagain held over an injection")]
    fn an_ordinary_error_is_returned_as_it_is(code: i32, sent_by: i64) {
        let flags = Some(SaFlags::SA_RESTART);
        check(code, Signal::SIGUSR1, flags, sent_by, (-1, code, 1));
    }

    /// The guest's raw `ppoll` with no descriptors and a 10 s timeout, under a
    /// temporary mask that lets `sig` through while the thread blocks it, with
    /// `sig` handled under `flags` (default action without). Returns the
    /// result, its errno, the handler runs, and whether `sig` is blocked
    /// again afterwards.
    fn masked_ppoll(
        code: i32,
        sig: Signal,
        flags: Option<SaFlags>,
        mode: i64,
    ) -> (i64, i32, usize, bool) {
        handle(sig, flags);
        SigSet::from(sig).thread_block().expect("block the signal");
        if mode == HELD_WITH_SIGUSR1_PENDING {
            handle(Signal::SIGUSR1, Some(SaFlags::SA_RESTART));
            SigSet::from(Signal::SIGUSR1)
                .thread_block()
                .expect("block SIGUSR1");
        }
        let blocks_it = SigSet::from(sig);
        configure(code, sig, mode, &blocks_it);
        let lets_it_through = SigSet::empty();
        let timeout = libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        // SAFETY: ppoll reads no descriptors, the timeout and the mask.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                std::ptr::null_mut::<libc::pollfd>(),
                0,
                &timeout as *const libc::timespec,
                lets_it_through.as_ref() as *const libc::sigset_t,
                std::mem::size_of::<u64>(),
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let blocked_after = SigSet::thread_get_mask()
            .expect("read the mask")
            .contains(sig);
        (
            ret,
            if ret == -1 { errno } else { 0 },
            HANDLED.load(Ordering::SeqCst),
            blocked_after,
        )
    }

    /// Configures the thread's next `ppoll` or `rt_sigsuspend`
    /// (`CONFIGURE_PPOLL`), with `set` for `HELD_THEN_BLOCKED`.
    fn configure(code: i32, sig: Signal, mode: i64, set: &SigSet) {
        // SAFETY: the probe syscall takes integers; Linux ignores them.
        unsafe {
            libc::syscall(
                libc::SYS_getppid,
                code as libc::c_long,
                sig as libc::c_long,
                CONFIGURE_PPOLL as libc::c_long,
                mode as libc::c_long,
                set.as_ref() as *const libc::sigset_t,
            )
        };
    }

    /// The guest's raw `rt_sigsuspend` with an empty mask while the thread
    /// blocks `sig`, handled under `flags`: as `masked_ppoll`.
    fn masked_sigsuspend(
        sig: Signal,
        flags: Option<SaFlags>,
        mode: i64,
    ) -> (i64, i32, usize, bool) {
        handle(sig, flags);
        SigSet::from(sig).thread_block().expect("block the signal");
        configure(0, sig, mode, &SigSet::empty());
        let lets_it_through = SigSet::empty();
        // SAFETY: rt_sigsuspend reads the mask.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_rt_sigsuspend,
                lets_it_through.as_ref() as *const libc::sigset_t,
                std::mem::size_of::<u64>(),
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let blocked_after = SigSet::thread_get_mask()
            .expect("read the mask")
            .contains(sig);
        (
            ret,
            if ret == -1 { errno } else { 0 },
            HANDLED.load(Ordering::SeqCst),
            blocked_after,
        )
    }

    /// The guest's raw `ppoll` of one ignored descriptor (so its first argument
    /// is a pointer) with a 10 s timeout, under a temporary mask that lets
    /// `sig` through while the thread blocks it, interrupted with `mode`.
    /// With `handler_polls`, `sig`'s handler runs a `ppoll` of its own through
    /// the same wrapper (`on_signal_polling`). Returns the result, its errno,
    /// the handler runs, whether `sig` is blocked again, and what the
    /// handler's `ppoll` returned.
    fn masked_ppoll_of_a_descriptor(
        sig: Signal,
        handler_polls: bool,
        mode: i64,
    ) -> (i64, i32, usize, bool, i64) {
        if handler_polls {
            let action = SigAction::new(
                SigHandler::Handler(on_signal_polling),
                SaFlags::SA_RESTART,
                SigSet::empty(),
            );
            // SAFETY: the handler increments an atomic and makes a syscall.
            unsafe { sigaction(sig, &action) }.expect("install the handler");
        }
        SigSet::from(sig).thread_block().expect("block the signal");
        configure(0, sig, mode, &SigSet::empty());
        let mut ignored = libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        };
        let lets_it_through = SigSet::empty();
        let timeout = libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        // SAFETY: ppoll reads one descriptor entry, the timeout and the mask.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut ignored as *mut libc::pollfd,
                1,
                &timeout as *const libc::timespec,
                lets_it_through.as_ref() as *const libc::sigset_t,
                std::mem::size_of::<u64>(),
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let blocked_after = SigSet::thread_get_mask()
            .expect("read the mask")
            .contains(sig);
        (
            ret,
            if ret == -1 { errno } else { 0 },
            HANDLED.load(Ordering::SeqCst),
            blocked_after,
            HANDLER_POLL.load(Ordering::SeqCst),
        )
    }

    fn check_masked_ppoll(
        code: i32,
        sig: Signal,
        flags: Option<SaFlags>,
        mode: i64,
        want: (i64, i32, usize, bool),
    ) {
        check_fn::<RestartResult, _>(move || {
            let got = masked_ppoll(code, sig, flags, mode);
            assert_eq!(
                got, want,
                "(result, errno, handler runs, the signal blocked again)"
            );
        });
    }

    /// `ppoll` leaves its temporary mask's restore pending with
    /// `-ERESTARTNOHAND` (`poll_select_finish`, fs/select.c). With a handler
    /// that is `-EINTR`, even under `SA_RESTART`, and the handler's return
    /// puts the guest's own mask back (`sigmask_to_save`).
    #[test]
    fn erestartnohand_under_a_temporary_mask_is_eintr_and_restores_the_mask() {
        let flags = Some(SaFlags::SA_RESTART);
        let want = (-1, libc::EINTR, 1, true);
        check_masked_ppoll(
            ERESTARTNOHAND,
            Signal::SIGUSR1,
            flags,
            HELD_OVER_INJECTION,
            want,
        );
    }

    /// With no handler (SIGWINCH at its default action), or with the held
    /// signal dropped, `ppoll` restarts with the guest's own mask back
    /// (`restore_saved_sigmask`), and the restarted call is answered.
    #[test_case(Signal::SIGWINCH, None, HELD_OVER_INJECTION; "sigwinch at its default action")]
    #[test_case(Signal::SIGUSR1, Some(SaFlags::SA_RESTART), HELD_AND_DROPPED; "sigusr1 dropped")]
    fn erestartnohand_under_a_temporary_mask_without_a_handler_restarts(
        sig: Signal,
        flags: Option<SaFlags>,
        mode: i64,
    ) {
        check_masked_ppoll(ERESTARTNOHAND, sig, flags, mode, (RESTARTED, 0, 0, true));
    }

    /// A held signal without a handler (SIGWINCH) with SIGUSR1, which has one,
    /// pending too: `get_signal` goes on to SIGUSR1 in the same `do_signal`,
    /// whose handler makes the call `-EINTR`.
    #[test]
    fn a_handled_signal_pending_behind_one_without_a_handler_is_eintr() {
        let want = (-1, libc::EINTR, 1, true);
        check_masked_ppoll(
            ERESTARTNOHAND,
            Signal::SIGWINCH,
            None,
            HELD_WITH_SIGUSR1_PENDING,
            want,
        );
    }

    /// `-ERESTARTSYS` with a handler under a pending mask restore, which Linux
    /// never returns: x86-64's kernel resolves it after the tracer's last stop
    /// (`SA_RESTART`: the handler runs and the call restarts).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn erestartsys_with_a_handler_under_a_temporary_mask() {
        let flags = Some(SaFlags::SA_RESTART);
        let want = (RESTARTED, 0, 1, true);
        check_masked_ppoll(
            ERESTARTSYS,
            Signal::SIGUSR1,
            flags,
            HELD_OVER_INJECTION,
            want,
        );
    }

    /// The same on aarch64 is refused by name, with an error that ends the
    /// run: its outcome hangs on `SA_RESTART`, which procfs does not show, so
    /// this Tool refuses it (`resolve_restart_under_pending_mask_restore`,
    /// `Undecidable::ErestartsysWithHandler`).
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn erestartsys_with_a_handler_under_a_temporary_mask() {
        assert_undecidable(Undecidable::ErestartsysWithHandler, || {
            masked_ppoll(
                ERESTARTSYS,
                Signal::SIGUSR1,
                Some(SaFlags::SA_RESTART),
                HELD_OVER_INJECTION,
            );
        });
    }

    /// Asserts that the backend ends the run `guest` makes with the refusal
    /// `reason` (`reverie_ptrace::RestartRefusal`).
    #[cfg(target_arch = "aarch64")]
    fn assert_refused(reason: reverie_ptrace::RestartRefusalReason, guest: impl FnOnce()) {
        let error = match reverie_ptrace::testing::test_fn::<RestartResult, _>(guest) {
            Ok((output, _)) => panic!("expected {reason:?}; the guest exited {:?}", output.status),
            Err(error) => error,
        };
        let refusal = match &error {
            Error::Tool(inner) => inner.downcast_ref::<reverie_ptrace::RestartRefusal>(),
            _ => None,
        };
        let refusal = refusal.unwrap_or_else(|| panic!("expected RestartRefusal, got {error:?}"));
        assert_eq!(refusal.reason, reason, "{refusal}");
    }

    /// Asserts that the run `guest` makes ends with this Tool's refusal of
    /// its `-ERESTARTSYS` for `ppoll`, for `reason` (`RestartRefused`).
    #[cfg(target_arch = "aarch64")]
    fn assert_undecidable(reason: Undecidable, guest: impl FnOnce()) {
        let error = match reverie_ptrace::testing::test_fn::<RestartResult, _>(guest) {
            Ok((output, _)) => panic!("expected {reason:?}; the guest exited {:?}", output.status),
            Err(error) => error,
        };
        let refusal = match &error {
            Error::Tool(inner) => inner.downcast_ref::<RestartRefused>(),
            _ => None,
        };
        let refusal = refusal.unwrap_or_else(|| panic!("expected RestartRefused, got {error:?}"));
        assert_eq!(
            *refusal,
            RestartRefused {
                syscall: Sysno::ppoll,
                code: Errno::ERESTARTSYS,
                reason,
            },
            "{refusal}"
        );
    }

    /// A held signal that an injected `rt_sigprocmask` then blocks: the kernel
    /// queues it again rather than deliver it, no handler runs, and the call
    /// restarts with the guest's own mask, where the signal stays pending.
    #[test]
    fn a_held_signal_the_mask_in_effect_then_blocks_restarts() {
        let flags = Some(SaFlags::SA_RESTART);
        let want = (RESTARTED, 0, 0, true);
        check_masked_ppoll(
            ERESTARTNOHAND,
            Signal::SIGUSR1,
            flags,
            HELD_THEN_BLOCKED,
            want,
        );
    }

    /// The plain pattern: the Tool injects the guest's own `ppoll` or
    /// `rt_sigsuspend`, a signal interrupts it, and the Tool returns the
    /// injection's result as the guest's, the signal left pending. Linux gives
    /// `-EINTR` for a handler, which runs once, and restarts the call without
    /// one (SIGWINCH), the guest's own mask restored either way.
    #[test_case(false, Signal::SIGUSR1, (-1, libc::EINTR, 1, true); "ppoll with a handler")]
    #[test_case(true, Signal::SIGUSR1, (-1, libc::EINTR, 1, true); "rt_sigsuspend with a handler")]
    #[test_case(false, Signal::SIGWINCH, (RESTARTED, 0, 0, true); "ppoll without a handler")]
    #[test_case(true, Signal::SIGWINCH, (RESTARTED, 0, 0, true); "rt_sigsuspend without a handler")]
    fn an_interrupted_injections_own_result_is_resolved_as_on_linux(
        sigsuspend: bool,
        sig: Signal,
        want: (i64, i32, usize, bool),
    ) {
        let flags = (sig == Signal::SIGUSR1).then_some(SaFlags::SA_RESTART);
        check_fn::<RestartResult, _>(move || {
            let got = if sigsuspend {
                masked_sigsuspend(sig, flags, PLAIN)
            } else {
                masked_ppoll(0, sig, flags, PLAIN)
            };
            assert_eq!(
                got, want,
                "(result, errno, handler runs, the signal blocked again)"
            );
        });
    }

    /// The Tool runs the guest's `ppoll` with a first argument of its own,
    /// a signal with no handler (SIGWINCH) interrupts it, and the Tool returns
    /// the call's result: the restarted call runs with the guest's own first
    /// argument, which the Tool checks. This Tool does not declare serialized
    /// execution, so on aarch64 the injection is single-stepped from the
    /// private page and ends at a SIGTRAP stop, after which the backend
    /// writes the restart itself, with the guest's first argument. The
    /// syscall-stop transport, after which the kernel restarts the call, is
    /// tested below.
    #[test]
    fn a_restarted_call_runs_with_the_guests_own_first_argument() {
        check_fn::<RestartResult, _>(|| {
            let got = masked_ppoll_of_a_descriptor(
                Signal::SIGWINCH,
                false,
                PLAIN_WITH_ANOTHER_FIRST_ARGUMENT,
            );
            assert_eq!(
                got,
                (RESTARTED, 0, 0, true, i64::MIN),
                "(result, errno, handler runs, the signal blocked again, the handler's ppoll)"
            );
        });
    }

    /// "ppoll without a handler" under a Tool that declares serialized
    /// execution, with the Tool's call given a first argument the call never
    /// reads (no descriptors; the same temporary mask and timeout). On aarch64
    /// the backend runs that mask-swapping injection between syscall stops
    /// (`syscall_stops_admitted`), which loads the injected arguments before
    /// the private `svc`, so the kernel saves the Tool's first argument as
    /// `orig_x0`, and a kernel restart would put it back in `x0`. The backend
    /// therefore writes the restart itself, with the guest's first argument
    /// (`defer_restart_under_pending_mask_restore`), and the Tool answers a
    /// restarted call only with the guest's first argument.
    #[test]
    fn ppoll_without_a_handler_restarts_with_the_guests_first_argument_after_a_serialized_injection()
     {
        check_fn_with_config::<RestartResult, _>(
            || {
                let got = masked_ppoll(
                    0,
                    Signal::SIGWINCH,
                    None,
                    PLAIN_WITH_AN_UNREAD_FIRST_ARGUMENT,
                );
                assert_eq!(
                    got,
                    (RESTARTED, 0, 0, true),
                    "(result, errno, handler runs, the signal blocked again)"
                );
            },
            true,
            true,
        );
    }

    /// As above, with the signal sent to the process, and another guest thread
    /// waiting for it in `rt_sigtimedwait` until after the interruption: that
    /// thread takes it from the shared pending set while the tracer holds the
    /// first, so no signal is left to deliver when the first resumes. A kernel
    /// restart would then come from a `do_signal` that finds no signal and
    /// restarts the call with no ptrace stop, where no tracer could put the
    /// guest's first argument back; the backend writes the restart itself.
    /// The second thread running guest code meanwhile breaks the
    /// serialized-execution contract the Tool declares; it is the only way a
    /// guest can take the signal away from the first thread.
    #[test]
    fn a_restart_with_the_signal_taken_by_another_thread_keeps_the_guests_first_argument() {
        check_fn_with_config::<RestartResult, _>(
            || {
                SigSet::from(Signal::SIGWINCH)
                    .thread_block()
                    .expect("block the signal");
                let waiting = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let taker = {
                    let waiting = waiting.clone();
                    std::thread::spawn(move || {
                        let set = SigSet::from(Signal::SIGWINCH);
                        let timeout = libc::timespec {
                            tv_sec: 1,
                            tv_nsec: 0,
                        };
                        waiting.store(true, Ordering::SeqCst);
                        // SAFETY: rt_sigtimedwait reads the set and the timeout.
                        unsafe {
                            libc::syscall(
                                libc::SYS_rt_sigtimedwait,
                                set.as_ref() as *const libc::sigset_t,
                                std::ptr::null_mut::<libc::siginfo_t>(),
                                &timeout as *const libc::timespec,
                                std::mem::size_of::<u64>(),
                            )
                        }
                    })
                };
                while !waiting.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                let got = masked_ppoll(0, Signal::SIGWINCH, None, TAKEN_BY_ANOTHER_THREAD);
                assert_eq!(
                    taker.join().unwrap(),
                    libc::SIGWINCH as libc::c_long,
                    "the other thread takes the signal"
                );
                assert_eq!(
                    got,
                    (RESTARTED, 0, 0, true),
                    "(result, errno, handler runs, the signal blocked again)"
                );
            },
            true,
            true,
        );
    }

    /// The Tool runs the guest's own `ppoll` of a descriptor, a signal whose
    /// handler runs a `ppoll` of its own through the same wrapper (so from the
    /// same `svc`, with the same syscall number and another first argument)
    /// interrupts it, and the Tool returns the call's result, which the kernel
    /// resolves: the guest's call is `-EINTR`, and the handler's call keeps its
    /// own first argument and returns 0.
    #[test]
    fn a_handler_calling_the_same_wrapper_keeps_its_own_first_argument() {
        check_fn::<RestartResult, _>(|| {
            let got = masked_ppoll_of_a_descriptor(Signal::SIGUSR1, true, PLAIN);
            assert_eq!(
                got,
                (-1, libc::EINTR, 1, true, 0),
                "(result, errno, handler runs, the signal blocked again, the handler's ppoll)"
            );
        });
    }

    /// Blocks every realtime signal from 34 to 64 for the thread, so those
    /// the tracer sends stay pending (`HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING`).
    fn block_every_realtime_signal() {
        let every_realtime: u64 = (34..=64).map(|signal| 1u64 << (signal - 1)).sum();
        // SAFETY: rt_sigprocmask reads the 8-byte set.
        let blocked = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_BLOCK,
                &every_realtime as *const u64,
                std::ptr::null_mut::<u64>(),
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(blocked, 0, "block every realtime signal");
    }

    /// A held signal with a handler while every realtime signal is pending:
    /// x86-64's kernel resolves the code, `-EINTR`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_held_signal_with_every_realtime_signal_pending() {
        check_fn::<RestartResult, _>(|| {
            block_every_realtime_signal();
            let flags = Some(SaFlags::SA_RESTART);
            let got = probe(
                ERESTARTNOHAND,
                Signal::SIGUSR1,
                flags,
                HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING,
            );
            assert_eq!(got, (-1, libc::EINTR, 1), "(result, errno, handler runs)");
        });
    }

    /// The same on aarch64 is refused by name: no realtime signal is free to
    /// carry the resume into `do_signal`.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn a_held_signal_with_every_realtime_signal_pending() {
        assert_refused(
            reverie_ptrace::RestartRefusalReason::NoFreeCarrierSignal,
            || {
                block_every_realtime_signal();
                probe(
                    ERESTARTNOHAND,
                    Signal::SIGUSR1,
                    Some(SaFlags::SA_RESTART),
                    HELD_WITH_EVERY_REALTIME_SIGNAL_PENDING,
                );
            },
        );
    }
}
