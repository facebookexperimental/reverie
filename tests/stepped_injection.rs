/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool's injected syscall that keeps the signal mask, run from Reverie's
//! private page and so stepped (a first injection runs it, and its arguments
//! differ from the guest's), and interrupted by a signal with a handler. The Tool gets the call's own
//! restart code: `-ERESTARTNOHAND` from `ppoll`, `-ERESTART_RESTARTBLOCK`
//! from `clock_nanosleep` and `-ERESTARTSYS` from a `read`. The signal stays
//! queued in the kernel and reaches the Tool at its own signal-delivery stop
//! when the guest resumes. A `ppoll` that swaps in a temporary mask is
//! stepped too under a Tool that does not serialize threads (no syscall-stop
//! transport), and reports `-ERESTARTNOHAND`; the signal its temporary mask
//! let through stays queued behind the step's SIGTRAP and reaches the Tool
//! at its own stop too. When that temporary mask also blocks SIGTRAP, x86-64's
//! step still takes its SIGTRAP first (`force_sig` unblocks it) and the signal
//! stays queued; aarch64 then makes the step's end with a second `svc`, and
//! the signal, taken first, is held for the guest's resume, which delivers it
//! with no report.

#[cfg(all(not(sanitized), test))]
use std::sync::Mutex;
#[cfg(all(not(sanitized), test))]
use std::time::Duration;

#[cfg(all(not(sanitized), test))]
use nix::sys::signal::Signal;
#[cfg(all(not(sanitized), test))]
use reverie::Errno;
#[cfg(all(not(sanitized), test))]
use reverie::Error;
#[cfg(all(not(sanitized), test))]
use reverie::GlobalTool;
#[cfg(all(not(sanitized), test))]
use reverie::Guest;
#[cfg(all(not(sanitized), test))]
use reverie::Pid;
#[cfg(all(not(sanitized), test))]
use reverie::Tool;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Syscall;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallArgs;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::SyscallInfo;
#[cfg(all(not(sanitized), test))]
use reverie::syscalls::Sysno;
#[cfg(all(not(sanitized), test))]
use serde::Deserialize;
#[cfg(all(not(sanitized), test))]
use serde::Serialize;

/// The first argument of the `getppid` with which the guest names the call
/// the Tool interrupts next (second argument, a `Case` number).
#[cfg(all(not(sanitized), test))]
const CONFIGURE: usize = 0x5354_4550;

/// The calls the Tool interrupts.
#[cfg(all(not(sanitized), test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    /// `ppoll` with no temporary mask: the Tool runs it with no descriptors.
    Ppoll = 1,
    /// A relative `clock_nanosleep`: the Tool runs it with no remainder.
    ClockNanosleep = 2,
    /// A one-byte `read` of an empty pipe: the Tool runs it for two bytes.
    Read = 3,
    /// `ppoll` under a temporary mask that lets SIGUSR1 through while the
    /// thread blocks it: the Tool runs it with no descriptors.
    PpollMasked = 4,
    /// As `PpollMasked`, with SIGTRAP in the temporary mask.
    PpollMaskedBlockingSigtrap = 5,
    /// `gettid`, not interrupted, while the thread has a SIGTRAP handler and
    /// blocks SIGTRAP, under a Tool that does not serialize threads (so no
    /// shield unblocks it for the step).
    GettidBlockingSigtrap = 6,
    /// As `Read`, while the thread has a SIGTRAP handler and blocks SIGTRAP,
    /// under a Tool that does not serialize threads.
    ReadBlockingSigtrap = 7,
    /// The guest's `getgid`, for which the Tool runs `getuid` from the
    /// private page, not interrupted, while the thread's own seccomp filter
    /// traps `getuid` (`SECCOMP_RET_TRAP`).
    GetuidTrapped = 8,
    /// As `ClockNanosleep`, while the thread has a SIGTRAP handler and
    /// blocks SIGTRAP, under a Tool that does not serialize threads.
    ClockNanosleepBlockingSigtrap = 9,
}

#[cfg(all(not(sanitized), test))]
impl Case {
    fn from_raw(raw: usize) -> Self {
        match raw {
            1 => Case::Ppoll,
            2 => Case::ClockNanosleep,
            3 => Case::Read,
            4 => Case::PpollMasked,
            5 => Case::PpollMaskedBlockingSigtrap,
            6 => Case::GettidBlockingSigtrap,
            7 => Case::ReadBlockingSigtrap,
            8 => Case::GetuidTrapped,
            9 => Case::ClockNanosleepBlockingSigtrap,
            _ => panic!("unknown case {raw}"),
        }
    }

    fn syscall(self) -> Sysno {
        match self {
            Case::Ppoll | Case::PpollMasked | Case::PpollMaskedBlockingSigtrap => Sysno::ppoll,
            Case::ClockNanosleep | Case::ClockNanosleepBlockingSigtrap => Sysno::clock_nanosleep,
            Case::Read | Case::ReadBlockingSigtrap => Sysno::read,
            Case::GettidBlockingSigtrap => Sysno::gettid,
            Case::GetuidTrapped => Sysno::getgid,
        }
    }

    /// The call the Tool runs from the private page.
    fn injected_nr(self) -> Sysno {
        match self {
            Case::GetuidTrapped => Sysno::getuid,
            case => case.syscall(),
        }
    }

    /// Whether the guest blocks a caught SIGTRAP for the call, so that the
    /// step's end is made with a second `svc` on aarch64.
    fn blocks_sigtrap(self) -> bool {
        matches!(
            self,
            Case::GettidBlockingSigtrap
                | Case::ReadBlockingSigtrap
                | Case::ClockNanosleepBlockingSigtrap
        )
    }

    /// The Tool's first injection, which runs at the guest's own syscall
    /// stop, and what it returns. Where the guest blocks a caught SIGTRAP it
    /// is the guest's own call with arguments that end it at once, so that
    /// it runs in place with no step: a step from that stop (the skip of the
    /// guest's call before a `getpid` from the private page) would force a
    /// SIGTRAP, which unblocks it and resets its action before the call
    /// under test runs.
    fn first(self, args: SyscallArgs, tid: i64) -> (Syscall, Result<i64, Errno>) {
        match self {
            Case::GettidBlockingSigtrap => (
                Syscall::from_raw(Sysno::gettid, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
                Ok(tid),
            ),
            Case::ReadBlockingSigtrap => (
                Syscall::from_raw(
                    Sysno::read,
                    SyscallArgs::new(usize::MAX, args.arg1, 0, 0, 0, 0),
                ),
                Err(Errno::EBADF),
            ),
            Case::ClockNanosleepBlockingSigtrap => (
                Syscall::from_raw(
                    Sysno::clock_nanosleep,
                    SyscallArgs::new(usize::MAX, 0, args.arg2, 0, 0, 0),
                ),
                Err(Errno::EINVAL),
            ),
            _ => (
                Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
                Ok(-1),
            ),
        }
    }

    /// Whether a signal interrupts the injected call.
    fn interrupts(self) -> bool {
        !matches!(self, Case::GettidBlockingSigtrap | Case::GetuidTrapped)
    }

    /// The guest's arguments, changed so that the call runs from the private
    /// page.
    fn injected(self, args: SyscallArgs) -> SyscallArgs {
        match self {
            Case::Ppoll | Case::PpollMasked | Case::PpollMaskedBlockingSigtrap => {
                SyscallArgs::new(0, 0, args.arg2, args.arg3, args.arg4, args.arg5)
            }
            Case::ClockNanosleep | Case::ClockNanosleepBlockingSigtrap => {
                SyscallArgs::new(args.arg0, args.arg1, args.arg2, 0, args.arg4, args.arg5)
            }
            Case::Read | Case::ReadBlockingSigtrap => {
                SyscallArgs::new(args.arg0, args.arg1, 2, args.arg3, args.arg4, args.arg5)
            }
            Case::GettidBlockingSigtrap | Case::GetuidTrapped => args,
        }
    }
}

/// What the Tool saw, in order.
#[cfg(all(not(sanitized), test))]
#[derive(Default)]
struct Log {
    seen: Mutex<Vec<String>>,
}

#[cfg(all(not(sanitized), test))]
#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = String;
    type Response = ();
    /// Whether the Tool serializes threads (`enforces_serialized_execution`).
    type Config = bool;

    async fn receive_rpc(&self, _from: Pid, seen: String) {
        self.seen.lock().unwrap().push(seen);
    }
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Serialize, Deserialize)]
struct ThreadState {
    armed: Option<usize>,
}

#[cfg(all(not(sanitized), test))]
#[derive(Debug, Default, Clone)]
struct SteppedInjection;

#[cfg(all(not(sanitized), test))]
#[reverie::tool]
impl Tool for SteppedInjection {
    type GlobalState = Log;
    type ThreadState = ThreadState;

    /// The guest has one thread, so either answer holds.
    fn enforces_serialized_execution(serialized: &bool) -> bool {
        *serialized
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        if nr == Sysno::getppid && args.arg0 == CONFIGURE {
            guest.thread_state_mut().armed = Some(args.arg1);
            return Ok(0);
        }
        let case = match guest.thread_state().armed.map(Case::from_raw) {
            Some(case) if case.syscall() == nr => case,
            _ => return guest.tail_inject(syscall).await,
        };
        guest.thread_state_mut().armed = None;
        let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
        // A first injection of a call that keeps the mask can run in place,
        // at the guest's own syscall; a second runs from the private page.
        let (first, returns) = case.first(args, i64::from(tid));
        let ran = guest.inject(first).await;
        if case.blocks_sigtrap() {
            assert_eq!(ran, returns, "the first injection");
            assert_sigtrap_still_caught_and_blocked(tid);
        } else {
            ran?;
        }
        let sender = case.interrupts().then(|| {
            std::thread::spawn(move || {
                // Long enough for the injected call to block.
                std::thread::sleep(Duration::from_millis(200));
                // SAFETY: tgkill takes three integers and touches no memory.
                unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGUSR1) }
            })
        });
        let injected = guest
            .inject(Syscall::from_raw(case.injected_nr(), case.injected(args)))
            .await;
        if let Some(sender) = sender {
            assert_eq!(sender.join().unwrap(), 0, "tgkill from the tracer");
        }
        // `gettid`'s result is shown as whether it is the thread's own ID,
        // which no other value the registers could hold matches.
        let shown = match case {
            Case::GettidBlockingSigtrap => format!(
                "injected {:?}",
                injected.map(|ret| ret == i64::from(tid))
            ),
            _ => format!("injected {injected:?}"),
        };
        guest.send_rpc(shown).await;
        Err(Errno::EINTR.into())
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        guest.send_rpc(format!("signal {signal:?}")).await;
        Ok(Some(signal))
    }

    /// A SIGUSR1 the backend passes on without a report is logged with why.
    async fn filter_unreported_signal<R: reverie::GlobalRPC<Self::GlobalState>>(
        &self,
        rpc: &R,
        signal: reverie::UnreportedSignal,
    ) -> bool {
        if signal.number() == libc::SIGUSR1 {
            rpc.send_rpc(format!("unreported SIGUSR1 {:?}", signal.reason()))
                .await;
        }
        true
    }
}

/// Asserts that thread `tid` still blocks and catches SIGTRAP (`SigBlk` and
/// `SigCgt` in its procfs status) after the Tool's first injection, so that
/// the call under test steps with SIGTRAP blocked: a forced step trap would
/// have unblocked it and reset its action.
#[cfg(all(not(sanitized), test))]
fn assert_sigtrap_still_caught_and_blocked(tid: i32) {
    let status =
        std::fs::read_to_string(format!("/proc/{tid}/status")).expect("read the thread's status");
    let set = |field: &str| {
        let hex = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap_or_else(|| panic!("the status has {field}"));
        u64::from_str_radix(hex.trim(), 16).expect("a hexadecimal signal set")
    };
    let sigtrap = 1u64 << (libc::SIGTRAP - 1);
    assert_ne!(set("SigBlk:") & sigtrap, 0, "SIGTRAP is still blocked");
    assert_ne!(set("SigCgt:") & sigtrap, 0, "SIGTRAP is still caught");
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use nix::sys::signal::SigSet;
    use test_case::test_case;

    use super::*;

    /// The interrupting SIGUSR1 stays queued and reaches the Tool at its own
    /// signal-delivery stop.
    const SIGNAL_AT_ITS_STOP: &str = "signal SIGUSR1";

    /// The interrupting SIGUSR1 is held for the guest's resume, which
    /// delivers it with no report.
    const HELD_SIGNAL: &str = "unreported SIGUSR1 HeldRestorePending";

    static HANDLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_signal(_: libc::c_int) {
        HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    /// Runs of the guest's SIGSYS handler.
    static SIGSYS_HANDLED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_sigsys(_: libc::c_int) {
        SIGSYS_HANDLED.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn on_sigtrap(_: libc::c_int) {}

    /// Gives SIGTRAP a handler and blocks it in the thread's mask.
    fn block_a_caught_sigtrap() {
        // SAFETY: the action is fully initialized; the handler does nothing.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigtrap as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGTRAP, &action, std::ptr::null_mut()), 0);
        }
        SigSet::from(Signal::SIGTRAP)
            .thread_block()
            .expect("block SIGTRAP");
    }

    /// Asserts what the step's trap, a `force_sig` of SIGTRAP while the
    /// thread blocks it, leaves: SIGTRAP unblocked and its action reset to
    /// `SIG_DFL`, as Linux's step traps leave it under a Tool that does not
    /// serialize threads. A trap the backend queues instead resets nothing.
    fn assert_the_step_trap_was_forced() {
        // SAFETY: sigaction writes the current action into `action`.
        let handler = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGTRAP, std::ptr::null(), &mut action), 0);
            action.sa_sigaction
        };
        assert_eq!(handler, libc::SIG_DFL, "the step's trap reset SIGTRAP's action");
        assert!(
            !SigSet::thread_get_mask()
                .expect("read the mask")
                .contains(Signal::SIGTRAP),
            "the step's trap unblocked SIGTRAP"
        );
    }

    /// The guest: SIGUSR1 has a handler (`SA_RESTART`), the Tool is told
    /// which call to interrupt, and the guest makes it.
    fn guest(case: Case) {
        // SAFETY: the action is fully initialized; the handler increments
        // an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()), 0);
        }
        // SAFETY: getppid takes no arguments; the Tool reads the two passed.
        unsafe { libc::syscall(libc::SYS_getppid, CONFIGURE, case as usize) };
        let masked = matches!(case, Case::PpollMasked | Case::PpollMaskedBlockingSigtrap);
        let blocks_sigtrap = case.blocks_sigtrap();
        if blocks_sigtrap {
            block_a_caught_sigtrap();
        }
        if masked {
            SigSet::from(Signal::SIGUSR1)
                .thread_block()
                .expect("block SIGUSR1");
        }
        let ten_seconds = libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        };
        // SAFETY: each call reads and writes only the locals passed to it.
        let ret = unsafe {
            match case {
                Case::Ppoll => {
                    let mut ignored = libc::pollfd {
                        fd: -1,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    libc::syscall(
                        libc::SYS_ppoll,
                        &mut ignored as *mut libc::pollfd,
                        1,
                        &ten_seconds as *const libc::timespec,
                        std::ptr::null::<u64>(),
                        std::mem::size_of::<u64>(),
                    )
                }
                Case::ClockNanosleep | Case::ClockNanosleepBlockingSigtrap => {
                    let mut remaining: libc::timespec = std::mem::zeroed();
                    libc::syscall(
                        libc::SYS_clock_nanosleep,
                        libc::CLOCK_MONOTONIC,
                        0,
                        &ten_seconds as *const libc::timespec,
                        &mut remaining as *mut libc::timespec,
                    )
                }
                Case::PpollMasked | Case::PpollMaskedBlockingSigtrap => {
                    let mut ignored = libc::pollfd {
                        fd: -1,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let lets_it_through: u64 = if case == Case::PpollMaskedBlockingSigtrap {
                        1 << (libc::SIGTRAP - 1)
                    } else {
                        0
                    };
                    libc::syscall(
                        libc::SYS_ppoll,
                        &mut ignored as *mut libc::pollfd,
                        1,
                        &ten_seconds as *const libc::timespec,
                        &lets_it_through as *const u64,
                        std::mem::size_of::<u64>(),
                    )
                }
                Case::GettidBlockingSigtrap | Case::GetuidTrapped => {
                    unreachable!("not an interrupted case")
                }
                Case::Read | Case::ReadBlockingSigtrap => {
                    let mut fds = [0; 2];
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                    let mut buffer = [0u8; 16];
                    libc::syscall(libc::SYS_read, fds[0], buffer.as_mut_ptr(), 1)
                }
            }
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)), "the Tool's answer");
        assert_eq!(HANDLED.load(Ordering::SeqCst), 1, "the handler ran once");
        if blocks_sigtrap {
            assert_the_step_trap_was_forced();
        }
        if masked {
            assert!(
                SigSet::thread_get_mask()
                    .expect("read the mask")
                    .contains(Signal::SIGUSR1),
                "SIGUSR1 is blocked again"
            );
        }
    }

    #[test_case(Case::Ppoll, true, Errno::ERESTARTNOHAND, SIGNAL_AT_ITS_STOP)]
    #[test_case(Case::ClockNanosleep, true, Errno::ERESTART_RESTARTBLOCK, SIGNAL_AT_ITS_STOP)]
    #[test_case(Case::Read, true, Errno::ERESTARTSYS, SIGNAL_AT_ITS_STOP)]
    #[test_case(Case::PpollMasked, false, Errno::ERESTARTNOHAND, SIGNAL_AT_ITS_STOP)]
    #[test_case(
        Case::PpollMaskedBlockingSigtrap,
        false,
        Errno::ERESTARTNOHAND,
        if cfg!(target_arch = "x86_64") { SIGNAL_AT_ITS_STOP } else { HELD_SIGNAL }
    )]
    #[test_case(Case::ReadBlockingSigtrap, false, Errno::ERESTARTSYS, SIGNAL_AT_ITS_STOP)]
    #[test_case(
        Case::ClockNanosleepBlockingSigtrap,
        false,
        Errno::ERESTART_RESTARTBLOCK,
        SIGNAL_AT_ITS_STOP
    )]
    fn an_interrupted_stepped_injection_reports_its_own_restart_code(
        case: Case,
        serialized: bool,
        code: Errno,
        then: &str,
    ) {
        let (output, log) = reverie_ptrace::testing::test_fn_with_config::<SteppedInjection, _>(
            || guest(case),
            serialized,
            true,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "the guest failed: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = vec![format!("injected {:?}", Err::<i64, _>(code)), then.to_owned()];
        assert_eq!(
            *log.seen.lock().unwrap(),
            expected,
            "the injection's own result, then a queued signal at its own stop"
        );
    }

    /// The guest of the uninterrupted cases: the Tool runs `gettid` from the
    /// private page while SIGTRAP is caught and blocked
    /// (`GettidBlockingSigtrap`), or while the thread's own filter traps
    /// `getuid` (`GetuidTrapped`), and answers the guest's call with EINTR.
    fn uninterrupted_guest(case: Case) {
        // SAFETY: getppid takes no arguments; the Tool reads the two passed.
        // The Tool answers it without running it, which a step from its
        // syscall stop does, before SIGTRAP is blocked.
        unsafe { libc::syscall(libc::SYS_getppid, CONFIGURE, case as usize) };
        match case {
            Case::GettidBlockingSigtrap => block_a_caught_sigtrap(),
            Case::GetuidTrapped => {
                // SAFETY: the action is fully initialized; the handler
                // increments an atomic. The filter traps only getuid.
                unsafe {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = on_sigsys as *const () as usize;
                    libc::sigemptyset(&mut action.sa_mask);
                    assert_eq!(libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()), 0);
                    let mut filter = [
                        // BPF_LD | BPF_W | BPF_ABS: the syscall number.
                        libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 0 },
                        // BPF_JMP | BPF_JEQ | BPF_K
                        libc::sock_filter {
                            code: 0x15,
                            jt: 0,
                            jf: 1,
                            k: libc::SYS_getuid as u32,
                        },
                        // BPF_RET | BPF_K: SECCOMP_RET_TRAP
                        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x0003_0000 },
                        // SECCOMP_RET_ALLOW
                        libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x7fff_0000 },
                    ];
                    let program = libc::sock_fprog {
                        len: filter.len() as u16,
                        filter: filter.as_mut_ptr(),
                    };
                    assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                    assert_eq!(
                        libc::prctl(
                            libc::PR_SET_SECCOMP,
                            libc::SECCOMP_MODE_FILTER,
                            &program as *const libc::sock_fprog
                        ),
                        0
                    );
                }
            }
            case => unreachable!("{case:?} is interrupted"),
        }
        // SAFETY: the call takes no arguments.
        let ret = unsafe { libc::syscall(case.syscall() as libc::c_long) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!((ret, errno), (-1, Some(libc::EINTR)), "the Tool's answer");
        match case {
            Case::GettidBlockingSigtrap => assert_the_step_trap_was_forced(),
            _ => assert_eq!(SIGSYS_HANDLED.load(Ordering::SeqCst), 1, "the trap's SIGSYS"),
        }
    }

    /// An injection that a signal does not interrupt, stepped from the
    /// private page: with SIGTRAP caught and blocked and no shield, it gets
    /// its result (the thread's own ID, which no register held before) and the
    /// step's trap is forced as Linux forces it; with the
    /// thread's own filter trapping the call, it gets `ENOSYS` and the trap's
    /// SIGSYS reaches the guest at its own stop.
    #[test_case(Case::GettidBlockingSigtrap, false, "injected Ok(true)".to_owned(), None)]
    #[test_case(Case::GetuidTrapped, true, "injected Err(ENOSYS)".to_owned(), Some("signal SIGSYS"))]
    fn an_uninterrupted_stepped_injection_reports_its_result(
        case: Case,
        serialized: bool,
        injected: String,
        then: Option<&str>,
    ) {
        let (output, log) = reverie_ptrace::testing::test_fn_with_config::<SteppedInjection, _>(
            || uninterrupted_guest(case),
            serialized,
            true,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "the guest failed: {:?}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected = vec![injected];
        expected.extend(then.map(str::to_owned));
        assert_eq!(*log.seen.lock().unwrap(), expected);
    }
}
