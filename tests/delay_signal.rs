/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! tests for delaying signal delivery
//! SIGALRM: suppressed
//! SIGVTALRM: delayed about 500ms, then delivered
//! SIGSYS: delayed till next syscall.
//!
//! NB: restarted syscalls should not count, as syscall
//! returning ERESTARTSYS could be automatically restarted

use nix::sys::signal::{self, Signal};
use reverie::{
    syscalls::{Errno, Syscall, SyscallInfo, Sysno, Tgkill},
    Error, Guest, Tool,
};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

const GAP_MS: u64 = 500;

#[derive(Debug, Serialize, Deserialize, Default)]
struct ThreadState {
    sigpending: Option<i32>,
    injected_signal: Option<i32>,
}

// syscall is interrupted and may restart
fn is_syscall_restarted(errno: Errno) -> bool {
    [
        Errno::ERESTARTSYS,
        Errno::ERESTARTNOINTR,
        Errno::ERESTARTNOHAND,
        Errno::ERESTART_RESTARTBLOCK,
    ]
    .contains(&errno)
}

#[reverie::tool]
impl Tool for LocalState {
    type ThreadState = ThreadState;
    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: signal::Signal,
    ) -> Result<Option<signal::Signal>, Errno> {
        Ok(if signal == Signal::SIGVTALRM {
            sleep(Duration::from_millis(GAP_MS)).await;
            Some(signal)
        } else if signal == Signal::SIGALRM {
            None // Suppress the signal.
        } else if signal == Signal::SIGSYS {
            eprintln!(
                "[pid = {}] delay delivery of signal {:?}, thread_state {:?}",
                guest.tid(),
                signal,
                guest.thread_state(),
            );
            match guest.thread_state_mut().injected_signal.take() {
                None => {
                    guest.thread_state_mut().sigpending = Some(signal as i32);
                    None
                }
                Some(sig) => {
                    guest.thread_state_mut().sigpending = None;
                    Some(Signal::try_from(sig).unwrap())
                }
            }
        } else {
            println!("[pid = {}] deliverying signal {:?}", guest.tid(), signal);
            Some(signal)
        })
    }
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let pending = guest.thread_state().sigpending;
        if pending.is_some() {
            eprintln!(
                "[pid = {}] syscall {:?} pending signal {:?}",
                guest.tid(),
                syscall,
                pending,
            );
        }

        if [
            Sysno::exit_group,
            Sysno::exit,
            Sysno::execve,
            Sysno::execveat,
        ]
        .contains(&syscall.number())
        {
            eprintln!("[pid = {}] tail injecting {:?}", guest.tid(), syscall);
            guest.tail_inject(syscall).await
        } else {
            eprintln!("[pid = {}] injecting {:?}", guest.tid(), syscall);
            let res = guest.inject(syscall).await;
            if let Some(sig) = pending {
                // NB: don't do signal delivery if syscall is interrupted
                // and restarted.
                if res.is_ok() || res.is_err() && is_syscall_restarted(res.unwrap_err()) {
                    eprintln!(
                        "[pid = {}] injecting tgkill to deliver signal {:?}",
                        guest.tid(),
                        sig
                    );
                    let send_signal = Tgkill::new()
                        .with_tgid(guest.pid().as_raw())
                        .with_tid(guest.tid().as_raw())
                        .with_sig(sig);
                    guest.thread_state_mut().injected_signal = Some(sig);
                    let _ = guest.inject(send_signal).await;
                }
            }
            Ok(res?)
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use reverie::ExitStatus;
    use reverie_ptrace::testing::{check_fn, test_fn};
    use std::{io, mem::MaybeUninit, sync::mpsc, thread, time};

    // kernel_sigset_t used by naked syscall
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct KernelSigset(u64);

    impl From<&[Signal]> for KernelSigset {
        fn from(signals: &[Signal]) -> Self {
            let mut set: u64 = 0;
            for &sig in signals {
                set |= 1u64 << (sig as usize - 1);
            }
            KernelSigset(set)
        }
    }

    #[allow(dead_code)]
    unsafe fn block_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        let set = KernelSigset::from(signals);
        let mut oldset: MaybeUninit<u64> = MaybeUninit::uninit();

        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &set as *const _,
            oldset.as_mut_ptr(),
            8,
        ) != 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(KernelSigset(oldset.assume_init()))
        }
    }

    // unblock signal(s) and set its handler to SIG_DFL
    unsafe fn unblock_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        let set = KernelSigset::from(signals);
        let mut oldset: MaybeUninit<u64> = MaybeUninit::uninit();

        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_UNBLOCK,
            &set as *const _,
            oldset.as_mut_ptr(),
            8,
        ) != 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(KernelSigset(oldset.assume_init()))
        }
    }

    unsafe fn restore_sig_handlers(signals: &[Signal]) -> io::Result<()> {
        for &sig in signals {
            libc::signal(sig as i32, libc::SIG_DFL);
        }
        Ok(())
    }

    #[no_mangle]
    extern "C" fn sigprof_handler(
        _sig: i32,
        _siginfo: *mut libc::siginfo_t,
        _ucontext: *const libc::c_void,
    ) {
        nix::unistd::write(2, b"caught SIGPROF!").unwrap();
        unsafe {
            libc::syscall(libc::SYS_exit_group, 0);
        }
    }

    unsafe fn install_sigprof_handler() -> i32 {
        let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
        sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO | libc::SA_NODEFER;
        sa.sa_sigaction = sigprof_handler as _;

        libc::sigaction(libc::SIGPROF, &sa as *const _, std::ptr::null_mut())
    }

    unsafe fn sigtimedwait(signals: &[Signal], timeout_ns: u64) -> io::Result<Signal> {
        let mut siginfo: MaybeUninit<libc::siginfo_t> = MaybeUninit::zeroed();
        let sigset = KernelSigset::from(signals);
        let timeout = libc::timespec {
            tv_sec: timeout_ns as i64 / 1000000000,
            tv_nsec: (timeout_ns % 1000000000) as i64,
        };

        match Signal::try_from(libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &sigset as *const _,
            siginfo.as_mut_ptr(),
            &timeout as *const _,
            8,
        ) as i32)
        {
            Ok(sig) => {
                let siginfo = siginfo.assume_init();
                assert_eq!(siginfo.si_signo, sig as i32);
                Ok(sig)
            }
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    unsafe fn sigsuspend(signals: &[Signal]) -> io::Result<()> {
        let mut set: u64 = 0;
        for &sig in signals {
            set |= 1u64 << (sig as usize - 1);
        }

        libc::syscall(libc::SYS_rt_sigsuspend, &set as *const _, 8);
        // always return Err.
        Err(io::Error::last_os_error())
    }

    // set timer with SIGPROF as signal
    unsafe fn settimer(time_us: u64) -> io::Result<()> {
        let zero = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };

        let mut next = libc::timeval {
            tv_sec: time_us as i64 / 1000000,
            tv_usec: time_us as i64 % 1000000,
        };

        if next.tv_usec > 1000000 {
            next.tv_sec += 1;
            next.tv_usec -= 1000000;
        }

        let timer_val = libc::itimerval {
            it_interval: zero,
            it_value: next,
        };

        if libc::syscall(
            libc::SYS_setitimer,
            libc::ITIMER_PROF,
            &timer_val as *const _,
            0,
        ) != 0
        {
            eprintln!("setitimer returned error: {:?}", io::Error::last_os_error());
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[test]
    fn signal_delay_500ms() {
        check_fn::<LocalState, _>(|| {
            assert!(unsafe { restore_sig_handlers(&[Signal::SIGVTALRM]) }.is_ok());
            assert!(unsafe { unblock_signals(&[Signal::SIGVTALRM]) }.is_ok());
            unsafe {
                libc::signal(libc::SIGVTALRM, libc::SIG_IGN)
            };
            let now = time::Instant::now();
            thread::sleep(time::Duration::from_millis(10));
            assert!(signal::raise(Signal::SIGVTALRM).is_ok());
            assert!(now.elapsed().as_millis() >= GAP_MS as u128 + 10);
        });
    }

    #[test]
    // signal is suppressed by handle_signal_event
    fn signal_suppress() {
        check_fn::<LocalState, _>(|| {
            assert!(unsafe { restore_sig_handlers(&[Signal::SIGALRM]) }.is_ok());
            assert!(unsafe { unblock_signals(&[Signal::SIGALRM]) }.is_ok());
            let now = time::Instant::now();
            thread::sleep(time::Duration::from_millis(10));
            assert!(signal::raise(Signal::SIGALRM).is_ok());
            assert!(now.elapsed().as_millis() < GAP_MS as u128);
        });
    }

    #[test]
    fn sigtimedwait_sanity() {
        check_fn::<LocalState, _>(|| {
            let (sender, receiver) = mpsc::channel();
            let handle = thread::spawn(move || {
                assert!(sender.send(nix::unistd::gettid()).is_ok());
                unsafe {
                    libc::signal(libc::SIGBUS, libc::SIG_DFL)
                };
                assert_eq!(
                    unsafe { sigtimedwait(&[Signal::SIGBUS], 1000000000000u64) }.unwrap(),
                    Signal::SIGBUS,
                );
                eprintln!("[thread] sigtimedwait returned SIGBUS");
            });

            let thread_id = receiver.recv().unwrap();
            // wait until thread is blocked by rt_sigtimedwait..
            thread::sleep(Duration::from_millis(500));
            let signal_sent = unsafe {
                libc::syscall(libc::SYS_tkill, thread_id.as_raw(), Signal::SIGBUS as i32)
            };
            assert_eq!(signal_sent, 0);
            assert!(handle.join().is_ok());
        });
    }

    #[test]
    fn sigsuspend_sanity() {
        let (output, _) = test_fn::<LocalState, _>(|| {
            let (sender, receiver) = mpsc::channel();
            let handle = thread::spawn(move || {
                assert!(sender.send(nix::unistd::gettid()).is_ok());
                unsafe {
                    libc::signal(libc::SIGBUS, libc::SIG_DFL)
                };
                assert_eq!(
                    unsafe { sigsuspend(&[]) }
                        .err()
                        .and_then(|e| e.raw_os_error()),
                    Some(libc::EINTR)
                );
            });

            let thread_id = receiver.recv().unwrap();
            // wait until thread is blocked by rt_sigtimedwait..
            thread::sleep(Duration::from_millis(500));
            let signal_sent = unsafe {
                libc::syscall(libc::SYS_tkill, thread_id.as_raw(), Signal::SIGBUS as i32)
            };
            assert_eq!(signal_sent, 0);
            assert!(handle.join().is_ok());
        })
        .unwrap();
        assert_eq!(output.status, ExitStatus::Signaled(Signal::SIGBUS, true));
    }

    #[test]
    // A sanity check ITIMER_PROF can indeed cause program to exit with SIGPROF
    // NB: rust runtime masks most signals, hence SIGPROF has to be explicitly
    // unmasked.
    fn sigprof_sanity() {
        check_fn::<LocalState, _>(|| {
            assert_eq!(unsafe { install_sigprof_handler() }, 0);
            // timer should expire
            assert!(unsafe { unblock_signals(&[Signal::SIGPROF]) }.is_ok());
            assert!(unsafe { settimer(100000) }.is_ok());
            loop {}
        });
    }

    #[test]
    // SIGSYS is delayed till next syscall is trapped. However, since we send
    // SIGSYS when rt_sigsuspend is called, rt_sigsuspend won't return because
    // the signal is delayed till next syscall. Which causes this test to timeout
    // pease note this is expected behavior. Showing we cannot assume signal
    // delivery can be always delayed.
    fn sigsuspend_delay_till_next_syscall_should_timeout_1() {
        check_fn::<LocalState, _>(|| {
            let (sender, receiver) = mpsc::channel();
            let _handle = thread::spawn(move || {
                assert!(sender.send(nix::unistd::gettid()).is_ok());
                unsafe {
                    libc::signal(libc::SIGSYS, libc::SIG_DFL)
                };

                assert_eq!(
                    unsafe { sigsuspend(&[Signal::SIGPROF, Signal::SIGVTALRM]) }
                        .err()
                        .and_then(|e| e.raw_os_error()),
                    Some(libc::EINTR)
                );
            });

            let thread_id = receiver.recv().unwrap();
            // wait until thread is blocked by rt_sigtimedwait..
            thread::sleep(Duration::from_millis(500));
            let signal_sent = unsafe {
                libc::syscall(libc::SYS_tkill, thread_id.as_raw(), Signal::SIGSYS as i32)
            };
            assert_eq!(signal_sent, 0);

            assert!(unsafe { restore_sig_handlers(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());

            assert_eq!(unsafe { install_sigprof_handler() }, 0);

            // timer should expire
            assert!(unsafe { unblock_signals(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());
            assert!(unsafe { settimer(500000) }.is_ok());
            loop { /* sigprof handler calls exit_group */ }
        });
    }

    #[test]
    // similar to sigsuspend_delay_till_next_syscall_should_timeout_1, but this test
    // only has one line difference compare to sigsuspend_delay_till_next_syscall_should_pass
    // to emphasis SIGSYS is indeeded not delivered without the extra syscall after tgkill.
    // because we delay SIGSYS delivery to next syscall.
    fn sigsuspend_delay_till_next_syscall_should_timeout_2() {
        check_fn::<LocalState, _>(|| {
            let (sender, receiver) = mpsc::channel();
            let _handle = thread::spawn(move || {
                let tid = nix::unistd::gettid();
                let pid = nix::unistd::getpid();
                assert!(sender.send(tid).is_ok());
                unsafe {
                    libc::signal(libc::SIGSYS, libc::SIG_DFL);
                };

                // block SIGPROF as the parent task is setting up a timer
                // with ITIMER_PROF. Linux does not guarantee which thread
                // receive the signal. As a result, we simply mask SIGPROF
                // in this thread, so that only parent task can receive it.
                assert!(unsafe { block_signals(&[Signal::SIGPROF]) }.is_ok());
                assert!(unsafe { unblock_signals(&[Signal::SIGSYS]) }.is_ok());
                assert_eq!(
                    unsafe { sigtimedwait(&[Signal::SIGSYS], 1000_000_000) }.ok(),
                    Some(Signal::SIGSYS)
                );

                unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        pid.as_raw(),
                        tid.as_raw(),
                        Signal::SIGSYS as i32,
                    );
                    // expected to timeout, because we delay signal delivery to next
                    // syscall which returns success
                    loop {}
                }
            });

            let thread_id = receiver.recv().unwrap();
            // wait until thread is blocked by rt_sigtimedwait..
            thread::sleep(Duration::from_millis(100));
            let signal_sent = unsafe {
                libc::syscall(libc::SYS_tkill, thread_id.as_raw(), Signal::SIGSYS as i32)
            };
            assert_eq!(signal_sent, 0);

            assert!(unsafe { restore_sig_handlers(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());

            assert_eq!(unsafe { install_sigprof_handler() }, 0);

            // timer should expire
            assert!(unsafe { unblock_signals(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());
            assert!(unsafe { settimer(500000) }.is_ok());

            loop {}
        });
    }

    #[test]
    // since we delay SIGSYS till next syscall, adding a syscall like getsid should
    // cause SIGSYS to be delivered, hence the program should be killed by SIGSYS.
    fn sigsuspend_delay_till_next_syscall_should_pass() {
        let (output, _) = test_fn::<LocalState, _>(|| {
            let (sender, receiver) = mpsc::channel();
            let _handle = thread::spawn(move || {
                let tid = nix::unistd::gettid();
                let pid = nix::unistd::getpid();
                assert!(sender.send(tid).is_ok());
                unsafe {
                    libc::signal(libc::SIGSYS, libc::SIG_DFL);
                };

                assert!(unsafe { unblock_signals(&[Signal::SIGSYS]) }.is_ok());
                assert_eq!(
                    unsafe { sigtimedwait(&[Signal::SIGSYS], 1000_000_000) }.ok(),
                    Some(Signal::SIGSYS)
                );

                unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        pid.as_raw(),
                        tid.as_raw(),
                        Signal::SIGSYS as i32,
                    );
                    // signal should delivered after SYS_getsid returned
                    // hence the program should be killed by SIGSYS
                    libc::syscall(libc::SYS_getsid);

                    // will run into SIGSYS handler (SIG_DFL) hence below
                    // statement is not reachable.
                    unreachable!()
                }
            });

            let thread_id = receiver.recv().unwrap();
            // wait until thread is blocked by rt_sigtimedwait..
            thread::sleep(Duration::from_millis(100));
            let signal_sent = unsafe {
                libc::syscall(libc::SYS_tkill, thread_id.as_raw(), Signal::SIGSYS as i32)
            };
            assert_eq!(signal_sent, 0);

            assert!(unsafe { restore_sig_handlers(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());

            assert_eq!(unsafe { install_sigprof_handler() }, 0);

            assert!(unsafe { unblock_signals(&[Signal::SIGPROF, Signal::SIGVTALRM]) }.is_ok());
            assert!(unsafe { settimer(500000) }.is_ok());

            // SIGSYS handler (SIG_DFL) should be called before timer expire
            unreachable!()
        })
        .unwrap();
        assert_eq!(output.status, ExitStatus::Signaled(Signal::SIGSYS, true));
    }
}
