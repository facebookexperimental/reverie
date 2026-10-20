/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(feature = "notifier", target_arch = "x86_64"))]

use std::future::Future;
use std::io::Read;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use safeptrace::Errno;
use safeptrace::Error;
use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::Options;
use safeptrace::OwnedWaitFuture;
use safeptrace::Pid;
use safeptrace::Running;
use safeptrace::Stopped;

const LIMIT: Duration = Duration::from_secs(2);
type ExitWait = Pin<Box<dyn Future<Output = Result<Stopped, Error>> + Send>>;

#[derive(Clone, Copy, Debug)]
enum WaitKind {
    Owned,
    Convenience,
}

enum ReturnedStop {
    Actual(Stopped),
    RetryOwned(OwnedWaitFuture),
    CleanupConvenience,
}

enum ReturnedExit {
    Actual(Stopped),
    Retry(ExitWait),
}

fn pipe() -> [OwnedFd; 2] {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

fn until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + LIMIT;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "sibling control deadline expired"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

struct RootCleanup {
    root: i32,
    pidfd: OwnedFd,
    reaped: bool,
}

impl RootCleanup {
    fn reap(&mut self) {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        assert!(rc == 0 || Errno::last() == Errno::ESRCH);
        let mut status = 0;
        until(|| {
            let waited = unsafe { libc::waitpid(self.root, &mut status, libc::WNOHANG) };
            assert!(waited == 0 || waited == self.root);
            waited == self.root
        });
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        self.reaped = true;
    }
}

impl Drop for RootCleanup {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            let deadline = Instant::now() + LIMIT;
            let mut status = 0;
            while Instant::now() < deadline {
                let waited = unsafe { libc::waitpid(self.root, &mut status, libc::WNOHANG) };
                if waited == self.root || waited == -1 {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

fn guest() -> (Pid, Pid, OwnedFd, RootCleanup) {
    let [receipt, send_receipt] = pipe();
    let [start, release] = pipe();
    let root = unsafe { libc::fork() };
    assert!(root >= 0);
    if root == 0 {
        unsafe {
            libc::close(receipt.as_raw_fd());
            libc::close(release.as_raw_fd());
        }
        extern "C" fn member(argument: *mut libc::c_void) -> *mut libc::c_void {
            let descriptors = unsafe { &*argument.cast::<[i32; 2]>() };
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            if unsafe { libc::write(descriptors[0], (&tid as *const i32).cast(), 4) } != 4 {
                unsafe { libc::_exit(125) };
            }
            let mut byte = 0u8;
            if unsafe { libc::read(descriptors[1], (&mut byte as *mut u8).cast(), 1) } != 1 {
                unsafe { libc::_exit(126) };
            }
            unsafe { libc::syscall(libc::SYS_exit, 23) };
            std::ptr::null_mut()
        }
        let mut descriptors = [send_receipt.as_raw_fd(), start.as_raw_fd()];
        let mut member_thread = mem::MaybeUninit::<libc::pthread_t>::uninit();
        if unsafe {
            libc::pthread_create(
                member_thread.as_mut_ptr(),
                std::ptr::null(),
                member,
                descriptors.as_mut_ptr().cast(),
            )
        } != 0
        {
            unsafe { libc::_exit(127) };
        }
        loop {
            unsafe { libc::pause() };
        }
    }
    drop((send_receipt, start));
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, root, 0) };
    assert!(pidfd >= 0);
    let cleanup = RootCleanup {
        root,
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd as i32) },
        reaped: false,
    };
    let mut readiness = libc::pollfd {
        fd: receipt.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut readiness, 1, LIMIT.as_millis() as i32) },
        1
    );
    let mut bytes = [0u8; 4];
    std::fs::File::from(receipt).read_exact(&mut bytes).unwrap();
    let member = Pid::from_raw(i32::from_ne_bytes(bytes));
    assert_ne!(member.as_raw(), root);
    (Pid::from_raw(root), member, release, cleanup)
}

fn observe_physical_stop(pid: Pid, event: i32) {
    // An owning ptrace observation only: this performs no wait, notifier
    // assistance, FIFO consumption or exit-epoch claim on the idle owner.
    until(|| {
        let mut info = mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETSIGINFO,
                pid.as_raw(),
                std::ptr::null_mut::<libc::c_void>(),
                info.as_mut_ptr(),
            )
        };
        if rc == -1 {
            assert_eq!(Errno::last(), Errno::ESRCH);
            return false;
        }
        let info = unsafe { info.assume_init() };
        info.si_signo == libc::SIGTRAP && info.si_code == (libc::SIGTRAP | (event << 8))
    });
}

#[tokio::test(flavor = "current_thread")]
async fn sibling_only_polling_preserves_public_wait_contract() {
    let sibling_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    let mut outcomes = Vec::new();
    for kind in [WaitKind::Owned, WaitKind::Convenience] {
        let (root, member, release, mut cleanup) = guest();
        let (initial_tx, initial_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = mpsc::sync_channel(1);
        let (exit_tx, exit_rx) = mpsc::sync_channel(1);
        let (return_exit_tx, return_exit_rx) = mpsc::sync_channel(1);
        let owner = thread::spawn(move || {
            let owner_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let options = Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_EXITKILL;
            let running = Running::seize(member, options).unwrap();
            let terminal = running.terminal_cleanup();
            terminal.ensure_registered().unwrap();
            let sibling_terminal = running.terminal_cleanup();
            assert!(terminal.same_generation(&sibling_terminal));
            running.interrupt().unwrap();
            observe_physical_stop(member, libc::PTRACE_EVENT_STOP);
            initial_tx
                .send((running, sibling_terminal, owner_tid))
                .unwrap();
            // The owner remains alive and idle during the sibling's entire
            // wait. It assists only after a recorded refusal returns here.
            let stopped = match stop_rx.recv_timeout(LIMIT).unwrap() {
                ReturnedStop::Actual(stopped) => stopped,
                ReturnedStop::RetryOwned(mut wait) => runtime.block_on(async {
                    tokio::time::timeout(LIMIT, &mut wait)
                        .await
                        .unwrap()
                        .unwrap()
                        .assume_stopped()
                        .0
                }),
                ReturnedStop::CleanupConvenience => {
                    let reservation = terminal.reserve_pending_for_cleanup(LIMIT).unwrap();
                    let (stopped, event) = reservation.decode().unwrap().assume_stopped();
                    assert_eq!(event, Event::Stop);
                    reservation.commit();
                    stopped
                }
            };
            assert_eq!(stopped.pid(), member);
            assert_eq!(
                stopped.getsiginfo().unwrap().si_code,
                libc::SIGTRAP | (libc::PTRACE_EVENT_STOP << 8)
            );
            // Exercise both public ExitFuture constructors without any
            // sibling ptrace request or NewChild/Exec status decoder.
            let stopped_exit = match kind {
                WaitKind::Owned => Some(Box::pin(stopped.exit_event()) as ExitWait),
                WaitKind::Convenience => None,
            };
            let running = stopped.resume(None).unwrap();
            let exit = stopped_exit.unwrap_or_else(|| Box::pin(running.exit_event()));
            drop(running);
            assert_eq!(
                unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
                1
            );
            observe_physical_stop(member, libc::PTRACE_EVENT_EXIT);
            exit_tx.send(exit).unwrap();
            let stopped = match return_exit_rx.recv_timeout(LIMIT).unwrap() {
                ReturnedExit::Actual(stopped) => stopped,
                ReturnedExit::Retry(mut exit) => runtime.block_on(async {
                    tokio::time::timeout(LIMIT, &mut exit)
                        .await
                        .unwrap()
                        .unwrap()
                }),
            };
            assert_eq!(stopped.pid(), member);
            assert_eq!(stopped.getevent().unwrap(), 23 << 8);
            let final_wait = runtime.block_on(async {
                tokio::time::timeout(LIMIT, stopped.resume(None).unwrap().wait_owned())
                    .await
                    .unwrap()
                    .unwrap()
            });
            assert_eq!(final_wait.assume_exited(), (member, ExitStatus::Exited(23)));
            assert!(terminal.wait(LIMIT));
            (owner_tid, terminal.observed_exit_status().unwrap())
        });
        let (running, terminal, owner_tid) = initial_rx.recv_timeout(LIMIT).unwrap();
        assert_ne!(owner_tid, sibling_tid);
        let stop_result = match kind {
            WaitKind::Owned => {
                let mut wait = running.wait_owned();
                match tokio::time::timeout(LIMIT, &mut wait).await.unwrap() {
                    Ok(waited) => {
                        let (stopped, event) = waited.assume_stopped();
                        assert_eq!(event, Event::Stop);
                        stop_tx.send(ReturnedStop::Actual(stopped)).unwrap();
                        Ok(())
                    }
                    Err(error) => {
                        let result = Err(format!("{error:?}"));
                        stop_tx.send(ReturnedStop::RetryOwned(wait)).unwrap();
                        result
                    }
                }
            }
            WaitKind::Convenience => match tokio::time::timeout(LIMIT, running.next_state())
                .await
                .unwrap()
            {
                Ok(waited) => {
                    let (stopped, event) = waited.assume_stopped();
                    assert_eq!(event, Event::Stop);
                    stop_tx.send(ReturnedStop::Actual(stopped)).unwrap();
                    Ok(())
                }
                Err(error) => {
                    let result = Err(format!("{error:?}"));
                    stop_tx.send(ReturnedStop::CleanupConvenience).unwrap();
                    result
                }
            },
        };
        let mut exit = exit_rx.recv_timeout(LIMIT).unwrap();
        let exit_result = match tokio::time::timeout(LIMIT, &mut exit).await.unwrap() {
            Ok(stopped) => {
                return_exit_tx.send(ReturnedExit::Actual(stopped)).unwrap();
                Ok(())
            }
            Err(error) => {
                return_exit_tx.send(ReturnedExit::Retry(exit)).unwrap();
                Err(format!("{error:?}"))
            }
        };
        let (confirmed_owner, terminal_status) = owner.join().unwrap();
        assert_eq!(confirmed_owner, owner_tid);
        assert_eq!(terminal_status, Some(ExitStatus::Exited(23)));
        assert!(terminal.wait(LIMIT));
        assert_eq!(
            terminal.observed_exit_status().unwrap(),
            Some(ExitStatus::Exited(23))
        );
        cleanup.reap();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{member}")).exists());
        println!(
            "SIBLING_CONTRACT kind={kind:?} owner={owner_tid} sibling={sibling_tid} owner_idle=true stop={stop_result:?} exit={exit_result:?} actual_exit=23 done=true root_reaped=true member_absent=true"
        );
        outcomes.push((kind, stop_result, exit_result));
    }
    assert!(
        outcomes
            .iter()
            .all(|(_, stop, exit)| stop.is_ok() && exit.is_ok()),
        "public sibling polling lost availability: {outcomes:?}"
    );
}
