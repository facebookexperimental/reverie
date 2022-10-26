/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Provide `waitid` which is based on `SYS_waitid` syscall.
//! `SYS_waitid` provide `WNOWAIT` flag which is absent in `SYS_waitpid`.
//! compare to `waitpid`, flags *must* be explicitly provided.
//! which could be a combination (bitwise-or) of `WEXITED`, `WSTOPPED`,
//! `WCONTINUED`, `WNOHANG` and `WNOWAIT`. see `waitid(2)` for more details.
//! NB: `waitid` here provide a similar interface as `nix`'s `waitpid`.

use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

use nix::sys::signal::Signal;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

use super::Errno;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IdType {
    Pid(Pid),
    Pgid(Pid),
    #[allow(unused)]
    Pidfd(RawFd), // this requires linux kernel >= 5.4
    All,
}

#[inline]
fn si_status_signal(info: &libc::siginfo_t) -> Signal {
    let status = unsafe { info.si_status() };
    // The status can sometimes be 0 when using PTRACE_SEIZE, so we report a
    // bogus SIGSTOP instead.
    Signal::try_from(status & 0xff).unwrap_or(Signal::SIGSTOP)
}

#[inline]
fn si_status_event(info: &libc::siginfo_t) -> i32 {
    (unsafe { info.si_status() } >> 8) as i32
}

/// Returns the raw siginfo from a waitid call.
fn waitid_si(waitid_type: IdType, flags: WaitPidFlag) -> Result<libc::siginfo_t, Errno> {
    let mut siginfo = MaybeUninit::<libc::siginfo_t>::zeroed();
    let siginfo_ptr: *mut libc::siginfo_t = siginfo.as_mut_ptr();

    let (id_type, pid_or_pidfd) = match waitid_type {
        IdType::Pid(pid) => (libc::P_PID, pid.as_raw()),
        IdType::Pgid(pid) => (libc::P_PGID, pid.as_raw()),
        IdType::Pidfd(raw_fd) => (libc::P_PIDFD, raw_fd),
        IdType::All => (libc::P_ALL, -1),
    };

    Errno::result(unsafe {
        libc::waitid(
            id_type,
            pid_or_pidfd as libc::id_t,
            siginfo_ptr,
            flags.bits(),
        )
    })?;

    Ok(unsafe { siginfo.assume_init() })
}

/// `waitpid` implemented with `waitid`. `waitid` has fewer limitations than `waitpid`.
pub fn waitpid(pid: Pid, flags: WaitPidFlag) -> Result<Option<i32>, Errno> {
    let si = waitid_si(IdType::Pid(pid), flags)?;

    if unsafe { si.si_pid() } == 0 {
        // Still alive.
        return Ok(None);
    }

    Ok(Some(siginfo_to_status(si)))
}

// Converts a siginfo to a more compact status code.
fn siginfo_to_status(si: libc::siginfo_t) -> i32 {
    let si_status = unsafe { si.si_status() };

    let status = match si.si_code {
        libc::CLD_EXITED => si_status << 8,
        libc::CLD_KILLED => si_status & 0x7f,
        libc::CLD_DUMPED => (si_status | 0x80) & 0xff,
        libc::CLD_TRAPPED => (si_status << 8) | 0x7f,
        libc::CLD_STOPPED => si_status << 8,
        libc::CLD_CONTINUED => 0xffff,
        other => panic!("unexpected si_code: {}", other),
    };

    debug_assert_eq!(
        siginfo_to_waitstatus(si),
        WaitStatus::from_raw(Pid::from_raw(unsafe { si.si_pid() }), status).unwrap()
    );

    status
}

fn siginfo_to_waitstatus(si: libc::siginfo_t) -> WaitStatus {
    let pid = Pid::from_raw(unsafe { si.si_pid() });
    match si.si_code {
        libc::CLD_EXITED => WaitStatus::Exited(pid, unsafe { si.si_status() }),
        libc::CLD_KILLED => WaitStatus::Signaled(pid, si_status_signal(&si), false),
        libc::CLD_DUMPED => WaitStatus::Signaled(pid, si_status_signal(&si), true),
        libc::CLD_STOPPED => WaitStatus::Stopped(pid, si_status_signal(&si)),
        libc::CLD_TRAPPED if unsafe { si.si_status() } == 0x80 | Signal::SIGTRAP as i32 => {
            WaitStatus::PtraceSyscall(pid)
        }
        libc::CLD_TRAPPED => {
            let trap_sig = si_status_signal(&si);
            let event = si_status_event(&si);
            if event == 0 {
                // could return SIGSTOP here for initial ptrace stop
                // right after clone/fork/vfork event.
                WaitStatus::Stopped(pid, trap_sig)
            } else {
                WaitStatus::PtraceEvent(pid, trap_sig, event)
            }
        }
        libc::CLD_CONTINUED => WaitStatus::Continued(pid),
        bad_si_code => panic!("unexpected si_code {} from siginfo_t", bad_si_code),
    }
}

/// waitid as to SYS_waitid.
/// return
///   - Err when syscall returns -1.
///   - OK(WaitStatus::StillAlive) when no state change
///   - OK(WaitStatus::...) when state has changed.
pub fn waitid(waitid_type: IdType, flags: WaitPidFlag) -> Result<WaitStatus, Errno> {
    let siginfo = waitid_si(waitid_type, flags)?;

    if unsafe { siginfo.si_pid() } == 0 {
        Ok(WaitStatus::StillAlive)
    } else {
        Ok(siginfo_to_waitstatus(siginfo))
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitPidFlag;
    use nix::unistd;
    use nix::unistd::ForkResult;

    use super::*;

    #[test]
    fn waitid_w_exited_0() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Exited(child, 0))
                );
            }
            ForkResult::Child => {
                let hundred_millies = std::time::Duration::from_millis(100);
                std::thread::sleep(hundred_millies);
                unsafe { libc::syscall(libc::SYS_exit_group, 0) };
            }
        }
    }

    #[test]
    fn waitid_w_exited_1() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Exited(child, 1))
                );
            }
            ForkResult::Child => {
                let hundred_millies = std::time::Duration::from_millis(100);
                std::thread::sleep(hundred_millies);
                unsafe { libc::syscall(libc::SYS_exit_group, 1) };
            }
        }
    }

    #[test]
    fn waitid_w_killed_by_signal() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert!(nix::sys::signal::kill(child, Signal::SIGINT).is_ok());
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Signaled(child, Signal::SIGINT, false))
                );
            }
            ForkResult::Child => {
                let one_sec = std::time::Duration::from_millis(1000);
                loop {
                    std::thread::sleep(one_sec);
                }
            }
        }
    }

    #[test]
    fn waitid_w_exited_no_wait_then_wait() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(
                        IdType::Pid(child),
                        WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT
                    ),
                    Ok(WaitStatus::Exited(child, 0))
                );
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Exited(child, 0))
                );
            }
            ForkResult::Child => {
                let hundred_millies = std::time::Duration::from_millis(100);
                std::thread::sleep(hundred_millies);
                unsafe { libc::syscall(libc::SYS_exit_group, 0) };
            }
        }
    }

    #[test]
    fn waitid_w_exited_then_echild() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Exited(child, 0))
                );
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Err(Errno::ECHILD)
                );
            }
            ForkResult::Child => {
                let hundred_millies = std::time::Duration::from_millis(100);
                std::thread::sleep(hundred_millies);
                unsafe { libc::syscall(libc::SYS_exit_group, 0) };
            }
        }
    }

    #[test]
    fn waitid_w_nohang_then_kill() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(
                        IdType::Pid(child),
                        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG
                    ),
                    Ok(WaitStatus::StillAlive),
                );
                assert!(nix::sys::signal::kill(child, Signal::SIGINT).is_ok());
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Signaled(child, Signal::SIGINT, false))
                );
            }
            ForkResult::Child => {
                let one_sec = std::time::Duration::from_millis(100);
                loop {
                    std::thread::sleep(one_sec);
                }
            }
        }
    }

    #[test]
    fn waitid_w_nohang_kill_nohang_nowait_wait() {
        let fork_result = unsafe { unistd::fork() };
        assert!(fork_result.is_ok());
        match fork_result.unwrap() {
            ForkResult::Parent { child, .. } => {
                assert_eq!(
                    waitid(
                        IdType::Pid(child),
                        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG
                    ),
                    Ok(WaitStatus::StillAlive),
                );
                assert!(nix::sys::signal::kill(child, Signal::SIGINT).is_ok());
                loop {
                    // this is not very ideal, the loops generally runs 1K - 10K times..
                    let status = waitid(
                        IdType::Pid(child),
                        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                    );
                    assert!(status.is_ok());
                    match status.unwrap() {
                        WaitStatus::StillAlive => {}
                        waitid_nohang_nowait => {
                            assert_eq!(
                                waitid_nohang_nowait,
                                WaitStatus::Signaled(child, Signal::SIGINT, false)
                            );
                            break;
                        }
                    }
                }
                assert_eq!(
                    waitid(IdType::Pid(child), WaitPidFlag::WEXITED),
                    Ok(WaitStatus::Signaled(child, Signal::SIGINT, false))
                );
            }
            ForkResult::Child => {
                let one_sec = std::time::Duration::from_millis(100);
                loop {
                    std::thread::sleep(one_sec);
                }
            }
        }
    }
}
