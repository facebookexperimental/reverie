/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// The premise behind the reapers' terminal checks: a thread's zombie can be
/// reaped with a different status from the one a `WNOWAIT` wait reported.
/// Linux's `wait_task_zombie` reports `signal->group_exit_code` once the
/// thread group has `SIGNAL_GROUP_EXIT`, and the thread's own `exit_code`
/// before that. So a thread that exits 0 and is observed, after which another
/// thread of its group calls `exit_group(11)`, is reaped as exited 11. A
/// guest that joins a helper thread and then exits does exactly that, since
/// the join returns at the helper's `CLONE_CHILD_CLEARTID`, before its
/// tracer reaps it; asserting the two statuses equal made the tracer panic
/// (https://github.com/rrnewton/reverie/issues/973).
#[cfg(target_arch = "x86_64")]
mod group_exit_status {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    const NAME: &str =
        "notifier::test::group_exit_status::reaped_status_follows_a_later_group_exit";
    const ROLE: &str = "SAFEPTRACE_GROUP_EXIT_STATUS_GUEST";
    /// Precedes the guest's TIDs. libtest prints `test <name> ... ` without a
    /// newline before a `--nocapture` test runs, so they share its line.
    const TIDS: &str = "SAFEPTRACE_GROUP_EXIT_TIDS";

    /// The traced child: a helper thread returns its TID and exits 0. After
    /// the join, this thread writes the helper's TID and its own, waits for
    /// one byte, then calls `exit_group(11)`.
    fn guest() -> ! {
        let helper = std::thread::spawn(|| unsafe { libc::gettid() })
            .join()
            .unwrap();
        let caller = unsafe { libc::gettid() };
        let mut stdout = std::io::stdout();
        writeln!(stdout, "{TIDS} {helper} {caller}").unwrap();
        stdout.flush().unwrap();
        let mut byte = [0u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        unsafe { libc::_exit(11) }
    }

    fn waitid(id: libc::id_t, idtype: libc::idtype_t, flags: libc::c_int) -> libc::siginfo_t {
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe { libc::waitid(idtype, id, &mut info, flags) } == 0 {
                return info;
            }
            let errno = std::io::Error::last_os_error();
            assert_eq!(errno.raw_os_error(), Some(libc::EINTR), "waitid: {errno}");
        }
    }

    fn exit_code(info: &libc::siginfo_t) -> Option<i32> {
        (info.si_code == libc::CLD_EXITED).then(|| unsafe { info.si_status() })
    }

    /// Consumes the stop of `pid` and resumes it, passing on only a signal
    /// that is not ptrace's own (a new thread's SIGSTOP, an exec SIGTRAP, or
    /// an event stop).
    fn resume_stop(pid: libc::pid_t) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::__WALL) },
            pid
        );
        assert!(libc::WIFSTOPPED(status), "{pid}: {status:#x}");
        let signal = libc::WSTOPSIG(status);
        let deliver = if status >> 16 != 0 || signal == libc::SIGSTOP || signal == libc::SIGTRAP {
            0
        } else {
            signal
        };
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, deliver) },
            0
        );
    }

    #[test]
    fn reaped_status_follows_a_later_group_exit() {
        if std::env::var(ROLE).as_deref() == Ok(NAME) {
            guest();
        }
        let mut child = unsafe {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
                .env(ROLE, NAME)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                // Its own process group, so this test waits only for it.
                .pre_exec(|| {
                    if libc::setpgid(0, 0) == 0 && libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                })
                .spawn()
                .unwrap()
        };
        let leader = child.id() as libc::pid_t;
        let group = leader as libc::id_t;
        // The exec stop. Trace new threads, report exits as event stops, and
        // kill the child if this test fails.
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(leader, &mut status, 0) }, leader);
        assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP);
        let options = libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_EXITKILL;
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, leader, 0, options) },
            0
        );
        assert_eq!(unsafe { libc::ptrace(libc::PTRACE_CONT, leader, 0, 0) }, 0);

        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        std::thread::scope(|scope| {
            let reader = scope.spawn(move || loop {
                let mut line = String::new();
                assert_ne!(
                    std::io::BufRead::read_line(&mut stdout, &mut line).unwrap(),
                    0,
                    "the guest wrote no TIDs"
                );
                if let Some((_, ids)) = line.split_once(TIDS) {
                    break ids.trim().to_owned();
                }
            });
            // Resume every stop until the helper's zombie is reported. A
            // WNOWAIT wait leaves it unreaped.
            let observed = loop {
                let info = waitid(
                    group,
                    libc::P_PGID,
                    libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT | libc::__WALL,
                );
                let pid = unsafe { info.si_pid() };
                if info.si_code == libc::CLD_TRAPPED || info.si_code == libc::CLD_STOPPED {
                    resume_stop(pid);
                    continue;
                }
                assert_ne!(pid, leader, "the leader exited first: {}", info.si_code);
                break (pid, exit_code(&info));
            };
            let line = reader.join().unwrap();
            let (helper, caller) = line.trim().split_once(' ').unwrap();
            let (helper, caller): (libc::pid_t, libc::pid_t) =
                (helper.parse().unwrap(), caller.parse().unwrap());
            assert_eq!(observed, (helper, Some(0)), "the helper's own exit status");

            // Let the caller exit_group(11), and wait for its own exit event
            // stop: exit_group sets SIGNAL_GROUP_EXIT before the caller exits.
            child.stdin.take().unwrap().write_all(b"x").unwrap();
            loop {
                let info = waitid(group, libc::P_PGID, libc::WSTOPPED | libc::WNOWAIT | libc::__WALL);
                let pid = unsafe { info.si_pid() };
                let event = unsafe { info.si_status() } >> 8;
                if pid == caller && event == libc::PTRACE_EVENT_EXIT {
                    break;
                }
                resume_stop(pid);
            }

            let reaped = waitid(helper as libc::id_t, libc::P_PID, libc::WEXITED | libc::__WALL);
            assert_eq!(
                exit_code(&reaped),
                Some(11),
                "the reap reports the group's exit code, not the observed 0"
            );
        });
        // Let the group finish exiting and reap the leader.
        assert_eq!(unsafe { libc::kill(leader, libc::SIGKILL) }, 0);
        loop {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-leader, &mut status, libc::__WALL) };
            if pid == leader && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                break;
            }
            if pid > 0 && libc::WIFSTOPPED(status) {
                unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) };
            }
        }
    }
}
