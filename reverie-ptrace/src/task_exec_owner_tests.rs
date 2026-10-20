/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

#[cfg(target_arch = "x86_64")]
#[test]
fn ordinary_post_exec_wait_retains_ptracer_owner_generation() {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;
    use std::time::Duration;
    use std::time::Instant;

    const CELL_ENV: &str = "REVERIE_POST_EXEC_OWNER_CELL";
    if let Ok(cell) = std::env::var(CELL_ENV) {
        assert!(cell == "normal" || cell == "forced");
        ordinary_post_exec_owner_cell(cell == "forced", false);
        ordinary_post_exec_owner_cell(cell == "forced", true);
        println!("POST_EXEC_OWNER_CELL_PASSED {cell}");
        return;
    }
    let mut all_passed = true;
    for cell in ["normal", "forced"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "task::exec_owner_tests::ordinary_post_exec_wait_retains_ptracer_owner_generation",
                "--exact",
                "--nocapture",
            ])
            .env(CELL_ENV, cell)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                assert_eq!(
                    unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                    0
                );
                let status = child.wait().unwrap();
                eprintln!("post-exec cell {cell} exceeded its 15s bound: {status}");
                break status;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stdout)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .take(65537)
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        println!("post-exec cell {cell}, actual status {status}:\n{stdout}");
        eprintln!("{stderr}");
        let marker = format!("POST_EXEC_OWNER_CELL_PASSED {cell}");
        all_passed &= status.success()
            && stdout.lines().filter(|line| *line == marker).count() == 1
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;");
    }
    assert!(
        all_passed,
        "both actual normal and PIDFD_THREAD-EINVAL cells must pass"
    );
    println!("ACTUAL_ORDINARY_POSTEXEC_OWNER_WAIT_EXERCISED");
}

#[cfg(target_arch = "x86_64")]
fn ordinary_post_exec_owner_cell(force_legacy: bool, unrelated_signal: bool) {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    struct Child(libc::pid_t);
    impl Drop for Child {
        fn drop(&mut self) {
            if self.0 > 0 {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    loop {
                        let mut status = 0;
                        let actual = libc::waitpid(self.0, &mut status, libc::__WALL);
                        if actual == self.0
                            && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                        {
                            break;
                        }
                        if actual < 0 && *libc::__errno_location() != libc::EINTR {
                            break;
                        }
                    }
                }
            }
        }
    }
    // This alarm/filter is confined to the new owned test process, not libtest's shared runner.
    unsafe { libc::alarm(10) };
    let raw = unsafe { libc::fork() };
    assert!(raw >= 0);
    if raw == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 || libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(2);
            }
            libc::execl(
                c"/bin/true".as_ptr(),
                c"/bin/true".as_ptr(),
                std::ptr::null::<libc::c_char>(),
            );
            libc::_exit(3);
        }
    }
    let mut child = Child(raw);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(raw, &mut status, 0) }, raw);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    let options = libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL;
    assert_eq!(
        unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, raw, 0, options) },
        0
    );
    let process_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
    assert!(process_fd >= 0);
    let process_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(process_fd as i32) });
    if force_legacy {
        let insn = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        let filter = [
            insn(0x20, 0, 0, 4),
            insn(0x15, 1, 0, 0xc000_003e),
            insn(0x06, 0, 0, 0x8000_0000),
            insn(0x20, 0, 0, 0),
            insn(0x15, 0, 3, libc::SYS_pidfd_open as u32),
            insn(0x20, 0, 0, 24),
            insn(0x15, 0, 1, libc::O_EXCL as u32),
            insn(0x06, 0, 0, 0x0005_0000 | libc::EINVAL as u32),
            insn(0x06, 0, 0, 0x7fff_0000),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_pidfd_open, raw, libc::O_EXCL) },
            -1
        );
        assert_eq!(unsafe { *libc::__errno_location() }, libc::EINVAL);
        let ordinary = unsafe { libc::syscall(libc::SYS_pidfd_open, raw, 0) };
        assert!(ordinary >= 0);
        assert_eq!(unsafe { libc::close(ordinary as i32) }, 0);
    }
    let pid = Pid::from_raw(raw);
    let original = Stopped::new_unchecked_on_ptracer_thread(pid).unwrap();
    let generation = original.generation();
    let terminal = Arc::new(original.terminal_cleanup());
    let events = Subscription::none();
    let (orphanage, _orphans) = mpsc::channel(1);
    let (daemon_kill, _) = broadcast::channel(1);
    let exec_stops = Arc::new(AtomicUsize::new(0));
    let preinit_stops = Arc::new(AtomicUsize::new(0));
    let sent_signal = Arc::new(AtomicBool::new(false));
    let intercepted_trap = Arc::new(AtomicBool::new(false));
    let exec_check = exec_stops.clone();
    let preinit_check = preinit_stops.clone();
    let signal_check = sent_signal.clone();
    let original_terminal = terminal.clone();
    let hook: PreinitPointForTest = Arc::new(move |tid, retained, point| {
        assert_eq!(tid, pid);
        assert!(retained.same_generation(&original_terminal));
        if point == PreinitPoint::ExecStopped {
            assert_eq!(exec_check.fetch_add(1, Ordering::SeqCst), 0);
            if unrelated_signal {
                assert!(!signal_check.swap(true, Ordering::SeqCst));
                assert_eq!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            process_fd.as_raw_fd(),
                            libc::SIGUSR1,
                            0,
                            0,
                        )
                    },
                    0
                );
            }
        }
        if point == PreinitPoint::RegsSaved {
            preinit_check.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut traced = TracedTask::<()>::new(
        pid,
        (),
        Arc::new(()),
        TracedTaskOptions {
            command_bootstrap: false,
            events: &events,
            injected_syscall_trap: None,
            liteinst_runtime: None,
            liteinst_trap_only: None,
            backend_stats: None,
            final_resume_signal_for_test: None,
            pre_syscall_for_test: None,
            preinit_point_for_test: Some(hook),
        },
        orphanage,
        daemon_kill,
        None,
    );
    traced.ptracer_waits.bind_stopped(&original);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let running = original.resume(None).unwrap();
        let (stopped, event) = traced
            .ptracer_waits
            .wait_running(running)
            .await
            .unwrap()
            .assume_stopped();
        assert_eq!(event, Event::Exec(pid));
        assert_eq!(stopped.generation(), generation);
        // Production arms each returned stop before dispatching its handler.
        traced.arm_liteinst_root_stop(&stopped, &event);
        assert!(traced.ordinary_held_stop.lock().unwrap().is_some());
        if unrelated_signal {
            let hook_generation = generation.clone();
            let trap_check = intercepted_trap.clone();
            POST_EXEC_STEP_FOR_TEST.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Box::new(move |running| {
                    // Own the actual Running returned by the production step.
                    // Its SDK wait returns the real first stopped capability;
                    // no unchecked state or numeric recapture is constructed.
                    assert_eq!(running.generation(), hook_generation);
                    let mut first = running.wait_owned_on_ptracer_thread().into_driver();
                    let waker = futures::task::noop_waker();
                    let mut context = Context::from_waker(&waker);
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                    let first = loop {
                        match first.poll_on_ptracer_thread(&mut context) {
                            Poll::Ready(result) => break result.unwrap(),
                            Poll::Pending => {
                                assert!(std::time::Instant::now() < deadline);
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                        }
                    };
                    let (stopped, event) = first.assume_stopped();
                    assert_eq!(event, Event::Signal(Signal::SIGTRAP));
                    assert_eq!(stopped.generation(), hook_generation);
                    assert!(!trap_check.swap(true, Ordering::SeqCst));
                    stopped.resume(None).unwrap()
                }));
            });
        }
        // This is the real ordinary production handler, including its post-exec
        // single-step wait, preinitialization and normal post-exec continuation.
        traced.handle_exec_event(stopped, pid).await
    });
    match &result {
        Ok(Wait::Exited(tid, status)) => eprintln!(
            "actual post-exec result forced={force_legacy} signal={unrelated_signal}: Exited({tid}, {status:?})"
        ),
        Ok(Wait::Stopped(stopped, event)) => eprintln!(
            "actual post-exec result forced={force_legacy} signal={unrelated_signal}: Stopped({}, {event:?})",
            stopped.pid()
        ),
        Err(TraceError::Errno(errno)) => eprintln!(
            "actual post-exec result forced={force_legacy} signal={unrelated_signal}: Errno({errno})"
        ),
        Err(TraceError::Died(_)) => eprintln!(
            "actual post-exec result forced={force_legacy} signal={unrelated_signal}: Died"
        ),
    }
    let expected = if unrelated_signal {
        assert!(sent_signal.load(Ordering::SeqCst));
        assert!(intercepted_trap.load(Ordering::SeqCst));
        assert_eq!(preinit_stops.load(Ordering::SeqCst), 0);
        ExitStatus::Signaled(Signal::SIGUSR1, false)
    } else {
        assert!(!sent_signal.load(Ordering::SeqCst));
        assert!(!intercepted_trap.load(Ordering::SeqCst));
        assert_eq!(
            preinit_stops.load(Ordering::SeqCst),
            1,
            "the actual accepted SIGTRAP reached real preinitialization"
        );
        ExitStatus::Exited(0)
    };
    assert_eq!(exec_stops.load(Ordering::SeqCst), 1);
    POST_EXEC_STEP_FOR_TEST.with(|slot| assert!(slot.borrow().is_none()));
    assert_eq!(result.unwrap().assume_exited(), (pid, expected));
    assert_eq!(terminal.observed_exit_status(), Ok(Some(expected)));
    assert!(traced.ordinary_held_stop.lock().unwrap().is_none());
    child.0 = 0;
    assert_eq!(
        unsafe { libc::waitpid(raw, &mut status, libc::WNOHANG | libc::__WALL) },
        -1
    );
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ECHILD);
    println!("POST_EXEC_REAL_HANDLER_PASSED forced={force_legacy} signal={unrelated_signal}");
    unsafe { libc::alarm(0) };
}
