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
    let options = libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD;
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
    let exit_stops = Arc::new(AtomicUsize::new(0));
    let drained_stops = Arc::new(AtomicUsize::new(0));
    let preinit_stops = Arc::new(AtomicUsize::new(0));
    let mmap_returns = Arc::new(AtomicUsize::new(0));
    let sent_signal = Arc::new(AtomicBool::new(false));
    let exec_check = exec_stops.clone();
    let exit_check = exit_stops.clone();
    let drained_check = drained_stops.clone();
    let preinit_check = preinit_stops.clone();
    let mmap_check = mmap_returns.clone();
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
        if point == PreinitPoint::PostExecDrained {
            assert_eq!(exit_check.load(Ordering::SeqCst), 1);
            assert_eq!(drained_check.fetch_add(1, Ordering::SeqCst), 0);
        }
        if point == PreinitPoint::RegsSaved {
            assert_eq!(exit_check.load(Ordering::SeqCst), 1);
            assert_eq!(drained_check.load(Ordering::SeqCst), 1);
            assert_eq!(preinit_check.fetch_add(1, Ordering::SeqCst), 0);
        }
        if point == PreinitPoint::MmapReturned {
            assert_eq!(mmap_check.fetch_add(1, Ordering::SeqCst), 0);
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
        let exec_regs = stopped.getregs().unwrap();
        let exec_info = stopped.getsyscallinfo().unwrap();
        assert_eq!(exec_info.operation, safeptrace::SyscallInfoOp::None);
        assert_eq!(exec_info.architecture, 0xc000_003e);
        assert_eq!(exec_info.instruction_pointer, exec_regs.ip());
        assert_eq!(exec_info.stack_pointer, exec_regs.stack_ptr());
        // Production arms each returned stop before dispatching its handler.
        traced.arm_liteinst_root_stop(&stopped, &event);
        assert!(traced.ordinary_held_stop.lock().unwrap().is_some());
        let hook_generation = generation.clone();
        let exit_check = exit_stops.clone();
        POST_EXEC_RETURN_FOR_TEST.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(move |stopped, info| {
                // Observe the real, validated stopped capability without
                // consuming it, waiting on another owner, or resuming it.
                assert_eq!(stopped.pid(), pid);
                assert_eq!(stopped.generation(), hook_generation);
                assert_eq!(exit_check.fetch_add(1, Ordering::SeqCst), 0);
                assert_eq!(
                    info.operation,
                    safeptrace::SyscallInfoOp::Exit {
                        return_value: 0,
                        is_error: false,
                    }
                );
                assert_eq!(info.architecture, exec_info.architecture);
                assert_eq!(info.instruction_pointer, exec_info.instruction_pointer);
                assert_eq!(info.stack_pointer, exec_info.stack_pointer);
                let exit_regs = stopped.getregs().unwrap();
                assert_eq!(exit_regs.ip(), exec_regs.ip());
                assert_eq!(exit_regs.stack_ptr(), exec_regs.stack_ptr());
                assert_eq!(exit_regs.ret(), 0);
                assert_eq!(*info, stopped.getsyscallinfo().unwrap());
                // Linux reports syscall EXIT before processing pending
                // signals. The queued instance must still belong to the
                // kernel here, not to a test hold or a synthetic delivery.
                let pending = pending_signal_mask(pid).unwrap();
                assert_eq!(
                    pending & signal_mask_bit(Signal::SIGUSR1) != 0,
                    unrelated_signal
                );
                eprintln!(
                    "actual exec-return forced={force_legacy} signal={unrelated_signal}: exec={exec_info:?}, exit={info:?}, generation={hook_generation:?}"
                );
            }));
        });
        // This is the real ordinary production handler, including its post-exec
        // syscall-exit wait, preinitialization and normal post-exec continuation.
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            traced.handle_exec_event(stopped),
        )
        .await
        .expect("the owned exec-return and preinit path exceeded its three-second bound")
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
        // The checked EXIT arrives before SIGUSR1 delivery, so preinit
        // saves the entry registers and patches its private mmap syscall.
        // SIGUSR1 then kills the tracee before that mmap returns or any
        // original image instruction can execute. The old test consumed a
        // synthetic SIGTRAP and CONTed before preinit; it tested a different
        // sequence and therefore expected no preinit visit.
        assert_eq!(preinit_stops.load(Ordering::SeqCst), 1);
        assert_eq!(mmap_returns.load(Ordering::SeqCst), 0);
        ExitStatus::Signaled(Signal::SIGUSR1, false)
    } else {
        assert!(!sent_signal.load(Ordering::SeqCst));
        assert_eq!(
            preinit_stops.load(Ordering::SeqCst),
            1,
            "the actual checked exec EXIT reached real preinitialization"
        );
        assert_eq!(mmap_returns.load(Ordering::SeqCst), 1);
        ExitStatus::Exited(0)
    };
    assert_eq!(exec_stops.load(Ordering::SeqCst), 1);
    assert_eq!(exit_stops.load(Ordering::SeqCst), 1);
    assert_eq!(drained_stops.load(Ordering::SeqCst), 1);
    POST_EXEC_RETURN_FOR_TEST.with(|slot| assert!(slot.borrow().is_none()));
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
