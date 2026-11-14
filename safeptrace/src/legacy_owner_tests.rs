/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(not(sanitized))]
fn legacy_owner_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "legacy owner control exceeded deadline"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(not(sanitized))]
fn legacy_owner_observe(pid: Pid, flags: WaitPidFlag) -> i32 {
    let flags = WaitPidFlag::from_bits_retain(
        flags.bits()
            | WaitPidFlag::WNOWAIT.bits()
            | WaitPidFlag::WNOHANG.bits()
            | libc::__WALL
            | libc::__WNOTHREAD,
    );
    let mut observed = None;
    legacy_owner_until(|| {
        observed = waitid::wait_raw(waitid::IdType::Pid(pid), flags).unwrap();
        observed.is_some()
    });
    observed.unwrap()
}

/// An untraced real child owns one live non-leader. The member cannot exec,
/// detach itself or exit until its pipe is released; the root stays alive
/// until the real parent sends a descriptor-bound SIGKILL and actually reaps.
#[cfg(not(sanitized))]
fn legacy_owner_guest() -> (Pid, Pid, OwnedFd, TraceeCleanupGuard) {
    legacy_owner_guest_with_name_change(false)
}

#[cfg(not(sanitized))]
fn legacy_owner_guest_with_name_change(
    invalid_name: bool,
) -> (Pid, Pid, OwnedFd, TraceeCleanupGuard) {
    let [receipt, send_receipt] = legacy_pipe();
    let [start, release] = legacy_pipe();
    let root = match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            unsafe {
                libc::close(receipt.as_raw_fd());
                libc::close(release.as_raw_fd());
            }
            extern "C" fn member(argument: *mut libc::c_void) -> *mut libc::c_void {
                let descriptors = unsafe { &*argument.cast::<[i32; 3]>() };
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
                if unsafe { libc::write(descriptors[0], (&tid as *const i32).cast(), 4) } != 4 {
                    unsafe { libc::_exit(125) };
                }
                let mut byte = 0u8;
                if unsafe { libc::read(descriptors[1], (&mut byte as *mut u8).cast(), 1) } != 1 {
                    unsafe { libc::_exit(126) };
                }
                if descriptors[2] != 0
                    && (unsafe { libc::prctl(libc::PR_SET_NAME, c"\xff-owned-live".as_ptr()) } != 0
                        || unsafe { libc::raise(libc::SIGTRAP) } != 0)
                {
                    unsafe { libc::_exit(128) };
                }
                unsafe { libc::syscall(libc::SYS_exit, 23) };
                std::ptr::null_mut()
            }
            let mut descriptors = [
                send_receipt.as_raw_fd(),
                start.as_raw_fd(),
                i32::from(invalid_name),
            ];
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
    };
    drop((send_receipt, start));
    let cleanup = TraceeCleanupGuard::new(root).unwrap();
    let mut readiness = libc::pollfd {
        fd: receipt.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut readiness, 1, TRACEE_WAIT_TIMEOUT.as_millis() as i32) },
        1
    );
    let mut bytes = [0u8; 4];
    fs::File::from(receipt).read_exact(&mut bytes).unwrap();
    let member = Pid::from_raw(i32::from_ne_bytes(bytes));
    assert_ne!(root, member);
    (root, member, release, cleanup)
}

#[cfg(not(sanitized))]
fn legacy_owner_reap_root(root: Pid, cleanup: &mut TraceeCleanupGuard) {
    pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL).unwrap_or_else(|error| {
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    });
    let status = waitpid_status_bounded(root, 0, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
}

/// Leaves the replacement's genuine TRACEME SIGSTOP report unconsumed.
/// clone3(set_tid) provides real numeric reuse in a fresh PID namespace.
#[cfg(not(sanitized))]
fn legacy_owner_replacement(requested: Option<Pid>) -> Option<(Pid, TraceeCleanupGuard, i32)> {
    legacy_owner_replacement_after_stop(requested, || {})
}

#[cfg(not(sanitized))]
fn legacy_owner_replacement_after_stop(
    requested: Option<Pid>,
    after_stop: impl FnOnce(),
) -> Option<(Pid, TraceeCleanupGuard, i32)> {
    let child = if let Some(requested) = requested {
        #[repr(C)]
        #[derive(Default)]
        struct CloneArgs {
            flags: u64,
            pidfd: u64,
            child_tid: u64,
            parent_tid: u64,
            exit_signal: u64,
            stack: u64,
            stack_size: u64,
            tls: u64,
            set_tid: u64,
            set_tid_size: u64,
            cgroup: u64,
        }
        let mut tid = requested.as_raw();
        let args = CloneArgs {
            exit_signal: libc::SIGCHLD as u64,
            set_tid: std::ptr::from_mut(&mut tid) as u64,
            set_tid_size: 1,
            ..CloneArgs::default()
        };
        // Errno is read inside the guarded call, before the guard's release
        // can make another syscall.
        let (result, error) = crate::test_fork::exclusive(|| {
            let result =
                unsafe { libc::syscall(libc::SYS_clone3, &args, mem::size_of::<CloneArgs>()) };
            (result, Errno::last())
        });
        if result == -1 {
            assert!(
                matches!(error, Errno::EPERM | Errno::EACCES | Errno::ENOSYS),
                "unexpected clone3 exact-reuse refusal: {error}"
            );
            return None;
        }
        if result == 0 {
            crate::traceme_and_stop().unwrap();
            after_stop();
            unsafe { libc::_exit(42) };
        }
        let child = Pid::from_raw(result as i32);
        assert_eq!(child, requested, "clone3 did not reuse the retired TID");
        child
    } else {
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                after_stop();
                unsafe { libc::_exit(42) };
            }
        }
    };
    let cleanup = TraceeCleanupGuard::new(child).unwrap();
    let status = legacy_owner_observe(child, WaitPidFlag::WSTOPPED);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    Some((child, cleanup, status))
}

#[cfg(not(sanitized))]
fn legacy_owner_finish_replacement(pid: Pid, mut cleanup: TraceeCleanupGuard, original: i32) {
    assert_eq!(
        legacy_owner_observe(pid, WaitPidFlag::WSTOPPED),
        original,
        "an old generation consumed the replacement's original SIGSTOP"
    );
    let flags = WaitPidFlag::from_bits_retain(
        WaitPidFlag::WSTOPPED.bits()
            | WaitPidFlag::WNOHANG.bits()
            | libc::__WALL
            | libc::__WNOTHREAD,
    );
    assert_eq!(
        waitid::wait_raw(waitid::IdType::Pid(pid), flags).unwrap(),
        Some(original)
    );
    nix::sys::ptrace::cont(pid, None).unwrap();
    let status =
        waitpid_status_bounded(pid, libc::__WALL | libc::__WNOTHREAD, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 42);
    cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[cfg(not(sanitized))]
async fn legacy_owner_exit_control(exact_reuse: bool) -> bool {
    for terminal_before_owner_exit in [false, true] {
        for owned_future in [false, true] {
            let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
            let (captured, observe_captured) = mpsc::sync_channel(1);
            let (resume, observe_resume) = mpsc::sync_channel(1);
            let (published, registered) = mpsc::sync_channel(1);
            let (owner_exit, owner_release) = mpsc::sync_channel(1);
            let release_fd = release.as_raw_fd();
            let owner = thread::spawn(move || {
                let _force = LegacyThreadGroup::new(root);
                let options = if terminal_before_owner_exit {
                    Options::empty()
                } else {
                    Options::PTRACE_O_EXITKILL
                };
                let running = Running::seize_on_ptracer_thread(tid.into(), options).unwrap();
                let running = if terminal_before_owner_exit {
                    running.interrupt().unwrap();
                    let (stopped, event) = running
                        .wait_sync_on_ptracer_thread()
                        .wait()
                        .unwrap()
                        .assume_stopped();
                    assert_eq!(event, crate::Event::Stop);
                    stopped.resume(None).unwrap()
                } else {
                    running
                };
                let terminal = running.terminal_cleanup();
                terminal.ensure_registered().unwrap();
                assert_eq!(terminal.has_thread_pidfd(), Ok(false));
                *terminal.event.event().legacy_observation_pause.lock() = Some(BoundedTestPause {
                    captured,
                    resume: observe_resume,
                });
                if terminal_before_owner_exit {
                    assert_eq!(
                        unsafe { libc::write(release_fd, b"x".as_ptr().cast(), 1) },
                        1
                    );
                } else {
                    running.interrupt().unwrap();
                }
                let status = legacy_owner_observe(
                    tid,
                    if terminal_before_owner_exit {
                        WaitPidFlag::WEXITED
                    } else {
                        WaitPidFlag::WSTOPPED
                    },
                );
                if terminal_before_owner_exit {
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 23);
                } else {
                    assert_eq!(
                        status,
                        (libc::PTRACE_EVENT_STOP << 16) | (libc::SIGTRAP << 8) | 0x7f
                    );
                    let info = nix::sys::ptrace::getsiginfo(tid).unwrap();
                    assert_eq!(info.si_signo, libc::SIGTRAP);
                    assert_eq!(info.si_code, (libc::PTRACE_EVENT_STOP << 8) | libc::SIGTRAP);
                }
                let host_tid = crate::Pid::from(nix::unistd::gettid());
                published
                    .send((running, terminal, host_tid, status))
                    .unwrap();
                owner_release.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
                // Actual pthread exit invokes exit_ptrace, outside Event's
                // gate. There is deliberately no CONT, DETACH or Safe reap.
            });
            let (running, terminal, host_tid, original) =
                registered.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
            observe_captured.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
            let event = terminal.event.event().clone();
            let identity = terminal.event.identity().unwrap().clone();
            assert!(
                event.status.lock().pending.is_empty(),
                "WNOWAIT hint became an acknowledged stop"
            );
            assert_eq!(event.status.lock().terminal, INVALID_STATUS);
            assert_eq!(event.legacy_wait_owner.get().unwrap().tid, host_tid);
            assert!(event.legacy_wait_owner.get().unwrap().is_live().unwrap());
            assert_eq!(identity.current_tracer_pid(), Ok(host_tid));
            assert!(if terminal_before_owner_exit {
                libc::WIFEXITED(original)
            } else {
                libc::WIFSTOPPED(original)
            });
            owner_exit.send(()).unwrap();
            owner.join().unwrap();
            // The join returns when the exiting thread clears its TID
            // (mm_release, from exit_mm), which do_exit does before
            // exit_notify and release_task detach its PID. Until then the
            // owner can still read as live, so wait for it to die.
            let wait_owner = event.legacy_wait_owner.get().unwrap();
            legacy_owner_until(|| !wait_owner.is_live().unwrap());
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(matches!(
                identity.current_tracer_pid(),
                Err(Errno::ENOENT | Errno::ESRCH)
            ));
            let replacement = legacy_owner_replacement(exact_reuse.then_some(tid));
            resume.send(()).unwrap();
            assert!(
                terminal.wait(TRACEE_WAIT_TIMEOUT),
                "dead owner left the observer parked forever"
            );
            assert_eq!(terminal.observed_exit_status(), Err(Errno::ECHILD));
            assert!(
                terminal
                    .reserve_pending_for_cleanup(Duration::ZERO)
                    .is_none()
            );
            assert!(terminal.queued_raw_statuses().is_empty());
            assert!(terminal.event.hold_tid().is_none());
            assert_eq!(event.status.lock().terminal, ECHILD_STATUS);
            assert_eq!(event.worker_state.load(Ordering::Acquire), WORKER_DONE);
            let exit = running.exit_event_on_ptracer_thread();
            assert!(matches!(
                tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
                    .await
                    .unwrap(),
                Err(Error::Errno(Errno::EPERM))
            ));
            if owned_future {
                let mut wait = running.wait_owned_on_ptracer_thread();
                assert!(matches!(
                    tokio::time::timeout(TRACEE_WAIT_TIMEOUT, &mut wait)
                        .await
                        .unwrap(),
                    Err(OwnedWaitError::Errno(Errno::EPERM))
                ));
                assert!(
                    wait.driver.inner.inner.is_some(),
                    "foreign-owner refusal discarded the original wait owner"
                );
            } else {
                let mut wait = running.wait_sync_on_ptracer_thread().into_driver();
                assert!(matches!(
                    wait.wait_on_ptracer_thread(),
                    Err(OwnedWaitError::Errno(Errno::EPERM))
                ));
                assert!(
                    wait.input.is_some(),
                    "foreign-owner refusal discarded the synchronous input"
                );
            }
            let Some((replacement, cleanup, stop)) = replacement else {
                return false;
            };
            legacy_owner_finish_replacement(replacement, cleanup, stop);
            drop(release);
        }
    }
    true
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_owner_exit_preserves_replacement_stop_and_terminal() {
    const NAME: &str = "forced_legacy_owner_exit_preserves_replacement_stop_and_terminal";
    const INNER: &str = "SAFEPTRACE_LEGACY_OWNER_REUSE_INNER";
    if env::var_os(INNER).is_some() {
        println!(
            "{}",
            if legacy_owner_exit_control(true).await {
                "ACTUAL_LEGACY_OWNER_REUSE_EXERCISED"
            } else {
                "ACTUAL_LEGACY_OWNER_REUSE_UNAVAILABLE"
            }
        );
        return;
    }
    if env::var("SAFEPTRACE_LEGACY_THREAD_INNER").as_deref() != Ok(NAME) {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")]);
        if classify_exact_reuse_output(
            output.as_ref(),
            "ACTUAL_LEGACY_OWNER_REUSE_EXERCISED",
            "ACTUAL_LEGACY_OWNER_REUSE_UNAVAILABLE",
        )
        .unwrap()
            == ExactReuseOutcome::Exercised
        {
            emit_completion_marker("ACTUAL_LEGACY_OWNER_REUSE_EXERCISED");
            return;
        }
        if run_legacy_test_outer(NAME) {
            return;
        }
    }
    assert!(legacy_owner_exit_control(false).await);
    println!("LEGACY_OWNER_EXIT_DISTINCT_PID_CONTROL_EXERCISED; exact reuse unavailable");
}

#[cfg(not(sanitized))]
async fn legacy_owner_finish_member(
    running: Running,
    tid: Pid,
    release: RawFd,
    method: LegacyAttachMethod,
) -> TerminalCleanup {
    let terminal = running.terminal_cleanup();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(stopped.pid(), tid.into());
    assert_eq!(
        event,
        if method == LegacyAttachMethod::Attach {
            crate::Event::Signal(Signal::SIGSTOP)
        } else {
            crate::Event::Stop
        }
    );
    stopped.getregs().unwrap();
    stopped.setoptions(legacy_thread_options()).unwrap();
    let exit = stopped.exit_event_on_ptracer_thread();
    assert_eq!(unsafe { libc::write(release, b"x".as_ptr().cast(), 1) }, 1);
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.pid(), tid.into());
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    assert!(!terminal.wait(Duration::ZERO));
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(
        terminal.observed_exit_status(),
        Ok(Some(crate::ExitStatus::Exited(23)))
    );
    drop(running);
    terminal
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_immediate_reattach_authenticates_current_host_owner() {
    if run_legacy_test_outer("forced_legacy_immediate_reattach_authenticates_current_host_owner") {
        return;
    }
    for method in [LegacyAttachMethod::Attach, LegacyAttachMethod::Seize] {
        for changed_owner in [false, true] {
            let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
            let _force = LegacyThreadGroup::new(root);
            let count_before = SPAWN_WORKER_COUNTS
                .lock()
                .get(&tid.into())
                .copied()
                .unwrap_or(0);
            let running =
                Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
            running.interrupt().unwrap();
            let (stopped, event) = running
                .wait_sync_on_ptracer_thread()
                .wait()
                .unwrap()
                .assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            let old_terminal = stopped.terminal_cleanup();
            old_terminal.ensure_registered().unwrap();
            let old_event = old_terminal.event.event().clone();
            let old_identity = old_terminal.event.identity().unwrap().clone();
            let (captured, capture) = mpsc::sync_channel(1);
            let (resume, resumed) = mpsc::sync_channel(1);
            *old_event.legacy_worker_cycle_pause.lock() = Some(BoundedTestPause {
                captured,
                resume: resumed,
            });
            capture.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
            let detached = stopped.detach(None).unwrap();
            assert!(
                !*old_event.terminal_reaping.read(),
                "worker naturally retired before reconnect control"
            );
            assert!(!old_terminal.wait(Duration::ZERO));
            let release_fd = release.as_raw_fd();
            let terminal = if changed_owner {
                let (entered, entering) = mpsc::sync_channel(1);
                let owner = thread::spawn(move || {
                    let _force = LegacyThreadGroup::new(root);
                    entered
                        .send(crate::Pid::from(nix::unistd::gettid()))
                        .unwrap();
                    let running = if method == LegacyAttachMethod::Attach {
                        Running::attach_on_ptracer_thread(tid.into()).unwrap()
                    } else {
                        let running =
                            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options())
                                .unwrap();
                        running.interrupt().unwrap();
                        running
                    };
                    tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap()
                        .block_on(legacy_owner_finish_member(running, tid, release_fd, method))
                });
                let current_owner = entering.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
                assert_ne!(
                    old_event.legacy_wait_owner.get().unwrap().tid,
                    current_owner
                );
                legacy_owner_until(|| {
                    old_identity.current_tracer_pid() == Ok(current_owner)
                        && *old_event.terminal_reaping.read()
                        && old_event.legacy_wait.lock().retiring
                });
                assert_ne!(
                    old_event.worker_state.load(Ordering::Acquire),
                    WORKER_DONE,
                    "reconnect bypassed the paused original observation owner"
                );
                resume.send(()).unwrap();
                let terminal = owner.join().unwrap();
                assert!(!terminal.same_generation(&old_terminal));
                assert!(old_terminal.wait(Duration::ZERO));
                assert_eq!(old_terminal.observed_exit_status(), Err(Errno::ECHILD));
                assert!(old_terminal.event.hold_tid().is_none());
                assert_eq!(
                    SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
                    Some(count_before + 2)
                );
                terminal
            } else {
                let running = if method == LegacyAttachMethod::Attach {
                    Running::attach_on_ptracer_thread(tid.into()).unwrap()
                } else {
                    let running =
                        Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options())
                            .unwrap();
                    running.interrupt().unwrap();
                    running
                };
                assert!(running.terminal_cleanup().same_generation(&old_terminal));
                assert!(!*old_event.terminal_reaping.read());
                assert!(!old_event.legacy_wait.lock().retiring);
                resume.send(()).unwrap();
                let terminal = legacy_owner_finish_member(running, tid, release_fd, method).await;
                assert!(terminal.same_generation(&old_terminal));
                assert_eq!(
                    SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
                    Some(count_before + 1)
                );
                terminal
            };
            // The controller is a wrong host thread for the changed-owner
            // session. Reading an already published result remains valid.
            assert_eq!(
                terminal.observed_exit_status(),
                Ok(Some(crate::ExitStatus::Exited(23)))
            );
            assert!(terminal.queued_raw_statuses().is_empty());
            assert!(
                terminal
                    .reserve_pending_for_cleanup(Duration::ZERO)
                    .is_none()
            );
            assert!(terminal.wait(Duration::ZERO));
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
            drop((detached, release));
        }
    }
}

/// Deny signal0 before the kernel even looks up the descriptor, including
/// for dead descriptors. Positive retained-directory reads must be the
/// independent wait identity evidence; EPERM itself cannot supply it.
#[cfg(not(sanitized))]
fn legacy_owner_deny_signal0() {
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let filter = [
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 3, libc::SYS_pidfd_send_signal as u32),
        instruction(0x20, 0, 0, 24),
        instruction(0x15, 0, 1, 0),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &program,
            )
        },
        0
    );
}

#[cfg(not(sanitized))]
async fn legacy_owner_denied_signal0_control(exact_reuse: bool) -> bool {
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.ensure_registered().unwrap();
    let identity = terminal.event.identity().unwrap().clone();
    assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
    assert_eq!(identity.pidfd_is_live(), Ok(true));
    assert_eq!(
        identity.current_tracer_pid(),
        Ok(crate::Pid::from(nix::unistd::gettid()))
    );
    legacy_owner_deny_signal0();
    assert_eq!(identity.pidfd_is_live(), Err(Errno::EPERM));
    assert_eq!(terminal.request_sigstop(), Err(Errno::EPERM));
    running.interrupt().unwrap();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    assert_eq!(
        stopped.observation().sample(false).pidfd_live(),
        Some(Err(Errno::EPERM))
    );
    assert_eq!(identity.pidfd_is_live(), Err(Errno::EPERM));
    stopped.getregs().unwrap();
    let exit = stopped.exit_event_on_ptracer_thread();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    assert_eq!(
        stopped.observation().sample(false).pidfd_live(),
        Some(Err(Errno::EPERM))
    );
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(
        terminal.observed_exit_status(),
        Ok(Some(crate::ExitStatus::Exited(23)))
    );
    assert_eq!(
        identity.pidfd_is_live(),
        Err(Errno::EPERM),
        "denial changed after retirement"
    );
    assert!(matches!(
        identity.current_tracer_pid(),
        Err(Errno::ENOENT | Errno::ESRCH)
    ));
    legacy_owner_reap_root(root, &mut root_cleanup);
    let Some((replacement, cleanup, stop)) = legacy_owner_replacement(exact_reuse.then_some(tid))
    else {
        return false;
    };
    let flags = WaitPidFlag::WSTOPPED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
    assert_eq!(identity.pidfd.wait_status(flags), Err(Errno::ECHILD));
    assert_eq!(identity.pidfd_is_live(), Err(Errno::EPERM));
    assert!(
        terminal
            .reserve_pending_for_cleanup(Duration::ZERO)
            .is_none()
    );
    assert!(terminal.queued_raw_statuses().is_empty());
    assert_eq!(
        terminal.observed_exit_status(),
        Ok(Some(crate::ExitStatus::Exited(23)))
    );
    assert!(terminal.wait(Duration::ZERO));
    legacy_owner_finish_replacement(replacement, cleanup, stop);
    drop(running);
    true
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_wait_preserves_authority_when_signal0_is_denied() {
    const NAME: &str = "forced_legacy_wait_preserves_authority_when_signal0_is_denied";
    const INNER: &str = "SAFEPTRACE_LEGACY_DENIED_SIGNAL0_INNER";
    if env::var_os(INNER).is_some() {
        println!(
            "{}",
            if legacy_owner_denied_signal0_control(true).await {
                "ACTUAL_LEGACY_DENIED_SIGNAL0_REUSE_EXERCISED"
            } else {
                "ACTUAL_LEGACY_DENIED_SIGNAL0_REUSE_UNAVAILABLE"
            }
        );
        return;
    }
    if env::var("SAFEPTRACE_LEGACY_THREAD_INNER").as_deref() != Ok(NAME) {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")]);
        if classify_exact_reuse_output(
            output.as_ref(),
            "ACTUAL_LEGACY_DENIED_SIGNAL0_REUSE_EXERCISED",
            "ACTUAL_LEGACY_DENIED_SIGNAL0_REUSE_UNAVAILABLE",
        )
        .unwrap()
            == ExactReuseOutcome::Exercised
        {
            emit_completion_marker("ACTUAL_LEGACY_DENIED_SIGNAL0_REUSE_EXERCISED");
            return;
        }
        if run_legacy_test_outer(NAME) {
            return;
        }
    }
    assert!(legacy_owner_denied_signal0_control(false).await);
    println!("LEGACY_DENIED_SIGNAL0_DISTINCT_PID_CONTROL_EXERCISED; exact reuse unavailable");
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_wait_preserves_authority_after_non_utf8_name_change() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_wait_preserves_authority_after_non_utf8_name_change",
        Some("ACTUAL_LEGACY_NON_UTF8_WAIT_EXERCISED"),
    ) {
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest_with_name_change(true);
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.ensure_registered().unwrap();
    let identity = terminal.event.identity().unwrap().clone();
    assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
    running.interrupt().unwrap();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    // The member changes comm only after the original Event is bound and
    // registered. Its subsequent SIGTRAP and EXIT are real owned reports.
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let (stopped, event) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGTRAP));
    let status_bytes = fs::read(format!("/proc/{tid}/status")).unwrap();
    assert!(
        std::str::from_utf8(&status_bytes).is_err(),
        "guest did not set a non-UTF8 name"
    );
    assert!(status_bytes.starts_with(b"Name:\t\xff-owned-live\n"));
    // Existing global snapshot/observer behavior is not broadened. The
    // wait-only reader independently parses the valid identity fields.
    assert!(worker_proc_snapshot(tid.into()).is_err());
    let retained = retained_proc_status(identity.proc_dir.as_raw_fd()).unwrap();
    assert_eq!(retained.pid, tid.into());
    assert_eq!(retained.tgid, root.into());
    assert_eq!(retained.tracer_pid, crate::Pid::from(nix::unistd::gettid()));
    assert_eq!(
        identity.current_tracer_pid(),
        Ok(crate::Pid::from(nix::unistd::gettid()))
    );
    assert_eq!(
        stopped.observation().sample(false).pidfd_live(),
        Some(Ok(true))
    );
    stopped.getregs().unwrap();
    let exit = stopped.exit_event_on_ptracer_thread();
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(
        terminal.observed_exit_status(),
        Ok(Some(crate::ExitStatus::Exited(23)))
    );
    legacy_owner_reap_root(root, &mut root_cleanup);
    assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    assert_eq!(
        terminal.event.event().worker_state.load(Ordering::Acquire),
        WORKER_DONE
    );
    drop(running);
    emit_completion_marker("ACTUAL_LEGACY_NON_UTF8_WAIT_EXERCISED");
}

/// The procfs state letter of thread `tid` in `root`'s thread group.
#[cfg(not(sanitized))]
fn legacy_owner_thread_state(root: Pid, tid: Pid) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{root}/task/{tid}/stat")).ok()?;
    Some(
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .next()?
            .to_owned(),
    )
}

/// With signal 0 refused, the stop proof cannot complete: the attempt that
/// consumes a stop tries it, falls back to the retained status read, and
/// consumes as before.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_stop_proof_falls_back_when_signal0_is_denied() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_stop_proof_falls_back_when_signal0_is_denied",
        Some("ACTUAL_LEGACY_STOP_PROOF_DENIED_FALLBACK_EXERCISED"),
    ) {
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.ensure_registered().unwrap();
    let identity = terminal.event.identity().unwrap().clone();
    assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
    legacy_owner_deny_signal0();
    assert_eq!(identity.pidfd_is_live(), Err(Errno::EPERM));
    // A first stop through an ordinary wait starts the observation worker.
    running.interrupt().unwrap();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    // Counted attempts consume the second stop.
    let running = stopped.resume(None).unwrap();
    running.interrupt().unwrap();
    legacy_owner_until(|| legacy_owner_thread_state(root, tid).as_deref() == Some("t"));
    let mut attempts = legacy_attempts_until_consumed(&terminal);
    let consuming = attempts.pop().unwrap();
    assert_eq!(
        consuming,
        LegacyAttempt {
            reads: 1,
            accepted: 0,
            refused: 1,
            consumed: 1,
        },
        "the consuming attempt did not fall back to the status read"
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.accepted == 0 && attempt.consumed == 0),
        "an attempt proved its owner with signal 0 refused, or consumed early: {attempts:?}"
    );
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    let exit = stopped.exit_event_on_ptracer_thread();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    legacy_owner_reap_root(root, &mut root_cleanup);
    drop(running);
    emit_completion_marker("ACTUAL_LEGACY_STOP_PROOF_DENIED_FALLBACK_EXERCISED");
}

/// A zombie is in no ptrace stop, so the stop proof never serves it: the
/// attempt that reaps it authenticates through the retained status read.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_zombie_observation_authenticates_through_status() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_zombie_observation_authenticates_through_status",
        Some("ACTUAL_LEGACY_ZOMBIE_READ_AUTHENTICATION_EXERCISED"),
    ) {
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.ensure_registered().unwrap();
    assert!(matches!(
        terminal.event.identity().unwrap().pidfd,
        ThreadHandle::Procfs { .. }
    ));
    running.interrupt().unwrap();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    let exit = stopped.exit_event_on_ptracer_thread();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    // Counted attempts reap the zombie.
    let exited = stopped.resume(None).unwrap();
    legacy_owner_until(|| legacy_owner_thread_state(root, tid).as_deref() == Some("Z"));
    let mut attempts = legacy_attempts_until_consumed(&terminal);
    let reaping = attempts.pop().unwrap();
    assert_eq!(
        reaping,
        LegacyAttempt {
            reads: 1,
            accepted: 0,
            refused: 0,
            consumed: 1,
        },
        "the reaping attempt did not authenticate through the status read"
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.accepted == 0 && attempt.refused == 0 && attempt.consumed == 0),
        "an attempt ran the stop proof for a zombie, or consumed early: {attempts:?}"
    );
    assert_eq!(
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exited.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    legacy_owner_reap_root(root, &mut root_cleanup);
    drop(running);
    emit_completion_marker("ACTUAL_LEGACY_ZOMBIE_READ_AUTHENTICATION_EXERCISED");
}

/// The ptrace stop status of an interrupt of a seized thread.
#[cfg(not(sanitized))]
const LEGACY_OWNER_EVENT_STOP: i32 = 0x7f | (libc::SIGTRAP << 8) | (libc::PTRACE_EVENT_STOP << 16);

/// Lowers RLIMIT_NOFILE to this process's lowest free descriptor, so that
/// the next descriptor any thread allocates fails with EMFILE, and returns
/// the limit to restore.
#[cfg(not(sanitized))]
fn legacy_owner_exhaust_descriptors() -> libc::rlimit {
    let mut saved = unsafe { mem::zeroed::<libc::rlimit>() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) },
        0
    );
    let lowest = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    assert!(
        lowest >= 0,
        "find the lowest free descriptor: {}",
        Errno::last()
    );
    assert_eq!(unsafe { libc::close(lowest) }, 0);
    let exhausted = libc::rlimit {
        rlim_cur: lowest as libc::rlim_t,
        rlim_max: saved.rlim_max,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &exhausted) },
        0
    );
    let probe = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert_eq!(
        (probe, Errno::last()),
        (-1, Errno::EMFILE),
        "the descriptor table is not exhausted"
    );
    saved
}

#[cfg(not(sanitized))]
fn legacy_owner_restore_descriptors(saved: &libc::rlimit) {
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, saved) }, 0);
}

/// The contract boundary of the stop proof, with exact results. While no
/// descriptor can be opened, the status read fails with EMFILE. An observed
/// stop whose proof succeeds is still consumed, with no read. An observed stop
/// whose proof is refused, and an attempt that observes nothing, authenticate
/// through the read and return its EMFILE, consuming nothing.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_stop_proof_needs_no_status_open_but_a_refused_proof_does() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_stop_proof_needs_no_status_open_but_a_refused_proof_does",
        Some("ACTUAL_LEGACY_STOP_PROOF_EMFILE_BOUNDARY_EXERCISED"),
    ) {
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.ensure_registered().unwrap();
    let identity = terminal.event.identity().unwrap().clone();
    assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
    // A first stop through an ordinary wait starts the observation worker.
    running.interrupt().unwrap();
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    let running = stopped.resume(None).unwrap();
    running.interrupt().unwrap();
    legacy_owner_until(|| legacy_owner_thread_state(root, tid).as_deref() == Some("t"));
    let event = Arc::clone(terminal.event.event());
    let stop = legacy_owner_observe(tid, WaitPidFlag::WSTOPPED);
    assert_eq!(stop, LEGACY_OWNER_EVENT_STOP);
    // The worker turns only under this mutex, so holding it keeps every other
    // status read out of the exhausted window. The block releases it before
    // the next await.
    let (refused, refused_attempt, after_refusal, accepted, accepted_attempt, empty, empty_attempt) = {
        let mut progress = event.legacy_wait.lock();
        assert!(event.worker_is_running() && !progress.retiring);
        assert!(progress.consumed.is_empty());
        let saved = legacy_owner_exhaust_descriptors();
        assert_eq!(identity.current_tracer_pid(), Err(Errno::EMFILE));

        // A refused proof (signal 0 through the retained descriptor refused).
        PIDFD_LIVENESS_ERRORS
            .lock()
            .entry(tid.into())
            .or_default()
            .push_back(Errno::EPERM);
        let before = LegacyAttempt::now();
        let refused = try_consume_legacy_status(&identity, &event, None);
        let refused_attempt = LegacyAttempt::since(before);
        let after_refusal = legacy_owner_observe(tid, WaitPidFlag::WSTOPPED);
        // A proof that succeeds.
        let before = LegacyAttempt::now();
        let accepted = try_consume_legacy_status(&identity, &event, None);
        let accepted_attempt = LegacyAttempt::since(before);
        // Nothing observed: the stop is consumed.
        let before = LegacyAttempt::now();
        let empty = try_consume_legacy_status(&identity, &event, None);
        let empty_attempt = LegacyAttempt::since(before);
        legacy_owner_restore_descriptors(&saved);

        // Hand a consumed stop to the worker, as `try_assist_legacy_wait`
        // does, so that the SDK wait below returns it.
        if let Ok(Some(status)) = accepted {
            progress.consumed.push_back(status);
            progress.observed = None;
            progress.error = None;
            event.count_legacy_wakeup();
        }
        (
            refused,
            refused_attempt,
            after_refusal,
            accepted,
            accepted_attempt,
            empty,
            empty_attempt,
        )
    };
    event.notify_legacy_worker();

    // Direct calls queue nothing for the worker, so `consumed` stays 0 even
    // for the attempt that consumed the stop from the kernel.
    assert_eq!(refused, Err(Errno::EMFILE));
    assert_eq!(
        refused_attempt,
        LegacyAttempt {
            reads: 1,
            accepted: 0,
            refused: 1,
            consumed: 0,
        }
    );
    assert_eq!(after_refusal, stop, "the refused attempt consumed the stop");
    assert_eq!(accepted, Ok(Some(stop)));
    assert_eq!(
        accepted_attempt,
        LegacyAttempt {
            reads: 0,
            accepted: 1,
            refused: 0,
            consumed: 0,
        }
    );
    assert_eq!(empty, Err(Errno::EMFILE));
    assert_eq!(
        empty_attempt,
        LegacyAttempt {
            reads: 1,
            accepted: 0,
            refused: 0,
            consumed: 0,
        }
    );
    let (stopped, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    let exit = stopped.exit_event_on_ptracer_thread();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let running = stopped.resume(None).unwrap();
    let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (tid.into(), crate::ExitStatus::Exited(23))
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    legacy_owner_reap_root(root, &mut root_cleanup);
    drop(running);
    emit_completion_marker("ACTUAL_LEGACY_STOP_PROOF_EMFILE_BOUNDARY_EXERCISED");
}

/// The stop proof needs the Event's bound owner, not merely the target's
/// current tracer. When another thread of this process becomes the tracer
/// behind the Event's back (a raw detach and seize that skip
/// `reconnect_attachment`, which would retire the Event), its attempt on the
/// old Event is refused with EPERM through the read, and the stop it holds is
/// left unconsumed.
#[test]
#[cfg(not(sanitized))]
fn forced_legacy_stop_proof_refuses_a_tracer_that_is_not_the_bound_owner() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_stop_proof_refuses_a_tracer_that_is_not_the_bound_owner",
        Some("ACTUAL_LEGACY_STOP_PROOF_WRONG_OWNER_EXERCISED"),
    ) {
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    let _force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let terminal = running.terminal_cleanup();
    assert!(matches!(
        terminal.event.identity().unwrap().pidfd,
        ThreadHandle::Procfs { .. }
    ));
    let event = Arc::clone(terminal.event.event());
    assert!(
        event
            .legacy_wait_owner
            .get()
            .is_some_and(|owner| owner.is_current() == Ok(true))
    );
    running.interrupt().unwrap();
    let (stopped, stop_event) = running
        .wait_sync_on_ptracer_thread()
        .wait()
        .unwrap()
        .assume_stopped();
    assert_eq!(stop_event, crate::Event::Stop);
    // The observation worker turns only under `legacy_wait`. Holding it from
    // here until the bound owner has the target back keeps the worker from
    // seeing the hand-offs below; the other thread's attempt runs under it.
    let progress = event.legacy_wait.lock();
    // A raw detach leaves this Event, its open gate and its bound owner.
    nix::sys::ptrace::detach(tid, None).unwrap();
    assert!(!*event.terminal_reaping.read());
    let handle = terminal.event.clone();
    let other = thread::spawn(move || {
        let identity = handle.identity().unwrap();
        let event = handle.event();
        nix::sys::ptrace::seize(tid, Options::PTRACE_O_EXITKILL).unwrap();
        nix::sys::ptrace::interrupt(tid).unwrap();
        let stop = legacy_owner_observe(tid, WaitPidFlag::WSTOPPED);
        let before = LegacyAttempt::now();
        let result = try_consume_legacy_status(identity, event, None);
        let attempt = LegacyAttempt::since(before);
        let left = waitid::wait_raw(
            waitid::IdType::Pid(tid),
            WaitPidFlag::from_bits_retain(
                WaitPidFlag::WSTOPPED.bits()
                    | WaitPidFlag::WNOWAIT.bits()
                    | WaitPidFlag::WNOHANG.bits()
                    | libc::__WALL
                    | libc::__WNOTHREAD,
            ),
        );
        nix::sys::ptrace::detach(tid, None).unwrap();
        (stop, result, attempt, left)
    });
    let (stop, result, attempt, left) = other.join().unwrap();
    assert_eq!(stop, LEGACY_OWNER_EVENT_STOP);
    assert_eq!(result, Err(Errno::EPERM));
    // A direct call queues nothing for the worker: `consumed` stays 0.
    assert_eq!(
        attempt,
        LegacyAttempt {
            reads: 1,
            accepted: 0,
            refused: 1,
            consumed: 0,
        }
    );
    assert_eq!(
        left,
        Ok(Some(stop)),
        "the refused attempt consumed the stop"
    );
    // The bound owner takes the target back and detaches through the SDK.
    nix::sys::ptrace::seize(tid, legacy_thread_options()).unwrap();
    nix::sys::ptrace::interrupt(tid).unwrap();
    let status = waitpid_status_bounded(tid, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
    assert_eq!(status, LEGACY_OWNER_EVENT_STOP);
    drop(progress);
    let detached = stopped.detach(None).unwrap();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    legacy_owner_reap_root(root, &mut root_cleanup);
    drop(detached);
    emit_completion_marker("ACTUAL_LEGACY_STOP_PROOF_WRONG_OWNER_EXERCISED");
}
