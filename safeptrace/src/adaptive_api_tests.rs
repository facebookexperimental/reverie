/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[test]
fn retained_controller_guard_keeps_send_and_sync_contracts() {
    fn send_and_sync<T: Send + Sync>() {}
    send_and_sync::<PtracerThreadGuard>();
}

#[test]
#[cfg(not(sanitized))]
fn retained_controller_host_guard_is_passive_and_rejects_foreign_tasks() {
    const NAME: &str = "retained_controller_host_guard_is_passive_and_rejects_foreign_tasks";
    const MARKER: &str = "ACTUAL_RETAINED_CONTROLLER_HOST_GUARD_EXERCISED";
    if run_legacy_test_outer_with_outcome(NAME, Some(MARKER)) {
        return;
    }
    for forced in [false, true] {
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                unsafe { libc::_exit(23) };
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let generation = stopped.generation();
        let terminal = generation.terminal_cleanup();
        let event = stopped.1.event().clone();
        let captures = PTRACER_OWNER_CAPTURES.with(Cell::get);
        let guard = generation.ptracer_thread_guard().unwrap();
        let retained = generation.retained_ptracer_thread_guard().unwrap().unwrap();
        assert!(Arc::ptr_eq(&guard.owner, &retained.owner));
        let cold_bound = generation.ptracer_thread_guard_for_wait().unwrap();
        assert!(Arc::ptr_eq(&guard.owner, &cold_bound.owner));
        assert!(Arc::ptr_eq(
            &guard.owner,
            stopped.1.ptracer_owner.as_ref().unwrap()
        ));
        assert_eq!(PTRACER_OWNER_CAPTURES.with(Cell::get), captures);
        assert_eq!(guard.check_current(), Ok(()));
        assert!(
            terminal.same_generation(&TerminalCleanup::new_unregistered(root.into(), &stopped.1))
        );
        assert_eq!(
            event.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert_eq!(
            event.event().wait_owner.load(Ordering::Acquire),
            WAIT_OWNER_NONE
        );
        assert!(!NOTIFIER.pids.lock().contains_key(&root.into()));
        if forced {
            assert_eq!(terminal.has_thread_pidfd(), Ok(false));
        }
        let original_registers = stopped.getregs().unwrap();
        let original_siginfo = stopped.getsiginfo().unwrap();
        let sibling_guard = guard.clone();
        thread::spawn(move || {
            assert_eq!(sibling_guard.check_current(), Err(Errno::EPERM));
        })
        .join()
        .unwrap();
        // No observer has started. A raw fork copies the same bound guard;
        // the child must not replace its anchor with its own host identity.
        let forked = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                assert_eq!(guard.check_current(), Err(Errno::EPERM));
                unsafe { libc::_exit(0) };
            }
        };
        let status = waitpid_status_bounded(forked, 0, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(guard.check_current(), Ok(()));
        assert_eq!(stopped.getregs().unwrap(), original_registers);
        assert_eq!(
            stopped.getsiginfo().unwrap().si_signo,
            original_siginfo.si_signo
        );
        assert_eq!(
            stopped.getsiginfo().unwrap().si_code,
            original_siginfo.si_code
        );
        assert_eq!(
            event.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert_eq!(
            event.event().wait_owner.load(Ordering::Acquire),
            WAIT_OWNER_NONE
        );
        assert!(terminal.pending_is_empty());
        let _detached = stopped.detach(Signal::SIGKILL).unwrap();
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        assert_eq!(retained.check_current(), Ok(()));
        assert!(Arc::ptr_eq(
            &guard.owner,
            &generation
                .retained_ptracer_thread_guard()
                .unwrap()
                .unwrap()
                .owner
        ));
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn owned_native_accessors_preserve_capture_refusal_without_registering() {
    const NAME: &str = "owned_native_accessors_preserve_capture_refusal_without_registering";
    const MARKER: &str = "ACTUAL_NATIVE_ACCESSOR_CAPTURE_REFUSAL_EXERCISED";
    if run_legacy_test_outer_with_outcome(NAME, Some(MARKER)) {
        return;
    }
    let (root, tid, _release, mut cleanup) = legacy_owner_guest();
    CAPTURE_ERRORS.lock().insert(tid.into(), Errno::EACCES);
    // A successful attachment retains its exact post-attachment capture
    // refusal. Running::new's separate fresh-token contract intentionally
    // does not retain an acquisition refusal and is not this fixture.
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    assert!(!CAPTURE_ERRORS.lock().contains_key(&tid.into()));
    assert_eq!(
        worker_proc_snapshot(tid.into()).unwrap().tracer_pid,
        nix::unistd::gettid().into()
    );
    let generation = running.generation();
    let event = running.1.event().clone();
    assert!(matches!(
        generation.ptracer_thread_guard(),
        Err(Errno::EACCES)
    ));
    assert!(matches!(
        generation.ptracer_thread_guard_for_wait(),
        Err(Errno::EACCES)
    ));
    assert!(matches!(
        generation.retained_ptracer_thread_guard(),
        Err(Errno::EACCES)
    ));
    let mut owned = running.wait_owned();
    assert_eq!(owned.generation().unwrap(), generation);
    let terminal = owned.terminal_cleanup().unwrap();
    assert_eq!(terminal.registration_error(), Some(Errno::EACCES));
    assert_eq!(
        event.event().worker_state.load(Ordering::Acquire),
        WORKER_NOT_STARTED
    );
    assert_eq!(
        event.event().wait_owner.load(Ordering::Acquire),
        WAIT_OWNER_NONE
    );
    assert!(!NOTIFIER.pids.lock().contains_key(&tid.into()));
    for _ in 0..2 {
        let waker = futures::task::noop_waker();
        assert!(matches!(
            Pin::new(&mut owned).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(OwnedWaitError::Errno(Errno::EACCES)))
        ));
        assert_eq!(owned.generation().unwrap(), generation);
        owned = match owned.into_zombie_after_observed_death() {
            Err(original) => original,
            Ok(_) => panic!("capture refusal manufactured a Zombie"),
        };
    }
    assert_eq!(
        event.event().worker_state.load(Ordering::Acquire),
        WORKER_NOT_STARTED
    );
    assert_eq!(
        event.event().wait_owner.load(Ordering::Acquire),
        WAIT_OWNER_NONE
    );
    pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL).unwrap();
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    loop {
        assert!(
            Instant::now() < deadline,
            "original capture-refusal cleanup deadline"
        );
        let status = waitpid_status_bounded(
            tid,
            libc::__WALL | libc::__WNOTHREAD,
            deadline.saturating_duration_since(Instant::now()),
        )
        .unwrap();
        if libc::WIFSTOPPED(status) {
            assert_eq!(
                unsafe { libc::ptrace(libc::PTRACE_CONT, tid.as_raw(), 0usize, 0usize) },
                0
            );
            continue;
        }
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        break;
    }
    legacy_owner_reap_root(root, &mut cleanup);
    assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn owned_native_death_transfer_retains_the_original_generation() {
    const NAME: &str = "owned_native_death_transfer_retains_the_original_generation";
    const INNER: &str = "SAFEPTRACE_NATIVE_DEATH_TRANSFER_INNER";
    const MARKER: &str = "ACTUAL_NATIVE_OWNED_DEATH_TRANSFER_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_DEATH_TRANSFER_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let fork_stop = (libc::PTRACE_EVENT_FORK << 16) | (libc::SIGTRAP << 8) | 0x7f;
    let root = match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            crate::traceme_and_stop().unwrap();
            unsafe {
                if libc::fork() == 0 {
                    libc::pause();
                    libc::_exit(0);
                }
                libc::pause();
                libc::_exit(0);
            }
        }
    };
    let mut root_cleanup = TraceeCleanupGuard::new(root).unwrap();
    let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    let running = match Running::try_new(root.into()) {
        Ok(running) => running,
        Err(Errno::EINVAL) => {
            assert_eq!(unsafe { libc::kill(root.as_raw(), libc::SIGKILL) }, 0);
            let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            root_cleanup.disarm();
            println!("{UNAVAILABLE}");
            return;
        }
        Err(error) => panic!("original native acquisition refused: {error}"),
    };
    let generation = running.generation();
    assert!(generation.1.ptracer_owner.is_none());
    assert!(
        generation
            .retained_ptracer_thread_guard()
            .unwrap()
            .is_none()
    );
    let terminal = generation.terminal_cleanup();
    let original = running.1.event().clone();
    assert_eq!(terminal.has_thread_pidfd(), Ok(true));
    let guard = generation.ptracer_thread_guard().unwrap();
    let cold_bound = generation.ptracer_thread_guard_for_wait().unwrap();
    assert_eq!(guard.check_current(), Ok(()));
    assert_eq!(cold_bound.check_current(), Ok(()));
    let foreign_generation = generation.clone();
    thread::spawn(move || {
        assert!(matches!(
            foreign_generation.ptracer_thread_guard_for_wait(),
            Err(Errno::EPERM)
        ));
    })
    .join()
    .unwrap();
    assert!(generation.1.ptracer_owner.is_none());
    assert_eq!(
        original.event().worker_state.load(Ordering::Acquire),
        WORKER_NOT_STARTED
    );
    assert_eq!(
        original.event().wait_owner.load(Ordering::Acquire),
        WAIT_OWNER_NONE
    );
    let stopped = generation.assume_stopped();
    drop(running);
    stopped
        .setoptions(
            Options::PTRACE_O_TRACEFORK | Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_EXITKILL,
        )
        .unwrap();
    let mut exit = Box::pin(root_cleanup.exit_event(&stopped).unwrap());
    let running = stopped.resume(None).unwrap();
    while terminal.pending_is_empty() {
        assert!(Instant::now() < deadline, "no actual fork front");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(terminal.queued_raw_statuses(), [fork_stop]);
    let child = Pid::from_raw(nix::sys::ptrace::getevent(root).unwrap() as i32);
    let _child_cleanup = TraceeCleanupGuard::new(child).unwrap();
    terminal.request_sigkill().unwrap();
    while !terminal.exit_stop_observed() {
        assert!(Instant::now() < deadline, "no actual EXIT stop");
        thread::sleep(Duration::from_millis(1));
    }
    drop(running);
    let stopped = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        exit.as_mut(),
    )
    .await
    .unwrap()
    .unwrap();
    root_cleanup.mark_claimed_exit();
    assert_eq!(
        stopped.superseded_new_child(),
        Err(SupersededStopRefusal::NewChild(fork_stop))
    );
    let Ok(running) = stopped.resume_retaining(None) else {
        panic!("actual EXIT resume refused");
    };
    let mut owned = running.wait_owned();
    assert_eq!(owned.generation().unwrap(), generation);
    assert!(owned.terminal_cleanup().unwrap().same_generation(&terminal));
    owned = match owned.into_zombie_after_observed_death() {
        Err(original) => original,
        Ok(_) => panic!("an unpolled wait manufactured a Zombie"),
    };
    assert!(matches!(
        tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut owned
        )
        .await
        .unwrap(),
        Err(OwnedWaitError::Died)
    ));
    assert_eq!(owned.generation().unwrap(), generation);
    let zombie = match owned.into_zombie_after_observed_death() {
        Ok(zombie) => zombie,
        Err(_) => panic!("actual decoder Died did not transfer its original input"),
    };
    assert_eq!(zombie.pid(), root.into());
    assert_eq!(zombie.generation(), generation);
    let mut final_wait = zombie.wait_owned();
    assert_eq!(final_wait.generation().unwrap(), generation);
    assert_eq!(
        tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut final_wait
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        )
    );
    assert!(final_wait.generation().is_none());
    assert!(final_wait.terminal_cleanup().is_none());
    assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
    assert_eq!(guard.check_current(), Ok(()));
    assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(false));
    // The original guard remains usable after actual target retirement;
    // a missing anchor cannot be minted from a retired Native directory.
    assert!(matches!(
        generation.ptracer_thread_guard(),
        Err(Errno::ESRCH)
    ));
    assert!(matches!(
        generation.ptracer_thread_guard_for_wait(),
        Err(Errno::ESRCH)
    ));
    assert!(terminal.pending_is_empty());
    root_cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
    emit_completion_marker(MARKER);
}
