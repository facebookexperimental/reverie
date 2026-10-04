/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_exit_payload_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn actual_exec_without_prior_payload_retains_same_owner_across_refusal() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let _observations = FatalReapObservationScope::new();
        let control = Arc::new(ExitPayloadControl::default());
        EXIT_PAYLOAD_CONTROL.with(|slot| *slot.borrow_mut() = Some(control.clone()));
        let sentinel = fork_paused_child(deadline);
        let sentinel_identity = untraced_process_identity(sentinel);
        let tracer = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            spawn_fn_with_config::<ExecOwnerTool, _>(
                || {
                    std::thread::spawn(|| {
                        let args = [c"/bin/true".as_ptr(), std::ptr::null()];
                        unsafe {
                            libc::execv(args[0], args.as_ptr());
                            libc::_exit(127);
                        }
                    });
                    loop {
                        unsafe {
                            libc::pause();
                        }
                    }
                },
                (false, 0),
                true,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let root = tracer.guest_pid();
        let log = tracer.gref.0.clone();
        let termination = tracer.termination_handle().unwrap();
        let mut outcome = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            tracer.wait_with_output_completion(),
        )
        .await
        .unwrap();
        let (recorded_pid, former, actual_exit) = control
            .payload
            .lock()
            .unwrap()
            .expect("real Exec and actual preceding EXIT payload required");
        assert_eq!(recorded_pid, root);
        assert_ne!(former, root);
        let owner = FATAL_REAP_OBSERVATIONS.with(|slot| {
            slot.borrow()
                .as_ref()
                .unwrap()
                .iter()
                .find(|owner| owner.tid == root)
                .unwrap()
                .clone()
        });
        for attempt in 0..2 {
            let ToolRunOutcome::CleanupPending(pending) = outcome else {
                panic!("missing actual EXIT payload must retain Pending, attempt {attempt}");
            };
            let failure = pending.failure();
            assert!(
                matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<ExitEventStatusUnavailable>().is_some_and(|error| error.pid == root && error.former == former))
            );
            assert!(failure.captured_prefix().unwrap().stdout().is_empty());
            {
                let held_guard = owner.held.lock().unwrap();
                let held = held_guard.as_ref().expect("actual Exec stop retained");
                assert!(held.armed && held.terminal.same_generation(&owner.terminal));
                assert_eq!(held.status, HeldRootStopStatus::Exec(former));
                assert!(!owner.terminal.wait(Duration::ZERO));
                assert_eq!(owner.terminal.observed_exit_status(), Ok(None));
            }
            let info = ptrace::getsiginfo(root.into()).unwrap();
            assert_eq!(
                (info.si_signo, info.si_code),
                (
                    libc::SIGTRAP,
                    (libc::PTRACE_EVENT_EXEC << 8) | libc::SIGTRAP
                )
            );
            assert_eq!(
                ptrace::getevent(root.into()).unwrap(),
                i64::from(former.as_raw())
            );
            let events = log.lock().unwrap().clone();
            assert_eq!(events.iter().filter(|event| event.0 == 0).count(), 2);
            assert!(
                !events.iter().any(|event| matches!(event.0, 1..=4)),
                "invented consuming/continuation hook: {events:?}"
            );
            let sentinel_untouched = sentinel_identity.same_process()
                && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                    == 0;
            assert!(sentinel_untouched);
            eprintln!(
                "actual Exec payload refusal: attempt={attempt}, root={root}, former={former}, actual_erased_payload={actual_exit:?}, same_generation=true, held_actual_exec=true, no_consuming_hooks=true, sentinel_untouched=true"
            );
            if attempt == 0 {
                outcome = tokio::time::timeout(
                    deadline.saturating_duration_since(Instant::now()),
                    pending.resume_cleanup(),
                )
                .await
                .unwrap();
            } else {
                outcome = ToolRunOutcome::CleanupPending(pending);
            }
        }
        assert!(Instant::now() < deadline);
        // This only qualifies refusal/retention. A real irretrievable payload
        // remains unavailable in production. For bounded test teardown, return
        // the exact actual value the test seam erased, then resume the SAME
        // pending owner under failure cancellation. This is not a claim that
        // production can reconstruct the missing kernel event payload.
        control.restore_for_teardown.store(true, Ordering::SeqCst);
        let _ = termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
        let ToolRunOutcome::CleanupPending(pending) = outcome else {
            unreachable!()
        };
        let rescued = tokio::time::timeout(Duration::from_secs(2), pending.resume_cleanup())
            .await
            .unwrap();
        EXIT_PAYLOAD_CONTROL.with(|slot| *slot.borrow_mut() = None);
        let ToolRunOutcome::Complete(done) = rescued else {
            panic!("same-owner test teardown failed")
        };
        let failure = done.result.unwrap_err();
        assert!(
            matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<ExitEventStatusUnavailable>().is_some())
        );
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        assert!(owner.terminal.wait(Duration::ZERO));
        assert!(owner.held.lock().unwrap().is_none());
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), 0) },
            sentinel.as_raw()
        );
        eprintln!(
            "separate same-owner teardown restored only the actually erased test payload; physical terminal retirement confirmed"
        );
    }

    struct ExitResumeScope;
    impl Drop for ExitResumeScope {
        fn drop(&mut self) {
            EXIT_RESUME_CONTROL.with(|slot| *slot.borrow_mut() = None);
        }
    }

    async fn real_exit_resume_control(kill: bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let started = Instant::now();
        let _observations = FatalReapObservationScope::new();
        let _control_scope = ExitResumeScope;
        let control = Arc::new(ExitResumeControl::default());
        EXIT_RESUME_CONTROL.with(|slot| *slot.borrow_mut() = Some(control.clone()));
        let words = FatalWords::new();
        let address = words.0 as usize;
        let sentinel = fork_paused_child(deadline);
        let sentinel_identity = untraced_process_identity(sentinel);
        let tracer = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            spawn_fn_with_config::<ExecOwnerTool, _>(
                move || {
                    let word = move |index: usize| unsafe {
                        &*(address as *const std::sync::atomic::AtomicUsize).add(index)
                    };
                    std::thread::spawn(move || {
                        word(1).store(
                            unsafe { libc::syscall(libc::SYS_gettid) } as usize,
                            Ordering::SeqCst,
                        );
                        while word(0).load(Ordering::SeqCst) == 0 {
                            unsafe {
                                libc::sched_yield();
                            }
                        }
                        unsafe {
                            libc::syscall(libc::SYS_exit, 0);
                        }
                    });
                    while word(1).load(Ordering::SeqCst) == 0 {
                        unsafe {
                            libc::sched_yield();
                        }
                    }
                    unsafe {
                        libc::syscall(libc::SYS_exit, 23);
                    }
                },
                (false, 0),
                true,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let root = tracer.guest_pid();
        control
            .target
            .store(root.as_raw() as usize, Ordering::SeqCst);
        let identity = untraced_process_identity(root);
        let termination = tracer.termination_handle().unwrap();
        let log = tracer.gref.0.clone();
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
            while !control.entered.load(Ordering::SeqCst) {
                tokio::select! {
                    _ = &mut completion => panic!("completed before real EXIT/getevent gate"),
                    () = tokio::task::yield_now() => {}
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(control.payload.load(Ordering::SeqCst), 23 << 8);
        let sibling = Pid::from_raw(words.read(1) as i32);
        assert_ne!(sibling, root);
        assert!(identity.same_process());
        if kill {
            identity.send_signal(Signal::SIGKILL).unwrap();
            tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), async {
                loop {
                    let mut query = libc::pollfd { fd: identity.pidfd.as_ref().unwrap().as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    let observed = unsafe { libc::poll(&mut query, 1, 0) };
                    assert!(observed >= 0);
                    if observed == 1 && query.revents & libc::POLLIN != 0 { break; }
                    tokio::select! {
                        _ = &mut completion => panic!("completed while original EXIT capability parked"),
                        () = tokio::task::yield_now() => {}
                    }
                }
            }).await.unwrap();
        } else {
            unsafe { &*(address as *const std::sync::atomic::AtomicUsize) }
                .store(1, Ordering::SeqCst);
        }
        control.release.store(true, Ordering::SeqCst);
        let result = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut completion,
        )
        .await;
        let resumes = control.results.lock().unwrap().clone();
        let events = log.lock().unwrap().clone();
        let untouched = sentinel_identity.same_process()
            && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                == 0;
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!("Complete({:?})", done.result),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "Unsupported".into(),
            Err(error) => format!("Timeout({error})"),
        };
        eprintln!(
            "actual EXIT/resume control before rescue: kill={kill}, root={root}, sibling={sibling}, payload={}, resumes={resumes:?}, events={events:?}, sentinel_untouched={untouched}, outcome={description}, elapsed={:?}",
            control.payload.load(Ordering::SeqCst),
            started.elapsed()
        );
        eprintln!(
            "actual EXIT/resume owner readback: {}",
            fatal_reap_readback()
        );
        let done = match result {
            Ok(ToolRunOutcome::Complete(done)) => done,
            other => {
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let _ = identity.send_signal(Signal::SIGKILL);
                let rescue = match other {
                    Err(_) => tokio::time::timeout(Duration::from_secs(2), &mut completion).await,
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout(Duration::from_secs(2), pending.resume_cleanup()).await
                    }
                    _ => panic!("unexpected unsupported ordinary owner"),
                };
                eprintln!(
                    "separate EXIT/resume rescue completed={}",
                    matches!(rescue, Ok(ToolRunOutcome::Complete(_)))
                );
                panic!("original EXIT/resume predicate failed: {description}");
            }
        };
        let status = if kill {
            ExitStatus::Signaled(Signal::SIGKILL, false)
        } else {
            ExitStatus::Exited(0)
        };
        assert!(done.callback_diagnostics().is_empty());
        let output = done.result.unwrap();
        assert_eq!(output.status, status);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        assert!(resumes.iter().any(|(pid, result)| *pid == root
            && *result == if kill { Err(Errno::ESRCH) } else { Ok(()) }));
        assert_eq!(events.iter().filter(|event| event.0 == 0).count(), 2);
        for tid in [root, sibling] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.0 == 2 && event.1 == tid && event.3 == Some(status))
                    .count(),
                1
            );
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| event.0 == 3 && event.1 == root && event.3 == Some(status))
                .count(),
            1
        );
        assert_eq!(events.len(), 5);
        assert!(
            FATAL_REAP_OBSERVATIONS.with(|slot| slot.borrow().as_ref().unwrap().iter().all(
                |owner| owner.terminal.wait(Duration::ZERO)
                    && owner.held.lock().unwrap().is_none()
                    && owner.terminal.observed_exit_status() == Ok(Some(status))
            ))
        );
        assert_reaped("EXIT/resume root", root);
        assert_reaped("EXIT/resume sibling", sibling);
        assert!(untouched && Instant::now() < deadline);
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), 0) },
            sentinel.as_raw()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_group_kill_after_exit_payload_retains_original_resume_owner() {
        real_exit_resume_control(true).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_exit_payload_without_kill_preserves_normal_resume() {
        real_exit_resume_control(false).await;
    }
}
