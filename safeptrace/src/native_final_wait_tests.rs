/* Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file. */

// Included under notifier::test for its actual TRACEME child and exact cleanup
// guard. These are native final-wait controls, not source or DSR authority.
mod native_final_wait_tests {
    use super::*;

    // Port adaptation: the source branch's public `TerminalCleanup::is_reaped`
    // arrived with a later, unported change. These tests need only its
    // observation, so it is reproduced here verbatim as a test-only helper.
    impl TerminalCleanup {
        /// Observe retirement of the retained kernel generation without
        /// waiting or consuming a status. This does not reopen a numeric PID.
        fn is_reaped(&self) -> Result<bool, Errno> {
            let identity = self.event.identity().ok_or(Errno::ENXIO)?;
            if identity.pid != self.pid {
                return Err(Errno::ECHILD);
            }
            let mut fd = libc::pollfd {
                fd: identity.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut fd, 1, 0) } < 0 {
                return Err(io_errno(io::Error::last_os_error()));
            }
            if fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(Errno::EBADF);
            }
            Ok(fd.revents & libc::POLLHUP != 0)
        }
    }

    fn remaining(deadline: Instant) -> Duration {
        deadline.saturating_duration_since(Instant::now())
    }

    struct PublicationRelease {
        release: Option<mpsc::SyncSender<()>>,
        event: Arc<Event>,
    }

    impl PublicationRelease {
        fn release(&mut self) {
            // Disconnection releases the existing real-worker pause. Do this
            // before taking its installation mutex, including during unwind.
            drop(self.release.take());
            self.event.terminal_publish_pause.lock().take();
            self.event.sync_wait_entered.lock().take();
        }
    }

    impl Drop for PublicationRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    #[test]
    fn original_sync_wait_joins_actual_reaped_unpublished_notifier() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn final-wait TRACEME child");
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        cleanup.bind_notifier(&stopped).unwrap();
        let identity = Arc::clone(terminal.event.identity().unwrap());
        let event = Arc::clone(terminal.event.event());
        let (captured, paused) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.terminal_publish_pause.lock() = Some(BoundedTestPause { captured, resume });
        let mut release = PublicationRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        let running = stopped.resume_retaining(None).unwrap();
        let same_event = Arc::ptr_eq(running.1.event().event(), &event);
        let paused = paused.recv_timeout(remaining(deadline));
        // These are observations of a genuine kernel final wait, not a test
        // update(status), replacement identity, or an ECHILD-to-exit inference.
        let reaped_before = terminal.is_reaped();
        let live_before = identity.pidfd_is_live();
        let terminal_before = terminal.observed_exit_status();
        let owner_before = event.wait_owner.load(Ordering::Acquire);
        let worker_before = event.worker_state.load(Ordering::Acquire);
        let (transition, transitions) = mpsc::sync_channel(2);
        let (done, completed) = mpsc::sync_channel(1);
        *event.sync_wait_entered.lock() = Some(transition.clone());
        let waiter = thread::spawn(move || {
            let result = running.wait();
            let _ = done.send(result);
            let _ = transition.send(SyncWaitTestTransition::Returned);
        });
        // Both outcomes are events from actual code: entering the original
        // Event's empty-status wait, or returning (including early recapture
        // failure). A timed absence is never taken as proof of wait entry.
        let first = transitions.recv_timeout(remaining(deadline));
        let terminal_during = terminal.observed_exit_status();
        release.release(); // Every outcome releases BEFORE assertions or joins.
        let result = completed.recv_timeout(remaining(deadline));
        let returned = if matches!(first, Ok(SyncWaitTestTransition::Returned)) {
            Ok(SyncWaitTestTransition::Returned)
        } else {
            transitions.recv_timeout(remaining(deadline))
        };
        let joined = if matches!(returned, Ok(SyncWaitTestTransition::Returned)) {
            Some(waiter.join())
        } else {
            // Do not turn a bounded failed receipt into an unbounded join.
            // The exact child guard still owns cleanup on this failure path.
            drop(waiter);
            None
        };
        let retired = terminal.wait(remaining(deadline));
        let terminal_after = terminal.observed_exit_status();
        let reaped_after = terminal.is_reaped();
        let cleanup_result = cleanup.cleanup();
        eprintln!(
            "actual final-wait gap pid={pid}: paused={paused:?}, same_event={same_event}, reaped_before={reaped_before:?}, live_before={live_before:?}, terminal_before={terminal_before:?}, owner={owner_before}, worker={worker_before}, first={first:?}, terminal_during={terminal_during:?}, result={result:?}, retired={retired}, terminal_after={terminal_after:?}, reaped_after={reaped_after:?}, cleanup={cleanup_result:?}"
        );
        cleanup_result.expect("exact original child cleanup");
        paused.expect("actual notifier final wait did not reach its publication pause");
        assert!(same_event, "resume changed the retained Event");
        assert_eq!(reaped_before, Ok(true));
        assert_eq!(live_before, Ok(false));
        assert_eq!(terminal_before, Ok(None));
        assert_eq!(terminal_during, Ok(None));
        assert_eq!(owner_before, WAIT_OWNER_NOTIFIER);
        assert_eq!(worker_before, WORKER_RUNNING);
        assert!(retired, "original notifier did not retire");
        assert_eq!(terminal_after, Ok(Some(crate::ExitStatus::Exited(42))));
        assert_eq!(reaped_after, Ok(true));
        joined
            .expect("synchronous waiter did not return within the original bound")
            .expect("synchronous waiter panicked");
        assert_eq!(
            first.unwrap(),
            SyncWaitTestTransition::WaitingForNotifier,
            "original synchronous wait returned before joining its retained Event"
        );
        assert_eq!(
            result.unwrap().unwrap().assume_exited(),
            (pid.into(), crate::ExitStatus::Exited(42))
        );
        assert!(
            Instant::now() < deadline,
            "final-wait control exhausted the original three-second component bound"
        );
    }

    #[test]
    fn original_sync_wait_consumes_actual_dead_but_unreaped_status() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn unreaped final-wait child");
        // Keep this actual child unregistered: the original synchronous wait
        // must consume the real pending exit itself. The pre-registration
        // cleanup guard retains its own exact pidfd throughout.
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        let identity = Arc::clone(terminal.event.identity().unwrap());
        let running = stopped.resume_retaining(None).unwrap();
        let mut pollfd = libc::pollfd {
            fd: identity.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_result = unsafe {
            libc::poll(
                &mut pollfd,
                1,
                remaining(deadline).as_millis().min(i32::MAX as u128) as i32,
            )
        };
        let poll_error = (poll_result < 0).then(Errno::last);
        let flags = WaitPidFlag::from_bits_retain(libc::WEXITED | libc::WNOHANG | libc::__WALL);
        let pending = waitid::waitpidfd(identity.pidfd.as_raw_fd(), flags | WaitPidFlag::WNOWAIT);
        let live_before = identity.pidfd_is_live();
        let reaped_before = terminal.is_reaped();
        let terminal_before = terminal.observed_exit_status();
        let worker_before = terminal.event.event().worker_state.load(Ordering::Acquire);
        let result = running.wait();
        // This is fixture cleanup on the retained pidfd AFTER the synchronous
        // owner returned. It cannot supply the test's required typed result.
        // On a broken wait it drains the actual still-pending child status;
        // on a correct wait it must find that exact status already consumed.
        let cleanup_wait = waitid::waitpidfd(identity.pidfd.as_raw_fd(), flags);
        let reaped_after = terminal.is_reaped();
        if matches!(reaped_after, Ok(true)) {
            cleanup.disarm();
        }
        let cleanup_result = cleanup.cleanup();
        eprintln!(
            "actual unreaped final-wait pid={pid}: poll={poll_result}, poll_error={poll_error:?}, revents={:#x}, pending={pending:?}, live_before={live_before:?}, reaped_before={reaped_before:?}, terminal_before={terminal_before:?}, worker={worker_before}, result={result:?}, cleanup_wait={cleanup_wait:?}, reaped_after={reaped_after:?}, cleanup={cleanup_result:?}",
            pollfd.revents
        );
        cleanup_result.expect("exact unreaped child cleanup");
        assert_eq!(poll_result, 1, "actual exit readiness: {poll_error:?}");
        assert_eq!(pollfd.revents & libc::POLLIN, libc::POLLIN);
        assert_eq!(
            pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL),
            0
        );
        assert_eq!(
            pending,
            Ok(Some(42 << 8)),
            "WNOWAIT must preserve the real exit"
        );
        assert_eq!(reaped_before, Ok(false));
        assert_eq!(terminal_before, Ok(None));
        assert_eq!(worker_before, WORKER_NOT_STARTED);
        assert_eq!(
            result.unwrap().assume_exited(),
            (pid.into(), crate::ExitStatus::Exited(42))
        );
        assert_eq!(cleanup_wait, Err(Errno::ECHILD));
        assert_eq!(reaped_after, Ok(true));
        assert!(
            Instant::now() < deadline,
            "unreaped control exhausted the original three-second component bound"
        );
    }

    #[test]
    fn retained_worker_does_not_return_queued_stop_after_actual_reap() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn queued final-wait child");
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        cleanup.bind_notifier(&stopped).unwrap();
        let event = Arc::clone(terminal.event.event());
        let (captured, paused) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.terminal_publish_pause.lock() = Some(BoundedTestPause { captured, resume });
        let mut release = PublicationRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        // Deliver SIGSTOP at the real initial signal-delivery stop. The
        // notifier must receive the resulting real group stop into its FIFO;
        // neither this test nor its hook calls Event::update with a made-up stop.
        let running = stopped.resume_retaining(Some(Signal::SIGSTOP)).unwrap();
        let queued_before = event
            .wait_pending_status(remaining(deadline))
            .and_then(|state| state.pending.front().copied());
        let killed = terminal.request_sigkill();
        let paused = paused.recv_timeout(remaining(deadline));
        let reaped_before = terminal.is_reaped();
        let terminal_before = terminal.observed_exit_status();
        let worker_before = event.worker_state.load(Ordering::Acquire);
        let owner_before = event.wait_owner.load(Ordering::Acquire);
        let result = running.wait();
        let queued_after = event.status.lock().pending.front().copied();
        let terminal_during = terminal.observed_exit_status();
        release.release();
        let retired = terminal.wait(remaining(deadline));
        let terminal_after = terminal.observed_exit_status();
        let reaped_after = terminal.is_reaped();
        let cleanup_result = cleanup.cleanup();
        eprintln!(
            "actual stale queued stop pid={pid}: queued_before={queued_before:?}, killed={killed:?}, paused={paused:?}, reaped_before={reaped_before:?}, terminal_before={terminal_before:?}, worker={worker_before}, owner={owner_before}, result={result:?}, queued_after={queued_after:?}, terminal_during={terminal_during:?}, retired={retired}, terminal_after={terminal_after:?}, reaped_after={reaped_after:?}, cleanup={cleanup_result:?}"
        );
        cleanup_result.expect("exact queued-stop child cleanup");
        killed.expect("signal the original retained pidfd");
        paused.expect("real queued-stop child reap before publication");
        let queued = queued_before.expect("actual second stop must reach the original FIFO");
        assert!(libc::WIFSTOPPED(queued));
        assert_eq!(libc::WSTOPSIG(queued), libc::SIGSTOP);
        assert_eq!(queued >> 16, 0, "ordinary stop, not an EXIT capability");
        assert_eq!(reaped_before, Ok(true));
        assert_eq!(terminal_before, Ok(None));
        assert_eq!(worker_before, WORKER_RUNNING);
        assert_eq!(owner_before, WAIT_OWNER_NOTIFIER);
        assert_eq!(terminal_during, Ok(None));
        assert_eq!(
            queued_after,
            Some(queued),
            "failed return consumed the old stop"
        );
        assert!(
            matches!(
                result,
                Err(Error::Errno(Errno::ECHILD | Errno::ENOENT | Errno::ESRCH))
            ),
            "retained worker minted a stopped capability from a reaped generation: {result:?}"
        );
        assert!(retired);
        assert_eq!(
            terminal_after,
            Ok(Some(crate::ExitStatus::Signaled(Signal::SIGKILL, false)))
        );
        assert_eq!(reaped_after, Ok(true));
        assert!(
            Instant::now() < deadline,
            "queued-stop control exhausted the original three-second component bound"
        );
    }

    struct IneligibleRelease {
        release: Option<mpsc::SyncSender<()>>,
        event: Arc<Event>,
    }

    impl IneligibleRelease {
        fn release(&mut self) {
            drop(self.release.take());
            self.event.sync_wait_ineligible_pause.lock().take();
        }
    }

    impl Drop for IneligibleRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    #[test]
    fn original_sync_wait_joins_notifier_started_after_ineligible_decision() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn startup-order final-wait child");
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        let identity = Arc::clone(terminal.event.identity().unwrap());
        let event = Arc::clone(terminal.event.event());
        let mut exit = stopped.exit_event();
        let same_exit_event = Arc::ptr_eq(exit.event.event(), &event);
        // Store exact cleanup custody without registering a notifier. Only the
        // retained public exit future's actual poll below will start this one.
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &stopped.1))
            .unwrap();
        let (captured, publication_paused) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.terminal_publish_pause.lock() = Some(BoundedTestPause { captured, resume });
        let mut publication_release = PublicationRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        let (captured, ineligible) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.sync_wait_ineligible_pause.lock() = Some(BoundedTestPause { captured, resume });
        let mut ineligible_release = IneligibleRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        let (transition, transitions) = mpsc::sync_channel(2);
        let (done, completed) = mpsc::sync_channel(1);
        *event.sync_wait_entered.lock() = Some(transition.clone());
        let running = stopped.resume_retaining(None).unwrap();
        let same_running_event = Arc::ptr_eq(running.1.event().event(), &event);
        let waiter = thread::spawn(move || {
            let result = running.wait();
            let _ = done.try_send(result);
            let _ = transition.try_send(SyncWaitTestTransition::Returned);
        });

        let ineligible = ineligible.recv_timeout(remaining(deadline));
        let worker_at_decision = event.worker_state.load(Ordering::Acquire);
        let owner_at_decision = event.wait_owner.load(Ordering::Acquire);
        // A missed observation is a failed premise, never permission to infer
        // the ordering from elapsed time. Both pause guards still own release.
        let exit_poll = if ineligible.is_ok() {
            let waker = Waker::from(Arc::new(WakeCounter::default()));
            let mut context = Context::from_waker(&waker);
            Some(Pin::new(&mut exit).poll(&mut context))
        } else {
            None
        };
        let exit_poll_pending = matches!(&exit_poll, Some(Poll::Pending));
        let exit_poll_summary = format!("{exit_poll:?}");
        if let Some(Poll::Ready(Ok(stopped))) = exit_poll {
            // An unexpected real exit-stop capability is a failed premise,
            // but its ownership must still reach exact cancellation cleanup.
            cleanup.mark_claimed_exit();
            drop(stopped);
        }
        let publication_paused = if exit_poll_pending {
            Some(publication_paused.recv_timeout(remaining(deadline)))
        } else {
            None
        };
        let same_registered_event = Arc::ptr_eq(exit.event.event(), &event);
        let same_registered_identity = terminal
            .event
            .identity()
            .is_some_and(|registered| Arc::ptr_eq(registered, &identity));
        let reaped_before = terminal.is_reaped();
        let live_before = identity.pidfd_is_live();
        let terminal_before = terminal.observed_exit_status();
        let worker_before = event.worker_state.load(Ordering::Acquire);
        let owner_before = event.wait_owner.load(Ordering::Acquire);

        // The real original notifier now owns exit42 but has not published it.
        // Let the original wait attempt numeric recapture only after that fact.
        ineligible_release.release();
        let first = transitions.recv_timeout(remaining(deadline));
        let terminal_during = terminal.observed_exit_status();
        publication_release.release();
        let result = completed.recv_timeout(remaining(deadline));
        let returned = if matches!(first, Ok(SyncWaitTestTransition::Returned)) {
            Ok(SyncWaitTestTransition::Returned)
        } else {
            transitions.recv_timeout(remaining(deadline))
        };
        // This poll bounds helper retirement, not either causal observation.
        // Never enter join on a helper whose completion has not been observed.
        while !waiter.is_finished() && !remaining(deadline).is_zero() {
            thread::sleep(SUBPROCESS_POLL_INTERVAL.min(remaining(deadline)));
        }
        let joined = if waiter.is_finished() {
            Some(waiter.join())
        } else {
            drop(waiter);
            None
        };
        let retired = terminal.wait(remaining(deadline));
        let terminal_after = terminal.observed_exit_status();
        let reaped_after = terminal.is_reaped();
        let cleanup_result = cleanup.cleanup();
        eprintln!(
            "actual startup final-wait pid={pid}: ineligible={ineligible:?}, worker_at_decision={worker_at_decision}, owner_at_decision={owner_at_decision}, same_exit_event={same_exit_event}, same_running_event={same_running_event}, exit_poll={exit_poll_summary}, publication_paused={publication_paused:?}, same_registered_event={same_registered_event}, same_registered_identity={same_registered_identity}, reaped_before={reaped_before:?}, live_before={live_before:?}, terminal_before={terminal_before:?}, worker={worker_before}, owner={owner_before}, first={first:?}, terminal_during={terminal_during:?}, result={result:?}, returned={returned:?}, retired={retired}, terminal_after={terminal_after:?}, reaped_after={reaped_after:?}, cleanup={cleanup_result:?}"
        );
        cleanup_result.expect("exact startup-order child cleanup");
        ineligible.expect("original wait did not reach its actual ineligible decision");
        assert_eq!(worker_at_decision, WORKER_NOT_STARTED);
        assert_eq!(owner_at_decision, WAIT_OWNER_NONE);
        assert!(same_exit_event && same_running_event);
        assert!(exit_poll_pending);
        publication_paused
            .expect("retained exit future did not register its actual notifier")
            .expect("actual notifier did not reap before publication");
        assert!(same_registered_event && same_registered_identity);
        assert_eq!(reaped_before, Ok(true));
        assert_eq!(live_before, Ok(false));
        assert_eq!(terminal_before, Ok(None));
        assert_eq!(terminal_during, Ok(None));
        assert_eq!(worker_before, WORKER_RUNNING);
        assert_eq!(owner_before, WAIT_OWNER_NOTIFIER);
        assert!(retired, "original startup notifier did not retire");
        assert_eq!(terminal_after, Ok(Some(crate::ExitStatus::Exited(42))));
        assert_eq!(reaped_after, Ok(true));
        assert_eq!(returned.unwrap(), SyncWaitTestTransition::Returned);
        joined
            .expect("startup synchronous helper did not finish within the original bound")
            .expect("startup synchronous helper panicked");
        assert_eq!(
            first.unwrap(),
            SyncWaitTestTransition::WaitingForNotifier,
            "startup after eligibility lost the original notifier's final result"
        );
        assert_eq!(
            result.unwrap().unwrap().assume_exited(),
            (pid.into(), crate::ExitStatus::Exited(42))
        );
        assert!(
            Instant::now() < deadline,
            "startup control exhausted the original three-second component bound"
        );
    }

    struct RegistrationRelease {
        release: Option<mpsc::SyncSender<()>>,
        event: Arc<Event>,
    }

    impl RegistrationRelease {
        fn release(&mut self) {
            drop(self.release.take());
            self.event.notifier_registration_pause.lock().take();
            self.event.sync_wait_owner_entered.lock().take();
        }
    }

    impl Drop for RegistrationRelease {
        fn drop(&mut self) {
            self.release();
        }
    }

    struct SpawnFailureReset(crate::Pid);

    impl Drop for SpawnFailureReset {
        fn drop(&mut self) {
            SPAWN_WORKER_ERRORS.lock().remove(&self.0);
        }
    }

    fn finish_helper<T>(helper: JoinHandle<T>, deadline: Instant) -> Option<thread::Result<T>> {
        while !helper.is_finished() && !remaining(deadline).is_zero() {
            thread::sleep(SUBPROCESS_POLL_INTERVAL.min(remaining(deadline)));
        }
        if helper.is_finished() {
            Some(helper.join())
        } else {
            // A failed receipt never licenses an unbounded join. The original
            // exact-child guard still owns cleanup, and pause guards release.
            drop(helper);
            None
        }
    }

    fn reap_original_for_control(
        identity: &WorkerIdentity,
        deadline: Instant,
    ) -> (i32, i16, Option<Errno>, Result<Option<i32>, Errno>) {
        let mut pollfd = libc::pollfd {
            fd: identity.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut pollfd,
                1,
                remaining(deadline).as_millis().min(i32::MAX as u128) as i32,
            )
        };
        let error = (ready < 0).then(Errno::last);
        let flags = WaitPidFlag::from_bits_retain(libc::WEXITED | libc::WNOHANG | libc::__WALL);
        let reaped = waitid::waitpidfd(identity.pidfd.as_raw_fd(), flags);
        (ready, pollfd.revents, error, reaped)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RegistrationOutcome {
        Commit,
        Rollback,
        ExternalReap,
    }

    fn registration_capture_failure(phase: i32, outcome: RegistrationOutcome) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn registration arbitration child");
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        let identity = Arc::clone(terminal.event.identity().unwrap());
        let event = Arc::clone(terminal.event.event());
        let mut exit = stopped.exit_event();
        let same_exit_event = Arc::ptr_eq(exit.event.event(), &event);
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &stopped.1))
            .unwrap();
        let failure_reset = SpawnFailureReset(pid.into());
        let (captured, publication_paused) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.terminal_publish_pause.lock() = Some(BoundedTestPause { captured, resume });
        let mut publication_release = PublicationRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        let (captured, registration_paused) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *event.notifier_registration_pause.lock() =
            Some((phase, BoundedTestPause { captured, resume }));
        let mut registration_release = RegistrationRelease {
            release: Some(release),
            event: Arc::clone(&event),
        };
        let (entered, owner_wait_entered) = mpsc::sync_channel(1);
        *event.sync_wait_owner_entered.lock() = Some(entered);
        let (transition, transitions) = mpsc::sync_channel(2);
        *event.sync_wait_entered.lock() = Some(transition.clone());
        let running = stopped.resume_retaining(None).unwrap();
        let same_running_event = Arc::ptr_eq(running.1.event().event(), &event);
        let (registered, registration_result) = mpsc::sync_channel(1);
        let registrar = thread::spawn(move || {
            // This original public future, not a direct worker-state edit,
            // owns the real registration attempt and its rollback on error.
            let waker = Waker::from(Arc::new(WakeCounter::default()));
            let mut context = Context::from_waker(&waker);
            let result = Pin::new(&mut exit).poll(&mut context);
            let _ = registered.try_send(result);
        });
        let paused = registration_paused.recv_timeout(remaining(deadline));
        let worker_at_pause = event.worker_state.load(Ordering::Acquire);
        let owner_at_pause = event.wait_owner.load(Ordering::Acquire);
        if outcome == RegistrationOutcome::Rollback {
            // Explicit spawn-error fault injection, with the real provisional
            // registration and production rollback on this actual child.
            SPAWN_WORKER_ERRORS.lock().insert(pid.into(), libc::EAGAIN);
        }
        let external_reap = if outcome == RegistrationOutcome::ExternalReap {
            // The real registrar is paused in STARTING before worker creation.
            // Only this exact original pidfd is consumed by the fixture; the
            // subsequent notifier must see real ECHILD, never invented exit42.
            Some(reap_original_for_control(&identity, deadline))
        } else {
            None
        };
        let reaped_at_pause = terminal.is_reaped();
        let terminal_at_pause = terminal.observed_exit_status();
        let (done, completed) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            if outcome != RegistrationOutcome::ExternalReap {
                // This is a labelled read-failure control at real registration
                // phases. The separate frozen startup test uses actual ENOENT.
                inject_capture_error_for_current_thread(Errno::EMFILE);
            }
            let result = running.wait();
            let _ = done.try_send(result);
            let _ = transition.try_send(SyncWaitTestTransition::Returned);
        });
        // A positive code-path receipt, not timed silence, establishes that
        // reconciliation encountered the still-provisional original owner.
        let ownership_wait = owner_wait_entered.recv_timeout(remaining(deadline));
        let worker_while_waiting = event.worker_state.load(Ordering::Acquire);
        let owner_while_waiting = event.wait_owner.load(Ordering::Acquire);
        registration_release.release();
        let publication_paused = if outcome == RegistrationOutcome::Commit {
            Some(publication_paused.recv_timeout(remaining(deadline)))
        } else {
            None
        };
        let registered = registration_result.recv_timeout(remaining(deadline));
        let registered_summary = format!("{registered:?}");
        let registration_expected = matches!(
            (&registered, outcome),
            (
                Ok(Poll::Pending),
                RegistrationOutcome::Commit | RegistrationOutcome::ExternalReap,
            ) | (
                Ok(Poll::Ready(Err(Error::Errno(Errno::EAGAIN)))),
                RegistrationOutcome::Rollback,
            ) | (
                Ok(Poll::Ready(Err(Error::Errno(Errno::ECHILD)))),
                RegistrationOutcome::ExternalReap,
            )
        );
        if let Ok(Poll::Ready(Ok(stopped))) = registered {
            cleanup.mark_claimed_exit();
            drop(stopped);
        }
        let first = transitions.recv_timeout(remaining(deadline));
        let terminal_before_release = terminal.observed_exit_status();
        let reaped_before_release = terminal.is_reaped();
        publication_release.release();
        let result = completed.recv_timeout(remaining(deadline));
        let waiter_joined = finish_helper(waiter, deadline);
        let registrar_joined = finish_helper(registrar, deadline);
        let worker_after = event.worker_state.load(Ordering::Acquire);
        let owner_after = event.wait_owner.load(Ordering::Acquire);
        let terminal_before_cleanup = terminal.observed_exit_status();
        let same_registered_event = Arc::ptr_eq(terminal.event.event(), &event);
        let same_registered_identity = terminal
            .event
            .identity()
            .is_some_and(|registered| Arc::ptr_eq(registered, &identity));
        // Clear the one-shot error even on a failed premise before exact-child
        // cleanup is allowed to retry registration. Both pauses are released.
        drop(failure_reset);
        let retired = if outcome == RegistrationOutcome::Rollback {
            None // No committed notifier existed; this is not retirement evidence.
        } else {
            Some(terminal.wait(remaining(deadline)))
        };
        let cleanup_result = cleanup.cleanup();
        let reaped_after = terminal.is_reaped();
        let terminal_after = terminal.observed_exit_status();
        eprintln!(
            "registration capture failure pid={pid}, phase={phase}, outcome={outcome:?}: paused={paused:?}, worker_at_pause={worker_at_pause}, owner_at_pause={owner_at_pause}, external_reap={external_reap:?}, reaped_at_pause={reaped_at_pause:?}, terminal_at_pause={terminal_at_pause:?}, ownership_wait={ownership_wait:?}, worker_while_waiting={worker_while_waiting}, owner_while_waiting={owner_while_waiting}, publication_paused={publication_paused:?}, registered={registered_summary}, first={first:?}, terminal_before_release={terminal_before_release:?}, reaped_before_release={reaped_before_release:?}, result={result:?}, worker_after={worker_after}, owner_after={owner_after}, terminal_before_cleanup={terminal_before_cleanup:?}, same_exit_event={same_exit_event}, same_running_event={same_running_event}, same_registered_event={same_registered_event}, same_registered_identity={same_registered_identity}, retired={retired:?}, reaped_after={reaped_after:?}, terminal_after={terminal_after:?}, cleanup={cleanup_result:?}"
        );
        cleanup_result.expect("exact registration arbitration child cleanup");
        paused.expect("actual registration did not reach the selected phase");
        assert_eq!(worker_at_pause, phase);
        assert_eq!(owner_at_pause, WAIT_OWNER_NOTIFIER);
        ownership_wait.expect("failed capture did not arbitrate the provisional original owner");
        assert_eq!(worker_while_waiting, phase);
        assert_eq!(owner_while_waiting, WAIT_OWNER_NOTIFIER);
        assert_eq!(terminal_at_pause, Ok(None));
        assert!(same_exit_event && same_running_event);
        assert!(same_registered_event && same_registered_identity);
        assert!(
            registration_expected,
            "unexpected original ExitFuture poll: {registered_summary}"
        );
        waiter_joined
            .expect("bounded synchronous helper completion")
            .unwrap();
        registrar_joined
            .expect("bounded registration helper completion")
            .unwrap();
        assert_eq!(reaped_after, Ok(true));
        match outcome {
            RegistrationOutcome::Commit => {
                publication_paused
                    .unwrap()
                    .expect("real notifier reap before publication");
                assert_eq!(retired, Some(true));
                assert_eq!(first.unwrap(), SyncWaitTestTransition::WaitingForNotifier);
                assert_eq!(terminal_before_release, Ok(None));
                assert_eq!(reaped_before_release, Ok(true));
                assert_eq!(
                    result.unwrap().unwrap().assume_exited(),
                    (pid.into(), crate::ExitStatus::Exited(42))
                );
                assert_eq!(terminal_after, Ok(Some(crate::ExitStatus::Exited(42))));
            }
            RegistrationOutcome::Rollback => {
                assert_eq!(first.unwrap(), SyncWaitTestTransition::Returned);
                assert!(matches!(result, Ok(Err(Error::Errno(Errno::EMFILE)))));
                assert_eq!(worker_after, WORKER_NOT_STARTED);
                assert_eq!(owner_after, WAIT_OWNER_NONE);
                assert_eq!(terminal_before_cleanup, Ok(None));
                assert_eq!(retired, None);
            }
            RegistrationOutcome::ExternalReap => {
                let (ready, revents, error, reaped) = external_reap.unwrap();
                assert_eq!(ready, 1, "actual exit readiness: {error:?}");
                assert_eq!(revents & libc::POLLIN, libc::POLLIN);
                assert_eq!(revents & (libc::POLLERR | libc::POLLNVAL), 0);
                assert_eq!(reaped, Ok(Some(42 << 8)));
                assert_eq!(reaped_at_pause, Ok(true));
                assert_eq!(retired, Some(true));
                assert!(matches!(result, Ok(Err(Error::Errno(Errno::ECHILD)))));
                assert_eq!(terminal_after, Err(Errno::ECHILD));
            }
        }
        assert!(
            Instant::now() < deadline,
            "registration control exhausted the original three-second component bound"
        );
    }

    // Port adaptation: the source branch also ran this control at
    // WORKER_STARTING (Commit, Rollback, ExternalReap). On this base, a failed
    // synchronous capture first retains its registrant under the registry
    // lock (`retain_failed_registrant`, 4c5858bb4), and the STARTING registrar
    // holds that lock across `spawn_worker`. The waiter therefore cannot reach
    // wait-owner arbitration until STARTING has resolved, so those variants'
    // premise is unreachable here; they were not ported.
    #[test]
    fn capture_failure_waits_for_provisional_notifier_commit() {
        registration_capture_failure(WORKER_NOT_STARTED, RegistrationOutcome::Commit);
    }

    #[test]
    fn capture_failure_preserves_error_after_provisional_notifier_rollback() {
        registration_capture_failure(WORKER_NOT_STARTED, RegistrationOutcome::Rollback);
    }

    #[test]
    fn capture_failure_without_notifier_owner_does_not_invent_final_status() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn no-owner capture-failure child");
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &stopped.1);
        let identity = Arc::clone(terminal.event.identity().unwrap());
        let event = Arc::clone(terminal.event.event());
        let running = stopped.resume_retaining(None).unwrap();
        // Genuine external reap before either a notifier or this synchronous
        // owner exists. No error injection or Event publication supplies it.
        let (ready, revents, error, reaped) = reap_original_for_control(&identity, deadline);
        let reaped_before = terminal.is_reaped();
        let (done, completed) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            let _ = done.try_send(running.wait());
        });
        let result = completed.recv_timeout(remaining(deadline));
        let joined = finish_helper(waiter, deadline);
        let worker_after = event.worker_state.load(Ordering::Acquire);
        let owner_after = event.wait_owner.load(Ordering::Acquire);
        let terminal_after = terminal.observed_exit_status();
        let reaped_after = terminal.is_reaped();
        if matches!(reaped_after, Ok(true)) {
            cleanup.disarm();
        }
        let cleanup_result = cleanup.cleanup();
        eprintln!(
            "actual no-owner capture failure pid={pid}: ready={ready}, revents={revents:#x}, error={error:?}, reaped={reaped:?}, reaped_before={reaped_before:?}, result={result:?}, worker_after={worker_after}, owner_after={owner_after}, terminal_after={terminal_after:?}, reaped_after={reaped_after:?}, cleanup={cleanup_result:?}"
        );
        cleanup_result.expect("exact no-owner child cleanup");
        assert_eq!(ready, 1, "actual exit readiness: {error:?}");
        assert_eq!(revents & libc::POLLIN, libc::POLLIN);
        assert_eq!(revents & (libc::POLLERR | libc::POLLNVAL), 0);
        assert_eq!(reaped, Ok(Some(42 << 8)));
        assert_eq!(reaped_before, Ok(true));
        joined.expect("bounded no-owner waiter completion").unwrap();
        assert!(matches!(
            result,
            Ok(Err(Error::Errno(
                Errno::ENOENT | Errno::ESRCH | Errno::ECHILD
            )))
        ));
        assert_eq!(worker_after, WORKER_NOT_STARTED);
        assert_eq!(owner_after, WAIT_OWNER_NONE);
        assert_eq!(terminal_after, Ok(None));
        assert_eq!(reaped_after, Ok(true));
        assert!(
            Instant::now() < deadline,
            "no-owner control exhausted the original three-second component bound"
        );
    }
}
