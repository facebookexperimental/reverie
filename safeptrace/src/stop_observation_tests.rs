/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside notifier::test. These tests do not give an observation any
// execution or wait ownership. The existing cleanup guard owns every tracee.
mod stop_observation_tests {
    use super::*;

    fn remaining(deadline: Instant) -> Duration {
        deadline.saturating_duration_since(Instant::now())
    }

    fn spawn_observed_child(deadline: Instant) -> (Pid, Stopped, TraceeCleanupGuard) {
        let pid = match unsafe { fork() }.expect("fork observation child") {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().expect("observation child TRACEME");
                unsafe { libc::_exit(42) };
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(pid).unwrap_or_else(|error| {
            // This child is still unreaped and cannot have been reused.
            let _ = unsafe { libc::kill(pid.as_raw(), libc::SIGKILL) };
            let _ = reap_tracee_bounded(pid);
            panic!("open observation child pidfd: {error}");
        });
        let status = waitpid_status_bounded(pid, libc::WUNTRACED, remaining(deadline))
            .expect("actual initial observation stop before original deadline");
        assert!(libc::WIFSTOPPED(status), "initial status {status:#x}");
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        assert_eq!(status >> 16, 0, "initial stop is not a ptrace event");
        // The sole raw wait above proved this stop before notifier registration.
        let stopped = Stopped::new_unchecked(pid.into());
        cleanup.bind_notifier(&stopped).unwrap();
        stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_EXITKILL)
            .unwrap();
        assert!(
            Instant::now() < deadline,
            "initial setup exceeded three seconds"
        );
        (pid, stopped, cleanup)
    }

    fn assert_refused_without_queries(sample: &StopObservationSample, error: StopObservationError) {
        assert_eq!(sample.refusal(), Some(error), "{sample:?}");
        assert_eq!(sample.siginfo(), None, "refusal issued GETSIGINFO");
        assert_eq!(sample.flags(), None, "refusal read proc flags");
        assert_eq!(sample.pidfd_live(), None, "refusal probed pidfd");
    }

    fn assert_initial_sample(sample: &StopObservationSample, pid: Pid) {
        assert_eq!(sample.refusal(), None, "{sample:?}");
        let info = sample.siginfo().expect("GETSIGINFO was attempted").unwrap();
        assert_eq!(info.signo, libc::SIGSTOP);
        assert_eq!(info.sender_pid, pid.as_raw());
        assert_eq!(info.sender_uid, unsafe { libc::getuid() });
        assert!(!info.has_exit_signature());
        assert_eq!(sample.flags(), None, "ordinary SIGSTOP must not read flags");
        assert_eq!(sample.pidfd_live(), Some(Ok(true)));
    }

    async fn finish_observed_child(
        pid: Pid,
        stopped: Stopped,
        mut cleanup: TraceeCleanupGuard,
        deadline: Instant,
        competing: Option<ExitFuture>,
    ) {
        let terminal = stopped.terminal_cleanup();
        let mut exit = Box::pin(cleanup.exit_event(&stopped).unwrap());
        let mut duplicate = Box::pin(stopped.exit_event());
        let running = stopped.resume_retaining(None).unwrap();
        let exiting = tokio::time::timeout(remaining(deadline), exit.as_mut())
            .await
            .expect("actual EXIT exceeded original deadline")
            .expect("original owner claims actual EXIT");
        cleanup.mark_claimed_exit();
        drop(running); // Superseded by the single actually claimed EXIT stop.
        assert_eq!(exiting.pid(), pid.into());
        assert_eq!(exiting.getevent().unwrap(), 42 << 8);
        let observation = exiting.observation();
        assert!(observation.same_generation(&terminal));
        let without_flags = observation.sample(false);
        let with_flags = observation.sample(true);
        eprintln!(
            "observation EXIT pid={pid}: without_flags={without_flags:?}, with_flags={with_flags:?}"
        );
        assert_eq!(without_flags.refusal(), None);
        assert_eq!(with_flags.refusal(), None);
        let info = with_flags.siginfo().unwrap().unwrap();
        assert!(
            info.has_exit_signature(),
            "actual EXIT GETSIGINFO: {info:?}"
        );
        assert_eq!(without_flags.siginfo(), Some(Ok(info)));
        assert_eq!(without_flags.flags(), None);
        assert!(matches!(with_flags.flags(), Some(Ok(_))), "{with_flags:?}");
        assert_eq!(with_flags.pidfd_live(), Some(Ok(true)));
        assert!(matches!(
            tokio::time::timeout(remaining(deadline), duplicate.as_mut())
                .await
                .unwrap(),
            Err(Error::Errno(Errno::EALREADY))
        ));
        if let Some(competing) = competing {
            assert!(matches!(
                tokio::time::timeout(remaining(deadline), competing)
                    .await
                    .unwrap(),
                Err(Error::Errno(Errno::EALREADY))
            ));
        }
        let final_wait = tokio::time::timeout(
            remaining(deadline),
            exiting.resume_retaining(None).unwrap().wait_owned(),
        )
        .await
        .expect("terminal wait exceeded original deadline")
        .expect("actual terminal status");
        assert_eq!(
            final_wait.assume_exited(),
            (pid.into(), crate::ExitStatus::Exited(42))
        );
        assert!(
            terminal.wait(remaining(deadline)),
            "notifier did not retire"
        );
        assert!(pidfd_exited(&cleanup.pidfd).unwrap());
        assert!(
            Instant::now() < deadline,
            "observation lifecycle exceeded three seconds"
        );
        cleanup.disarm();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_live_and_exit_observations_preserve_the_wait_owner() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, cleanup) = spawn_observed_child(deadline);
        let terminal = stopped.terminal_cleanup();
        let observation = stopped.observation();
        assert!(observation.same_generation(&terminal));
        let first = observation.sample(true);
        let second = observation.sample(false);
        eprintln!("observation live pid={pid}: first={first:?}, second={second:?}");
        assert_initial_sample(&first, pid);
        assert_initial_sample(&second, pid);
        assert_eq!(first.siginfo(), second.siginfo());
        assert!(
            !terminal.wait(Duration::ZERO),
            "observation acknowledged terminal"
        );
        finish_observed_child(pid, stopped, cleanup, deadline, None).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_thread_refuses_before_queries_and_original_thread_can_continue() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, cleanup) = spawn_observed_child(deadline);
        let observation = stopped.observation();
        let (send, receive) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let sample = observation.sample(true);
            let _ = send.send((observation, sample));
        });
        let (observation, sample) = receive
            .recv_timeout(remaining(deadline))
            .expect("wrong-thread observation exceeded original deadline");
        worker.join().expect("wrong-thread observer panicked");
        assert_refused_without_queries(&sample, StopObservationError::WrongThread);
        assert_initial_sample(&observation.sample(true), pid);
        finish_observed_child(pid, stopped, cleanup, deadline, None).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn competing_event_adoption_refuses_old_observer_without_another_exit_owner() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, cleanup) = spawn_observed_child(deadline);
        let original = stopped.observation();
        let terminal = stopped.terminal_cleanup();
        let competitor = distinct_running(pid.into());
        let competing_terminal = TerminalCleanup::new_unregistered(pid.into(), &competitor.1);
        // This is deliberately an unregistered observer refusal control, not
        // a fabricated successful stopped capability or another raw wait owner.
        let unbound = StoppedObservation::new(pid.into(), &competitor.1);
        assert!(!original.same_generation(&competing_terminal));
        assert_refused_without_queries(
            &unbound.sample(true),
            StopObservationError::Identity(Errno::ENODATA),
        );
        assert!(
            competitor.1.event().identity().is_none(),
            "sample captured an identity"
        );
        competing_terminal.ensure_registered().unwrap();
        assert!(original.same_generation(&competing_terminal));
        assert!(competing_terminal.same_generation(&terminal));
        assert_refused_without_queries(
            &unbound.sample(true),
            StopObservationError::GenerationMismatch,
        );
        assert_initial_sample(&original.sample(true), pid);
        let competing_exit = ExitFuture::new(pid.into(), &competitor.1);
        finish_observed_child(pid, stopped, cleanup, deadline, Some(competing_exit)).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_numeric_projection_refuses_before_any_kernel_query() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, cleanup) = spawn_observed_child(deadline);
        let mut observation = stopped.observation();
        // Explicit private negative projection. No new Stopped token or kernel
        // result is invented, and the target remains owned by the real token.
        observation.pid = crate::Pid::from_raw(unsafe { libc::getpid() });
        assert_ne!(observation.pid, stopped.pid());
        assert!(!observation.same_generation(&stopped.terminal_cleanup()));
        assert_refused_without_queries(
            &observation.sample(true),
            StopObservationError::PidMismatch,
        );
        assert_initial_sample(&stopped.observation().sample(true), pid);
        finish_observed_child(pid, stopped, cleanup, deadline, None).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_nonleader_exec_refuses_the_old_observation_epoch() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
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
            }
        };
        let mut root_cleanup = TraceeCleanupGuard::new(root).unwrap();
        let status = waitpid_status_bounded(root, libc::WUNTRACED, remaining(deadline)).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked(root.into());
        root_cleanup.bind_notifier(&stopped).unwrap();
        stopped
            .setoptions(
                Options::PTRACE_O_TRACECLONE
                    | Options::PTRACE_O_TRACEEXEC
                    | Options::PTRACE_O_TRACEEXIT
                    | Options::PTRACE_O_EXITKILL,
            )
            .unwrap();
        let terminal = stopped.terminal_cleanup();
        let old_observation = stopped.observation();
        assert_initial_sample(&old_observation.sample(true), root);
        let mut old_exit = Box::pin(stopped.exit_event());
        let wait = tokio::time::timeout(
            remaining(deadline),
            stopped.resume_retaining(None).unwrap().wait_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = wait.assume_stopped()
        else {
            panic!("missing actual clone");
        };
        let former = child.pid();
        let child_terminal = child.terminal_cleanup();
        let child_identity = child_terminal.event.identity().unwrap();
        let fd = unsafe { libc::fcntl(child_identity.pidfd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        assert!(fd >= 0);
        let mut child_cleanup = TraceeCleanupGuard {
            pid: former.into(),
            pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            ownership: TraceeCleanupOwnership::PreRegistration,
            armed: true,
        };
        child_cleanup.bind_running_notifier(&child).unwrap();
        let initial = tokio::time::timeout(remaining(deadline), child.wait_owned())
            .await
            .unwrap()
            .unwrap();
        let (child, event) = initial.assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        let mut former_wait = Box::pin(child.resume_retaining(None).unwrap().wait_owned());
        let old_running = parent.resume_retaining(None).unwrap();
        let first = tokio::time::timeout(remaining(deadline), old_exit.as_mut())
            .await
            .unwrap()
            .unwrap();
        root_cleanup.mark_claimed_exit();
        drop(old_running);
        assert_eq!(
            first.getevent().unwrap(),
            0,
            "old leader's actual EXIT message"
        );
        let next = tokio::time::timeout(
            remaining(deadline),
            first.resume_retaining(None).unwrap().wait_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        let (replacement, crate::Event::Exec(actual_former)) = next.assume_stopped() else {
            panic!("missing actual replacement exec");
        };
        assert_eq!(actual_former, former);
        assert_eq!(replacement.pid(), root.into());
        assert!(replacement.terminal_cleanup().same_generation(&terminal));
        // Same Event is necessary but insufficient: actual Exec changed its epoch.
        assert!(old_observation.same_generation(&terminal));
        assert_refused_without_queries(
            &old_observation.sample(true),
            StopObservationError::ExecEpochMismatch,
        );
        let fresh = replacement.observation();
        assert!(fresh.same_generation(&terminal));
        let sample = fresh.sample(true);
        eprintln!("observation Exec leader={root}, former={former}: {sample:?}");
        assert_eq!(sample.refusal(), None);
        let info = sample.siginfo().unwrap().unwrap();
        assert_eq!(info.signo, libc::SIGTRAP);
        assert_eq!(info.code, (libc::PTRACE_EVENT_EXEC << 8) | libc::SIGTRAP);
        assert!(!info.has_exit_signature());
        assert_eq!(sample.flags(), None);
        assert_eq!(sample.pidfd_live(), Some(Ok(true)));
        let mut next_exit = Box::pin(replacement.exit_event());
        assert!(matches!(
            tokio::time::timeout(remaining(deadline), old_exit.as_mut())
                .await
                .unwrap(),
            Err(Error::Errno(Errno::EALREADY))
        ));
        let running = replacement.resume_retaining(None).unwrap();
        let second = tokio::time::timeout(remaining(deadline), next_exit.as_mut())
            .await
            .unwrap()
            .unwrap();
        root_cleanup.mark_claimed_exit();
        drop(running);
        assert_eq!(second.getevent().unwrap(), 0);
        let final_wait = tokio::time::timeout(
            remaining(deadline),
            second.resume_retaining(None).unwrap().wait_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            final_wait.assume_exited(),
            (root.into(), crate::ExitStatus::Exited(0))
        );
        assert!(matches!(
            tokio::time::timeout(remaining(deadline), former_wait.as_mut())
                .await
                .unwrap(),
            Err(OwnedWaitError::Errno(Errno::ECHILD))
        ));
        assert!(terminal.wait(remaining(deadline)));
        assert!(child_terminal.wait(remaining(deadline)));
        assert!(pidfd_exited(&root_cleanup.pidfd).unwrap());
        assert!(pidfd_exited(&child_cleanup.pidfd).unwrap());
        assert!(
            Instant::now() < deadline,
            "exec observation exceeded three seconds"
        );
        root_cleanup.disarm();
        // Transfer was proved by consumed Exec(former) and terminal leader wait,
        // not by ECHILD or a liveness query on the former numeric TID.
        child_cleanup.disarm();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_reap_before_publication_preserves_disappearance_and_original_wait_owner() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, stopped, mut cleanup) = spawn_observed_child(deadline);
        let (sentinel, sentinel_stop, sentinel_cleanup) = spawn_observed_child(deadline);
        let terminal = stopped.terminal_cleanup();
        let identity = terminal.event.identity().unwrap().clone();
        let mut exit = Box::pin(cleanup.exit_event(&stopped).unwrap());
        let running = stopped.resume_retaining(None).unwrap();
        let exiting = tokio::time::timeout(remaining(deadline), exit.as_mut())
            .await
            .unwrap()
            .unwrap();
        cleanup.mark_claimed_exit();
        drop(running);
        assert_eq!(exiting.getevent().unwrap(), 42 << 8);
        let observation = exiting.observation();
        let (captured, ready) = mpsc::sync_channel(1);
        let (release, resume) = mpsc::sync_channel(1);
        *terminal.event.event().terminal_publish_pause.lock() =
            Some(BoundedTestPause { captured, resume });
        let mut original_wait = Box::pin(exiting.resume_retaining(None).unwrap().wait_owned());
        ready
            .recv_timeout(remaining(deadline))
            .expect("actual sole-worker reap did not reach bounded publication barrier");
        // These are real observations after a real reap. No terminal status is
        // minted from them, and the original wait still owns the unpublished result.
        let sample = observation.sample(true);
        let flags = read_bound_stat_flags(&identity);
        let final_pidfd = identity.pidfd_is_live();
        eprintln!(
            "reaped-before-publication pid={pid}: sample={sample:?}, relative_proc={flags:?}, final_pidfd={final_pidfd:?}"
        );
        assert_eq!(sample.refusal(), None);
        assert_eq!(sample.siginfo(), Some(Err(Errno::ESRCH)));
        assert_eq!(sample.pidfd_live(), Some(Ok(false)));
        assert!(
            matches!(flags, Err(ProcStatError::Io(Errno::ESRCH | Errno::ENOENT))),
            "{flags:?}"
        );
        assert_eq!(final_pidfd, Ok(false));
        assert!(terminal.observed_exit_status().unwrap().is_none());
        assert!(!terminal.wait(Duration::ZERO));
        assert!(futures::poll!(original_wait.as_mut()).is_pending());
        assert_initial_sample(&sentinel_stop.observation().sample(true), sentinel);
        release.send(()).unwrap();
        let actual = tokio::time::timeout(remaining(deadline), original_wait.as_mut())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            actual.assume_exited(),
            (pid.into(), crate::ExitStatus::Exited(42))
        );
        assert!(terminal.wait(remaining(deadline)));
        assert!(pidfd_exited(&cleanup.pidfd).unwrap());
        cleanup.disarm();
        finish_observed_child(sentinel, sentinel_stop, sentinel_cleanup, deadline, None).await;
        assert!(Instant::now() < deadline);
    }

    #[test]
    fn stat_parser_uses_last_comm_delimiter_and_exact_field_nine() {
        let pid = crate::Pid::from_raw(123);
        let bytes = b"123 (odd ) (name\n\xff) S 9 8 7 6 5 1028 777 888\n";
        assert_eq!(parse_bound_stat_flags(bytes, pid), Ok(0x404));
        assert_eq!(
            parse_bound_stat_flags(b"123 (x) t 1 2 3 4 -1 0\n", pid),
            Ok(0)
        );
        assert_eq!(
            parse_bound_stat_flags(bytes, crate::Pid::from_raw(124)),
            Err(ProcStatError::PidMismatch)
        );
    }

    #[test]
    fn stat_parser_accepts_the_bound_and_refuses_overflow_and_malformed_records() {
        let pid = crate::Pid::from_raw(123);
        let suffix = b") S 1 2 3 4 5 4294967295\n";
        let mut exact = b"123 (".to_vec();
        exact.resize(4096 - suffix.len(), b'x');
        exact.extend_from_slice(suffix);
        assert_eq!(exact.len(), 4096);
        assert_eq!(parse_bound_stat_flags(&exact, pid), Ok(u32::MAX));
        exact.push(b' ');
        assert_eq!(
            parse_bound_stat_flags(&exact, pid),
            Err(ProcStatError::Format("record exceeds 4096 bytes"))
        );

        for (bytes, reason) in [
            (
                &b"123 no-comm S 1 2 3 4 5 0"[..],
                "missing comm opening delimiter",
            ),
            (&b"nan (x) S 1 2 3 4 5 0"[..], "invalid PID"),
            (
                &b"123 (x S 1 2 3 4 5 0"[..],
                "missing comm closing delimiter",
            ),
            (&b"123 (x)S 1 2 3 4 5 0"[..], "invalid comm separator"),
            (&b"123 (x) "[..], "missing state"),
            (&b"123 (x) 7 1 2 3 4 5 0"[..], "invalid state"),
            (&b"123 (x) SS 1 2 3 4 5 0"[..], "invalid state"),
            (&b"123 (x) S 1 2 3 4 5"[..], "missing flags"),
            (
                &b"123 (x) S 1 2 3 4 5 -1"[..],
                "flags are not unsigned decimal",
            ),
            (
                &b"123 (x) S 1 2 3 4 5 +1"[..],
                "flags are not unsigned decimal",
            ),
            (
                &b"123 (x) S 1 2 3 4 5 0xff"[..],
                "flags are not unsigned decimal",
            ),
            (&b"123 (x) S 1 2 3 4 5 4294967296"[..], "flags overflow u32"),
        ] {
            assert_eq!(
                parse_bound_stat_flags(bytes, pid),
                Err(ProcStatError::Format(reason)),
                "input={bytes:?}"
            );
        }
    }
}
