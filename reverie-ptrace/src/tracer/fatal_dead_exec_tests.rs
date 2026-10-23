/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Cleanup owners and the ordinary terminal path meeting an Exec, fork,
/// vfork or clone status that the tracee left through a fatal signal:
/// <https://github.com/rrnewton/reverie/issues/686>.
mod fatal_dead_exec_tests {
    use super::*;

    const EXEC_STOP: i32 = (libc::PTRACE_EVENT_EXEC << 16) | (libc::SIGTRAP << 8) | 0x7f;

    /// Forks a single-threaded tracee that execs `/bin/sleep`, resumes it
    /// into its exec stop and, once the notifier has queued that stop,
    /// SIGKILLs it. The kill takes the tracee out of the exec stop into its
    /// exit stop, so the queued Exec names a stop it has left. Returns once
    /// the exit stop is published.
    fn killed_exec_tracee(deadline: Instant) -> (Pid, Running) {
        let pid = match unsafe { unistd::fork() }.expect("fork exec tracee") {
            ForkResult::Child => {
                safeptrace::traceme_and_stop().expect("TRACEME exec tracee");
                let args = [c"/bin/sleep".as_ptr(), c"30".as_ptr(), std::ptr::null()];
                unsafe {
                    libc::execv(args[0], args.as_ptr());
                    libc::_exit(127)
                };
            }
            ForkResult::Parent { child } => Pid::from(child),
        };
        let (stopped, event) = Running::new_on_ptracer_thread(pid)
            .unwrap()
            .wait_sync_on_ptracer_thread()
            .wait()
            .expect("wait exec tracee")
            .assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGSTOP));
        stopped
            .setoptions(
                ptrace::Options::PTRACE_O_TRACEEXEC
                    | ptrace::Options::PTRACE_O_TRACEEXIT
                    | ptrace::Options::PTRACE_O_EXITKILL,
            )
            .expect("set exec tracee options");
        let terminal = stopped.terminal_cleanup();
        let running = stopped.resume(None).expect("resume exec tracee");
        while terminal.pending_is_empty() {
            assert!(Instant::now() < deadline, "no exec stop queued");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(terminal.queued_raw_statuses(), [EXEC_STOP]);
        assert_eq!(unsafe { libc::kill(pid.as_raw(), libc::SIGKILL) }, 0);
        while !terminal.exit_stop_observed() {
            assert!(Instant::now() < deadline, "no exit stop observed");
            std::thread::sleep(Duration::from_millis(1));
        }
        (pid, running)
    }

    /// Claims the killed tracee's exit stop and requires its actual final
    /// SIGKILL status.
    async fn reap_killed_exec(pid: Pid, running: Running, deadline: Instant) {
        let exit_stop =
            tokio::time::timeout_at(deadline.into(), running.exit_event_on_ptracer_thread())
                .await
                .expect("exit stop claim is bounded")
                .expect("claim the exit stop");
        let exited = tokio::time::timeout_at(
            deadline.into(),
            exit_stop
                .resume(None)
                .expect("resume exit stop")
                .next_state_on_ptracer_thread(),
        )
        .await
        .expect("final status is bounded")
        .expect("wait final status");
        assert_eq!(
            exited.assume_exited(),
            (pid, ExitStatus::Signaled(Signal::SIGKILL, false))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fatal_freeze_consumes_a_killed_exec_without_holding_it() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, running) = killed_exec_tracee(deadline);
        let waits = Arc::new(PtracerWaitOwner::default());
        waits.bind_running(&running);
        let stop = FatalTaskStop {
            tid: pid,
            terminal: running.terminal_cleanup(),
            held: Arc::new(StdMutex::new(None)),
            frozen: AtomicBool::new(false),
            waits: waits.clone(),
        };
        // This single-threaded fixture is held at its actual EXIT stop. Keep
        // a regular process descriptor available for the legacy callback too.
        let group = TraceeIdentity::open_root(pid).expect("retain fixture process descriptor");
        let mut retained_delivery = None;
        let frozen = tokio::time::timeout_at(
            deadline.into(),
            stop.freeze(
                deadline,
                |parent, op, child| {
                    panic!(
                        "a killed exec reported child {} of {parent} by {op:?}",
                        child.pid()
                    )
                },
                || group.send_signal(Signal::SIGSTOP),
                &mut retained_delivery,
            ),
        )
        .await
        .expect("freeze of a killed exec is bounded");
        assert!(frozen.is_ok(), "freeze of a killed exec failed: {frozen:?}");
        assert!(
            stop.held.lock().unwrap().is_none(),
            "a dead Exec was recorded as the held stop"
        );
        assert!(
            stop.terminal.pending_is_empty(),
            "the dead Exec stayed queued"
        );
        reap_killed_exec(pid, running, deadline).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fatal_newborn_reap_consumes_a_killed_exec() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, running) = killed_exec_tracee(deadline);
        let session = FatalSession::for_test(pid);
        let newborn = FatalNewborn::new(pid, &running);
        let terminal = running.terminal_cleanup();
        drop(running);
        tokio::time::timeout_at(deadline.into(), newborn.reap_owned(&session))
            .await
            .expect("reap of a killed exec is bounded");
        assert!(!session.cleanup_was_refused());
        assert!(!session.ordinary_receipt().failure_published);
        assert!(terminal.pending_is_empty(), "the dead Exec stayed queued");
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
        );
        assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
    }

    /// Claims the exit stop of a tracee killed with a status still queued
    /// before it, and runs the ordinary terminal path on it with a fresh
    /// session, as `drive_ordinary` does when the exit future wins. Any
    /// cleanup refusal is recorded and then retried once, as a supervisor's
    /// `resume_cleanup` would.
    async fn finish_killed(
        pid: Pid,
        running: Running,
        deadline: Instant,
    ) -> (
        Option<ExitStatus>,
        FatalSession,
        safeptrace::TerminalCleanup,
    ) {
        let session = FatalSession::for_test(pid);
        let terminal = running.terminal_cleanup();
        let held = Arc::new(StdMutex::new(None));
        let waits = Arc::new(PtracerWaitOwner::default());
        waits.bind_running(&running);
        let exit_stop = tokio::time::timeout_at(deadline.into(), waits.exit_running(&running))
            .await
            .expect("exit stop claim is bounded")
            .expect("claim the exit stop");
        drop(running);
        let status = {
            let mut retried = false;
            let mut finish = std::pin::pin!(finish_ordinary_terminal(
                Ok(exit_stop),
                &terminal,
                &held,
                &waits,
                &session
            ));
            loop {
                let step = tokio::time::timeout(Duration::from_millis(1), finish.as_mut()).await;
                match step {
                    Ok(OrdinaryTerminal::Exited(status, _, _)) => break Some(status),
                    Ok(OrdinaryTerminal::Exec { .. }) => break None,
                    Err(_) if Instant::now() >= deadline => break None,
                    Err(_) => {
                        if session.cleanup_was_refused() && !retried {
                            retried = true;
                            session.resume_cleanup();
                        }
                    }
                }
            }
        };
        (status, session, terminal)
    }

    fn failure_messages(session: &FatalSession) -> Vec<String> {
        session
            .failure_snapshot()
            .map(|failure| {
                std::iter::once(failure.primary().to_string())
                    .chain(
                        failure
                            .secondary()
                            .iter()
                            .map(|entry| entry.error().to_string()),
                    )
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The ordinary terminal path takes the exit stop of a tracee killed
    /// while its Exec was queued. Resuming the exit stop retires that Exec
    /// with the pre-exit prefix, so the path settles on the final SIGKILL
    /// status with no failure. Before, its wait decoded the dead Exec, and
    /// the session failed with "owned ptrace wait observed death during
    /// decoding".
    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_terminal_retires_a_killed_exec_and_reaches_its_exit() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let (pid, running) = killed_exec_tracee(deadline);
        let (status, session, terminal) = finish_killed(pid, running, deadline).await;
        assert_eq!(
            (status, failure_messages(&session)),
            (Some(ExitStatus::Signaled(Signal::SIGKILL, false)), vec![]),
        );
        assert!(!session.cleanup_was_refused());
        assert!(terminal.pending_is_empty(), "the dead Exec stayed queued");
        assert_eq!(terminal.retired_stops_before_exit(), 1);
        assert_eq!(terminal.retired_dead_exec_stops(), 0);
    }

    /// As above, with a fork stop queued before the exit stop instead of an
    /// Exec. The fork's child is a live tracee named only by that stop's
    /// event message, which the exit stop has replaced. The session fails
    /// first with the typed refusal naming the queued status, not with the
    /// death its wait then meets while decoding it.
    #[tokio::test(flavor = "current_thread")]
    async fn ordinary_terminal_refuses_a_killed_fork_stop_queued_before_the_exit_stop() {
        const FORK_STOP: i32 = (libc::PTRACE_EVENT_FORK << 16) | (libc::SIGTRAP << 8) | 0x7f;
        let deadline = Instant::now() + Duration::from_secs(3);
        let pid = match unsafe { unistd::fork() }.expect("fork fork tracee") {
            ForkResult::Child => {
                safeptrace::traceme_and_stop().expect("TRACEME fork tracee");
                unsafe {
                    if libc::fork() == 0 {
                        libc::pause();
                        libc::_exit(0);
                    }
                    libc::pause();
                    libc::_exit(0)
                };
            }
            ForkResult::Parent { child } => Pid::from(child),
        };
        let (stopped, event) = Running::new_on_ptracer_thread(pid)
            .unwrap()
            .wait_sync_on_ptracer_thread()
            .wait()
            .expect("wait fork tracee")
            .assume_stopped();
        assert_eq!(event, Event::Signal(Signal::SIGSTOP));
        stopped
            .setoptions(
                ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEEXIT
                    | ptrace::Options::PTRACE_O_EXITKILL,
            )
            .expect("set fork tracee options");
        let terminal = stopped.terminal_cleanup();
        let running = stopped.resume(None).expect("resume fork tracee");
        while terminal.pending_is_empty() {
            assert!(Instant::now() < deadline, "no fork stop queued");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(terminal.queued_raw_statuses(), [FORK_STOP]);
        // Read while the tracee is in its fork stop, only to clean up the
        // child below; the terminal path is never given this PID.
        let child = ptrace::getevent(pid.into()).expect("read the fork child") as i32;
        assert_eq!(unsafe { libc::kill(pid.as_raw(), libc::SIGKILL) }, 0);
        while !terminal.exit_stop_observed() {
            assert!(Instant::now() < deadline, "no exit stop observed");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(terminal);
        let (status, session, terminal) = finish_killed(pid, running, deadline).await;
        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
        let child_reaped = loop {
            let mut raw = 0;
            let waited = unsafe { libc::waitpid(child, &mut raw, libc::WNOHANG | libc::__WALL) };
            if waited == child && (libc::WIFEXITED(raw) || libc::WIFSIGNALED(raw)) {
                break true;
            }
            // The child inherited PTRACE_O_TRACEEXIT, so the SIGKILL leaves it
            // in its exit stop (after its initial SIGSTOP stop, if that was not
            // yet reported); resume each stop until it is reaped.
            if waited == child && libc::WIFSTOPPED(raw) {
                let null = std::ptr::null_mut::<libc::c_void>();
                unsafe { libc::ptrace(libc::PTRACE_CONT, child, null, null) };
                continue;
            }
            if waited < 0 || Instant::now() >= deadline + Duration::from_secs(2) {
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let messages = failure_messages(&session);
        assert_eq!(
            messages.first().map(String::as_str),
            Some(
                "queued wait status 0x1057f is a fork, vfork or clone stop superseded by the exit stop; its child PID is no longer readable"
            ),
            "{messages:?}"
        );
        assert_eq!(
            status,
            Some(ExitStatus::Signaled(Signal::SIGKILL, false)),
            "{messages:?}"
        );
        assert_eq!(terminal.retired_stops_before_exit(), 0);
        assert!(child_reaped, "the fork child {child} was not reaped");
    }
}
