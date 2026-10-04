/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_callback_owner_tests {
    use reverie::syscalls::Addr;
    use reverie::syscalls::MemoryAccess;

    use super::*;

    const MAGIC: usize = 0x4558_4543;
    fn word(address: usize, index: usize) -> &'static std::sync::atomic::AtomicUsize {
        unsafe { &*(address as *const std::sync::atomic::AtomicUsize).add(index) }
    }
    type Events = Vec<(u8, Pid, usize, Option<ExitStatus>)>;
    #[derive(Default)]
    struct ExecLog(Arc<StdMutex<Events>>);
    #[reverie::global_tool]
    impl GlobalTool for ExecLog {
        type Config = (usize, u64);
        type Request = (u8, Pid, usize, Option<ExitStatus>);
        type Response = ();
        async fn receive_rpc(&self, _: Pid, event: Self::Request) {
            self.0.lock().unwrap().push(event);
        }
    }
    #[derive(Default)]
    struct ExecTool;
    #[reverie::tool]
    impl Tool for ExecTool {
        type GlobalState = ExecLog;
        type ThreadState = usize;
        fn subscriptions(_: &(usize, u64)) -> Subscription {
            Subscription::none()
        }
        fn init_thread_state(&self, tid: Pid, _: Option<(Pid, &usize)>) -> usize {
            tid.as_raw() as usize
        }
        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            guest
                .send_rpc((0, guest.tid(), *guest.thread_state(), None))
                .await;
            Ok(())
        }
        async fn handle_signal_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            signal: Signal,
        ) -> Result<Option<Signal>, Errno> {
            assert_eq!(signal, Signal::SIGUSR1);
            assert_eq!(guest.pid(), guest.tid());
            let (address, deadline) = *guest.config();
            assert_ne!(word(address, 1).load(Ordering::SeqCst), 0);
            let location = Addr::<usize>::from_raw(address).unwrap();
            assert_eq!(guest.memory().read_value(location)?, MAGIC);
            word(address, 4).fetch_add(1, Ordering::SeqCst);
            word(address, 2).store(1, Ordering::SeqCst);
            // The sibling's exec executes natively; no await or second waiter
            // can put its syscall behind this callback poll.
            loop {
                assert!(
                    fatal_monotonic_ns() < deadline,
                    "exec-zapped memory did not fail before original deadline"
                );
                match guest.memory().read_value(location) {
                    Ok(value) => {
                        assert_eq!(value, MAGIC);
                        word(address, 4).fetch_add(1, Ordering::SeqCst);
                    }
                    Err(errno) => {
                        assert_eq!(errno, Errno::ESRCH);
                        word(address, 5).store(errno.into_raw() as usize, Ordering::SeqCst);
                        return Err(errno);
                    }
                }
            }
        }
        async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
            assert_ne!(*guest.thread_state(), guest.tid().as_raw() as usize);
            guest
                .send_rpc((1, guest.tid(), *guest.thread_state(), None))
                .await;
            Ok(())
        }
        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            state: usize,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((2, tid, state, Some(status))).await;
            Ok(())
        }
        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            global.send_rpc((3, pid, 0, Some(status))).await;
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_callback_errno_keeps_original_exit_to_exec_owner_and_surviving_state() {
        let started = Instant::now();
        let deadline = fatal_monotonic_ns() + 3_000_000_000;
        let words = FatalWords::new();
        let address = words.0 as usize;
        word(address, 0).store(MAGIC, Ordering::SeqCst);
        let sentinel = fork_paused_child(Instant::now() + fatal_remaining(deadline));
        let sentinel_identity = untraced_process_identity(sentinel);
        let tracer = tokio::time::timeout(
            fatal_remaining(deadline),
            spawn_fn_with_config::<ExecTool, _>(
                move || {
                    std::thread::spawn(move || {
                        word(address, 1).store(
                            unsafe { libc::syscall(libc::SYS_gettid) } as usize,
                            Ordering::SeqCst,
                        );
                        while word(address, 2).load(Ordering::SeqCst) == 0 {
                            unsafe {
                                libc::sched_yield();
                            }
                        }
                        let args = [
                            c"/bin/sh".as_ptr(),
                            c"-c".as_ptr(),
                            c"printf exec-survived".as_ptr(),
                            std::ptr::null(),
                        ];
                        unsafe {
                            libc::execv(args[0], args.as_ptr());
                            libc::_exit(127);
                        }
                    });
                    while word(address, 1).load(Ordering::SeqCst) == 0 {
                        unsafe {
                            libc::sched_yield();
                        }
                    }
                    assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
                    word(address, 3).store(1, Ordering::SeqCst);
                    loop {
                        unsafe {
                            libc::pause();
                        }
                    }
                },
                (address, deadline),
                true,
            ),
        )
        .await
        .expect("exec fixture spawn exceeded original deadline")
        .unwrap();
        let root = tracer.guest_pid();
        let identity = untraced_process_identity(root);
        let termination = tracer.termination_handle().unwrap();
        let log = tracer.gref.0.clone();
        let mut completion = Box::pin(tracer.wait_with_output_completion());
        let result = tokio::time::timeout(fatal_remaining(deadline), &mut completion).await;
        let snapshot: Vec<_> = (0..6).map(|index| words.read(index)).collect();
        let former = Pid::from_raw(snapshot[1] as i32);
        let events = log.lock().unwrap().clone();
        let retired = !identity.same_process();
        let untouched = sentinel_identity.same_process()
            && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                == 0;
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!(
                "Complete({:?}), diagnostics={:?}",
                done.result,
                done.callback_diagnostics()
            ),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "Unsupported".to_owned(),
            Err(error) => format!("Timeout({error})"),
        };
        eprintln!(
            "callback-exec original predicate: root={root}, former={former}, retired={retired}, sentinel_untouched={untouched}, shared={snapshot:?}, events={events:?}, elapsed={:?}, outcome={description}",
            started.elapsed()
        );
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        let rescue_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let got =
                unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) };
            if got == sentinel.as_raw() {
                break;
            }
            assert_eq!(got, 0);
            assert!(Instant::now() < rescue_deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let done = match result {
            Ok(ToolRunOutcome::Complete(done)) => done,
            other => {
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let signal = identity.send_signal(Signal::SIGKILL);
                let rescued = match other {
                    Err(_) => {
                        tokio::time::timeout(
                            rescue_deadline.saturating_duration_since(Instant::now()),
                            &mut completion,
                        )
                        .await
                    }
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout(
                            rescue_deadline.saturating_duration_since(Instant::now()),
                            pending.resume_cleanup(),
                        )
                        .await
                    }
                    _ => panic!("unexpected ordinary completion route"),
                };
                eprintln!(
                    "callback-exec rescue only: signal={signal:?}, complete={}",
                    matches!(rescued, Ok(ToolRunOutcome::Complete(_)))
                );
                panic!("original callback-exec predicate failed: {description}");
            }
        };
        assert!(retired && untouched);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(snapshot[3], 0, "old leader resumed its guest continuation");
        assert!(snapshot[4] >= 1);
        assert_eq!(snapshot[5], libc::ESRCH as usize);
        let records = done.callback_diagnostics();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.origin().pid, root);
        assert_eq!(record.origin().tid, root);
        assert_eq!(record.origin().phase, "ptrace signal callback");
        assert_eq!(record.errno(), Errno::ESRCH);
        assert_eq!(
            record.decision(),
            crate::PtraceCallbackDecision::AwaitingOwner
        );
        assert_eq!(
            record.owner_outcome(),
            Some(crate::PtraceCallbackOutcome::Exec {
                former,
                exit_stop_status: ExitStatus::Exited(0)
            })
        );
        assert!(!record.failure_published_at_outcome());
        assert!(!record.backend_signalling_at_outcome());
        assert!(record.refusal().is_none());
        assert_eq!(events.iter().filter(|e| e.0 == 0).count(), 2);
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 1 && e.1 == root && e.2 == former.as_raw() as usize)
                .count(),
            1
        );
        assert_eq!(events.iter().filter(|e| e.0 == 2).count(), 2);
        for state in [root, former] {
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.0 == 2
                        && e.1 == root
                        && e.2 == state.as_raw() as usize
                        && e.3 == Some(ExitStatus::Exited(0)))
                    .count(),
                1
            );
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 3 && e.1 == root && e.3 == Some(ExitStatus::Exited(0)))
                .count(),
            1
        );
        let output = done
            .result
            .expect("legitimate sibling exec became a fatal Tool error");
        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(output.stdout, b"exec-survived");
        assert!(output.stderr.is_empty());
    }
}
