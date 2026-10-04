/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_namespace_timer_tests {
    use super::*;

    type Observations = Vec<(u8, i32, u64, i32, i32)>;
    #[derive(Default)]
    struct Log(Arc<StdMutex<Observations>>);
    #[reverie::global_tool]
    impl GlobalTool for Log {
        type Config = bool;
        type Request = (u8, i32, u64, i32, i32);
        type Response = ();
        async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
            self.0.lock().unwrap().push(event);
        }
    }
    #[derive(Default)]
    struct NamespaceTimerTool;
    #[reverie::tool]
    impl Tool for NamespaceTimerTool {
        type GlobalState = Log;
        type ThreadState = ();
        fn subscriptions(_: &bool) -> reverie::Subscription {
            [reverie::syscalls::Sysno::getpgid].into_iter().collect()
        }
        async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
            guest.send_rpc((0, guest.tid().as_raw(), 0, 0, 0)).await;
            Ok(())
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            call: Syscall,
        ) -> Result<i64, Error> {
            let result = guest.inject(call).await?;
            let clock = guest.read_clock()?;
            guest.send_rpc((1, guest.tid().as_raw(), clock, 0, 0)).await;
            if *guest.config() {
                guest.set_timer_precise(reverie::TimerSchedule::Rcbs(1))?;
            }
            Ok(result)
        }
        async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
            let clock = guest.read_clock().unwrap();
            guest.send_rpc((2, guest.tid().as_raw(), clock, 0, 0)).await;
        }
        async fn handle_signal_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            signal: Signal,
        ) -> Result<Option<Signal>, Errno> {
            assert_eq!(signal, reverie::PERF_EVENT_SIGNAL);
            // Read-only observation of the actual current signal stop.
            let info = nix::sys::ptrace::getsiginfo(guest.tid().into())
                .map_err(|error| Errno::new(error as i32))?;
            guest
                .send_rpc((3, guest.tid().as_raw(), 0, info.si_code, unsafe {
                    info.si_pid()
                }))
                .await;
            Ok(None)
        }
        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            _: (),
            status: ExitStatus,
        ) -> Result<(), Error> {
            eprintln!("namespace timer actual thread exit: {tid} {status:?}");
            global.send_rpc((4, tid.as_raw(), 0, 0, 0)).await;
            Ok(())
        }
        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), Error> {
            eprintln!("namespace timer actual process exit: {pid} {status:?}");
            global.send_rpc((5, pid.as_raw(), 0, 0, 0)).await;
            Ok(())
        }
    }

    fn payload() -> PathBuf {
        static PAYLOAD: LazyLock<PathBuf> = LazyLock::new(|| {
            let source = fixture("fatal_namespace_timer.c");
            let output = std::env::temp_dir().join(format!(
                "reverie-fatal-namespace-timer-{}",
                std::process::id()
            ));
            let status = std::process::Command::new("timeout")
                .args([
                    "--signal=TERM",
                    "--kill-after=1s",
                    "1s",
                    "cc",
                    "-std=c11",
                    "-O1",
                ])
                .arg(source)
                .arg("-o")
                .arg(&output)
                .status()
                .unwrap();
            assert!(status.success(), "bounded namespace payload compile failed");
            output
        });
        PAYLOAD.clone()
    }

    async fn control(descendant: bool, mode: &str) {
        let query_failure = mode == "query-failure";
        if query_failure {
            crate::timer::CONTROLLER_NAMESPACE_PATH
                .with(|slot| *slot.borrow_mut() = Some(PathBuf::from("/proc/self/fd/-1")));
        }
        let started = Instant::now();
        let original_deadline = std::env::var("REVERIE_NAMESPACE_TIMER_DEADLINE_NS")
            .ok()
            .map(|value| value.parse::<u64>().unwrap())
            .unwrap_or_else(|| fatal_monotonic_ns() + 3_000_000_000);
        let deadline = started + fatal_remaining(original_deadline);
        let marker_log = Arc::new(StdMutex::new(Vec::new()));
        crate::timer::EXEC_SIGNAL_OBSERVATIONS
            .with(|slot| *slot.borrow_mut() = Some(marker_log.clone()));
        let sentinel = fork_paused_child(deadline);
        let sentinel_identity = untraced_process_identity(sentinel);
        let mut command = Command::new(payload());
        command
            .arg(if query_failure { "kick" } else { mode })
            .stdout(reverie::process::Stdio::piped())
            .stderr(reverie::process::Stdio::piped());
        if descendant {
            command.map_root().unshare(reverie::process::Namespace::PID);
        }
        let tracer = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            TracerBuilder::<NamespaceTimerTool>::new(command)
                .config(mode != "guest")
                .spawn(),
        )
        .await
        .expect("namespace spawn exceeded original pre-start3s deadline")
        .expect("actual public namespace spawn failed");
        let root = tracer.guest_pid();
        let ours = std::fs::metadata("/proc/thread-self/ns/pid").unwrap();
        let theirs = std::fs::metadata(format!("/proc/{root}/ns/pid")).unwrap();
        let namespaces = ((ours.dev(), ours.ino()), (theirs.dev(), theirs.ino()));
        assert_eq!(namespaces.0 != namespaces.1, descendant);
        eprintln!("actual PID namespace identities: tracer/guest={namespaces:?}");
        let identity = untraced_process_identity(root);
        let termination = tracer.termination_handle().unwrap();
        let log = tracer.gref.0.clone();
        let mut wait = Box::pin(tracer.wait_with_output_completion());
        let result = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            &mut wait,
        )
        .await;
        crate::timer::EXEC_SIGNAL_OBSERVATIONS.with(|slot| *slot.borrow_mut() = None);
        crate::timer::CONTROLLER_NAMESPACE_PATH.with(|slot| *slot.borrow_mut() = None);
        let events = log.lock().unwrap().clone();
        let markers = marker_log.lock().unwrap().clone();
        let retired = !identity.same_process();
        let sentinel_untouched = sentinel_identity.same_process()
            && unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), libc::WNOHANG) }
                == 0;
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!("Complete({:?})", done.result),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "UnsupportedBackend".into(),
            Err(error) => format!("Timeout({error})"),
        };
        eprintln!(
            "namespace timer original predicate: descendant={descendant}, mode={mode}, tracer={}, root={root}, retired={retired}, sentinel_untouched={sentinel_untouched}, elapsed={:?}, events={events:?}, markers={markers:?}, outcome={description}",
            std::process::id(),
            started.elapsed()
        );
        sentinel_identity.send_signal(Signal::SIGKILL).unwrap();
        assert_eq!(
            unsafe { libc::waitpid(sentinel.as_raw(), std::ptr::null_mut(), 0) },
            sentinel.as_raw()
        );
        let done = match result {
            Ok(ToolRunOutcome::Complete(done)) => done,
            other => {
                // This rescue cannot satisfy the original predicate, and keeps
                // the same completion/Pending owner until it is polled again.
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let signal = identity.send_signal(Signal::SIGKILL);
                let rescue = match other {
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout(Duration::from_secs(2), pending.resume_cleanup()).await
                    }
                    Err(_) => tokio::time::timeout(Duration::from_secs(2), &mut wait).await,
                    _ => unreachable!(),
                };
                panic!(
                    "original namespace predicate failed; separate rescue signal={signal:?}, completed={}",
                    matches!(rescue, Ok(ToolRunOutcome::Complete(_)))
                );
            }
        };
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(fatal_monotonic_ns() < original_deadline);
        assert!(retired && sentinel_untouched);
        if query_failure {
            let failure = done
                .result
                .expect_err("actual namespace metadata ENOENT must fail the run");
            eprintln!("actual namespace lookup failure: {failure:?}");
            assert_eq!(failure.origin().phase, "ptrace timer signal");
            assert!(
                matches!(failure.primary(), Error::Errno(Errno::ENOENT)),
                "original query errno lost: {:?}",
                failure.primary()
            );
            assert!(failure.captured_prefix().unwrap().stdout().is_empty());
            for kind in [0, 1, 4, 5] {
                assert_eq!(events.iter().filter(|event| event.0 == kind).count(), 1);
            }
            assert!(
                !events.iter().any(|event| matches!(event.0, 2 | 3)),
                "query failure continued into Tool timer/signal"
            );
            return;
        }
        let output = done.result.unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));
        assert!(output.stderr.is_empty(), "guest stderr={:?}", output.stderr);
        let guest_pid = if descendant { 1 } else { root.as_raw() };
        assert_eq!(
            output.stdout,
            format!("guest_pid={guest_pid}\nnamespace-survived").as_bytes()
        );
        for kind in [0, 1, 4, 5] {
            assert_eq!(
                events.iter().filter(|event| event.0 == kind).count(),
                1,
                "hook kind {kind}"
            );
        }
        let timers: Vec<_> = events.iter().filter(|event| event.0 == 2).collect();
        let signals: Vec<_> = events.iter().filter(|event| event.0 == 3).collect();
        assert_eq!(
            timers.len(),
            usize::from(mode == "kick"),
            "controller kick must deliver exactly one timer; guest markers must not become timer callbacks"
        );
        assert_eq!(
            signals.len(),
            usize::from(mode != "kick"),
            "controller kick must not become a guest signal; genuine guest markers stay visible"
        );
        let expected_sender = if mode == "kick" {
            if descendant {
                0
            } else {
                std::process::id() as i32
            }
        } else if mode == "zero-active" {
            0
        } else {
            guest_pid
        };
        assert!(
            markers
                .iter()
                .any(|row| row.1 == reverie::PERF_EVENT_SIGNAL as i32
                    && row.2 == libc::SI_TKILL
                    && row.3 == expected_sender),
            "missing actual expected sender/code"
        );
        if matches!(mode, "guest-active" | "zero-active") {
            let first = markers.first().expect("actual guest-first marker missing");
            assert_eq!(
                (first.1, first.2, first.3),
                (
                    reverie::PERF_EVENT_SIGNAL as i32,
                    libc::SI_TKILL,
                    expected_sender
                )
            );
            assert!(
                first.6,
                "guest marker must be observed with a current controller request"
            );
        }
        if mode == "kick" {
            let requested = events.iter().find(|event| event.0 == 1).unwrap().2;
            assert!(
                timers[0].2 > requested,
                "timer fired before its requested clock target"
            );
        } else {
            assert_eq!(
                (signals[0].3, signals[0].4),
                (libc::SI_TKILL, expected_sender)
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn namespace_lookup_real_enoent_keeps_failure_and_retires_owned_tree() {
        control(true, "query-failure").await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn descendant_guest_pid_equal_to_controller_pid_is_not_controller() {
        const NAME: &str = "tracer::tests::fatal_namespace_timer_tests::descendant_guest_pid_equal_to_controller_pid_is_not_controller";
        const CHILD: &str = "REVERIE_NAMESPACE_TIMER_PID_ONE_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(NAME) {
            assert_eq!(std::process::id(), 1, "outer tracer must actually be PID1");
            control(true, "guest-active").await;
            return;
        }
        let deadline = fatal_monotonic_ns() + 3_000_000_000;
        let mut child = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--mount-proc",
            ])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, NAME)
            .env("REVERIE_NAMESPACE_TIMER_DEADLINE_NS", deadline.to_string())
            .spawn()
            .unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                eprintln!(
                    "nested namespace exact child status={status}, remaining_ns={}",
                    deadline.saturating_sub(fatal_monotonic_ns())
                );
                assert!(status.success());
                assert!(fatal_monotonic_ns() < deadline);
                return;
            }
            if fatal_monotonic_ns() >= deadline {
                eprintln!("nested namespace original pre-start3s predicate failed");
                let kill = child.kill();
                let rescue = Instant::now() + Duration::from_secs(2);
                let status = loop {
                    let status = child.try_wait().unwrap();
                    if status.is_some() || Instant::now() >= rescue {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                panic!(
                    "nested namespace timed out; separate rescue kill={kill:?}, status={status:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn same_pid_namespace_controller_kick_delivers_once() {
        control(false, "kick").await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn descendant_pid_namespace_controller_kick_delivers_once() {
        control(true, "kick").await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn descendant_pid_namespace_guest_marker_is_visible() {
        control(true, "guest").await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn descendant_pid_namespace_guest_marker_with_active_request_is_visible() {
        control(true, "guest-active").await;
    }
    #[tokio::test(flavor = "current_thread")]
    async fn same_pid_namespace_zero_sender_with_active_request_is_not_controller() {
        control(false, "zero-active").await;
    }
}
