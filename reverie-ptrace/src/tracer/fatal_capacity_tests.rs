/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub(super) mod fatal_capacity_tests {
    use super::*;

    type FinishedObservations = Vec<(i32, bool, bool, bool)>;
    thread_local! {
        static FINISHED: std::cell::RefCell<Option<FinishedObservations>> = const { std::cell::RefCell::new(None) };
        static REPORTED_FINISHED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static RETIREMENT: std::cell::RefCell<Option<CapacityRetirement>> = const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn record_finished(stop: &FatalTaskStop) {
        FINISHED.with(|slot| {
            if let Some(records) = slot.borrow_mut().as_mut() {
                records.push((
                    stop.tid.as_raw(),
                    matches!(stop.terminal.observed_exit_status(), Ok(Some(_))),
                    stop.terminal.wait(Duration::ZERO),
                    stop.held.lock().unwrap().is_none(),
                ));
            }
        });
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CapacityFault {
        None,
        RetainSixOwners,
        // Retains three owners, and each marker samples only after the bodies
        // of every child created so far have dropped.
        RetainThreeOwnersSettledSamples,
        HoldOneExitHook,
    }

    struct CapacityRetirement {
        root: Option<Pid>,
        registered: usize,
        completed: usize,
        expected_child_status: ExitStatus,
        waiter: Option<std::task::Waker>,
        steady_fds: Option<usize>,
        fault: CapacityFault,
        // Only the explicit negative controls retain real descriptor owners.
        retained: Vec<Arc<FatalTaskStop>>,
        held_hook: bool,
        release_hook: bool,
        hook_waiter: Option<std::task::Waker>,
    }

    pub(crate) fn record_registered(task: &Arc<FatalTaskStop>) {
        RETIREMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(state) = slot.as_mut() else { return };
            if state.registered == 0 {
                assert_eq!(Some(task.tid), state.root, "first registration is the root");
            } else {
                assert_ne!(Some(task.tid), state.root, "root registered twice");
                let retain = match state.fault {
                    CapacityFault::RetainSixOwners => 6,
                    CapacityFault::RetainThreeOwnersSettledSamples => 3,
                    _ => 0,
                };
                if state.retained.len() < retain {
                    state.retained.push(Arc::clone(task));
                }
            }
            state.registered = state.registered.checked_add(1).unwrap();
            assert!(
                state.registered <= TASKS + 1,
                "extra capacity task registration"
            );
        });
    }

    pub(crate) fn record_body_dropped(tid: Pid, status: Option<ExitStatus>) {
        let waiter = RETIREMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let state = slot.as_mut()?;
            assert_ne!(Some(tid), state.root, "root cannot publish a child receipt");
            assert_eq!(
                status,
                Some(state.expected_child_status),
                "child did not complete naturally"
            );
            state.completed = state.completed.checked_add(1).unwrap();
            assert!(
                state.completed <= TASKS,
                "extra child-body completion receipt"
            );
            state.waiter.take()
        });
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    async fn all_child_bodies_dropped() {
        // One publisher continuation exists per successful ordinary child
        // wrapper. Each such body registered once before it ran. The root has
        // no wrapper and stays stopped in its final marker. Together the two
        // checked counts establish this fixture's complete child set without
        // matching reusable numeric TIDs or serializing earlier iterations.
        futures::future::poll_fn(|cx| {
            RETIREMENT.with(|slot| {
                let mut slot = slot.borrow_mut();
                let state = slot.as_mut().unwrap();
                state.waiter = Some(cx.waker().clone());
                if state.completed != TASKS {
                    return std::task::Poll::Pending;
                }
                assert_eq!(state.registered, TASKS + 1);
                FINISHED.with(|finished| {
                    let finished = finished.borrow();
                    let records = finished.as_ref().unwrap();
                    assert_eq!(records.len(), TASKS);
                    assert!(
                        records.iter().all(|record| {
                            Some(Pid::from_raw(record.0)) != state.root
                                && record.1
                                && record.2
                                && record.3
                        }),
                        "child receipt preceded terminal retirement or consuming hooks"
                    );
                });
                state.waiter = None;
                std::task::Poll::Ready(())
            })
        })
        .await;
    }

    async fn settle_before_sample(iteration: usize) {
        // Settled-samples control only; every other mode returns here without
        // awaiting. At marker `iteration` the guest has waited for or joined
        // children 0..=iteration and has not created the next one, so exactly
        // those children are registered. Each publishes one receipt after its
        // whole body has dropped, so `completed > iteration` means none of
        // them is in flight. There is no separate timer: if a body never
        // drops, the original shared deadline expires before this marker
        // prints, and the control's marker count and checkpoint fail.
        let completed = RETIREMENT.with(|slot| {
            let slot = slot.borrow();
            let state = slot.as_ref().unwrap();
            if state.fault != CapacityFault::RetainThreeOwnersSettledSamples {
                return None;
            }
            assert_eq!(
                state.registered,
                iteration + 2,
                "settled sample saw an unexpected child set"
            );
            Some(state.completed)
        });
        let Some(completed) = completed else { return };
        if completed > iteration {
            return;
        }
        eprintln!("capacity settle wait: iteration={iteration}, completed_at_entry={completed}");
        futures::future::poll_fn(|cx| {
            RETIREMENT.with(|slot| {
                let mut slot = slot.borrow_mut();
                let state = slot.as_mut().unwrap();
                state.waiter = Some(cx.waker().clone());
                if state.completed <= iteration {
                    return std::task::Poll::Pending;
                }
                state.waiter = None;
                std::task::Poll::Ready(())
            })
        })
        .await;
    }

    fn release_hook_for_rescue() {
        let waiter = RETIREMENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            let state = slot.as_mut().unwrap();
            state.release_hook = true;
            state.hook_waiter.take()
        });
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    const TASKS: usize = 96;
    const FD_LIMIT: libc::rlim_t = 128;

    #[derive(Default)]
    struct CapacityLog(Arc<StdMutex<Vec<(usize, usize)>>>);

    #[reverie::global_tool]
    impl GlobalTool for CapacityLog {
        type Config = ();
        type Request = (usize, usize);
        type Response = ();
        async fn receive_rpc(&self, _: Pid, sample: Self::Request) {
            self.0.lock().unwrap().push(sample);
        }
    }

    #[derive(Default)]
    struct CapacityTool;

    #[reverie::tool]
    impl Tool for CapacityTool {
        type GlobalState = CapacityLog;
        type ThreadState = ();

        fn subscriptions(_: &()) -> Subscription {
            [Sysno::getpgid].into_iter().collect()
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            // The guest join/wait has completed. A yield permits the backend
            // owner to progress but does not itself prove retirement. Record
            // the actual post-hook session.finished boundary separately using
            // scalar observations only; no descriptor authority is retained.
            tokio::task::yield_now().await;
            let (_, args) = syscall.into_parts();
            settle_before_sample(args.arg0).await;
            let fds = fs::read_dir("/proc/self/fd")
                .map_err(anyhow::Error::new)?
                .count();
            // FINISHED only appends immutable scalar observations on this
            // ptracer thread. Indexed deltas reconstruct every marker
            // prefix without repeatedly cloning and printing old tuples.
            let start = REPORTED_FINISHED.with(|reported| reported.get());
            let (end, finished) = FINISHED.with(|slot| {
                let slot = slot.borrow();
                let records = slot.as_ref().unwrap();
                (records.len(), records[start..].to_vec())
            });
            eprintln!(
                "capacity marker: iteration={}, fds={fds}, finished_after_hooks_range={start}..{end}, finished_after_hooks_new={finished:?}",
                args.arg0
            );
            REPORTED_FINISHED.with(|reported| reported.set(end));
            guest.send_rpc((args.arg0, fds)).await;
            if args.arg0 == TASKS - 1 {
                // Preserve all original immediate samples and their overlap.
                // Only the final steady-state predicate changes phase: the
                // root remains alive here until every child body has dropped.
                all_child_bodies_dropped().await;
                let steady_fds = fs::read_dir("/proc/self/fd")
                    .map_err(anyhow::Error::new)?
                    .count();
                RETIREMENT.with(|slot| {
                    assert!(
                        slot.borrow_mut()
                            .as_mut()
                            .unwrap()
                            .steady_fds
                            .replace(steady_fds)
                            .is_none()
                    );
                });
                eprintln!(
                    "capacity retirement sample: iteration={}, fds={steady_fds}, root_alive=true",
                    args.arg0
                );
            }
            Ok(0)
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            _: &G,
            _: (),
            _: ExitStatus,
        ) -> Result<(), Error> {
            let hold = RETIREMENT.with(|slot| {
                let mut slot = slot.borrow_mut();
                let state = slot.as_mut().unwrap();
                if state.fault == CapacityFault::HoldOneExitHook
                    && Some(tid) != state.root
                    && !state.held_hook
                {
                    state.held_hook = true;
                    true
                } else {
                    false
                }
            });
            if hold {
                futures::future::poll_fn(|cx| {
                    RETIREMENT.with(|slot| {
                        let mut slot = slot.borrow_mut();
                        let state = slot.as_mut().unwrap();
                        state.hook_waiter = Some(cx.waker().clone());
                        if state.release_hook {
                            state.hook_waiter = None;
                            std::task::Poll::Ready(())
                        } else {
                            std::task::Poll::Pending
                        }
                    })
                })
                .await;
            }
            Ok(())
        }
    }

    async fn isolated_capacity(threads: bool, deadline: u64) {
        FINISHED.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
        REPORTED_FINISHED.with(|reported| reported.set(0));
        let fault = match std::env::var("REVERIE_FATAL_CAPACITY_FAULT").as_deref() {
            Err(std::env::VarError::NotPresent) => CapacityFault::None,
            Ok("retain-six-owners") => CapacityFault::RetainSixOwners,
            Ok("retain-three-owners-settled-samples") => {
                CapacityFault::RetainThreeOwnersSettledSamples
            }
            Ok("hold-one-exit-hook") => CapacityFault::HoldOneExitHook,
            other => panic!("unknown capacity fault: {other:?}"),
        };
        RETIREMENT.with(|slot| {
            *slot.borrow_mut() = Some(CapacityRetirement {
                root: None,
                registered: 0,
                completed: 0,
                expected_child_status: ExitStatus::Exited(if threads { 0 } else { 7 }),
                waiter: None,
                steady_fds: None,
                fault,
                retained: Vec::new(),
                held_hook: false,
                release_hook: false,
                hook_waiter: None,
            })
        });
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0
        );
        assert!(original.rlim_max >= FD_LIMIT);
        let limited = libc::rlimit {
            rlim_cur: FD_LIMIT,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        let tracer = tokio::time::timeout(
            fatal_remaining(deadline),
            spawn_fn_with_config::<CapacityTool, _>(
                move || {
                    for iteration in 0..TASKS {
                        if threads {
                            std::thread::spawn(|| 7).join().unwrap();
                        } else {
                            let child = unsafe { libc::fork() };
                            assert!(child >= 0);
                            if child == 0 {
                                unsafe { libc::_exit(7) };
                            }
                            let mut status = 0;
                            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                            assert!(libc::WIFEXITED(status));
                            assert_eq!(libc::WEXITSTATUS(status), 7);
                        }
                        assert_eq!(unsafe { libc::syscall(libc::SYS_getpgid, iteration) }, 0);
                    }
                },
                (),
                true,
            ),
        )
        .await
        .expect("capacity spawn exceeded the original shared deadline")
        .unwrap();
        let root = tracer.guest_pid();
        RETIREMENT.with(|slot| slot.borrow_mut().as_mut().unwrap().root = Some(root));
        let termination = tracer.termination_handle().unwrap();
        let samples = tracer.gref.0.clone();
        let mut owner = Box::pin(tracer.wait_with_output_completion());
        let result = tokio::time::timeout(fatal_remaining(deadline), &mut owner).await;
        let captured = samples.lock().unwrap().clone();
        let description = match &result {
            Ok(ToolRunOutcome::Complete(done)) => format!("Complete({:?})", done.result),
            Ok(ToolRunOutcome::CleanupPending(pending)) => {
                format!("Pending({:?})", pending.failure())
            }
            Ok(ToolRunOutcome::UnsupportedBackend(_)) => "UnsupportedBackend".to_owned(),
            Err(error) => format!("Timeout({error})"),
        };
        eprintln!(
            "capacity original predicate: threads={threads}, soft_nofile={FD_LIMIT}, required_tasks={TASKS}, samples={captured:?}, outcome={description}"
        );
        // Keep one self-contained checkpoint, including any observations
        // since the last marker, before rescue can add observations.
        let finished = FINISHED.with(|slot| slot.borrow().as_ref().unwrap().clone());
        eprintln!("capacity original checkpoint: finished_after_hooks={finished:?}");
        let steady_fds = RETIREMENT.with(|slot| {
            let slot = slot.borrow();
            let state = slot.as_ref().unwrap();
            eprintln!(
                "capacity retirement checkpoint: registered={}, completed={}, retained={}, held_hook={}, steady_fds={:?}",
                state.registered, state.completed, state.retained.len(), state.held_hook, state.steady_fds
            );
            state.steady_fds
        });
        let complete = match result {
            Ok(ToolRunOutcome::Complete(done)) => done,
            other => {
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                // Negative-control release happens only after the original
                // outcome and checkpoint are captured. Rescue remains failure.
                release_hook_for_rescue();
                termination.terminate(Error::Tool(anyhow::Error::new(TestDeadline)));
                let rescued = match other {
                    Err(_) => tokio::time::timeout_at(rescue_deadline.into(), &mut owner).await,
                    Ok(ToolRunOutcome::CleanupPending(pending)) => {
                        tokio::time::timeout_at(rescue_deadline.into(), pending.resume_cleanup())
                            .await
                    }
                    Ok(ToolRunOutcome::UnsupportedBackend(tracer)) => {
                        tokio::time::timeout_at(
                            rescue_deadline.into(),
                            tracer.wait_with_output_completion(),
                        )
                        .await
                    }
                    Ok(ToolRunOutcome::Complete(_)) => unreachable!(),
                };
                eprintln!(
                    "capacity rescue only: completed={}",
                    matches!(rescued, Ok(ToolRunOutcome::Complete(_)))
                );
                panic!(
                    "capacity did not complete under the original shared 3s deadline: {description}"
                );
            }
        };
        let output = complete
            .result
            .expect("short-lived tasks must not exhaust tracer fds");
        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(captured.len(), TASKS);
        for (index, sample) in captured.iter().enumerate() {
            assert_eq!(sample.0, index);
        }
        // Fixed headroom accounts for the original task/hook completing beside
        // the next marker. It cannot hide the 3/4-fd-per-task baseline slope.
        let baseline = captured[0].1;
        let maximum_immediate = captured.iter().map(|sample| sample.1).max().unwrap();
        eprintln!(
            "capacity fd bounds: baseline={baseline}, maximum_immediate={maximum_immediate}, steady_fds={steady_fds:?}"
        );
        assert!(
            captured.iter().all(|sample| sample.1 <= baseline + 8),
            "retired tasks retained descriptors: {captured:?}"
        );
        assert!(
            steady_fds.expect("final marker did not observe every child-body retirement")
                <= baseline + 2,
            "descriptor count did not return to the initial steady state"
        );
        assert_reaped("capacity root", root);
        let _remaining = fatal_remaining(deadline);
    }

    async fn capacity_control(threads: bool, name: &str) {
        if std::env::var("REVERIE_FATAL_CAPACITY_TEST").as_deref() == Ok(name) {
            assert!(std::env::args().any(|arg| arg == name));
            let deadline = std::env::var("REVERIE_FATAL_CAPACITY_DEADLINE_NS")
                .unwrap()
                .parse()
                .unwrap();
            isolated_capacity(threads, deadline).await;
            return;
        }
        // A reduced process-wide fd limit belongs only to this exact isolated
        // test process. The deadline begins before the re-exec, not after it.
        let deadline = fatal_monotonic_ns() + 3_000_000_000;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--nocapture", "--test-threads=1"])
            .env("REVERIE_FATAL_CAPACITY_TEST", name)
            .env("REVERIE_FATAL_CAPACITY_DEADLINE_NS", deadline.to_string())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated reduced-NOFILE capacity predicate failed: {status}"
        );
        let _remaining = fatal_remaining(deadline);
    }

    fn capacity_negative_control(
        threads: bool,
        fault: &str,
        failure: &str,
        checkpoint: &str,
    ) -> String {
        let name = if threads {
            "tracer::tests::fatal_capacity_tests::retired_threads_release_descriptors_under_reduced_nofile"
        } else {
            "tracer::tests::fatal_capacity_tests::retired_processes_release_descriptors_under_reduced_nofile"
        };
        // Enter the same isolated predicate directly. Its original shared 3s
        // deadline still begins before this re-exec; retain the literal red.
        let deadline = fatal_monotonic_ns() + 3_000_000_000;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name, "--exact", "--nocapture", "--test-threads=1"])
            .env("REVERIE_FATAL_CAPACITY_TEST", name)
            .env("REVERIE_FATAL_CAPACITY_DEADLINE_NS", deadline.to_string())
            .env("REVERIE_FATAL_CAPACITY_FAULT", fault)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        eprintln!(
            "capacity injected control: fault={fault}, literal_status={}\n{stderr}",
            output.status
        );
        eprintln!(
            "capacity injected child stdout begin\n{stdout}\ncapacity injected child stdout end"
        );
        assert_eq!(
            output.status.code(),
            Some(101),
            "injected control did not fail: {stderr}"
        );
        assert_eq!(
            stderr
                .lines()
                .filter(|line| line.starts_with("capacity marker:"))
                .count(),
            TASKS
        );
        assert!(
            stderr.contains(checkpoint),
            "wrong retirement boundary: {stderr}"
        );
        assert!(
            stderr.contains(failure),
            "wrong original predicate failed: {stderr}"
        );
        stderr
    }

    // CleanupPending and UnsupportedBackend reach the same generic deadline
    // panic. Qualify the unique original outcome, before rescue can alter it.
    fn capacity_original_timeout_before_rescue(stderr: &str) -> bool {
        let mut originals = stderr
            .lines()
            .enumerate()
            .filter(|(_, line)| line.starts_with("capacity original predicate:"));
        let Some((original_line, original)) = originals.next() else {
            return false;
        };
        if originals.next().is_some()
            || !original.ends_with(", outcome=Timeout(deadline has elapsed)")
        {
            return false;
        }
        stderr
            .lines()
            .position(|line| line.starts_with("capacity rescue only:"))
            .is_some_and(|rescue_line| original_line < rescue_line)
    }

    #[test]
    fn stalled_hook_control_rejects_non_timeout_original_outcomes() {
        let stderr = |outcome| {
            format!(
                "capacity original predicate: threads=true, soft_nofile=128, required_tasks=96, samples=[], outcome={outcome}\n\
                 capacity rescue only: completed=true\n\
                 capacity did not complete under the original shared 3s deadline: {outcome}\n"
            )
        };
        assert!(capacity_original_timeout_before_rescue(&stderr(
            "Timeout(deadline has elapsed)"
        )));
        for outcome in [
            "Pending(backend failure)",
            "Pending(Timeout(deadline has elapsed))",
            "UnsupportedBackend",
            "Complete(Ok(output))",
        ] {
            assert!(
                !capacity_original_timeout_before_rescue(&stderr(outcome)),
                "non-timeout original outcome accepted: {outcome}"
            );
        }
    }

    #[test]
    fn stalled_hook_control_requires_unique_pre_rescue_outcome() {
        let original = "capacity original predicate: threads=true, soft_nofile=128, required_tasks=96, samples=[], outcome=Timeout(deadline has elapsed)\n";
        let rescue = "capacity rescue only: completed=true\n";
        assert!(capacity_original_timeout_before_rescue(&format!(
            "{original}{rescue}"
        )));
        for stderr in [
            original.to_owned(),
            rescue.to_owned(),
            format!("{rescue}{original}"),
            format!("{original}{original}{rescue}"),
            format!("{original}{rescue}{original}"),
        ] {
            assert!(
                !capacity_original_timeout_before_rescue(&stderr),
                "ambiguous or missing pre-rescue outcome accepted: {stderr}"
            );
        }
    }

    #[test]
    fn retained_child_owners_falsify_capacity_bound() {
        let stderr = capacity_negative_control(
            true,
            "retain-six-owners",
            "retired tasks retained descriptors",
            "capacity retirement checkpoint: registered=97, completed=96, retained=6, held_hook=false, steady_fds=Some(",
        );
        assert!(!stderr.contains("capacity rescue only:"));
    }

    #[test]
    fn retained_owners_with_settled_samples_falsify_steady_state_bound() {
        // The first retained owner's two descriptors are already in the
        // baseline. The other two owners add a pair each, so iteration 2 on
        // and steady_fds should read baseline + 4: above +2, within +8. This
        // fault mode samples each marker only after every child created so
        // far has dropped its body, so no child is in flight at any sample.
        // Check the actual measurements; do not assume that accounting.
        let failure = "descriptor count did not return to the initial steady state";
        let stderr = capacity_negative_control(
            true,
            "retain-three-owners-settled-samples",
            failure,
            "capacity retirement checkpoint: registered=97, completed=96, retained=3, held_hook=false, steady_fds=Some(",
        );
        assert!(!stderr.contains("capacity rescue only:"));
        assert!(!stderr.contains("retired tasks retained descriptors"));
        assert_eq!(stderr.lines().filter(|line| *line == failure).count(), 1);
        let mut bounds = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("capacity fd bounds: baseline="));
        let bound = bounds.next().expect("missing original fd measurements");
        assert!(
            bounds.next().is_none(),
            "duplicate original fd measurements"
        );
        let (baseline, rest) = bound.split_once(", maximum_immediate=").unwrap();
        let (maximum_immediate, steady_fds) = rest.split_once(", steady_fds=Some(").unwrap();
        let baseline: usize = baseline.parse().unwrap();
        let maximum_immediate: usize = maximum_immediate.parse().unwrap();
        let steady_fds: usize = steady_fds.strip_suffix(')').unwrap().parse().unwrap();
        assert!(
            maximum_immediate <= baseline + 8,
            "final-bound control exceeded the unchanged immediate bound: {bound}"
        );
        assert!(
            steady_fds > baseline + 2 && steady_fds <= baseline + 8,
            "retained owners did not isolate the final +2 bound: {bound}"
        );
    }

    #[test]
    fn nonretiring_child_hook_falsifies_original_deadline() {
        let stderr = capacity_negative_control(
            true,
            "hold-one-exit-hook",
            "capacity did not complete under the original shared 3s deadline",
            "capacity retirement checkpoint: registered=97, completed=95, retained=0, held_hook=true, steady_fds=None",
        );
        assert!(
            capacity_original_timeout_before_rescue(&stderr),
            "stalled hook did not produce a unique original timeout before rescue: {stderr}"
        );
        assert!(stderr.contains("capacity rescue only: completed=true"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_processes_release_descriptors_under_reduced_nofile() {
        capacity_control(false, "tracer::tests::fatal_capacity_tests::retired_processes_release_descriptors_under_reduced_nofile").await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_threads_release_descriptors_under_reduced_nofile() {
        capacity_control(true, "tracer::tests::fatal_capacity_tests::retired_threads_release_descriptors_under_reduced_nofile").await;
    }
}
