/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

#[derive(Default)]
struct LowerTool;
#[reverie::tool]
impl Tool for LowerTool {
    type GlobalState = ();
    type ThreadState = ();
}
#[derive(Default)]
struct AdapterTool(LowerTool);
impl AsMut<LowerTool> for AdapterTool {
    fn as_mut(&mut self) -> &mut LowerTool {
        &mut self.0
    }
}
#[reverie::tool]
impl Tool for AdapterTool {
    type GlobalState = ();
    type ThreadState = Box<()>;
}
struct RefusingExecutor;
impl GuestSyscallExecutor<AdapterTool> for RefusingExecutor {
    fn read_clock(&self) -> Result<u64> {
        Err(Error::GuestClock(
            "signal test adapter has no guest counter".into(),
        ))
    }

    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("terminal cancellation executed a syscall")
    }
    fn tail_injection_allowed(&self, _request: &SyscallRequest) -> bool {
        false
    }
    fn complete_injection<'a>(
        &'a mut self,
        _: ToolContext<'a, AdapterTool>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        AdapterTool: 'a,
    {
        panic!("terminal cancellation completed an injection")
    }
}

#[test]
fn terminal_read_injection_keeps_nonreturning_cancellation_and_typed_failures() {
    struct ReadExecutor {
        result: Option<Result<i64>>,
        parked: Option<reverie::ParkedSignalFailureContext>,
        completions: usize,
        wrapped: usize,
    }
    impl GuestSyscallExecutor<LowerTool> for ReadExecutor {
        fn read_clock(&self) -> Result<u64> {
            panic!("read cancellation requested a guest clock")
        }
        fn execute(&mut self, request: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
            assert_eq!(request.number(), libc::SYS_read as u64);
            assert_eq!(request.args()[..3], [0, 0, 0]);
            self.result.take().expect("terminal read was retried")
        }
        fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
            self.parked
        }
        fn with_signal_effects(&mut self, error: Error, raw: Option<i64>) -> Error {
            assert_eq!(raw, None);
            self.wrapped += 1;
            error
        }
        fn complete_injection<'a>(
            &'a mut self,
            _: ToolContext<'a, LowerTool>,
        ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
        where
            LowerTool: 'a,
        {
            self.completions += 1;
            Box::pin(async {
                Ok(InjectionCompletion::Returns {
                    syscall_result: None,
                })
            })
        }
    }

    let parked = reverie::ParkedSignalFailureContext {
        site: reverie::CallbackSignalSite {
            process: reverie::SignalProcessId {
                tgid: Pid::from_raw(71),
                generation: 3,
            },
            tid: Pid::from_raw(72),
            task_generation: 4,
            callback_nonce: 5,
            boundary_nonce: 6,
        },
        ledger_nonce: 7,
    };
    for case in [
        "cancelled",
        "parked",
        "dequeue",
        "returned",
        "failed",
        "cleanup",
    ] {
        let mut executor = ReadExecutor {
            result: Some(match case {
                "returned" => Ok(0),
                "failed" => Err(Error::RunAborted),
                "cleanup" => Err(
                    Error::TerminalReadCancelled.with_cleanup(vec![Error::HostIo(
                        std::io::Error::from_raw_os_error(libc::EIO),
                    )]),
                ),
                _ => Err(Error::TerminalReadCancelled),
            }),
            parked: (case == "parked").then_some(parked),
            completions: 0,
            wrapped: 0,
        };
        let mut state = ();
        let subscriptions = Subscription::none();
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let mut guest = KvmGuest::<LowerTool>::new(
            Pid::from_raw(71),
            Pid::from_raw(72),
            Arc::new(LowerTool),
            GuestMemory::new(0, STACK_CAPACITY).unwrap(),
            &[],
            // This mock has no vCPU and never accesses registers.
            unsafe { std::mem::zeroed() },
            &mut state,
            &mut executor,
            &(),
            None,
            &(),
            &subscriptions,
            signal.clone(),
            starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        guest.notifying_dequeue = case == "dequeue";
        let mut continued = false;
        let outcome = futures::executor::block_on(drive_handler(
            async {
                let read = SyscallRequest::new(libc::SYS_read as u64, [0; 6])
                    .into_syscall()
                    .unwrap();
                let result = guest.inject(read).await;
                continued = true;
                result
            },
            signal,
            starts,
            std::future::pending(),
        ));
        drop(guest);
        assert_eq!(continued, case == "returned", "case={case}");
        assert_eq!(executor.completions, usize::from(case == "returned"));
        assert_eq!(
            executor.wrapped,
            usize::from(matches!(case, "dequeue" | "failed" | "cleanup"))
        );
        match (case, outcome) {
            ("cancelled", HandlerOutcome::ThreadCancelled) => {}
            ("parked", HandlerOutcome::ParkedCancelled(actual)) => assert_eq!(actual, parked),
            ("returned", HandlerOutcome::Returned(Ok(0))) => {}
            ("dequeue" | "failed", HandlerOutcome::RuntimeError(Error::RunAborted)) => {}
            ("cleanup", HandlerOutcome::RuntimeError(Error::WithCleanup { primary, cleanup })) => {
                assert!(matches!(primary.as_ref(), Error::TerminalReadCancelled));
                assert_eq!(cleanup.len(), 1);
                assert!(
                    matches!(cleanup[0].as_ref(), Error::HostIo(error) if error.raw_os_error() == Some(libc::EIO))
                );
            }
            _ => panic!("wrong terminal-read disposition for {case}"),
        }
    }
}

#[test]
fn terminal_cancellation_and_into_guest_forwarding_do_not_inject_or_start_children() {
    for adapted in [false, true] {
        for thread in [false, true] {
            let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
            let mut state = Box::new(());
            let mut executor = RefusingExecutor;
            let subscriptions = Subscription::none();
            let signal = Arc::new(Mutex::new(None));
            let starts = Arc::new(Mutex::new(Vec::new()));
            let (sender, receiver) = std::sync::mpsc::channel();
            let gate = ChildStartGate::new(sender);
            starts.lock().unwrap().push(if thread {
                PendingChildStart::tool_thread(2, gate)
            } else {
                PendingChildStart::fork_process(2, gate)
            });
            let mut guest = KvmGuest::<AdapterTool>::new(
                Pid::from_raw(1),
                Pid::from_raw(2),
                Arc::new(AdapterTool::default()),
                memory,
                &[],
                // SAFETY: this test never reads the register fields.
                unsafe { std::mem::zeroed() },
                &mut state,
                &mut executor,
                &(),
                None,
                &(),
                &subscriptions,
                signal.clone(),
                starts.clone(),
                crate::bootstrap::TOOL_STACK_TOP,
                Arc::new(AtomicBool::new(false)),
            );
            let outcome = futures::executor::block_on(drive_handler(
                async {
                    if adapted {
                        <_ as Guest<LowerTool>>::cancel_current_thread(&mut guest.into_guest())
                            .await
                    } else {
                        guest.cancel_current_thread().await
                    }
                },
                signal,
                starts.clone(),
                std::future::pending(),
            ));
            assert!(
                matches!(outcome, HandlerOutcome::ThreadCancelled),
                "adapted={adapted}"
            );
            assert_eq!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            assert_eq!(starts.lock().unwrap().len(), 1);
            // The owning caller, after dropping the callback, releases successful starts.
            start_pending_children(&starts).unwrap();
            assert_eq!(receiver.recv().unwrap(), ChildStartCommand::Start);
            assert!(starts.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn natural_retirement_and_into_guest_forwarding_do_not_inject_or_start_children() {
    for adapted in [false, true] {
        for thread in [false, true] {
            let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
            let mut state = Box::new(());
            let mut executor = RefusingExecutor;
            let subscriptions = Subscription::none();
            let signal = Arc::new(Mutex::new(None));
            let starts = Arc::new(Mutex::new(Vec::new()));
            let (sender, receiver) = std::sync::mpsc::channel();
            let gate = ChildStartGate::new(sender);
            starts.lock().unwrap().push(if thread {
                PendingChildStart::tool_thread(2, gate)
            } else {
                PendingChildStart::fork_process(2, gate)
            });
            let mut guest = KvmGuest::<AdapterTool>::new(
                Pid::from_raw(1),
                Pid::from_raw(2),
                Arc::new(AdapterTool::default()),
                memory,
                &[],
                // SAFETY: this test never reads the register fields.
                unsafe { std::mem::zeroed() },
                &mut state,
                &mut executor,
                &(),
                None,
                &(),
                &subscriptions,
                signal.clone(),
                starts.clone(),
                crate::bootstrap::TOOL_STACK_TOP,
                Arc::new(AtomicBool::new(false)),
            );
            let outcome = futures::executor::block_on(drive_handler(
                async {
                    if adapted {
                        <_ as Guest<LowerTool>>::retire_current_thread(&mut guest.into_guest())
                            .await
                    } else {
                        guest.retire_current_thread().await
                    }
                },
                signal,
                starts.clone(),
                std::future::pending(),
            ));
            assert!(
                matches!(outcome, HandlerOutcome::ThreadRetired),
                "adapted={adapted}"
            );
            assert_eq!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            assert_eq!(starts.lock().unwrap().len(), 1);
            // The owning caller, after dropping the callback, releases successful starts.
            start_pending_children(&starts).unwrap();
            assert_eq!(receiver.recv().unwrap(), ChildStartCommand::Start);
            assert!(starts.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn terminal_exit_retires_only_current_identity_and_preserves_existing_status() {
    let cwd = std::env::current_dir().unwrap();
    let memory = GuestMemory::new(0, 4096).unwrap();
    for established in [
        None,
        Some((libc::SYS_exit, 17, false)),
        Some((libc::SYS_exit_group, 37, true)),
    ] {
        let mut leader = ElfExecutor::new(crate::executor::test_loaded_state_for_vm(&cwd), false);
        let mut retired = leader.thread_child(7).unwrap();
        let _peer = leader.thread_child(8).unwrap();
        let probe = |tid| SyscallRequest::new(libc::SYS_tgkill as u64, [1, tid, 0, 0, 0, 0]);
        assert_eq!(leader.execute(&probe(7), &memory), 0);
        if let Some((number, status, _)) = established {
            assert_eq!(
                retired.execute(
                    &SyscallRequest::new(number as u64, [status, 0, 0, 0, 0, 0]),
                    &memory
                ),
                0
            );
        }
        let exit = retired.cancel_current_thread();
        assert_eq!(
            exit.status,
            established.map_or(ExitStatus::SUCCESS, |(_, status, _)| ExitStatus::Exited(
                status as i32
            ))
        );
        assert_eq!(exit.group, established.is_some_and(|(_, _, group)| group));
        assert!(
            retired.take_exit().is_none(),
            "terminal state is consumed once"
        );
        assert_eq!(leader.execute(&probe(7), &memory), -i64::from(libc::ESRCH));
        assert_eq!(
            leader.execute(&probe(8), &memory),
            0,
            "a live peer stays registered"
        );
        let _replacement = leader.thread_child(7).unwrap();
        drop(retired);
        assert_eq!(
            leader.execute(&probe(7), &memory),
            0,
            "old generation drop must not retire reused TID"
        );
    }
}

// These are the exact context predicates, so this control needs no KVM device.
// Returning ordinary injections remain supported; only a terminal operation
// can tail out of a timestamp callback without a syscall return transport.
#[test]
fn timestamp_exit_admission_preserves_returning_ordinary_injections() {
    let context = ProcessExecutionContext::Instruction;
    for (number, tail, ordinary) in [
        (libc::SYS_exit, true, true),
        (libc::SYS_exit_group, true, true),
        (libc::SYS_write, false, true),
        (libc::SYS_execve, false, false),
        (libc::SYS_fork, false, false),
    ] {
        let request = SyscallRequest::new(number as u64, [29, 0x100, 3, 0, 0, 0]);
        assert_eq!(
            context.tail_injection_allowed(&request),
            tail,
            "syscall={number}"
        );
        assert_eq!(
            context.ordinary_injection_allowed(&request),
            ordinary,
            "syscall={number}"
        );
    }
}

#[test]
fn parked_retirement_requires_current_permit_and_acknowledged_real_removal() {
    for case in [
        "before removal",
        "acknowledged",
        "unacknowledged",
        "stale site",
        "wrong permit",
    ] {
        let cwd = std::env::current_dir().unwrap();
        let mut executor = ElfExecutor::new(crate::executor::test_loaded_state_for_vm(&cwd), false);
        executor.enable_signal_dequeues();
        let global = Arc::new(());
        let failure = RunFailure::new(&global);
        executor
            .install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &failure);
        let site = executor.begin_signal_callback().unwrap();
        let permit = reverie::SignalDeliveryPermit {
            task: executor.signal_task_identity().unwrap(),
            sequence: 7,
            site: Some(site),
        };
        let control = executor.backend_signal_control();
        control.process.reserve_delivery(permit).unwrap();
        executor
            .admit_signal_observation(site, reverie::ParkedObservationLease { nonce: 7 })
            .unwrap();
        let context = executor.signal_failure_context().unwrap();
        let mut removed = None;
        if case != "before removal" {
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
            let event = SignalEvent::new(
                libc::SIGALRM,
                info,
                reverie::SignalTarget::Process {
                    pid: Pid::from_raw(1),
                },
            )
            .unwrap();
            assert!(matches!(
                executor.queue_process_alarm_signal(event),
                reverie::ProcessAlarmSignalOutcome::Accepted(_)
            ));
            assert_eq!(
                executor
                    .take_pending_signal_for_delivery()
                    .unwrap()
                    .unwrap()
                    .event,
                event
            );
            let effect = executor.signal_dequeue_front().unwrap();
            executor.retain_signal_dequeue(effect);
            if case != "unacknowledged" {
                executor.acknowledge_signal_dequeue(effect).unwrap();
                executor.mark_signal_dequeue_acknowledged(effect.sequence);
            }
            removed = Some(effect);
        }
        if case == "stale site" {
            executor.begin_signal_callback().unwrap();
        }
        if case == "wrong permit" {
            control.process.release_delivery(permit).unwrap();
            control
                .process
                .reserve_delivery(reverie::SignalDeliveryPermit {
                    sequence: 8,
                    ..permit
                })
                .unwrap();
        }
        let result = executor.validate_signal_retirement(Some(context));
        if matches!(case, "before removal" | "acknowledged") {
            result.unwrap();
            assert_eq!(
                executor.owned_delivery_permit(),
                Some(permit),
                "validation must not release ownership"
            );
            assert_eq!(
                executor.signal_failure_context(),
                Some(context),
                "validation must not erase the ledger"
            );
        } else {
            let error = executor.with_signal_effects(result.unwrap_err(), None);
            match error {
                Error::SignalEffects {
                    cause,
                    dequeues,
                    acknowledged_through,
                    context: retained,
                    ..
                } => {
                    assert!(matches!(cause.as_ref(), Error::UnexpectedVcpuExit(_)));
                    assert_eq!(dequeues, vec![removed.unwrap()]);
                    assert_eq!(retained.as_deref(), Some(&context));
                    assert_eq!(
                        acknowledged_through,
                        if case == "unacknowledged" {
                            0
                        } else {
                            removed.unwrap().sequence
                        }
                    );
                }
                other => panic!("retirement refusal lost irreversible effects: {other:?}"),
            }
        }
    }
}

#[test]
fn parked_retirement_rejects_reused_task_and_process_generations() {
    for separate_process in [false, true] {
        let cwd = std::env::current_dir().unwrap();
        let leader = ElfExecutor::new(crate::executor::test_loaded_state_for_vm(&cwd), false);
        let mut old = if separate_process {
            leader.fork_child(3, false, false).unwrap()
        } else {
            leader.thread_child(2).unwrap()
        };
        old.enable_signal_dequeues();
        let site = old.begin_signal_callback().unwrap();
        old.retain_parked_effects(site).unwrap();
        let context = old.signal_failure_context().unwrap();
        old.validate_signal_retirement(Some(context)).unwrap();
        let old_identity = old.signal_task_identity().unwrap();
        old.cancel_current_thread();
        let replacement = if separate_process {
            leader.fork_child(3, false, false).unwrap()
        } else {
            leader.thread_child(2).unwrap()
        };
        let new_identity = replacement.signal_task_identity().unwrap();
        assert_eq!(new_identity.tid, old_identity.tid);
        assert_ne!(new_identity.task_generation, old_identity.task_generation);
        if separate_process {
            assert_ne!(
                new_identity.process.generation,
                old_identity.process.generation
            );
        }
        assert!(!old.signal_failure_context_is_current(context));
        assert!(old.validate_signal_retirement(Some(context)).is_err());
        assert!(
            replacement
                .validate_signal_retirement(Some(context))
                .is_err()
        );
        assert_eq!(old.signal_failure_context(), Some(context));
    }
    let cwd = std::env::current_dir().unwrap();
    let mut executor = ElfExecutor::new(crate::executor::test_loaded_state_for_vm(&cwd), false);
    executor.enable_signal_dequeues();
    let site = executor.begin_signal_callback().unwrap();
    executor.retain_parked_effects(site).unwrap();
    let context = executor.signal_failure_context().unwrap();
    executor.replace_after_exec(crate::executor::test_loaded_state_for_vm(&cwd));
    // The post-exec constructor is a new callback, not either bound driver
    // continuation. Its unchanged fresh-nonce fence invalidates the old site.
    let fresh = executor.begin_signal_callback().unwrap();
    assert_ne!(fresh.callback_nonce, site.callback_nonce);
    assert!(!executor.signal_failure_context_is_current(context));
    assert!(executor.validate_signal_retirement(Some(context)).is_err());
    assert_eq!(executor.signal_failure_context(), Some(context));
}

#[test]
fn shared_failure_wins_over_retirement_before_and_after_callback_poll() {
    for already_failed in [false, true] {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let failure = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let mut state = Box::new(());
        let mut executor = RefusingExecutor;
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let subscriptions = Subscription::none();
        let mut guest = KvmGuest::<AdapterTool>::new(
            Pid::from_raw(1),
            Pid::from_raw(2),
            Arc::new(AdapterTool::default()),
            GuestMemory::new(0, STACK_CAPACITY).unwrap(),
            &[],
            // No instruction or register access occurs in this callback control.
            unsafe { std::mem::zeroed() },
            &mut state,
            &mut executor,
            &(),
            None,
            &(),
            &subscriptions,
            signal.clone(),
            starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        if already_failed {
            failure.publish("before retirement", Error::InvalidGuestPid(-17));
        }
        let mut entered = false;
        let outcome = futures::executor::block_on(drive_handler(
            async {
                entered = true;
                failure.publish("during retirement", Error::InvalidGuestPid(-17));
                guest.retire_current_thread().await
            },
            signal,
            starts,
            wait_for_failure(global.as_ref(), Some(run.subscribe())),
        ));
        assert_eq!(entered, !already_failed);
        assert!(matches!(outcome, HandlerOutcome::RunFailed));
        let result: Result<()> = run.complete(Err(Error::RunAborted));
        assert!(matches!(
            result.unwrap_err().primary(),
            Error::InvalidGuestPid(-17)
        ));
    }
}

#[test]
fn signal_terminal_receipt_preserves_committed_scope_and_status() {
    for status in [
        ExitStatus::Exited(29),
        ExitStatus::Signaled(reverie::Signal::SIGALRM, false),
    ] {
        for group in [false, true] {
            let exit = ProcessExit { status, group };
            let outcome = ToolProcessExit::from(exit).signal_boundary_outcome();
            assert_eq!(
                outcome,
                reverie::SignalBoundaryOutcome::Terminated {
                    group,
                    wait_status: status.into_raw()
                }
            );
            for disposition in [
                ToolExitDisposition::ExplicitCancellation,
                ToolExitDisposition::Retirement,
            ] {
                assert_eq!(
                    ToolProcessExit { exit, disposition }.signal_boundary_outcome(),
                    reverie::SignalBoundaryOutcome::Cancelled
                );
            }
        }
    }
}

#[test]
fn wait_group_exit_injection_is_nonreturning_and_failure_still_wins() {
    // A transport control: real exact-generation selection/retirement is
    // exercised separately through ElfExecutor and the public KVM driver.
    struct FailurePublication {
        context: crate::failure::FailureContext,
        cause: Arc<Error>,
        published: Arc<Mutex<Option<Arc<Error>>>>,
    }
    impl FailurePublication {
        fn publish(self) {
            assert!(self.context.run.primary().is_none());
            let error = self.context.publish(
                "wait control peer failure",
                Error::SharedFailure(self.cause.clone()),
            );
            let Error::SharedFailure(primary) = error else {
                panic!("real failure did not retain its primary Arc");
            };
            assert!(std::ptr::eq(primary.primary(), self.cause.primary()));
            assert!(self.published.lock().unwrap().replace(primary).is_none());
        }
    }
    struct WaitExecutor {
        status: ExitStatus,
        parked: reverie::ParkedSignalFailureContext,
        fail: Option<FailurePublication>,
        wrapped: usize,
    }
    impl GuestSyscallExecutor<LowerTool> for WaitExecutor {
        fn read_clock(&self) -> Result<u64> {
            panic!("terminal wait requested a guest clock")
        }
        fn execute(&mut self, request: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
            assert_eq!(request.number(), libc::SYS_waitid as u64);
            if let Some(failure) = self.fail.take() {
                failure.publish();
            }
            Err(Error::ChildWaitGroupExit {
                status: self.status,
            })
        }
        fn signal_failure_context(&self) -> Option<reverie::ParkedSignalFailureContext> {
            Some(self.parked)
        }
        fn with_signal_effects(&mut self, error: Error, _: Option<i64>) -> Error {
            self.wrapped += 1;
            error
        }
        fn complete_injection<'a>(
            &'a mut self,
            _: ToolContext<'a, LowerTool>,
        ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
        where
            LowerTool: 'a,
        {
            panic!("terminal wait completed an ordinary injection")
        }
    }
    struct Dropped {
        dropped: Arc<AtomicBool>,
        failure: Option<FailurePublication>,
    }
    impl Drop for Dropped {
        fn drop(&mut self) {
            // The owned driver selects GroupExit before destroying its
            // suspended callback allocation. Publish only in that destructor.
            if let Some(failure) = self.failure.take() {
                failure.publish();
            }
            self.dropped.store(true, Ordering::Release);
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailureTiming {
        Never,
        BeforeSelection,
        DuringDrop,
    }
    for timing in [
        FailureTiming::Never,
        FailureTiming::BeforeSelection,
        FailureTiming::DuringDrop,
    ] {
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        let status = ExitStatus::Exited(37);
        let cause = Arc::new(Error::GuestClock("retained primary".to_owned()));
        let published = Arc::new(Mutex::new(None));
        let publication = || FailurePublication {
            context: crate::failure::FailureContext::new(
                run.clone(),
                Pid::from_raw(71),
                Pid::from_raw(73),
            ),
            cause: cause.clone(),
            published: published.clone(),
        };
        let mut executor = WaitExecutor {
            status,
            parked: reverie::ParkedSignalFailureContext {
                site: reverie::CallbackSignalSite {
                    process: reverie::SignalProcessId {
                        tgid: Pid::from_raw(71),
                        generation: 3,
                    },
                    tid: Pid::from_raw(72),
                    task_generation: 4,
                    callback_nonce: 5,
                    boundary_nonce: 6,
                },
                ledger_nonce: 7,
            },
            fail: (timing == FailureTiming::BeforeSelection).then(publication),
            wrapped: 0,
        };
        let mut state = ();
        let subscriptions = Subscription::none();
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let mut guest = KvmGuest::<LowerTool>::new(
            Pid::from_raw(71),
            Pid::from_raw(72),
            Arc::new(LowerTool),
            GuestMemory::new(0, STACK_CAPACITY).unwrap(),
            &[],
            // The transport mock never reads vCPU registers.
            unsafe { std::mem::zeroed() },
            &mut state,
            &mut executor,
            global.as_ref(),
            None,
            &(),
            &subscriptions,
            signal.clone(),
            starts.clone(),
            crate::bootstrap::TOOL_STACK_TOP,
            Arc::new(AtomicBool::new(false)),
        );
        let dropped = Arc::new(AtomicBool::new(false));
        let mut continued = false;
        let outcome = futures::executor::block_on(drive_handler(
            async {
                let _drop = Dropped {
                    dropped: dropped.clone(),
                    failure: (timing == FailureTiming::DuringDrop).then(publication),
                };
                let wait = SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [libc::P_PID as u64, 2, 0, libc::WEXITED as u64, 0, 0],
                )
                .into_syscall()
                .unwrap();
                let result = guest.inject(wait).await;
                continued = true;
                result
            },
            signal,
            starts,
            wait_for_failure(global.as_ref(), Some(run.subscribe())),
        ));
        drop(guest);
        assert!(!continued);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(executor.wrapped, 0);
        if timing == FailureTiming::BeforeSelection {
            assert!(matches!(outcome, HandlerOutcome::RunFailed));
        } else {
            assert!(matches!(outcome, HandlerOutcome::GroupExit(actual) if actual == status));
        }
        if timing == FailureTiming::Never {
            assert!(published.lock().unwrap().is_none());
            assert!(run.primary().is_none());
            assert!(run.complete::<()>(Ok(())).is_ok());
        } else {
            let expected = published.lock().unwrap().clone().unwrap();
            assert!(Arc::ptr_eq(&run.primary().unwrap(), &expected));
            let error = run.complete::<()>(Ok(())).unwrap_err();
            assert!(error.retains_primary(&cause));
            assert!(std::ptr::eq(error.primary(), cause.primary()));
            assert!(
                matches!(&error, Error::SharedFailure(actual) if Arc::ptr_eq(actual, &expected))
            );
            assert!(Arc::ptr_eq(&run.primary().unwrap(), &expected));
        }
    }
}
