/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// This file is included in runtime.rs to use the one real KvmGuest reborrow.

impl StaticElfSyscallExecutor<'_> {
    fn signal_injection_allowed(&self, request: &SyscallRequest) -> bool {
        if self.signal_guard == SignalGuard::DequeueNotification {
            return false;
        }
        if (self.signal_guard == SignalGuard::Observation || self.executor.has_prepared_signal())
            && (injection_can_be_nonreturning(request)
                || matches!(
                    request.number() as libc::c_long,
                    libc::SYS_fork | libc::SYS_vfork | libc::SYS_clone | libc::SYS_clone3
                ))
        {
            return false;
        }
        if request.number() == libc::SYS_rt_sigaction as u64
            && request.args()[1] != 0
            && self
                .executor
                .prepared_signal_number()
                .is_some_and(|signal| request.args()[0] == signal as u64)
        {
            return false;
        }
        self.process_context.ordinary_injection_allowed(request)
    }

    fn current_parked_site(&self) -> Option<reverie::CallbackSignalSite> {
        (self.executor.signal_dequeues_enabled()
            && matches!(
                self.process_context,
                ProcessExecutionContext::SyscallBoundary(_)
            )
            && !*self.process_completed
            && !self.executor.has_prepared_signal()
            && (self.executor.signal_controlled() || self.executor.sole_signal_receiver()))
        .then_some(self.callback_site)
        .flatten()
    }
}

impl<T: Tool> KvmGuest<'_, T> {
    async fn complete_signal_effects(
        &mut self,
        raw: Option<i64>,
    ) -> Result<Option<reverie::SignalDequeue>> {
        let mut last = None;
        if self.executor.signal_dequeue_front().is_some() {
            // Stored outside this future: cancellation during the notification
            // must retain the real copyout errno along with the removal.
            self.executor.retain_signal_effect_result(raw);
        }
        loop {
            let next = futures::future::poll_fn(|cx| self.executor.poll_signal_dequeue(cx)).await;
            let effect = match next {
                Ok(Some(effect)) => effect,
                Ok(None) => break,
                Err(error) => return Err(self.executor.with_signal_effects(error, raw)),
            };
            self.executor.retain_signal_dequeue(effect);
            let previous = self
                .executor
                .set_signal_guard(SignalGuard::DequeueNotification);
            self.notifying_dequeue = true;
            let tool = self.process_state.clone();
            let result = tool.handle_signal_dequeue(self, effect).await;
            self.notifying_dequeue = false;
            self.executor.set_signal_guard(previous);
            if let Err(errno) = result {
                return Err(self
                    .executor
                    .with_signal_effects(Error::Reverie(errno.into()), raw));
            }
            if let Err(errno) = self.executor.acknowledge_signal_dequeue(effect) {
                return Err(self
                    .executor
                    .with_signal_effects(Error::Reverie(errno.into()), raw));
            }
            last = Some(effect);
        }
        Ok(last)
    }

    async fn observe_parked_signal_impl(
        &mut self,
        site: reverie::CallbackSignalSite,
        lease: reverie::ParkedObservationLease,
    ) -> std::result::Result<reverie::ParkedSignalObservation, reverie::SignalObservationFailure>
    {
        use reverie::SignalObservationFailure as Failure;
        use reverie::SignalObservationStep as Step;
        use reverie::SignalObservationStop as Stop;
        if self.executor.parked_signal_site() != Some(site)
            || self.observation_lease.is_some()
            || self.notifying_dequeue
            || self.stack_checked_out.load(Ordering::Acquire)
        {
            return Err(Failure::RejectedBeforeRemoval {
                errno: Errno::ENOSYS,
            });
        }
        let mut steps = Vec::new();
        steps
            .try_reserve_exact(64)
            .map_err(|_| Failure::RejectedBeforeRemoval {
                errno: Errno::ENOMEM,
            })?;
        self.executor
            .admit_signal_observation(site, lease)
            .map_err(|errno| Failure::RejectedBeforeRemoval { errno })?;
        self.observation_lease = Some(lease);
        let previous = self.executor.set_signal_guard(SignalGuard::Observation);
        let result: Result<reverie::ParkedSignalObservation> = async {
            for _ in 0..64 {
                self.resume_ordinary_operation(None).await;
                let pending = self.executor.take_signal_for_observation();
                // Even readiness failure after removal must flush before propagating.
                let effect = self.complete_signal_effects(None).await?;
                let pending = pending.map_err(|errno| Error::Reverie(errno.into()))?;
                self.resume_ordinary_operation(None).await;
                let Some(pending) = pending else {
                    return Ok(reverie::ParkedSignalObservation {
                        steps,
                        stop: Stop::NoEligibleSignal,
                    });
                };
                let effect = effect.ok_or_else(|| {
                    Error::UnexpectedVcpuExit(
                        "parked removal had no dequeue journal entry".to_owned(),
                    )
                })?;
                if effect.event != pending.event
                    || effect.domain
                        != match pending.domain {
                            crate::executor::PendingSignalDomain::Thread => {
                                reverie::PendingDomain::Thread
                            }
                            crate::executor::PendingSignalDomain::Process => {
                                reverie::PendingDomain::Process
                            }
                        }
                    || effect.consumer != reverie::SignalConsumer::ReturnToUser
                {
                    return Err(Error::UnexpectedVcpuExit(
                        "parked dequeue identity did not match selected event".to_owned(),
                    ));
                }
                let id = effect.id();
                let tool = self.process_state.clone();
                let replacement = tool
                    .handle_structured_signal_event(self, pending.event)
                    .await
                    .map_err(|errno| Error::Reverie(errno.into()))?;
                // A nested hook may catch a fatal MemoryAccess errno and
                // complete within this same poll. No further removal or
                // delivery reservation may follow that private failure.
                self.resume_ordinary_operation(None).await;
                let Some(event) = replacement else {
                    steps.push(Step::Suppressed { dequeue: id });
                    continue;
                };
                let selected = self
                    .executor
                    .filter_signal_replacement(event, pending.domain)
                    .map_err(|errno| Error::Reverie(errno.into()))?;
                let Some(selected) = selected else {
                    steps.push(Step::Reblocked {
                        dequeue: id,
                        domain: effect.domain,
                    });
                    continue;
                };
                let fatal = match self.executor.signal_disposition(selected.event.signal()) {
                    crate::executor::SignalDisposition::Ignore => {
                        steps.push(Step::Ignored { dequeue: id });
                        continue;
                    }
                    crate::executor::SignalDisposition::Handled => false,
                    crate::executor::SignalDisposition::Terminate => true,
                    crate::executor::SignalDisposition::Stop => {
                        return Err(Error::Reverie(Errno::ENOSYS.into()));
                    }
                };
                let selection = self
                    .executor
                    .reserve_signal_delivery(selected, id, fatal)
                    .map_err(|errno| Error::Reverie(errno.into()))?;
                steps.push(if fatal {
                    Step::Fatal { dequeue: id }
                } else {
                    Step::Caught { dequeue: id }
                });
                return Ok(reverie::ParkedSignalObservation {
                    steps,
                    stop: if fatal {
                        Stop::Fatal(selection)
                    } else {
                        Stop::Caught(selection)
                    },
                });
            }
            Err(Error::UnexpectedVcpuExit(
                "parked signal observation exhausted 64 actual selections".to_owned(),
            ))
        }
        .await;
        self.executor.set_signal_guard(previous);
        self.observation_lease = None;
        match result {
            Ok(observation) => {
                if self.executor.signal_controlled()
                    && matches!(
                        observation.stop,
                        reverie::SignalObservationStop::NoEligibleSignal
                    )
                {
                    // Every removal was acknowledged and there is no prepared
                    // frame. End this observation's effect ownership before
                    // reenrolling the original wait; a long ignored interval
                    // must not accumulate one ledger across all expirations.
                    self.executor.finish_parked_delivery();
                }
                Ok(observation)
            }
            Err(error) => {
                // Dropping the outer future cannot erase acknowledged removals.
                let error = self.executor.with_signal_effects(error, None);
                self.signal_handler(HandlerSignal::RuntimeError(error));
                std::future::pending().await
            }
        }
    }
}

// Give an already-ready consuming cleanup its result even after failure. A
// blocked FIFO predecessor or notification must still observe run termination.
// This is deliberately different from ordinary callbacks, where failure wins
// before the callback is polled. No cancellation acknowledges a removal.
async fn drive_signal_cleanup<T>(
    future: impl Future<Output = T>,
    handler_signal: SharedHandlerSignal,
    pending_children: SharedChildStarts,
    failure: impl Future<Output = ()>,
) -> crate::failure::owned_future::CaughtFuture<HandlerOutcome<T>> {
    // Cancellation is selected by the owning driver, so it still catches
    // destruction of the actual callback allocation before returning. Dropping
    // a pending nested driver would bypass that completion protocol.
    drive_handler_completion_inner(
        future,
        handler_signal,
        pending_children,
        failure,
        None,
        HandlerFailureOrder::AfterReadyCleanup,
    )
    .await
}

/// Signal-dequeue notifications cannot create a child: the guest is under
/// `SignalGuard::DequeueNotification`, and `signal_injection_allowed` rejects
/// every injected syscall before `complete_injection` can publish a fork or
/// thread start. The lifecycle process context independently rejects fork and
/// clone actions before they can spawn. Keep that production invariant
/// explicit. Detect and recover it here without joining: `CancelAfterFailure`
/// is a terminal command, so the finalized parent error must be published
/// before any child receives it.
fn signal_cleanup_child_start_violation(pending_children: &SharedChildStarts) -> Option<Error> {
    let poisoned = pending_children.is_poisoned();
    let has_children = !pending_children
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_empty();
    if poisoned {
        // The completion driver already caught the panic that poisoned this
        // lock. Recovery must not replace or obscure that owned payload.
        pending_children.clear_poison();
    }
    if !has_children && !poisoned {
        return None;
    }
    Some(Error::UnexpectedVcpuExit(
        match (has_children, poisoned) {
            (true, true) => {
                "signal dequeue notification created a child start and poisoned its child-start state"
            }
            (true, false) => {
                "signal dequeue notification created a child start despite its injection guard"
            }
            (false, true) => "signal dequeue notification poisoned its child-start state",
            (false, false) => unreachable!(),
        }
        .to_owned(),
    ))
}

fn finish_signal_cleanup<T>(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    completion: crate::failure::owned_future::CaughtFuture<HandlerOutcome<Result<T>>>,
    pending_children: &SharedChildStarts,
    raw: Option<i64>,
) -> Result<()> {
    let violation = signal_cleanup_child_start_violation(pending_children);
    let outcome = backend.finish_handler_completion(completion, Ok(()), std::convert::identity);
    let result = match outcome {
        Err(error) => Err(error),
        Ok(HandlerOutcome::Returned(result)) => result.map(|_| ()),
        Ok(HandlerOutcome::RuntimeError(error)) => Err(error),
        Ok(HandlerOutcome::ParkedCancelled(_)) | Ok(HandlerOutcome::RunFailed) => {
            Err(Error::RunAborted)
        }
        Ok(_) => Err(Error::UnexpectedVcpuExit(
            "nonlocal operation during dequeue acknowledgment".to_owned(),
        )),
    };
    let Some(violation) = violation else {
        return result.map_err(|error| executor.with_signal_effects(error, raw));
    };

    // A real selected error or panic remains primary. A derived RunAborted
    // cannot publish a terminal transition, so promote the invariant failure
    // ahead of it. Attach the signal ledger/raw errno exactly once and before
    // publication.
    let error = match result {
        Ok(()) => violation,
        Err(error) if matches!(error.primary(), Error::RunAborted) => {
            violation.with_cleanup(vec![error])
        }
        Err(error) => error.with_cleanup(vec![violation]),
    };
    let error = executor.with_signal_effects(error, raw);
    let error = backend.report_tool_failure("Tool callback", error);
    let error =
        match backend.settle_unstarted_tool_children_after_failure(executor, pending_children) {
            Ok(()) => error,
            Err(cleanup) => error.with_cleanup(vec![
                cleanup.cleanup("signal-cleanup child retirement failed"),
            ]),
        };
    Err(error)
}

#[allow(clippy::too_many_arguments)]
async fn flush_pending_signal_effects_with_tool<T>(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    pid: Pid,
    tid: Pid,
    tool: &Arc<T>,
    memory: &GuestMemory,
    auxv: &[(libc::c_ulong, libc::c_ulong)],
    registers: libc::user_regs_struct,
    thread_state: &mut T::ThreadState,
    global_state: &Arc<T::GlobalState>,
    config: &<T::GlobalState as GlobalTool>::Config,
    subscriptions: &Subscription,
    stack_checked_out: &Arc<AtomicBool>,
    raw: Option<i64>,
) -> Result<()>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    if executor.signal_dequeue_front().is_none() && executor.signal_dequeue_failure().is_none() {
        return Ok(());
    }
    let failure = backend.failure_subscription(executor.is_traced_tree_root());
    let handler_signal = Arc::new(Mutex::new(None));
    let pending_children = Arc::new(Mutex::new(Vec::new()));
    let pending_children_after_cleanup = pending_children.clone();
    let mut process_completed = false;
    let tool_stack_top = backend.tool_stack_top();
    let continuation_site = executor
        .signal_failure_context()
        .map(|context| context.site);
    let outcome = {
        let mut adapter = StaticElfSyscallExecutor {
            backend,
            executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::Lifecycle,
            last_result: raw,
            polled_read_attempt: None,
            process_completed: &mut process_completed,
            callback_site: continuation_site,
            original_syscall: None,
            signal_guard: SignalGuard::Ordinary,
        };
        let mut guest = KvmGuest::new(
            pid,
            tid,
            tool.clone(),
            memory.clone(),
            auxv,
            registers,
            thread_state,
            &mut adapter,
            global_state.as_ref(),
            Some(global_state.clone()),
            config,
            subscriptions,
            handler_signal.clone(),
            pending_children.clone(),
            tool_stack_top,
            stack_checked_out.clone(),
        );
        // Consuming cleanup must flush even when the run has already failed.
        drive_signal_cleanup(
            guest.complete_signal_effects(raw),
            handler_signal,
            pending_children,
            wait_for_failure(global_state.as_ref(), failure),
        )
        .await
    };
    finish_signal_cleanup(
        backend,
        executor,
        outcome,
        &pending_children_after_cleanup,
        raw,
    )
}

#[cfg(test)]
mod signal_cleanup_tests {
    use std::task::Context;

    use futures::task::noop_waker;

    use super::*;

    #[test]
    fn signal_cleanup_pending_callback_observes_published_peer_failure() {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let polled = Arc::new(AtomicBool::new(false));
        let pending = polled.clone();
        let future = futures::future::poll_fn(move |_| {
            pending.store(true, Ordering::Release);
            Poll::<Result<()>>::Pending
        });
        let mut cleanup = pin!(drive_signal_cleanup(
            future,
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(Vec::new())),
            wait_for_failure(global.as_ref(), Some(run.subscribe())),
        ));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(cleanup.as_mut().poll(&mut cx).is_pending());
        assert!(polled.load(Ordering::Acquire));
        context.publish("lost dequeue owner", Error::GuestWorkerPanic);
        let Poll::Ready(completion) = cleanup.as_mut().poll(&mut cx) else {
            panic!("a published lost owner must terminate consuming cleanup, not leave it parked");
        };
        assert!(matches!(completion.output, Some(HandlerOutcome::RunFailed)));
        assert!(completion.panics.is_empty());
        assert!(matches!(
            run.primary().unwrap().primary(),
            Error::GuestWorkerPanic
        ));
    }

    #[test]
    fn signal_cleanup_ready_result_precedes_terminal_cancellation() {
        for result in [Ok(()), Err(Error::Reverie(Errno::EFAULT.into()))] {
            let was_error = result.is_err();
            let outcome = futures::executor::block_on(drive_signal_cleanup(
                std::future::ready(result),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(Vec::new())),
                std::future::ready(()),
            ));
            assert!(outcome.panics.is_empty());
            match outcome.output {
                Some(HandlerOutcome::Returned(result)) => {
                    assert_eq!(result.is_err(), was_error);
                    if was_error {
                        assert!(
                            matches!(result, Err(Error::Reverie(reverie::Error::Errno(errno))) if errno == Errno::EFAULT)
                        );
                    } else {
                        assert!(matches!(result, Ok(())));
                    }
                }
                _ => panic!("already-ready cleanup/result was discarded"),
            }
        }
    }
    #[test]
    fn signal_bookkeeping_failure_cannot_resume_injected_or_unsubscribed_syscall() {
        for signalfd in [false, true] {
            for injected in [false, true] {
                let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
                let state = crate::executor::native_loaded_state(std::path::Path::new("."));
                state.process_signals.lock().unwrap().dequeue_sequence = u64::MAX;
                let mut executor = ElfExecutor::new(state, false);
                let mut memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
                memory
                    .write(0x80, &(1_u64 << (libc::SIGALRM - 1)).to_ne_bytes())
                    .unwrap();
                let fd = executor.execute(
                    &SyscallRequest::new(
                        libc::SYS_signalfd4 as u64,
                        [u64::MAX, 0x80, 8, libc::SFD_NONBLOCK as u64, 0, 0],
                    ),
                    &memory,
                );
                assert!(fd >= 0);
                executor.enable_signal_dequeues();
                let pid = Pid::from_raw(1);
                let mut info = [0; reverie::SIGNAL_INFO_SIZE];
                info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
                info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
                let event =
                    SignalEvent::new(libc::SIGALRM, info, reverie::SignalTarget::Process { pid })
                        .unwrap();
                assert!(matches!(
                    executor.queue_process_alarm_signal(event),
                    reverie::ProcessAlarmSignalOutcome::Accepted(_)
                ));
                let request = if signalfd {
                    SyscallRequest::new(libc::SYS_read as u64, [fd as u64, 0x100, 128, 0, 0, 0])
                } else {
                    SyscallRequest::new(libc::SYS_rt_sigtimedwait as u64, [0x80, 0x100, 0, 8, 0, 0])
                };
                let tool = Arc::new(crate::StraceTool);
                let global = Arc::new(crate::StraceLog::default());
                let mut state = ();
                let subscriptions = Subscription::none();
                let stack = Arc::new(AtomicBool::new(false));
                // No instruction executes in this initialized VM control.
                let registers = unsafe { std::mem::zeroed() };
                let error = if injected {
                    let signal = Arc::new(Mutex::new(None));
                    let starts = Arc::new(Mutex::new(Vec::new()));
                    let mut completed = false;
                    let top = backend.tool_stack_top();
                    let mut adapter = StaticElfSyscallExecutor {
                        backend: &mut backend,
                        executor: &mut executor,
                        memory: memory.clone(),
                        process_context: ProcessExecutionContext::Lifecycle,
                        last_result: None,
                        polled_read_attempt: None,
                        process_completed: &mut completed,
                        callback_site: None,
                        original_syscall: None,
                        signal_guard: SignalGuard::Ordinary,
                    };
                    let mut guest = KvmGuest::new(
                        pid,
                        pid,
                        tool.clone(),
                        memory.clone(),
                        &[],
                        registers,
                        &mut state,
                        &mut adapter,
                        global.as_ref(),
                        Some(global.clone()),
                        &(),
                        &subscriptions,
                        signal.clone(),
                        starts.clone(),
                        top,
                        stack.clone(),
                    );
                    match futures::executor::block_on(drive_handler(
                        guest.inject(request.into_syscall().unwrap()),
                        signal,
                        starts,
                        std::future::pending(),
                    )) {
                        HandlerOutcome::RuntimeError(error) => error,
                        _ => panic!("bookkeeping failure resumed the injecting Tool"),
                    }
                } else {
                    let raw = executor.execute(&request, &memory);
                    assert_eq!(raw, -i64::from(libc::EOVERFLOW));
                    futures::executor::block_on(flush_pending_signal_effects_with_tool(
                        &mut backend,
                        &mut executor,
                        pid,
                        pid,
                        &tool,
                        &memory,
                        &[],
                        registers,
                        &mut state,
                        &global,
                        &(),
                        &subscriptions,
                        &stack,
                        Some(raw),
                    ))
                    .expect_err("unsubscribed syscall cannot publish a bookkeeping errno")
                };
                assert!(
                    matches!(error.primary(), Error::Reverie(reverie::Error::Errno(errno))
                    if *errno == Errno::EOVERFLOW)
                );
                assert!(executor.has_eligible_pending_signal());
                assert!(executor.signal_dequeue_front().is_none());
            }
        }
    }
    #[test]
    fn signal_cleanup_real_fifo_wait_retains_only_waiting_owner_after_failure() {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        let mut first = ElfExecutor::new(
            crate::executor::native_loaded_state(std::path::Path::new(".")),
            false,
        );
        first.enable_signal_dequeues();
        let mut second = first.thread_child(2).unwrap();
        second.enable_signal_dequeues();
        for (executor, tid) in [(&mut first, 1), (&mut second, 2)] {
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
            let event = SignalEvent::new(
                libc::SIGUSR1,
                info,
                reverie::SignalTarget::Thread {
                    pid: Pid::from_raw(1),
                    tid: Pid::from_raw(tid),
                },
            )
            .unwrap();
            executor.defer_signal_delivery(event).unwrap();
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap();
        }
        let first_effect = first.signal_dequeue_front().unwrap();
        let second_effect = second.signal_dequeue_front().unwrap();
        assert_eq!((first_effect.sequence, second_effect.sequence), (1, 2));
        let global = Arc::new(crate::StraceLog::default());
        let failure = RunFailure::new(&global);
        let context = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(1));
        backend.tool_failure = Some(context.for_thread(Pid::from_raw(2)));
        let tool = Arc::new(crate::StraceTool);
        let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
        let stack = Arc::new(AtomicBool::new(false));
        let subscriptions = Subscription::none();
        let mut state = ();
        let error = {
            let mut cleanup = pin!(flush_pending_signal_effects_with_tool(
                &mut backend,
                &mut second,
                Pid::from_raw(1),
                Pid::from_raw(2),
                &tool,
                &memory,
                &[],
                unsafe { std::mem::zeroed() },
                &mut state,
                &global,
                &(),
                &subscriptions,
                &stack,
                Some(-i64::from(libc::EFAULT)),
            ));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(
                cleanup.as_mut().poll(&mut cx).is_pending(),
                "actual second owner must wait for the real FIFO predecessor"
            );
            context.publish("failed FIFO predecessor", Error::GuestWorkerPanic);
            match cleanup.as_mut().poll(&mut cx) {
                Poll::Ready(Err(error)) => error,
                _ => panic!("actual flush did not terminate after peer failure"),
            }
        };
        assert!(matches!(&error, Error::SignalEffects {
            dequeues, acknowledged_through: 0, raw_result: Some(raw), ..
        } if dequeues == &[second_effect] && *raw == -i64::from(libc::EFAULT)));
        assert_eq!(
            first.signal_dequeue_front(),
            Some(first_effect),
            "the waiter must not steal or acknowledge the failed owner's entry"
        );
        assert!(second.signal_dequeue_front().is_none());
        let completed = failure.complete::<()>(Err(error)).unwrap_err();
        assert!(matches!(completed.primary(), Error::GuestWorkerPanic));
    }
    #[test]
    fn signal_cleanup_terminal_race_keeps_error_already_transferred_by_callback() {
        let global = Arc::new(());
        let failure = RunFailure::new(&global);
        let context = FailureContext::new(failure.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = std::sync::mpsc::channel();
        starts.lock().unwrap().push(PendingChildStart::tool_thread(
            3,
            ChildStartGate::new(sender),
        ));
        let transferred = Arc::new(Error::SignalEffects {
            cause: Arc::new(Error::RunAborted),
            dequeues: Vec::new(),
            acknowledged_through: 17,
            publications: Vec::new(),
            raw_result: Some(-14),
            context: None,
        });
        let callback_error = transferred.clone();
        let callback_signal = signal.clone();
        let callback = async {
            *callback_signal.lock().unwrap() = Some(HandlerSignal::RuntimeError(
                Error::SharedFailure(callback_error),
            ));
            context.publish("failure during callback poll", Error::GuestWorkerPanic);
            123
        };
        let outcome = futures::executor::block_on(drive_handler(
            callback,
            signal,
            starts.clone(),
            wait_for_failure(global.as_ref(), Some(failure.subscribe())),
        ));
        let error = match outcome {
            HandlerOutcome::RuntimeError(Error::SharedFailure(error)) => {
                assert!(Arc::ptr_eq(&error, &transferred));
                Error::SharedFailure(error)
            }
            _ => panic!("terminal notification discarded already-transferred effects"),
        };
        assert!(
            matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "failure must not release an ordinary child-start gate"
        );
        assert!(matches!(
            starts.lock().unwrap().pop().unwrap().cancel(),
            PendingChildCancellation::NewlyCancelled { .. }
        ));
        assert_eq!(receiver.recv().unwrap(), ChildStartCommand::Cancel);
        let completed = failure.complete::<()>(Err(error)).unwrap_err();
        assert!(matches!(completed.primary(), Error::GuestWorkerPanic));
        let Error::WithCleanup { cleanup, .. } = completed else {
            panic!("effects lost")
        };
        assert_eq!(cleanup.len(), 1);
        assert!(matches!(cleanup[0].as_ref(), Error::SharedFailure(error)
            if Arc::ptr_eq(error, &transferred)));
    }
}
