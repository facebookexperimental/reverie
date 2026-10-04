/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Actual executor consumers and their post-removal error paths.
#[test]
fn signal_dequeue_all_consumers_preserve_domain_and_post_copyout_effects() {
    use reverie::PendingDomain;
    use reverie::SignalConsumer;
    let root = TestDir::new();
    for consumer in [
        SignalConsumer::ReturnToUser,
        SignalConsumer::SignalFd,
        SignalConsumer::SignalTimedWait,
    ] {
        for domain in [PendingDomain::Thread, PendingDomain::Process] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            executor.enable_signal_dequeues();
            executor.observe_ignored_signals_with_tool();
            let identity = executor.signal_task_identity().unwrap();
            let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
            let fd = process_alarm_signalfd(&mut executor, &mut memory);
            let event = process_alarm_event(executor.state.pid);
            if domain == PendingDomain::Thread {
                executor.defer_signal_delivery(event).unwrap();
            } else {
                assert!(matches!(
                    executor.queue_process_alarm_signal(event),
                    reverie::ProcessAlarmSignalOutcome::Accepted(_)
                ));
            }
            match consumer {
                SignalConsumer::ReturnToUser => assert_eq!(
                    executor
                        .take_pending_signal_for_delivery()
                        .unwrap()
                        .unwrap()
                        .event,
                    event
                ),
                SignalConsumer::SignalFd => assert_eq!(
                    signalfd_read(
                        &mut memory,
                        &mut executor.state,
                        fd,
                        PAGE_SIZE - 1,
                        SIGNALFD_RECORD_SIZE
                    ),
                    Some(negative_errno(libc::EFAULT))
                ),
                SignalConsumer::SignalTimedWait => assert_eq!(
                    rt_sigtimedwait(
                        &mut memory,
                        &mut executor.state,
                        &[0x80, PAGE_SIZE - 1, 0, 8, 0, 0]
                    ),
                    negative_errno(libc::EFAULT)
                ),
            }
            let effect = executor.signal_dequeue_front().unwrap();
            assert_eq!(
                effect,
                reverie::SignalDequeue {
                    process: identity.process,
                    sequence: 1,
                    consumer,
                    domain,
                    event
                }
            );
            assert!(!executor.has_eligible_pending_signal());
            let mut conflicting = effect;
            conflicting.event =
                event_for_thread(libc::SIGUSR1, executor.state.pid, executor.state.tid).unwrap();
            assert_eq!(
                executor.acknowledge_signal_dequeue(conflicting),
                Err(reverie::syscalls::Errno::EINVAL)
            );
            assert_eq!(executor.signal_dequeue_front(), Some(effect));
            executor.acknowledge_signal_dequeue(effect).unwrap();
            executor.acknowledge_signal_dequeue(effect).unwrap();
            assert_eq!(executor.signal_dequeue_front(), None);
            assert_eq!(
                executor
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .dequeue_sequence,
                1
            );
        }
    }
}

#[test]
fn signal_dequeue_readiness_error_retains_complete_removal() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = process_alarm_signalfd(&mut executor, &mut memory);
    let event = process_alarm_event(executor.state.pid);
    assert!(matches!(
        executor.queue_process_alarm_signal(event),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    // Delivery refreshes process-owned carriers independently of the guest
    // descriptor table. Fail the actual readiness read after removal commits.
    let broken_carrier = crate::signal::SignalFdCarrier::pin_eventfd(
        &std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap(),
    )
    .unwrap();
    assert!(
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .insert(fd, broken_carrier)
            .is_some(),
        "the negative control must replace the installed readiness carrier"
    );
    assert_eq!(
        executor.take_pending_signal_for_delivery(),
        Err(reverie::syscalls::Errno::EBADF)
    );
    let effect = executor.signal_dequeue_front().unwrap();
    assert_eq!(effect.event, event);
    assert_eq!(effect.domain, reverie::PendingDomain::Process);
    assert!(!executor.has_eligible_pending_signal());
}

#[test]
fn signal_dequeue_sequence_exhaustion_refuses_before_removal() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let event = process_alarm_event(executor.state.pid);
    assert!(matches!(
        executor.queue_process_alarm_signal(event),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    executor
        .state
        .process_signals
        .lock()
        .unwrap()
        .dequeue_sequence = u64::MAX;
    let before = process_alarm_snapshot(&executor);
    assert_eq!(
        executor.take_pending_signal_for_delivery(),
        Err(reverie::syscalls::Errno::EOVERFLOW)
    );
    assert_eq!(process_alarm_snapshot(&executor), before);
    assert_eq!(executor.signal_dequeue_front(), None);
}

#[test]
fn signal_dequeue_fork_resets_and_exec_retains_process_sequence() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let event = process_alarm_event(executor.state.pid);
    assert!(matches!(
        executor.queue_process_alarm_signal(event),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    executor
        .take_pending_signal_for_delivery()
        .unwrap()
        .unwrap();
    let effect = executor.signal_dequeue_front().unwrap();
    executor.acknowledge_signal_dequeue(effect).unwrap();
    let process = executor.state.process_signals.lock().unwrap();
    let fork = process.for_fork();
    let exec = process.after_exec();
    assert!(fork.dequeue_enabled && exec.dequeue_enabled);
    assert_eq!(fork.dequeue_sequence, 0);
    assert!(fork.dequeue_journal.is_empty());
    assert_eq!(fork.dequeue_acknowledged, None);
    assert_eq!(exec.dequeue_sequence, 1);
    assert!(exec.dequeue_journal.is_empty());
    assert_eq!(exec.dequeue_acknowledged, Some(effect));
}

#[test]
fn signal_dequeue_reused_task_refuses_before_all_three_removals() {
    use reverie::SignalConsumer;
    let root = TestDir::new();
    for consumer in [
        SignalConsumer::ReturnToUser,
        SignalConsumer::SignalFd,
        SignalConsumer::SignalTimedWait,
    ] {
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        executor.enable_signal_dequeues();
        let original = executor.signal_task_identity().unwrap();
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let fd = process_alarm_signalfd(&mut executor, &mut memory);
        let event = process_alarm_event(executor.state.pid);
        assert!(matches!(
            executor.queue_process_alarm_signal(event),
            reverie::ProcessAlarmSignalOutcome::Accepted(_)
        ));
        {
            let mut lifecycle = executor.state.task_lifecycle.lock().unwrap();
            lifecycle.remove(executor.state.tid, executor.task_generation);
            let generation = lifecycle.register(
                executor.state.tid,
                executor.state.pid,
                executor.state.pgid,
                true,
            );
            assert_ne!(generation, original.task_generation);
        }
        assert!(executor.signal_task_identity().is_none());
        let before = process_alarm_snapshot(&executor);
        let raw = match consumer {
            SignalConsumer::ReturnToUser => executor
                .take_pending_signal_for_delivery()
                .map(|pending| i64::from(pending.is_some()))
                .unwrap_or_else(|errno| -(i64::from(errno.into_raw()))),
            SignalConsumer::SignalFd => signalfd_read(
                &mut memory,
                &mut executor.state,
                fd,
                0x100,
                SIGNALFD_RECORD_SIZE,
            )
            .unwrap(),
            SignalConsumer::SignalTimedWait => {
                rt_sigtimedwait(&mut memory, &mut executor.state, &[0x80, 0x100, 0, 8, 0, 0])
            }
        };
        assert_eq!(
            raw,
            negative_errno(libc::ESRCH),
            "stale {consumer:?} cannot observe a replacement lifetime"
        );
        assert_eq!(process_alarm_snapshot(&executor), before);
        // The raw helper's private error code above must not resume either the
        // Tool or guest. The production completion path polls this typed error.
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(matches!(executor.poll_signal_dequeue(&mut cx),
            std::task::Poll::Ready(Err(crate::Error::Reverie(reverie::Error::Errno(errno))))
                if errno == reverie::syscalls::Errno::ESRCH));
    }
}

#[test]
fn signal_dequeue_first_private_nonalarm_is_bound_before_any_parked_call() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let identity = executor.signal_task_identity().unwrap();
    let event = event_for_thread(libc::SIGUSR1, executor.state.pid, executor.state.tid).unwrap();
    executor.defer_signal_delivery(event).unwrap();
    assert_eq!(
        executor
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap()
            .event,
        event
    );
    assert_eq!(
        executor.signal_dequeue_front(),
        Some(reverie::SignalDequeue {
            process: identity.process,
            sequence: 1,
            consumer: reverie::SignalConsumer::ReturnToUser,
            domain: reverie::PendingDomain::Thread,
            event,
        })
    );
    let thread = executor.state.thread_signals.lock();
    assert_eq!(thread.dequeue_identity, Some(identity));
    assert_eq!(thread.after_exec().dequeue_identity, Some(identity));
    assert_eq!(thread.for_fork().dequeue_identity, None);
    assert_eq!(thread.for_clone_thread().dequeue_identity, None);
}

#[test]
fn parked_handles_reject_equal_ordinals_across_fork_and_stale_callbacks() {
    fn prepare(executor: &mut ElfExecutor) -> reverie::PreparedSignalToken {
        executor.enable_signal_dequeues();
        let site = executor.begin_signal_callback().unwrap();
        executor.retain_parked_effects(site).unwrap();
        let event = process_alarm_event(executor.state.pid);
        assert!(matches!(
            executor.queue_process_alarm_signal(event),
            reverie::ProcessAlarmSignalOutcome::Accepted(_)
        ));
        let pending = executor
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap();
        let effect = executor.signal_dequeue_front().unwrap();
        executor.retain_signal_dequeue(effect);
        executor.acknowledge_signal_dequeue(effect).unwrap();
        executor
            .reserve_signal_delivery(pending, effect.id(), true)
            .unwrap()
    }
    let root = TestDir::new();
    let mut parent = ElfExecutor::new(test_state(&root.0), false);
    let mut child = parent.fork_child(3, false, false).unwrap();
    let parent_token = prepare(&mut parent);
    let child_token = prepare(&mut child);
    assert_ne!(
        parent_token, child_token,
        "equal local ordinals are not equal lifetime handles"
    );
    assert_ne!(
        parent.signal_failure_context(),
        child.signal_failure_context()
    );
    assert!(!child.prepared_signal_is_fatal(parent_token));
    assert!(!parent.prepared_signal_is_fatal(child_token));
    assert!(parent.prepared_signal_is_fatal(parent_token));
    assert!(child.prepared_signal_is_fatal(child_token));
    let parent_context = parent.signal_failure_context().unwrap();
    let child_context = child.signal_failure_context().unwrap();
    assert!(!child.signal_failure_context_is_current(parent_context));
    assert!(!parent.signal_failure_context_is_current(child_context));
    assert!(parent.signal_failure_context_is_current(parent_context));
    assert!(child.signal_failure_context_is_current(child_context));
    let mut current = parent.fork_child(4, false, false).unwrap();
    let current_token = prepare(&mut current);
    assert!(current.prepared_signal_is_fatal(current_token));
    assert!(current.take_prepared_signal().unwrap().is_some());
    assert!(current.take_prepared_signal().unwrap().is_none());
    assert!(!current.prepared_signal_is_fatal(current_token));
    child.begin_signal_callback().unwrap();
    assert!(
        !child.prepared_signal_is_fatal(child_token),
        "next callback invalidates old handle"
    );
    assert!(!child.signal_failure_context_is_current(child_context));
    let child_ledger = child.parked_signals.clone();
    assert_eq!(
        child.take_prepared_signal(),
        Err(reverie::syscalls::Errno::EINVAL)
    );
    assert_eq!(child.parked_signals, child_ledger);
    {
        let mut lifecycle = parent.state.task_lifecycle.lock().unwrap();
        lifecycle.remove(parent.state.tid, parent.task_generation);
        let replacement =
            lifecycle.register(parent.state.tid, parent.state.pid, parent.state.pgid, true);
        assert_ne!(replacement, parent.task_generation);
    }
    assert!(
        !parent.prepared_signal_is_fatal(parent_token),
        "reused TID cannot consume the old reservation"
    );
    assert!(!parent.signal_failure_context_is_current(parent_context));
    let ledger = parent.parked_signals.clone();
    assert_eq!(
        parent.take_prepared_signal(),
        Err(reverie::syscalls::Errno::EINVAL)
    );
    assert_eq!(parent.parked_signals, ledger);
}

#[test]
fn parked_observation_lease_replay_preserves_pending_sequence_ack_and_ledger() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let site = executor.begin_signal_callback().unwrap();
    let lease = reverie::ParkedObservationLease { nonce: 7 };
    executor.admit_signal_observation(site, lease).unwrap();
    let event = process_alarm_event(executor.state.pid);
    for sequence in 1..=2 {
        assert!(matches!(
            executor.queue_process_alarm_signal(event),
            reverie::ProcessAlarmSignalOutcome::Accepted(_)
        ));
        if sequence == 2 {
            let pending = process_alarm_snapshot(&executor);
            let ledger = executor.parked_signals.clone();
            assert_eq!(
                executor.admit_signal_observation(site, lease),
                Err(reverie::syscalls::Errno::EINVAL)
            );
            assert_eq!(process_alarm_snapshot(&executor), pending);
            assert_eq!(executor.parked_signals, ledger);
            // Uniqueness, not numeric ordering, is the contract.
            executor
                .admit_signal_observation(site, reverie::ParkedObservationLease { nonce: 3 })
                .unwrap();
        }
        assert_eq!(
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap()
                .event,
            event
        );
        let effect = executor.signal_dequeue_front().unwrap();
        assert_eq!(effect.sequence, sequence);
        executor.retain_signal_dequeue(effect);
        executor.acknowledge_signal_dequeue(effect).unwrap();
        executor.mark_signal_dequeue_acknowledged(sequence);
    }
    assert_eq!(executor.parked_signals.as_ref().unwrap().acknowledged, 2);
    assert_eq!(executor.parked_signals.as_ref().unwrap().effects.len(), 2);
}

#[test]
fn signal_dequeue_sibling_cannot_flush_or_ack_another_owner() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    leader.enable_signal_dequeues();
    let sibling = leader.thread_child(7).unwrap();
    sibling.enable_signal_dequeues();
    let event = event_for_thread(libc::SIGUSR1, leader.state.pid, leader.state.tid).unwrap();
    leader.defer_signal_delivery(event).unwrap();
    leader.take_pending_signal_for_delivery().unwrap().unwrap();
    let effect = leader.signal_dequeue_front().unwrap();
    assert_eq!(
        sibling.signal_dequeue_front(),
        None,
        "the sibling owns no removal"
    );
    assert_eq!(
        sibling.acknowledge_signal_dequeue(effect),
        Err(reverie::syscalls::Errno::EINVAL)
    );
    leader.acknowledge_signal_dequeue(effect).unwrap();
    assert_eq!(
        sibling.acknowledge_signal_dequeue(effect),
        Err(reverie::syscalls::Errno::EINVAL)
    );
}

#[test]
fn signal_dequeue_owner_waits_for_contiguous_ack_and_keeps_sibling_failure_effects() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Context;
    use std::task::Poll;

    use futures::task::ArcWake;
    use futures::task::waker;
    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    for fail in [false, true] {
        let root = TestDir::new();
        let mut leader = ElfExecutor::new(test_state(&root.0), false);
        leader.enable_signal_dequeues();
        let mut sibling = leader.thread_child(7).unwrap();
        sibling.enable_signal_dequeues();
        for executor in [&mut leader, &mut sibling] {
            let event =
                event_for_thread(libc::SIGUSR1, executor.state.pid, executor.state.tid).unwrap();
            executor.defer_signal_delivery(event).unwrap();
            executor
                .take_pending_signal_for_delivery()
                .unwrap()
                .unwrap();
        }
        let first = leader.signal_dequeue_front().unwrap();
        let second = sibling.signal_dequeue_front().unwrap();
        assert_eq!((first.sequence, second.sequence), (1, 2));
        let wake = Arc::new(WakeCount::default());
        let waker = waker(wake.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(sibling.poll_signal_dequeue(&mut cx).is_pending());
        assert_eq!(
            sibling.acknowledge_signal_dequeue(second),
            Err(reverie::syscalls::Errno::EINVAL)
        );
        if fail {
            let error = leader.with_signal_effects(crate::Error::RunAborted, Some(-14));
            assert!(
                matches!(error, crate::Error::SignalEffects { dequeues, .. } if dequeues == [first])
            );
            assert_eq!(sibling.signal_dequeue_front(), Some(second));
            assert!(matches!(
                sibling.poll_signal_dequeue(&mut cx),
                Poll::Ready(Err(crate::Error::RunAborted))
            ));
            let error = sibling.with_signal_effects(crate::Error::RunAborted, Some(-14));
            assert!(
                matches!(error, crate::Error::SignalEffects { dequeues, acknowledged_through: 0, raw_result: Some(-14), .. } if dequeues == [second])
            );
        } else {
            leader.acknowledge_signal_dequeue(first).unwrap();
            assert!(
                matches!(sibling.poll_signal_dequeue(&mut cx), Poll::Ready(Ok(Some(effect))) if effect == second)
            );
            sibling.acknowledge_signal_dequeue(second).unwrap();
            sibling.acknowledge_signal_dequeue(second).unwrap();
            assert_eq!(
                leader.acknowledge_signal_dequeue(first),
                Err(reverie::syscalls::Errno::EINVAL)
            );
            assert!(matches!(
                sibling.poll_signal_dequeue(&mut cx),
                Poll::Ready(Ok(None))
            ));
        }
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(
            leader
                .state
                .process_signals
                .lock()
                .unwrap()
                .dequeue_journal
                .is_empty()
        );
    }
}

#[test]
fn parked_ledger_creation_rejects_each_foreign_site_before_allocation() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let site = executor.begin_signal_callback().unwrap();
    let mut sites = [site; 6];
    sites[0].process.generation += 1;
    sites[1].process.tgid = reverie::Pid::from_raw(99);
    sites[2].tid = reverie::Pid::from_raw(99);
    sites[3].task_generation += 1;
    sites[4].callback_nonce += 1;
    sites[5].boundary_nonce += 1;
    let before = process_alarm_snapshot(&executor);
    for foreign in sites {
        assert_eq!(
            executor.retain_parked_effects(foreign),
            Err(reverie::syscalls::Errno::EINVAL)
        );
        assert!(executor.parked_signals.is_none());
        assert!(executor.completed_signal_effects.is_empty());
        assert_eq!(process_alarm_snapshot(&executor), before);
    }
    executor.retain_parked_effects(site).unwrap();
    assert_eq!(executor.signal_failure_context().unwrap().site, site);
}

#[test]
fn signal_dequeue_raw_consumers_keep_bookkeeping_failure_terminal() {
    use std::task::Context;
    use std::task::Poll;

    use reverie::SignalConsumer;
    for consumer in [SignalConsumer::SignalFd, SignalConsumer::SignalTimedWait] {
        for stale in [false, true] {
            let root = TestDir::new();
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            executor.enable_signal_dequeues();
            let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
            let fd = process_alarm_signalfd(&mut executor, &mut memory);
            let event = process_alarm_event(executor.state.pid);
            assert!(matches!(
                executor.queue_process_alarm_signal(event),
                reverie::ProcessAlarmSignalOutcome::Accepted(_)
            ));
            let expected = if stale {
                executor
                    .state
                    .task_lifecycle
                    .lock()
                    .unwrap()
                    .remove(executor.state.tid, executor.task_generation);
                reverie::syscalls::Errno::ESRCH
            } else {
                executor
                    .state
                    .process_signals
                    .lock()
                    .unwrap()
                    .dequeue_sequence = u64::MAX;
                reverie::syscalls::Errno::EOVERFLOW
            };
            let before = process_alarm_snapshot(&executor);
            let raw = match consumer {
                SignalConsumer::SignalFd => signalfd_read(
                    &mut memory,
                    &mut executor.state,
                    fd,
                    0x100,
                    SIGNALFD_RECORD_SIZE,
                )
                .unwrap(),
                SignalConsumer::SignalTimedWait => {
                    rt_sigtimedwait(&mut memory, &mut executor.state, &[0x80, 0x100, 0, 8, 0, 0])
                }
                _ => unreachable!(),
            };
            assert_eq!(raw, -i64::from(expected.into_raw()));
            assert_eq!(process_alarm_snapshot(&executor), before);
            let waker = futures::task::noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(
                matches!(executor.poll_signal_dequeue(&mut cx),
                Poll::Ready(Err(crate::Error::Reverie(reverie::Error::Errno(errno))))
                    if errno == expected),
                "{consumer:?} bookkeeping refusal must prevent delivery of its intermediate raw result"
            );
        }
    }
}

#[test]
fn signal_dequeue_no_effect_error_preserves_live_sibling_stream() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    leader.enable_signal_dequeues();
    let mut sibling = leader.thread_child(7).unwrap();
    sibling.enable_signal_dequeues();
    let event = event_for_thread(libc::SIGUSR1, leader.state.pid, leader.state.tid).unwrap();
    leader.defer_signal_delivery(event).unwrap();
    leader.take_pending_signal_for_delivery().unwrap().unwrap();
    let before = process_alarm_snapshot(&leader);
    let error = sibling.with_signal_effects(
        crate::Error::Reverie(reverie::syscalls::Errno::EIO.into()),
        None,
    );
    assert!(
        matches!(error, crate::Error::Reverie(reverie::Error::Errno(errno))
        if errno == reverie::syscalls::Errno::EIO)
    );
    assert_eq!(
        process_alarm_snapshot(&leader),
        before,
        "no-effect error wrapping must not poison another owner's live stream"
    );
    let effect = leader.signal_dequeue_front().unwrap();
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    assert!(matches!(leader.poll_signal_dequeue(&mut cx),
        std::task::Poll::Ready(Ok(Some(actual))) if actual == effect));
    leader.acknowledge_signal_dequeue(effect).unwrap();
}

#[test]
fn signal_dequeue_full_journal_failure_retains_partial_read_and_every_removal() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    executor.enable_signal_dequeues();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = process_alarm_signalfd(&mut executor, &mut memory);
    for _ in 0..63 {
        let event =
            event_for_thread(libc::SIGUSR1, executor.state.pid, executor.state.tid).unwrap();
        executor.defer_signal_delivery(event).unwrap();
        executor
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap();
    }
    let private = event_for_thread(libc::SIGALRM, executor.state.pid, executor.state.tid).unwrap();
    executor.defer_signal_delivery(private).unwrap();
    let shared = process_alarm_event(executor.state.pid);
    assert!(matches!(
        executor.queue_process_alarm_signal(shared),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    let raw = signalfd_read(
        &mut memory,
        &mut executor.state,
        fd,
        0x100,
        2 * SIGNALFD_RECORD_SIZE,
    )
    .unwrap();
    assert_eq!(
        raw, SIGNALFD_RECORD_SIZE as i64,
        "the first record was actually copied before the second selection failed"
    );
    let mut record = [0; SIGNALFD_RECORD_SIZE];
    memory.read(0x100, &mut record).unwrap();
    assert_eq!(record, encode_signalfd_siginfo(private));
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let cause = match executor.poll_signal_dequeue(&mut cx) {
        std::task::Poll::Ready(Err(error)) => error,
        _ => panic!("partial positive read must not conceal full-journal failure"),
    };
    let error = executor.with_signal_effects(cause, Some(raw));
    match error {
        crate::Error::SignalEffects {
            cause,
            dequeues,
            acknowledged_through,
            raw_result,
            context,
            publications,
        } => {
            assert!(
                matches!(cause.as_ref(), crate::Error::Reverie(reverie::Error::Errno(errno))
                if *errno == reverie::syscalls::Errno::EOVERFLOW)
            );
            assert_eq!(dequeues.len(), 64);
            assert_eq!(
                dequeues
                    .iter()
                    .map(|effect| effect.sequence)
                    .collect::<Vec<_>>(),
                (1..=64).collect::<Vec<_>>()
            );
            assert_eq!(dequeues[63].event, private);
            assert_eq!(dequeues[63].domain, reverie::PendingDomain::Thread);
            assert_eq!(acknowledged_through, 0);
            assert_eq!(raw_result, Some(raw));
            assert!(context.is_none() && publications.is_empty());
        }
        _ => panic!("terminal error lost actual partial-read effects"),
    }
    let pending = executor.state.process_signals.lock().unwrap();
    assert!(pending.shared_pending.any_matching(
        KernelSigset::from_bytes((1_u64 << (libc::SIGALRM - 1)).to_ne_bytes()),
        &pending.pending_generations
    ));
    assert_eq!(pending.dequeue_sequence, 64);
    assert!(pending.dequeue_journal.is_empty());
}
