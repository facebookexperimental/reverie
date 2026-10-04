/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use futures::task::noop_waker;
use reverie::Pid;

use super::*;
use crate::entry::EntryOrigin;
use crate::failure::FailureContext;
use crate::failure::RunFailure;

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(&noop_waker()))
}

fn clock(name: &str) -> Error {
    Error::GuestClock(name.to_owned())
}

fn effects(cause: Error) -> Error {
    Error::SignalEffects {
        cause: Arc::new(cause),
        dequeues: Vec::new(),
        acknowledged_through: 41,
        publications: Vec::new(),
        raw_result: Some(-5),
        context: None,
    }
}

fn contains_effects(error: &Error) -> bool {
    match error {
        Error::SignalEffects {
            acknowledged_through,
            raw_result,
            ..
        } => *acknowledged_through == 41 && *raw_result == Some(-5),
        Error::WithCleanup { primary, cleanup } => {
            contains_effects(primary) || cleanup.iter().any(|error| contains_effects(error))
        }
        Error::SharedFailure(error)
        | Error::Cleanup { error, .. }
        | Error::WorkerFailure { error, .. } => contains_effects(error),
        Error::ExecWorkerTeardown(error) => contains_effects(error),
        _ => false,
    }
}

#[test]
fn private_watch_ignores_callback_drop_and_rechecks_rotating_notifications() {
    let scope = DriverScope::new();
    let owner = scope.owner();
    let gate = EntryGate::new();
    let watch = EntryDriverWatch {
        owner: Some(owner.clone()),
        gate: gate.clone(),
    };
    let mut waiting = Box::pin(watch.wait());
    assert!(poll(waiting.as_mut()).is_pending());
    let callback = owner.begin_callback(None).unwrap();
    drop(callback);
    assert!(poll(waiting.as_mut()).is_pending());
    let failure = gate.poison(
        EntryOrigin {
            failure: None,
            operation: Some(owner.origin()),
        },
        clock("private cause"),
    );
    assert!(poll(waiting.as_mut()).is_ready());
    assert!(
        watch
            .check()
            .unwrap_err()
            .retains_primary(&failure.causes()[0])
    );
    assert!(Arc::ptr_eq(&owner.pending()[0], &failure));
    drop(waiting);
    let retired = scope.retire();
    retired.result.unwrap();
    retired.notification.notify();
}

#[test]
fn peer_waits_for_publication_after_origin_callback_destruction() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let scope = DriverScope::new();
    let owner = scope.owner();
    let callback = owner.begin_callback(None).unwrap();
    let gate = EntryGate::new();
    let failure = gate.poison(
        EntryOrigin {
            failure: Some(context.clone()),
            operation: Some(callback.origin()),
        },
        clock("origin cause"),
    );
    let mut peer = Box::pin(route_foreign::<()>(Err(effects(failure.error())), &failure));
    assert!(poll(peer.as_mut()).is_pending());
    assert!(run.published_primary().is_none());
    assert!(!failure.operation.as_ref().unwrap().callback_dropped());
    drop(callback);
    assert!(poll(peer.as_mut()).is_pending());
    assert!(run.published_primary().is_none());
    let _published = context.publish("origin after callback", failure.error());
    let Poll::Ready(Err(error)) = poll(peer.as_mut()) else {
        panic!("peer did not leave after actual publication");
    };
    assert!(matches!(error.primary(), Error::RunAborted));
    assert!(contains_effects(&error));
    assert!(!references_shared_error(&error, &failure.causes()[0]));
    assert!(Arc::ptr_eq(&owner.pending()[0], &failure));
    let retired = scope.retire();
    retired.result.unwrap();
    retired.notification.notify();
}

#[test]
fn competing_publication_releases_peer_but_keeps_origin_obligation() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let origin = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let other = origin.for_thread(Pid::from_raw(3));
    let scope = DriverScope::new();
    let owner = scope.owner();
    let callback = owner.begin_callback(None).unwrap();
    let gate = EntryGate::new();
    let failure = gate.poison(
        EntryOrigin {
            failure: Some(origin.clone()),
            operation: Some(callback.origin()),
        },
        clock("unpublished origin"),
    );
    let mut peer = Box::pin(route_foreign::<()>(Err(failure.error()), &failure));
    assert!(poll(peer.as_mut()).is_pending());
    let competing = other.publish("independent failure", clock("first publisher"));
    let first = run.published_primary().unwrap();
    assert!(competing.retains_primary(&first));
    let Poll::Ready(Err(derived)) = poll(peer.as_mut()) else {
        panic!("competing real notification did not release peer");
    };
    assert!(matches!(derived.primary(), Error::RunAborted));
    assert!(!callback.origin().callback_dropped());
    assert_eq!(owner.pending().len(), 1);
    drop(callback);
    let own_result = fold_causes::<()>(
        Err(effects(Error::RunAborted)),
        owner.pending().iter().flat_map(|failure| failure.causes()),
    );
    let own_result = origin.publish("origin completion", own_result.unwrap_err());
    let retired = scope.retire();
    for retained in retired.pending {
        run.retain_entry_failure(retained);
    }
    retired.result.unwrap();
    retired.notification.notify();
    gate.poison(None, clock("late cleanup"));
    let complete = run.complete::<()>(Err(own_result)).unwrap_err();
    assert!(complete.retains_primary(&first));
    assert!(contains_effects(&complete));
    for cause in failure.causes() {
        assert!(references_shared_error(&complete, &cause));
    }
}

#[test]
fn independent_peer_error_does_not_wait_or_lose_its_signal_effects() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let scope = DriverScope::new();
    let callback = scope.owner().begin_callback(None).unwrap();
    let failure = EntryGate::new().poison(
        EntryOrigin {
            failure: Some(context),
            operation: Some(callback.origin()),
        },
        clock("origin"),
    );
    let own = Arc::new(clock("independent peer"));
    let result = Error::ExecWorkerTeardown(Box::new(Error::WorkerFailure {
        tid: 7,
        error: Arc::new(
            effects(failure.error()).with_cleanup(vec![Error::SharedFailure(own.clone())]),
        ),
    }));
    let mut peer = Box::pin(route_foreign::<()>(Err(result), &failure));
    let Poll::Ready(Err(error)) = poll(peer.as_mut()) else {
        panic!("independent peer failure waited for origin");
    };
    assert!(error.retains_primary(&own));
    assert!(contains_effects(&error));
    assert!(!references_shared_error(&error, &failure.causes()[0]));
    assert!(run.published_primary().is_none());
    assert!(!callback.origin().callback_dropped());
    drop(callback);
    let retired = scope.retire();
    retired.result.unwrap();
    retired.notification.notify();
}

#[test]
fn retired_or_abandoned_origin_does_not_imply_publication() {
    for abandon in [false, true] {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let scope = DriverScope::new();
        let owner = scope.owner();
        let failure = EntryGate::new().poison(
            EntryOrigin {
                failure: Some(context),
                operation: Some(owner.origin()),
            },
            clock("lost owner"),
        );
        if abandon {
            drop(scope);
        } else {
            let retired = scope.retire();
            retired.result.unwrap();
            retired.notification.notify();
        }
        let mut peer = Box::pin(route_foreign::<()>(Err(failure.error()), &failure));
        let Poll::Ready(Err(error)) = poll(peer.as_mut()) else {
            panic!("closed origin left waiter pending");
        };
        assert!(matches!(error.primary(), Error::EntryControl { .. }));
        assert!(references_shared_error(&error, &failure.causes()[0]));
        assert!(run.published_primary().is_none());
    }
}

#[test]
fn retained_old_generation_captures_without_acknowledging_current_callback() {
    let scope = DriverScope::new();
    let owner = scope.owner();
    let old = owner.begin_callback(None).unwrap();
    let retained = old.origin();
    drop(old);
    let current = owner.begin_callback(None).unwrap();
    let gate = EntryGate::new();
    let failure = gate.poison(
        EntryOrigin {
            failure: None,
            operation: Some(retained.clone()),
        },
        clock("retained view"),
    );
    assert!(retained.callback_dropped());
    assert!(!current.origin().callback_dropped());
    assert!(!retained.same_callback(&current.origin()));
    let watch = EntryDriverWatch {
        owner: Some(owner.clone()),
        gate,
    };
    assert!(
        watch
            .check()
            .unwrap_err()
            .retains_primary(&failure.causes()[0])
    );
    assert!(!current.origin().callback_dropped());
    drop(current);
    let retired = scope.retire();
    assert_eq!(retired.pending.len(), 1);
    retired.result.unwrap();
    retired.notification.notify();
}

#[test]
fn repeated_completion_keeps_late_causes_without_duplicate_shared_references() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let gate = EntryGate::new();
    let failure = gate.poison(None, clock("primary"));
    run.retain_entry_failure(failure.clone());
    run.retain_entry_failure(failure.clone());
    let first = run.complete::<()>(Err(failure.error())).unwrap_err();
    gate.poison(None, clock("cleanup after retirement"));
    let complete = run.complete::<()>(Err(first)).unwrap_err();
    let again = run.complete::<()>(Err(complete)).unwrap_err();
    let Error::WithCleanup { primary, cleanup } = again else {
        panic!("late cleanup lost");
    };
    assert_eq!(cleanup.len(), 1);
    assert!(references_shared_error(&primary, &failure.causes()[0]));
    assert!(references_shared_error(&cleanup[0], &failure.causes()[1]));
}

#[test]
fn retained_entry_failure_does_not_keep_its_run_alive() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let weak = Arc::downgrade(&run);
    let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let gate = EntryGate::new();
    let failure = gate.poison(
        EntryOrigin {
            failure: Some(context),
            operation: None,
        },
        clock("retained"),
    );
    run.retain_entry_failure(failure.clone());
    drop(run);
    assert!(weak.upgrade().is_none());
    assert!(
        failure
            .origin
            .as_ref()
            .unwrap()
            .subscribe()
            .now_or_never()
            .unwrap()
            .is_err()
    );
    assert!(
        matches!(failure.error().primary(), Error::GuestClock(message) if message == "retained")
    );
}

fn occurrences(error: &Error, wanted: &Arc<Error>) -> usize {
    let shared = |error: &Arc<Error>| {
        if Arc::ptr_eq(error, wanted) {
            1
        } else {
            occurrences(error, wanted)
        }
    };
    match error {
        Error::SignalEffects { cause, .. }
        | Error::SharedFailure(cause)
        | Error::WorkerFailure { error: cause, .. }
        | Error::Cleanup { error: cause, .. } => shared(cause),
        Error::WithCleanup { primary, cleanup } => {
            shared(primary) + cleanup.iter().map(shared).sum::<usize>()
        }
        Error::ExecWorkerTeardown(error) => occurrences(error, wanted),
        _ => 0,
    }
}

#[test]
fn peer_promotion_preserves_nonempty_ledger_and_worker_context_exactly_once() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let peer_context = context.for_thread(Pid::from_raw(7));
    let scope = DriverScope::new();
    let callback = scope.owner().begin_callback(None).unwrap();
    let failure = EntryGate::new().poison(
        EntryOrigin {
            failure: Some(context),
            operation: Some(callback.origin()),
        },
        clock("origin"),
    );
    let pid = Pid::from_raw(7);
    let mut info = [0; 128];
    info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[24] = 0x5a;
    let event =
        reverie::SignalEvent::new(libc::SIGUSR1, info, reverie::SignalTarget::Process { pid })
            .unwrap();
    let dequeued = reverie::SignalDequeue {
        process: reverie::SignalProcessId {
            tgid: pid,
            generation: 13,
        },
        sequence: 42,
        consumer: reverie::SignalConsumer::SignalTimedWait,
        domain: reverie::PendingDomain::Process,
        event,
    };
    let publication = reverie::ProcessAlarmSignalOutcome::FailedAfterCommit {
        errno: reverie::syscalls::Errno::EPIPE,
        receipt: reverie::ProcessAlarmSignalReceipt {
            blocked: true,
            disposition: reverie::ProcessAlarmSignalDisposition::Caught,
            pending_generation: 19,
            coalesced: false,
        },
    };
    let own = Arc::new(clock("peer cause"));
    let ledger = Arc::new(Error::SignalEffects {
        cause: own.clone(),
        dequeues: vec![dequeued],
        acknowledged_through: 41,
        publications: vec![publication],
        raw_result: Some(-14),
        context: None,
    });
    let result = Error::ExecWorkerTeardown(Box::new(Error::WorkerFailure {
        tid: 7,
        error: Arc::new(
            failure
                .error()
                .with_cleanup(vec![Error::SharedFailure(ledger.clone())]),
        ),
    }));
    let mut peer = Box::pin(route_foreign::<()>(Err(result), &failure));
    let Poll::Ready(Err(error)) = poll(peer.as_mut()) else {
        panic!("peer own error did not return");
    };
    assert_eq!(error.worker_tid(), Some(7));
    assert_eq!(occurrences(&error, &ledger), 1);
    assert_eq!(occurrences(&error, &own), 1);
    assert!(error.retains_primary(&own));
    let complete = run
        .complete::<()>(Err(peer_context.publish("peer", error)))
        .unwrap_err();
    assert_eq!(complete.worker_tid(), Some(7));
    assert_eq!(occurrences(&complete, &ledger), 1);
    assert_eq!(occurrences(&complete, &own), 1);
    let Error::SignalEffects {
        dequeues,
        publications,
        raw_result,
        ..
    } = ledger.as_ref()
    else {
        unreachable!()
    };
    assert_eq!(dequeues, &[dequeued]);
    assert_eq!(publications, &[publication]);
    assert_eq!(*raw_result, Some(-14));
    drop(callback);
    let retired = scope.retire();
    retired.result.unwrap();
    retired.notification.notify();
}

#[test]
fn rejected_old_view_survives_prior_publication_and_independent_peer_error() {
    for abandon in [false, true] {
        for independent in [false, true] {
            let global = Arc::new(());
            let run = RunFailure::new(&global);
            let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
            let _first = context
                .for_thread(Pid::from_raw(3))
                .publish("earlier unrelated", clock("earlier"));
            let scope = DriverScope::new();
            let retained = scope.owner().origin();
            if abandon {
                drop(scope);
            } else {
                let retired = scope.retire();
                assert!(retired.pending.is_empty());
                retired.result.unwrap();
                retired.notification.notify();
            }
            let failure = EntryGate::new().poison(
                EntryOrigin {
                    failure: Some(context),
                    operation: Some(retained),
                },
                clock("new rejected operation"),
            );
            assert!(!failure.owner_registered());
            let own = Arc::new(clock("independent peer"));
            let result = if independent {
                Err(Error::SharedFailure(own.clone()))
            } else {
                Err(failure.error())
            };
            let result =
                futures::executor::block_on(route_foreign::<()>(result, &failure)).unwrap_err();
            assert_eq!(occurrences(&result, &failure.causes()[0]), 1);
            let complete = run.complete::<()>(Err(result)).unwrap_err();
            assert_eq!(occurrences(&complete, &failure.causes()[0]), 1);
            if independent {
                assert_eq!(occurrences(&complete, &own), 1);
            }
        }
    }
}

#[test]
fn already_retained_secondary_owner_cause_is_promoted_once() {
    let cause = Arc::new(clock("owned cause"));
    let result = Error::WorkerFailure {
        tid: 9,
        error: Arc::new(
            effects(Error::RunAborted).with_cleanup(vec![Error::SharedFailure(cause.clone())]),
        ),
    };
    let result = fold_causes::<()>(Err(result), [cause.clone()]).unwrap_err();
    assert!(result.retains_primary(&cause));
    assert_eq!(result.worker_tid(), Some(9));
    assert_eq!(occurrences(&result, &cause), 1);
    assert!(contains_effects(&result));
}

#[test]
fn last_failure_context_disconnects_only_after_gate_unlock() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Wake;
    use std::task::Waker;
    struct Observe {
        gate: Arc<EntryGate>,
        locked: AtomicBool,
        wakes: AtomicUsize,
    }
    impl Wake for Observe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.locked
                .fetch_or(self.gate.state.try_lock().is_err(), Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }
    for already_failed in [false, true] {
        let global = Arc::new(());
        let run = RunFailure::new(&global);
        let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
        let gate = EntryGate::new();
        if already_failed {
            gate.poison(None, clock("first"));
        }
        let observed = Arc::new(Observe {
            gate: gate.clone(),
            locked: AtomicBool::new(false),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(observed.clone());
        let mut subscription = Box::pin(run.subscribe());
        assert!(
            subscription
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let weak = Arc::downgrade(&run);
        drop(run);
        gate.poison(Some(context), clock("last context"));
        assert!(weak.upgrade().is_none());
        assert!(observed.wakes.load(Ordering::SeqCst) > 0);
        assert!(!observed.locked.load(Ordering::SeqCst));
        assert!(matches!(poll(subscription.as_mut()), Poll::Ready(Err(_))));
    }
}

#[test]
fn suspended_peer_rechecks_abandonment_when_terminal_notification_wins() {
    let global = Arc::new(());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(2));
    let other = context.for_thread(Pid::from_raw(3));
    let scope = DriverScope::new();
    let failure = EntryGate::new().poison(
        EntryOrigin {
            failure: Some(context),
            operation: Some(scope.owner().origin()),
        },
        clock("captured before abandonment"),
    );
    assert!(failure.owner_registered());
    let mut peer = Box::pin(route_foreign::<()>(Err(failure.error()), &failure));
    assert!(poll(peer.as_mut()).is_pending());
    drop(scope);
    other.publish("unrelated while peer suspended", clock("first published"));
    let Poll::Ready(Err(result)) = poll(peer.as_mut()) else {
        panic!("abandoned peer did not return");
    };
    assert!(matches!(result.primary(), Error::EntryControl { .. }));
    assert_eq!(occurrences(&result, &failure.causes()[0]), 1);
    let completed = run.complete::<()>(Err(result)).unwrap_err();
    assert_eq!(occurrences(&completed, &failure.causes()[0]), 1);
}
