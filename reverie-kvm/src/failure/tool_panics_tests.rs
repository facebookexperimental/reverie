/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Host controls for the production ToolPanics owner. Constructed effect
//! records test preservation, not actual signal removal or callback routing.

use std::cell::Cell;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;

use futures::FutureExt;
use reverie::BackendFailure;
use reverie::GlobalTool;
use reverie::Pid;

use super::ToolPanics;
use crate::Error;
use crate::failure::FailureContext;
use crate::failure::RunFailure;
use crate::failure::owned_future::CaughtFuture;
use crate::failure::owned_future::PanicPayload;

struct Payload {
    label: &'static str,
    drops: Arc<Mutex<Vec<&'static str>>>,
    owner: Weak<ToolPanics>,
    // The same payload domain as JoinHandle: Send, without requiring Sync.
    _send_only: Cell<u8>,
}

impl Drop for Payload {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            assert!(owner.pending.try_lock().is_ok());
        }
        self.drops.lock().unwrap().push(self.label);
    }
}

fn payload(
    owner: &Arc<ToolPanics>,
    drops: &Arc<Mutex<Vec<&'static str>>>,
    label: &'static str,
) -> (PanicPayload, usize) {
    let payload = Box::new(Payload {
        label,
        drops: drops.clone(),
        owner: Arc::downgrade(owner),
        _send_only: Cell::new(17),
    });
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    (payload, address)
}

fn assert_payloads(payloads: &[PanicPayload], expected: &[(&str, usize)]) {
    assert_eq!(payloads.len(), expected.len());
    for (payload, &(label, address)) in payloads.iter().zip(expected) {
        let actual = payload
            .downcast_ref::<Payload>()
            .expect("exact payload type");
        assert_eq!(actual.label, label);
        assert_eq!(std::ptr::from_ref(actual) as usize, address);
    }
}

fn references(error: &Error, wanted: &Arc<Error>) -> usize {
    let shared = |error: &Arc<Error>| {
        if Arc::ptr_eq(error, wanted) {
            1
        } else {
            references(error, wanted)
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
        Error::ExecWorkerTeardown(error) => references(error, wanted),
        _ => 0,
    }
}

fn effects(cause: Arc<Error>) -> Arc<Error> {
    let pid = Pid::from_raw(71);
    let process = reverie::SignalProcessId {
        tgid: pid,
        generation: 13,
    };
    let mut info = [0; 128];
    info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[24] = 0x5a;
    let event =
        reverie::SignalEvent::new(libc::SIGUSR1, info, reverie::SignalTarget::Process { pid })
            .unwrap();
    Arc::new(Error::SignalEffects {
        cause,
        dequeues: vec![reverie::SignalDequeue {
            process,
            sequence: 42,
            consumer: reverie::SignalConsumer::SignalTimedWait,
            domain: reverie::PendingDomain::Process,
            event,
        }],
        acknowledged_through: 41,
        publications: vec![reverie::ProcessAlarmSignalOutcome::FailedAfterCommit {
            errno: reverie::syscalls::Errno::EPIPE,
            receipt: reverie::ProcessAlarmSignalReceipt {
                blocked: true,
                disposition: reverie::ProcessAlarmSignalDisposition::Caught,
                pending_generation: 19,
                coalesced: false,
            },
        }],
        raw_result: Some(-i64::from(libc::EFAULT)),
        context: Some(Box::new(reverie::ParkedSignalFailureContext {
            site: reverie::CallbackSignalSite {
                process,
                tid: Pid::from_raw(72),
                task_generation: 23,
                callback_nonce: 29,
                boundary_nonce: 31,
            },
            ledger_nonce: 37,
        })),
    })
}

fn assert_effects(error: &Error) {
    let Error::SignalEffects {
        dequeues,
        acknowledged_through,
        publications,
        raw_result,
        context,
        ..
    } = error
    else {
        panic!("original effects wrapper disappeared");
    };
    assert_eq!(dequeues.len(), 1);
    assert_eq!(dequeues[0].process.tgid, Pid::from_raw(71));
    assert_eq!(dequeues[0].process.generation, 13);
    assert_eq!(dequeues[0].sequence, 42);
    assert_eq!(
        dequeues[0].consumer,
        reverie::SignalConsumer::SignalTimedWait
    );
    assert_eq!(dequeues[0].domain, reverie::PendingDomain::Process);
    let mut info = [0; 128];
    info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[24] = 0x5a;
    assert_eq!(dequeues[0].event.siginfo(), info);
    assert_eq!(*acknowledged_through, 41);
    assert_eq!(publications.len(), 1);
    assert_eq!(
        publications[0],
        reverie::ProcessAlarmSignalOutcome::FailedAfterCommit {
            errno: reverie::syscalls::Errno::EPIPE,
            receipt: reverie::ProcessAlarmSignalReceipt {
                blocked: true,
                disposition: reverie::ProcessAlarmSignalDisposition::Caught,
                pending_generation: 19,
                coalesced: false,
            },
        }
    );
    assert_eq!(*raw_result, Some(-i64::from(libc::EFAULT)));
    let context = context.as_ref().expect("original callback ledger context");
    assert_eq!(context.site.process, dequeues[0].process);
    assert_eq!(context.site.tid, Pid::from_raw(72));
    assert_eq!(context.site.task_generation, 23);
    assert_eq!(context.site.callback_nonce, 29);
    assert_eq!(context.site.boundary_nonce, 31);
    assert_eq!(context.ledger_nonce, 37);
}

fn assert_panic_cleanup(error: &Error, expected_phase: &str) {
    let Error::Cleanup { phase, error } = error else {
        panic!("panic lost its typed cleanup phase");
    };
    assert_eq!(*phase, expected_phase);
    assert!(matches!(error.as_ref(), Error::GuestWorkerPanic));
}

#[test]
fn real_error_effects_and_two_exact_payloads_keep_their_original_ownership() {
    let owner = Arc::new(ToolPanics::default());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let (poll, poll_address) = payload(&owner, &drops, "poll");
    let (destroy, destroy_address) = payload(&owner, &drops, "drop");
    let cause = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
    let effects = effects(cause.clone());
    let earlier = Arc::new(Error::GuestClock("earlier cleanup".to_owned()));
    let original = Error::ExecWorkerTeardown(Box::new(
        Error::SharedFailure(effects.clone())
            .with_cleanup(vec![Error::SharedFailure(earlier.clone())]),
    ));
    let error = owner
        .finish::<()>(
            CaughtFuture {
                output: Some(Err(original)),
                panics: vec![poll, destroy],
            },
            "callback completion",
        )
        .unwrap_err();
    assert!(std::ptr::eq(error.primary(), cause.as_ref()));
    assert!(
        matches!(error.primary(), Error::HostIo(error) if error.raw_os_error() == Some(libc::EIO))
    );
    assert_eq!(references(&error, &effects), 1);
    assert_eq!(references(&error, &earlier), 1);
    assert_effects(&effects);
    let Error::WithCleanup { primary, cleanup } = &error else {
        panic!("two panic diagnostics were not retained");
    };
    assert!(matches!(primary.as_ref(), Error::ExecWorkerTeardown(_)));
    assert_eq!(cleanup.len(), 2);
    for diagnostic in cleanup {
        assert_panic_cleanup(diagnostic, "callback completion");
    }
    assert!(drops.lock().unwrap().is_empty());
    let retained = owner.take();
    assert_payloads(
        &retained,
        &[("poll", poll_address), ("drop", destroy_address)],
    );
    assert!(owner.take().is_empty());
    assert!(drops.lock().unwrap().is_empty());
    drop(retained);
    assert_eq!(*drops.lock().unwrap(), vec!["poll", "drop"]);
    assert_eq!(references(&error, &effects), 1);
    assert_eq!(references(&error, &earlier), 1);
}

#[derive(Default)]
struct PublicationLog(Mutex<Vec<BackendFailure>>);

#[reverie::global_tool]
impl GlobalTool for PublicationLog {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn report_backend_failure(&self, failure: BackendFailure) {
        self.0.lock().unwrap().push(failure);
    }
}

#[test]
fn panic_promotes_wrapped_abort_and_publishes_its_complete_effects_subtree() {
    let owner = Arc::new(ToolPanics::default());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let (panic, address) = payload(&owner, &drops, "abort drop");
    let effects = effects(Arc::new(Error::RunAborted));
    let earlier = Arc::new(Error::GuestClock("abort cleanup".to_owned()));
    let abort = Arc::new(Error::ExecWorkerTeardown(Box::new(
        Error::SharedFailure(effects.clone())
            .with_cleanup(vec![Error::SharedFailure(earlier.clone())]),
    )));
    let global = Arc::new(PublicationLog::default());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run.clone(), Pid::from_raw(71), Pid::from_raw(72));
    let run_wake = run.subscribe();
    let process_wake = context.driver_subscription(false);
    // The same wrapped marker alone remains derived cancellation. The real
    // publisher must distinguish the later panic without a copied predicate.
    let unchanged = context.publish("derived marker", Error::SharedFailure(abort.clone()));
    assert!(matches!(unchanged, Error::SharedFailure(ref error) if Arc::ptr_eq(error, &abort)));
    assert!(run.primary().is_none());
    assert!(global.0.lock().unwrap().is_empty());
    assert!(run_wake.clone().now_or_never().is_none());
    assert!(process_wake.clone().now_or_never().is_none());

    let outcome = owner.finish::<()>(
        CaughtFuture {
            output: Some(Err(Error::SharedFailure(abort.clone()))),
            panics: vec![panic],
        },
        "callback destruction",
    );
    assert!(!crate::runtime::is_peer_cancelled_tool_worker(
        (Pid::from_raw(71), Pid::from_raw(72)),
        true,
        &outcome,
    ));
    let error = outcome.unwrap_err();
    assert!(matches!(error.primary(), Error::GuestWorkerPanic));
    assert_eq!(references(&error, &abort), 1);
    assert_eq!(references(&error, &effects), 1);
    assert_eq!(references(&error, &earlier), 1);
    assert_effects(&effects);
    assert!(
        run.primary().is_none(),
        "ToolPanics must not publish itself"
    );
    assert!(global.0.lock().unwrap().is_empty());
    let published = context.publish("callback destruction", error);
    let first = run
        .published_primary()
        .expect("real panic must be published");
    assert!(matches!(first.primary(), Error::GuestWorkerPanic));
    assert!(published.retains_primary(&first));
    assert_eq!(references(&published, &abort), 1);
    assert_eq!(references(&published, &effects), 1);
    assert_eq!(references(&published, &earlier), 1);
    assert_eq!(run_wake.now_or_never(), Some(Ok(())));
    assert_eq!(process_wake.now_or_never(), Some(Ok(())));
    let events = global.0.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].pid, Pid::from_raw(71));
    assert_eq!(events[0].tid, Pid::from_raw(72));
    assert_eq!(events[0].phase, "callback destruction");
    drop(events);
    let retained = owner.take();
    assert_payloads(&retained, &[("abort drop", address)]);
    assert!(drops.lock().unwrap().is_empty());
    drop(retained);
    assert_eq!(*drops.lock().unwrap(), vec!["abort drop"]);
}

#[test]
fn no_panic_preserves_success_and_typed_errors_without_new_wrappers() {
    let owner = ToolPanics::default();
    let value = Arc::new(String::from("owned value"));
    let returned = owner
        .finish(
            CaughtFuture {
                output: Some(Ok(value.clone())),
                panics: Vec::new(),
            },
            "normal success",
        )
        .unwrap();
    assert!(Arc::ptr_eq(&returned, &value));
    for cause in [
        Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
            libc::EPIPE,
        ))),
        effects(Arc::new(Error::RunAborted)),
    ] {
        let returned = owner
            .finish::<()>(
                CaughtFuture {
                    output: Some(Err(Error::SharedFailure(cause.clone()))),
                    panics: Vec::new(),
                },
                "normal failure",
            )
            .unwrap_err();
        let Error::SharedFailure(actual) = returned else {
            panic!("no-panic error gained or lost an ownership wrapper");
        };
        assert!(Arc::ptr_eq(&actual, &cause));
    }
    assert!(owner.take().is_empty());
}

#[test]
fn take_transfers_only_pending_payloads_once_and_accepts_a_later_batch() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ToolPanics>();
    let owner = Arc::new(ToolPanics::default());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let (first, first_address) = payload(&owner, &drops, "earlier");
    let (second, second_address) = payload(&owner, &drops, "caught");
    owner.append(vec![first]);
    let error = owner
        .finish::<()>(
            CaughtFuture {
                output: None,
                panics: vec![second],
            },
            "poll failure",
        )
        .unwrap_err();
    assert_panic_cleanup(&error, "poll failure");
    // Completing an unrelated non-panicking consumer must not consume or
    // relabel an earlier pending payload batch.
    assert_eq!(
        owner
            .finish(
                CaughtFuture {
                    output: Some(Ok(43)),
                    panics: Vec::new()
                },
                "later success"
            )
            .unwrap(),
        43
    );
    let retained = owner.take();
    assert_payloads(
        &retained,
        &[("earlier", first_address), ("caught", second_address)],
    );
    assert!(owner.take().is_empty());
    let (third, third_address) = payload(&owner, &drops, "later");
    owner.append(vec![third]);
    let later = owner.take();
    assert_payloads(&later, &[("later", third_address)]);
    assert!(owner.take().is_empty());
    assert!(drops.lock().unwrap().is_empty());
    drop(retained);
    assert_eq!(*drops.lock().unwrap(), vec!["earlier", "caught"]);
    drop(later);
    assert_eq!(*drops.lock().unwrap(), vec!["earlier", "caught", "later"]);
    assert_panic_cleanup(&error, "poll failure");
}

#[test]
fn worker_execution_panic_keeps_its_original_payload_and_bare_primary() {
    let owner = Arc::new(ToolPanics::default());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let (poll, poll_address) = payload(&owner, &drops, "worker poll");
    let (destroy, destroy_address) = payload(&owner, &drops, "worker drop");
    let error = owner
        .finish_worker_execution::<()>(
            CaughtFuture {
                output: None,
                panics: vec![poll, destroy],
            },
            "Tool callback",
        )
        .unwrap_err();
    assert!(owner.worker_execution_panicked());
    let Error::WithCleanup { primary, cleanup } = &error else {
        panic!("worker execution lost its secondary destruction panic");
    };
    assert!(matches!(primary.as_ref(), Error::GuestWorkerPanic));
    assert_eq!(cleanup.len(), 1);
    assert_panic_cleanup(&cleanup[0], "Tool callback");
    let retained = owner.take();
    assert_payloads(
        &retained,
        &[
            ("worker poll", poll_address),
            ("worker drop", destroy_address),
        ],
    );
    assert!(drops.lock().unwrap().is_empty());
    drop(retained);
    assert_eq!(*drops.lock().unwrap(), vec!["worker poll", "worker drop"]);
}

#[test]
fn worker_execution_panic_preserves_a_prior_real_error_and_abort_effects() {
    for abort in [false, true] {
        let owner = Arc::new(ToolPanics::default());
        let drops = Arc::new(Mutex::new(Vec::new()));
        let (panic, address) = payload(&owner, &drops, "execution");
        let cause = Arc::new(if abort {
            Error::RunAborted
        } else {
            Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO))
        });
        let retained_effects = effects(cause.clone());
        let error = owner
            .finish_worker_execution::<()>(
                CaughtFuture {
                    output: Some(Err(Error::SharedFailure(retained_effects.clone()))),
                    panics: vec![panic],
                },
                "Tool callback",
            )
            .unwrap_err();
        assert!(owner.worker_execution_panicked());
        assert_eq!(references(&error, &retained_effects), 1);
        assert_effects(&retained_effects);
        if abort {
            let Error::WithCleanup { primary, cleanup } = &error else {
                panic!("worker panic lost its original cancellation effects");
            };
            assert!(matches!(primary.as_ref(), Error::GuestWorkerPanic));
            assert_eq!(cleanup.len(), 1);
        } else {
            assert!(std::ptr::eq(error.primary(), cause.as_ref()));
            let Error::WithCleanup { cleanup, .. } = &error else {
                panic!("worker lost its secondary execution panic");
            };
            assert_eq!(cleanup.len(), 1);
            assert_panic_cleanup(&cleanup[0], "Tool callback");
        }
        let retained = owner.take();
        assert_payloads(&retained, &[("execution", address)]);
        assert!(drops.lock().unwrap().is_empty());
        drop(retained);
        assert_eq!(*drops.lock().unwrap(), vec!["execution"]);
    }
}

#[test]
fn transferred_and_consuming_panics_do_not_mark_local_worker_execution() {
    let owner = Arc::new(ToolPanics::default());
    let drops = Arc::new(Mutex::new(Vec::new()));
    let (child, child_address) = payload(&owner, &drops, "child");
    owner.append(vec![child]);
    let returned = owner
        .finish_worker_execution::<()>(
            CaughtFuture {
                output: Some(Err(Error::RunAborted)),
                panics: Vec::new(),
            },
            "Tool execution",
        )
        .unwrap_err();
    assert!(matches!(returned, Error::RunAborted));
    assert!(!owner.worker_execution_panicked());
    let (cleanup, cleanup_address) = payload(&owner, &drops, "exit hook");
    let error = owner
        .finish::<()>(
            CaughtFuture {
                output: None,
                panics: vec![cleanup],
            },
            "thread exit hook",
        )
        .unwrap_err();
    assert_panic_cleanup(&error, "thread exit hook");
    assert!(!owner.worker_execution_panicked());
    let retained = owner.take();
    assert_payloads(
        &retained,
        &[("child", child_address), ("exit hook", cleanup_address)],
    );
    assert!(drops.lock().unwrap().is_empty());
    drop(retained);
    assert_eq!(*drops.lock().unwrap(), vec!["child", "exit hook"]);
}
