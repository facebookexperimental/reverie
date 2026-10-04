/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Controls for retaining a driver outcome through actual callback destruction.

use std::cell::Cell;
use std::panic::resume_unwind;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;

use super::*;
use crate::failure::owned_future::PanicPayload;

struct ExpectedError {
    weak: Weak<Error>,
    dequeues: Vec<reverie::SignalDequeue>,
    publication: reverie::ProcessAlarmSignalOutcome,
    context: reverie::ParkedSignalFailureContext,
    context_address: usize,
}

fn owned_error() -> (Error, ExpectedError) {
    let process = reverie::SignalProcessId {
        tgid: Pid::from_raw(31),
        generation: 17,
    };
    let mut info = [0_u8; 128];
    info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    for (index, byte) in info[4..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let event = reverie::SignalEvent::new(
        libc::SIGALRM,
        info,
        reverie::SignalTarget::Process { pid: process.tgid },
    )
    .unwrap();
    let dequeues = vec![
        reverie::SignalDequeue {
            process,
            sequence: 11,
            consumer: reverie::SignalConsumer::SignalTimedWait,
            domain: reverie::PendingDomain::Process,
            event,
        },
        reverie::SignalDequeue {
            process,
            sequence: 12,
            consumer: reverie::SignalConsumer::SignalFd,
            domain: reverie::PendingDomain::Thread,
            event,
        },
    ];
    let publication = reverie::ProcessAlarmSignalOutcome::FailedAfterCommit {
        errno: Errno::EIO,
        receipt: reverie::ProcessAlarmSignalReceipt {
            blocked: true,
            disposition: reverie::ProcessAlarmSignalDisposition::Caught,
            pending_generation: 39,
            coalesced: true,
        },
    };
    let context = Box::new(reverie::ParkedSignalFailureContext {
        site: reverie::CallbackSignalSite {
            process,
            tid: Pid::from_raw(32),
            task_generation: 23,
            callback_nonce: 7,
            boundary_nonce: 19,
        },
        ledger_nonce: 41,
    });
    let context_address = std::ptr::from_ref(context.as_ref()) as usize;
    let expected_context = *context;
    let error = Arc::new(Error::SignalEffects {
        cause: Arc::new(
            Error::HostIo(std::io::Error::from_raw_os_error(libc::EAGAIN))
                .with_cleanup(vec![Error::GuestClock("earlier cleanup".to_owned())]),
        ),
        dequeues: dequeues.clone(),
        acknowledged_through: 11,
        publications: vec![publication],
        raw_result: Some(-(libc::EFAULT as i64)),
        context: Some(context),
    });
    let expected = ExpectedError {
        weak: Arc::downgrade(&error),
        dequeues,
        publication,
        context: expected_context,
        context_address,
    };
    (Error::SharedFailure(error), expected)
}

fn assert_error(error: &Error, expected: &ExpectedError) {
    let Error::SharedFailure(error) = error else {
        panic!("driver replaced the original shared error");
    };
    assert_eq!(Arc::as_ptr(error), expected.weak.as_ptr());
    assert_eq!(
        Arc::strong_count(error),
        1,
        "test retains no spare error owner"
    );
    let Error::SignalEffects {
        cause,
        dequeues,
        acknowledged_through,
        publications,
        raw_result,
        context,
    } = error.as_ref()
    else {
        panic!("driver discarded the irreversible effects");
    };
    assert_eq!(dequeues, &expected.dequeues);
    assert_eq!(*acknowledged_through, 11);
    assert_eq!(publications.as_slice(), &[expected.publication]);
    assert_eq!(*raw_result, Some(-(libc::EFAULT as i64)));
    let context = context.as_ref().unwrap();
    assert_eq!(**context, expected.context);
    assert_eq!(
        std::ptr::from_ref(context.as_ref()) as usize,
        expected.context_address
    );
    let Error::WithCleanup { primary, cleanup } = cause.as_ref() else {
        panic!("driver flattened the original typed error tree");
    };
    assert!(
        matches!(primary.as_ref(), Error::HostIo(error) if error.raw_os_error() == Some(libc::EAGAIN))
    );
    assert_eq!(cleanup.len(), 1);
    assert!(
        matches!(cleanup[0].as_ref(), Error::GuestClock(message) if message == "earlier cleanup")
    );
}

#[derive(Default)]
struct Counts {
    polls: AtomicUsize,
    drops: AtomicUsize,
    failure_drops: AtomicUsize,
}

struct Payload {
    label: &'static str,
    _send_only: Cell<u8>,
}

fn payload(label: &'static str) -> (PanicPayload, usize) {
    let payload = Box::new(Payload {
        label,
        _send_only: Cell::new(7),
    });
    let address = std::ptr::from_ref(payload.as_ref()) as usize;
    (payload, address)
}

struct Callback {
    signal: SharedHandlerSignal,
    error: Option<Error>,
    weak: Weak<Error>,
    failure_ready: Arc<AtomicBool>,
    counts: Arc<Counts>,
    poll_panic: Option<PanicPayload>,
    drop_panic: Option<PanicPayload>,
}

impl Future for Callback {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        assert_eq!(this.counts.polls.fetch_add(1, Ordering::SeqCst), 0);
        let mut signal = this.signal.lock().unwrap();
        assert!(signal.is_none());
        *signal = Some(HandlerSignal::RuntimeError(this.error.take().unwrap()));
        if let Some(payload) = this.poll_panic.take() {
            // Poison the actual shared slot after transferring the only strong
            // error owner. Recovery must retain it before running our Drop.
            resume_unwind(payload);
        }
        drop(signal);
        this.failure_ready.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        assert_eq!(self.counts.drops.fetch_add(1, Ordering::SeqCst), 0);
        assert!(self.error.is_none());
        let retained = self
            .weak
            .upgrade()
            .expect("callback Drop lost the original error");
        assert_eq!(Arc::strong_count(&retained), 2);
        drop(retained);
        if let Some(payload) = self.drop_panic.take() {
            resume_unwind(payload);
        }
    }
}

struct Failure {
    ready: Arc<AtomicBool>,
    counts: Arc<Counts>,
    drop_panic: Option<PanicPayload>,
}

impl Future for Failure {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.ready.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Failure {
    fn drop(&mut self) {
        assert_eq!(self.counts.drops.load(Ordering::SeqCst), 1);
        assert_eq!(self.counts.failure_drops.fetch_add(1, Ordering::SeqCst), 0);
        if let Some(payload) = self.drop_panic.take() {
            resume_unwind(payload);
        }
    }
}

fn check_completion(poll_panics: bool, callback_drop_panics: bool, failure_drop_panics: bool) {
    let (error, expected) = owned_error();
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let (sender, receiver) = std::sync::mpsc::channel();
    let gate = ChildStartGate::new(sender);
    starts
        .lock()
        .unwrap()
        .push(PendingChildStart::tool_thread(77, gate.clone()));
    let counts = Arc::new(Counts::default());
    let failure_ready = Arc::new(AtomicBool::new(false));
    let mut expected_payloads = Vec::new();
    let mut make_payload = |enabled: bool, label: &'static str| {
        enabled.then(|| {
            let (payload, address) = payload(label);
            expected_payloads.push((address, label));
            payload
        })
    };
    let callback = Callback {
        signal: signal.clone(),
        error: Some(error),
        weak: expected.weak.clone(),
        failure_ready: failure_ready.clone(),
        counts: counts.clone(),
        poll_panic: make_payload(poll_panics, "poll"),
        drop_panic: make_payload(callback_drop_panics, "callback drop"),
    };
    let failure = Failure {
        ready: failure_ready,
        counts: counts.clone(),
        drop_panic: make_payload(failure_drop_panics, "failure drop"),
    };
    let mut driven = Box::pin(drive_handler_completion(
        callback,
        signal.clone(),
        starts.clone(),
        failure,
    ));
    fn require_send<T: Send>(_: &T) {}
    require_send(&driven);
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
        panic!("terminal callback remained pending");
    };
    drop(driven);
    assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.failure_drops.load(Ordering::SeqCst), 1);
    assert_eq!(signal.is_poisoned(), poll_panics);
    assert!(
        signal
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_none()
    );
    assert_eq!(starts.lock().unwrap().len(), 1);
    assert!(
        gate.is_pending(),
        "driver started a child after error or panic"
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let Some(HandlerOutcome::RuntimeError(ref error)) = completion.output else {
        panic!("bare cancellation or panic replaced the owned RuntimeError");
    };
    assert_error(error, &expected);
    assert_eq!(completion.panics.len(), expected_payloads.len());
    for (actual, (address, label)) in completion.panics.iter().zip(expected_payloads) {
        let actual = actual.downcast_ref::<Payload>().unwrap();
        assert_eq!(std::ptr::from_ref(actual) as usize, address);
        assert_eq!(actual.label, label);
    }
    drop(completion);
    assert!(
        expected.weak.upgrade().is_none(),
        "test leaked the original error owner"
    );
}

#[test]
fn owned_runtime_error_survives_actual_callback_destructor_panic() {
    check_completion(false, true, false);
}

#[test]
fn owned_runtime_error_survives_normal_callback_destruction() {
    check_completion(false, false, false);
}

#[test]
fn polling_panic_recovers_owned_error_before_callback_destructor_panic() {
    check_completion(true, true, false);
}

#[test]
fn owned_runtime_error_survives_failure_future_destructor_panic() {
    check_completion(false, false, true);
}

#[test]
fn selected_runtime_error_survives_discarded_ready_value_panic() {
    struct ReturnedValue {
        weak: Weak<Error>,
        payload: Option<PanicPayload>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for ReturnedValue {
        fn drop(&mut self) {
            assert_eq!(self.dropped.fetch_add(1, Ordering::SeqCst), 0);
            assert!(self.weak.upgrade().is_some());
            resume_unwind(self.payload.take().unwrap());
        }
    }

    let (error, expected) = owned_error();
    let (panic, address) = payload("discarded ready value");
    let dropped = Arc::new(AtomicUsize::new(0));
    let value = ReturnedValue {
        weak: expected.weak.clone(),
        payload: Some(panic),
        dropped: dropped.clone(),
    };
    let signal = Arc::new(Mutex::new(None));
    let callback_signal = signal.clone();
    let ready = Arc::new(AtomicBool::new(false));
    let callback_ready = ready.clone();
    let callback = async move {
        *callback_signal.lock().unwrap() = Some(HandlerSignal::RuntimeError(error));
        callback_ready.store(true, Ordering::SeqCst);
        value
    };
    let failure = poll_fn(move |_| {
        if ready.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    });
    let mut driven = Box::pin(drive_handler_completion(
        callback,
        signal.clone(),
        Arc::new(Mutex::new(Vec::new())),
        failure,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
        panic!("discarding a ready value left the callback pending");
    };
    drop(driven);
    let Some(HandlerOutcome::RuntimeError(ref error)) = completion.output else {
        panic!("discarding a ready value lost the selected RuntimeError");
    };
    assert_error(error, &expected);
    assert!(signal.lock().unwrap().is_none());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(completion.panics.len(), 1);
    let actual = completion.panics[0].downcast_ref::<Payload>().unwrap();
    assert_eq!(std::ptr::from_ref(actual) as usize, address);
    assert_eq!(actual.label, "discarded ready value");
    drop(completion);
    assert!(expected.weak.upgrade().is_none());
}

#[test]
fn constructor_panic_recovers_owned_signal_before_failure_future_destruction() {
    struct ConstructionFailure {
        signal: SharedHandlerSignal,
        weak: Weak<Error>,
        counts: Arc<Counts>,
        polls: Arc<AtomicUsize>,
        drop_panic: Option<PanicPayload>,
    }

    impl Future for ConstructionFailure {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            panic!("construction failure must not poll the failure future");
        }
    }

    impl Drop for ConstructionFailure {
        fn drop(&mut self) {
            assert_eq!(self.counts.polls.load(Ordering::SeqCst), 0);
            assert_eq!(self.counts.drops.load(Ordering::SeqCst), 0);
            assert_eq!(self.polls.load(Ordering::SeqCst), 0);
            assert_eq!(self.counts.failure_drops.fetch_add(1, Ordering::SeqCst), 0);
            assert!(self.signal.is_poisoned());
            assert!(
                self.signal
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_none(),
                "constructor outcome was not recovered before failure destruction"
            );
            let retained = self
                .weak
                .upgrade()
                .expect("constructor error was discarded");
            assert_eq!(Arc::strong_count(&retained), 2);
            drop(retained);
            if let Some(payload) = self.drop_panic.take() {
                resume_unwind(payload);
            }
        }
    }

    for failure_drop_panics in [false, true] {
        let (error, expected) = owned_error();
        let signal = Arc::new(Mutex::new(None));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(sender);
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(77, gate.clone()));
        let counts = Arc::new(Counts::default());
        let constructions = Arc::new(AtomicUsize::new(0));
        let failure_polls = Arc::new(AtomicUsize::new(0));
        let (constructor_payload, constructor_address) = payload("callback constructor");
        let mut expected_payloads = vec![(constructor_address, "callback constructor")];
        let failure_payload = failure_drop_panics.then(|| {
            let (payload, address) = payload("failure drop after constructor");
            expected_payloads.push((address, "failure drop after constructor"));
            payload
        });
        let failure = ConstructionFailure {
            signal: signal.clone(),
            weak: expected.weak.clone(),
            counts: counts.clone(),
            polls: failure_polls.clone(),
            drop_panic: failure_payload,
        };
        let callback_signal = signal.clone();
        let constructor_calls = constructions.clone();
        // This is synchronous construction, not an async block whose first
        // poll panics. No Callback allocation is created or returned.
        let build = move || -> Callback {
            assert_eq!(constructor_calls.fetch_add(1, Ordering::SeqCst), 0);
            let mut slot = callback_signal.lock().unwrap();
            assert!(slot.is_none());
            *slot = Some(HandlerSignal::RuntimeError(error));
            // Transfer the only strong error owner, then poison the real slot.
            resume_unwind(constructor_payload);
        };
        let mut driven = Box::pin(drive_handler_completion_from(
            build,
            signal.clone(),
            starts.clone(),
            failure,
        ));
        fn require_send<T: Send>(_: &T) {}
        require_send(&driven);
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
            panic!("failed callback construction stayed pending");
        };
        drop(driven);
        assert_eq!(constructions.load(Ordering::SeqCst), 1);
        assert_eq!(counts.polls.load(Ordering::SeqCst), 0);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 0);
        assert_eq!(failure_polls.load(Ordering::SeqCst), 0);
        assert_eq!(counts.failure_drops.load(Ordering::SeqCst), 1);
        assert!(signal.is_poisoned());
        assert!(
            signal
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
        );
        assert_eq!(starts.lock().unwrap().len(), 1);
        assert!(gate.is_pending(), "constructor panic started a child");
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let Some(HandlerOutcome::RuntimeError(ref error)) = completion.output else {
            panic!("construction panic replaced the transferred RuntimeError");
        };
        assert_error(error, &expected);
        assert_eq!(completion.panics.len(), expected_payloads.len());
        for (actual, (address, label)) in completion.panics.iter().zip(expected_payloads) {
            let actual = actual.downcast_ref::<Payload>().unwrap();
            assert_eq!(std::ptr::from_ref(actual) as usize, address);
            assert_eq!(actual.label, label);
        }
        drop(completion);
        assert!(expected.weak.upgrade().is_none());
    }
}
