/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Finite private-driver controls. KVM setup only; no guest entry.

use std::panic::resume_unwind;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;

use futures::task::ArcWake;

use super::*;
use crate::entry::owner::OperationOrigin;
use crate::failure::owned_future::PanicPayload;

#[derive(Default)]
struct Counts {
    polls: AtomicUsize,
    drops: AtomicUsize,
    wakes: AtomicUsize,
}

impl ArcWake for Counts {
    fn wake_by_ref(this: &Arc<Self>) {
        this.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

struct PendingCallback {
    counts: Arc<Counts>,
    origin: OperationOrigin,
}

impl Future for PendingCallback {
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(self.counts.polls.fetch_add(1, Ordering::SeqCst), 0);
        Poll::Pending
    }
}

impl Drop for PendingCallback {
    fn drop(&mut self) {
        assert!(!self.origin.callback_dropped());
        assert_eq!(self.counts.drops.fetch_add(1, Ordering::SeqCst), 0);
    }
}

fn backend() -> KvmBackend {
    KvmBackend::new(0x10000).expect("entry owner controls require /dev/kvm")
}

#[test]
fn private_entry_failure_wakes_pending_callback_before_scope_acknowledgement() {
    let mut backend = backend();
    let driver = backend.start_entry_driver();
    let callback = backend.begin_entry_callback().unwrap().unwrap();
    let origin = callback.origin();
    let memory = backend.memory.clone();
    let watch = backend.entry_driver_watch();
    let counts = Arc::new(Counts::default());
    let probe = PendingCallback {
        counts: counts.clone(),
        origin: origin.clone(),
    };
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut driven = Box::pin(drive_entry_handler_completion_from(
        || probe,
        signal,
        starts,
        std::future::pending(),
        watch.clone(),
    ));
    let waker = futures::task::waker(counts.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(driven.as_mut().poll(&mut cx).is_pending());
    assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 0);
    let failure = memory.entry_gate().poison(
        memory.entry_origin(),
        Error::GuestClock("private wake".into()),
    );
    assert!(counts.wakes.load(Ordering::SeqCst) > 0);
    let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
        panic!("private cause did not end callback polling");
    };
    drop(driven);
    assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    assert!(!origin.callback_dropped());
    assert!(completion.panics.is_empty());
    drop(callback);
    backend.restore_entry_origin();
    assert!(origin.callback_dropped());
    let result = futures::executor::block_on(backend.finish_entry_handler_completion(
        completion,
        Ok(()),
        |error| error,
        &watch,
    ))
    .unwrap();
    let HandlerOutcome::RuntimeError(error) = result else {
        panic!("private failure was hidden");
    };
    assert!(error.retains_primary(&failure.causes()[0]));
    let retired = backend.finish_entry_driver(driver, Err::<(), _>(error));
    assert!(retired.unwrap_err().retains_primary(&failure.causes()[0]));
}

struct DropPanic {
    payload: Option<PanicPayload>,
    drops: Arc<AtomicUsize>,
}

impl Drop for DropPanic {
    fn drop(&mut self) {
        assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
        resume_unwind(self.payload.take().unwrap());
    }
}

struct UnpolledFailure {
    _guard: DropPanic,
}
impl Future for UnpolledFailure {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        panic!("pre-construction failure must not poll failure future");
    }
}

#[test]
fn existing_entry_failure_skips_factory_and_retains_both_destructor_payloads() {
    let mut backend = backend();
    let driver = backend.start_entry_driver();
    let callback = backend.begin_entry_callback().unwrap().unwrap();
    let watch = backend.entry_driver_watch();
    let memory = backend.memory.clone();
    let failure = memory.entry_gate().poison(
        memory.entry_origin(),
        Error::GuestClock("before factory".into()),
    );
    let build_calls = Arc::new(AtomicUsize::new(0));
    let builder_drops = Arc::new(AtomicUsize::new(0));
    let failure_drops = Arc::new(AtomicUsize::new(0));
    let first = Box::new(201_u64);
    let first_address = std::ptr::from_ref(first.as_ref()) as usize;
    let second = Box::new(202_u64);
    let second_address = std::ptr::from_ref(second.as_ref()) as usize;
    let guard = DropPanic {
        payload: Some(first),
        drops: builder_drops.clone(),
    };
    let calls = build_calls.clone();
    let build = move || {
        let _guard = guard;
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<()>>()
    };
    let completion = futures::executor::block_on(drive_entry_handler_completion_from(
        build,
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(Vec::new())),
        UnpolledFailure {
            _guard: DropPanic {
                payload: Some(second),
                drops: failure_drops.clone(),
            },
        },
        watch,
    ));
    assert_eq!(build_calls.load(Ordering::SeqCst), 0);
    assert_eq!(builder_drops.load(Ordering::SeqCst), 1);
    assert_eq!(failure_drops.load(Ordering::SeqCst), 1);
    assert_eq!(completion.panics.len(), 2);
    for (actual, address, value) in [
        (&completion.panics[0], first_address, 201),
        (&completion.panics[1], second_address, 202),
    ] {
        let actual = actual.downcast_ref::<u64>().unwrap();
        assert_eq!(std::ptr::from_ref(actual) as usize, address);
        assert_eq!(*actual, value);
    }
    let Some(HandlerOutcome::RuntimeError(error)) = completion.output else {
        panic!("dropping the uncalled factory lost the typed entry cause");
    };
    assert!(error.retains_primary(&failure.causes()[0]));
    drop(callback);
    backend.restore_entry_origin();
    assert!(
        backend
            .finish_entry_driver(driver, Err::<(), _>(error))
            .is_err()
    );
}

#[test]
fn ready_typed_error_survives_entry_failure_and_outer_mapping() {
    let mut backend = backend();
    let driver = backend.start_entry_driver();
    let callback = backend.begin_entry_callback().unwrap().unwrap();
    let memory = backend.memory.clone();
    let watch = backend.entry_driver_watch();
    let original = Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
        libc::ENOSPC,
    )));
    let weak = Arc::downgrade(&original);
    let mut original = Some(Error::SharedFailure(original));
    let calls = Arc::new(AtomicUsize::new(0));
    let polls = calls.clone();
    let future = poll_fn(move |_| {
        assert_eq!(polls.fetch_add(1, Ordering::SeqCst), 0);
        memory.entry_gate().poison(
            memory.entry_origin(),
            Error::GuestClock("after Ready".into()),
        );
        Poll::Ready(Err::<(), _>(original.take().unwrap()))
    });
    let mut driven = Box::pin(drive_entry_handler_completion_from(
        || future,
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(Vec::new())),
        std::future::pending(),
        watch.clone(),
    ));
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
        panic!("Ready error stayed pending");
    };
    drop(driven);
    assert!(matches!(
        &completion.output,
        Some(HandlerOutcome::Returned(Err(_)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(completion.panics.is_empty());
    drop(callback);
    backend.restore_entry_origin();
    let result = futures::executor::block_on(backend.finish_entry_handler_completion(
        completion,
        Ok(()),
        |error| error,
        &watch,
    ))
    .unwrap();
    let HandlerOutcome::RuntimeError(error) = result else {
        panic!("entry cause was ignored");
    };
    let expected = weak.upgrade().expect("typed callback error was lost");
    assert!(error.retains_primary(&expected));
    assert!(
        matches!(expected.as_ref(), Error::HostIo(error) if error.raw_os_error() == Some(libc::ENOSPC))
    );
    let gate = backend.memory.entry_gate().pending_failure().unwrap();
    assert!(crate::failure::references_shared_error(
        &error,
        &gate.causes()[0]
    ));
    drop(expected);
    drop(backend.finish_entry_driver(driver, Err::<(), _>(error)));
    assert!(weak.upgrade().is_none());
}
