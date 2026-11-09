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
use crate::error::ErrorExt;
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
        &watch,
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
        &watch,
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
        &watch,
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

/// The callback watch a syscall callback builds is the watch its callback
/// memory would build (`EntryDriverWatch::for_memory`), with a driver and
/// without one, so `KvmGuest::new_with_watch` may lend it to the guest
/// handle: the same owner allocation and the same gate, by pointer.
#[test]
fn a_callback_watch_is_the_watch_its_callback_memory_would_build() {
    use crate::entry::driver::EntryDriverWatch;

    // Without a driver: no owner, no origin.
    let backend = backend();
    let watch = backend.entry_driver_watch();
    let memory = backend.memory.clone();
    assert!(watch.observes_memory(&memory));
    assert!(watch.same_as(&EntryDriverWatch::for_memory(&memory)));

    // With a driver, as the run loop's syscall callback has it.
    let mut backend = backend;
    let driver = backend.start_entry_driver();
    let callback = backend.begin_entry_callback().unwrap().unwrap();
    let watch = backend.entry_driver_watch();
    let memory = backend.memory.clone();
    assert!(watch.observes_memory(&memory));
    let built = EntryDriverWatch::for_memory(&memory);
    assert!(watch.same_as(&built));
    // A failure recorded on the gate mid-callback is seen through either.
    let failure = memory.entry_gate().poison(
        memory.entry_origin(),
        Error::GuestClock("lent watch".into()),
    );
    assert!(watch.check().is_err());
    assert!(built.check().is_err());

    // A memory whose origin is another driver's, or whose gate is another
    // mapping's, is not observed: the handle builds its own watch there.
    let other = crate::entry::owner::DriverScope::new();
    let mut foreign = memory.clone();
    foreign.set_operation_origin(Some(other.owner().origin()));
    assert!(!watch.observes_memory(&foreign));
    let elsewhere = GuestMemory::new(0, 0x4000).unwrap();
    assert!(!watch.observes_memory(&elsewhere));
    // A watch with no owner does not observe a memory with an origin, even
    // one whose driver is gone.
    let unowned = EntryDriverWatch::for_memory(&elsewhere);
    let mut gone = elsewhere.clone();
    gone.set_operation_origin(Some(
        crate::entry::owner::DriverScope::new().owner().origin(),
    ));
    assert!(!unowned.observes_memory(&gone));
    assert!(unowned.observes_memory(&elsewhere));

    drop(failure);
    drop(callback);
    backend.restore_entry_origin();
    drop(driver);
}

/// The syscall callback returns a settled outcome itself, without building
/// `route_finished_entry_handler`'s future, exactly when that future would
/// return it unchanged at its first poll.
#[test]
fn a_settled_outcome_after_a_passing_entry_check_is_returned_unrouted() {
    type Outcome = HandlerOutcome<std::result::Result<i64, reverie::Error>>;
    fn settled() -> Vec<Outcome> {
        vec![
            HandlerOutcome::Returned(Ok(7)),
            HandlerOutcome::Returned(Err(reverie::Error::Errno(Errno::EPERM))),
            HandlerOutcome::RunFailed,
            HandlerOutcome::ThreadCancelled,
            HandlerOutcome::GroupExit(ExitStatus::Exited(3)),
            HandlerOutcome::ThreadRetired,
            HandlerOutcome::TailInjected {
                result: Err(Errno::EINTR),
                image_replaced: true,
                process_exited: false,
            },
        ]
    }
    fn same(left: &Outcome, right: &Outcome) -> bool {
        match (left, right) {
            (HandlerOutcome::Returned(Ok(left)), HandlerOutcome::Returned(Ok(right))) => {
                left == right
            }
            (HandlerOutcome::Returned(Err(left)), HandlerOutcome::Returned(Err(right))) => {
                left.to_string() == right.to_string()
            }
            (HandlerOutcome::RunFailed, HandlerOutcome::RunFailed)
            | (HandlerOutcome::ThreadCancelled, HandlerOutcome::ThreadCancelled)
            | (HandlerOutcome::ThreadRetired, HandlerOutcome::ThreadRetired) => true,
            (HandlerOutcome::GroupExit(left), HandlerOutcome::GroupExit(right)) => left == right,
            (
                HandlerOutcome::TailInjected {
                    result: left,
                    image_replaced: left_image,
                    process_exited: left_exit,
                },
                HandlerOutcome::TailInjected {
                    result: right,
                    image_replaced: right_image,
                    process_exited: right_exit,
                },
            ) => (left, left_image, left_exit) == (right, right_image, right_exit),
            _ => false,
        }
    }

    let mut backend = backend();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    for (outcome, expected) in settled().into_iter().zip(settled()) {
        assert!(!entry_handler_outcome_needs_routing(&outcome, &Ok(())));
        let mut routed =
            Box::pin(backend.route_finished_entry_handler(outcome, Ok(()), Error::Reverie));
        let Poll::Ready(Ok(routed)) = routed.as_mut().poll(&mut cx) else {
            panic!("a settled outcome after a passing check was routed");
        };
        assert!(same(&routed, &expected));
    }
    // Everything else is routed: a runtime error, and any outcome after a
    // failed check.
    let runtime_error: Outcome = HandlerOutcome::RuntimeError(Error::RunAborted);
    assert!(entry_handler_outcome_needs_routing(&runtime_error, &Ok(())));
    for outcome in settled() {
        assert!(entry_handler_outcome_needs_routing(
            &outcome,
            &Err(Error::RunAborted)
        ));
    }
}
