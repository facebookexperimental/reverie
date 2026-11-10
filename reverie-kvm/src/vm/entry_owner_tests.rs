/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Setup-only controls for backend owner binding and the caught-worker owner
//! boundary. These construct the callback and retained consumer; no KVM_RUN,
//! actual failed spawn, or guest callback dispatch is exercised here.

use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Poll;

use super::*;
use crate::entry::owner::DriverLifecycle;
use crate::failure::owned_future::PanicPayload;

#[test]
fn child_driver_rebinds_inherited_callback_view_and_preserves_generation() {
    let mut parent = KvmBackend::new(0x10000).expect("owner binding control requires /dev/kvm");
    let parent_scope = parent.start_entry_driver();
    let parent_callback = parent.begin_entry_callback().unwrap().unwrap();
    let parent_view = parent.memory.clone();
    let parent_origin = parent_view.entry_origin().operation.unwrap();
    let mut child = KvmBackend::new_with_memory(parent.memory.clone(), None)
        .expect("child binding control requires /dev/kvm");
    assert!(child.entry_driver_owner().is_none());
    assert!(
        child
            .memory
            .entry_origin()
            .operation
            .unwrap()
            .same_callback(&parent_origin)
    );

    let child_scope = child.start_entry_driver();
    let child_owner = child.entry_driver_owner().unwrap();
    let ordinary = child.memory.entry_origin().operation.unwrap();
    assert!(ordinary.same_driver(&child_owner.origin()));
    assert!(!ordinary.same_driver(&parent_origin));
    assert_eq!(ordinary.callback_id(), None);

    let first = child.begin_entry_callback().unwrap().unwrap();
    let retained = child.memory.clone();
    let first_origin = retained.entry_origin().operation.unwrap();
    drop(first);
    child.restore_entry_origin();
    let second = child.begin_entry_callback().unwrap().unwrap();
    let second_origin = child.memory.entry_origin().operation.unwrap();
    assert!(first_origin.same_driver(&second_origin));
    assert!(!first_origin.same_callback(&second_origin));
    assert!(first_origin.callback_dropped());
    assert!(!second_origin.callback_dropped());
    assert!(
        retained
            .entry_origin()
            .operation
            .unwrap()
            .same_callback(&first_origin)
    );
    assert!(!parent_origin.callback_dropped());
    drop(second);
    child.restore_entry_origin();
    child.finish_entry_driver(child_scope, Ok(())).unwrap();
    assert_eq!(child_owner.lifecycle(), DriverLifecycle::Retired);
    assert!(child.entry_driver_owner().is_none());
    assert!(child.memory.entry_origin().operation.is_none());
    assert!(!parent_origin.callback_dropped());
    drop(parent_callback);
    parent.restore_entry_origin();
    parent.finish_entry_driver(parent_scope, Ok(())).unwrap();
    assert_eq!(parent_origin.lifecycle(), DriverLifecycle::Retired);
}

fn same_part<T>(left: Option<&T>, right: Option<&T>, same: impl Fn(&T, &T) -> bool) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => same(left, right),
        (None, None) => true,
        _ => false,
    }
}

/// The same failure context and the same operation origin, by identity.
fn same_entry_origin(left: &crate::entry::EntryOrigin, right: &crate::entry::EntryOrigin) -> bool {
    same_part(
        left.failure.as_ref(),
        right.failure.as_ref(),
        crate::failure::FailureContext::same_as,
    ) && same_part(
        left.operation.as_ref(),
        right.operation.as_ref(),
        crate::entry::owner::OperationOrigin::same_as,
    )
}

/// What the participant held before it took its attribution by move: a copy
/// of the vCPU handle's attribution after each set, which every set made
/// equal to the backend handle's.
#[track_caller]
fn assert_participant_matches_backend(backend: &KvmBackend, step: &str) {
    assert!(
        same_entry_origin(
            backend.vcpu.participant_origin(),
            &backend.memory.entry_origin()
        ),
        "{step}"
    );
    let handle = backend.vcpu.handle_origin();
    assert!(
        handle.failure.is_none() && handle.operation.is_none(),
        "{step}: the vCPU handle kept a copy"
    );
}

fn failure_context(
    run: &Arc<crate::failure::RunFailure>,
    tid: i32,
) -> crate::failure::FailureContext {
    crate::failure::FailureContext::new(run.clone(), Pid::from_raw(1), Pid::from_raw(tid))
}

/// Every failure the vCPU's participant records is attributed to exactly what
/// it was before its origin was moved in rather than copied: the backend
/// handle's failure context and operation origin, as of the last set, through
/// the driver origin, each callback, a nested callback and the restore of the
/// enclosing one, failure-context changes inside a callback, and retirement.
#[test]
fn the_vcpu_participant_records_the_backend_attribution_after_every_set() {
    let mut backend =
        KvmBackend::new(0x10000).expect("participant origin control requires /dev/kvm");
    let unset = backend.vcpu.participant_origin();
    assert!(unset.failure.is_none() && unset.operation.is_none());
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    let failure = failure_context(&run, 1);
    backend.set_tool_failure(Some(failure.clone()));
    assert_participant_matches_backend(&backend, "tool failure");
    let driver = backend.start_entry_driver();
    assert_participant_matches_backend(&backend, "driver");
    let owner = backend.entry_driver_owner().unwrap();
    let operation =
        |backend: &KvmBackend| backend.vcpu.participant_origin().operation.clone().unwrap();
    assert!(operation(&backend).same_as(&owner.origin()));
    for round in 0..3 {
        let callback = backend.begin_entry_callback().unwrap().unwrap();
        assert_participant_matches_backend(&backend, "callback");
        assert!(operation(&backend).same_as(&callback.origin()), "{round}");
        let nested = owner.begin_callback(Some(&callback.origin())).unwrap();
        backend.set_operation_origin(Some(nested.origin()));
        assert_participant_matches_backend(&backend, "nested");
        assert!(operation(&backend).same_as(&nested.origin()), "{round}");
        backend.set_operation_origin(Some(callback.origin()));
        assert_participant_matches_backend(&backend, "enclosing restored");
        assert!(operation(&backend).same_as(&callback.origin()), "{round}");
        drop(nested);
        if round == 1 {
            backend.set_tool_failure(Some(failure.for_thread(Pid::from_raw(2))));
            assert_participant_matches_backend(&backend, "failure in callback");
            assert!(operation(&backend).same_as(&callback.origin()));
            backend.set_tool_failure(Some(failure.clone()));
            assert_participant_matches_backend(&backend, "failure restored");
        }
        drop(callback);
        backend.restore_entry_origin();
        assert_participant_matches_backend(&backend, "callback ended");
        assert!(operation(&backend).same_as(&owner.origin()), "{round}");
    }
    backend.set_tool_failure(None);
    assert_participant_matches_backend(&backend, "no tool failure");
    backend.finish_entry_driver(driver, Ok(())).unwrap();
    assert_participant_matches_backend(&backend, "retired");
    let retired = backend.vcpu.participant_origin();
    assert!(retired.failure.is_none() && retired.operation.is_none());
}

/// A vCPU made from a handle that already carries attribution (a fork
/// child's inherited memory) starts with an empty participant, as before.
/// Its first set gives the participant the part that set names and the
/// handle's other part, which it used to read back from its own handle;
/// later sets replace one part each.
#[test]
fn a_new_vcpu_takes_the_part_its_first_set_does_not_name_from_its_handle() {
    for first in ["operation", "failure"] {
        let mut parent =
            KvmBackend::new(0x10000).expect("participant seed control requires /dev/kvm");
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        let inherited_failure = failure_context(&run, 1);
        parent.set_tool_failure(Some(inherited_failure.clone()));
        let parent_scope = parent.start_entry_driver();
        let parent_callback = parent.begin_entry_callback().unwrap().unwrap();
        let inherited = parent.memory.entry_origin();
        let mut child = KvmBackend::new_with_memory(parent.memory.clone(), None)
            .expect("participant seed control requires /dev/kvm");
        let unset = child.vcpu.participant_origin();
        assert!(
            unset.failure.is_none() && unset.operation.is_none(),
            "{first}"
        );
        let handle = child.vcpu.handle_origin();
        assert!(
            handle.failure.is_none() && handle.operation.is_none(),
            "{first}"
        );
        assert!(same_entry_origin(&child.memory.entry_origin(), &inherited));

        let own_failure = failure_context(&run, 2);
        let child_scope = match first {
            "operation" => {
                let scope = child.start_entry_driver();
                let origin = child.vcpu.participant_origin();
                assert!(origin.failure.as_ref().unwrap().same_as(&inherited_failure));
                assert!(
                    origin
                        .operation
                        .as_ref()
                        .unwrap()
                        .same_as(&child.entry_driver_owner().unwrap().origin())
                );
                Some(scope)
            }
            _ => {
                child.set_tool_failure(Some(own_failure.clone()));
                let origin = child.vcpu.participant_origin();
                assert!(origin.failure.as_ref().unwrap().same_as(&own_failure));
                assert!(
                    origin
                        .operation
                        .as_ref()
                        .unwrap()
                        .same_as(inherited.operation.as_ref().unwrap())
                );
                None
            }
        };
        assert_participant_matches_backend(&child, first);
        // Every later set replaces only the part it names.
        child.set_tool_failure(Some(own_failure.clone()));
        assert_participant_matches_backend(&child, "then failure");
        child.set_operation_origin(Some(parent_callback.origin()));
        assert_participant_matches_backend(&child, "then operation");
        child.set_operation_origin(None);
        assert_participant_matches_backend(&child, "then no operation");
        if let Some(scope) = child_scope {
            child.finish_entry_driver(scope, Ok(())).unwrap();
            assert_participant_matches_backend(&child, "child retired");
        }
        drop(child);
        drop(parent_callback);
        parent.restore_entry_origin();
        parent.finish_entry_driver(parent_scope, Ok(())).unwrap();
    }
}

struct CallbackDrop {
    payload: Option<PanicPayload>,
}

impl Future for CallbackDrop {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

impl Drop for CallbackDrop {
    fn drop(&mut self) {
        resume_unwind(self.payload.take().unwrap());
    }
}

#[test]
fn caught_worker_driver_retires_after_pending_consumer_and_before_payload_resume() {
    let mut backend = KvmBackend::new(0x10000).expect("owner unwind control requires /dev/kvm");
    backend.is_guest_thread = true;
    let group = backend.thread_group.clone();
    let state = crate::executor::native_loaded_state(Path::new("/"));
    let lifecycle = state.task_lifecycle.clone();
    let leader = ElfExecutor::new(state, false);
    let mut executor = leader.thread_child(2).unwrap();
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    backend.set_tool_failure(Some(crate::failure::FailureContext::new(
        run.clone(),
        Pid::from_raw(1),
        Pid::from_raw(2),
    )));
    let driver = backend.start_entry_driver();
    executor.bind_address_space(&backend.memory);
    let owner = backend.entry_driver_owner().unwrap();
    let callback = backend.begin_entry_callback().unwrap().unwrap();
    let origin = callback.origin();
    let cause = Arc::new(Error::GuestClock(
        "captured callback owner cause".to_owned(),
    ));
    backend.memory.entry_gate().poison(
        backend.memory.entry_origin(),
        Error::SharedFailure(cause.clone()),
    );
    let cleanup = Arc::new(Error::GuestClock(
        "retained child consumer cause".to_owned(),
    ));
    let consumer_cleanup = cleanup.clone();
    let consumer_owner = owner.clone();
    let consumer_run = run.clone();
    let consumer_lifecycle = lifecycle.clone();
    let polls = Arc::new(AtomicUsize::new(0));
    let consumer_polls = polls.clone();
    executor.retain_unstarted_tool_cleanup(Box::pin(async move {
        std::future::poll_fn(|cx| {
            assert_eq!(consumer_owner.lifecycle(), DriverLifecycle::Active);
            assert!(consumer_run.published_primary().is_some());
            assert!(consumer_lifecycle.lock().unwrap().get(2).is_some());
            match consumer_polls.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                1 => Poll::Ready(()),
                _ => panic!("completed consumer was polled again"),
            }
        })
        .await;
        Err(Error::SharedFailure(consumer_cleanup))
    }));
    let original = Box::new(0x6f776e65725f6472_u64);
    let address = std::ptr::from_ref(original.as_ref()) as usize;
    let caught = catch_unwind(AssertUnwindSafe(|| {
        // The scope is outside the owned future and acknowledges only after
        // the real future destructor starts the caught unwind.
        let _callback = callback;
        futures::executor::block_on(Box::pin(CallbackDrop {
            payload: Some(original),
        }));
    }))
    .expect_err("constructed callback destructor must panic");
    assert!(origin.callback_dropped());
    let resumed = catch_unwind(AssertUnwindSafe(|| {
        backend.finish_panicked_guest_worker_with_entry(
            &mut executor,
            2,
            caught,
            Some(driver),
            |_| Ok(()),
        );
    }))
    .expect_err("worker must resume the exact original panic");
    assert_eq!(
        std::ptr::from_ref(resumed.downcast_ref::<u64>().unwrap()) as usize,
        address
    );
    assert_eq!(owner.lifecycle(), DriverLifecycle::Retired);
    assert!(backend.entry_driver_owner().is_none());
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert!(lifecycle.lock().unwrap().get(2).is_none());
    assert!(executor.take_unstarted_tool_cleanup().is_empty());
    let diagnostic = group
        .reported_worker_panics
        .lock()
        .unwrap()
        .get(&2)
        .unwrap()
        .error
        .clone();
    assert!(crate::failure::references_shared_error(&diagnostic, &cause));
    assert!(crate::failure::references_shared_error(
        &diagnostic,
        &cleanup
    ));
}
