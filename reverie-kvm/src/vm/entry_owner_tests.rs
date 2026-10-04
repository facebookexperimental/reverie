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
    let mut child = KvmBackend::new_with_memory_and_cpuid_policy(
        parent.memory.clone(),
        CpuidPolicy::default(),
        None,
    )
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
