/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A thread's kept callback slots never carry anything into the next callback.
//!
//! Each test leaves in the slots what one event leaves there in a real
//! callback (a child start from clone, fork or vfork, a handler outcome from
//! exec, exit or a signal, a reference kept by a child or a waiter) and checks
//! that the next callback gets new, empty slots, while the event's own state
//! is dropped exactly when the callback ends, as it was before slots were
//! kept. The descriptor table is not in the context at all; its test checks
//! that the context's slots are the same objects before and after a change.

use std::sync::mpsc::TryRecvError;

use super::*;

fn gate() -> (ChildStartGate, std::sync::mpsc::Receiver<ChildStartCommand>) {
    let (sender, receiver) = std::sync::mpsc::channel();
    (ChildStartGate::new(sender), receiver)
}

fn signal_context() -> reverie::ParkedSignalFailureContext {
    reverie::ParkedSignalFailureContext {
        site: reverie::CallbackSignalSite {
            process: reverie::SignalProcessId {
                tgid: reverie::Pid::from_raw(1),
                generation: 2,
            },
            tid: reverie::Pid::from_raw(1),
            task_generation: 3,
            callback_nonce: 7,
            boundary_nonce: 8,
        },
        ledger_nonce: 8,
    }
}

/// One callback that leaves `signal` and `starts` behind. Returns whether
/// the context kept each slot (a slot not kept was dropped when returned),
/// after checking that the next callback's slots are empty either way.
fn after_callback(
    context: &mut CallbackContext,
    signal: Option<HandlerSignal>,
    starts: Vec<PendingChildStart>,
) -> (bool, bool) {
    let (handler_signal, pending_child_starts) = context.begin();
    let pointers = (
        Arc::as_ptr(&handler_signal),
        Arc::as_ptr(&pending_child_starts),
    );
    *handler_signal.lock().unwrap() = signal;
    pending_child_starts.lock().unwrap().extend(starts);
    context.keep_handler_signal(handler_signal);
    context.keep_child_starts(pending_child_starts);
    let kept = (
        context
            .handler_signal
            .as_ref()
            .is_some_and(|slot| Arc::as_ptr(slot) == pointers.0),
        context
            .pending_child_starts
            .as_ref()
            .is_some_and(|slot| Arc::as_ptr(slot) == pointers.1),
    );
    assert_eq!(kept.0, context.handler_signal.is_some());
    assert_eq!(kept.1, context.pending_child_starts.is_some());
    let (handler_signal, pending_child_starts) = context.begin();
    assert!(handler_signal.lock().unwrap().is_none());
    assert!(pending_child_starts.lock().unwrap().is_empty());
    context.keep_handler_signal(handler_signal);
    context.keep_child_starts(pending_child_starts);
    kept
}

#[test]
fn an_ordinary_callback_keeps_both_slots_for_the_next() {
    let mut context = CallbackContext::default();
    let (kept_signal, kept_starts) = after_callback(&mut context, None, Vec::new());
    assert!(kept_signal && kept_starts);
    // Many callbacks in a row reuse the same two objects.
    let (signal, starts) = context.begin();
    let pointers = (Arc::as_ptr(&signal), Arc::as_ptr(&starts));
    for _ in 0..16 {
        context.keep_handler_signal(signal.clone());
        context.keep_child_starts(starts.clone());
        // The clones above are still alive: not kept.
        let (fresh_signal, fresh_starts) = context.begin();
        assert_ne!(Arc::as_ptr(&fresh_signal), pointers.0);
        assert_ne!(Arc::as_ptr(&fresh_starts), pointers.1);
    }
    context.keep_handler_signal(signal);
    context.keep_child_starts(starts);
    let (signal, starts) = context.begin();
    assert_eq!((Arc::as_ptr(&signal), Arc::as_ptr(&starts)), pointers);
}

#[test]
fn a_thread_clone_child_start_is_not_kept() {
    let mut context = CallbackContext::default();
    let (start, receiver) = gate();
    let (kept_signal, kept_starts) = after_callback(
        &mut context,
        None,
        vec![PendingChildStart::tool_thread(12, start)],
    );
    assert!(kept_signal);
    assert!(!kept_starts);
    // Dropped when its callback returned the slot, not at the next one.
    assert!(matches!(
        receiver.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
}

#[test]
fn a_process_clone_or_fork_child_start_is_not_kept() {
    let mut context = CallbackContext::default();
    let (start, receiver) = gate();
    let (kept_signal, kept_starts) = after_callback(
        &mut context,
        None,
        vec![PendingChildStart::fork_process(13, start)],
    );
    assert!(kept_signal);
    assert!(!kept_starts);
    assert!(matches!(
        receiver.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
}

#[test]
fn a_vfork_child_holding_the_slot_keeps_it_from_the_context() {
    // A vfork child's start, and anything else still holding the slot past
    // its callback, shares it: the context must not take it back.
    let mut context = CallbackContext::default();
    let (handler_signal, pending_child_starts) = context.begin();
    let (start, receiver) = gate();
    pending_child_starts
        .lock()
        .unwrap()
        .push(PendingChildStart::fork_process(14, start));
    let held = pending_child_starts.clone();
    pending_child_starts.lock().unwrap().clear();
    context.keep_handler_signal(handler_signal);
    context.keep_child_starts(pending_child_starts);
    let (_, next_starts) = context.begin();
    assert!(!Arc::ptr_eq(&next_starts, &held));
    // The holder's slot is untouched by the next callback's.
    next_starts
        .lock()
        .unwrap()
        .push(PendingChildStart::fork_process(15, gate().0));
    assert!(held.lock().unwrap().is_empty());
    assert!(matches!(
        receiver.try_recv(),
        Err(TryRecvError::Disconnected)
    ));
}

#[test]
fn an_exec_outcome_is_not_kept() {
    let mut context = CallbackContext::default();
    let (kept_signal, kept_starts) = after_callback(
        &mut context,
        Some(HandlerSignal::TailInjected {
            result: Ok(0),
            image_replaced: true,
            process_exited: false,
        }),
        Vec::new(),
    );
    assert!(!kept_signal);
    assert!(kept_starts);
}

#[test]
fn exit_outcomes_are_not_kept_and_thread_exit_drops_the_context() {
    for signal in [
        HandlerSignal::GroupExit(ExitStatus::Exited(3)),
        HandlerSignal::ThreadRetired,
        HandlerSignal::ThreadCancelled,
        HandlerSignal::TailInjected {
            result: Ok(0),
            image_replaced: false,
            process_exited: true,
        },
    ] {
        let mut context = CallbackContext::default();
        let (kept_signal, _) = after_callback(&mut context, Some(signal), Vec::new());
        assert!(!kept_signal);
    }
    // The context lives in the thread's run loop: when the thread exits, it
    // goes with it, and with it only the empty slots it kept.
    let mut context = CallbackContext::default();
    let (signal, starts) = context.begin();
    let weak = (Arc::downgrade(&signal), Arc::downgrade(&starts));
    context.keep_handler_signal(signal);
    context.keep_child_starts(starts);
    drop(context);
    assert!(weak.0.upgrade().is_none() && weak.1.upgrade().is_none());
}

#[test]
fn signal_delivery_outcomes_are_not_kept() {
    for signal in [
        HandlerSignal::ParkedRetired(signal_context()),
        HandlerSignal::ParkedCancelled(signal_context()),
        HandlerSignal::RuntimeError(Error::RunAborted),
    ] {
        let mut context = CallbackContext::default();
        let (kept_signal, kept_starts) = after_callback(&mut context, Some(signal), Vec::new());
        assert!(!kept_signal);
        assert!(kept_starts);
    }
}

#[test]
fn a_poisoned_slot_is_not_kept() {
    let mut context = CallbackContext::default();
    let (handler_signal, pending_child_starts) = context.begin();
    let poison = handler_signal.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poison.lock().unwrap();
        panic!("poison the handler slot");
    })
    .join();
    assert!(handler_signal.is_poisoned());
    assert!(
        handler_signal
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    );
    context.keep_handler_signal(handler_signal);
    context.keep_child_starts(pending_child_starts);
    assert!(context.handler_signal.is_none());
    assert!(context.pending_child_starts.is_some());
    let (next, _) = context.begin();
    assert!(!next.is_poisoned());
}

#[test]
fn a_descriptor_table_change_reaches_nothing_the_context_keeps() {
    // The context holds two empty slots and nothing about descriptors. A
    // table change between callbacks leaves them as they were, and the next
    // callback's slots are still empty.
    let mut context = CallbackContext::default();
    let (signal, starts) = context.begin();
    let pointers = (Arc::as_ptr(&signal), Arc::as_ptr(&starts));
    context.keep_handler_signal(signal);
    context.keep_child_starts(starts);
    let mut pipe = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let duplicate = unsafe { libc::fcntl(pipe[1], libc::F_DUPFD_CLOEXEC, 0) };
    assert!(duplicate >= 0);
    for fd in [pipe[0], pipe[1], duplicate] {
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    let (signal, starts) = context.begin();
    assert_eq!((Arc::as_ptr(&signal), Arc::as_ptr(&starts)), pointers);
    assert!(signal.lock().unwrap().is_none());
    assert!(starts.lock().unwrap().is_empty());
}
