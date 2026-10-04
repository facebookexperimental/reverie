/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Consuming signal cleanup retains its result and owns callback destruction.

use std::cell::Cell;
use std::panic::resume_unwind;
use std::sync::Weak;
use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;

use super::*;
use crate::failure::owned_future::PanicPayload;

struct Payload {
    label: &'static str,
    _send_only: Cell<u8>,
}

fn payload(label: &'static str) -> (PanicPayload, usize) {
    let value = Box::new(Payload {
        label,
        _send_only: Cell::new(1),
    });
    let address = std::ptr::from_ref(value.as_ref()) as usize;
    (value, address)
}

fn assert_payload(actual: &PanicPayload, address: usize, label: &str) {
    let actual = actual.downcast_ref::<Payload>().unwrap();
    assert_eq!(std::ptr::from_ref(actual) as usize, address);
    assert_eq!(actual.label, label);
}

#[derive(Default)]
struct Counts {
    polls: AtomicUsize,
    drops: AtomicUsize,
    failure_drops: AtomicUsize,
}

struct Cleanup {
    counts: Arc<Counts>,
    output: Option<Result<usize>>,
    transfer: Option<(SharedHandlerSignal, Error)>,
    retained: Option<Weak<Error>>,
    poll_panic: Option<PanicPayload>,
    drop_panic: Option<PanicPayload>,
}

impl Future for Cleanup {
    type Output = Result<usize>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.counts.polls.fetch_add(1, Ordering::SeqCst);
        if let Some((slot, error)) = this.transfer.take() {
            let mut slot = slot.lock().unwrap();
            assert!(slot.is_none());
            *slot = Some(HandlerSignal::RuntimeError(error));
            // Poison the actual slot after transferring the sole error owner.
            if let Some(payload) = this.poll_panic.take() {
                resume_unwind(payload);
            }
        }
        if let Some(payload) = this.poll_panic.take() {
            resume_unwind(payload);
        }
        this.output.take().map_or(Poll::Pending, Poll::Ready)
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        assert_eq!(self.counts.drops.fetch_add(1, Ordering::SeqCst), 0);
        if let Some(retained) = &self.retained {
            assert!(
                retained.upgrade().is_some(),
                "cleanup dropped its selected error"
            );
        }
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

fn effects_error() -> (Error, Weak<Error>) {
    let error = Arc::new(Error::SignalEffects {
        cause: Arc::new(Error::Reverie(Errno::EIO.into())),
        dequeues: Vec::new(),
        acknowledged_through: 17,
        publications: Vec::new(),
        raw_result: Some(-i64::from(libc::EFAULT)),
        context: None,
    });
    let weak = Arc::downgrade(&error);
    (Error::SharedFailure(error), weak)
}

fn assert_effects_error(error: &Error, expected: &Weak<Error>) {
    let Error::SharedFailure(error) = error else {
        panic!("cleanup replaced its selected error");
    };
    assert_eq!(Arc::as_ptr(error), expected.as_ptr());
    assert_eq!(Arc::strong_count(error), 1);
    assert!(matches!(error.as_ref(), Error::SignalEffects {
        cause, acknowledged_through: 17, raw_result: Some(raw), ..
    } if matches!(cause.as_ref(), Error::Reverie(reverie::Error::Errno(errno)) if *errno == Errno::EIO)
        && *raw == -i64::from(libc::EFAULT)));
}

#[test]
fn ready_cleanup_error_survives_callback_and_failure_destruction() {
    let (error, expected) = effects_error();
    let counts = Arc::new(Counts::default());
    let (callback_panic, callback_address) = payload("callback drop");
    let (failure_panic, failure_address) = payload("failure drop");
    let completion = futures::executor::block_on(drive_signal_cleanup(
        Cleanup {
            counts: counts.clone(),
            output: Some(Err(error)),
            transfer: None,
            retained: Some(expected.clone()),
            poll_panic: None,
            drop_panic: Some(callback_panic),
        },
        Arc::new(Mutex::new(None)),
        Arc::new(Mutex::new(Vec::new())),
        Failure {
            ready: Arc::new(AtomicBool::new(true)),
            counts: counts.clone(),
            drop_panic: Some(failure_panic),
        },
    ));
    let Some(HandlerOutcome::Returned(Err(error))) = &completion.output else {
        panic!("ready cleanup error was replaced by cancellation or panic");
    };
    assert_effects_error(error, &expected);
    assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.failure_drops.load(Ordering::SeqCst), 1);
    assert_eq!(completion.panics.len(), 2);
    assert_payload(&completion.panics[0], callback_address, "callback drop");
    assert_payload(&completion.panics[1], failure_address, "failure drop");

    let backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let outcome = backend
        .finish_handler_completion(completion, Ok(()), std::convert::identity)
        .unwrap();
    let HandlerOutcome::RuntimeError(Error::WithCleanup { primary, cleanup }) = outcome else {
        panic!("production finalizer lost the error or panic diagnostics");
    };
    assert_effects_error(primary.as_ref(), &expected);
    assert_eq!(cleanup.len(), 2);
    assert!(cleanup.iter().all(|error| matches!(error.as_ref(),
        Error::Cleanup { phase: "Tool callback", error }
        if matches!(error.as_ref(), Error::GuestWorkerPanic))));
    let panics = backend.tool_panic_owner().take();
    assert_eq!(panics.len(), 2);
    assert_payload(&panics[0], callback_address, "callback drop");
    assert_payload(&panics[1], failure_address, "failure drop");
    drop(primary);
    assert!(expected.upgrade().is_none());
}

#[test]
fn pending_cleanup_cancellation_catches_destruction_and_rejects_children() {
    let counts = Arc::new(Counts::default());
    let failed = Arc::new(AtomicBool::new(false));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let (callback_panic, callback_address) = payload("pending callback drop");
    let (failure_panic, failure_address) = payload("pending failure drop");
    let mut driven = Box::pin(drive_signal_cleanup(
        Cleanup {
            counts: counts.clone(),
            output: None,
            transfer: None,
            retained: None,
            poll_panic: None,
            drop_panic: Some(callback_panic),
        },
        Arc::new(Mutex::new(None)),
        starts.clone(),
        Failure {
            ready: failed.clone(),
            counts: counts.clone(),
            drop_panic: Some(failure_panic),
        },
    ));
    fn require_send<T: Send>(_: &T) {}
    require_send(&driven);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(driven.as_mut().poll(&mut cx).is_pending());
    assert_eq!(counts.drops.load(Ordering::SeqCst), 0);
    let (sender, receiver) = std::sync::mpsc::channel();
    let gate = ChildStartGate::new(sender);
    starts
        .lock()
        .unwrap()
        .push(PendingChildStart::tool_thread(3, gate.clone()));
    failed.store(true, Ordering::SeqCst);
    let Poll::Ready(completion) = driven.as_mut().poll(&mut cx) else {
        panic!("pending cleanup failed to consume cancellation");
    };
    drop(driven);
    assert!(matches!(completion.output, Some(HandlerOutcome::RunFailed)));
    assert_eq!(counts.polls.load(Ordering::SeqCst), 2);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.failure_drops.load(Ordering::SeqCst), 1);
    assert_eq!(completion.panics.len(), 2);
    assert_payload(
        &completion.panics[0],
        callback_address,
        "pending callback drop",
    );
    assert_payload(
        &completion.panics[1],
        failure_address,
        "pending failure drop",
    );
    assert!(gate.is_pending());
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let mut executor = ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new(".")),
        false,
    );
    let error = finish_signal_cleanup(&mut backend, &mut executor, completion, &starts, None)
        .expect_err("child-start violation passed production signal cleanup");
    assert!(starts.lock().unwrap().is_empty());
    assert!(gate.is_cancelled());
    assert_eq!(
        receiver.try_recv().unwrap(),
        ChildStartCommand::CancelAfterFailure
    );
    assert!(matches!(error.primary(), Error::GuestWorkerPanic));
    let Error::WithCleanup {
        primary: combined,
        cleanup: retirement,
    } = &error
    else {
        panic!("child retirement failure did not retain the callback result");
    };
    assert_eq!(retirement.len(), 1);
    assert!(matches!(retirement[0].as_ref(),
        Error::Cleanup { phase: "signal-cleanup child retirement failed", error }
        if matches!(error.as_ref(), Error::UnexpectedVcpuExit(message)
            if message.contains("unstarted KVM guest thread 3 was not registered"))));
    let Error::WithCleanup {
        primary: completion,
        cleanup: invariant,
    } = combined.as_ref()
    else {
        panic!("child-start violation did not retain the callback completion");
    };
    assert_eq!(invariant.len(), 1);
    assert!(
        matches!(invariant[0].as_ref(), Error::UnexpectedVcpuExit(message)
        if message == "signal dequeue notification created a child start despite its injection guard")
    );
    let Error::WithCleanup {
        primary,
        cleanup: destruction,
    } = completion.as_ref()
    else {
        panic!("callback destruction discarded its selected cancellation");
    };
    assert!(matches!(primary.as_ref(),
        Error::Cleanup { phase: "Tool callback", error }
        if matches!(error.as_ref(), Error::GuestWorkerPanic)));
    assert_eq!(destruction.len(), 2);
    assert!(matches!(destruction[0].as_ref(), Error::RunAborted));
    assert!(matches!(destruction[1].as_ref(),
        Error::Cleanup { phase: "Tool callback", error }
        if matches!(error.as_ref(), Error::GuestWorkerPanic)));
    let panics = backend.tool_panic_owner().take();
    assert_eq!(panics.len(), 2);
    assert_payload(&panics[0], callback_address, "pending callback drop");
    assert_payload(&panics[1], failure_address, "pending failure drop");
}

#[test]
fn poisoned_signal_cleanup_child_state_becomes_a_typed_invariant_error() {
    let starts = Arc::new(Mutex::new(Vec::new()));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = starts.lock().unwrap();
            panic!("controlled child-start lock poison");
        }))
        .is_err()
    );
    assert!(starts.is_poisoned());
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let mut executor = ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new(".")),
        false,
    );
    let completion = crate::failure::owned_future::CaughtFuture {
        output: Some(HandlerOutcome::Returned(Ok::<(), Error>(()))),
        panics: Vec::new(),
    };
    let error = finish_signal_cleanup(&mut backend, &mut executor, completion, &starts, None)
        .expect_err("poisoned child-start state passed the production invariant");
    assert!(!starts.is_poisoned());
    assert!(starts.lock().unwrap().is_empty());
    assert!(
        error
            .to_string()
            .contains("signal dequeue notification poisoned its child-start state")
    );
}

#[test]
fn signal_cleanup_publishes_effects_before_cancelling_and_joining_registered_child() {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let mut executor = ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new(".")),
        false,
    );
    executor.enable_signal_dequeues();
    let pid = Pid::from_raw(1);
    let mut info = [0_u8; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
    executor
        .defer_signal_delivery(
            SignalEvent::new(
                libc::SIGUSR1,
                info,
                reverie::SignalTarget::Thread { pid, tid: pid },
            )
            .unwrap(),
        )
        .unwrap();
    executor
        .take_pending_signal_for_delivery()
        .unwrap()
        .unwrap();
    let effect = executor.signal_dequeue_front().unwrap();

    let global = Arc::new(crate::StraceLog::default());
    let run = RunFailure::new(&global);
    backend.tool_failure = Some(FailureContext::new(run.clone(), pid, pid));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let child_pid = 41;
    let (sender, receiver) = std::sync::mpsc::channel();
    let gate = ChildStartGate::new(sender);
    let observed_publication = Arc::new(AtomicBool::new(false));
    let child_observed_publication = observed_publication.clone();
    let child_run = run.clone();
    let child = crate::executor::ChildThread::spawn(move || {
        assert_eq!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("registered child never received terminal cancellation"),
            ChildStartCommand::CancelAfterFailure
        );
        let published = child_run.published_primary().ok_or_else(|| {
            Error::UnexpectedVcpuExit(
                "child cancellation preceded parent failure publication".to_owned(),
            )
        })?;
        if !matches!(published.as_ref(), Error::SignalEffects { .. }) {
            return Err(Error::UnexpectedVcpuExit(
                "child cancellation preceded parent signal-ledger publication".to_owned(),
            ));
        }
        child_observed_publication.store(true, Ordering::Release);
        Err(Error::RunAborted)
    });
    executor.register_child_process_with_gate(
        child_pid,
        gate.clone(),
        Arc::new(crate::executor::ChildCompletionSlot::default()),
        child,
    );
    starts
        .lock()
        .unwrap()
        .push(PendingChildStart::fork_process(child_pid, gate));
    let completion = crate::failure::owned_future::CaughtFuture {
        output: Some(HandlerOutcome::Returned(Ok::<(), Error>(()))),
        panics: Vec::new(),
    };

    let error = finish_signal_cleanup(
        &mut backend,
        &mut executor,
        completion,
        &starts,
        Some(-i64::from(libc::EFAULT)),
    )
    .expect_err("impossible registered child start passed signal cleanup");

    assert!(observed_publication.load(Ordering::Acquire));
    assert!(starts.lock().unwrap().is_empty());
    assert!(!executor.has_pending_child_process(child_pid));
    let published = run
        .published_primary()
        .expect("parent invariant failure was not published");
    let Error::SharedFailure(returned) = error else {
        panic!("signal cleanup did not return its published parent failure");
    };
    assert!(Arc::ptr_eq(&returned, &published));
    let Error::SignalEffects {
        cause,
        dequeues,
        acknowledged_through,
        publications,
        raw_result,
        context,
    } = published.as_ref()
    else {
        panic!("published child-start violation lost its signal ledger");
    };
    assert_eq!(dequeues.as_slice(), &[effect]);
    assert_eq!(*acknowledged_through, 0);
    assert!(publications.is_empty());
    assert_eq!(*raw_result, Some(-i64::from(libc::EFAULT)));
    assert!(context.is_none());
    assert!(matches!(cause.as_ref(), Error::UnexpectedVcpuExit(message)
        if message == "signal dequeue notification created a child start despite its injection guard"));
}

#[test]
fn cleanup_poll_panic_keeps_transferred_error_and_all_destructor_panics() {
    let (error, expected) = effects_error();
    let counts = Arc::new(Counts::default());
    let signal = Arc::new(Mutex::new(None));
    let (poll_panic, poll_address) = payload("poll");
    let (callback_panic, callback_address) = payload("callback drop");
    let (failure_panic, failure_address) = payload("failure drop");
    let completion = futures::executor::block_on(drive_signal_cleanup(
        Cleanup {
            counts: counts.clone(),
            output: None,
            transfer: Some((signal.clone(), error)),
            retained: Some(expected.clone()),
            poll_panic: Some(poll_panic),
            drop_panic: Some(callback_panic),
        },
        signal.clone(),
        Arc::new(Mutex::new(Vec::new())),
        Failure {
            ready: Arc::new(AtomicBool::new(true)),
            counts: counts.clone(),
            drop_panic: Some(failure_panic),
        },
    ));
    let Some(HandlerOutcome::RuntimeError(error)) = &completion.output else {
        panic!("poll panic discarded transferred signal effects");
    };
    assert_effects_error(error, &expected);
    assert!(signal.is_poisoned());
    assert!(
        signal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
    );
    assert_eq!(counts.polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.failure_drops.load(Ordering::SeqCst), 1);
    assert_eq!(completion.panics.len(), 3);
    assert_payload(&completion.panics[0], poll_address, "poll");
    assert_payload(&completion.panics[1], callback_address, "callback drop");
    assert_payload(&completion.panics[2], failure_address, "failure drop");
    drop(completion);
    assert!(expected.upgrade().is_none());
}

#[derive(Clone, Copy, Default)]
enum Notification {
    #[default]
    Ready,
    RejectedChildInjections,
    Error,
    PollPanic,
    PendingDropPanic,
}

#[derive(Default)]
struct CleanupTool {
    notification: Notification,
    calls: AtomicUsize,
    drops: Arc<AtomicUsize>,
    panic: Mutex<Option<PanicPayload>>,
}

struct NotificationDrop {
    drops: Arc<AtomicUsize>,
    panic: Option<PanicPayload>,
}

impl Drop for NotificationDrop {
    fn drop(&mut self) {
        assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
        resume_unwind(self.panic.take().unwrap());
    }
}

#[reverie::tool]
impl Tool for CleanupTool {
    type GlobalState = crate::StraceLog;
    type ThreadState = ();

    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);
        match self.notification {
            Notification::Ready => Ok(()),
            Notification::RejectedChildInjections => {
                let thread_flags = libc::CLONE_THREAD | libc::CLONE_VM | libc::CLONE_SIGHAND;
                for request in [
                    SyscallRequest::new(libc::SYS_fork as u64, [0; 6]),
                    SyscallRequest::new(libc::SYS_vfork as u64, [0; 6]),
                    SyscallRequest::new(
                        libc::SYS_clone as u64,
                        [thread_flags as u64, 0, 0, 0, 0, 0],
                    ),
                    SyscallRequest::new(libc::SYS_clone3 as u64, [0; 6]),
                ] {
                    assert_eq!(
                        guest.inject(request.into_syscall().unwrap()).await,
                        Err(Errno::ENOSYS),
                        "dequeue notification admitted a child-producing injection"
                    );
                }
                Ok(())
            }
            Notification::Error => Err(Errno::EIO),
            Notification::PollPanic => {
                let payload = self.panic.lock().unwrap().take().unwrap();
                resume_unwind(payload);
            }
            Notification::PendingDropPanic => {
                let _owned = NotificationDrop {
                    drops: self.drops.clone(),
                    panic: self.panic.lock().unwrap().take(),
                };
                std::future::pending().await
            }
        }
    }
}

fn check_actual_flush(notification: Notification) {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    let mut executor = ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new(".")),
        false,
    );
    executor.enable_signal_dequeues();
    let pid = Pid::from_raw(1);
    let mut info = [0_u8; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
    executor
        .defer_signal_delivery(
            SignalEvent::new(
                libc::SIGUSR1,
                info,
                reverie::SignalTarget::Thread { pid, tid: pid },
            )
            .unwrap(),
        )
        .unwrap();
    executor
        .take_pending_signal_for_delivery()
        .unwrap()
        .unwrap();
    let effect = executor.signal_dequeue_front().unwrap();
    let (panic, address) = payload("actual notification");
    let tool = Arc::new(CleanupTool {
        notification,
        panic: Mutex::new(Some(panic)),
        ..CleanupTool::default()
    });
    let global = Arc::new(crate::StraceLog::default());
    let run = RunFailure::new(&global);
    let context = FailureContext::new(run, pid, pid);
    backend.tool_failure = Some(context.clone());
    let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
    let stack = Arc::new(AtomicBool::new(false));
    let subscriptions = Subscription::none();
    let mut state = ();
    let result = {
        let mut cleanup = Box::pin(flush_pending_signal_effects_with_tool(
            &mut backend,
            &mut executor,
            pid,
            pid,
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
        let mut cx = Context::from_waker(Waker::noop());
        if matches!(notification, Notification::PendingDropPanic) {
            assert!(cleanup.as_mut().poll(&mut cx).is_pending());
            assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
            assert_eq!(tool.drops.load(Ordering::SeqCst), 0);
        }
        context.publish("peer stopped", Error::GuestWorkerPanic);
        let Poll::Ready(result) = cleanup.as_mut().poll(&mut cx) else {
            panic!("actual cleanup did not finish after run failure");
        };
        result
    };
    assert_eq!(tool.calls.load(Ordering::SeqCst), 1);
    assert!(executor.signal_dequeue_front().is_none());
    let panics = backend.tool_panic_owner().take();
    match notification {
        Notification::Ready | Notification::RejectedChildInjections => {
            assert!(result.is_ok());
            assert!(panics.is_empty());
            assert!(executor.signal_dequeue_failure().is_none());
        }
        Notification::Error | Notification::PollPanic | Notification::PendingDropPanic => {
            let Error::SignalEffects {
                cause,
                dequeues,
                acknowledged_through,
                raw_result,
                ..
            } = result.unwrap_err()
            else {
                panic!("actual cleanup lost its real dequeue or raw errno");
            };
            assert_eq!(dequeues, vec![effect]);
            assert_eq!(acknowledged_through, 0);
            assert_eq!(raw_result, Some(-i64::from(libc::EFAULT)));
            if matches!(notification, Notification::Error) {
                assert!(
                    matches!(cause.primary(), Error::Reverie(reverie::Error::Errno(errno)) if *errno == Errno::EIO)
                );
                assert!(panics.is_empty());
            } else {
                assert!(matches!(cause.primary(), Error::GuestWorkerPanic));
                assert_eq!(panics.len(), 1);
                assert_payload(&panics[0], address, "actual notification");
                if matches!(notification, Notification::PendingDropPanic) {
                    let Error::WithCleanup { cleanup, .. } = cause.as_ref() else {
                        panic!("pending notification lost cancellation behind its panic");
                    };
                    assert_eq!(cleanup.len(), 1);
                    assert!(matches!(cleanup[0].as_ref(), Error::RunAborted));
                }
            }
        }
    }
    assert_eq!(
        tool.drops.load(Ordering::SeqCst),
        usize::from(matches!(notification, Notification::PendingDropPanic))
    );
}

#[test]
fn actual_ready_signal_cleanup_keeps_success_after_run_failure() {
    check_actual_flush(Notification::Ready);
}

#[test]
fn actual_signal_cleanup_rejects_fork_vfork_clone_and_clone3_injection() {
    check_actual_flush(Notification::RejectedChildInjections);
}

#[test]
fn actual_ready_signal_cleanup_keeps_errno_and_removal_after_run_failure() {
    check_actual_flush(Notification::Error);
}

#[test]
fn actual_signal_cleanup_poll_panic_retains_effects_errno_and_payload() {
    check_actual_flush(Notification::PollPanic);
}

#[test]
fn actual_signal_cleanup_pending_drop_panic_retains_effects_errno_and_payload() {
    check_actual_flush(Notification::PendingDropPanic);
}
