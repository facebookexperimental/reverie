/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Actual Exec wait/group ownership with a constructed callback and host
//! worker. KVM setup is required; no guest instruction or KVM_RUN is used.

use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use super::*;

const WAIT: Duration = Duration::from_secs(5);

struct WakeCount(AtomicUsize);

impl futures::task::ArcWake for WakeCount {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Callback<'a> {
    wait: Pin<Box<dyn Future<Output = Result<()>> + 'a>>,
    destroyed: Arc<AtomicBool>,
}

impl Future for Callback<'_> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.wait.as_mut().poll(cx)
    }
}

impl Drop for Callback<'_> {
    fn drop(&mut self) {
        self.destroyed.store(true, Ordering::Release);
    }
}

struct WorkerDone(mpsc::Sender<()>);

impl Drop for WorkerDone {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

struct Rescue {
    group: Arc<GuestThreadGroup>,
    release: Option<mpsc::Sender<()>>,
    done: mpsc::Receiver<()>,
    finished: bool,
    joined: bool,
}

impl Drop for Rescue {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if self.finished || self.done.recv_timeout(WAIT).is_ok() {
            self.group.join_workers();
        }
    }
}

#[test]
fn exec_wait_private_failure_leaves_worker_owned_until_callback_destruction() {
    let mut backend = KvmBackend::new(0x10000).expect("Exec wait control requires /dev/kvm");
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    backend.set_tool_failure(Some(crate::failure::FailureContext::new(
        run.clone(),
        Pid::from_raw(1),
        Pid::from_raw(1),
    )));
    let driver = backend.start_entry_driver();
    let callback_scope = backend.begin_entry_callback().unwrap().unwrap();
    let origin = callback_scope.origin();
    let memory = backend.memory.clone();
    let group = backend.thread_group.clone();
    let destroyed = Arc::new(AtomicBool::new(false));
    let worker_destroyed = destroyed.clone();
    let worker_run = run.clone();
    let (start, wait_start) = mpsc::channel();
    let gate = ChildStartGate::new(start);
    let (cancelled, wait_cancelled) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    let (done, wait_done) = mpsc::channel();
    let notice = WorkerCompletionNotice::new(group.clone());
    let returning = notice.returning.clone();
    let handle = std::thread::spawn(move || {
        let _done = WorkerDone(done);
        let _notice = notice;
        let run_worker = move || -> GuestWorkerResult {
            assert_eq!(
                wait_start.recv_timeout(WAIT).unwrap(),
                ChildStartCommand::Cancel
            );
            cancelled.send(()).unwrap();
            // A regressed blocking join is finite too: this receive times out
            // and fails the worker rather than stranding the control process.
            wait_release.recv_timeout(WAIT).unwrap();
            assert!(worker_destroyed.load(Ordering::Acquire));
            assert!(worker_run.published_primary().is_some());
            Err(Error::RunAborted)
        };
        run_worker()
    });
    group.add_worker_handle_with_completion(2, Some(gate.clone()), Some(returning.clone()), handle);
    let mut rescue = Rescue {
        group: group.clone(),
        release: Some(release),
        done: wait_done,
        finished: false,
        joined: false,
    };
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = futures::task::waker(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut stop = Box::pin(std::future::pending());
    let mut callback = Box::pin(Callback {
        wait: Box::pin(backend.cancel_guest_threads_for_exec(stop.as_mut())),
        destroyed: destroyed.clone(),
    });
    assert!(callback.as_mut().poll(&mut cx).is_pending());
    wait_cancelled
        .recv_timeout(WAIT)
        .expect("Exec did not request worker cancellation");
    assert!(gate.is_cancelled());
    assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
    assert!(!returning.load(Ordering::Acquire));
    assert!(run.published_primary().is_none());

    let cause = Arc::new(Error::GuestClock(
        "private failure during Exec wait".to_owned(),
    ));
    let before = wakes.0.load(Ordering::SeqCst);
    memory
        .entry_gate()
        .poison(memory.entry_origin(), Error::SharedFailure(cause.clone()));
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    let error = match callback.as_mut().poll(&mut cx) {
        Poll::Ready(Err(error)) => error,
        _ => panic!("private cause must interrupt the pending Exec callback"),
    };
    assert!(crate::failure::references_shared_error(&error, &cause));
    assert!(!destroyed.load(Ordering::Acquire));
    assert!(!origin.callback_dropped());
    assert!(run.published_primary().is_none());
    assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
    assert!(group.worker_errors.lock().unwrap().is_empty());
    assert!(!returning.load(Ordering::Acquire));

    drop(callback);
    drop(callback_scope);
    backend.restore_entry_origin();
    assert!(destroyed.load(Ordering::Acquire));
    assert!(origin.callback_dropped());
    let error =
        futures::executor::block_on(backend.route_entry_outcome::<()>(Err(error))).unwrap_err();
    let error = backend.report_tool_failure("constructed Exec callback", error);
    assert!(run.published_primary().is_some());
    let mut completion = Box::pin(group.subscribe_worker_completion());
    assert!(completion.as_mut().poll(&mut cx).is_pending());
    rescue.release.take().unwrap().send(()).unwrap();
    rescue
        .done
        .recv_timeout(WAIT)
        .expect("released worker did not finish");
    rescue.finished = true;
    assert!(completion.as_mut().poll(&mut cx).is_ready());
    assert!(returning.load(Ordering::Acquire));
    group.join_workers();
    rescue.joined = true;
    assert!(group.worker_handles.lock().unwrap().is_empty());
    assert!(group.worker_start_gates.lock().unwrap().is_empty());
    let completed = backend
        .finish_entry_driver::<()>(driver, Err(error))
        .unwrap_err();
    assert!(crate::failure::references_shared_error(&completed, &cause));
}

struct TlsExitProbe {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    done: mpsc::Sender<()>,
    timed_out: Arc<AtomicBool>,
    callback_destroyed: Arc<AtomicBool>,
    run: Arc<crate::failure::RunFailure>,
    ordering_satisfied: Arc<AtomicBool>,
}

impl Drop for TlsExitProbe {
    fn drop(&mut self) {
        // A failed assertion in a TLS destructor aborts the process. Report
        // observations to the parent instead, and bound a regressed join.
        let _ = self.entered.send(());
        if self.release.recv_timeout(WAIT).is_err() {
            self.timed_out.store(true, Ordering::Release);
        }
        self.ordering_satisfied.store(
            self.callback_destroyed.load(Ordering::Acquire)
                && self.run.published_primary().is_some(),
            Ordering::Release,
        );
        let _ = self.done.send(());
    }
}

thread_local! {
    static TLS_EXIT_PROBE: std::cell::RefCell<Option<TlsExitProbe>> = const {
        std::cell::RefCell::new(None)
    };
}

#[test]
fn exec_wait_private_failure_interrupts_worker_tls_destructor() {
    let mut backend = KvmBackend::new(0x10000).expect("Exec TLS control requires /dev/kvm");
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    backend.set_tool_failure(Some(crate::failure::FailureContext::new(
        run.clone(),
        Pid::from_raw(1),
        Pid::from_raw(1),
    )));
    let driver = backend.start_entry_driver();
    let callback_scope = backend.begin_entry_callback().unwrap().unwrap();
    let origin = callback_scope.origin();
    let memory = backend.memory.clone();
    let group = backend.thread_group.clone();
    let destroyed = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let ordering_satisfied = Arc::new(AtomicBool::new(false));
    let worker_cause = Arc::new(Error::GuestClock("worker returned before TLS exit".into()));
    let retained_cause = worker_cause.clone();
    let (entered, wait_entered) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    let (done, wait_done) = mpsc::channel();
    let probe = TlsExitProbe {
        entered,
        release: wait_release,
        done,
        timed_out: timed_out.clone(),
        callback_destroyed: destroyed.clone(),
        run: run.clone(),
        ordering_satisfied: ordering_satisfied.clone(),
    };
    let handle = std::thread::spawn(move || -> GuestWorkerResult {
        TLS_EXIT_PROBE.with(|slot| *slot.borrow_mut() = Some(probe));
        Err(Error::SharedFailure(retained_cause))
    });
    wait_entered
        .recv_timeout(WAIT)
        .expect("worker did not enter its real TLS destructor");
    // This is the distinction the old closure-only control could not make.
    assert!(handle.is_finished());
    assert!(!timed_out.load(Ordering::Acquire));
    group.add_worker_handle(2, handle);
    let mut rescue = Rescue {
        group: group.clone(),
        release: Some(release),
        done: wait_done,
        finished: false,
        joined: false,
    };
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = futures::task::waker(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut stop = Box::pin(std::future::pending());
    let mut callback = Box::pin(Callback {
        wait: Box::pin(backend.cancel_guest_threads_for_exec(stop.as_mut())),
        destroyed: destroyed.clone(),
    });
    assert!(
        callback.as_mut().poll(&mut cx).is_pending(),
        "Exec must remain interruptible while the worker TLS destructor is blocked"
    );
    assert!(!timed_out.load(Ordering::Acquire));
    assert!(group.worker_errors.lock().unwrap().is_empty());
    let cause = Arc::new(Error::GuestClock(
        "private failure during worker TLS".into(),
    ));
    let before = wakes.0.load(Ordering::SeqCst);
    memory
        .entry_gate()
        .poison(memory.entry_origin(), Error::SharedFailure(cause.clone()));
    assert!(wakes.0.load(Ordering::SeqCst) > before);
    let error = match callback.as_mut().poll(&mut cx) {
        Poll::Ready(Err(error)) => error,
        _ => panic!("private cause must interrupt Exec before TLS destruction completes"),
    };
    assert!(crate::failure::references_shared_error(&error, &cause));
    assert!(!destroyed.load(Ordering::Acquire));
    assert!(!origin.callback_dropped());
    assert!(run.published_primary().is_none());
    assert!(rescue.done.try_recv().is_err());
    assert!(group.worker_errors.lock().unwrap().is_empty());

    drop(callback);
    drop(callback_scope);
    backend.restore_entry_origin();
    let error =
        futures::executor::block_on(backend.route_entry_outcome::<()>(Err(error))).unwrap_err();
    let error = backend.report_tool_failure("constructed Exec TLS callback", error);
    rescue.release.take().unwrap().send(()).unwrap();
    rescue
        .done
        .recv_timeout(WAIT)
        .expect("TLS did not complete");
    rescue.finished = true;
    group.join_workers();
    rescue.joined = true;
    assert!(!timed_out.load(Ordering::Acquire));
    assert!(ordering_satisfied.load(Ordering::Acquire));
    assert!(group.worker_handles.lock().unwrap().is_empty());
    let worker_error = group.teardown_result().unwrap_err();
    assert!(crate::failure::references_shared_error(
        &worker_error,
        &worker_cause
    ));
    assert_eq!(
        group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
        1
    );
    group.join_workers();
    assert_eq!(
        group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
        1
    );
    let completed = backend
        .finish_entry_driver::<()>(driver, Err(error))
        .unwrap_err();
    assert!(crate::failure::references_shared_error(&completed, &cause));
}

// The controls below extend the two original controls without changing them.
// A timeout records failure outside TLS destruction, where panicking is safe.
struct HeldTlsExit {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    done: mpsc::Sender<()>,
    timed_out: Arc<AtomicBool>,
    destroyed: Option<Arc<AtomicBool>>,
    ordered: Arc<AtomicBool>,
}

impl Drop for HeldTlsExit {
    fn drop(&mut self) {
        let _ = self.entered.send(());
        if self.release.recv_timeout(WAIT).is_err() {
            self.timed_out.store(true, Ordering::Release);
        }
        self.ordered.store(
            self.destroyed
                .as_ref()
                .is_none_or(|flag| flag.load(Ordering::Acquire)),
            Ordering::Release,
        );
        let _ = self.done.send(());
    }
}

thread_local! {
    static HELD_TLS_EXIT: std::cell::RefCell<Option<HeldTlsExit>> = const {
        std::cell::RefCell::new(None)
    };
}

struct TlsHold {
    entered: mpsc::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
    done: mpsc::Receiver<()>,
    timed_out: Arc<AtomicBool>,
    ordered: Arc<AtomicBool>,
}

impl TlsHold {
    fn new(destroyed: Option<Arc<AtomicBool>>) -> (HeldTlsExit, Self) {
        let (entered, wait_entered) = mpsc::channel();
        let (release, wait_release) = mpsc::channel();
        let (done, wait_done) = mpsc::channel();
        let timed_out = Arc::new(AtomicBool::new(false));
        let ordered = Arc::new(AtomicBool::new(false));
        (
            HeldTlsExit {
                entered,
                release: wait_release,
                done,
                timed_out: timed_out.clone(),
                destroyed,
                ordered: ordered.clone(),
            },
            Self {
                entered: wait_entered,
                release: Some(release),
                done: wait_done,
                timed_out,
                ordered,
            },
        )
    }

    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }

    fn assert_finished(&self) {
        self.done
            .recv_timeout(WAIT)
            .expect("TLS destruction did not finish");
        assert!(!self.timed_out.load(Ordering::Acquire));
        assert!(self.ordered.load(Ordering::Acquire));
    }
}

impl Drop for TlsHold {
    fn drop(&mut self) {
        self.release();
    }
}

struct GroupDrain(Arc<GuestThreadGroup>);

impl Drop for GroupDrain {
    fn drop(&mut self) {
        self.0.cancel_workers();
        self.0.join_workers();
    }
}

fn bounded_until(mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + WAIT;
    while !condition() {
        assert!(
            std::time::Instant::now() < deadline,
            "bounded join control made no progress"
        );
        std::thread::yield_now();
    }
}

#[test]
fn exec_wait_success_requires_worker_tls_physical_completion() {
    let backend =
        KvmBackend::new(0x10000).expect("Exec physical completion control requires /dev/kvm");
    let group = backend.thread_group.clone();
    let destroyed = Arc::new(AtomicBool::new(false));
    let (probe, mut held) = TlsHold::new(None);
    let handle = std::thread::spawn(move || {
        HELD_TLS_EXIT.with(|slot| *slot.borrow_mut() = Some(probe));
        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
    });
    held.entered.recv_timeout(WAIT).unwrap();
    assert!(handle.is_finished());
    group.add_worker_handle(2, handle);
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut stop = Box::pin(std::future::pending());
    let mut callback = Box::pin(Callback {
        wait: Box::pin(backend.cancel_guest_threads_for_exec(stop.as_mut())),
        destroyed: destroyed.clone(),
    });
    assert!(callback.as_mut().poll(&mut cx).is_pending());
    bounded_until(|| {
        assert!(callback.as_mut().poll(&mut cx).is_pending());
        group.worker_join_helper_state().1
    });
    let helper = group.worker_join_helper_state().0.unwrap();
    assert!(group.worker_handles.lock().unwrap().is_empty());
    assert_eq!(group.worker_joins.lock().active.len(), 1);
    assert!(held.done.try_recv().is_err());
    held.release();
    bounded_until(|| match callback.as_mut().poll(&mut cx) {
        Poll::Ready(result) => {
            result.unwrap();
            true
        }
        Poll::Pending => false,
    });
    held.assert_finished();
    assert!(!destroyed.load(Ordering::Acquire));
    assert!(group.worker_joins.lock().active.is_empty());
    assert_eq!(group.worker_join_helper_state().0, Some(helper));
    group.teardown_result().unwrap();
    drop(callback);
    group.join_workers();
    assert!(group.worker_join_helper_state().0.is_none());
    assert!(destroyed.load(Ordering::Acquire));
}

#[test]
fn refused_exec_join_helper_preserves_original_worker_and_gate() {
    let group = Arc::new(GuestThreadGroup::default());
    let _drain = GroupDrain(group.clone());
    let (sender, receiver) = mpsc::channel();
    let gate = ChildStartGate::new(sender);
    let cause = Arc::new(Error::GuestClock("refused helper's original worker".into()));
    let worker_cause = cause.clone();
    group.add_unstarted_worker(
        2,
        gate.clone(),
        std::thread::spawn(move || {
            assert_eq!(
                receiver.recv_timeout(WAIT).unwrap(),
                ChildStartCommand::Cancel
            );
            Err(Error::SharedFailure(worker_cause))
        }),
    );
    let error = group
        .start_worker_join_helper_with(
            std::thread::Builder::new().stack_size(usize::MAX / 2),
            || {},
        )
        .expect_err("impossible helper stack unexpectedly spawned");
    let Error::SharedFailure(ref helper_cause) = error else {
        panic!("missing retained spawn error")
    };
    assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
    assert!(group.worker_joins.lock().active.is_empty());
    assert!(group.worker_join_helper_state().0.is_none());
    assert!(!gate.is_cancelled());
    assert!(group.worker_start_gates.lock().unwrap().contains_key(&2));
    group.cancel_workers();
    group.join_workers();
    let completed = group.teardown_result().unwrap_err();
    assert!(crate::failure::references_shared_error(
        &completed,
        helper_cause
    ));
    assert!(crate::failure::references_shared_error(&completed, &cause));
    group.join_workers();
    assert_eq!(
        group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
        1
    );
    assert!(group.worker_start_gates.lock().unwrap().is_empty());
}

struct JoinPanicToken(Arc<AtomicUsize>);

impl Drop for JoinPanicToken {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn exec_join_helper_retains_exact_worker_panic_through_repeated_teardown() {
    let group = Arc::new(GuestThreadGroup::default());
    let drain = GroupDrain(group.clone());
    let (probe, mut held) = TlsHold::new(None);
    let drops = Arc::new(AtomicUsize::new(0));
    let payload = Box::new(JoinPanicToken(drops.clone()));
    let address = (&*payload as *const JoinPanicToken) as usize;
    let handle = std::thread::spawn(move || -> GuestWorkerResult {
        HELD_TLS_EXIT.with(|slot| *slot.borrow_mut() = Some(probe));
        std::panic::resume_unwind(payload);
    });
    held.entered.recv_timeout(WAIT).unwrap();
    assert!(handle.is_finished());
    group.add_worker_handle(2, handle);
    bounded_until(|| {
        assert!(!group.advance_worker_joins_for_exec().unwrap().0);
        group.worker_join_helper_state().1
    });
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(group.completed_worker_panics.lock().unwrap().is_empty());
    held.release();
    bounded_until(|| group.advance_worker_joins_for_exec().unwrap().0);
    held.assert_finished();
    let retained = {
        let records = group.completed_worker_panics.lock().unwrap();
        assert_eq!(records.len(), 1);
        let payload = records[0]._join_payload.as_ref().unwrap();
        assert_eq!(
            (&**payload as *const dyn std::any::Any as *const ()) as usize,
            address
        );
        records[0].error.clone()
    };
    for _ in 0..2 {
        group.join_workers();
        let error = group.teardown_result().unwrap_err();
        assert!(crate::failure::references_shared_error(&error, &retained));
        assert_eq!(
            group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
            1
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    drop(drain);
    drop(group);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn exec_join_helper_does_not_capture_nested_discard_behind_another_worker() {
    let group = Arc::new(GuestThreadGroup::default());
    let _drain = GroupDrain(group.clone());
    let (probe, mut held) = TlsHold::new(None);
    let unrelated = std::thread::spawn(move || {
        HELD_TLS_EXIT.with(|slot| *slot.borrow_mut() = Some(probe));
        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
    });
    held.entered.recv_timeout(WAIT).unwrap();
    group.add_worker_handle(2, unrelated);
    bounded_until(|| {
        assert!(!group.advance_worker_joins_for_exec().unwrap().0);
        group.worker_join_helper_state().1
    });
    let nested = group.clone();
    let (proceed, wait_proceed) = mpsc::channel();
    let (cleaned, wait_cleaned) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    // Dropping this sender rescues A even when an assertion fails.
    let enclosing = std::thread::spawn(move || {
        wait_proceed.recv_timeout(WAIT).unwrap();
        let (sender, receiver) = mpsc::channel();
        let gate = ChildStartGate::new(sender);
        nested.add_unstarted_worker(
            4,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(
                    receiver.recv_timeout(WAIT).unwrap(),
                    ChildStartCommand::Cancel
                );
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        gate.cancel();
        let discarded = nested.discard_unstarted_worker(4);
        cleaned.send(discarded).unwrap();
        let _ = wait_release.recv_timeout(WAIT);
        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
    });
    group.add_worker_handle(3, enclosing);
    proceed.send(()).unwrap();
    assert!(
        wait_cleaned
            .recv_timeout(WAIT)
            .expect("nested discard waited for unrelated TLS")
            .unwrap()
    );
    assert!(held.done.try_recv().is_err());
    assert!(group.worker_join_helper_state().1);
    assert_eq!(
        group
            .worker_handles
            .lock()
            .unwrap()
            .iter()
            .map(|worker| worker.tid)
            .collect::<Vec<_>>(),
        vec![3]
    );
    assert!(!group.worker_start_gates.lock().unwrap().contains_key(&4));
    release.send(()).unwrap();
    held.release();
    group.join_workers();
    held.assert_finished();
    group.teardown_result().unwrap();
    assert!(group.worker_joins.lock().active.is_empty());
}

#[test]
fn exec_join_helper_parent_spawn_hook_panic_restores_original_ownership() {
    std::thread::spawn(|| {
        let group = Arc::new(GuestThreadGroup::default());
        let _drain = GroupDrain(group.clone());
        let (sender, receiver) = mpsc::channel();
        let gate = ChildStartGate::new(sender);
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(
                    receiver.recv_timeout(WAIT).unwrap(),
                    ChildStartCommand::Cancel
                );
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = Box::new(JoinPanicToken(drops.clone()));
        let address = (&*payload as *const JoinPanicToken) as usize;
        let payload: crate::failure::owned_future::PanicPayload = payload;
        let hook_payload = Arc::new(Mutex::new(Some(payload)));
        std::thread::add_spawn_hook(move |thread| {
            if thread.name() == Some("reverie-kvm-join") {
                let payload = { hook_payload.lock().unwrap().take() };
                if let Some(payload) = payload {
                    std::panic::resume_unwind(payload);
                }
            }
            || {}
        });
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            group.start_worker_join_helper_with(
                std::thread::Builder::new().name("reverie-kvm-join".into()),
                || {},
            )
        }))
        .expect_err("actual parent spawn hook did not panic");
        assert_eq!(
            (&*caught as *const dyn std::any::Any as *const ()) as usize,
            address
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(group.worker_join_helper_state().0.is_none());
        assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
        assert!(group.worker_joins.lock().active.is_empty());
        assert!(!gate.is_cancelled());
        assert!(group.advance_worker_joins_for_exec().is_err());
        group.cancel_workers();
        group.join_workers();
        assert!(group.worker_start_gates.lock().unwrap().is_empty());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(caught);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    })
    .join()
    .unwrap();
}

#[test]
fn exec_join_helper_child_spawn_hook_panic_retains_handle_payload_and_originals() {
    std::thread::spawn(|| {
        let group = Arc::new(GuestThreadGroup::default());
        let drain = GroupDrain(group.clone());
        let (sender, receiver) = mpsc::channel();
        let gate = ChildStartGate::new(sender);
        let cause = Arc::new(Error::GuestClock(
            "original survived child helper hook".into(),
        ));
        let worker_cause = cause.clone();
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(
                    receiver.recv_timeout(WAIT).unwrap(),
                    ChildStartCommand::Cancel
                );
                Err(Error::SharedFailure(worker_cause))
            }),
        );
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = Box::new(JoinPanicToken(drops.clone()));
        let address = (&*payload as *const JoinPanicToken) as usize;
        let payload: crate::failure::owned_future::PanicPayload = payload;
        let (entered, wait_entered) = mpsc::channel();
        let (release, wait_release) = mpsc::channel();
        let hook_state = Arc::new(Mutex::new(Some((payload, entered, wait_release))));
        std::thread::add_spawn_hook(move |thread| {
            let state = if thread.name() == Some("reverie-kvm-join") {
                hook_state.lock().unwrap().take()
            } else {
                None
            };
            move || {
                if let Some((payload, entered, release)) = state {
                    let _ = entered.send(());
                    let _ = release.recv_timeout(WAIT);
                    std::panic::resume_unwind(payload);
                }
            }
        });
        let body_entered = Arc::new(AtomicBool::new(false));
        let body_flag = body_entered.clone();
        group
            .start_worker_join_helper_with(
                std::thread::Builder::new().name("reverie-kvm-join".into()),
                move || {
                    body_flag.store(true, Ordering::Release);
                },
            )
            .unwrap();
        wait_entered.recv_timeout(WAIT).unwrap();
        let helper = group.worker_join_helper_state().0.unwrap();
        assert!(!group.advance_worker_joins_for_exec().unwrap().0);
        assert!(!body_entered.load(Ordering::Acquire));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = futures::task::waker(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut changed = Box::pin(group.subscribe_worker_completion());
        assert!(changed.as_mut().poll(&mut cx).is_pending());
        release.send(()).unwrap();
        bounded_until(|| {
            group.advance_worker_joins_for_exec().is_err() && wakes.0.load(Ordering::SeqCst) > 0
        });
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(changed.as_mut().poll(&mut cx).is_ready());
        let error = group.advance_worker_joins_for_exec().unwrap_err();
        let Error::SharedFailure(ref startup_cause) = error else {
            panic!("startup failure lost typed owner")
        };
        assert_eq!(group.worker_join_helper_state().0, Some(helper));
        assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
        assert!(group.worker_joins.lock().active.is_empty());
        assert!(!body_entered.load(Ordering::Acquire));
        assert!(!gate.is_cancelled());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        group.cancel_workers();
        group.join_workers();
        assert_eq!(group.worker_join_helper_payload_addresses(), vec![address]);
        assert!(group.worker_join_helper_state().0.is_none());
        for _ in 0..2 {
            let completed = group.teardown_result().unwrap_err();
            assert!(crate::failure::references_shared_error(
                &completed,
                startup_cause
            ));
            assert!(crate::failure::references_shared_error(&completed, &cause));
            group.join_workers();
            assert_eq!(
                group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
                1
            );
        }
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(drain);
        drop(group);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    })
    .join()
    .unwrap();
}

#[test]
fn exec_join_helper_reuses_thread_and_defers_inherited_tls_to_outer_drain() {
    std::thread::spawn(|| {
        let backend = KvmBackend::new(0x10000).expect("helper TLS control requires /dev/kvm");
        let group = backend.thread_group.clone();
        let destroyed = Arc::new(AtomicBool::new(false));
        let (probe, mut held) = TlsHold::new(Some(destroyed.clone()));
        let hook_probe = Arc::new(Mutex::new(Some(probe)));
        let installed = Arc::new(AtomicUsize::new(0));
        let hook_installed = installed.clone();
        std::thread::add_spawn_hook(move |thread| {
            let probe = if thread.name() == Some("reverie-kvm-join") {
                hook_probe.lock().unwrap().take()
            } else {
                None
            };
            let installed = hook_installed.clone();
            move || {
                if let Some(probe) = probe {
                    HELD_TLS_EXIT.with(|slot| *slot.borrow_mut() = Some(probe));
                    installed.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut helper = None;
        for tid in [2, 3] {
            destroyed.store(false, Ordering::Release);
            group.add_worker_handle(
                tid,
                std::thread::spawn(|| Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))),
            );
            let mut stop = Box::pin(std::future::pending());
            let mut callback = Box::pin(Callback {
                wait: Box::pin(backend.cancel_guest_threads_for_exec(stop.as_mut())),
                destroyed: destroyed.clone(),
            });
            bounded_until(|| match callback.as_mut().poll(&mut cx) {
                Poll::Ready(result) => {
                    result.unwrap();
                    true
                }
                Poll::Pending => false,
            });
            assert_eq!(installed.load(Ordering::SeqCst), 1);
            let current = group.worker_join_helper_state().0.unwrap();
            if let Some(previous) = helper {
                assert_eq!(current, previous);
            }
            helper = Some(current);
            assert!(held.entered.try_recv().is_err());
            assert!(!destroyed.load(Ordering::Acquire));
            drop(callback);
        }
        assert!(destroyed.load(Ordering::Acquire));
        held.release();
        group.join_workers();
        held.entered.recv_timeout(WAIT).unwrap();
        held.assert_finished();
        assert!(group.worker_join_helper_state().0.is_none());
        group.teardown_result().unwrap();
    })
    .join()
    .unwrap();
}

#[test]
fn leader_backend_drop_physically_reaps_idle_exec_join_helper() {
    let backend = KvmBackend::new(0x10000).expect("leader Drop join control requires /dev/kvm");
    let group = backend.thread_group.clone();
    let cause = Arc::new(Error::GuestClock(
        "worker error survives leader Drop".into(),
    ));
    let worker_cause = cause.clone();
    group.add_worker_handle(
        2,
        std::thread::spawn(move || Err(Error::SharedFailure(worker_cause))),
    );
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut stop = Box::pin(std::future::pending());
    let mut callback = Box::pin(backend.cancel_guest_threads_for_exec(stop.as_mut()));
    bounded_until(|| match callback.as_mut().poll(&mut cx) {
        Poll::Ready(result) => {
            result.unwrap();
            true
        }
        Poll::Pending => false,
    });
    assert!(group.worker_join_helper_state().0.is_some());
    assert!(!group.worker_join_helper_state().1);
    assert!(group.worker_joins.lock().active.is_empty());
    drop(callback);
    // This is the actual production owner Drop, with no explicit group join.
    drop(backend);
    assert!(group.worker_join_helper_state().0.is_none());
    assert!(group.worker_joins.lock().active.is_empty());
    assert!(group.worker_handles.lock().unwrap().is_empty());
    assert!(group.worker_start_gates.lock().unwrap().is_empty());
    let error = group.teardown_result().unwrap_err();
    assert!(crate::failure::references_shared_error(&error, &cause));
    assert_eq!(
        group.worker_errors.lock().unwrap().get(&2).unwrap().len(),
        1
    );
}
