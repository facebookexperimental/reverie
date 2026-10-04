/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests for the existing minimal ELF builder.
mod entry_wait_tests {
    use std::cell::RefCell;
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::task::Context;
    use std::task::Poll;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;
    use crate::runtime::entry_wait_observation::Boundary;
    use crate::runtime::entry_wait_observation::Site;
    use crate::runtime::entry_wait_observation::{self};

    const WAIT: Duration = Duration::from_secs(5);
    const EXIT: i32 = 37;
    const STOP: i32 = 23;
    const STATE: u64 = 0x7265_6769_7374_6572;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Effect {
        Group,
        Global,
        OneShot,
        CloseAgain,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Boundary(Boundary),
        Applied(Boundary, Effect),
    }
    #[derive(Debug, Eq, PartialEq)]
    struct Counts {
        fd: usize,
        masks: usize,
        untracked: usize,
        tracked: usize,
        begins: usize,
        intervals: usize,
    }
    fn counts(probe: &crate::clock::RunProbe) -> Counts {
        let load = |counter: &AtomicUsize| counter.load(Ordering::SeqCst);
        Counts {
            fd: load(&probe.shared_fd_accesses),
            masks: load(&probe.prepare.mask_installs),
            untracked: load(&probe.untracked_runs),
            tracked: load(&probe.tracked_runs),
            begins: load(&probe.clock_begins),
            intervals: load(&probe.intervals_created),
        }
    }
    fn no_dispatch(control: &Control, exits: &KvmExitCollector) {
        assert_eq!(
            counts(&control.probe),
            Counts {
                fd: 0,
                masks: 0,
                untracked: 0,
                tracked: 0,
                begins: 0,
                intervals: 0
            }
        );
        assert_eq!(exits.snapshot().total_exits(), 0);
    }
    fn finite_entry(control: &Control, exits: &KvmExitCollector, tool: bool) {
        let seen = counts(&control.probe);
        assert!(seen.fd > 0, "real ELF syscall dispatch reads its registers");
        assert_eq!(seen.masks, 1);
        assert_eq!(seen.untracked, usize::from(!tool));
        assert_eq!(seen.tracked, usize::from(tool));
        assert_eq!(seen.begins, usize::from(tool));
        assert_eq!(seen.intervals, usize::from(tool));
        assert_eq!(exits.snapshot().total_exits(), 1);
        assert_eq!(
            exits
                .snapshot()
                .count(crate::stats::KvmExitReason::Hypercall),
            1
        );
    }

    struct Control {
        site: Site,
        gate: Arc<crate::entry::EntryGate>,
        group: Arc<GuestThreadGroup>,
        closed: Mutex<Option<crate::entry::Closed>>,
        closes: AtomicUsize,
        probe: Arc<crate::clock::RunProbe>,
        action: Mutex<Option<(Boundary, Effect)>>,
        events: Mutex<Vec<Event>>,
        failed: AtomicBool,
        failure_waker: futures::task::AtomicWaker,
        stop_sender: Mutex<Option<oneshot::Sender<()>>>,
        stop_completions: AtomicUsize,
        cleanup_sender: Mutex<Option<oneshot::Sender<()>>>,
        cleanup_receiver: Mutex<Option<oneshot::Receiver<()>>>,
        consumer_pending: AtomicBool,
        status: AtomicI32,
        thread_starts: AtomicUsize,
        thread_consumed: AtomicUsize,
        process_consumed: AtomicUsize,
        failures: AtomicUsize,
        global_drops: AtomicUsize,
    }
    impl Control {
        fn install(backend: &mut KvmBackend, site: Site) -> (Arc<Self>, mpsc::Receiver<()>) {
            let probe = Arc::new(crate::clock::RunProbe::default());
            let (wait_notice, waited) = mpsc::channel();
            probe.prepare.set_subscription_notice(wait_notice);
            let (cleanup_sender, cleanup_receiver) = oneshot::channel();
            let control = Arc::new(Self {
                site,
                gate: backend.memory.entry_gate(),
                group: backend.thread_group.clone(),
                closed: Mutex::new(None),
                closes: AtomicUsize::new(0),
                probe: probe.clone(),
                action: Mutex::new(None),
                events: Mutex::new(Vec::new()),
                failed: AtomicBool::new(false),
                failure_waker: Default::default(),
                stop_sender: Mutex::new(None),
                stop_completions: AtomicUsize::new(0),
                cleanup_sender: Mutex::new(Some(cleanup_sender)),
                cleanup_receiver: Mutex::new(Some(cleanup_receiver)),
                consumer_pending: AtomicBool::new(false),
                status: AtomicI32::new(-1),
                thread_starts: AtomicUsize::new(0),
                thread_consumed: AtomicUsize::new(0),
                process_consumed: AtomicUsize::new(0),
                failures: AtomicUsize::new(0),
                global_drops: AtomicUsize::new(0),
            });
            if site != Site::Parking {
                let weak = Arc::downgrade(&control);
                probe.before_run(move |probe| {
                    let control = weak.upgrade().unwrap();
                    probe.arm();
                    control.close();
                });
            }
            backend.vcpu.set_run_probe(probe);
            (control, waited)
        }
        fn close(&self) {
            assert!(self.closed.lock().unwrap().is_none());
            let closed = self
                .gate
                .try_close()
                .unwrap()
                .expect("distinct close must begin from Open")
                .finish()
                .now_or_never()
                .expect("all fixture participants are stopped")
                .unwrap();
            assert!(self.closed.lock().unwrap().replace(closed).is_none());
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
        fn reopen(&self) {
            let token = self.closed.lock().unwrap_or_else(|p| p.into_inner()).take();
            drop(token);
        }
        fn release_consumer(&self) {
            if let Some(sender) = self
                .cleanup_sender
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                let _ = sender.send(());
            }
        }
        fn rescue(&self) {
            self.reopen();
            self.release_consumer();
            self.group.request_exit_group(ExitStatus::Exited(STOP));
            if let Some(sender) = self
                .stop_sender
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take()
            {
                let _ = sender.send(());
            }
        }
        fn observe(&self, site: Site, boundary: Boundary) {
            if site != self.site || !self.probe.prepare.armed.load(Ordering::Acquire) {
                return;
            }
            self.events.lock().unwrap().push(Event::Boundary(boundary));
            let action = {
                let mut action = self.action.lock().unwrap();
                if action
                    .as_ref()
                    .is_some_and(|(selected, _)| *selected == boundary)
                {
                    action.take()
                } else {
                    None
                }
            };
            let Some((_, effect)) = action else {
                return;
            };
            match effect {
                Effect::Group => {
                    assert!(self.closed.lock().unwrap().is_some());
                    self.group.request_exit_group(ExitStatus::Exited(STOP));
                }
                Effect::Global => {
                    assert!(self.closed.lock().unwrap().is_some());
                    self.failed.store(true, Ordering::Release);
                    self.failure_waker.wake();
                }
                Effect::OneShot => {
                    assert!(self.closed.lock().unwrap().is_some());
                    self.stop_sender
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send(())
                        .unwrap();
                }
                Effect::CloseAgain => {
                    assert_eq!(self.closes.load(Ordering::SeqCst), 1);
                    self.close();
                    assert_eq!(self.closes.load(Ordering::SeqCst), 2);
                }
            }
            self.events
                .lock()
                .unwrap()
                .push(Event::Applied(boundary, effect));
        }
        fn scope(self: &Arc<Self>) -> entry_wait_observation::Scope {
            let control = self.clone();
            entry_wait_observation::Scope::new(Arc::new(move |site, boundary| {
                control.observe(site, boundary)
            }))
        }
        fn arm(&self, boundary: Boundary, effect: Effect) -> usize {
            let baseline = self.events.lock().unwrap().len();
            assert!(
                self.action
                    .lock()
                    .unwrap()
                    .replace((boundary, effect))
                    .is_none()
            );
            baseline
        }
        fn assert_action(&self, baseline: usize, boundary: Boundary, effect: Effect) {
            assert!(self.action.lock().unwrap().is_none());
            let expected = match boundary {
                Boundary::BeforeSubscription => vec![
                    Event::Boundary(boundary),
                    Event::Applied(boundary, effect),
                    Event::Boundary(Boundary::AfterSubscription),
                ],
                Boundary::AfterSubscription => vec![
                    Event::Boundary(Boundary::BeforeSubscription),
                    Event::Boundary(boundary),
                    Event::Applied(boundary, effect),
                ],
            };
            assert_eq!(
                &self.events.lock().unwrap()[baseline..],
                expected.as_slice()
            );
        }
        fn wait_counts(&self) -> (usize, usize) {
            (
                self.probe.prepare.closed_admissions.load(Ordering::SeqCst),
                self.probe
                    .prepare
                    .pending_subscriptions
                    .load(Ordering::SeqCst),
            )
        }
        fn assert_held(&self) {
            assert!(self.closed.lock().unwrap().is_some());
        }
    }
    impl Drop for Control {
        fn drop(&mut self) {
            self.reopen();
            self.release_consumer();
        }
    }

    fn elf() -> (KvmBackend, Arc<KvmExitCollector>) {
        let mut backend = KvmBackend::new(16 * 1024 * 1024)
            .expect("main retry-registration control requires /dev/kvm");
        let mut code = vec![0xb8, 231, 0, 0, 0, 0xbf];
        code.extend_from_slice(&EXIT.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05]);
        backend
            .install_static_elf(&minimal_test_elf(&code), "/bin/entry-wait-control")
            .unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        (backend, exits)
    }
    fn initial_wait(control: &Control, waited: &mpsc::Receiver<()>, exits: &KvmExitCollector) {
        waited
            .recv_timeout(WAIT)
            .expect("main driver never polled the actual closed wait");
        control.assert_held();
        no_dispatch(control, exits);
        assert_eq!(control.closes.load(Ordering::SeqCst), 1);
        let (denied, pending) = control.wait_counts();
        assert!(denied > 0 && pending > 0);
        while waited.try_recv().is_ok() {}
    }
    fn host_case(boundary: Boundary, second_close: bool) {
        let (mut backend, exits) = elf();
        let (control, waited) = Control::install(&mut backend, Site::HostMain);
        let worker_control = control.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _scope = worker_control.scope();
            let result = backend.run_static_elf();
            sender
                .send((backend, result))
                .unwrap_or_else(|_| panic!("Host controller lost result"));
        });
        let measured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            initial_wait(&control, &waited, &exits);
            let before_wait = control.wait_counts();
            let effect = if second_close {
                Effect::CloseAgain
            } else {
                Effect::Group
            };
            let baseline = control.arm(boundary, effect);
            let mut resumed_at = None;
            if second_close {
                control.reopen();
                waited
                    .recv_timeout(WAIT)
                    .expect("second close never reached a real Pending wait");
                control.assert_held();
                assert_eq!(
                    control.wait_counts(),
                    (before_wait.0 + 1, before_wait.1 + 1)
                );
                no_dispatch(&control, &exits);
                control.assert_action(baseline, boundary, effect);
                assert!(matches!(
                    receiver.try_recv(),
                    Err(mpsc::TryRecvError::Empty)
                ));
                resumed_at = Some(control.events.lock().unwrap().len());
                control.reopen();
            } else {
                control.gate.notify_unchanged_for_test();
            }
            let (backend, outcome) = receiver
                .recv_timeout(WAIT)
                .expect("Host terminal selection waited for reopen");
            if second_close {
                assert_eq!(
                    &control.events.lock().unwrap()[resumed_at.unwrap()..],
                    &[
                        Event::Boundary(Boundary::BeforeSubscription),
                        Event::Boundary(Boundary::AfterSubscription)
                    ]
                );
                assert_eq!(outcome.unwrap(), EXIT);
                finite_entry(&control, &exits, false);
            } else {
                control.assert_action(baseline, boundary, effect);
                control.assert_held();
                no_dispatch(&control, &exits);
                assert_eq!(control.wait_counts(), before_wait);
                assert_eq!(outcome.unwrap(), STOP);
                control.reopen();
            }
            assert!(!control.group.has_worker_handles());
            drop(backend);
        }));
        if measured.is_err() {
            control.rescue();
            // If the controller failed before receiving the moved backend,
            // obtain that owned result before joining the host actor.
            match receiver.recv_timeout(WAIT) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => panic!(
                    "Host actor did not return after finite rescue; do not enter a blocking join"
                ),
            }
        }
        worker.join().unwrap();
        if let Err(payload) = measured {
            std::panic::resume_unwind(payload);
        }
    }

    thread_local! { static TOOL_CONTROL: RefCell<Option<Arc<Control>>> = const { RefCell::new(None) }; }
    struct ToolScope;
    impl ToolScope {
        fn new(control: Arc<Control>) -> Self {
            TOOL_CONTROL.with(|slot| assert!(slot.replace(Some(control)).is_none()));
            Self
        }
    }
    impl Drop for ToolScope {
        fn drop(&mut self) {
            TOOL_CONTROL.with(|slot| slot.replace(None));
        }
    }
    fn tool_control() -> Arc<Control> {
        TOOL_CONTROL.with(|slot| slot.borrow().as_ref().unwrap().clone())
    }
    #[derive(Default)]
    struct WaitGlobal {
        control: Option<Arc<Control>>,
    }
    impl Drop for WaitGlobal {
        fn drop(&mut self) {
            if let Some(control) = &self.control {
                control.global_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    #[reverie::global_tool]
    impl GlobalTool for WaitGlobal {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn init_global_state(_: &()) -> Self {
            Self {
                control: Some(tool_control()),
            }
        }
        async fn receive_rpc(&self, _: Pid, _: ()) {
            panic!("wait control issues no ordinary RPC");
        }
        fn report_backend_failure(&self, _: reverie::BackendFailure) {
            self.control
                .as_ref()
                .unwrap()
                .failures
                .fetch_add(1, Ordering::SeqCst);
        }
        async fn wait_for_backend_failure(&self) {
            let control = self.control.as_ref().unwrap();
            std::future::poll_fn(|cx| {
                control.failure_waker.register(cx.waker());
                if control.failed.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }
    #[derive(Default)]
    struct WaitTool {
        control: Option<Arc<Control>>,
    }
    #[reverie::tool]
    impl Tool for WaitTool {
        type GlobalState = WaitGlobal;
        type ThreadState = u64;
        fn new(_: Pid, _: &()) -> Self {
            Self {
                control: Some(tool_control()),
            }
        }
        fn subscriptions(_: &()) -> reverie::Subscription {
            reverie::Subscription::none()
        }
        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &u64)>) -> u64 {
            assert_eq!(tid, Pid::from_raw(1));
            assert!(parent.is_none());
            STATE
        }
        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            _: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(
                self.control
                    .as_ref()
                    .unwrap()
                    .thread_starts
                    .fetch_add(1, Ordering::SeqCst),
                0
            );
            Ok(())
        }
        async fn on_exit_thread<G: reverie::GlobalRPC<WaitGlobal>>(
            &self,
            tid: Pid,
            _: &G,
            state: u64,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(tid, Pid::from_raw(1));
            assert_eq!(state, STATE);
            let control = self.control.as_ref().unwrap();
            assert_eq!(control.thread_consumed.fetch_add(1, Ordering::SeqCst), 0);
            control
                .status
                .store(conventional_exit_code(status), Ordering::Release);
            let mut release = control.cleanup_receiver.lock().unwrap().take().unwrap();
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut release).poll(cx);
                if result.is_pending() {
                    control.consumer_pending.store(true, Ordering::Release);
                }
                result
            })
            .await
            .expect("controller releases actual consuming cleanup");
            Ok(())
        }
        async fn on_exit_process<G: reverie::GlobalRPC<WaitGlobal>>(
            self,
            pid: Pid,
            _: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let control = self.control.as_ref().unwrap();
            assert_eq!(pid, Pid::from_raw(1));
            assert_eq!(control.thread_consumed.load(Ordering::SeqCst), 1);
            assert_eq!(
                conventional_exit_code(status),
                control.status.load(Ordering::Acquire)
            );
            assert_eq!(control.process_consumed.fetch_add(1, Ordering::SeqCst), 0);
            Ok(())
        }
    }
    fn finish<F: Future>(mut run: Pin<&mut F>, cx: &mut Context<'_>) -> F::Output {
        let deadline = Instant::now() + WAIT;
        loop {
            match run.as_mut().poll(cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    assert!(
                        Instant::now() < deadline,
                        "released driver did not complete"
                    );
                    std::thread::yield_now();
                }
            }
        }
    }
    fn tool_case(boundary: Boundary, effect: Effect) {
        let (mut backend, exits) = elf();
        let (control, waited) = Control::install(&mut backend, Site::ToolMain);
        let _tool = ToolScope::new(control.clone());
        let _scope = control.scope();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut run = Box::pin(backend.run_static_elf_with_tool_completion::<WaitTool>((), false));
        let measured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(run.as_mut().poll(&mut cx).is_pending());
            initial_wait(&control, &waited, &exits);
            assert_eq!(control.thread_starts.load(Ordering::SeqCst), 1);
            assert_eq!(control.thread_consumed.load(Ordering::SeqCst), 0);
            let before_wait = control.wait_counts();
            let baseline = control.arm(boundary, effect);
            if effect == Effect::CloseAgain {
                control.reopen();
                assert!(run.as_mut().poll(&mut cx).is_pending());
                waited
                    .try_recv()
                    .expect("same Tool run never polled its second closed subscription");
                control.assert_held();
                assert_eq!(
                    control.wait_counts(),
                    (before_wait.0 + 1, before_wait.1 + 1)
                );
                assert_eq!(control.thread_consumed.load(Ordering::SeqCst), 0);
            } else {
                control.gate.notify_unchanged_for_test();
                assert!(run.as_mut().poll(&mut cx).is_pending());
                assert!(
                    control.consumer_pending.load(Ordering::Acquire),
                    "terminal consumer must be selected before reopen"
                );
                let expected = if effect == Effect::Global { 255 } else { STOP };
                assert_eq!(control.status.load(Ordering::Acquire), expected);
                assert_eq!(control.wait_counts(), before_wait);
                control.assert_held();
            }
            no_dispatch(&control, &exits);
            control.assert_action(baseline, boundary, effect);
            control.events.lock().unwrap().len()
        }));
        // No cleanup operation is required to pass a held fence: reopen before
        // releasing the actual selected consumer, also after assertion failure.
        control.reopen();
        control.release_consumer();
        if measured.is_err() {
            control.rescue();
        }
        let completed = finish(run.as_mut(), &mut cx);
        drop(run);
        let resumed_at = measured.unwrap_or_else(|payload| std::panic::resume_unwind(payload));
        let expected_retry = if effect == Effect::CloseAgain {
            vec![
                Event::Boundary(Boundary::BeforeSubscription),
                Event::Boundary(Boundary::AfterSubscription),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(
            &control.events.lock().unwrap()[resumed_at..],
            expected_retry.as_slice()
        );
        let completed = completed.unwrap();
        let status = if effect == Effect::Global {
            assert!(matches!(
                completed.result.unwrap_err().primary(),
                Error::RunAborted
            ));
            255
        } else {
            let expected = if effect == Effect::CloseAgain {
                EXIT
            } else {
                STOP
            };
            assert_eq!(
                completed.result.unwrap(),
                (expected, Vec::new(), Vec::new())
            );
            expected
        };
        drop(completed.global_state);
        assert_eq!(control.status.load(Ordering::Acquire), status);
        assert_eq!(control.thread_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(control.process_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(control.global_drops.load(Ordering::SeqCst), 1);
        assert_eq!(control.failures.load(Ordering::SeqCst), 0);
        assert!(!control.group.has_worker_handles());
        if effect == Effect::CloseAgain {
            finite_entry(&control, &exits, true);
        } else {
            no_dispatch(&control, &exits);
        }
    }

    fn parking_case(boundary: Boundary, effect: Effect) {
        let mut backend =
            KvmBackend::new(0x10000).expect("parking registration control requires /dev/kvm");
        backend.install_real_mode_program(0x1000, &[HLT]).unwrap();
        let registers = backend.vcpu.get_regs().unwrap();
        let mut trampoline = [0; 256];
        backend
            .memory
            .read_raw(SYSCALL_TRAMPOLINE_ADDRESS, &mut trampoline)
            .unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let (control, _) = Control::install(&mut backend, Site::Parking);
        control.probe.arm();
        control.close();
        let _scope = control.scope();
        let (sender, receiver) = oneshot::channel();
        *control.stop_sender.lock().unwrap() = Some(sender);
        let stop_control = control.clone();
        // An ordinary non-fused async block: repoll after completion is a real
        // failure, not hidden by a fused always-ready stand-in.
        let mut stop = Box::pin(async move {
            receiver.await.unwrap();
            assert_eq!(
                stop_control.stop_completions.fetch_add(1, Ordering::SeqCst),
                0
            );
        });
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut parking =
            Box::pin(backend.park_process_action("registration control", stop.as_mut()));
        let measured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(parking.as_mut().poll(&mut cx).is_pending());
            // This branch's only await is the actual gate/cancellation/stop
            // select. The before/after events bind this Pending to its real
            // subscription, rather than to an unrelated Tool callback.
            assert_eq!(
                *control.events.lock().unwrap(),
                vec![
                    Event::Boundary(Boundary::BeforeSubscription),
                    Event::Boundary(Boundary::AfterSubscription)
                ]
            );
            control.assert_held();
            no_dispatch(&control, &exits);
            let baseline = control.arm(boundary, effect);
            control.gate.notify_unchanged_for_test();
            let result = parking.as_mut().poll(&mut cx);
            if effect == Effect::Group {
                assert!(matches!(result, Poll::Ready(Ok(false))));
                assert_eq!(control.group.exit_status(), Some(ExitStatus::Exited(STOP)));
                assert_eq!(control.stop_completions.load(Ordering::SeqCst), 0);
            } else {
                assert!(matches!(result, Poll::Ready(Err(Error::RunAborted))));
                assert_eq!(control.stop_completions.load(Ordering::SeqCst), 1);
                assert!(control.stop_sender.lock().unwrap().is_none());
            }
            control.assert_action(baseline, boundary, effect);
            control.assert_held();
            no_dispatch(&control, &exits);
        }));
        drop(parking);
        drop(stop);
        control.reopen();
        if let Err(payload) = measured {
            std::panic::resume_unwind(payload);
        }
        // The measured interval has ended with exact zero work and terminal
        // return. Disarm only for fixture inspection; never reset counters.
        control.probe.prepare.armed.store(false, Ordering::Release);
        assert_eq!(backend.vcpu.get_regs().unwrap(), registers);
        let mut after = [0; 256];
        backend
            .memory
            .read_raw(SYSCALL_TRAMPOLINE_ADDRESS, &mut after)
            .unwrap();
        assert_eq!(
            after, trampoline,
            "registration cancellation changed the prepared bytes"
        );
    }

    #[test]
    fn host_elf_stop_before_retry_subscription_does_no_entry_work() {
        host_case(Boundary::BeforeSubscription, false);
    }
    #[test]
    fn host_elf_stop_after_retry_subscription_does_no_entry_work() {
        host_case(Boundary::AfterSubscription, false);
    }
    #[test]
    fn host_elf_same_run_second_close_waits_before_fresh_reopen() {
        host_case(Boundary::BeforeSubscription, true);
    }
    #[test]
    fn tool_elf_group_stop_before_retry_subscription_does_no_entry_work() {
        tool_case(Boundary::BeforeSubscription, Effect::Group);
    }
    #[test]
    fn tool_elf_group_stop_after_retry_subscription_does_no_entry_work() {
        tool_case(Boundary::AfterSubscription, Effect::Group);
    }
    #[test]
    fn tool_elf_global_stop_before_retry_subscription_does_no_entry_work() {
        tool_case(Boundary::BeforeSubscription, Effect::Global);
    }
    #[test]
    fn tool_elf_global_stop_after_retry_subscription_does_no_entry_work() {
        tool_case(Boundary::AfterSubscription, Effect::Global);
    }
    #[test]
    fn tool_elf_same_run_second_close_waits_before_fresh_reopen() {
        tool_case(Boundary::BeforeSubscription, Effect::CloseAgain);
    }
    #[test]
    fn parking_stop_before_retry_subscription_preserves_disposition() {
        for effect in [Effect::Group, Effect::OneShot] {
            parking_case(Boundary::BeforeSubscription, effect);
        }
    }
    #[test]
    fn parking_stop_after_retry_subscription_preserves_disposition() {
        for effect in [Effect::Group, Effect::OneShot] {
            parking_case(Boundary::AfterSubscription, effect);
        }
    }
}
