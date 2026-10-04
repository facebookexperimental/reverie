/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in vm::tests to reuse the private minimal static ELF fixture.
mod entry_main_tests {
    use std::collections::BTreeMap;
    use std::sync::Weak;
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::task::Context;
    use std::task::Poll;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const EXIT_CODE: i32 = 37;
    const STOP_CODE: i32 = 23;
    const THREAD_STATE: u64 = 0xc10_5ed;

    #[derive(Debug, Eq, PartialEq)]
    struct Counts {
        shared_fd: usize,
        masks: usize,
        untracked: usize,
        tracked: usize,
        begins: usize,
        intervals: usize,
    }

    fn counts(probe: &crate::clock::RunProbe) -> Counts {
        let load = |counter: &AtomicUsize| counter.load(Ordering::SeqCst);
        Counts {
            shared_fd: load(&probe.shared_fd_accesses),
            masks: load(&probe.prepare.mask_installs),
            untracked: load(&probe.untracked_runs),
            tracked: load(&probe.tracked_runs),
            begins: load(&probe.clock_begins),
            intervals: load(&probe.intervals_created),
        }
    }

    fn assert_no_dispatch(probe: &crate::clock::RunProbe, exits: &KvmExitCollector) {
        assert_eq!(
            counts(probe),
            Counts {
                shared_fd: 0,
                masks: 0,
                untracked: 0,
                tracked: 0,
                begins: 0,
                intervals: 0,
            }
        );
        assert_eq!(exits.snapshot().total_exits(), 0);
    }

    struct CloseControl {
        gate: Arc<crate::entry::EntryGate>,
        closed: Arc<Mutex<Option<crate::entry::Closed>>>,
        probe: Arc<crate::clock::RunProbe>,
        waited: mpsc::Receiver<()>,
    }

    impl CloseControl {
        fn install(backend: &mut KvmBackend) -> Self {
            let gate = backend.memory.entry_gate();
            let closed = Arc::new(Mutex::new(None));
            let probe = Arc::new(crate::clock::RunProbe::default());
            let (sender, waited) = mpsc::channel();
            probe.prepare.set_wait_notice(sender);
            let hook_gate = gate.clone();
            let hook_closed = closed.clone();
            probe.before_run(move |hook_probe| {
                // This is after caller setup and any ordinary stop check,
                // including its setup ioctls/initial clock validation. Nothing has
                // entered KVM yet; every participant is stopped at this fence.
                hook_probe.arm();
                let token = hook_gate
                    .try_close()
                    .unwrap()
                    .unwrap()
                    .finish()
                    .now_or_never()
                    .expect("initial stopped fence must be ready")
                    .unwrap();
                let mut slot = hook_closed.lock().unwrap();
                assert!(slot.is_none());
                *slot = Some(token);
            });
            backend.vcpu.set_run_probe(probe.clone());
            Self {
                gate,
                closed,
                probe,
                waited,
            }
        }

        fn reopen(&self) {
            let closed = self.closed.lock().unwrap().take();
            drop(closed);
        }

        fn assert_parked(&self) {
            assert!(self.closed.lock().unwrap().is_some());
            assert!(self.probe.prepare.closed_admissions.load(Ordering::Acquire) > 0);
            assert!(self.probe.prepare.closed_waits.load(Ordering::Acquire) > 0);
        }
    }

    impl Drop for CloseControl {
        fn drop(&mut self) {
            self.reopen();
        }
    }

    fn backend(elf: bool) -> (KvmBackend, Arc<KvmExitCollector>) {
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("real main-entry control requires /dev/kvm");
        if elf {
            // mov eax,231; mov edi,37; syscall. One real exit_group effect.
            let mut code = vec![0xb8, 231, 0, 0, 0, 0xbf];
            code.extend_from_slice(&EXIT_CODE.to_le_bytes());
            code.extend_from_slice(&[0x0f, 0x05]);
            backend
                .install_static_elf(&minimal_test_elf(&code), "/bin/entry-main")
                .unwrap();
        } else {
            backend.install_real_mode_program(0x1000, &[0xf4]).unwrap();
        }
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        (backend, exits)
    }

    fn assert_finite_entry(
        probe: &crate::clock::RunProbe,
        exits: &KvmExitCollector,
        elf: bool,
        tool: bool,
    ) {
        let observed = counts(probe);
        assert_eq!(observed.masks, 1);
        assert_eq!(observed.untracked, usize::from(!tool));
        assert_eq!(observed.tracked, usize::from(tool));
        assert_eq!(observed.begins, usize::from(tool));
        assert_eq!(observed.intervals, usize::from(tool));
        // ELF handles its real syscall using register access after the exit.
        if elf {
            assert!(observed.shared_fd > 0);
        }
        let snapshot = exits.snapshot();
        assert_eq!(snapshot.total_exits(), 1);
        assert_eq!(
            snapshot.count(if elf {
                crate::stats::KvmExitReason::Hypercall
            } else {
                crate::stats::KvmExitReason::Hlt
            }),
            1
        );
    }

    struct HostRescue {
        gate: Arc<crate::entry::EntryGate>,
        closed: Arc<Mutex<Option<crate::entry::Closed>>>,
        group: Arc<GuestThreadGroup>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for HostRescue {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                let closed = self.closed.lock().unwrap().take();
                drop(closed);
                self.gate.poison(
                    None,
                    Error::GuestClock("failed main-entry control rescue".into()),
                );
                self.group.request_exit_group(ExitStatus::Exited(255));
                thread.join().unwrap();
            }
        }
    }

    fn host_case(elf: bool, stop: bool) {
        let (mut backend, exits) = backend(elf);
        let control = CloseControl::install(&mut backend);
        let group = backend.thread_group.clone();
        let (sender, result) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let outcome = if elf {
                backend.run_static_elf()
            } else {
                backend
                    .run(|_, _| panic!("HLT fixture dispatched a syscall"))
                    .map(|_| 0)
            };
            sender
                .send((backend, outcome))
                .unwrap_or_else(|_| panic!("Host controller dropped its outcome receiver"));
        });
        let mut rescue = HostRescue {
            gate: control.gate.clone(),
            closed: control.closed.clone(),
            group: group.clone(),
            thread: Some(thread),
        };
        control
            .waited
            .recv_timeout(WAIT)
            .expect("Host driver never polled a real closed wait");
        control.assert_parked();
        assert_no_dispatch(&control.probe, &exits);
        assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let cause = Arc::new(Error::GuestClock("raw main stop while closed".into()));
        if stop {
            if elf {
                group.request_exit_group(ExitStatus::Exited(STOP_CODE));
            } else {
                control
                    .gate
                    .poison(None, Error::SharedFailure(cause.clone()));
            }
        } else {
            control.reopen();
        }
        // Terminal Host selection must complete before reopen. If the driver
        // regresses, rescue opens the fence and the assertion still fails.
        let completed = result.recv_timeout(WAIT);
        if completed.is_err() {
            control.reopen();
        }
        let (backend, outcome) = completed.expect("Host terminal choice waited for reopening");
        if stop {
            control.assert_parked();
            assert_no_dispatch(&control.probe, &exits);
            if elf {
                assert_eq!(outcome.unwrap(), STOP_CODE);
            } else {
                assert!(crate::failure::references_shared_error(
                    &outcome.unwrap_err(),
                    &cause
                ));
            }
            control.reopen();
        } else {
            assert_eq!(outcome.unwrap(), if elf { EXIT_CODE } else { 0 });
            assert_finite_entry(&control.probe, &exits, elf, false);
        }
        rescue.thread.take().unwrap().join().unwrap();
        assert!(!group.has_worker_handles());
        drop(backend);
        if stop {
            assert_no_dispatch(&control.probe, &exits);
        }
    }

    #[test]
    fn host_raw_main_closed_wait_poison_stops_without_ioctl() {
        host_case(false, true);
    }

    #[test]
    fn host_elf_main_closed_wait_group_exit_stops_without_ioctl() {
        host_case(true, true);
    }

    #[test]
    fn host_main_fresh_reopen_executes_finite_raw_and_elf_once() {
        host_case(false, false);
        host_case(true, false);
    }

    static NEXT: AtomicU64 = AtomicU64::new(1);
    static OBSERVATIONS: OnceLock<Mutex<BTreeMap<u64, Weak<ToolObservation>>>> = OnceLock::new();

    struct ToolObservation {
        failed: AtomicBool,
        failure_waker: futures::task::AtomicWaker,
        failures: Mutex<Vec<reverie::BackendFailure>>,
        events: Mutex<Vec<(u8, i32)>>,
        terminal_status: AtomicI32,
        consumer_pending: AtomicBool,
        cleanup_receiver: Mutex<Option<oneshot::Receiver<()>>>,
        cleanup_sender: Mutex<Option<oneshot::Sender<()>>>,
        global_drops: AtomicUsize,
    }

    impl ToolObservation {
        fn new() -> Arc<Self> {
            let (sender, receiver) = oneshot::channel();
            Arc::new(Self {
                failed: AtomicBool::new(false),
                failure_waker: Default::default(),
                failures: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                terminal_status: AtomicI32::new(-1),
                consumer_pending: AtomicBool::new(false),
                cleanup_receiver: Mutex::new(Some(receiver)),
                cleanup_sender: Mutex::new(Some(sender)),
                global_drops: AtomicUsize::new(0),
            })
        }

        fn fail(&self) {
            self.failed.store(true, Ordering::Release);
            self.failure_waker.wake();
        }

        fn release_consumer(&self) {
            let sender = self.cleanup_sender.lock().unwrap().take();
            if let Some(sender) = sender {
                let _ = sender.send(());
            }
        }
    }

    struct ObservationRegistration(u64, Arc<ToolObservation>);

    impl ObservationRegistration {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let observation = ToolObservation::new();
            OBSERVATIONS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .insert(id, Arc::downgrade(&observation));
            Self(id, observation)
        }
    }

    impl Drop for ObservationRegistration {
        fn drop(&mut self) {
            self.1.release_consumer();
            OBSERVATIONS.get().unwrap().lock().unwrap().remove(&self.0);
        }
    }

    #[derive(Default)]
    struct EntryGlobal {
        observation: Option<Arc<ToolObservation>>,
    }

    impl Drop for EntryGlobal {
        fn drop(&mut self) {
            if let Some(observed) = &self.observation {
                observed.global_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for EntryGlobal {
        type Request = (u8, i32);
        type Response = ();
        type Config = u64;

        async fn init_global_state(id: &u64) -> Self {
            Self {
                observation: Some(
                    OBSERVATIONS.get().unwrap().lock().unwrap()[id]
                        .upgrade()
                        .unwrap(),
                ),
            }
        }

        async fn receive_rpc(&self, from: Pid, (kind, status): (u8, i32)) {
            assert_eq!(from, Pid::from_raw(1));
            let observed = self.observation.as_ref().unwrap();
            observed.events.lock().unwrap().push((kind, status));
            if kind == 1 {
                observed.terminal_status.store(status, Ordering::Release);
                let mut receiver = observed.cleanup_receiver.lock().unwrap().take().unwrap();
                std::future::poll_fn(|cx| {
                    let outcome = Pin::new(&mut receiver).poll(cx);
                    if outcome.is_pending() {
                        observed.consumer_pending.store(true, Ordering::Release);
                    }
                    outcome
                })
                .await
                .expect("controller releases the selected terminal consumer");
            }
        }

        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            self.observation
                .as_ref()
                .unwrap()
                .failures
                .lock()
                .unwrap()
                .push(event);
        }

        async fn wait_for_backend_failure(&self) {
            let observed = self.observation.as_ref().unwrap();
            std::future::poll_fn(|cx| {
                observed.failure_waker.register(cx.waker());
                if observed.failed.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }

    #[derive(Default)]
    struct EntryTool;

    #[reverie::tool]
    impl Tool for EntryTool {
        type GlobalState = EntryGlobal;
        type ThreadState = u64;

        fn subscriptions(_: &u64) -> reverie::Subscription {
            reverie::Subscription::none()
        }

        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &u64)>) -> u64 {
            assert_eq!(tid, Pid::from_raw(1));
            assert!(parent.is_none());
            THREAD_STATE
        }

        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            guest.send_rpc((0, 0)).await;
            Ok(())
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<EntryGlobal>>(
            &self,
            tid: Pid,
            global: &G,
            state: u64,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(tid, Pid::from_raw(1));
            assert_eq!(state, THREAD_STATE);
            global.send_rpc((1, conventional_exit_code(status))).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<EntryGlobal>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(pid, Pid::from_raw(1));
            global.send_rpc((2, conventional_exit_code(status))).await;
            Ok(())
        }
    }

    struct NoSyscalls;
    impl crate::runtime::SyscallExecutor for NoSyscalls {
        fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> i64 {
            panic!("direct HLT control dispatched a syscall")
        }
    }

    async fn run_tool(backend: &mut KvmBackend, config: u64, elf: bool) -> Result<i32> {
        if elf {
            let completion = backend
                .run_static_elf_with_tool_completion::<EntryTool>(config, false)
                .await?;
            drop(completion.global_state);
            completion.result.map(|(code, stdout, stderr)| {
                assert!(stdout.is_empty() && stderr.is_empty());
                code
            })
        } else {
            let global = backend
                .run_with_tool::<EntryTool, _>(config, NoSyscalls)
                .await?;
            drop(global);
            Ok(0)
        }
    }

    fn finish<F: Future>(mut future: Pin<&mut F>, cx: &mut Context<'_>) -> F::Output {
        let deadline = Instant::now() + WAIT;
        loop {
            match future.as_mut().poll(cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    assert!(
                        Instant::now() < deadline,
                        "main-entry driver failed to finish after rescue/reopen"
                    );
                    std::thread::yield_now();
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Stop {
        Global,
        Group,
        Reopen,
    }

    fn tool_case(elf: bool, stop: Stop) {
        let (mut backend, exits) = backend(elf);
        let group = backend.thread_group.clone();
        let control = CloseControl::install(&mut backend);
        let registration = ObservationRegistration::new();
        let observed = &registration.1;
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut run = Box::pin(run_tool(&mut backend, registration.0, elf));
        assert!(run.as_mut().poll(&mut cx).is_pending());
        control
            .waited
            .try_recv()
            .expect("Tool Pending was not the actual closed gate wait");
        control.assert_parked();
        assert_no_dispatch(&control.probe, &exits);
        assert_eq!(*observed.events.lock().unwrap(), vec![(0, 0)]);

        // A real notification without a state change must recheck once and
        // park again. It cannot become an entry or a busy retry loop.
        let denials = control
            .probe
            .prepare
            .closed_admissions
            .load(Ordering::SeqCst);
        let waits = control.probe.prepare.closed_waits.load(Ordering::SeqCst);
        control.gate.notify_unchanged_for_test();
        assert!(run.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            control
                .probe
                .prepare
                .closed_admissions
                .load(Ordering::SeqCst),
            denials + 1
        );
        assert_eq!(
            control.probe.prepare.closed_waits.load(Ordering::SeqCst),
            waits + 1
        );
        assert_no_dispatch(&control.probe, &exits);

        match stop {
            Stop::Global => observed.fail(),
            Stop::Group => group.request_exit_group(ExitStatus::Exited(STOP_CODE)),
            Stop::Reopen => control.reopen(),
        }
        let terminal_before_reopen = if matches!(stop, Stop::Reopen) {
            true
        } else {
            assert!(run.as_mut().poll(&mut cx).is_pending());
            let selected = observed.consumer_pending.load(Ordering::Acquire);
            let expected = if matches!(stop, Stop::Global) {
                255
            } else {
                STOP_CODE
            };
            let correct_status = observed.terminal_status.load(Ordering::Acquire) == expected;
            control.assert_parked();
            assert_no_dispatch(&control.probe, &exits);
            selected && correct_status
        };
        // Terminal choice is observed in the actual consuming hook. Open the
        // unchanged Mapping before allowing any dependent cleanup to finish.
        control.reopen();
        observed.release_consumer();
        let result = finish(run.as_mut(), &mut cx);
        drop(run);
        assert!(
            terminal_before_reopen,
            "reopen preceded the actual selected terminal consumer"
        );
        let status = match stop {
            Stop::Global => {
                assert!(matches!(result.unwrap_err().primary(), Error::RunAborted));
                assert_no_dispatch(&control.probe, &exits);
                255
            }
            Stop::Group => {
                assert_eq!(result.unwrap(), STOP_CODE);
                assert_no_dispatch(&control.probe, &exits);
                STOP_CODE
            }
            Stop::Reopen => {
                let status = if elf { EXIT_CODE } else { 0 };
                assert_eq!(result.unwrap(), status);
                assert_finite_entry(&control.probe, &exits, elf, true);
                status
            }
        };
        assert_eq!(
            *observed.events.lock().unwrap(),
            vec![(0, 0), (1, status), (2, status)]
        );
        assert_eq!(observed.global_drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed.failures.lock().unwrap().len(),
            usize::from(!elf && matches!(stop, Stop::Global))
        );
        assert!(!group.has_worker_handles());
        drop(backend);
        if !matches!(stop, Stop::Reopen) {
            assert_no_dispatch(&control.probe, &exits);
        }
    }

    #[test]
    fn tool_direct_main_closed_wait_global_failure_stops_without_ioctl() {
        tool_case(false, Stop::Global);
    }

    #[test]
    fn tool_elf_main_closed_wait_group_exit_stops_without_ioctl() {
        tool_case(true, Stop::Group);
    }

    #[test]
    fn tool_elf_main_closed_wait_global_failure_stops_without_ioctl() {
        tool_case(true, Stop::Global);
    }

    #[test]
    fn tool_main_fresh_reopen_executes_finite_direct_and_elf_once() {
        tool_case(false, Stop::Reopen);
        tool_case(true, Stop::Reopen);
    }

    #[test]
    fn closed_tool_main_wait_uses_its_independent_global_scope() {
        let (mut first, first_exits) = backend(true);
        let (mut second, second_exits) = backend(true);
        let first_control = CloseControl::install(&mut first);
        let second_control = CloseControl::install(&mut second);
        let first_observation = ObservationRegistration::new();
        let second_observation = ObservationRegistration::new();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut first_run = Box::pin(run_tool(&mut first, first_observation.0, true));
        let mut second_run = Box::pin(run_tool(&mut second, second_observation.0, true));
        assert!(first_run.as_mut().poll(&mut cx).is_pending());
        assert!(second_run.as_mut().poll(&mut cx).is_pending());
        first_control.waited.try_recv().unwrap();
        second_control.waited.try_recv().unwrap();
        first_control.assert_parked();
        second_control.assert_parked();
        first_observation.1.fail();
        assert!(first_run.as_mut().poll(&mut cx).is_pending());
        assert!(first_observation.1.consumer_pending.load(Ordering::Acquire));
        assert_eq!(
            first_observation.1.terminal_status.load(Ordering::Acquire),
            255
        );
        assert!(second_run.as_mut().poll(&mut cx).is_pending());
        assert!(
            !second_observation
                .1
                .consumer_pending
                .load(Ordering::Acquire)
        );
        assert_eq!(*second_observation.1.events.lock().unwrap(), vec![(0, 0)]);
        assert_no_dispatch(&first_control.probe, &first_exits);
        assert_no_dispatch(&second_control.probe, &second_exits);
        first_control.reopen();
        first_observation.1.release_consumer();
        assert!(matches!(
            finish(first_run.as_mut(), &mut cx).unwrap_err().primary(),
            Error::RunAborted
        ));
        drop(first_run);
        second_control.reopen();
        second_observation.1.release_consumer();
        assert_eq!(finish(second_run.as_mut(), &mut cx).unwrap(), EXIT_CODE);
        drop(second_run);
        assert_no_dispatch(&first_control.probe, &first_exits);
        assert_finite_entry(&second_control.probe, &second_exits, true, true);
        assert_eq!(
            *first_observation.1.events.lock().unwrap(),
            vec![(0, 0), (1, 255), (2, 255)]
        );
        assert_eq!(
            *second_observation.1.events.lock().unwrap(),
            vec![(0, 0), (1, EXIT_CODE), (2, EXIT_CODE)]
        );
        assert_eq!(first_observation.1.global_drops.load(Ordering::SeqCst), 1);
        assert_eq!(second_observation.1.global_drops.load(Ordering::SeqCst), 1);
        assert!(second_observation.1.failures.lock().unwrap().is_empty());
        assert!(!first.thread_group.has_worker_handles());
        assert!(!second.thread_group.has_worker_handles());
        drop(first);
        drop(second);
        assert_no_dispatch(&first_control.probe, &first_exits);
        assert_finite_entry(&second_control.probe, &second_exits, true, true);
    }
}
