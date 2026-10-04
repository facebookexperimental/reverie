/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests. The observations below never replace an operation.
pub(crate) mod entry_action_tests {
    use std::cell::RefCell;
    use std::sync::Weak;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Poll;
    use std::time::Duration;
    use std::time::Instant;

    use reverie::Guest;

    use super::*;

    const CHILD: i32 = 2;
    const PARENT_TID: u64 = 0x20_1000;
    const CHILD_TID: u64 = PARENT_TID + 8;
    const CHILD_RAN: u64 = PARENT_TID + 16;
    const WAIT_STATUS: u64 = PARENT_TID + 24;
    const ORIGINAL_PARENT: i32 = -101;
    const ORIGINAL_CHILD: i32 = -202;
    const STOP: i32 = 29;
    const EXEC_EXIT: i32 = 53;
    const STAGES: [&str; 12] = [
        "snapshot",
        "fork_backend",
        "thread_backend",
        "exec_image",
        "parent_capture",
        "park_restore",
        "park_prepare",
        "park_hlt",
        "fork_executor",
        "host_spawn",
        "tool_spawn",
        "tid_store",
    ];

    struct Stages {
        counts: [AtomicUsize; STAGES.len()],
        fork_memory: Mutex<Option<Weak<crate::entry::EntryGate>>>,
    }

    impl Default for Stages {
        fn default() -> Self {
            Self {
                counts: std::array::from_fn(|_| AtomicUsize::new(0)),
                fork_memory: Mutex::new(None),
            }
        }
    }

    impl Stages {
        fn count(&self, stage: &str) -> usize {
            self.counts[STAGES
                .iter()
                .position(|candidate| *candidate == stage)
                .unwrap()]
            .load(Ordering::SeqCst)
        }

        fn assert_exact(&self, expected: &[(&str, usize)]) {
            for stage in STAGES {
                let count = expected
                    .iter()
                    .find(|(name, _)| *name == stage)
                    .map_or(0, |(_, count)| *count);
                assert_eq!(self.count(stage), count, "action stage {stage}");
            }
        }
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Stages>>> = const { RefCell::new(None) };
    }

    pub(crate) fn observe(stage: &'static str) {
        // Unarmed production neighbors may run during host TLS destruction.
        // Observation must not invent a failure if this test-only key is gone.
        let _ = ACTIVE.try_with(|slot| {
            if let Some(probe) = slot.borrow().as_ref() {
                let index = STAGES
                    .iter()
                    .position(|candidate| *candidate == stage)
                    .unwrap();
                probe.counts[index].fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    pub(crate) fn observe_fork_memory(gate: &Arc<crate::entry::EntryGate>) {
        let _ = ACTIVE.try_with(|slot| {
            if let Some(probe) = slot.borrow().as_ref() {
                assert!(
                    probe
                        .fork_memory
                        .lock()
                        .unwrap()
                        .replace(Arc::downgrade(gate))
                        .is_none()
                );
            }
        });
    }

    struct ObservationScope {
        prior: Option<Arc<Stages>>,
        thread: std::thread::ThreadId,
    }

    impl ObservationScope {
        fn new(probe: Arc<Stages>) -> Self {
            Self {
                prior: ACTIVE.with(|slot| slot.replace(Some(probe))),
                thread: std::thread::current().id(),
            }
        }
    }

    impl Drop for ObservationScope {
        fn drop(&mut self) {
            assert_eq!(self.thread, std::thread::current().id());
            let old = ACTIVE.with(|slot| slot.replace(self.prior.take()));
            drop(old);
        }
    }

    #[derive(Default)]
    struct ActionLog {
        failed: AtomicBool,
        failure_waker: futures::task::AtomicWaker,
        initialized: AtomicUsize,
        child_state: Mutex<Option<Weak<usize>>>,
        events: Mutex<Vec<(u8, i32, i32)>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for ActionLog {
        type Request = (u8, i32, i32);
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, from: Pid, event: Self::Request) {
            assert_eq!(from.as_raw(), CHILD);
            self.events.lock().unwrap().push(event);
        }

        async fn wait_for_backend_failure(&self) {
            futures::future::poll_fn(|cx| {
                self.failure_waker.register(cx.waker());
                if self.failed.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }

    #[derive(Default)]
    struct ActionTool {
        observed: Arc<ActionLog>,
    }

    #[reverie::tool]
    impl Tool for ActionTool {
        type GlobalState = ActionLog;
        type ThreadState = Arc<usize>;

        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &Arc<usize>)>) -> Arc<usize> {
            assert_eq!(tid.as_raw(), CHILD);
            let (parent_tid, parent_state) = parent.unwrap();
            assert_eq!(parent_tid.as_raw(), 1);
            assert_eq!(**parent_state, 1);
            assert_eq!(self.observed.initialized.fetch_add(1, Ordering::SeqCst), 0);
            let state = Arc::new(CHILD as usize);
            *self.observed.child_state.lock().unwrap() = Some(Arc::downgrade(&state));
            state
        }

        async fn handle_thread_start<G: Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            guest.send_rpc((1, guest.tid().as_raw(), 0)).await;
            Ok(())
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<ActionLog>>(
            &self,
            tid: Pid,
            global: &G,
            state: Arc<usize>,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(tid.as_raw(), CHILD);
            assert_eq!(*state, CHILD as usize);
            assert!(Weak::ptr_eq(
                self.observed.child_state.lock().unwrap().as_ref().unwrap(),
                &Arc::downgrade(&state),
            ));
            assert_eq!(Arc::strong_count(&state), 1);
            global
                .send_rpc((2, tid.as_raw(), conventional_exit_code(status)))
                .await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<ActionLog>>(
            self,
            _: Pid,
            _: &G,
            _: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            panic!("a Tool thread consumed its shared process Tool");
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Site {
        Fork,
        HostThread,
        Exec,
        ToolThread,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Failure,
        Cancel,
        Poison,
        Reopen,
    }

    fn fixture() -> (KvmBackend, ElfExecutor, u64) {
        // Actual getpid hypercall, then read the real child-TID store as the
        // child's exit status. No user HLT is accepted as a successful child.
        let mut code = vec![0xb8];
        code.extend_from_slice(&(libc::SYS_getpid as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x8b, 0x3c, 0x25]);
        code.extend_from_slice(&(CHILD_TID as u32).to_le_bytes());
        // mov dword [CHILD_RAN], edi: shared-thread cases expose the value
        // actually read by the child before its exit syscall.
        code.extend_from_slice(&[0x89, 0x3c, 0x25]);
        code.extend_from_slice(&(CHILD_RAN as u32).to_le_bytes());
        code.push(0xb8);
        code.extend_from_slice(&(libc::SYS_exit as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        let mut image = minimal_test_elf(&code);
        // This new fixture has legitimate writable TID data in its second
        // page. Existing loader/copy permission guards remain in force.
        image[68..72].copy_from_slice(&7u32.to_le_bytes());
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("action controls require /dev/kvm");
        backend
            .install_static_elf(&image, "/bin/entry-action")
            .unwrap();
        backend
            .memory
            .write_raw(PARENT_TID, &ORIGINAL_PARENT.to_le_bytes())
            .unwrap();
        backend
            .memory
            .write_raw(CHILD_TID, &ORIGINAL_CHILD.to_le_bytes())
            .unwrap();
        backend.vcpu.track_clock().unwrap();
        let mut executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
        match backend
            .vcpu
            .run()
            .unwrap()
            .expect("fixture admission unexpectedly closed")
        {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                *exit.ret = 0;
            }
            exit => panic!("fixture did not reach actual getpid boundary: {exit:?}"),
        }
        let boundary =
            CompletedSyscallBoundary::capture(&backend, backend.syscall_frame_address, None)
                .unwrap();
        executor.set_current_user_stack_pointer(boundary.registers.rsp);
        let child_stack = boundary.registers.rsp - 4096;
        backend.set_backend_stats_request(BackendStatsRequest::ENABLED);
        (backend, executor, child_stack)
    }

    fn action(site: Site, stack: u64) -> ProcessAction {
        match site {
            Site::Fork => ProcessAction::Fork {
                child_pid: CHILD,
                child_stack: None,
                parent_tid: Some(PARENT_TID),
                child_tid: Some(CHILD_TID),
                clear_child_tid: None,
                clear_sighand: false,
                share_address_space: false,
            },
            Site::HostThread | Site::ToolThread => ProcessAction::Thread {
                child_tid: CHILD,
                child_stack: stack,
                parent_tid: Some(PARENT_TID),
                child_tid_address: Some(CHILD_TID),
                clear_child_tid: None,
                tls: None,
            },
            Site::Exec => {
                let mut code = vec![0xbf];
                code.extend_from_slice(&EXEC_EXIT.to_le_bytes());
                code.push(0xb8);
                code.extend_from_slice(&(libc::SYS_exit as u32).to_le_bytes());
                code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
                ProcessAction::Exec {
                    executable_path: Path::new("/bin/entry-action-new").to_owned(),
                    executable_file: None,
                    image: minimal_test_elf(&code),
                    argv: vec!["/bin/entry-action-new".to_owned()],
                    envp: vec![],
                }
            }
        }
    }

    struct ClosedScope(Arc<Mutex<Option<crate::entry::Closed>>>);
    impl ClosedScope {
        fn reopen(&self) {
            let token = self.0.lock().unwrap().take();
            drop(token);
        }
    }
    impl Drop for ClosedScope {
        fn drop(&mut self) {
            self.reopen();
        }
    }

    fn no_entry(probe: &crate::clock::RunProbe, exits: &KvmExitCollector) {
        for counter in [
            &probe.shared_fd_accesses,
            &probe.untracked_runs,
            &probe.tracked_runs,
            &probe.clock_begins,
            &probe.intervals_created,
            &probe.prepare.mask_installs,
        ] {
            assert_eq!(counter.load(Ordering::SeqCst), 0);
        }
        assert_eq!(exits.snapshot().total_exits(), 0);
    }

    fn finish<F: Future + ?Sized>(mut future: Pin<&mut F>, cx: &mut Context<'_>) -> F::Output {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return result;
            }
            assert!(
                Instant::now() < deadline,
                "action did not complete after notification"
            );
            std::thread::yield_now();
        }
    }

    fn case(site: Site, event: Event) {
        let (mut backend, mut executor, stack) = fixture();
        backend.thread_ownership = if site == Site::ToolThread {
            ThreadOwnership::Tool
        } else {
            ThreadOwnership::Host
        };
        let group = backend.thread_group.clone();
        // The production pool initializes lazily and retains its capacity
        // after release. Initialize through its real reserve/release path
        // before measurement so exact equality detects any live slot rather
        // than comparing initialized storage with an empty representation.
        assert!(group.transport_slots.lock().unwrap().is_empty());
        let initial_slot = group.reserve_transport_slot(CHILD).unwrap();
        assert_eq!(initial_slot, 0);
        {
            let allocated = group.transport_slots.lock().unwrap();
            assert_eq!(allocated.len(), MAX_GUEST_THREADS as usize);
            for (index, in_use) in allocated.iter().enumerate() {
                assert_eq!(*in_use, index == initial_slot);
            }
        }
        group.release_transport_slot(initial_slot);
        let slots = group.transport_slots.lock().unwrap().clone();
        assert_eq!(slots, vec![false; MAX_GUEST_THREADS as usize]);
        let memory = backend.memory.clone();
        let mut original_image = [0; 64];
        memory.read_raw(0x20_0000, &mut original_image).unwrap();
        let gate = memory.entry_gate();
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let stages = Arc::new(Stages::default());
        let _observations = ObservationScope::new(stages.clone());
        let run_probe = Arc::new(crate::clock::RunProbe::default());
        let (notice, waited) = std::sync::mpsc::channel();
        run_probe.prepare.set_wait_notice(notice);
        let closed = ClosedScope(Arc::new(Mutex::new(None)));
        let hook_token = closed.0.clone();
        let hook_gate = gate.clone();
        let hook_memory = memory.clone();
        let prepared_bytes = Arc::new(Mutex::new(None));
        let hook_bytes = prepared_bytes.clone();
        run_probe.before_run(move |probe| {
            let mut bytes = [0; 256];
            hook_memory
                .read_raw(SYSCALL_TRAMPOLINE_ADDRESS, &mut bytes)
                .unwrap();
            *hook_bytes.lock().unwrap() = Some(bytes);
            probe.arm();
            let token = hook_gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .expect("parking hook had an active participant")
                .unwrap();
            assert!(hook_token.lock().unwrap().replace(token).is_none());
        });
        backend.vcpu.set_run_probe(run_probe.clone());
        let log = Arc::new(ActionLog::default());
        let tool = Arc::new(ActionTool {
            observed: log.clone(),
        });
        let parent_state = Arc::new(1usize);
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (stop_sender, stop_receiver) = oneshot::channel();
        let mut stop = Box::pin(async {
            stop_receiver.await.unwrap();
        });
        let cause = Arc::new(Error::GuestClock("prepared action poison".to_owned()));
        let prepared_action = action(site, stack);
        let mut running: Pin<Box<dyn Future<Output = Result<ProcessActionOutcome>> + '_>> =
            if site == Site::ToolThread {
                Box::pin(backend.run_process_action_with_tool_inner(
                    &mut executor,
                    prepared_action,
                    true,
                    ToolContext::<ActionTool> {
                        pid: Pid::from_raw(1),
                        tid: Pid::from_raw(1),
                        process_state: tool.clone(),
                        thread_state: &parent_state,
                        global_state: Some(log.clone()),
                        config: (),
                        subscriptions: reverie::Subscription::none(),
                        pending_child_starts: starts.clone(),
                    },
                    None,
                ))
            } else {
                Box::pin(backend.run_process_action_inner(
                    &mut executor,
                    prepared_action,
                    true,
                    None,
                    stop.as_mut(),
                    None,
                ))
            };
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(running.as_mut().poll(&mut cx).is_pending());
        waited
            .try_recv()
            .expect("caller did not reach a real closed parking wait");
        assert!(closed.0.lock().unwrap().is_some());
        assert!(run_probe.prepare.closed_admissions.load(Ordering::SeqCst) > 0);
        assert!(run_probe.prepare.closed_waits.load(Ordering::SeqCst) > 0);
        let prepared = match site {
            Site::Fork => vec![("fork_executor", 1), ("park_prepare", 1)],
            Site::HostThread | Site::ToolThread => vec![("parent_capture", 1), ("park_prepare", 1)],
            Site::Exec => vec![("park_prepare", 1)],
        };
        stages.assert_exact(&prepared);
        no_entry(&run_probe, &exits);
        assert_eq!(*group.transport_slots.lock().unwrap(), slots);
        assert!(!group.has_worker_handles());
        assert!(starts.lock().unwrap().is_empty());
        assert_eq!(log.initialized.load(Ordering::SeqCst), 0);
        assert!(log.events.lock().unwrap().is_empty());
        let waits = run_probe.prepare.closed_waits.load(Ordering::SeqCst);
        gate.notify_unchanged_for_test();
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            run_probe.prepare.closed_waits.load(Ordering::SeqCst),
            waits + 1
        );
        stages.assert_exact(&prepared);
        no_entry(&run_probe, &exits);
        assert_eq!(*group.transport_slots.lock().unwrap(), slots);
        match event {
            Event::Failure if site == Site::ToolThread => {
                log.failed.store(true, Ordering::Release);
                log.failure_waker.wake();
            }
            Event::Failure => {
                stop_sender.send(()).unwrap();
            }
            Event::Cancel => group.request_exit_group(ExitStatus::Exited(STOP)),
            Event::Poison => {
                gate.poison(None, Error::SharedFailure(cause.clone()));
            }
            Event::Reopen => closed.reopen(),
        }
        let result = finish(running.as_mut(), &mut cx);
        drop(running);
        if event != Event::Reopen {
            assert!(
                closed.0.lock().unwrap().is_some(),
                "terminal action waited for reopen"
            );
            match event {
                Event::Failure => {
                    assert!(matches!(result.unwrap_err().primary(), Error::RunAborted))
                }
                Event::Cancel => {
                    assert_eq!(result.unwrap(), ProcessActionOutcome::cancelled());
                    assert_eq!(group.exit_status(), Some(ExitStatus::Exited(STOP)));
                }
                Event::Poison => assert!(crate::failure::references_shared_error(
                    &result.unwrap_err(),
                    &cause
                )),
                Event::Reopen => unreachable!(),
            }
            stages.assert_exact(&prepared);
            no_entry(&run_probe, &exits);
            assert!(!group.has_worker_handles());
            assert!(starts.lock().unwrap().is_empty());
            assert_eq!(log.initialized.load(Ordering::SeqCst), 0);
            assert!(log.events.lock().unwrap().is_empty());
            // All futures have returned; this fixture still owns the backing.
            // Inspect exact bytes without asking a poisoned/closed gate to admit
            // another copy. No pointer is passed to production across a wait.
            let raw = |address: u64, length: usize| unsafe {
                std::slice::from_raw_parts((memory.host_address() + address) as *const u8, length)
            };
            assert_eq!(raw(PARENT_TID, 4), ORIGINAL_PARENT.to_le_bytes());
            assert_eq!(raw(CHILD_TID, 4), ORIGINAL_CHILD.to_le_bytes());
            assert_eq!(raw(CHILD_RAN, 4), [0; 4]);
            assert_eq!(raw(0x20_0000, original_image.len()), original_image);
            // park_process_action documents why terminal preparation leaves
            // this retired thread's park byte installed instead of restoring.
            assert_eq!(
                raw(SYSCALL_TRAMPOLINE_ADDRESS, 256),
                prepared_bytes.lock().unwrap().as_ref().unwrap()
            );
            closed.reopen();
        } else {
            let expected = if site == Site::Exec {
                ProcessActionOutcome::replaced()
            } else {
                ProcessActionOutcome::returned(i64::from(CHILD))
            };
            assert_eq!(result.unwrap(), expected);
            let mut completed = prepared.clone();
            completed.extend([("park_hlt", 1), ("park_restore", 1)]);
            match site {
                Site::Fork => {
                    completed.extend([("snapshot", 1), ("fork_backend", 1), ("tid_store", 2)])
                }
                Site::HostThread => {
                    completed.extend([("thread_backend", 1), ("host_spawn", 1), ("tid_store", 2)])
                }
                Site::ToolThread => {
                    completed.extend([("thread_backend", 1), ("tool_spawn", 1), ("tid_store", 2)])
                }
                Site::Exec => completed.push(("exec_image", 1)),
            }
            stages.assert_exact(&completed);
            assert_eq!(run_probe.tracked_runs.load(Ordering::SeqCst), 1);
            assert_eq!(run_probe.untracked_runs.load(Ordering::SeqCst), 0);
            assert_eq!(run_probe.prepare.mask_installs.load(Ordering::SeqCst), 1);
            assert_eq!(run_probe.clock_begins.load(Ordering::SeqCst), 1);
            assert_eq!(run_probe.intervals_created.load(Ordering::SeqCst), 1);
            assert_eq!(exits.snapshot().count(crate::stats::KvmExitReason::Hlt), 1);
            if site == Site::ToolThread {
                assert_eq!(log.initialized.load(Ordering::SeqCst), 1);
                assert_eq!(starts.lock().unwrap().len(), 1);
                assert!(
                    log.events.lock().unwrap().is_empty(),
                    "child started before caller completion"
                );
                backend
                    .start_pending_tool_children(&mut executor, &starts)
                    .unwrap();
            }
            backend.join_guest_threads();
            backend.guest_worker_teardown_result().unwrap();
            assert!(!group.has_worker_handles());
            assert!(starts.lock().unwrap().is_empty());
            assert_eq!(*group.transport_slots.lock().unwrap(), slots);
            if site == Site::Exec {
                let (status, stdout, stderr) =
                    backend.run_static_elf_process(&mut executor).unwrap();
                assert_eq!(status, ExitStatus::Exited(EXEC_EXIT));
                assert!(stdout.is_empty() && stderr.is_empty());
            } else {
                let mut bytes = [0; 4];
                memory.read_raw(PARENT_TID, &mut bytes).unwrap();
                assert_eq!(i32::from_le_bytes(bytes), CHILD);
                memory.read_raw(CHILD_TID, &mut bytes).unwrap();
                assert_eq!(
                    i32::from_le_bytes(bytes),
                    if site == Site::Fork {
                        ORIGINAL_CHILD
                    } else {
                        CHILD
                    }
                );
                if site == Site::Fork {
                    let wait = SyscallRequest::new(
                        libc::SYS_wait4 as u64,
                        [CHILD as u64, WAIT_STATUS, libc::WNOHANG as u64, 0, 0, 0],
                    );
                    assert_eq!(executor.execute(&wait, &memory), i64::from(CHILD));
                    memory.read_raw(WAIT_STATUS, &mut bytes).unwrap();
                    assert_eq!(i32::from_ne_bytes(bytes), CHILD << 8);
                } else {
                    memory.read_raw(CHILD_RAN, &mut bytes).unwrap();
                    assert_eq!(i32::from_le_bytes(bytes), CHILD);
                }
                assert_eq!(
                    exits
                        .snapshot()
                        .count(crate::stats::KvmExitReason::Hypercall),
                    1
                );
            }
            if site == Site::Fork {
                assert!(
                    stages
                        .fork_memory
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .is_none()
                );
            }
            if site == Site::ToolThread {
                assert_eq!(
                    *log.events.lock().unwrap(),
                    vec![(1, CHILD, 0), (2, CHILD, CHILD)]
                );
                assert!(
                    log.child_state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .is_none()
                );
            }
            stages.assert_exact(&completed);
        }
        assert_eq!(*group.transport_slots.lock().unwrap(), slots);
        assert!(!group.has_worker_handles());
        drop(backend);
        if event != Event::Reopen {
            no_entry(&run_probe, &exits);
        }
    }

    fn all_cases(site: Site) {
        for event in [Event::Failure, Event::Cancel, Event::Poison, Event::Reopen] {
            case(site, event);
        }
    }

    #[test]
    fn prepared_fork_parking_retains_setup_and_stops_before_snapshot() {
        all_cases(Site::Fork);
    }
    #[test]
    fn prepared_host_thread_parking_stops_before_child_effects() {
        all_cases(Site::HostThread);
    }
    #[test]
    fn prepared_exec_parking_stops_before_image_replacement() {
        all_cases(Site::Exec);
    }
    #[test]
    fn prepared_tool_thread_parking_stops_before_child_state_and_start() {
        all_cases(Site::ToolThread);
    }
}
