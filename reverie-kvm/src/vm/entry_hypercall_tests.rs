/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Real public drivers retain the same private hypercall through a no-op close.
mod entry_hypercall_tests {
    use std::collections::BTreeMap;
    use std::sync::Weak;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::task::Context;
    use std::task::Poll;
    use std::time::Duration;
    use std::time::Instant;

    use reverie::GlobalRPC;
    use reverie::Guest;
    use reverie::syscalls::Sysno;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const DATA: u64 = 0x3000;
    const GUEST_FD: u64 = 9;
    const BYTES: &[u8] = b"one private hypercall write\n";
    const THREAD_STATE: u64 = 0x4879_7065_7263_616c;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    static OBSERVATIONS: OnceLock<Mutex<BTreeMap<u64, Weak<Observed>>>> = OnceLock::new();

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
        let load = |value: &AtomicUsize| value.load(Ordering::SeqCst);
        Counts {
            fd: load(&probe.shared_fd_accesses),
            masks: load(&probe.prepare.mask_installs),
            untracked: load(&probe.untracked_runs),
            tracked: load(&probe.tracked_runs),
            begins: load(&probe.clock_begins),
            intervals: load(&probe.intervals_created),
        }
    }

    fn assert_no_completion_entry(probe: &crate::clock::RunProbe, exits: &KvmExitCollector) {
        assert_eq!(
            counts(probe),
            Counts {
                fd: 0,
                masks: 0,
                untracked: 0,
                tracked: 0,
                begins: 0,
                intervals: 0,
            }
        );
        assert_eq!(exits.snapshot().total_exits(), 1);
        assert_eq!(
            exits
                .snapshot()
                .count(crate::stats::KvmExitReason::Hypercall),
            1
        );
        assert_eq!(exits.snapshot().count(crate::stats::KvmExitReason::Hlt), 0);
    }

    struct Fence {
        gate: Arc<crate::entry::EntryGate>,
        closed: Mutex<Option<crate::entry::Closed>>,
        probe: Arc<crate::clock::RunProbe>,
        slot: crate::clock::HypercallProbe,
        response: Mutex<Option<crate::clock::HypercallSnapshot>>,
    }

    impl Fence {
        fn close(&self) {
            let token = self
                .gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .expect("a stopped private hypercall must not count as an active ioctl")
                .unwrap();
            assert!(self.closed.lock().unwrap().replace(token).is_none());
        }

        fn reopen(&self) {
            drop(self.closed.lock().unwrap().take());
        }

        fn arm_after_response(self: &Arc<Self>) {
            // Weak avoids a cycle through Fence -> RunProbe -> this hook if a
            // failed control never reaches the next entry.
            let weak = Arc::downgrade(self);
            self.probe.before_run(move |probe| {
                let fence = weak
                    .upgrade()
                    .expect("live outstanding-hypercall controller");
                // SAFETY: the actual driver's call has not entered KVM; its
                // preceding response write is complete on this same thread.
                let response = unsafe { fence.slot.snapshot() };
                assert_eq!(response.number, VMCALL_SYSCALL_TRANSPORT);
                assert_eq!(response.return_value, BYTES.len() as u64);
                assert!(fence.response.lock().unwrap().replace(response).is_none());
                probe.arm();
                fence.close();
            });
        }
    }

    impl Drop for Fence {
        fn drop(&mut self) {
            self.reopen();
        }
    }

    fn request() -> SyscallRequest {
        SyscallRequest::new(
            libc::SYS_write as u64,
            [GUEST_FD, DATA, BYTES.len() as u64, 0, 0, 0],
        )
    }

    struct Effect {
        file: File,
        calls: AtomicUsize,
        mapping_address: u64,
        gate: Arc<crate::entry::EntryGate>,
    }

    impl Effect {
        fn execute(&self, actual: &SyscallRequest, memory: &GuestMemory) -> i64 {
            assert_eq!(*actual, request());
            assert_eq!(memory.host_address(), self.mapping_address);
            assert!(Arc::ptr_eq(&memory.entry_gate(), &self.gate));
            let mut bytes = vec![0; BYTES.len()];
            memory.read_raw(DATA, &mut bytes).unwrap();
            assert_eq!(bytes, BYTES);
            assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);
            // This is the public direct driver's real syscall executor. An
            // actual write changes the memfd offset and length, so replaying
            // the syscall would duplicate bytes rather than hide behind a
            // synthetic return value or an idempotent truncation.
            let result =
                unsafe { libc::write(self.file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            assert_eq!(result, BYTES.len() as isize);
            result as i64
        }

        fn assert_once(&self) {
            assert_eq!(self.calls.load(Ordering::SeqCst), 1);
            assert_eq!(self.file.metadata().unwrap().len(), BYTES.len() as u64);
            let mut actual = vec![0; BYTES.len() + 1];
            let read = unsafe {
                libc::pread(
                    self.file.as_raw_fd(),
                    actual.as_mut_ptr().cast(),
                    actual.len(),
                    0,
                )
            };
            assert_eq!(read, BYTES.len() as isize);
            assert_eq!(&actual[..BYTES.len()], BYTES);
            assert_eq!(actual[BYTES.len()], 0);
        }
    }

    fn setup() -> (
        KvmBackend,
        Arc<Fence>,
        Arc<Effect>,
        Arc<KvmExitCollector>,
        mpsc::Receiver<()>,
    ) {
        let mut backend = KvmBackend::new(16 * 1024 * 1024)
            .expect("outstanding private hypercall controls require /dev/kvm");
        backend.install_syscall(0x1000, 0x2000, request()).unwrap();
        backend.memory.write_raw(DATA, BYTES).unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let probe = Arc::new(crate::clock::RunProbe::default());
        let (sender, waited) = mpsc::channel();
        probe.prepare.set_wait_notice(sender);
        let slot = backend.vcpu.hypercall_probe();
        backend.vcpu.set_run_probe(probe.clone());
        let fence = Arc::new(Fence {
            gate: backend.memory.entry_gate(),
            closed: Mutex::new(None),
            probe,
            slot,
            response: Mutex::new(None),
        });
        let fd = unsafe { libc::memfd_create(c"kvm-hypercall-effect".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(
            fd >= 0,
            "create effect file: {}",
            std::io::Error::last_os_error()
        );
        let effect = Arc::new(Effect {
            file: unsafe { File::from_raw_fd(fd) },
            calls: AtomicUsize::new(0),
            mapping_address: backend.memory.host_address(),
            gate: fence.gate.clone(),
        });
        (backend, fence, effect, exits, waited)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Callback,
        Effect,
        RpcPending,
        RpcDropped,
        CallbackReturned,
        CallbackDropped,
        Published,
        ThreadConsumed,
        ProcessConsumed,
    }

    struct Observed {
        fence: Arc<Fence>,
        after_response: bool,
        events: Mutex<Vec<Event>>,
        rpc_receiver: Mutex<Option<oneshot::Receiver<()>>>,
        rpc_sender: Mutex<Option<oneshot::Sender<()>>>,
        cleanup_receiver: Mutex<Option<oneshot::Receiver<()>>>,
        cleanup_sender: Mutex<Option<oneshot::Sender<()>>>,
        failure: AtomicBool,
        failure_waker: futures::task::AtomicWaker,
        rpc_pending: AtomicBool,
        consumer_pending: AtomicBool,
        statuses: Mutex<Vec<i32>>,
        global_drops: AtomicUsize,
    }

    impl Observed {
        fn event(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
        fn release_rpc(&self) {
            if let Some(sender) = self.rpc_sender.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
        fn release_consumer(&self) {
            if let Some(sender) = self.cleanup_sender.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
        fn fail(&self) {
            self.failure.store(true, Ordering::Release);
            self.failure_waker.wake();
        }
    }

    struct Registration(u64, Arc<Observed>);
    impl Registration {
        fn new(fence: Arc<Fence>, after_response: bool) -> Self {
            let id = NEXT.fetch_add(1, Ordering::SeqCst);
            let (rpc_sender, rpc_receiver) = oneshot::channel();
            let (cleanup_sender, cleanup_receiver) = oneshot::channel();
            let observed = Arc::new(Observed {
                fence,
                after_response,
                events: Mutex::new(Vec::new()),
                rpc_receiver: Mutex::new(Some(rpc_receiver)),
                rpc_sender: Mutex::new(Some(rpc_sender)),
                cleanup_receiver: Mutex::new(Some(cleanup_receiver)),
                cleanup_sender: Mutex::new(Some(cleanup_sender)),
                failure: AtomicBool::new(false),
                failure_waker: Default::default(),
                rpc_pending: AtomicBool::new(false),
                consumer_pending: AtomicBool::new(false),
                statuses: Mutex::new(Vec::new()),
                global_drops: AtomicUsize::new(0),
            });
            OBSERVATIONS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .insert(id, Arc::downgrade(&observed));
            Self(id, observed)
        }
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            OBSERVATIONS.get().unwrap().lock().unwrap().remove(&self.0);
        }
    }
    fn observation(id: u64) -> Arc<Observed> {
        OBSERVATIONS.get().unwrap().lock().unwrap()[&id]
            .upgrade()
            .unwrap()
    }

    struct RecordDrop(Arc<Observed>, Event);
    impl Drop for RecordDrop {
        fn drop(&mut self) {
            self.0.event(self.1);
        }
    }

    #[derive(Default)]
    struct HypercallGlobal {
        observed: Option<Arc<Observed>>,
    }
    impl Drop for HypercallGlobal {
        fn drop(&mut self) {
            if let Some(observed) = &self.observed {
                observed.global_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for HypercallGlobal {
        type Request = (u8, i32);
        type Response = ();
        type Config = u64;

        async fn init_global_state(id: &u64) -> Self {
            Self {
                observed: Some(observation(*id)),
            }
        }
        async fn receive_rpc(&self, from: Pid, (kind, status): (u8, i32)) {
            assert_eq!(from, Pid::from_raw(1));
            let observed = self.observed.as_ref().unwrap();
            match kind {
                0 => {
                    let _drop = RecordDrop(observed.clone(), Event::RpcDropped);
                    let mut receiver = observed.rpc_receiver.lock().unwrap().take().unwrap();
                    std::future::poll_fn(|cx| {
                        let result = Pin::new(&mut receiver).poll(cx);
                        if result.is_pending() && !observed.rpc_pending.swap(true, Ordering::SeqCst)
                        {
                            observed.event(Event::RpcPending);
                        }
                        result
                    })
                    .await
                    .expect("controller releases the actual ordinary RPC");
                }
                1 => {
                    observed.event(Event::ThreadConsumed);
                    observed.statuses.lock().unwrap().push(status);
                    let mut receiver = observed.cleanup_receiver.lock().unwrap().take().unwrap();
                    std::future::poll_fn(|cx| {
                        let result = Pin::new(&mut receiver).poll(cx);
                        if result.is_pending() {
                            observed.consumer_pending.store(true, Ordering::Release);
                        }
                        result
                    })
                    .await
                    .expect("controller releases the actual consuming hook");
                }
                2 => {
                    observed.event(Event::ProcessConsumed);
                    observed.statuses.lock().unwrap().push(status);
                }
                _ => panic!("unexpected hypercall control RPC {kind}"),
            }
        }
        fn report_backend_failure(&self, _: reverie::BackendFailure) {
            let observed = self.observed.as_ref().unwrap();
            assert!(
                observed
                    .events
                    .lock()
                    .unwrap()
                    .contains(&Event::CallbackDropped)
            );
            observed.event(Event::Published);
        }
        async fn wait_for_backend_failure(&self) {
            let observed = self.observed.as_ref().unwrap();
            std::future::poll_fn(|cx| {
                observed.failure_waker.register(cx.waker());
                if observed.failure.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }

    #[derive(Default)]
    struct HypercallTool {
        observed: Option<Arc<Observed>>,
    }
    #[reverie::tool]
    impl Tool for HypercallTool {
        type GlobalState = HypercallGlobal;
        type ThreadState = u64;

        fn new(pid: Pid, id: &u64) -> Self {
            assert_eq!(pid, Pid::from_raw(1));
            Self {
                observed: Some(observation(*id)),
            }
        }
        fn subscriptions(_: &u64) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.syscall(Sysno::write);
            subscriptions
        }
        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &u64)>) -> u64 {
            assert_eq!(tid, Pid::from_raw(1));
            assert!(parent.is_none());
            THREAD_STATE
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            assert_eq!(SyscallRequest::from_syscall(syscall), request());
            let observed = self.observed.as_ref().unwrap();
            observed.event(Event::Callback);
            let _drop = RecordDrop(observed.clone(), Event::CallbackDropped);
            let result = guest.inject(syscall).await?;
            assert_eq!(result, BYTES.len() as i64);
            observed.event(Event::Effect);
            guest.send_rpc((0, 0)).await;
            if observed.after_response {
                observed.fence.arm_after_response();
            }
            observed.event(Event::CallbackReturned);
            Ok(result)
        }
        async fn on_exit_thread<G: GlobalRPC<HypercallGlobal>>(
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
        async fn on_exit_process<G: GlobalRPC<HypercallGlobal>>(
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

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl futures::task::ArcWake for WakeCount {
        fn wake_by_ref(arc: &Arc<Self>) {
            arc.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct ToolRescue(Arc<Observed>);
    impl Drop for ToolRescue {
        fn drop(&mut self) {
            self.0.fence.reopen();
            self.0.release_rpc();
            self.0.release_consumer();
        }
    }

    fn tool_case(after_response: bool, stop: bool) {
        let (mut backend, fence, effect, exits, waited) = setup();
        let registration = Registration::new(fence.clone(), after_response);
        let observed = &registration.1;
        if after_response {
            observed.release_rpc();
        }
        let wake = Arc::new(WakeCount::default());
        let waker = futures::task::waker(wake.clone());
        let mut cx = Context::from_waker(&waker);
        let executor_effect = effect.clone();
        let mut run = Box::pin(backend.run_with_tool::<HypercallTool, _>(
            registration.0,
            move |request: &SyscallRequest, memory: &GuestMemory| {
                executor_effect.execute(request, memory)
            },
        ));
        // Created after run, so failed assertions reopen before dropping the
        // actual driver's future. No close token is held across rescue.
        let rescue = ToolRescue(observed.clone());
        assert!(run.as_mut().poll(&mut cx).is_pending());
        effect.assert_once();
        // SAFETY: this is the same driver thread, between public-future polls;
        // the still-borrowed backend owns its stopped KVM_RUN mapping.
        let outstanding = unsafe { fence.slot.snapshot() };
        assert_eq!(outstanding.number, VMCALL_SYSCALL_TRANSPORT);
        if after_response {
            waited
                .try_recv()
                .expect("actual driver never polled its closed entry wait");
            assert!(fence.probe.prepare.closed_waits.load(Ordering::Acquire) > 0);
            assert_eq!(*fence.response.lock().unwrap(), Some(outstanding));
            assert_eq!(outstanding.return_value, BYTES.len() as u64);
        } else {
            assert!(observed.rpc_pending.load(Ordering::Acquire));
            assert_eq!(
                *observed.events.lock().unwrap(),
                vec![Event::Callback, Event::Effect, Event::RpcPending]
            );
            assert_ne!(
                outstanding.return_value,
                BYTES.len() as u64,
                "fixture must distinguish a response write from the pending slot value"
            );
            fence.probe.arm();
            fence.close();
        }
        assert!(fence.closed.lock().unwrap().is_some());
        assert_no_completion_entry(&fence.probe, &exits);
        // Close/drain completed while the original callback/return slot and
        // backend Mapping were still owned. It did not complete the syscall.
        assert_eq!(unsafe { fence.slot.snapshot() }, outstanding);
        let before_wake = wake.0.load(Ordering::SeqCst);
        if stop {
            observed.fail();
            assert!(wake.0.load(Ordering::SeqCst) > before_wake);
            assert!(run.as_mut().poll(&mut cx).is_pending());
            assert!(observed.consumer_pending.load(Ordering::Acquire));
            assert_eq!(*observed.statuses.lock().unwrap(), vec![255]);
            assert!(fence.closed.lock().unwrap().is_some());
            assert_no_completion_entry(&fence.probe, &exits);
            assert_eq!(unsafe { fence.slot.snapshot() }, outstanding);
            // Release the no-op fence only after the actual terminal hook was
            // reached; dependent cleanup is never required to copy while closed.
            fence.reopen();
        } else {
            fence.reopen();
            if !after_response {
                observed.release_rpc();
            }
            assert!(wake.0.load(Ordering::SeqCst) > before_wake);
        }
        observed.release_consumer();
        let deadline = Instant::now() + WAIT;
        let result = loop {
            match run.as_mut().poll(&mut cx) {
                Poll::Ready(result) => break result,
                Poll::Pending => {
                    assert!(
                        Instant::now() < deadline,
                        "private hypercall did not settle after releases"
                    );
                    std::thread::yield_now();
                }
            }
        };
        drop(run);
        if stop {
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("global failure completed the private hypercall"),
            };
            assert!(matches!(error.primary(), Error::RunAborted));
            assert_no_completion_entry(&fence.probe, &exits);
            assert_eq!(unsafe { fence.slot.snapshot() }, outstanding);
        } else {
            drop(result.unwrap());
            let actual = counts(&fence.probe);
            assert_eq!(
                actual,
                Counts {
                    fd: 0,
                    masks: 1,
                    untracked: 0,
                    tracked: 1,
                    begins: 1,
                    intervals: 1
                }
            );
            assert_eq!(exits.snapshot().total_exits(), 2);
            assert_eq!(
                exits
                    .snapshot()
                    .count(crate::stats::KvmExitReason::Hypercall),
                1
            );
            assert_eq!(exits.snapshot().count(crate::stats::KvmExitReason::Hlt), 1);
            // This post-run ioctl is outside the measured interval. It checks
            // that real KVM consumed the exact response and reached guest HLT.
            assert_eq!(backend.vcpu.get_regs().unwrap().rax, BYTES.len() as u64);
        }
        effect.assert_once();
        assert_eq!(backend.memory.host_address(), effect.mapping_address);
        assert!(Arc::ptr_eq(&backend.memory.entry_gate(), &fence.gate));
        assert_eq!(
            *observed.statuses.lock().unwrap(),
            vec![if stop { 255 } else { 0 }; 2]
        );
        assert_eq!(observed.global_drops.load(Ordering::SeqCst), 1);
        let events = observed.events.lock().unwrap();
        let count = |wanted| events.iter().filter(|event| **event == wanted).count();
        let position = |wanted| events.iter().position(|event| *event == wanted).unwrap();
        for once in [
            Event::Callback,
            Event::Effect,
            Event::RpcDropped,
            Event::CallbackDropped,
            Event::ThreadConsumed,
            Event::ProcessConsumed,
        ] {
            assert_eq!(count(once), 1);
        }
        assert_eq!(
            count(Event::CallbackReturned),
            usize::from(after_response || !stop)
        );
        assert_eq!(count(Event::RpcPending), usize::from(!after_response));
        assert_eq!(count(Event::Published) > 0, stop);
        assert!(position(Event::Effect) < position(Event::RpcDropped));
        assert!(position(Event::RpcDropped) < position(Event::CallbackDropped));
        assert!(position(Event::CallbackDropped) < position(Event::ThreadConsumed));
        assert!(position(Event::ThreadConsumed) < position(Event::ProcessConsumed));
        if stop {
            assert!(position(Event::CallbackDropped) < position(Event::Published));
        }
        drop(events);
        assert!(!backend.thread_group.has_worker_handles());
        drop(backend);
        if stop {
            assert_no_completion_entry(&fence.probe, &exits);
        }
        drop(rescue);
    }

    struct HostRescue {
        fence: Arc<Fence>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for HostRescue {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                self.fence.reopen();
                self.fence.gate.poison(
                    None,
                    Error::GuestClock("failed private hypercall control rescue".into()),
                );
                worker.join().unwrap();
            }
        }
    }

    fn host_case(stop: bool) {
        let (mut backend, fence, effect, exits, waited) = setup();
        let handler_fence = fence.clone();
        let handler_effect = effect.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = backend.run(move |syscall, memory| {
                let result = handler_effect.execute(&SyscallRequest::from_syscall(syscall), memory);
                handler_fence.arm_after_response();
                result
            });
            sender
                .send((backend, result))
                .unwrap_or_else(|_| panic!("Host hypercall controller dropped its receiver"));
        });
        let mut rescue = HostRescue {
            fence: fence.clone(),
            worker: Some(worker),
        };
        waited
            .recv_timeout(WAIT)
            .expect("Host private hypercall never reached a real closed wait");
        let outstanding = fence.response.lock().unwrap().unwrap();
        assert_eq!(outstanding.number, VMCALL_SYSCALL_TRANSPORT);
        assert_eq!(outstanding.return_value, BYTES.len() as u64);
        assert!(fence.closed.lock().unwrap().is_some());
        assert_no_completion_entry(&fence.probe, &exits);
        effect.assert_once();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let cause = Arc::new(Error::GuestClock(
            "stop private hypercall while closed".into(),
        ));
        if stop {
            fence.gate.poison(None, Error::SharedFailure(cause.clone()));
        } else {
            fence.reopen();
        }
        let completed = receiver.recv_timeout(WAIT);
        if completed.is_err() {
            fence.reopen();
        }
        let (backend, result) = completed.expect("Host terminal choice waited for reopen");
        rescue.worker.take().unwrap().join().unwrap();
        if stop {
            assert!(crate::failure::references_shared_error(
                &result.unwrap_err(),
                &cause
            ));
            assert!(fence.closed.lock().unwrap().is_some());
            assert_no_completion_entry(&fence.probe, &exits);
            // SAFETY: physical host worker joined; the returned backend still
            // owns the stopped mapping, and no driver can mutate its response.
            assert_eq!(unsafe { fence.slot.snapshot() }, outstanding);
            fence.reopen();
        } else {
            result.unwrap();
            assert_eq!(
                counts(&fence.probe),
                Counts {
                    fd: 0,
                    masks: 1,
                    untracked: 1,
                    tracked: 0,
                    begins: 0,
                    intervals: 0
                }
            );
            assert_eq!(exits.snapshot().total_exits(), 2);
            assert_eq!(
                exits
                    .snapshot()
                    .count(crate::stats::KvmExitReason::Hypercall),
                1
            );
            assert_eq!(exits.snapshot().count(crate::stats::KvmExitReason::Hlt), 1);
            assert_eq!(backend.vcpu.get_regs().unwrap().rax, BYTES.len() as u64);
        }
        effect.assert_once();
        assert_eq!(backend.memory.host_address(), effect.mapping_address);
        assert!(Arc::ptr_eq(&backend.memory.entry_gate(), &fence.gate));
        assert!(!backend.thread_group.has_worker_handles());
        drop(backend);
        if stop {
            assert_no_completion_entry(&fence.probe, &exits);
        }
    }

    #[test]
    fn direct_tool_pending_response_reopens_without_replaying_write() {
        tool_case(false, false);
    }
    #[test]
    fn direct_tool_pending_response_failure_avoids_completion_entry() {
        tool_case(false, true);
    }
    #[test]
    fn direct_tool_written_response_reopens_and_reaches_hlt_once() {
        tool_case(true, false);
    }
    #[test]
    fn direct_tool_written_response_failure_avoids_completion_entry() {
        tool_case(true, true);
    }
    #[test]
    fn host_written_response_reopens_and_reaches_hlt_once() {
        host_case(false);
    }
    #[test]
    fn host_written_response_poison_avoids_completion_entry() {
        host_case(true);
    }
}
