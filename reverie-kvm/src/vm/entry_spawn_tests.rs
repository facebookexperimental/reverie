/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests to use the unchanged minimal_test_elf fixture.
mod entry_spawn_tests {
    use std::sync::Weak;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;
    use std::time::Duration;
    use std::time::Instant;

    use reverie::Guest;
    use reverie::syscalls::Errno;
    use reverie::syscalls::Sysno;

    use super::*;
    use crate::failure::spawn_refusal;

    const ROOT_STATE: u64 = 0x7061_7265_6e74_0011;
    const CHILD_STATE: u64 = 0x6368_696c_6400_0022;
    static CASE_LOCK: Mutex<()> = Mutex::new(());
    static ACTIVE: Mutex<Option<Arc<Observed>>> = Mutex::new(None);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        ParentCallback,
        ChildProcessConstructed,
        ChildInitialized,
        ParentCallbackDropped,
        Published,
        ChildThreadEntered,
        ChildThreadPending,
        ChildThreadReleased,
        ChildStateDropped,
        ChildProcessConsumed,
        ParentThreadConsumed,
        ParentProcessConsumed,
    }

    struct Observed {
        thread: bool,
        events: Mutex<Vec<Event>>,
        publications: Mutex<Vec<reverie::BackendFailure>>,
        parent: Mutex<Option<Weak<u64>>>,
        child: Mutex<Option<Weak<u64>>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        callback_dropped: AtomicBool,
        pending: AtomicBool,
        child_initialized: AtomicUsize,
        child_thread_consumed: AtomicUsize,
        child_process_consumed: AtomicUsize,
        parent_thread_consumed: AtomicUsize,
        parent_process_consumed: AtomicUsize,
        child_started: AtomicUsize,
        refusal: Arc<spawn_refusal::Probe>,
    }

    impl Observed {
        fn event(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }

        fn child(&self) -> Weak<u64> {
            self.child.lock().unwrap().as_ref().unwrap().clone()
        }

        fn assert_published_after_callback(&self) {
            assert!(self.callback_dropped.load(Ordering::SeqCst));
            assert!(!self.publications.lock().unwrap().is_empty());
        }
    }

    struct ActiveCase;
    impl Drop for ActiveCase {
        fn drop(&mut self) {
            let old = ACTIVE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            drop(old);
        }
    }

    struct CallbackDrop(Arc<Observed>);
    impl Drop for CallbackDrop {
        fn drop(&mut self) {
            let observed = &self.0;
            assert!(
                observed.publications.lock().unwrap().is_empty(),
                "spawn failure was published inside its borrowing callback"
            );
            assert_eq!(observed.child_initialized.load(Ordering::SeqCst), 1);
            assert_eq!(observed.child_thread_consumed.load(Ordering::SeqCst), 0);
            assert_eq!(observed.child_process_consumed.load(Ordering::SeqCst), 0);
            assert_eq!(observed.child_started.load(Ordering::SeqCst), 0);
            assert_eq!(observed.refusal.consumed(), 1);
            assert!(observed.refusal.error().is_some());
            let child = observed
                .child()
                .upgrade()
                .expect("recovered child state was dropped inside parent callback");
            assert_eq!(*child, CHILD_STATE);
            assert_eq!(
                Arc::strong_count(&child),
                2,
                "one production owner plus this temporary witness"
            );
            assert!(!observed.callback_dropped.swap(true, Ordering::SeqCst));
            observed.event(Event::ParentCallbackDropped);
        }
    }

    #[derive(Default)]
    struct SpawnGlobal {
        observed: Option<Arc<Observed>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for SpawnGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn init_global_state(_: &()) -> Self {
            Self {
                observed: Some(ACTIVE.lock().unwrap().as_ref().unwrap().clone()),
            }
        }

        async fn receive_rpc(&self, _: Pid, _: ()) {
            panic!("spawn control does not issue an ordinary RPC");
        }

        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            let observed = self.observed.as_ref().unwrap();
            assert!(
                observed.callback_dropped.load(Ordering::SeqCst),
                "legitimate outer publication follows actual parent callback destruction"
            );
            observed.publications.lock().unwrap().push(event);
            observed.event(Event::Published);
        }
    }

    #[derive(Default)]
    struct SpawnTool {
        pid: i32,
    }

    #[reverie::tool]
    impl Tool for SpawnTool {
        type GlobalState = SpawnGlobal;
        // Reverie's existing serde rc feature supplies the ordinary ThreadState
        // contract. The controller retains only Weak witnesses, never owners.
        type ThreadState = Arc<u64>;

        fn new(pid: Pid, _: &()) -> Self {
            if pid.as_raw() != 1 {
                let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
                assert!(!observed.thread);
                assert_eq!(pid.as_raw(), 2);
                observed.event(Event::ChildProcessConstructed);
            }
            Self { pid: pid.as_raw() }
        }

        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.syscall(Sysno::getpid);
            subscriptions
        }

        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &Arc<u64>)>) -> Arc<u64> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            match parent {
                None => {
                    assert_eq!((self.pid, tid.as_raw()), (1, 1));
                    let state = Arc::new(ROOT_STATE);
                    assert!(
                        observed
                            .parent
                            .lock()
                            .unwrap()
                            .replace(Arc::downgrade(&state))
                            .is_none()
                    );
                    state
                }
                Some((parent_tid, parent_state)) => {
                    assert_eq!(parent_tid.as_raw(), 1);
                    assert_eq!(**parent_state, ROOT_STATE);
                    assert_eq!(tid.as_raw(), 2);
                    assert_eq!(self.pid, if observed.thread { 1 } else { 2 });
                    assert!(!observed.callback_dropped.load(Ordering::SeqCst));
                    assert!(observed.publications.lock().unwrap().is_empty());
                    assert_eq!(observed.child_initialized.fetch_add(1, Ordering::SeqCst), 0);
                    let state = Arc::new(CHILD_STATE);
                    assert!(!Arc::ptr_eq(parent_state, &state));
                    assert!(
                        observed
                            .child
                            .lock()
                            .unwrap()
                            .replace(Arc::downgrade(&state))
                            .is_none()
                    );
                    observed.event(Event::ChildInitialized);
                    state
                }
            }
        }

        async fn handle_thread_start<G: Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            if guest.tid().as_raw() != 1 {
                ACTIVE
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .child_started
                    .fetch_add(1, Ordering::SeqCst);
                panic!("refused guest worker reached its start hook");
            }
            assert_eq!(guest.pid().as_raw(), 1);
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            assert!(matches!(syscall, Syscall::Getpid(_)));
            assert_eq!((guest.pid().as_raw(), guest.tid().as_raw()), (1, 1));
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            observed.event(Event::ParentCallback);
            let _callback = CallbackDrop(observed.clone());
            let request = if observed.thread {
                let stack = guest.regs().await.rsp.checked_sub(4096).unwrap();
                let flags = libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD;
                SyscallRequest::new(libc::SYS_clone as u64, [flags as u64, stack, 0, 0, 0, 0])
            } else {
                SyscallRequest::new(libc::SYS_fork as u64, [0; 6])
            }
            .into_syscall()
            .unwrap();
            // No other spawn_owned lies between this admission and the actual
            // matched Fork/Tool Thread producer. The real OS refusal recovers
            // the initialized child in that producer's existing Err arm.
            let _refusal = spawn_refusal::Guard::arm(observed.refusal.clone());
            let _ = guest.inject(request).await?;
            panic!("actual failed guest-worker spawn returned to the parent Tool callback");
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<SpawnGlobal>>(
            &self,
            tid: Pid,
            _: &G,
            state: Arc<u64>,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            observed.assert_published_after_callback();
            assert_eq!(status, ExitStatus::Exited(255));
            if tid.as_raw() == 1 {
                assert_eq!(self.pid, 1);
                assert_eq!(*state, ROOT_STATE);
                assert_eq!(
                    observed
                        .parent_thread_consumed
                        .fetch_add(1, Ordering::SeqCst),
                    0
                );
                assert_eq!(observed.child_thread_consumed.load(Ordering::SeqCst), 1);
                assert!(observed.child().upgrade().is_none());
                observed.event(Event::ParentThreadConsumed);
                drop(state);
                return Ok(());
            }
            assert_eq!(tid.as_raw(), 2);
            assert_eq!(self.pid, if observed.thread { 1 } else { 2 });
            assert_eq!(*state, CHILD_STATE);
            let original = observed
                .child()
                .upgrade()
                .expect("child state owner missing at consuming hook");
            assert!(Arc::ptr_eq(&original, &state));
            drop(original);
            assert_eq!(Arc::strong_count(&state), 1);
            assert_eq!(
                observed
                    .child_thread_consumed
                    .fetch_add(1, Ordering::SeqCst),
                0
            );
            observed.event(Event::ChildThreadEntered);
            let mut release = observed.release.lock().unwrap().take().unwrap();
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut release).poll(cx);
                if result.is_pending() && !observed.pending.swap(true, Ordering::SeqCst) {
                    observed.event(Event::ChildThreadPending);
                }
                result
            })
            .await
            .expect("controller must release actual pending child hook");
            observed.event(Event::ChildThreadReleased);
            drop(state);
            assert!(
                observed.child().upgrade().is_none(),
                "child state consumed exactly once"
            );
            observed.event(Event::ChildStateDropped);
            Err(Errno::ENOSPC.into())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<SpawnGlobal>>(
            self,
            pid: Pid,
            _: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            observed.assert_published_after_callback();
            assert_eq!(status, ExitStatus::Exited(255));
            assert_eq!(pid.as_raw(), self.pid);
            if self.pid == 1 {
                assert_eq!(observed.parent_thread_consumed.load(Ordering::SeqCst), 1);
                assert_eq!(
                    observed
                        .parent_process_consumed
                        .fetch_add(1, Ordering::SeqCst),
                    0
                );
                observed.event(Event::ParentProcessConsumed);
                Ok(())
            } else {
                assert!(
                    !observed.thread,
                    "never-started thread does not own a process hook"
                );
                assert_eq!(self.pid, 2);
                assert_eq!(observed.child_thread_consumed.load(Ordering::SeqCst), 1);
                assert_eq!(
                    observed
                        .child_process_consumed
                        .fetch_add(1, Ordering::SeqCst),
                    0
                );
                assert!(observed.child().upgrade().is_none());
                observed.event(Event::ChildProcessConsumed);
                Err(Errno::EOWNERDEAD.into())
            }
        }
    }

    fn diagnostics(
        error: &Error,
        host: &mut Vec<spawn_refusal::ObservedError>,
        cleanup: &mut Vec<Errno>,
    ) {
        match error {
            Error::HostIo(error) => host.push(spawn_refusal::ObservedError::read(error)),
            Error::Reverie(reverie::Error::Errno(errno)) => cleanup.push(*errno),
            Error::SignalEffects { cause, .. }
            | Error::SharedFailure(cause)
            | Error::WorkerFailure { error: cause, .. }
            | Error::Cleanup { error: cause, .. } => diagnostics(cause, host, cleanup),
            Error::WithCleanup {
                primary,
                cleanup: later,
            } => {
                diagnostics(primary, host, cleanup);
                for error in later {
                    diagnostics(error, host, cleanup);
                }
            }
            Error::ExecWorkerTeardown(error) => diagnostics(error, host, cleanup),
            _ => {}
        }
    }

    fn run_case(thread: bool) {
        let _case = CASE_LOCK.lock().unwrap();
        assert!(!spawn_refusal::is_armed());
        let mut backend = KvmBackend::new(16 * 1024 * 1024)
            .expect("actual guest-worker spawn control requires /dev/kvm");
        // Real userspace getpid reaches the subscribed callback. UD2 would
        // expose an incorrect continuation after the injected fatal action.
        let code = [0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b];
        backend
            .install_static_elf(&minimal_test_elf(&code), "/bin/entry-spawn-control")
            .unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let (release, receiver) = oneshot::channel();
        let observed = Arc::new(Observed {
            thread,
            events: Mutex::new(Vec::new()),
            publications: Mutex::new(Vec::new()),
            parent: Mutex::new(None),
            child: Mutex::new(None),
            release: Mutex::new(Some(receiver)),
            callback_dropped: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            child_initialized: AtomicUsize::new(0),
            child_thread_consumed: AtomicUsize::new(0),
            child_process_consumed: AtomicUsize::new(0),
            parent_thread_consumed: AtomicUsize::new(0),
            parent_process_consumed: AtomicUsize::new(0),
            child_started: AtomicUsize::new(0),
            refusal: Arc::new(spawn_refusal::Probe::default()),
        });
        assert!(ACTIVE.lock().unwrap().replace(observed.clone()).is_none());
        let _active = ActiveCase;
        let mut run = Box::pin(backend.run_static_elf_with_tool_completion::<SpawnTool>((), false));
        let mut context = Context::from_waker(Waker::noop());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                matches!(run.as_mut().poll(&mut context), Poll::Pending),
                "public driver finished before its retained child consuming hook was released"
            );
            if observed.pending.load(Ordering::SeqCst) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "actual child consuming hook never became pending"
            );
            std::thread::yield_now();
        }
        assert!(
            !spawn_refusal::is_armed(),
            "callback destruction restores thread-local admission"
        );
        assert_eq!(observed.refusal.consumed(), 1);
        let spawn_error = observed
            .refusal
            .error()
            .expect("real Builder.spawn refusal metadata");
        assert!(spawn_error.raw_errno.is_some());
        assert!(
            exits.snapshot().total_exits() > 0,
            "actual public ELF guest must reach its syscall"
        );
        assert_eq!(observed.child_initialized.load(Ordering::SeqCst), 1);
        assert_eq!(observed.child_started.load(Ordering::SeqCst), 0);
        assert_eq!(observed.child_thread_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(observed.child_process_consumed.load(Ordering::SeqCst), 0);
        assert_eq!(observed.parent_thread_consumed.load(Ordering::SeqCst), 0);
        assert_eq!(observed.parent_process_consumed.load(Ordering::SeqCst), 0);
        assert!(
            observed.child().upgrade().is_some(),
            "pending hook retains exact child state"
        );
        assert!(
            observed
                .parent
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .is_some()
        );
        let before = observed.events.lock().unwrap().clone();
        let position = |event| before.iter().position(|entry| *entry == event).unwrap();
        assert!(position(Event::ParentCallback) < position(Event::ChildInitialized));
        assert!(position(Event::ChildInitialized) < position(Event::ParentCallbackDropped));
        assert!(position(Event::ParentCallbackDropped) < position(Event::Published));
        assert!(position(Event::Published) < position(Event::ChildThreadEntered));
        assert!(position(Event::ChildThreadEntered) < position(Event::ChildThreadPending));
        let first = observed.publications.lock().unwrap()[0];
        assert_eq!((first.pid.as_raw(), first.tid.as_raw()), (1, 1));
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let completion = loop {
            if let Poll::Ready(result) = run.as_mut().poll(&mut context) {
                break result;
            }
            assert!(
                Instant::now() < deadline,
                "released child cleanup did not complete"
            );
            std::thread::yield_now();
        }
        .expect("public driver must retain completed global state on runtime failure");
        drop(run);
        let error = completion
            .result
            .expect_err("actual spawn refusal cannot be guest success");
        let Error::HostIo(primary) = error.primary() else {
            panic!("spawn error lost primary position: {error:?}");
        };
        assert_eq!(spawn_refusal::ObservedError::read(primary), spawn_error);
        let mut host = Vec::new();
        let mut cleanup = Vec::new();
        diagnostics(&error, &mut host, &mut cleanup);
        assert_eq!(
            host,
            vec![spawn_error],
            "retain original spawn diagnostic exactly once"
        );
        assert_eq!(
            cleanup
                .iter()
                .filter(|errno| **errno == Errno::ENOSPC)
                .count(),
            1
        );
        assert_eq!(
            cleanup
                .iter()
                .filter(|errno| **errno == Errno::EOWNERDEAD)
                .count(),
            usize::from(!thread)
        );
        assert_eq!(cleanup.len(), if thread { 1 } else { 2 });
        assert!(observed.child().upgrade().is_none());
        assert!(
            observed
                .parent
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .is_none()
        );
        assert_eq!(observed.child_thread_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(
            observed.child_process_consumed.load(Ordering::SeqCst),
            usize::from(!thread)
        );
        assert_eq!(observed.parent_thread_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(observed.parent_process_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(observed.child_started.load(Ordering::SeqCst), 0);
        assert_eq!(observed.refusal.consumed(), 1);
        assert!(!spawn_refusal::is_armed());
        let events = observed.events.lock().unwrap().clone();
        let position = |event| events.iter().position(|entry| *entry == event).unwrap();
        assert!(position(Event::ChildThreadPending) < position(Event::ChildThreadReleased));
        assert!(position(Event::ChildThreadReleased) < position(Event::ChildStateDropped));
        if !thread {
            assert!(position(Event::ChildStateDropped) < position(Event::ChildProcessConsumed));
            assert!(position(Event::ChildProcessConsumed) < position(Event::ParentThreadConsumed));
        }
        assert!(position(Event::ChildStateDropped) < position(Event::ParentThreadConsumed));
        assert!(position(Event::ParentThreadConsumed) < position(Event::ParentProcessConsumed));
    }

    #[test]
    fn public_elf_refused_fork_retains_child_until_published_cleanup() {
        run_case(false);
    }

    #[test]
    fn public_elf_refused_tool_thread_retains_child_until_published_cleanup() {
        run_case(true);
    }

    #[test]
    fn unarmed_spawn_owned_starts_exact_initialized_state() {
        assert!(!spawn_refusal::is_armed());
        let state = Arc::new(AtomicUsize::new(0));
        let original = state.clone();
        let handle =
            match crate::failure::spawn_owned(std::thread::Builder::new(), state, |state| {
                assert_eq!(state.fetch_add(1, Ordering::SeqCst), 0);
                state
            }) {
                Ok(handle) => handle,
                Err((error, _)) => panic!("unarmed healthy host spawn failed: {error}"),
            };
        let returned = handle.join().unwrap();
        assert!(Arc::ptr_eq(&original, &returned));
        assert_eq!(original.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&original), 2);
        assert!(!spawn_refusal::is_armed());
    }
}
