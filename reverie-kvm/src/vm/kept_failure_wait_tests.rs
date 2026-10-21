/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests so the existing minimal ELF fixture remains private.
mod kept_failure_wait_tests {
    use std::collections::BTreeSet;
    use std::panic::AssertUnwindSafe;
    use std::panic::resume_unwind;
    use std::sync::atomic::AtomicU64;

    use super::*;

    static ACTIVE: Mutex<Option<Arc<Observation>>> = Mutex::new(None);
    const SELECTED: &str = "kept-wait selected execution error";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Armed,
        ThreadConsumed,
        ProcessConsumed,
        GlobalDropped,
    }

    #[derive(Default)]
    struct Observation {
        events: Mutex<Vec<Event>>,
        next_wait: AtomicU64,
        /// Waits whose future exists: created by wait_for_backend_failure and
        /// not yet dropped.
        live: Mutex<BTreeSet<u64>>,
        /// The wait polled most recently. The BeforeCallback order polls the
        /// thread's kept wait immediately before each Tool callback.
        last_polled: AtomicU64,
        /// Waits whose drop panics: the syscall callback arms the last polled
        /// one, which is the kept wait. Other waits never panic.
        armed: Mutex<BTreeSet<u64>>,
        dropped_armed: Mutex<Vec<u64>>,
    }

    /// The payload a kept wait's destructor raises.
    struct WaitDropPayload(u64);

    struct WaitGuard {
        id: u64,
        observed: Arc<Observation>,
    }

    impl Drop for WaitGuard {
        fn drop(&mut self) {
            self.observed.live.lock().unwrap().remove(&self.id);
            if self.observed.armed.lock().unwrap().remove(&self.id) {
                self.observed.dropped_armed.lock().unwrap().push(self.id);
                if !std::thread::panicking() {
                    resume_unwind(Box::new(WaitDropPayload(self.id)));
                }
            }
        }
    }

    #[derive(Default)]
    struct WaitGlobal {
        observed: Option<Arc<Observation>>,
    }

    impl Drop for WaitGlobal {
        fn drop(&mut self) {
            if let Some(observed) = &self.observed {
                observed.events.lock().unwrap().push(Event::GlobalDropped);
            }
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for WaitGlobal {
        type Request = u8;
        type Response = ();
        type Config = ();

        async fn init_global_state(_: &()) -> Self {
            Self {
                observed: Some(ACTIVE.lock().unwrap().as_ref().unwrap().clone()),
            }
        }

        async fn receive_rpc(&self, _from: Pid, kind: u8) {
            let observed = self.observed.as_ref().unwrap();
            match kind {
                1 => observed.events.lock().unwrap().push(Event::ThreadConsumed),
                2 => observed.events.lock().unwrap().push(Event::ProcessConsumed),
                _ => panic!("unexpected kept-wait RPC {kind}"),
            }
        }

        async fn wait_for_backend_failure(&self) {
            let observed = self.observed.as_ref().unwrap().clone();
            let id = observed.next_wait.fetch_add(1, Ordering::SeqCst);
            observed.live.lock().unwrap().insert(id);
            let guard = WaitGuard { id, observed };
            std::future::poll_fn(|_| {
                guard.observed.last_polled.store(guard.id, Ordering::SeqCst);
                std::task::Poll::<()>::Pending
            })
            .await
        }
    }

    #[derive(Default)]
    struct WaitTool;

    #[reverie::tool]
    impl Tool for WaitTool {
        type GlobalState = WaitGlobal;
        type ThreadState = ();

        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscription = reverie::Subscription::none();
            subscription.syscall(reverie::syscalls::Sysno::getpid);
            subscription
        }

        async fn handle_syscall_event<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
            _call: reverie::syscalls::Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            // Arm from here, not through an RPC: an RPC polls a failure wait
            // of its own, which would then be the last polled one.
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            let kept = observed.last_polled.load(Ordering::SeqCst);
            assert!(
                observed.live.lock().unwrap().contains(&kept),
                "the callback ran without a live polled failure wait"
            );
            observed.armed.lock().unwrap().insert(kept);
            observed.events.lock().unwrap().push(Event::Armed);
            let _ = guest;
            // Not an errno, which would become the guest's syscall result:
            // a Tool failure, which selects a typed execution error.
            Err(reverie::Error::Io(std::io::Error::other(SELECTED)))
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<WaitGlobal>>(
            &self,
            _tid: Pid,
            global: &G,
            _state: (),
            _status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(1).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<WaitGlobal>>(
            self,
            _pid: Pid,
            global: &G,
            _status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(2).await;
            Ok(())
        }
    }

    fn contains_selected(error: &Error) -> bool {
        match error {
            Error::Reverie(reverie::Error::Io(error)) => error.to_string() == SELECTED,
            Error::SignalEffects { cause, .. }
            | Error::SharedFailure(cause)
            | Error::WorkerFailure { error: cause, .. }
            | Error::Cleanup { error: cause, .. } => contains_selected(cause),
            Error::WithCleanup { primary, cleanup } => {
                contains_selected(primary) || cleanup.iter().any(|next| contains_selected(next))
            }
            Error::ExecWorkerTeardown(error) => contains_selected(error),
            _ => false,
        }
    }

    /// The static-ELF loop keeps one failure wait for all of a thread's Tool
    /// callbacks and destroys it after the execution completes. A GlobalTool
    /// whose wait future panics when dropped must not lose the execution's
    /// selected error or skip the consuming hooks and GlobalState recovery:
    /// the kept wait is destroyed under the execution's catch, and its
    /// payload joins the execution's panics.
    #[test]
    fn a_kept_failure_wait_destructor_panic_keeps_the_outcome_and_runs_consumers() {
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("kept failure wait control requires /dev/kvm");
        // mov eax, SYS_getpid; syscall; hlt.
        backend
            .install_static_elf(
                &minimal_test_elf(&[0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0xf4]),
                "/bin/kept-failure-wait",
            )
            .unwrap();
        let observed = Arc::new(Observation::default());
        {
            let mut active = ACTIVE.lock().unwrap();
            assert!(active.is_none());
            *active = Some(observed.clone());
        }
        let run = AssertUnwindSafe(backend.run_static_elf_with_tool_completion::<WaitTool>((), false))
            .catch_unwind();
        let outcome = futures::executor::block_on(run);
        let payload = match outcome {
            Err(payload) => payload,
            Ok(result) => panic!(
                "the kept wait's destructor panic was lost: {:?}",
                result.map(|_| ())
            ),
        };
        let armed = observed.dropped_armed.lock().unwrap().clone();
        assert_eq!(armed.len(), 1, "the kept wait was armed and dropped once");
        let payload = payload
            .downcast::<WaitDropPayload>()
            .expect("the original destructor payload is resumed");
        assert_eq!(payload.0, armed[0]);
        assert_eq!(
            *observed.events.lock().unwrap(),
            vec![
                Event::Armed,
                Event::ThreadConsumed,
                Event::ProcessConsumed,
                Event::GlobalDropped,
            ],
            "consuming hooks and GlobalState recovery must follow the panic"
        );
        {
            let completed = backend.completed_tool_panics.lock().unwrap();
            assert_eq!(completed.len(), 1);
            assert!(
                contains_selected(&completed[0]._error),
                "the callback's selected error was lost: {:?}",
                completed[0]._error
            );
        }
        ACTIVE.lock().unwrap().take();
        drop(backend);
    }
}
