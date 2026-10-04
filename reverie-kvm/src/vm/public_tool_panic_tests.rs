/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests so the existing minimal ELF fixture remains private.
mod public_tool_panic_tests {
    use std::cell::Cell;
    use std::panic::AssertUnwindSafe;
    use std::panic::resume_unwind;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use super::*;
    use crate::failure::owned_future::PanicPayload;

    const THREAD_STATE: u64 = 0x726f_6f74_7374_6174;
    static ACTIVE: Mutex<Option<Arc<Observation>>> = Mutex::new(None);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Start,
        ThreadConsumed,
        ThreadReleased,
        ProcessConsumed,
        GlobalDropped,
    }

    struct Observation {
        events: Mutex<Vec<Event>>,
        failures: Mutex<Vec<reverie::BackendFailure>>,
        first: Mutex<Option<PanicPayload>>,
        second: Mutex<Option<PanicPayload>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        pending: AtomicBool,
        payload_drops: Arc<[AtomicUsize; 2]>,
    }

    struct ActiveObservation;

    impl Drop for ActiveObservation {
        fn drop(&mut self) {
            // The one declaration owns this slot. Taking the Arc out first
            // keeps any final payload destruction outside the static mutex.
            let old = ACTIVE.lock().unwrap_or_else(|p| p.into_inner()).take();
            drop(old);
        }
    }

    struct Payload {
        index: usize,
        drops: Arc<[AtomicUsize; 2]>,
        _send_only: Cell<u8>,
    }

    impl Drop for Payload {
        fn drop(&mut self) {
            self.drops[self.index].fetch_add(1, Ordering::SeqCst);
        }
    }

    fn payload(drops: &Arc<[AtomicUsize; 2]>, index: usize) -> (PanicPayload, usize) {
        let payload = Box::new(Payload {
            index,
            drops: drops.clone(),
            _send_only: Cell::new(index as u8),
        });
        let address = std::ptr::from_ref(payload.as_ref()) as usize;
        (payload, address)
    }

    fn assert_payload(payload: &PanicPayload, index: usize, address: usize) {
        let actual = payload
            .downcast_ref::<Payload>()
            .expect("exact original payload type");
        assert_eq!(actual.index, index);
        assert_eq!(std::ptr::from_ref(actual) as usize, address);
    }

    fn assert_payload_drops(observed: &Observation, expected: [usize; 2]) {
        assert_eq!(
            observed.payload_drops[0].load(Ordering::SeqCst),
            expected[0]
        );
        assert_eq!(
            observed.payload_drops[1].load(Ordering::SeqCst),
            expected[1]
        );
    }

    #[derive(Default)]
    struct OwnerGlobal {
        observed: Option<Arc<Observation>>,
    }

    impl Drop for OwnerGlobal {
        fn drop(&mut self) {
            if let Some(observed) = &self.observed {
                observed.events.lock().unwrap().push(Event::GlobalDropped);
            }
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for OwnerGlobal {
        type Request = (u8, u64);
        type Response = ();
        type Config = ();

        async fn init_global_state(_: &()) -> Self {
            Self {
                observed: Some(ACTIVE.lock().unwrap().as_ref().unwrap().clone()),
            }
        }

        async fn receive_rpc(&self, from: Pid, (kind, state): (u8, u64)) {
            let observed = self.observed.as_ref().unwrap();
            assert_eq!(from, Pid::from_raw(1));
            match kind {
                0 => {
                    assert_eq!(state, 0);
                    observed.events.lock().unwrap().push(Event::Start);
                    let payload = observed.first.lock().unwrap().take().unwrap();
                    resume_unwind(payload);
                }
                1 => {
                    assert_eq!(state, THREAD_STATE);
                    assert!(
                        !observed.failures.lock().unwrap().is_empty(),
                        "thread consumer must observe published failure"
                    );
                    observed.events.lock().unwrap().push(Event::ThreadConsumed);
                    let mut release = observed.release.lock().unwrap().take().unwrap();
                    std::future::poll_fn(|cx| {
                        let result = Pin::new(&mut release).poll(cx);
                        if result.is_pending() {
                            observed.pending.store(true, Ordering::SeqCst);
                        }
                        result
                    })
                    .await
                    .expect("controller releases the pending consuming hook");
                    observed.events.lock().unwrap().push(Event::ThreadReleased);
                    let payload = observed.second.lock().unwrap().take().unwrap();
                    resume_unwind(payload);
                }
                2 => {
                    assert_eq!(state, 0);
                    assert!(!observed.failures.lock().unwrap().is_empty());
                    observed.events.lock().unwrap().push(Event::ProcessConsumed);
                }
                _ => panic!("unexpected public-owner RPC {kind}"),
            }
        }

        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            self.observed
                .as_ref()
                .unwrap()
                .failures
                .lock()
                .unwrap()
                .push(event);
        }
    }

    #[derive(Default)]
    struct OwnerTool;

    #[reverie::tool]
    impl Tool for OwnerTool {
        type GlobalState = OwnerGlobal;
        type ThreadState = u64;

        fn subscriptions(_: &()) -> reverie::Subscription {
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
            panic!("start callback resumed after its original panic")
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<OwnerGlobal>>(
            &self,
            tid: Pid,
            global: &G,
            state: u64,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(tid, Pid::from_raw(1));
            assert_eq!(state, THREAD_STATE);
            assert_eq!(status, ExitStatus::Exited(255));
            global.send_rpc((1, state)).await;
            panic!("thread consumer resumed after its original panic")
        }

        async fn on_exit_process<G: reverie::GlobalRPC<OwnerGlobal>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(pid, Pid::from_raw(1));
            assert_eq!(status, ExitStatus::Exited(255));
            global.send_rpc((2, 0)).await;
            Err(reverie::syscalls::Errno::ENOSPC.into())
        }
    }

    fn diagnostic_counts(error: &Error) -> (usize, usize) {
        match error {
            Error::GuestWorkerPanic => (1, 0),
            Error::Reverie(reverie::Error::Errno(errno))
                if *errno == reverie::syscalls::Errno::ENOSPC =>
            {
                (0, 1)
            }
            Error::SignalEffects { cause, .. }
            | Error::SharedFailure(cause)
            | Error::WorkerFailure { error: cause, .. }
            | Error::Cleanup { error: cause, .. } => diagnostic_counts(cause),
            Error::WithCleanup { primary, cleanup } => {
                cleanup
                    .iter()
                    .fold(diagnostic_counts(primary), |(panics, errors), next| {
                        let (next_panics, next_errors) = diagnostic_counts(next);
                        (panics + next_panics, errors + next_errors)
                    })
            }
            Error::ExecWorkerTeardown(error) => diagnostic_counts(error),
            _ => (0, 0),
        }
    }

    #[test]
    fn public_direct_and_elf_owners_finish_pending_consumers_before_resuming_panic() {
        // One declaration owns ACTIVE, and the two public routes run serially.
        // Both fail during thread start, before their first guest-entry loop.
        for elf in [false, true] {
            let mut backend = KvmBackend::new(16 * 1024 * 1024)
                .expect("public owner panic control requires /dev/kvm");
            if elf {
                backend
                    .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/public-owner-panic")
                    .unwrap();
            } else {
                backend
                    .install_syscall(
                        0x1000,
                        0x2000,
                        SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
                    )
                    .unwrap();
            }
            backend.set_backend_stats_request(BackendStatsRequest::new(true));
            let exits = backend.exit_collector.as_ref().unwrap().clone();
            let drops = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
            let (first, first_address) = payload(&drops, 0);
            let (second, second_address) = payload(&drops, 1);
            let (release, receiver) = oneshot::channel();
            let observed = Arc::new(Observation {
                events: Mutex::new(Vec::new()),
                failures: Mutex::new(Vec::new()),
                first: Mutex::new(Some(first)),
                second: Mutex::new(Some(second)),
                release: Mutex::new(Some(receiver)),
                pending: AtomicBool::new(false),
                payload_drops: drops,
            });
            {
                let mut active = ACTIVE.lock().unwrap();
                assert!(active.is_none());
                *active = Some(observed.clone());
            }
            let active = ActiveObservation;
            let public_run = async {
                if elf {
                    backend
                        .run_static_elf_with_tool_completion::<OwnerTool>((), false)
                        .await
                        .map(|_| ())
                } else {
                    backend
                        .run_with_tool::<OwnerTool, _>(
                            (),
                            |_: &SyscallRequest, _: &GuestMemory| -> i64 {
                                panic!("public owner continued into a guest syscall")
                            },
                        )
                        .await
                        .map(|_| ())
                }
            };
            let mut caught = Box::pin(AssertUnwindSafe(public_run).catch_unwind());
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(caught.as_mut().poll(&mut context), Poll::Pending));
            assert!(observed.pending.load(Ordering::SeqCst));
            assert_eq!(
                *observed.events.lock().unwrap(),
                vec![Event::Start, Event::ThreadConsumed]
            );
            assert_payload_drops(&observed, [0, 0]);
            assert_eq!(exits.snapshot().total_exits(), 0);
            release.send(()).unwrap();
            let original = futures::executor::block_on(caught.as_mut())
                .expect_err("public owner must resume its original panic");
            drop(caught);
            assert_payload(&original, 0, first_address);
            assert_eq!(
                *observed.events.lock().unwrap(),
                vec![
                    Event::Start,
                    Event::ThreadConsumed,
                    Event::ThreadReleased,
                    Event::ProcessConsumed,
                    Event::GlobalDropped,
                ]
            );
            assert_payload_drops(&observed, [0, 0]);
            assert_eq!(exits.snapshot().total_exits(), 0);
            assert!(backend.tool_panics.take().is_empty());
            assert!(backend.tool_failure.is_none());
            {
                let completed = backend.completed_tool_panics.lock().unwrap();
                assert_eq!(completed.len(), 1);
                assert!(matches!(
                    completed[0]._error.primary(),
                    Error::GuestWorkerPanic
                ));
                assert_eq!(diagnostic_counts(&completed[0]._error), (2, 1));
                assert_eq!(completed[0]._secondary_payloads.len(), 1);
                assert_payload(&completed[0]._secondary_payloads[0], 1, second_address);
                assert_eq!(completed[0]._run_failure.is_some(), elf);
            }
            assert!(observed.first.lock().unwrap().is_none());
            assert!(observed.second.lock().unwrap().is_none());
            drop(original);
            assert_payload_drops(&observed, [1, 0]);
            drop(backend);
            assert_payload_drops(&observed, [1, 1]);
            assert_eq!(
                observed
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == Event::GlobalDropped)
                    .count(),
                1
            );
            drop(active);
            assert!(ACTIVE.lock().unwrap().is_none());
        }
    }
}
