/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod instruction_callback_panic_tests {
    use std::cell::Cell;
    use std::future::Future;
    use std::marker::PhantomData;
    use std::panic::AssertUnwindSafe;
    use std::panic::resume_unwind;
    use std::pin::Pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use reverie::Guest;
    use reverie::syscalls::Errno;

    use super::*;
    use crate::failure::owned_future::PanicPayload;

    static SERIAL: Mutex<()> = Mutex::new(());
    static ADDRESS: AtomicUsize = AtomicUsize::new(0);
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    static POLLS: AtomicUsize = AtomicUsize::new(0);

    struct Payload(Cell<u8>);

    impl Drop for Payload {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct InstructionFuture<R> {
        payload: Option<PanicPayload>,
        _output: PhantomData<fn() -> R>,
    }

    impl<R> InstructionFuture<R> {
        fn new() -> Self {
            let payload = Box::new(Payload(Cell::new(37)));
            ADDRESS.store(
                std::ptr::from_ref(payload.as_ref()) as usize,
                Ordering::SeqCst,
            );
            Self {
                payload: Some(payload),
                _output: PhantomData,
            }
        }
    }

    impl<R> Future for InstructionFuture<R> {
        type Output = std::result::Result<R, Errno>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            assert_eq!(POLLS.fetch_add(1, Ordering::SeqCst), 0);
            Poll::Ready(Err(Errno::EIO))
        }
    }

    impl<R> Drop for InstructionFuture<R> {
        fn drop(&mut self) {
            resume_unwind(self.payload.take().unwrap());
        }
    }

    #[derive(Default)]
    struct InstructionTool;

    #[derive(Default)]
    struct ConstructorTool;

    fn fail_constructor<G: Guest<ConstructorTool>>(guest: &mut G) -> ! {
        // This unsupported instruction-context tail injection transfers its
        // real RuntimeError into the callback's signal slot before suspending.
        let mut injection = Box::pin(guest.tail_inject(reverie::syscalls::Getpid::new()));
        let mut context = Context::from_waker(Waker::noop());
        assert!(injection.as_mut().poll(&mut context).is_pending());
        drop(injection);
        let payload = Box::new(Payload(Cell::new(37)));
        ADDRESS.store(
            std::ptr::from_ref(payload.as_ref()) as usize,
            Ordering::SeqCst,
        );
        resume_unwind(payload)
    }

    impl Tool for ConstructorTool {
        type GlobalState = ();
        type ThreadState = ();

        fn subscriptions(config: &()) -> reverie::Subscription {
            InstructionTool::subscriptions(config)
        }

        fn handle_rdtsc_event<'life0, 'life1, 'async_trait, G>(
            &'life0 self,
            guest: &'life1 mut G,
            _: reverie::Rdtsc,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<reverie::RdtscResult, Errno>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            G: Guest<Self> + 'async_trait,
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            fail_constructor(guest)
        }

        fn handle_cpuid_event<'life0, 'life1, 'async_trait, G>(
            &'life0 self,
            guest: &'life1 mut G,
            _: u32,
            _: u32,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<reverie::CpuIdResult, Errno>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            G: Guest<Self> + 'async_trait,
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            fail_constructor(guest)
        }
    }

    // The actual Tool ABI permits a returned future to yield an errno and
    // independently panic when destroyed. An async fn local guard would
    // instead panic before returning Ready and would not test this defect.
    impl Tool for InstructionTool {
        type GlobalState = ();
        type ThreadState = ();

        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.rdtsc();
            subscriptions.cpuid();
            subscriptions
        }

        fn handle_rdtsc_event<'life0, 'life1, 'async_trait, G>(
            &'life0 self,
            _: &'life1 mut G,
            _: reverie::Rdtsc,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<reverie::RdtscResult, Errno>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            G: Guest<Self> + 'async_trait,
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(InstructionFuture::new())
        }

        fn handle_cpuid_event<'life0, 'life1, 'async_trait, G>(
            &'life0 self,
            _: &'life1 mut G,
            _: u32,
            _: u32,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<reverie::CpuIdResult, Errno>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            G: Guest<Self> + 'async_trait,
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(InstructionFuture::new())
        }
    }

    fn counts(error: &Error, expected: Errno) -> (usize, usize) {
        match error {
            Error::Reverie(reverie::Error::Errno(errno)) => (usize::from(*errno == expected), 0),
            Error::GuestWorkerPanic => (0, 1),
            Error::SharedFailure(error)
            | Error::WorkerFailure { error, .. }
            | Error::Cleanup { error, .. }
            | Error::SignalEffects { cause: error, .. } => counts(error, expected),
            Error::ExecWorkerTeardown(error) => counts(error, expected),
            Error::WithCleanup { primary, cleanup } => {
                cleanup
                    .iter()
                    .fold(counts(primary, expected), |(a, b), error| {
                        let (c, d) = counts(error, expected);
                        (a + c, b + d)
                    })
            }
            _ => (0, 0),
        }
    }

    #[test]
    fn actual_timestamp_and_cpuid_callbacks_retain_returned_errno_after_destructor_panic() {
        let _serial = SERIAL.lock().unwrap();
        for instruction in [&[0x0f, 0x31][..], &[0x0f, 0xa2][..]] {
            ADDRESS.store(0, Ordering::SeqCst);
            DROPS.store(0, Ordering::SeqCst);
            POLLS.store(0, Ordering::SeqCst);
            let mut backend = KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
            let mut code = vec![0x31, 0xc0, 0x31, 0xc9]; // eax=ecx=0
            code.extend_from_slice(instruction);
            code.push(HLT);
            backend
                .install_static_elf(&minimal_test_elf(&code), "/instruction-drop-panic")
                .unwrap();
            backend.set_backend_stats_request(BackendStatsRequest::new(true));
            let original = std::panic::catch_unwind(AssertUnwindSafe(|| {
                futures::executor::block_on(
                    backend.run_static_elf_with_tool_completion::<InstructionTool>((), false),
                )
            }))
            .err()
            .expect("original callback destructor panic must propagate");
            let payload = original
                .downcast_ref::<Payload>()
                .expect("exact original payload type");
            assert_eq!(payload.0.get(), 37);
            assert_eq!(
                std::ptr::from_ref(payload) as usize,
                ADDRESS.load(Ordering::SeqCst)
            );
            assert_eq!(DROPS.load(Ordering::SeqCst), 0);
            assert_eq!(POLLS.load(Ordering::SeqCst), 1);
            assert_eq!(
                backend
                    .exit_collector
                    .as_ref()
                    .unwrap()
                    .snapshot()
                    .total_exits(),
                1
            );
            assert!(backend.tool_panics.take().is_empty());
            assert!(backend.tool_failure.is_none());
            {
                let records = backend.completed_tool_panics.lock().unwrap();
                assert_eq!(records.len(), 1);
                assert!(matches!(
                    records[0]._error.primary(),
                    Error::Reverie(reverie::Error::Errno(Errno::EIO))
                ));
                assert_eq!(counts(&records[0]._error, Errno::EIO), (1, 1));
                assert!(records[0]._secondary_payloads.is_empty());
                assert!(records[0]._run_failure.is_some());
            }
            drop(original);
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn actual_instruction_constructor_panic_retains_the_injected_runtime_error() {
        let _serial = SERIAL.lock().unwrap();
        for instruction in [&[0x0f, 0x31][..], &[0x0f, 0xa2][..]] {
            ADDRESS.store(0, Ordering::SeqCst);
            DROPS.store(0, Ordering::SeqCst);
            POLLS.store(0, Ordering::SeqCst);
            let mut backend = KvmBackend::new(16 * 1024 * 1024).expect("actual KVM is mandatory");
            let mut code = vec![0x31, 0xc0, 0x31, 0xc9];
            code.extend_from_slice(instruction);
            code.push(HLT);
            backend
                .install_static_elf(&minimal_test_elf(&code), "/instruction-constructor-panic")
                .unwrap();
            backend.set_backend_stats_request(BackendStatsRequest::new(true));
            let original = std::panic::catch_unwind(AssertUnwindSafe(|| {
                futures::executor::block_on(
                    backend.run_static_elf_with_tool_completion::<ConstructorTool>((), false),
                )
            }))
            .err()
            .expect("original callback constructor panic must propagate");
            let payload = original
                .downcast_ref::<Payload>()
                .expect("exact original payload type");
            assert_eq!(payload.0.get(), 37);
            assert_eq!(
                std::ptr::from_ref(payload) as usize,
                ADDRESS.load(Ordering::SeqCst)
            );
            assert_eq!(DROPS.load(Ordering::SeqCst), 0);
            assert_eq!(
                POLLS.load(Ordering::SeqCst),
                0,
                "constructor returned no callback future"
            );
            assert_eq!(
                backend
                    .exit_collector
                    .as_ref()
                    .unwrap()
                    .snapshot()
                    .total_exits(),
                1
            );
            assert!(backend.tool_panics.take().is_empty());
            assert!(backend.tool_failure.is_none());
            {
                let records = backend.completed_tool_panics.lock().unwrap();
                assert_eq!(records.len(), 1);
                assert!(matches!(
                    records[0]._error.primary(),
                    Error::Reverie(reverie::Error::Errno(Errno::ENOSYS))
                ));
                assert_eq!(counts(&records[0]._error, Errno::ENOSYS), (1, 1));
                assert!(records[0]._secondary_payloads.is_empty());
                assert!(records[0]._run_failure.is_some());
            }
            drop(original);
            assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        }
    }
}
