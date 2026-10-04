/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included within vm::tests for the existing minimal_test_elf fixture.
mod entry_public_tests {
    use std::io::IoSlice;
    use std::io::IoSliceMut;
    use std::sync::atomic::AtomicUsize;

    use reverie::GlobalRPC;
    use reverie::Guest;
    use reverie::syscalls::Addr;
    use reverie::syscalls::AddrMut;
    use reverie::syscalls::AddrSlice;
    use reverie::syscalls::AddrSliceMut;
    use reverie::syscalls::Errno;
    use reverie::syscalls::MemoryAccess;

    use super::*;
    use crate::entry::owner::OperationOrigin;

    const TEST_FD: i32 = 9;
    const FILE_LENGTH: u64 = 7;
    const THREAD_STATE: u64 = 0x7374_6174_6500_0011;
    static CASE_LOCK: Mutex<()> = Mutex::new(());
    static ACTIVE: Mutex<Option<Arc<Observed>>> = Mutex::new(None);

    #[derive(Clone, Copy, Debug)]
    struct Case {
        elf: bool,
        injection: bool,
        write: bool,
        poison_after: Option<usize>,
        address: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        CallbackStarted,
        CopyReturned,
        CallbackDropped,
        Published,
        ThreadConsumed,
        ProcessConsumed,
    }

    struct Observed {
        case: Case,
        events: Mutex<Vec<Event>>,
        copy_boundaries: Mutex<Vec<usize>>,
        origin: Mutex<Option<OperationOrigin>>,
        failure_context_present: Mutex<Option<bool>>,
        cause: Arc<Error>,
        copy_armed: AtomicBool,
        injection_armed: AtomicBool,
        ordinary_constructors: AtomicUsize,
        ordinary_polls: AtomicUsize,
        target_dispatches: AtomicUsize,
        ordinary_completed: AtomicUsize,
        publications: AtomicUsize,
        thread_consumed: AtomicUsize,
        process_consumed: AtomicUsize,
        callback_dropped: AtomicBool,
    }

    impl Observed {
        fn new(case: Case) -> Self {
            Self {
                case,
                events: Mutex::new(Vec::new()),
                copy_boundaries: Mutex::new(Vec::new()),
                origin: Mutex::new(None),
                failure_context_present: Mutex::new(None),
                cause: Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
                    libc::EOWNERDEAD,
                ))),
                copy_armed: AtomicBool::new(false),
                injection_armed: AtomicBool::new(false),
                ordinary_constructors: AtomicUsize::new(0),
                ordinary_polls: AtomicUsize::new(0),
                target_dispatches: AtomicUsize::new(0),
                ordinary_completed: AtomicUsize::new(0),
                publications: AtomicUsize::new(0),
                thread_consumed: AtomicUsize::new(0),
                process_consumed: AtomicUsize::new(0),
                callback_dropped: AtomicBool::new(false),
            }
        }

        fn event(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }

        fn dispatched(&self, request: &SyscallRequest) {
            if request.number() == libc::SYS_ftruncate as u64 {
                assert!(self.injection_armed.load(Ordering::SeqCst));
                assert_eq!(request.args()[0], TEST_FD as u64);
                assert_eq!(request.args()[1], FILE_LENGTH);
                self.target_dispatches.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct ActiveCase;
    impl Drop for ActiveCase {
        fn drop(&mut self) {
            let old = ACTIVE.lock().unwrap_or_else(|p| p.into_inner()).take();
            drop(old);
        }
    }

    struct CallbackDrop(Arc<Observed>);
    impl Drop for CallbackDrop {
        fn drop(&mut self) {
            assert_eq!(self.0.publications.load(Ordering::SeqCst), 0);
            assert!(
                !self
                    .0
                    .origin
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .callback_dropped()
            );
            assert!(!self.0.callback_dropped.swap(true, Ordering::SeqCst));
            self.0.event(Event::CallbackDropped);
        }
    }

    #[derive(Default)]
    struct PublicGlobal {
        observed: Option<Arc<Observed>>,
    }

    // Explicit async_trait ABI distinguishes actual RPC construction from polling.
    impl GlobalTool for PublicGlobal {
        type Request = u8;
        type Response = ();
        type Config = ();

        fn init_global_state<'life0, 'async_trait>(
            _: &'life0 (),
        ) -> Pin<Box<dyn Future<Output = Self> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async {
                Self {
                    observed: Some(ACTIVE.lock().unwrap().as_ref().unwrap().clone()),
                }
            })
        }

        fn receive_rpc<'life0, 'async_trait>(
            &'life0 self,
            from: Pid,
            kind: u8,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            Self: 'async_trait,
        {
            let observed = self.observed.as_ref().unwrap();
            assert_eq!(from, Pid::from_raw(1));
            if kind == 0 {
                observed
                    .ordinary_constructors
                    .fetch_add(1, Ordering::SeqCst);
            }
            Box::pin(async move {
                match kind {
                    0 => {
                        observed.ordinary_polls.fetch_add(1, Ordering::SeqCst);
                    }
                    1 => {
                        assert!(observed.callback_dropped.load(Ordering::SeqCst));
                        assert_eq!(
                            observed.publications.load(Ordering::SeqCst) > 0,
                            observed.case.poison_after.is_some()
                        );
                        assert_eq!(observed.thread_consumed.fetch_add(1, Ordering::SeqCst), 0);
                        observed.event(Event::ThreadConsumed);
                    }
                    2 => {
                        assert_eq!(observed.thread_consumed.load(Ordering::SeqCst), 1);
                        assert_eq!(observed.process_consumed.fetch_add(1, Ordering::SeqCst), 0);
                        observed.event(Event::ProcessConsumed);
                    }
                    _ => panic!("unexpected public entry control RPC {kind}"),
                }
            })
        }

        fn report_backend_failure(&self, _: reverie::BackendFailure) {
            let observed = self.observed.as_ref().unwrap();
            assert!(observed.case.poison_after.is_some());
            assert!(observed.callback_dropped.load(Ordering::SeqCst));
            assert!(
                observed
                    .origin
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .callback_dropped()
            );
            observed.publications.fetch_add(1, Ordering::SeqCst);
            observed.event(Event::Published);
        }
    }

    #[derive(Default)]
    struct PublicTool;

    #[reverie::tool]
    impl Tool for PublicTool {
        type GlobalState = PublicGlobal;
        type ThreadState = u64;

        fn subscriptions(_: &()) -> reverie::Subscription {
            reverie::Subscription::none()
        }

        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &u64)>) -> u64 {
            assert_eq!(tid, Pid::from_raw(1));
            assert!(parent.is_none());
            THREAD_STATE
        }

        async fn handle_thread_start<G: Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            observed.event(Event::CallbackStarted);
            let _drop = CallbackDrop(observed.clone());
            observed.copy_armed.store(true, Ordering::SeqCst);
            let mut memory = guest.memory();
            let mut read_left = [0xa5; 2];
            let mut read_right = [0xa5; 2];
            let actual = if observed.case.write {
                let from = [IoSlice::new(b"WX"), IoSlice::new(b"YZ")];
                // AddrSliceMut creates remote-vector metadata; the adapter
                // translates these guest addresses before touching bytes.
                let mut left = unsafe {
                    AddrSliceMut::from_raw_parts(
                        AddrMut::<u8>::from_raw(observed.case.address as usize).unwrap(),
                        2,
                    )
                };
                let mut right = unsafe {
                    AddrSliceMut::from_raw_parts(
                        AddrMut::<u8>::from_raw(observed.case.address as usize + 2).unwrap(),
                        2,
                    )
                };
                let mut to = [unsafe { left.as_ioslice_mut() }, unsafe {
                    right.as_ioslice_mut()
                }];
                memory.write_vectored(&from, &mut to)
            } else {
                let left = unsafe {
                    AddrSlice::from_raw_parts(
                        Addr::<u8>::from_raw(observed.case.address as usize).unwrap(),
                        2,
                    )
                };
                let right = unsafe {
                    AddrSlice::from_raw_parts(
                        Addr::<u8>::from_raw(observed.case.address as usize + 2).unwrap(),
                        2,
                    )
                };
                let from = [unsafe { left.as_ioslice() }, unsafe { right.as_ioslice() }];
                let mut to = [
                    IoSliceMut::new(&mut read_left),
                    IoSliceMut::new(&mut read_right),
                ];
                memory.read_vectored(&from, &mut to)
            };
            observed.copy_armed.store(false, Ordering::SeqCst);
            assert_eq!(
                actual,
                if observed.case.poison_after.is_some() {
                    Err(Errno::EIO)
                } else {
                    Ok(4)
                }
            );
            if !observed.case.write {
                let expected = match observed.case.poison_after {
                    Some(0) => [0xa5; 4],
                    Some(2) => [b'A', b'B', 0xa5, 0xa5],
                    None => *b"ABCD",
                    _ => unreachable!(),
                };
                assert_eq!(
                    [read_left[0], read_left[1], read_right[0], read_right[1]],
                    expected
                );
            }
            observed.event(Event::CopyReturned);
            if observed.case.injection {
                observed.injection_armed.store(true, Ordering::SeqCst);
                assert_eq!(
                    guest
                        .inject(
                            reverie::syscalls::Ftruncate::new()
                                .with_fd(TEST_FD)
                                .with_length(FILE_LENGTH as libc::off_t)
                        )
                        .await?,
                    0
                );
            } else {
                guest.send_rpc(0).await;
            }
            observed.ordinary_completed.fetch_add(1, Ordering::SeqCst);
            assert!(
                observed.case.poison_after.is_none(),
                "fatal MemoryAccess result allowed ordinary operation to finish"
            );
            Ok(())
        }

        async fn on_exit_thread<G: GlobalRPC<PublicGlobal>>(
            &self,
            tid: Pid,
            global: &G,
            state: u64,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(tid, Pid::from_raw(1));
            assert_eq!(state, THREAD_STATE);
            assert_eq!(
                status,
                ExitStatus::Exited(if observed.case.poison_after.is_some() {
                    255
                } else {
                    0
                })
            );
            global.send_rpc(1).await;
            Ok(())
        }

        async fn on_exit_process<G: GlobalRPC<PublicGlobal>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(pid, Pid::from_raw(1));
            assert_eq!(
                status,
                ExitStatus::Exited(if observed.case.poison_after.is_some() {
                    255
                } else {
                    0
                })
            );
            global.send_rpc(2).await;
            Ok(())
        }
    }

    fn effect_file() -> File {
        let fd =
            unsafe { libc::memfd_create(c"kvm-entry-public-effect".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(
            fd >= 0,
            "create isolated effect file: {}",
            std::io::Error::last_os_error()
        );
        unsafe { File::from_raw_fd(fd) }
    }

    fn run_case(elf: bool, injection: bool, write: bool, poison_after: Option<usize>) {
        let address = if elf { 0x20_1000 } else { 0x30_0000 };
        let case = Case {
            elf,
            injection,
            write,
            poison_after,
            address,
        };
        let mut backend = KvmBackend::new(16 * 1024 * 1024)
            .expect("public memory failure control requires /dev/kvm");
        let effect = Arc::new(effect_file());
        if elf {
            // mov eax, 60; xor edi, edi; syscall. Healthy cases really enter
            // the guest and exit normally; poisoned cases never enter it.
            let code = [0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
            backend
                .install_static_elf(&minimal_test_elf(&code), "/bin/public-entry-control")
                .unwrap();
            backend
                .static_elf
                .as_mut()
                .unwrap()
                .insert_file(TEST_FD, effect.try_clone().unwrap());
        } else {
            backend
                .install_syscall(
                    0x1000,
                    0x2000,
                    SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
                )
                .unwrap();
        }
        backend.memory.write_raw(address, b"ABCD").unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let observed = Arc::new(Observed::new(case));
        let copy_observed = observed.clone();
        let gate = backend.memory.entry_gate();
        backend
            .memory
            .set_test_vector_copy_observer(Arc::new(move |total, origin| {
                if !copy_observed.copy_armed.load(Ordering::SeqCst) {
                    return;
                }
                assert_eq!(origin.failure.is_some(), copy_observed.case.elf);
                let operation = origin
                    .operation
                    .as_ref()
                    .expect("actual callback-bound memory origin");
                assert!(operation.callback_id().is_some());
                assert!(!operation.callback_dropped());
                *copy_observed.origin.lock().unwrap() = Some(operation.clone());
                *copy_observed.failure_context_present.lock().unwrap() =
                    Some(origin.failure.is_some());
                copy_observed.copy_boundaries.lock().unwrap().push(total);
                if copy_observed.case.poison_after == Some(total) {
                    gate.poison(origin, Error::SharedFailure(copy_observed.cause.clone()));
                }
            }));
        let dispatch_observed = observed.clone();
        backend
            .memory
            .set_test_syscall_dispatch_observer(Arc::new(move |request| {
                dispatch_observed.dispatched(request);
            }));
        {
            let mut active = ACTIVE.lock().unwrap();
            assert!(active.is_none());
            *active = Some(observed.clone());
        }
        let active = ActiveCase;
        let result = if elf {
            let completion = futures::executor::block_on(
                backend.run_static_elf_with_tool_completion::<PublicTool>((), false),
            )
            .unwrap();
            completion.result.map(|(status, stdout, stderr)| {
                assert_eq!(status, 0);
                assert!(stdout.is_empty());
                assert!(stderr.is_empty());
            })
        } else {
            let direct_observed = observed.clone();
            let direct_effect = effect.clone();
            futures::executor::block_on(backend.run_with_tool::<PublicTool, _>(
                (),
                move |request: &SyscallRequest, _: &GuestMemory| -> i64 {
                    if request.number() == libc::SYS_ftruncate as u64 {
                        direct_observed.dispatched(request);
                        direct_effect.set_len(request.args()[1]).unwrap();
                        0
                    } else {
                        assert_eq!(request.number(), libc::SYS_getpid as u64);
                        1
                    }
                },
            ))
            .map(|_| ())
        };
        if poison_after.is_some() {
            let error = result.expect_err("public driver must retain the fatal private cause");
            assert!(
                crate::failure::references_shared_error(&error, &observed.cause),
                "{error}"
            );
            assert_eq!(observed.ordinary_completed.load(Ordering::SeqCst), 0);
            assert_eq!(observed.ordinary_constructors.load(Ordering::SeqCst), 0);
            assert_eq!(observed.ordinary_polls.load(Ordering::SeqCst), 0);
            assert_eq!(observed.target_dispatches.load(Ordering::SeqCst), 0);
            assert_eq!(effect.metadata().unwrap().len(), 0);
            assert!(observed.publications.load(Ordering::SeqCst) > 0);
            assert_eq!(exits.snapshot().total_exits(), 0);
        } else {
            result.unwrap();
            assert_eq!(observed.ordinary_completed.load(Ordering::SeqCst), 1);
            assert_eq!(
                observed.ordinary_constructors.load(Ordering::SeqCst),
                usize::from(!injection)
            );
            assert_eq!(
                observed.ordinary_polls.load(Ordering::SeqCst),
                usize::from(!injection)
            );
            assert_eq!(
                observed.target_dispatches.load(Ordering::SeqCst),
                usize::from(injection)
            );
            assert_eq!(
                effect.metadata().unwrap().len(),
                if injection { FILE_LENGTH } else { 0 }
            );
            assert_eq!(observed.publications.load(Ordering::SeqCst), 0);
            assert!(exits.snapshot().total_exits() > 0);
        }
        assert_eq!(
            *observed.copy_boundaries.lock().unwrap(),
            match poison_after {
                Some(0) => vec![0],
                Some(2) => vec![0, 2],
                None => vec![0, 2, 4],
                _ => unreachable!(),
            }
        );
        assert_eq!(*observed.failure_context_present.lock().unwrap(), Some(elf));
        assert_eq!(observed.thread_consumed.load(Ordering::SeqCst), 1);
        assert_eq!(observed.process_consumed.load(Ordering::SeqCst), 1);
        assert!(observed.callback_dropped.load(Ordering::SeqCst));
        let expected = if write {
            match poison_after {
                Some(0) => *b"ABCD",
                Some(2) => *b"WXCD",
                None => *b"WXYZ",
                _ => unreachable!(),
            }
        } else {
            *b"ABCD"
        };
        // The fixture uses low identity-backed addresses. The public driver has
        // fully returned, so no guest or callback can write concurrently. Read
        // the retained backing directly to inspect real prefix effects after
        // poison without bypassing the production adapter during the run.
        let physical = backend.memory.host_address() + address - backend.memory.guest_base();
        let actual = unsafe { std::slice::from_raw_parts(physical as *const u8, 4) };
        assert_eq!(actual, &expected, "case {case:?}");
        let events = observed.events.lock().unwrap();
        let position = |wanted| events.iter().position(|event| *event == wanted).unwrap();
        assert!(position(Event::CallbackStarted) < position(Event::CopyReturned));
        assert!(position(Event::CopyReturned) < position(Event::CallbackDropped));
        assert!(position(Event::CallbackDropped) < position(Event::ThreadConsumed));
        assert!(position(Event::ThreadConsumed) < position(Event::ProcessConsumed));
        if poison_after.is_some() {
            assert!(position(Event::CallbackDropped) < position(Event::Published));
            assert!(position(Event::Published) < position(Event::ThreadConsumed));
        }
        drop(events);
        assert!(backend.tool_failure.is_none());
        assert!(backend.tool_panics.take().is_empty());
        drop(active);
    }

    fn run_route(elf: bool, injection: bool) {
        // Each declaration gets every before-byte/prefix read/write refusal and
        // both healthy copy directions. A failed earlier declaration cannot
        // prevent another route/operation from being selected independently.
        let _exclusive = CASE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for write in [false, true] {
            for poison_after in [Some(0), Some(2), None] {
                run_case(elf, injection, write, poison_after);
            }
        }
    }

    #[test]
    fn public_direct_memory_failure_refuses_ready_rpc() {
        run_route(false, false);
    }

    #[test]
    fn public_direct_memory_failure_refuses_injection() {
        run_route(false, true);
    }

    #[test]
    fn public_elf_memory_failure_refuses_ready_rpc() {
        run_route(true, false);
    }

    #[test]
    fn public_elf_memory_failure_refuses_injection() {
        run_route(true, true);
    }
}
