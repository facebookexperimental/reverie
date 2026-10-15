/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests so the existing minimal ELF fixture remains private.
mod kept_rpc_failure_tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::task::Poll;
    use std::task::Waker;

    use super::*;

    /// What the GlobalTool saw. One per run, keyed by the run's mode.
    #[derive(Default)]
    struct Counts {
        /// GlobalTool::wait_for_backend_failure calls: one per failure wait
        /// the backend built.
        waits: AtomicU64,
        /// RPCs of each kind that reached receive_rpc.
        first: AtomicU64,
        second: AtomicU64,
        third: AtomicU64,
        /// FORKED_PEER_FAILS: the child's never-answered RPC has started.
        fourth: AtomicU64,
        /// The backend failure the GlobalTool's waits report once set.
        failed: AtomicBool,
        /// Wakers the GlobalTool's waits registered while Pending, and how
        /// many registrations happened after a PENDING_RPC_WAKES RPC began.
        wakers: Mutex<Vec<Waker>>,
        registered_after_third: AtomicU64,
    }

    impl Counts {
        /// Publish the backend failure and wake every registered wait.
        fn fail(&self) {
            self.failed.store(true, Ordering::SeqCst);
            for waker in self.wakers.lock().unwrap().drain(..) {
                waker.wake();
            }
        }
    }

    static ACTIVE: Mutex<Option<Arc<Counts>>> = Mutex::new(None);
    /// Runs share ACTIVE, so tests in one process take turns.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Modes: RPCs per getpid, or the failure-precedence run.
    const ONE_RPC: u8 = 1;
    const FOUR_RPCS: u8 = 4;
    const FAIL_DURING_FIRST: u8 = 0;
    const FAIL_BETWEEN_RPCS: u8 = 5;
    const PENDING_RPC_WAKES: u8 = 6;
    const FORKED_PEER_FAILS: u8 = 8;

    #[derive(Default)]
    struct RpcGlobal {
        counts: Option<Arc<Counts>>,
        mode: u8,
    }

    #[reverie::global_tool]
    impl GlobalTool for RpcGlobal {
        type Request = u8;
        type Response = ();
        type Config = u8;

        async fn init_global_state(mode: &u8) -> Self {
            Self {
                counts: Some(ACTIVE.lock().unwrap().as_ref().unwrap().clone()),
                mode: *mode,
            }
        }

        async fn receive_rpc(&self, _from: Pid, kind: u8) {
            let counts = self.counts.as_ref().unwrap();
            match kind {
                1 => {
                    counts.first.fetch_add(1, Ordering::SeqCst);
                    if self.mode == FAIL_DURING_FIRST {
                        counts.fail();
                    }
                }
                2 => {
                    counts.second.fetch_add(1, Ordering::SeqCst);
                }
                3 => {
                    counts.third.fetch_add(1, Ordering::SeqCst);
                    // Publish from another thread only after the RPC's failure
                    // wait has registered a waker while this response was
                    // Pending, so only that wake can end the RPC.
                    let publisher = counts.clone();
                    std::thread::spawn(move || {
                        while publisher.registered_after_third.load(Ordering::SeqCst) == 0 {
                            std::thread::yield_now();
                        }
                        publisher.fail();
                    });
                    std::future::pending::<()>().await;
                }
                4 => {
                    counts.fourth.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                _ => panic!("unexpected RPC {kind}"),
            }
        }

        async fn wait_for_backend_failure(&self) {
            let counts = self.counts.as_ref().unwrap().clone();
            counts.waits.fetch_add(1, Ordering::SeqCst);
            std::future::poll_fn(move |context| {
                if counts.failed.load(Ordering::SeqCst) {
                    return Poll::Ready(());
                }
                counts.wakers.lock().unwrap().push(context.waker().clone());
                if counts.third.load(Ordering::SeqCst) != 0 {
                    counts.registered_after_third.fetch_add(1, Ordering::SeqCst);
                }
                if counts.failed.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await
        }
    }

    #[derive(Default)]
    struct RpcTool {
        mode: u8,
    }

    #[reverie::tool]
    impl Tool for RpcTool {
        type GlobalState = RpcGlobal;
        type ThreadState = ();

        fn new(_: Pid, mode: &u8) -> Self {
            Self { mode: *mode }
        }

        fn subscriptions(_: &u8) -> reverie::Subscription {
            let mut subscription = reverie::Subscription::none();
            subscription.syscall(reverie::syscalls::Sysno::getpid);
            subscription.syscall(reverie::syscalls::Sysno::getppid);
            subscription
        }

        async fn handle_syscall_event<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
            call: reverie::syscalls::Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            match self.mode {
                FAIL_DURING_FIRST => {
                    // The first RPC publishes the failure; the second must be
                    // stopped before it reaches the GlobalTool.
                    guest.send_rpc(1).await;
                    guest.send_rpc(2).await;
                }
                FAIL_BETWEEN_RPCS => {
                    // The first RPC completes; the failure is published
                    // outside any RPC, so only the check before dispatch can
                    // stop the second.
                    guest.send_rpc(1).await;
                    ACTIVE.lock().unwrap().as_ref().unwrap().fail();
                    guest.send_rpc(2).await;
                }
                PENDING_RPC_WAKES => {
                    guest.send_rpc(3).await;
                }
                FORKED_PEER_FAILS if reverie::syscalls::SyscallInfo::number(&call) == reverie::syscalls::Sysno::getpid => {
                    // The child: an RPC nothing answers. Only a failure wait
                    // can end it.
                    guest.send_rpc(4).await;
                }
                FORKED_PEER_FAILS => {
                    // The parent: fail once the child's RPC is pending.
                    let counts = ACTIVE.lock().unwrap().as_ref().unwrap().clone();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    while counts.fourth.load(Ordering::SeqCst) == 0 {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the child's RPC never started"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    // Not an errno, which would be the syscall's result: a Tool failure.
                    return Err(reverie::Error::Io(std::io::Error::other("the parent fails")));
                }
                rpcs => {
                    for _ in 0..rpcs {
                        guest.send_rpc(1).await;
                    }
                }
            }
            guest.tail_inject(call).await
        }
    }

    // mov eax, SYS_getpid; syscall (three times); mov eax, SYS_exit; xor edi,
    // edi; syscall.
    fn three_getpids_then_exit() -> Vec<u8> {
        let getpid = [0xb8, 39, 0, 0, 0, 0x0f, 0x05];
        let exit = [0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
        [&getpid[..], &getpid, &getpid, &exit].concat()
    }

    // mov eax, SYS_fork; syscall; test rax, rax; jz child. The parent calls
    // getppid, the child getpid; each then exits.
    fn fork_then_getppid_or_getpid() -> Vec<u8> {
        let exit = [0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
        let parent = [&[0xb8, 110, 0, 0, 0, 0x0f, 0x05][..], &exit].concat();
        let child = [&[0xb8, 39, 0, 0, 0, 0x0f, 0x05][..], &exit].concat();
        [
            &[0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74][..],
            &[parent.len() as u8],
            &parent,
            &child,
        ]
        .concat()
    }

    fn run(mode: u8) -> (Arc<Counts>, Result<i32>) {
        let code = if mode == FORKED_PEER_FAILS {
            fork_then_getppid_or_getpid()
        } else {
            three_getpids_then_exit()
        };
        let _serial = SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let counts = Arc::new(Counts::default());
        {
            let mut active = ACTIVE.lock().unwrap();
            assert!(active.is_none());
            *active = Some(counts.clone());
        }
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("kept RPC failure test requires /dev/kvm");
        backend
            .install_static_elf(&minimal_test_elf(&code), "/bin/kept-rpc")
            .unwrap();
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<RpcTool>(mode, true),
        )
        .map(|(_, status, _, _)| status);
        ACTIVE.lock().unwrap().take();
        drop(backend);
        (counts, result)
    }

    /// The ordinary syscall callback's RPCs share one kept failure wait per
    /// thread, so the GlobalTool builds as many failure waits when every
    /// getpid sends four RPCs as when it sends one. Before, each RPC built
    /// its own wait.
    #[test]
    fn rpcs_share_the_threads_kept_failure_wait() {
        let (one, status) = run(ONE_RPC);
        assert_eq!(status.unwrap(), 0);
        assert_eq!(one.first.load(Ordering::SeqCst), 3);
        let (four, status) = run(FOUR_RPCS);
        assert_eq!(status.unwrap(), 0);
        assert_eq!(four.first.load(Ordering::SeqCst), 12);
        assert_eq!(
            four.waits.load(Ordering::SeqCst),
            one.waits.load(Ordering::SeqCst),
            "nine more RPCs built no more failure waits"
        );
    }

    /// A failure published during one RPC stops the next RPC of the same
    /// callback before it reaches the GlobalTool, as when each RPC built its
    /// own wait: the kept wait is polled first and reports the failure.
    #[test]
    fn a_failure_published_during_an_rpc_stops_the_next_one() {
        let (counts, result) = run(FAIL_DURING_FIRST);
        assert!(result.is_err(), "the run must end in the published failure");
        assert_eq!(counts.first.load(Ordering::SeqCst), 1);
        assert_eq!(
            counts.second.load(Ordering::SeqCst),
            0,
            "the RPC after the failure was dispatched"
        );
    }

    /// A failure published between two RPCs, with the first already
    /// complete, stops the second before dispatch: the kept wait is polled
    /// before the response is constructed.
    #[test]
    fn a_failure_published_between_rpcs_stops_the_next_before_dispatch() {
        let (counts, result) = run(FAIL_BETWEEN_RPCS);
        assert!(result.is_err(), "the run must end in the published failure");
        assert_eq!(counts.first.load(Ordering::SeqCst), 1);
        assert_eq!(
            counts.second.load(Ordering::SeqCst),
            0,
            "the RPC after the failure was dispatched"
        );
    }

    /// An RPC whose response stays Pending ends when another thread
    /// publishes a failure after the RPC's failure wait has registered a
    /// waker. In this root process the callback's own failure wait would
    /// also end the callback, so this checks only that the run ends; the
    /// per-RPC wake is pinned by
    /// failure::tests::a_kept_rpc_failure_wakes_every_pending_listener.
    #[test]
    fn a_pending_rpc_wakes_on_a_failure_published_later() {
        let (counts, result) = run(PENDING_RPC_WAKES);
        assert!(result.is_err(), "the run must end in the published failure");
        assert_eq!(counts.third.load(Ordering::SeqCst), 1);
        assert_ne!(counts.registered_after_third.load(Ordering::SeqCst), 0);
    }

    /// A forked child, which is not the traced tree's root, has an RPC that
    /// nothing answers when its parent's callback fails. The GlobalTool's
    /// failure wait never fires, and the child's callbacks watch only their
    /// own process's failures, so only the RPC's kept wait on the run-wide
    /// subscription can end the RPC and let the run finish.
    #[test]
    fn a_forked_childs_pending_rpc_ends_when_its_parent_fails() {
        let (counts, result) = run(FORKED_PEER_FAILS);
        assert!(result.is_err(), "the run must end in the parent's failure");
        assert_eq!(counts.fourth.load(Ordering::SeqCst), 1);
    }
}
