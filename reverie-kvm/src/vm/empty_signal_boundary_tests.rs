/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests so the existing minimal ELF fixture remains private.
mod empty_signal_boundary_tests {
    use std::sync::atomic::AtomicU64;

    use reverie::BackendSignalControl;
    use reverie::BackendSignalControlMode;
    use reverie::SignalDeliveryPermit;
    use reverie::SignalTaskIdentity;

    use super::*;

    /// The Tool keeps the default and is asked at every boundary.
    const ASKED: u8 = 0;
    /// The Tool lets the backend skip boundaries with nothing to deliver.
    const SKIPPED: u8 = 1;
    /// The Tool keeps the default and publishes SIGALRM from inside its
    /// first authorization, which a skipped boundary would never see.
    const PUBLISHES_WHEN_ASKED: u8 = 2;
    /// The Tool keeps the default and never authorizes a delivery.
    const DECLINES: u8 = 3;

    #[derive(Default)]
    struct BoundaryGlobal {
        mode: u8,
        control: Mutex<Option<BackendSignalControl>>,
        authorized: AtomicU64,
        permits: AtomicU64,
        receipts: AtomicU64,
        /// For each receipt, how many ordinary return boundaries the thread
        /// had entered when it arrived.
        receipt_boundaries: Mutex<Vec<u64>>,
    }

    fn alarm(pid: Pid) -> reverie::SignalEvent {
        let mut info = [0; reverie::SIGNAL_INFO_SIZE];
        info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
        reverie::SignalEvent::new(libc::SIGALRM, info, reverie::SignalTarget::Process { pid })
            .unwrap()
    }

    #[reverie::global_tool]
    impl GlobalTool for BoundaryGlobal {
        type Request = ();
        type Response = ();
        type Config = u8;

        async fn init_global_state(mode: &u8) -> Self {
            Self {
                mode: *mode,
                ..Self::default()
            }
        }

        async fn receive_rpc(&self, _from: Pid, _: ()) {}

        fn install_backend_signal_control(
            &self,
            control: Option<BackendSignalControl>,
        ) -> std::result::Result<BackendSignalControlMode, reverie::Error> {
            *self.control.lock().unwrap() =
                Some(control.ok_or(reverie::syscalls::Errno::ENOSYS)?);
            Ok(BackendSignalControlMode::ToolControlled)
        }

        fn skip_empty_signal_boundaries(&self) -> bool {
            self.mode == SKIPPED
        }

        fn authorize_backend_signal_boundary(
            &self,
            task: SignalTaskIdentity,
        ) -> std::result::Result<Option<SignalDeliveryPermit>, reverie::Error> {
            let first = self.authorized.fetch_add(1, Ordering::SeqCst) == 0;
            if self.mode == DECLINES {
                return Ok(None);
            }
            let control = self.control.lock().unwrap().clone().unwrap();
            if self.mode == PUBLISHES_WHEN_ASKED && first {
                let published = control
                    .process
                    .publish_alarm(task.process, alarm(task.process.tgid));
                assert!(
                    matches!(
                        published,
                        reverie::ProcessSignalPublicationResult::Committed(_)
                    ),
                    "{published:?}"
                );
            }
            if !control
                .process
                .signal_recipients(task.process, libc::SIGALRM)?
                .into_iter()
                .any(|recipient| recipient.task == task)
            {
                return Ok(None);
            }
            let permit = SignalDeliveryPermit {
                task,
                sequence: self.permits.fetch_add(1, Ordering::SeqCst) + 1,
                site: None,
            };
            control.process.reserve_delivery(permit)?;
            Ok(Some(permit))
        }

        async fn on_backend_signal_boundary(
            &self,
            _receipt: reverie::SignalBoundaryReceipt,
        ) -> std::result::Result<(), reverie::Error> {
            self.receipts.fetch_add(1, Ordering::SeqCst);
            self.receipt_boundaries
                .lock()
                .unwrap()
                .push(crate::runtime::signal_return_observation::return_boundaries());
            Ok(())
        }
    }

    #[derive(Default)]
    struct BoundaryTool;

    #[reverie::tool]
    impl Tool for BoundaryTool {
        type GlobalState = BoundaryGlobal;
        type ThreadState = ();
    }

    fn run(mode: u8, code: &[u8]) -> (BoundaryGlobal, i32) {
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("empty signal boundary test requires /dev/kvm");
        backend
            .install_static_elf(&minimal_test_elf(code), "/bin/empty-signal-boundary")
            .unwrap();
        let (global, status, _, _) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<BoundaryTool>(mode, true))
                .unwrap();
        (global, status)
    }

    const GETPID: [u8; 7] = [0xb8, 39, 0, 0, 0, 0x0f, 0x05];
    const EXIT_ZERO: [u8; 9] = [0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];

    fn three_getpids_then_exit() -> Vec<u8> {
        [&GETPID[..], &GETPID, &GETPID, &EXIT_ZERO].concat()
    }

    /// The skip is the Tool's choice. A Tool that keeps the default is asked
    /// at every syscall return; one that opts in is not asked at boundaries
    /// with nothing to deliver, and the guest's result is the same.
    #[test]
    fn empty_boundaries_are_skipped_only_for_a_tool_that_opts_in() {
        let (asked, status) = run(ASKED, &three_getpids_then_exit());
        assert_eq!(status, 0);
        assert!(
            asked.authorized.load(Ordering::SeqCst) >= 3,
            "every getpid return must be authorized: {}",
            asked.authorized.load(Ordering::SeqCst)
        );
        assert_eq!(asked.permits.load(Ordering::SeqCst), 0);

        let (skipped, status) = run(SKIPPED, &three_getpids_then_exit());
        assert_eq!(status, 0);
        assert_eq!(skipped.authorized.load(Ordering::SeqCst), 0);
        assert_eq!(skipped.receipts.load(Ordering::SeqCst), 0);
    }

    /// A Tool that keeps the default may publish from inside authorization,
    /// and that signal is still delivered at the same boundary.
    #[test]
    fn a_tool_that_publishes_while_authorizing_is_still_asked() {
        let (global, status) = run(PUBLISHES_WHEN_ASKED, &three_getpids_then_exit());
        assert_eq!(status, 128 + libc::SIGALRM);
        assert_eq!(global.authorized.load(Ordering::SeqCst), 1);
        assert_eq!(global.permits.load(Ordering::SeqCst), 1);
        assert_eq!(global.receipts.load(Ordering::SeqCst), 1);
    }

    /// With the skip enabled, a boundary with a deliverable signal still takes
    /// the full path: the guest's own kill(getpid(), SIGALRM) is authorized
    /// and delivered at that syscall's return.
    #[test]
    fn an_opted_in_tool_is_asked_when_a_signal_is_pending() {
        // getpid; mov edi, eax; mov esi, SIGALRM; mov eax, SYS_kill; syscall;
        // then exit(0), which the default SIGALRM action must preempt.
        let code = [
            &GETPID[..],
            &[0x89, 0xc7],
            &[0xbe, libc::SIGALRM as u8, 0, 0, 0],
            &[0xb8, 62, 0, 0, 0, 0x0f, 0x05],
            &EXIT_ZERO,
        ]
        .concat();
        let (global, status) = run(SKIPPED, &code);
        assert_eq!(status, 128 + libc::SIGALRM);
        assert_eq!(global.authorized.load(Ordering::SeqCst), 1);
        assert_eq!(global.permits.load(Ordering::SeqCst), 1);
        assert_eq!(global.receipts.load(Ordering::SeqCst), 1);
    }

    // The ordinary syscall-return boundary runs its first selection
    // iteration's synchronous start (and, when it selects nothing, the exit
    // test) without building the selection future, and finishes a boundary
    // with no owned permit without building the receipt future. The tests
    // below run each guest twice: on that synchronous path, and on the full
    // path, which is the code as it was before (`Scope::new(true, ..)`), and
    // compare every decision the Tool and the guest can see.

    use crate::executor::ElfExecutor;
    use crate::runtime::signal_return_observation::Hook;
    use crate::runtime::signal_return_observation::HookPoint;
    use crate::runtime::signal_return_observation::Scope;

    /// Everything a Tool or the guest can observe of one run, plus which path
    /// the ordinary returns took.
    #[derive(Debug)]
    struct Observed {
        status: std::result::Result<i32, String>,
        authorized: Option<u64>,
        permits: Option<u64>,
        receipts: Option<u64>,
        receipt_boundaries: Option<Vec<u64>>,
        /// The ordinary return boundary at which a signal first acted.
        first_signal_at: Option<u64>,
        sync_returns: u64,
        full_returns: u64,
        settled_injections: u64,
        unsettled_injections: u64,
    }

    impl Observed {
        /// The decisions both paths must agree on.
        fn decisions(&self) -> impl PartialEq + std::fmt::Debug + '_ {
            (
                &self.status,
                self.authorized,
                self.permits,
                self.receipts,
                &self.receipt_boundaries,
                self.first_signal_at,
            )
        }
    }

    fn observe(mode: u8, code: &[u8], full_path: bool, hook: Option<Hook>) -> Observed {
        let scope = Scope::new(full_path, hook);
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("empty signal boundary test requires /dev/kvm");
        backend
            .install_static_elf(&minimal_test_elf(code), "/bin/empty-signal-boundary")
            .unwrap();
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<BoundaryTool>(mode, true));
        let (status, global) = match result {
            Ok((global, status, _, _)) => (Ok(status), Some(global)),
            Err(error) => (Err(error.to_string()), None),
        };
        let count = |field: fn(&BoundaryGlobal) -> &AtomicU64| {
            global
                .as_ref()
                .map(|global| field(global).load(Ordering::SeqCst))
        };
        Observed {
            status,
            authorized: count(|global| &global.authorized),
            permits: count(|global| &global.permits),
            receipts: count(|global| &global.receipts),
            receipt_boundaries: global
                .as_ref()
                .map(|global| global.receipt_boundaries.lock().unwrap().clone()),
            first_signal_at: scope.first_signal_at(),
            sync_returns: scope.sync_returns(),
            full_returns: scope.full_returns(),
            settled_injections: scope.settled_injections(),
            unsettled_injections: scope.unsettled_injections(),
        }
    }

    /// Runs `code` on both paths, asserts that every decision agrees, and
    /// returns (synchronous, full).
    fn both_paths(
        mode: u8,
        code: &[u8],
        hook: impl Fn() -> Option<Hook>,
    ) -> (Observed, Observed) {
        let fast = observe(mode, code, false, hook());
        let full = observe(mode, code, true, hook());
        assert_eq!(fast.decisions(), full.decisions(), "{fast:#?}\n{full:#?}");
        assert_eq!(full.sync_returns, 0, "{full:#?}");
        assert_eq!(full.settled_injections, 0, "{full:#?}");
        (fast, full)
    }

    /// A hook that publishes one process-directed SIGALRM, as Detcore does
    /// when a guest timer expires, the first time it reaches `at`.
    fn publish_alarm_once(at: HookPoint) -> Option<Hook> {
        let mut published = false;
        Some(Box::new(move |point: HookPoint, executor: &ElfExecutor| {
            if point != at || published {
                return;
            }
            published = true;
            let task = executor.signal_task_identity().unwrap();
            let outcome = executor
                .backend_signal_control()
                .process
                .publish_alarm(task.process, alarm(task.process.tgid));
            assert!(
                matches!(outcome, reverie::ProcessSignalPublicationResult::Committed(_)),
                "{outcome:?}"
            );
        }))
    }

    /// getpid; kill(pid, SIGALRM); exit(0).
    fn kill_self_with_alarm() -> Vec<u8> {
        [
            &GETPID[..],
            &[0x89, 0xc7],
            &[0xbe, libc::SIGALRM as u8, 0, 0, 0],
            &[0xb8, 62, 0, 0, 0, 0x0f, 0x05],
            &EXIT_ZERO,
        ]
        .concat()
    }

    /// With nothing to deliver, every ordinary return finishes synchronously,
    /// for a Tool that lets the backend skip (no Tool call) and for one that
    /// keeps the default (asked and declining); the full path builds the
    /// selection future at every return. Both make the same decisions.
    #[test]
    fn returns_with_nothing_to_deliver_build_no_future() {
        for mode in [SKIPPED, ASKED] {
            let (fast, full) = both_paths(mode, &three_getpids_then_exit(), || None);
            assert_eq!(fast.status, Ok(0));
            assert_eq!(fast.authorized, Some(if mode == SKIPPED { 0 } else { 3 }));
            assert_eq!((fast.sync_returns, fast.full_returns), (3, 0), "{fast:#?}");
            assert_eq!(full.full_returns, 3, "{full:#?}");
            // Injections with no signal effects skip the flush future.
            assert_eq!(fast.unsettled_injections, 0, "{fast:#?}");
            assert_eq!(
                fast.settled_injections, full.unsettled_injections,
                "{fast:#?}\n{full:#?}"
            );
        }
    }

    /// A pending, unblocked signal is authorized and delivered at the return
    /// of the kill that sent it, on both paths, with one receipt.
    #[test]
    fn a_pending_signal_is_delivered_at_the_same_boundary_on_both_paths() {
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &kill_self_with_alarm(), || None);
            assert_eq!(fast.status, Ok(128 + libc::SIGALRM));
            assert_eq!(fast.first_signal_at, Some(2));
            assert_eq!(fast.permits, Some(1));
            assert_eq!(fast.receipts, Some(1));
            assert_eq!(fast.sync_returns, 1, "{fast:#?}");
        }
    }

    /// A caught signal runs its handler at the return of the kill that sent
    /// it, and its receipt arrives at that same boundary, on both paths; the
    /// guest then returns through rt_sigreturn and exits 0.
    #[test]
    fn a_caught_signal_is_receipted_at_its_boundary_on_both_paths() {
        const LOAD_ADDRESS: u32 = 0x20_0000;
        let mut code = Vec::new();
        // sub rsp, 64; [rsp+0..32] = { handler, SA_RESTORER, restorer, 0 },
        // with the two addresses patched in below.
        code.extend([0x48, 0x83, 0xec, 0x40]);
        let handler_at = code.len() + 4;
        code.extend([0x48, 0xc7, 0x04, 0x24, 0, 0, 0, 0]);
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x08]);
        code.extend((crate::signal::SA_RESTORER as u32).to_le_bytes());
        let restorer_at = code.len() + 5;
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x10, 0, 0, 0, 0]);
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0]);
        // rt_sigaction(SIGALRM, rsp, NULL, 8)
        code.extend([0xbf, libc::SIGALRM as u8, 0, 0, 0, 0x48, 0x89, 0xe6, 0x31, 0xd2]);
        code.extend([0x41, 0xba, 8, 0, 0, 0, 0xb8, 13, 0, 0, 0, 0x0f, 0x05]);
        // getpid; kill(pid, SIGALRM); getpid; exit(0)
        code.extend(GETPID);
        code.extend([0x89, 0xc7, 0xbe, libc::SIGALRM as u8, 0, 0, 0]);
        code.extend([0xb8, 62, 0, 0, 0, 0x0f, 0x05]);
        code.extend(GETPID);
        code.extend(EXIT_ZERO);
        // handler: ret (to the restorer)
        let handler = LOAD_ADDRESS + code.len() as u32;
        code.push(0xc3);
        // restorer: rt_sigreturn
        let restorer = LOAD_ADDRESS + code.len() as u32;
        code.extend([0xb8, 15, 0, 0, 0, 0x0f, 0x05]);
        code[handler_at..handler_at + 4].copy_from_slice(&handler.to_le_bytes());
        code[restorer_at..restorer_at + 4].copy_from_slice(&restorer.to_le_bytes());
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &code, || None);
            assert_eq!(fast.status, Ok(0), "{fast:#?}");
            assert_eq!(fast.first_signal_at, Some(3), "{fast:#?}");
            assert_eq!(fast.permits, Some(1));
            assert_eq!(fast.receipt_boundaries, Some(vec![3]), "{fast:#?}");
        }
    }

    /// A blocked pending signal waits on both paths, and is delivered at the
    /// return of the rt_sigprocmask that unblocks it.
    #[test]
    fn a_masked_signal_waits_for_the_unmask_on_both_paths() {
        // push SIGALRM's bit; block it; getpid; kill(pid, SIGALRM); getpid;
        // unblock it; exit(0).
        let set_on_stack: &[u8] = &[0x68, 0x00, 0x20, 0x00, 0x00];
        let sigprocmask = |how: u8| -> Vec<u8> {
            [
                &[0x48, 0x89, 0xe6][..],
                &[0xbf, how, 0, 0, 0],
                &[0x31, 0xd2],
                &[0x41, 0xba, 8, 0, 0, 0],
                &[0xb8, 14, 0, 0, 0, 0x0f, 0x05],
            ]
            .concat()
        };
        let code = [
            set_on_stack,
            &sigprocmask(libc::SIG_BLOCK as u8),
            &GETPID,
            &[0x89, 0xc7],
            &[0xbe, libc::SIGALRM as u8, 0, 0, 0],
            &[0xb8, 62, 0, 0, 0, 0x0f, 0x05],
            &GETPID,
            &sigprocmask(libc::SIG_UNBLOCK as u8),
            &EXIT_ZERO,
        ]
        .concat();
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &code, || None);
            assert_eq!(fast.status, Ok(128 + libc::SIGALRM));
            assert_eq!(fast.first_signal_at, Some(5));
            assert_eq!(fast.permits, Some(1));
            assert_eq!(fast.receipts, Some(1));
        }
    }

    /// A Tool that publishes from inside its authorization still has that
    /// signal delivered at the same boundary on both paths.
    #[test]
    fn a_tool_that_publishes_while_authorizing_decides_the_same_on_both_paths() {
        let (fast, _) = both_paths(PUBLISHES_WHEN_ASKED, &three_getpids_then_exit(), || None);
        assert_eq!(fast.status, Ok(128 + libc::SIGALRM));
        assert_eq!(fast.first_signal_at, Some(1));
        assert_eq!(fast.authorized, Some(1));
        assert_eq!(fast.receipts, Some(1));
    }

    /// A timer signal published after a Tool declined, but before the exit
    /// test, is seen by that exit test and delivered at this boundary on both
    /// paths: the synchronous path resumes the selection loop at its second
    /// iteration, as the full path's loop continues.
    #[test]
    fn an_alarm_after_a_declined_start_is_delivered_at_this_boundary_on_both_paths() {
        let (fast, _) = both_paths(ASKED, &three_getpids_then_exit(), || {
            publish_alarm_once(HookPoint::AfterNothingSelected)
        });
        assert_eq!(fast.status, Ok(128 + libc::SIGALRM));
        assert_eq!(fast.first_signal_at, Some(1));
        assert_eq!(fast.authorized, Some(2));
        assert_eq!(fast.receipts, Some(1));
        assert_eq!((fast.sync_returns, fast.full_returns), (0, 1), "{fast:#?}");
    }

    /// A timer signal published after a skipped start, but before the exit
    /// test, is seen by that exit test and delivered at this boundary on both
    /// paths: the synchronous path rechecks, as the full path's loop does.
    #[test]
    fn an_alarm_after_a_skipped_start_is_delivered_at_this_boundary_on_both_paths() {
        let (fast, _) = both_paths(SKIPPED, &three_getpids_then_exit(), || {
            publish_alarm_once(HookPoint::AfterNothingSelected)
        });
        assert_eq!(fast.status, Ok(128 + libc::SIGALRM));
        assert_eq!(fast.first_signal_at, Some(1));
        assert_eq!(fast.authorized, Some(1));
        assert_eq!(fast.receipts, Some(1));
        assert_eq!((fast.sync_returns, fast.full_returns), (0, 1), "{fast:#?}");
    }

    /// The same late publication when the guest's next call is exit: the
    /// signal must still end the guest at the getpid boundary (status 142)
    /// on both paths, not be outrun by the exit, which skips selection.
    #[test]
    fn an_alarm_after_a_skipped_start_still_beats_an_immediate_exit() {
        let code = [&GETPID[..], &EXIT_ZERO].concat();
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &code, || {
                publish_alarm_once(HookPoint::AfterNothingSelected)
            });
            assert_eq!(fast.status, Ok(128 + libc::SIGALRM), "{fast:#?}");
            assert_eq!(fast.first_signal_at, Some(1), "{fast:#?}");
        }
    }

    /// A Tool that never authorizes while a signal stays eligible exhausts
    /// the boundary after the same 64 selection iterations on both paths:
    /// the synchronous start counts as the first.
    #[test]
    fn a_declining_tool_exhausts_the_same_iteration_bound_on_both_paths() {
        let declined = std::rc::Rc::new(std::cell::Cell::new(0_u32));
        let hook = || -> Option<Hook> {
            let declined = declined.clone();
            Some(Box::new(move |point: HookPoint, _: &ElfExecutor| {
                if point == HookPoint::AfterNothingSelected {
                    declined.set(declined.get() + 1);
                }
            }))
        };
        let fast = observe(DECLINES, &kill_self_with_alarm(), false, hook());
        let fast_declined = declined.replace(0);
        let full = observe(DECLINES, &kill_self_with_alarm(), true, hook());
        let full_declined = declined.replace(0);
        for run in [&fast, &full] {
            assert!(
                matches!(&run.status, Err(message) if message.contains("exhausted one return boundary")),
                "{run:#?}"
            );
        }
        // One decline at getpid's return, then 64 at kill's.
        assert_eq!((fast_declined, full_declined), (65, 65));
    }

    /// The guest program for the mask tests: block `blocked`; if `kill`,
    /// kill(getpid(), SIGALRM); pselect6(0, NULL, NULL, NULL, {0, 0},
    /// {&temporary, 8}); then read its mask and exit with bit `bit` of it.
    fn temporary_mask_program(blocked: u32, kill: bool, temporary: u32, bit: u8) -> Vec<u8> {
        let mut code = Vec::new();
        // sub rsp, 64
        code.extend([0x48, 0x83, 0xec, 0x40]);
        // [rsp] = blocked; [rsp+8] = temporary; [rsp+16..32] = {0, 0}
        code.extend([0x48, 0xc7, 0x04, 0x24]);
        code.extend(blocked.to_le_bytes());
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x08]);
        code.extend(temporary.to_le_bytes());
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x10, 0, 0, 0, 0]);
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0]);
        // [rsp+32] = rsp+8; [rsp+40] = 8
        code.extend([0x48, 0x8d, 0x44, 0x24, 0x08]);
        code.extend([0x48, 0x89, 0x44, 0x24, 0x20]);
        code.extend([0x48, 0xc7, 0x44, 0x24, 0x28, 8, 0, 0, 0]);
        // rt_sigprocmask(SIG_BLOCK, rsp, NULL, 8)
        code.extend([0x31, 0xff, 0x48, 0x89, 0xe6, 0x31, 0xd2]);
        code.extend([0x41, 0xba, 8, 0, 0, 0, 0xb8, 14, 0, 0, 0, 0x0f, 0x05]);
        if kill {
            code.extend(GETPID);
            code.extend([0x89, 0xc7, 0xbe, libc::SIGALRM as u8, 0, 0, 0]);
            code.extend([0xb8, 62, 0, 0, 0, 0x0f, 0x05]);
        }
        // pselect6(0, NULL, NULL, NULL, rsp+16, rsp+32)
        code.extend([0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2]);
        code.extend([0x4c, 0x8d, 0x44, 0x24, 0x10, 0x4c, 0x8d, 0x4c, 0x24, 0x20]);
        code.extend([0xb8, 0x0e, 0x01, 0, 0, 0x0f, 0x05]);
        // rt_sigprocmask(SIG_BLOCK, NULL, rsp+48, 8)
        code.extend([0x31, 0xff, 0x31, 0xf6, 0x48, 0x8d, 0x54, 0x24, 0x30]);
        code.extend([0x41, 0xba, 8, 0, 0, 0, 0xb8, 14, 0, 0, 0, 0x0f, 0x05]);
        // exit(([rsp+48] >> bit) & 1)
        code.extend([0x48, 0x8b, 0x7c, 0x24, 0x30, 0x48, 0xc1, 0xef, bit]);
        code.extend([0x83, 0xe7, 0x01, 0xb8, 60, 0, 0, 0, 0x0f, 0x05]);
        code
    }

    const ALARM_BIT: u32 = 1 << (libc::SIGALRM - 1);
    const USR1_BIT: u32 = 1 << (libc::SIGUSR1 - 1);

    /// A masked pselect6 that finds nothing leaves no temporary mask (Linux's
    /// poll_select_finish restores it before returning 0), so the skipped
    /// boundary has no saved mask to restore; the guest sees its own mask on
    /// both paths.
    #[test]
    fn a_masked_pselect6_with_nothing_pending_keeps_the_mask_on_both_paths() {
        let code = temporary_mask_program(0, false, USR1_BIT, (libc::SIGUSR1 - 1) as u8);
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &code, || None);
            assert_eq!(fast.status, Ok(0), "{fast:#?}");
            assert_eq!(fast.first_signal_at, None);
        }
    }

    /// A skipped boundary that has a saved mask still restores it. The
    /// guest blocks SIGALRM and SIGUSR1, makes SIGALRM pending, and calls a
    /// pselect6 whose empty temporary mask lets SIGALRM end it with EINTR,
    /// saving the own mask. A hook then blocks SIGALRM again before the
    /// boundary starts, as a Tool's injected rt_sigprocmask could, so the
    /// boundary is empty but must still put the saved mask back: the guest
    /// then reads SIGUSR1 blocked (exit 1), on both paths.
    #[test]
    fn a_skipped_boundary_restores_a_saved_mask_on_both_paths() {
        let code = temporary_mask_program(
            ALARM_BIT | USR1_BIT,
            true,
            0,
            (libc::SIGUSR1 - 1) as u8,
        );
        let hook = || -> Option<Hook> {
            Some(Box::new(|point: HookPoint, executor: &ElfExecutor| {
                if point == HookPoint::BeforeSelectionStart {
                    executor.block_signal_for_test(libc::SIGALRM);
                }
            }))
        };
        for mode in [SKIPPED, ASKED] {
            let (fast, _) = both_paths(mode, &code, hook);
            assert_eq!(fast.status, Ok(1), "{fast:#?}");
            assert_eq!(fast.first_signal_at, None);
            assert_eq!(fast.full_returns, 0, "{fast:#?}");
        }
    }

    /// Future sizes at their call sites in this test build (debug profile,
    /// this file's Tool), recorded for the review; asserted only to be
    /// nonzero so that a missing record fails.
    #[test]
    fn signal_boundary_future_sizes() {
        use crate::runtime::signal_future_sizes as sizes;
        both_paths(SKIPPED, &kill_self_with_alarm(), || None);
        both_paths(ASKED, &three_getpids_then_exit(), || None);
        let read = |slot: &std::sync::atomic::AtomicUsize| slot.load(Ordering::Relaxed);
        let measured = [
            ("run_loop", read(&sizes::RUN_LOOP)),
            ("filter_one", read(&sizes::FILTER_ONE)),
            ("filter_next", read(&sizes::FILTER_NEXT)),
            ("finish_signal_boundary", read(&sizes::FINISH_BOUNDARY)),
            ("finish_signal_boundary_with_permit", read(&sizes::FINISH_WITH_PERMIT)),
            ("complete_signal_effects", read(&sizes::COMPLETE_EFFECTS)),
        ];
        eprintln!("signal boundary future sizes: {measured:?}");
        for (name, size) in measured {
            assert_ne!(size, 0, "{name} was never built");
        }
    }
}
