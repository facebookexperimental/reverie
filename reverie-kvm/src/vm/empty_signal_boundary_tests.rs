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

    #[derive(Default)]
    struct BoundaryGlobal {
        mode: u8,
        control: Mutex<Option<BackendSignalControl>>,
        authorized: AtomicU64,
        permits: AtomicU64,
        receipts: AtomicU64,
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
}
