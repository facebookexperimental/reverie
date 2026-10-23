/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod entry_race_tests {
    use std::sync::atomic::AtomicUsize;
    use std::task::Context;

    use super::*;

    fn mask_bits() -> u64 {
        // SAFETY: the query writes initialized storage and does not change the
        // calling thread's mask. Every queried Linux signal number is valid.
        unsafe {
            let mut mask: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            (1..=64).fold(0, |bits, signal| {
                let present = libc::sigismember(&mask, signal);
                assert!(matches!(present, 0 | 1));
                bits | ((present as u64) << (signal - 1))
            })
        }
    }

    struct RestoreMask(libc::sigset_t);

    impl RestoreMask {
        fn install(reserved_blocked: bool) -> Self {
            // SAFETY: both sets are live and initialized. This changes only
            // the current test thread, and Drop restores its original mask.
            unsafe {
                let mut saved = std::mem::zeroed();
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut saved),
                    0
                );
                let restore = Self(saved);
                let mut selected = saved;
                assert_eq!(libc::sigaddset(&mut selected, libc::SIGUSR2), 0);
                assert_eq!(
                    if reserved_blocked {
                        libc::sigaddset(&mut selected, 64)
                    } else {
                        libc::sigdelset(&mut selected, 64)
                    },
                    0
                );
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, &selected, std::ptr::null_mut()),
                    0
                );
                restore
            }
        }
    }

    impl Drop for RestoreMask {
        fn drop(&mut self) {
            // SAFETY: this is the same thread and the original complete mask.
            let result =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
            assert_eq!(result, 0);
        }
    }

    type CloseFuture = Pin<
        Box<
            dyn Future<
                    Output = std::result::Result<
                        crate::entry::Closed,
                        Arc<crate::entry::PendingFailure>,
                    >,
                > + Send,
        >,
    >;

    fn count(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }

    fn assert_no_entry(probe: &crate::clock::RunProbe) {
        assert_eq!(count(&probe.shared_fd_accesses), 0);
        assert_eq!(count(&probe.prepare.activations), 0);
        assert_eq!(count(&probe.untracked_runs), 0);
        assert_eq!(count(&probe.tracked_runs), 0);
        assert_eq!(count(&probe.clock_begins), 0);
        assert_eq!(count(&probe.intervals_created), 0);
    }

    fn late_close_case(tracked: bool) {
        for reserved_blocked in [false, true] {
            let original_mask = mask_bits();
            let restore = RestoreMask::install(reserved_blocked);
            let before = mask_bits();
            let mut backend =
                KvmBackend::new(0x10000).expect("final admission control requires /dev/kvm");
            // Real-mode inc byte ptr [0x2000]; hlt. The successful neighbor
            // must execute this actual memory effect exactly once.
            backend
                .install_real_mode_program(0x1000, &[0xfe, 0x06, 0x00, 0x20, HLT])
                .unwrap();
            backend.memory.write_raw(0x2000, &[0]).unwrap();
            if tracked {
                backend.vcpu.track_clock().unwrap();
            }
            let gate = backend.memory.entry_gate();
            let probe = Arc::new(crate::clock::RunProbe::default());
            backend.vcpu.set_run_probe(probe.clone());
            let pending: Arc<Mutex<Option<CloseFuture>>> = Arc::new(Mutex::new(None));
            let hook_pending = pending.clone();
            let hook_gate = Arc::downgrade(&gate);
            let hook_calls = Arc::new(AtomicUsize::new(0));
            let calls = hook_calls.clone();
            probe.prepare.before_activate(move || {
                assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
                assert_eq!(mask_bits(), before & !(1_u64 << 63));
                let closing = hook_gate
                    .upgrade()
                    .expect("the controller retains the gate through entry")
                    .try_close()
                    .unwrap()
                    .unwrap();
                let mut finish: CloseFuture = Box::pin(closing.finish());
                assert!(
                    finish
                        .as_mut()
                        .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
                        .is_pending(),
                    "Setup remains counted until the actual entry cleanup acknowledges it"
                );
                assert!(hook_pending.lock().unwrap().replace(finish).is_none());
            });
            probe.arm();
            assert!(backend.vcpu.run().unwrap().is_none());
            assert_eq!(count(&hook_calls), 1);
            assert_no_entry(&probe);
            // This was a final-activation refusal, not the earlier try_enter
            // refusal counted by closed_admissions.
            assert_eq!(count(&probe.prepare.closed_admissions), 0);
            // Signal 64 stays unblocked after the first entry setup.
            assert_eq!(mask_bits(), before & !(1_u64 << 63));
            let closing = pending.lock().unwrap().take().unwrap();
            let closed = closing
                .now_or_never()
                .expect("actual cleanup must release the close")
                .unwrap();
            assert_no_entry(&probe);
            drop(closed);
            let mut value = [0xff];
            backend.memory.read_raw(0x2000, &mut value).unwrap();
            assert_eq!(value, [0]);

            // A fresh close must still refuse entry after the first close was
            // reopened. The prior acknowledgement cannot admit this generation.
            let closed = gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .unwrap()
                .unwrap();
            assert!(backend.vcpu.run().unwrap().is_none());
            assert_no_entry(&probe);
            assert_eq!(count(&probe.prepare.closed_admissions), 1);
            // Signal 64 stays unblocked after the first entry setup.
            assert_eq!(mask_bits(), before & !(1_u64 << 63));
            drop(closed);
            backend.memory.read_raw(0x2000, &mut value).unwrap();
            assert_eq!(value, [0]);
            assert!(matches!(backend.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
            backend.memory.read_raw(0x2000, &mut value).unwrap();
            assert_eq!(value, [1]);
            assert_eq!(count(&hook_calls), 1);
            assert_eq!(count(&probe.shared_fd_accesses), 0);
            assert_eq!(count(&probe.prepare.activations), 1);
            assert_eq!(count(&probe.untracked_runs), usize::from(!tracked));
            assert_eq!(count(&probe.tracked_runs), usize::from(tracked));
            assert_eq!(count(&probe.clock_begins), usize::from(tracked));
            assert_eq!(count(&probe.intervals_created), usize::from(tracked));
            // Signal 64 stays unblocked after the first entry setup.
            assert_eq!(mask_bits(), before & !(1_u64 << 63));
            drop(backend);
            drop(restore);
            assert_eq!(mask_bits(), original_mask);
        }
    }

    #[test]
    fn untracked_final_activation_close_restores_mask_and_rechecks_next_close() {
        late_close_case(false);
    }

    #[test]
    fn tracked_final_activation_close_restores_mask_and_rechecks_next_close() {
        late_close_case(true);
    }

    /// A boundary capture whose first attempt finds the gate closed must
    /// subscribe before rechecking and then park, and reopening the gate
    /// must wake it. The first attempt takes no subscription, so this is the
    /// retry boundary: a reopen after the subscribed recheck still wakes it.
    #[test]
    fn a_boundary_capture_on_a_closed_gate_wakes_when_the_gate_reopens() {
        #[derive(Default)]
        struct Wakes(AtomicUsize);
        impl futures::task::ArcWake for Wakes {
            fn wake_by_ref(arc: &Arc<Self>) {
                arc.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut backend =
            KvmBackend::new(0x10000).expect("boundary capture control requires /dev/kvm");
        backend
            .install_syscall(
                0x1000,
                0x2000,
                SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
            )
            .unwrap();
        let gate = backend.memory.entry_gate();
        let closed = gate
            .try_close()
            .unwrap()
            .unwrap()
            .finish()
            .now_or_never()
            .expect("an idle gate closes at once")
            .unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = futures::task::waker(wakes.clone());
        let mut context = Context::from_waker(&waker);
        let mut stop = std::pin::pin!(std::future::pending::<()>());
        let stop: Pin<&mut (dyn Future<Output = ()> + Send)> = stop.as_mut();
        let mut capture = Box::pin(CompletedSyscallBoundary::capture_admitted(
            &mut backend,
            0x2000,
            None,
            stop,
        ));
        assert!(
            capture.as_mut().poll(&mut context).is_pending(),
            "a capture read through a closed gate"
        );
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        drop(closed);
        assert!(
            wakes.0.load(Ordering::SeqCst) > 0,
            "reopening the gate did not wake the parked capture"
        );
        // The woken capture is admitted and runs its read. This vCPU never
        // ran, so the read finds no syscall boundary and refuses with that
        // typed error, which only the admitted read can produce. Pending would
        // mean the wake was lost; RunAborted would mean the stop fired.
        match capture.as_mut().poll(&mut context) {
            std::task::Poll::Ready(Err(Error::UnexpectedVcpuExit(message)))
                if message.starts_with("syscall boundary RIP") => {}
            std::task::Poll::Ready(other) => {
                panic!("capture after reopen: {:?}", other.map(|b| b.is_some()))
            }
            std::task::Poll::Pending => {
                panic!("a woken capture did not read after the gate reopened")
            }
        }
    }
}
