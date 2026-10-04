/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod entry_eintr_tests {
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    fn current_mask() -> libc::sigset_t {
        // SAFETY: initialized writable storage; this query changes no mask.
        unsafe {
            let mut mask = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
                0
            );
            mask
        }
    }

    fn mask_bytes(mask: &libc::sigset_t) -> Vec<u8> {
        // The storage is fully zero-initialized before libc populates it.
        // Preserve the whole saved libc representation, not selected bits.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(mask).cast::<u8>(),
                std::mem::size_of::<libc::sigset_t>(),
            )
            .to_vec()
        }
    }

    struct RestoreMask {
        saved: libc::sigset_t,
        active: bool,
    }

    impl RestoreMask {
        fn for_sigurg() -> Self {
            let restore = Self {
                saved: current_mask(),
                active: true,
            };
            // Only this worker's mask changes. Other blockable signals are
            // excluded from the foreign-interrupt fixture; KVM's reserved64
            // remains independently controlled by the production entry guard.
            unsafe {
                let mut selected = std::mem::zeroed();
                assert_eq!(libc::sigfillset(&mut selected), 0);
                assert_eq!(libc::sigdelset(&mut selected, libc::SIGURG), 0);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, &selected, std::ptr::null_mut()),
                    0
                );
                assert_eq!(libc::sigismember(&current_mask(), libc::SIGURG), 0);
            }
            restore
        }

        fn finish(mut self) {
            assert_eq!(
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved, std::ptr::null_mut())
                },
                0
            );
            self.active = false;
            assert_eq!(mask_bytes(&current_mask()), mask_bytes(&self.saved));
        }
    }

    impl Drop for RestoreMask {
        fn drop(&mut self) {
            if self.active {
                let result = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &self.saved, std::ptr::null_mut())
                };
                if !std::thread::panicking() {
                    assert_eq!(result, 0);
                }
            }
        }
    }

    // The target is usable only while this lease is held by its own live host
    // thread. A sender keeps the same mutex through pthread_kill; withdrawal
    // therefore excludes every later send, including after a release timeout.
    struct TargetLifetime(Arc<Mutex<Option<libc::pthread_t>>>);
    impl Drop for TargetLifetime {
        fn drop(&mut self) {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }
    }

    struct WorkerOwner {
        gate: Arc<crate::entry::EntryGate>,
        release: Option<mpsc::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
        rescued: Arc<AtomicBool>,
    }

    impl WorkerOwner {
        fn join(&mut self) {
            self.release.take().unwrap().send(()).unwrap();
            self.thread.take().unwrap().join().unwrap();
        }
    }

    impl Drop for WorkerOwner {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                self.rescued.store(true, Ordering::SeqCst);
                // Failure-only rescue: a real reserved-signal gate kick stops
                // an in-flight run, while poison also stops setup/wait/retry.
                // Its result is never accepted as the foreign EINTR control.
                let closing = self.gate.try_close();
                self.gate.poison(
                    None,
                    Error::GuestClock("foreign EINTR control rescue".to_owned()),
                );
                drop(closing);
                if let Some(release) = self.release.take() {
                    let _ = release.send(());
                }
                let joined = thread.join();
                if !std::thread::panicking() {
                    joined.unwrap();
                }
            }
        }
    }

    #[test]
    fn raw_public_foreign_sigurg_preserves_eintr_and_allows_fresh_entry() {
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("foreign EINTR control requires /dev/kvm");
        // A busy real-mode guest controlled by the host deadline and actual
        // interrupt. It has no synthetic exit or syscall-return path.
        backend
            .install_real_mode_program(0x1000, &[0xeb, 0xfe])
            .unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::ENABLED);
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let gate = backend.memory.entry_gate();
        let probe = Arc::new(crate::clock::RunProbe::default());
        let target = Arc::new(Mutex::new(None));
        let (entered, entering) = mpsc::channel();
        let hook_target = target.clone();
        probe.before_run(move |probe| {
            probe.arm();
            let pthread = unsafe { libc::pthread_self() };
            assert!(hook_target.lock().unwrap().replace(pthread).is_none());
            entered.send(pthread).unwrap();
        });
        backend.vcpu.set_run_probe(probe.clone());
        let (returned, results) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let worker_target = target.clone();
        let worker = std::thread::spawn(move || {
            let mask = RestoreMask::for_sigurg();
            let selected = mask_bytes(&current_mask());
            let target_lifetime = TargetLifetime(worker_target);
            let outcome = backend.run(|_, _| panic!("busy fixture invoked a syscall"));
            assert_eq!(
                mask_bytes(&current_mask()),
                selected,
                "entry failed to restore its caller mask"
            );
            if returned.send((backend, outcome)).is_err() {
                panic!("controller dropped the real public-loop result");
            }
            // Keep the pthread alive until sending has stopped. Timeout is an
            // actual test failure, and TargetLifetime still excludes late sends.
            let received_release = released.recv_timeout(WAIT);
            drop(target_lifetime);
            mask.finish();
            received_release.expect("controller did not release the returned worker");
        });
        let rescued = Arc::new(AtomicBool::new(false));
        let mut owner = WorkerOwner {
            gate: gate.clone(),
            release: Some(release),
            thread: Some(worker),
            rescued: rescued.clone(),
        };
        let announced = entering
            .recv_timeout(WAIT)
            .expect("public loop did not reach CountedVcpu::run");
        let deadline = Instant::now() + WAIT;
        let mut sends = 0usize;
        let (mut backend, outcome) = loop {
            match results.try_recv() {
                Ok(result) => break result,
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("worker exited without its public result")
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            assert!(
                Instant::now() < deadline,
                "real SIGURG did not interrupt the busy guest"
            );
            // Wait for the actual private RUN dispatch counter, after mask
            // installation. The first signal may still beat kernel entry;
            // keep sending until the real returned EINTR establishes delivery
            // during the ioctl. No signal-count/timing comparator is inferred.
            if probe.untracked_runs.load(Ordering::SeqCst) == 0 {
                std::thread::yield_now();
                continue;
            }
            {
                let lease = target.lock().unwrap();
                let pthread = (*lease).expect("worker withdrew its live target before returning");
                assert_eq!(pthread, announced);
                // Production installed its independent SIGURG handler at
                // backend construction. This is not the reserved64 close kick.
                assert_eq!(unsafe { libc::pthread_kill(pthread, libc::SIGURG) }, 0);
                sends += 1;
            }
            std::thread::yield_now();
        };
        // No further signal is sent after this point. Physically join before
        // moving the stopped backend to a fresh public invocation.
        owner.join();
        assert!(target.lock().unwrap().is_none());
        assert!(!rescued.load(Ordering::SeqCst));
        assert!(sends > 0);
        assert!(matches!(outcome, Err(Error::Kvm(error)) if error.errno() == libc::EINTR));
        assert!(
            gate.pending_failure().is_none(),
            "foreign EINTR poisoned admission"
        );
        assert_eq!(probe.untracked_runs.load(Ordering::SeqCst), 1);
        assert_eq!(probe.tracked_runs.load(Ordering::SeqCst), 0);
        assert_eq!(probe.prepare.mask_installs.load(Ordering::SeqCst), 1);
        assert_eq!(probe.clock_begins.load(Ordering::SeqCst), 0);
        assert_eq!(probe.intervals_created.load(Ordering::SeqCst), 0);
        assert_eq!(probe.shared_fd_accesses.load(Ordering::SeqCst), 0);
        assert_eq!(exits.snapshot().total_exits(), 0);

        let caller_mask = mask_bytes(&current_mask());
        backend.install_real_mode_program(0x1000, &[HLT]).unwrap();
        backend
            .run(|_, _| panic!("finite HLT fixture invoked a syscall"))
            .unwrap();
        assert_eq!(mask_bytes(&current_mask()), caller_mask);
        assert_eq!(probe.untracked_runs.load(Ordering::SeqCst), 2);
        assert_eq!(probe.prepare.mask_installs.load(Ordering::SeqCst), 2);
        assert_eq!(probe.tracked_runs.load(Ordering::SeqCst), 0);
        assert_eq!(probe.clock_begins.load(Ordering::SeqCst), 0);
        assert_eq!(probe.intervals_created.load(Ordering::SeqCst), 0);
        assert_eq!(exits.snapshot().total_exits(), 1);
        assert_eq!(exits.snapshot().count(crate::stats::KvmExitReason::Hlt), 1);
        assert!(gate.pending_failure().is_none());
        assert!(!backend.thread_group.has_worker_handles());
    }
}
