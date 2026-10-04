/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod fatal_quarantine_tests {
    use super::*;

    const NAME: &str = "tracer::tests::fatal_quarantine_tests::ptracer_thread_exit_does_not_reopen_process_admission";
    const CHILD: &str = "REVERIE_FATAL_THREAD_EXIT_CHILD";
    const DEADLINE: &str = "REVERIE_FATAL_THREAD_EXIT_DEADLINE_NS";

    #[tokio::test(flavor = "current_thread")]
    async fn ptracer_thread_exit_does_not_reopen_process_admission() {
        if std::env::var(CHILD).as_deref() != Ok(NAME) {
            // Deliberate TLS-owner retention is process-wide. Keep this case
            // in an exact-name subprocess, never a shared parallel test worker.
            let deadline = fatal_monotonic_ns() + 3_000_000_000;
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, NAME)
                .env(DEADLINE, deadline.to_string())
                .spawn()
                .unwrap();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    eprintln!(
                        "quarantine thread-exit exact child: {status}; remaining_ns={}",
                        deadline.saturating_sub(fatal_monotonic_ns())
                    );
                    assert!(status.success());
                    assert!(fatal_monotonic_ns() < deadline);
                    return;
                }
                if fatal_monotonic_ns() >= deadline {
                    eprintln!("quarantine thread-exit original pre-start3s deadline FAILED");
                    let signal = child.kill();
                    let rescue_deadline = Instant::now() + Duration::from_secs(2);
                    let reaped = loop {
                        let status = child.try_wait().unwrap();
                        if status.is_some() || Instant::now() >= rescue_deadline {
                            break status;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    };
                    panic!(
                        "thread-exit fixture timed out; separate rescue only: signal={signal:?}, reaped={reaped:?}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        assert!(std::env::args().any(|arg| arg == NAME));
        assert!(std::env::args().any(|arg| arg == "--exact"));
        let deadline = std::env::var(DEADLINE).unwrap().parse::<u64>().unwrap();
        let words = FatalWords::new();
        let address = words.0 as usize;
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let control = Arc::new(crate::task::FatalFreezeControl::default());
                crate::task::FATAL_FREEZE_CONTROL.with(|slot| *slot.borrow_mut() = Some(control));
                let tracer = tokio::time::timeout(fatal_remaining(deadline), spawn_fn_with_config::<FatalTool, _>(move || {
                    std::thread::spawn(move || {
                        unsafe { libc::syscall(libc::SYS_getpgid, 0); }
                        unsafe { &*(address as *const std::sync::atomic::AtomicUsize) }.store(1, Ordering::SeqCst);
                    }).join().unwrap();
                }, 1, false)).await.unwrap().unwrap();
                let root = tracer.guest_pid();
                let log = tracer.gref.0.clone();
                let error = tokio::time::timeout(fatal_remaining(deadline), Box::pin(tracer.wait())).await.unwrap().err().expect("actual freeze refusal required");
                assert!(matches!(&error, Error::Tool(error) if error.downcast_ref::<CleanupUnconfirmed>().is_some()));
                // The pending owner stays in this thread's actual quarantine.
                // Returning drops the runtime and then runs TLS destructors.
                (error, root, log)
            })
        });
        while !worker.is_finished() {
            assert!(
                fatal_monotonic_ns() < deadline,
                "ptracer thread did not return its real pending diagnostic"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let (error, root, log) = worker
            .join()
            .expect("ptracer thread or TLS destructor panicked");
        let Error::Tool(error) = error else {
            panic!("typed pending diagnostic lost");
        };
        let pending = error.downcast_ref::<CleanupUnconfirmed>().unwrap();
        assert!(
            matches!(pending.primary(), Error::Tool(primary) if primary.downcast_ref::<NonleaderFailure>().is_some())
        );
        assert_eq!(pending.origin().phase, "ptrace syscall callback");
        assert!(pending.recovery_key() > 0);
        assert!(matches!(
            pending.take_cleanup::<FatalLog, ExitStatus>(),
            Err(CleanupLookupError::WrongThread)
        ));
        let state_owners = Arc::strong_count(&log);
        let counter = *UNCONFIRMED_QUARANTINES.lock().unwrap();
        eprintln!(
            "quarantine after actual ptracer thread exit: root={root}, root_proc_present={}, retained={counter}, state_owners={state_owners}, continuation={}, original={:?}, events={:?}",
            std::path::Path::new(&format!("/proc/{root}")).exists(),
            words.read(0),
            pending.primary(),
            log.lock().unwrap()
        );
        assert_eq!(counter, 1, "TLS exit falsely reported completed cleanup");
        assert!(
            state_owners > 1,
            "TLS exit dropped the quarantined GlobalTool owner"
        );
        assert_eq!(words.read(0), 0);
        drop(error);
        let refused = spawn_fn::<(), _>(|| panic!("post-TLS-refusal guest executed")).await;
        assert!(
            matches!(refused, Err(Error::Tool(error)) if error.downcast_ref::<CleanupAdmissionRefused>().is_some_and(|refusal| refusal.retained() == 1))
        );
        let fresh_thread = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let refused = spawn_fn::<(), _>(|| panic!("cross-thread quarantine bypass executed")).await;
                assert!(matches!(refused, Err(Error::Tool(error)) if error.downcast_ref::<CleanupAdmissionRefused>().is_some_and(|refusal| refusal.retained() == 1)));
            });
        });
        while !fresh_thread.is_finished() {
            assert!(fatal_monotonic_ns() < deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        fresh_thread.join().unwrap();
        assert_eq!(*UNCONFIRMED_QUARANTINES.lock().unwrap(), 1);
        assert!(fatal_monotonic_ns() < deadline);
        // Deliberately no recovery/Complete claim: its required ptracer thread
        // is gone. This child process now exits, releasing retained host state.
    }
}
