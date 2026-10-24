/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod adaptive_wait_tests {
    use super::*;

    async fn cold_owner_refusal_and_cancelled_wait() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let stopped = group_fixture_root(GroupFixtureAttach::Traceme, false).await;
        let terminal = stopped.generation().terminal_cleanup();
        let native = terminal.has_thread_pidfd().unwrap();
        // Obtain a real generic Native stop, which has no explicit owner
        // field. This makes the cold sibling check exercise actual target
        // role authentication rather than a prepopulated controller cell.
        let stopped = if native {
            let running = stopped.step(None).unwrap();
            let (stopped, event) = tokio::time::timeout_at(deadline.into(), running.wait_owned())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
            assert_eq!(event, Event::Signal(Signal::SIGTRAP));
            assert!(
                stopped
                    .generation()
                    .retained_ptracer_thread_guard()
                    .unwrap()
                    .is_none()
            );
            stopped
        } else {
            stopped
        };
        let generation = stopped.generation();
        let tid = stopped.pid();
        let before = terminal.queued_raw_statuses();
        let owner = Arc::new(PtracerWaitOwner::default());
        let sibling = owner.clone();
        let (mut exit, mut adapter) = std::thread::spawn(move || {
            let mut exit = sibling.exit_stopped(&stopped);
            let mut adapter = sibling.wait_owned_stopped(stopped);
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(matches!(
                std::future::Future::poll(std::pin::Pin::new(&mut adapter), &mut cx),
                std::task::Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            assert!(matches!(
                std::future::Future::poll(exit.as_mut(), &mut cx),
                std::task::Poll::Ready(Err(TraceError::Errno(Errno::EPERM)))
            ));
            assert_eq!(sibling.progress(), Err(Errno::EPERM));
            assert!(matches!(
                sibling
                    .with_pending::<()>(Duration::ZERO, |_| panic!("foreign reservation consumed")),
                Err(Error::Errno(Errno::EPERM))
            ));
            assert!(sibling.controller().guard.lock().unwrap().is_none());
            (exit, adapter)
        })
        .join()
        .unwrap();
        assert_eq!(terminal.queued_raw_statuses(), before);
        assert_eq!(*owner.generation.lock().unwrap(), Some(generation.clone()));
        owner.prime_controller().unwrap();
        assert!(
            matches!(
                owner.mode().unwrap(),
                PtracerMode::Native if native
            ) || matches!(owner.mode().unwrap(), PtracerMode::Explicit if !native)
        );
        let guard = owner.controller().guard.lock().unwrap().clone().unwrap();
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(std::pin::Pin::new(&mut adapter), &mut cx),
            std::task::Poll::Pending
        ));
        assert!(matches!(
            std::future::Future::poll(exit.as_mut(), &mut cx),
            std::task::Poll::Pending
        ));
        let before_warm_refusal = terminal.queued_raw_statuses();
        let sibling = owner.clone();
        (exit, adapter) = std::thread::spawn(move || {
            assert!(sibling.controller().guard.lock().unwrap().is_some());
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(matches!(
                std::future::Future::poll(std::pin::Pin::new(&mut adapter), &mut cx),
                std::task::Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            assert!(matches!(
                std::future::Future::poll(exit.as_mut(), &mut cx),
                std::task::Poll::Ready(Err(TraceError::Errno(Errno::EPERM)))
            ));
            assert_eq!(sibling.progress(), Err(Errno::EPERM));
            assert!(matches!(
                sibling.with_pending::<()>(Duration::ZERO, |_| panic!(
                    "warm foreign reservation consumed"
                )),
                Err(Error::Errno(Errno::EPERM))
            ));
            (exit, adapter)
        })
        .join()
        .unwrap();
        assert_eq!(terminal.queued_raw_statuses(), before_warm_refusal);
        assert_eq!(*owner.generation.lock().unwrap(), Some(generation.clone()));
        assert_eq!(guard.check_current(), Ok(()));
        assert!(matches!(
            std::future::Future::poll(std::pin::Pin::new(&mut adapter), &mut cx),
            std::task::Poll::Pending
        ));
        assert!(matches!(
            std::future::Future::poll(exit.as_mut(), &mut cx),
            std::task::Poll::Pending
        ));
        let slot = {
            let retained = owner.waits.lock().unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(
                retained[0].lock().unwrap().as_ref().unwrap().generation(),
                Some(generation.clone())
            );
            Arc::downgrade(&retained[0])
        };
        drop(adapter);
        let retained = slot.upgrade().unwrap();
        assert_eq!(
            Arc::strong_count(&retained),
            2,
            "owner and this readback retain the original cancelled core"
        );
        terminal.request_sigkill().unwrap();
        let stopped = tokio::time::timeout_at(deadline.into(), &mut exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.generation(), generation);
        assert_eq!(stopped.getevent().unwrap(), libc::SIGKILL as i64);
        assert!(!terminal.wait(Duration::ZERO));
        let running = stopped.resume(None).unwrap();
        let actual = tokio::time::timeout_at(
            deadline.into(),
            futures::future::poll_fn(|cx| {
                retained
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .poll_on_ptracer_thread(cx)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            actual.assume_exited(),
            (tid, ExitStatus::Signaled(Signal::SIGKILL, false))
        );
        assert!(matches!(
            retained
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .poll_on_ptracer_thread(&mut cx),
            std::task::Poll::Ready(Err(OwnedWaitError::Completed))
        ));
        let sibling = retained.clone();
        std::thread::spawn(move || {
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            let mut retained = sibling.lock().unwrap();
            let driver = retained.as_mut().unwrap();
            assert!(driver.generation().is_none());
            let actual = driver.poll_on_ptracer_thread(&mut cx);
            if native {
                assert!(matches!(
                    actual,
                    std::task::Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                ));
            } else {
                // The unchanged Explicit driver reports Completed before
                // admission once its sole input has already transferred.
                assert!(matches!(
                    actual,
                    std::task::Poll::Ready(Err(OwnedWaitError::Completed))
                ));
            }
            assert!(driver.generation().is_none());
        })
        .join()
        .unwrap();
        assert!(matches!(
            retained
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .poll_on_ptracer_thread(&mut cx),
            std::task::Poll::Ready(Err(OwnedWaitError::Completed))
        ));
        assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
        );
        assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
        assert_eq!(
            guard.check_current(),
            Ok(()),
            "the early controller survives target retirement"
        );
        drop(running);
        assert_reaped("adaptive original root", tid);
        let weak = Arc::downgrade(&owner);
        drop(exit);
        drop(retained);
        drop(owner);
        assert!(
            weak.upgrade().is_none(),
            "a cancelled driver creates no owner cycle"
        );
        assert!(Instant::now() < deadline);
        println!("ADAPTIVE_COLD_OWNER_AND_CANCELLATION_PASSED native={native}");
        println!("ADAPTIVE_WARM_OWNER_REFUSAL_AND_RECOVERY_PASSED native={native}");
    }

    async fn newborn_inherits_original_controller() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let stopped = group_fixture_root(GroupFixtureAttach::Traceme, true).await;
        let root = stopped.pid();
        let owner = Arc::new(PtracerWaitOwner::default());
        owner.bind_stopped(&stopped);
        owner.prime_controller().unwrap();
        let session = FatalSession::for_test(root);
        session.bind_controller(&owner);
        session.capture_root(&stopped);
        let exit = owner.exit_stopped(&stopped);
        let (stopped, event) = tokio::time::timeout_at(
            deadline.into(),
            owner.wait_running(stopped.resume(None).unwrap()),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        let Event::NewChild(ChildOp::Fork, child) = event else {
            panic!("actual fork event required, got {event:?}");
        };
        let child_tid = child.pid();
        let child_generation = child.generation();
        let child_terminal = child_generation.terminal_cleanup();
        assert_ne!(stopped.generation(), child_generation);
        session.capture_for_group_stop_test(root, ChildOp::Fork, &child);
        let mut newborn = session
            .take_group_stop_newborn_for_test(&child_terminal)
            .unwrap();
        assert_eq!(
            *newborn.waits.generation.lock().unwrap(),
            Some(child_generation.clone())
        );
        assert!(newborn.terminal.same_generation(&child_terminal));
        assert!(Arc::ptr_eq(
            &owner.controller().guard,
            &newborn.waits.controller().guard
        ));
        assert!(!Arc::ptr_eq(&owner, &newborn.waits));
        assert!(newborn.waits.inherited.lock().unwrap().is_empty());
        let before = child_terminal.queued_raw_statuses();
        newborn = std::thread::spawn(move || {
            let waker = futures::task::noop_waker();
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(matches!(
                std::future::Future::poll(newborn.exit.as_mut(), &mut cx),
                std::task::Poll::Ready(Err(TraceError::Errno(Errno::EPERM)))
            ));
            assert_eq!(newborn.waits.progress(), Err(Errno::EPERM));
            assert!(matches!(
                newborn.waits.with_pending::<()>(Duration::ZERO, |_| panic!(
                    "foreign child reservation consumed"
                )),
                Err(Error::Errno(Errno::EPERM))
            ));
            newborn
        })
        .join()
        .unwrap();
        assert_eq!(child_terminal.queued_raw_statuses(), before);
        assert_eq!(
            *newborn.waits.generation.lock().unwrap(),
            Some(child_generation)
        );
        let child_owner = Arc::downgrade(&newborn.waits);
        newborn.signal().unwrap();
        tokio::time::timeout_at(deadline.into(), newborn.reap_owned(&session))
            .await
            .unwrap();
        assert!(child_terminal.wait(deadline.saturating_duration_since(Instant::now())));
        assert_eq!(
            child_terminal.observed_exit_status(),
            Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
        );
        assert!(
            child_owner.upgrade().is_none(),
            "the host anchor retains no child owner"
        );
        assert_reaped("adaptive original newborn", child_tid);
        let running = stopped.resume(None).unwrap();
        // The exit token follows this owner's selected mode. Drain it with
        // the same owner instead of cold-binding the legacy fixture helper
        // after a Native notifier may already have observed retirement.
        let terminal = running.generation().terminal_cleanup();
        terminal.request_sigkill().unwrap();
        let stop = tokio::time::timeout_at(deadline.into(), exit)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !terminal.wait(Duration::ZERO),
            "actual EXIT stop is not a final wait"
        );
        assert_eq!(
            tokio::time::timeout_at(
                deadline.into(),
                owner.wait_running(stop.resume(None).unwrap())
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (running.pid(), ExitStatus::Signaled(Signal::SIGKILL, false))
        );
        assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
        assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
        assert_reaped("group cleanup fixture root", running.pid());
        assert!(!session.cleanup_was_refused());
        assert!(!session.ordinary_receipt().failure_published);
        println!("ADAPTIVE_ORIGINAL_NEWBORN_CONTROLLER_PASSED");
    }

    // Both cells re-execute this exact test. Only the forced child installs
    // seccomp; no process-wide fixture policy changes reach other libtests.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn managed_waits_retain_controller_across_foreign_calls_and_newborns() {
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        const CELL: &str = "REVERIE_ADAPTIVE_OWNER_CELL";
        const SELECTOR: &str = "tracer::tests::adaptive_wait_tests::managed_waits_retain_controller_across_foreign_calls_and_newborns";
        if let Ok(cell) = std::env::var(CELL) {
            assert!(cell == "normal" || cell == "forced");
            unsafe { libc::alarm(10) };
            if cell == "forced" {
                let insn = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
                let filter = [
                    insn(0x20, 0, 0, 4),
                    insn(0x15, 1, 0, 0xc000_003e),
                    insn(0x06, 0, 0, 0x8000_0000),
                    insn(0x20, 0, 0, 0),
                    insn(0x15, 0, 3, libc::SYS_pidfd_open as u32),
                    insn(0x20, 0, 0, 24),
                    insn(0x15, 0, 1, libc::O_EXCL as u32),
                    insn(0x06, 0, 0, 0x0005_0000 | libc::EINVAL as u32),
                    insn(0x06, 0, 0, 0x7fff_0000),
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr().cast_mut(),
                };
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    0
                );
                assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
            }
            let native =
                unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), libc::O_EXCL) };
            if native >= 0 {
                assert_eq!(cell, "normal");
                assert_eq!(unsafe { libc::close(native as i32) }, 0);
            } else {
                assert_eq!(Errno::last(), Errno::EINVAL);
            }
            let ordinary = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
            assert!(ordinary >= 0, "flag-zero process pidfd remains available");
            assert_eq!(unsafe { libc::close(ordinary as i32) }, 0);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(cold_owner_refusal_and_cancelled_wait());
            runtime.block_on(newborn_inherits_original_controller());
            println!("ADAPTIVE_OWNER_CELL_PASSED {cell}");
            return;
        }
        let mut passed = true;
        for cell in ["normal", "forced"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([SELECTOR, "--exact", "--nocapture"])
                .env(CELL, cell)
                .process_group(0)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let pid = i32::try_from(child.id()).unwrap();
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(raw >= 0);
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
            let read = |pipe: Box<dyn Read + Send>| {
                std::thread::spawn(move || {
                    let mut bytes = Vec::new();
                    pipe.take(65537).read_to_end(&mut bytes).unwrap();
                    bytes
                })
            };
            let stdout = read(Box::new(child.stdout.take().unwrap()));
            let stderr = read(Box::new(child.stderr.take().unwrap()));
            let deadline = Instant::now() + Duration::from_secs(15);
            let timed_out = loop {
                let mut fd = libc::pollfd {
                    fd: pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut fd, 1, 10) };
                assert!(result >= 0 || Errno::last() == Errno::EINTR);
                if result == 1 {
                    assert_ne!(fd.revents & libc::POLLIN, 0);
                    break false;
                }
                if Instant::now() >= deadline {
                    break true;
                }
            };
            // The unreaped owned child prevents its process-group number
            // from being reused before this failure cleanup.
            let killed = unsafe { libc::kill(-pid, libc::SIGKILL) };
            assert!(killed == 0 || Errno::last() == Errno::ESRCH);
            let status = child.wait().unwrap();
            let stdout = stdout.join().unwrap();
            let stderr = stderr.join().unwrap();
            assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
            let stdout = String::from_utf8(stdout).unwrap();
            let stderr = String::from_utf8(stderr).unwrap();
            println!(
                "adaptive owner cell {cell}: actual status={status}, timed_out={timed_out}\n{stdout}"
            );
            eprintln!("{stderr}");
            passed &= !timed_out
                && status.success()
                && stdout
                    .lines()
                    .filter(|line| *line == format!("ADAPTIVE_OWNER_CELL_PASSED {cell}"))
                    .count()
                    == 1
                && stdout
                    .lines()
                    .filter(|line| {
                        line.starts_with("ADAPTIVE_COLD_OWNER_AND_CANCELLATION_PASSED native=")
                    })
                    .count()
                    == 1
                && stdout
                    .lines()
                    .filter(|line| {
                        line.starts_with("ADAPTIVE_WARM_OWNER_REFUSAL_AND_RECOVERY_PASSED native=")
                    })
                    .count()
                    == 1
                && stdout
                    .lines()
                    .filter(|line| *line == "ADAPTIVE_ORIGINAL_NEWBORN_CONTROLLER_PASSED")
                    .count()
                    == 1
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
                && !stdout.contains("SKIP:")
                && !stderr.contains("SKIP:");
        }
        assert!(
            passed,
            "actual normal and forced-EINVAL owner controls must both pass"
        );
    }
}
