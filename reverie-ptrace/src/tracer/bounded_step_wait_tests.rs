/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The bounded step wait (`PtracerWaitOwner::wait_running_bounded`) on a
// current-thread runtime, through its real managed driver and a real traced
// child. Its one test is x86_64-only, as its seccomp cell is.
#[cfg(target_arch = "x86_64")]
mod bounded_step_wait_tests {
    use super::*;

    /// A waker that counts its wakes, for the manual polls below.
    struct CountingWaker(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// How long a helper looks for the bounded wait's sleep before it acts
    /// anyway. The wait itself sleeps at most `BOUNDED_STEP_WAIT`.
    const SLEEP_SEARCH: Duration = Duration::from_secs(1);

    fn timed_out() -> u64 {
        BOUNDED_STEP_WAITS_TIMED_OUT.load(Ordering::SeqCst)
    }

    fn send_signal(pidfd: &OwnedFd, signal: Signal) {
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal as i32,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        assert_eq!(sent, 0, "pidfd_send_signal({signal:?}): {}", Errno::last());
    }

    /// From another thread, waits until thread `tid` of this process is
    /// asleep in futex(2), the bounded wait's condvar sleep, then sends
    /// `signal` to the child. Returns whether that sleep was seen; the signal
    /// is sent either way, so a failing case still finishes.
    fn signal_once_asleep(
        tid: libc::pid_t,
        pidfd: Arc<OwnedFd>,
        signal: Signal,
    ) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let path = format!("/proc/self/task/{tid}/syscall");
            let futex = libc::SYS_futex.to_string();
            let deadline = Instant::now() + SLEEP_SEARCH;
            let seen = loop {
                if let Ok(text) = std::fs::read_to_string(&path)
                    && text.split_whitespace().next() == Some(futex.as_str())
                {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_micros(200));
            };
            send_signal(&pidfd, signal);
            seen
        })
    }

    fn expect_signal_stop(wait: Wait, generation: &TraceeGeneration, signal: Signal) -> Stopped {
        let (stopped, event) = wait.assume_stopped();
        assert_eq!(event, Event::Signal(signal));
        assert_eq!(stopped.generation(), *generation);
        stopped
    }

    /// The status was taken exactly once: none is left queued, and the
    /// owner retains no unfinished wait.
    fn assert_consumed(owner: &Arc<PtracerWaitOwner>, terminal: &safeptrace::TerminalCleanup) {
        assert!(terminal.queued_raw_statuses().is_empty());
        assert!(owner.waits.lock().unwrap().is_empty());
    }

    /// The one unfinished wait the owner retains has the original generation.
    fn retained_wait(
        owner: &Arc<PtracerWaitOwner>,
        generation: &TraceeGeneration,
    ) -> Arc<StdMutex<Option<ManagedWaitDriver>>> {
        let waits = owner.waits.lock().unwrap();
        assert_eq!(waits.len(), 1);
        assert_eq!(
            waits[0].lock().unwrap().as_ref().unwrap().generation(),
            Some(generation.clone())
        );
        waits[0].clone()
    }

    async fn bounded_waits_on_a_current_thread_runtime() {
        let deadline = Instant::now() + Duration::from_secs(10);
        let tid = unsafe { libc::gettid() };
        let stopped = group_fixture_root(GroupFixtureAttach::Traceme, false).await;
        let child = stopped.pid();
        let generation = stopped.generation();
        let terminal = generation.terminal_cleanup();
        let native = terminal.has_thread_pidfd().unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.as_raw(), 0) };
        assert!(raw >= 0, "pidfd_open: {}", Errno::last());
        let pidfd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw as i32) });
        let owner = Arc::new(PtracerWaitOwner::default());
        owner.bind_stopped(&stopped);
        owner.prime_controller().unwrap();
        assert!(
            matches!(owner.mode().unwrap(), PtracerMode::Native if native)
                || matches!(owner.mode().unwrap(), PtracerMode::Explicit if !native)
        );
        let guard = owner.controller().guard.lock().unwrap().clone().unwrap();
        let controller = owner.controller().guard.clone();
        // Created once for the generation and left pending until its exit,
        // as the run loop does.
        let mut exit = owner.exit_stopped(&stopped);

        // Warm-up through the plain wait: after it the notifier worker owns
        // this Event's wait for the Event's life, so every bounded wait
        // below can block (`Event::block_until_status`).
        let running = stopped.resume(None).unwrap();
        send_signal(&pidfd, Signal::SIGUSR1);
        let wait = tokio::time::timeout_at(deadline.into(), owner.wait_running(running))
            .await
            .unwrap()
            .unwrap();
        let stopped = expect_signal_stop(wait, &generation, Signal::SIGUSR1);
        assert_consumed(&owner, &terminal);

        // 1. The status is published before the first poll.
        let running = stopped.resume(None).unwrap();
        send_signal(&pidfd, Signal::SIGUSR1);
        while terminal.queued_raw_statuses().is_empty() {
            assert!(Instant::now() < deadline, "the stop was never queued");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let queued = terminal.queued_raw_statuses();
        assert_eq!(queued.len(), 1);
        assert!(libc::WIFSTOPPED(queued[0]) && libc::WSTOPSIG(queued[0]) == libc::SIGUSR1);
        let before = timed_out();
        let mut wait = owner.wait_running_bounded(running);
        let mut polls = 0;
        let result = tokio::time::timeout_at(
            deadline.into(),
            futures::future::poll_fn(|cx| {
                polls += 1;
                std::future::Future::poll(wait.as_mut(), cx)
            }),
        )
        .await
        .unwrap();
        assert_eq!(polls, 1);
        let stopped = expect_signal_stop(result.unwrap(), &generation, Signal::SIGUSR1);
        assert_eq!(timed_out(), before);
        assert_consumed(&owner, &terminal);
        drop(wait);
        println!("BOUNDED_WAIT_READY_BEFORE_POLL_PASSED native={native}");

        // 2. The status is published while the first poll blocks.
        let running = stopped.resume(None).unwrap();
        let before = timed_out();
        let mut wait = owner.wait_running_bounded(running);
        let helper = signal_once_asleep(tid, pidfd.clone(), Signal::SIGUSR1);
        let mut polls = 0;
        let started = Instant::now();
        let result = tokio::time::timeout_at(
            deadline.into(),
            futures::future::poll_fn(|cx| {
                polls += 1;
                std::future::Future::poll(wait.as_mut(), cx)
            }),
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();
        let seen = helper.join().unwrap();
        assert!(
            seen,
            "the signal is sent only after the wait was seen asleep"
        );
        assert_eq!(polls, 1, "the blocked first poll returned the status");
        let stopped = expect_signal_stop(result.unwrap(), &generation, Signal::SIGUSR1);
        assert_eq!(
            timed_out(),
            before,
            "publication ended the wait before its bound"
        );
        assert_consumed(&owner, &terminal);
        drop(wait);
        println!(
            "BOUNDED_WAIT_PUBLISHED_DURING_WAIT_PASSED native={native} poll_us={}",
            elapsed.as_micros()
        );

        // 3. Nothing is published: the first poll times out and returns
        // Pending; a repoll makes no second bounded wait; the later status
        // wakes and completes the same original driver.
        let counter = Arc::new(CountingWaker(std::sync::atomic::AtomicUsize::new(0)));
        let waker = std::task::Waker::from(counter.clone());
        let mut cx = std::task::Context::from_waker(&waker);
        let running = stopped.resume(None).unwrap();
        let before = timed_out();
        let mut wait = owner.wait_running_bounded(running);
        let started = Instant::now();
        assert!(std::future::Future::poll(wait.as_mut(), &mut cx).is_pending());
        let first = started.elapsed();
        assert!(first >= BOUNDED_STEP_WAIT, "{first:?}");
        assert_eq!(timed_out(), before + 1);
        let retained = retained_wait(&owner, &generation);
        assert!(terminal.queued_raw_statuses().is_empty());
        let started = Instant::now();
        assert!(std::future::Future::poll(wait.as_mut(), &mut cx).is_pending());
        let repoll = started.elapsed();
        assert_eq!(
            timed_out(),
            before + 1,
            "a repoll makes no second bounded wait"
        );
        assert!(Arc::ptr_eq(&retained, &retained_wait(&owner, &generation)));
        drop(retained);
        send_signal(&pidfd, Signal::SIGUSR1);
        while counter.0.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the original driver was never woken"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let std::task::Poll::Ready(result) = std::future::Future::poll(wait.as_mut(), &mut cx)
        else {
            panic!("the woken original driver did not return the published status");
        };
        let stopped = expect_signal_stop(result.unwrap(), &generation, Signal::SIGUSR1);
        assert_eq!(timed_out(), before + 1);
        assert_consumed(&owner, &terminal);
        drop(wait);
        println!(
            "BOUNDED_WAIT_TIMEOUT_THEN_ORIGINAL_DRIVER_PASSED native={native} first_poll_us={} repoll_us={}",
            first.as_micros(),
            repoll.as_micros()
        );

        // 4. The exit stop arrives while the first poll blocks. The exit
        // stop is not queued, so the running wait stays Pending and the exit
        // future wins the biased race, as in the run loop; the bounded wait
        // is then dropped, which cancels it.
        let running = stopped.resume(None).unwrap();
        let before = timed_out();
        let mut wait = owner.wait_running_bounded(running);
        let helper = signal_once_asleep(tid, pidfd.clone(), Signal::SIGKILL);
        let mut polls = 0;
        let raced = tokio::time::timeout_at(
            deadline.into(),
            futures::future::select(
                futures::future::poll_fn(|cx| {
                    polls += 1;
                    std::future::Future::poll(wait.as_mut(), cx)
                }),
                &mut exit,
            ),
        )
        .await
        .unwrap();
        let stop = match raced {
            Either::Right((stop, _unfinished)) => stop.unwrap(),
            Either::Left((result, _)) => panic!(
                "the bounded wait finished before the exit stop (ok={})",
                result.is_ok()
            ),
        };
        drop(wait);
        let seen = helper.join().unwrap();
        assert!(seen, "SIGKILL is sent only after the wait was seen asleep");
        assert_eq!(
            timed_out(),
            before,
            "the exit stop ended the wait before its bound"
        );
        assert_eq!(stop.generation(), generation);
        assert_eq!(stop.getevent().unwrap(), libc::SIGKILL as i64);
        assert!(terminal.queued_raw_statuses().is_empty());
        // The cancelled wait's original driver stays with its owner, and does
        // not return the exit stop a second time.
        let retained = retained_wait(&owner, &generation);
        let noop = futures::task::noop_waker();
        let mut noop_cx = std::task::Context::from_waker(&noop);
        assert!(
            retained
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .poll_on_ptracer_thread(&mut noop_cx)
                .is_pending()
        );
        let running = stop.resume(None).unwrap();
        let exited = tokio::time::timeout_at(
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
            exited.assume_exited(),
            (child, ExitStatus::Signaled(Signal::SIGKILL, false))
        );
        assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
        );
        assert!(Arc::ptr_eq(&controller, &owner.controller().guard));
        assert_eq!(guard.check_current(), Ok(()));
        assert_eq!(*owner.generation.lock().unwrap(), Some(generation));
        drop(running);
        assert_reaped("bounded step wait root", child);
        let weak = Arc::downgrade(&owner);
        drop(exit);
        drop(retained);
        drop(owner);
        assert!(
            weak.upgrade().is_none(),
            "a cancelled bounded wait creates no owner cycle"
        );
        assert!(Instant::now() < deadline);
        println!("BOUNDED_WAIT_EXIT_DURING_WAIT_PASSED native={native} polls={polls}");
    }

    // Each cell re-executes this exact test in its own process, so the
    // process-global timeout counter counts only this test's waits. Only the
    // forced cell installs seccomp, which makes the owner select the
    // Explicit driver; no process-wide policy reaches other libtests.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn bounded_step_waits_keep_their_original_driver_on_a_current_thread_runtime() {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

        const CELL: &str = "REVERIE_BOUNDED_STEP_WAIT_CELL";
        const SELECTOR: &str = "tracer::tests::bounded_step_wait_tests::bounded_step_waits_keep_their_original_driver_on_a_current_thread_runtime";
        const CASES: [&str; 4] = [
            "BOUNDED_WAIT_READY_BEFORE_POLL_PASSED native=",
            "BOUNDED_WAIT_PUBLISHED_DURING_WAIT_PASSED native=",
            "BOUNDED_WAIT_TIMEOUT_THEN_ORIGINAL_DRIVER_PASSED native=",
            "BOUNDED_WAIT_EXIT_DURING_WAIT_PASSED native=",
        ];
        if let Ok(cell) = std::env::var(CELL) {
            assert!(cell == "normal" || cell == "forced");
            unsafe { libc::alarm(20) };
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(bounded_waits_on_a_current_thread_runtime());
            println!("BOUNDED_WAIT_CELL_PASSED {cell}");
            return;
        }
        let mut passed = true;
        for cell in ["normal", "forced"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
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
            let deadline = Instant::now() + Duration::from_secs(30);
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
            // The unreaped owned child keeps its process-group number from
            // being reused before this cleanup.
            let killed = unsafe { libc::kill(-pid, libc::SIGKILL) };
            assert!(killed == 0 || Errno::last() == Errno::ESRCH);
            let status = child.wait().unwrap();
            let stdout = stdout.join().unwrap();
            let stderr = stderr.join().unwrap();
            assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
            let stdout = String::from_utf8(stdout).unwrap();
            let stderr = String::from_utf8(stderr).unwrap();
            println!(
                "bounded step wait cell {cell}: actual status={status}, timed_out={timed_out}\n{stdout}"
            );
            eprintln!("{stderr}");
            passed &= !timed_out
                && status.success()
                && stdout
                    .lines()
                    .filter(|line| *line == format!("BOUNDED_WAIT_CELL_PASSED {cell}"))
                    .count()
                    == 1
                && CASES
                    .iter()
                    .all(|case| stdout.lines().filter(|line| line.starts_with(case)).count() == 1)
                && (cell == "normal"
                    || stdout
                        .lines()
                        .filter(|line| CASES.iter().any(|case| line.starts_with(case)))
                        .all(|line| line.contains("native=false")))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
                && !stdout.contains("SKIP:")
                && !stderr.contains("SKIP:");
        }
        assert!(
            passed,
            "the bounded step wait must pass all four cases in the normal and forced cells"
        );
    }
}
