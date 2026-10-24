/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
*/

#[test]
fn explicit_ptracer_namespace_guard_requires_complete_original_self_field() {
    require_aligned_proc_pid_namespace().unwrap();
    let tid = super::Pid::from_raw(123);
    assert_eq!(
        aligned_proc_pid_namespace(b"Name:\t\xff-name\nNSpid:\t123\n", tid),
        Ok(())
    );
    assert_eq!(
        aligned_proc_pid_namespace(b"NSpid:\t123 1\n", tid),
        Err(Errno::EXDEV)
    );
    assert_eq!(
        aligned_proc_pid_namespace(b"NSpid:\t456\n", tid),
        Err(Errno::EXDEV)
    );
    assert_eq!(
        aligned_proc_pid_namespace(b"NSpid:\t123", tid),
        Err(Errno::EOPNOTSUPP)
    );
    assert_eq!(
        aligned_proc_pid_namespace(b"NSpid:\t123 ", tid),
        Err(Errno::EOPNOTSUPP)
    );
    let mut large = b"Name:\tlarge-groups\nGroups:\t".to_vec();
    for _ in 0..65536 {
        large.extend_from_slice(b"4294967294 ");
    }
    large.extend_from_slice(b"\nNSpid:\t123\n");
    assert!(large.len() < 1024 * 1024);
    assert_eq!(aligned_proc_pid_namespace(&large, tid), Ok(()));
}

#[test]
#[cfg(not(sanitized))]
fn explicit_ptracer_namespace_guard_refuses_inherited_outer_proc() {
    const NAME: &str = "explicit_ptracer_namespace_guard_refuses_inherited_outer_proc";
    const INNER: &str = "SAFEPTRACE_PROC_NAMESPACE_GUARD_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_PTRACER_PROC_NAMESPACE_GUARD_EXERCISED";
    if env::var_os(INNER).is_none() {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")]);
        match classify_exact_reuse_output(
            output.as_ref(),
            MARKER,
            "PROC_NAMESPACE_GUARD_UNAVAILABLE",
        )
        .unwrap()
        {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("PROC_NAMESPACE_GUARD_UNAVAILABLE"),
        }
        return;
    }
    require_aligned_proc_pid_namespace().unwrap();
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWPID) }, 0);
    let child = match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            let tid = super::Pid::from(nix::unistd::gettid());
            assert_eq!(tid.as_raw(), 1);
            // The inherited proc mount still names the outer namespace.
            // Both the exact target capture and host anchor must refuse it
            // before opening a numeric proc target or sending any signal.
            assert_eq!(require_aligned_proc_pid_namespace(), Err(Errno::EXDEV));
            assert_eq!(
                Running::new_on_ptracer_thread(tid).unwrap_err(),
                Errno::EXDEV
            );
            assert_eq!(
                LegacyWaitOwner::capture_current().unwrap_err(),
                Errno::EXDEV
            );
            let exact_self = pidfd_open_with_flags(tid, 0).unwrap();
            assert_eq!(descriptor_is_live(exact_self.as_raw_fd()), Ok(true));
            unsafe { libc::_exit(0) };
        }
    };
    let status = waitpid_status_bounded(child, 0, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_ptracer_drivers_retain_authority_after_foreign_polls() {
    const MARKER: &str = "ACTUAL_EXPLICIT_PTRACER_DRIVER_RECOVERY_EXERCISED";
    if run_legacy_test_outer_with_outcome(
        "explicit_ptracer_drivers_retain_authority_after_foreign_polls",
        Some(MARKER),
    ) {
        return;
    }
    for forced in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        let terminal = running.terminal_cleanup();
        let native = terminal.has_thread_pidfd().unwrap();
        if forced {
            assert!(!native);
            let before = terminal.registration_error();
            assert_eq!(
                EventHandle::current_or_new(tid.into()).unwrap_err(),
                Errno::EINVAL
            );
            assert_eq!(
                NOTIFIER.event(tid.into(), running.1.event()).unwrap_err(),
                Errno::EINVAL
            );
            assert_eq!(terminal.registration_error(), before);
        }
        running.interrupt().unwrap();
        let mut driver = running.wait_owned_on_ptracer_thread().into_driver();
        driver = thread::spawn(move || {
            let waker = futures::task::noop_waker();
            assert!(matches!(
                driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            driver
        })
        .join()
        .unwrap();
        let (stopped, event) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            futures::future::poll_fn(|cx| driver.poll_on_ptracer_thread(cx)),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert_eq!(stopped.pid(), tid.into());
        assert!(matches!(
            driver.poll_on_ptracer_thread(&mut Context::from_waker(&futures::task::noop_waker())),
            Poll::Ready(Err(OwnedWaitError::Completed))
        ));

        let mut exit = stopped.exit_event_on_ptracer_thread().into_driver();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        exit = thread::spawn(move || {
            let waker = futures::task::noop_waker();
            assert!(matches!(
                exit.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(Error::Errno(Errno::EPERM)))
            ));
            exit
        })
        .join()
        .unwrap();
        let stopped = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            futures::future::poll_fn(|cx| exit.poll_on_ptracer_thread(cx)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        let mut final_wait = stopped
            .resume(None)
            .unwrap()
            .wait_owned_on_ptracer_thread()
            .into_driver();
        final_wait = thread::spawn(move || {
            let waker = futures::task::noop_waker();
            assert!(matches!(
                final_wait.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            final_wait
        })
        .join()
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT,
                futures::future::poll_fn(|cx| final_wait.poll_on_ptracer_thread(cx)),
            ).await.unwrap().unwrap(),
            Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into()
        ));
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        assert!(matches!(
            exit.poll_on_ptracer_thread(&mut Context::from_waker(&futures::task::noop_waker())),
            Poll::Ready(Err(Error::Errno(Errno::EALREADY | Errno::ECHILD)))
        ));
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        println!(
            "EXPLICIT_PTRACER_DRIVER_RECOVERY native={native} forced={forced} actual_exit=23 done=true root_reaped=true member_absent=true"
        );
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn explicit_ptracer_mode_cannot_recapture_an_unbound_generic_token() {
    let (pid, mut cleanup) = spawn_stopped_process(None).unwrap();
    let _force = LegacyThreadGroup::new(pid);
    let unbound = Running::new(pid.into());
    assert!(unbound.1.event().identity().is_none());
    let mut driver = unbound.wait_owned_on_ptracer_thread().into_driver();
    let waker = futures::task::noop_waker();
    assert!(matches!(
        driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(OwnedWaitError::Errno(Errno::ENODATA)))
    ));
    assert!(
        driver
            .inner
            .inner
            .as_ref()
            .unwrap()
            .token
            .event()
            .identity()
            .is_none()
    );
    let running = Running::new_on_ptracer_thread(pid.into()).unwrap();
    cleanup.bind_running_notifier(&running).unwrap();
    let terminal = running.terminal_cleanup();
    terminal.request_sigkill().unwrap();
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[tokio::test(flavor = "current_thread")]
#[cfg(all(feature = "memory", not(sanitized)))]
async fn explicit_native_user_write_enforces_original_ptracer_owner() {
    use reverie_memory::{Addr, AddrMut, MemoryAccess, RemoteIoVec};
    use std::io::IoSlice;

    if run_legacy_test_outer("explicit_native_user_write_enforces_original_ptracer_owner") {
        return;
    }
    for forced in [false, true] {
        // The child inherits this private mapping before creating its member.
        // Its remote bytes and the parent's unchanged bytes are independent.
        let canary = vec![0x5au8; 32];
        let address = canary.as_ptr() as usize;
        std::hint::black_box(&canary);
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        let terminal = running.terminal_cleanup();
        running.interrupt().unwrap();
        let (mut stopped, event) = running
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        let generation = stopped.generation();
        let native = terminal.has_thread_pidfd().unwrap();
        if forced {
            assert!(!native);
            assert!(matches!(
                stopped.1.event().identity().unwrap().pidfd,
                ThreadHandle::Procfs { .. }
            ));
        }
        let remote = [RemoteIoVec::new(AddrMut::from_raw(address + 12).unwrap(), 8).unwrap()];
        let mut expected = [0x5au8; 32];
        let mut observed = [0u8; 32];
        stopped
            .read_exact(Addr::from_raw(address).unwrap(), &mut observed)
            .unwrap();
        assert_eq!(observed, expected);
        let first = [0x33u8; 8];
        assert_eq!(
            stopped.write_native_user_vectored(tid.as_raw(), &[IoSlice::new(&first)], &remote),
            Ok(8)
        );
        expected[12..20].copy_from_slice(&first);
        stopped
            .read_exact(Addr::from_raw(address).unwrap(), &mut observed)
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(canary, [0x5a; 32]);

        stopped = thread::spawn(move || {
            let forbidden = [0x77u8; 8];
            assert_eq!(
                stopped.write_native_user_vectored(
                    tid.as_raw(),
                    &[IoSlice::new(&forbidden)],
                    &remote,
                ),
                Err(Errno::EPERM)
            );
            stopped
        })
        .join()
        .unwrap();
        assert_eq!(stopped.generation(), generation);
        stopped
            .read_exact(Addr::from_raw(address).unwrap(), &mut observed)
            .unwrap();
        assert_eq!(
            observed, expected,
            "foreign native write changed the target"
        );
        assert_eq!(canary, [0x5a; 32]);

        let second = [0x44u8; 8];
        let remote = [RemoteIoVec::new(AddrMut::from_raw(address + 12).unwrap(), 8).unwrap()];
        assert_eq!(
            stopped.write_native_user_vectored(tid.as_raw(), &[IoSlice::new(&second)], &remote),
            Ok(8)
        );
        expected[12..20].copy_from_slice(&second);
        stopped
            .read_exact(Addr::from_raw(address).unwrap(), &mut observed)
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(canary, [0x5a; 32]);

        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        assert!(matches!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
            )
            .await
            .unwrap()
            .unwrap(),
            Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into()
        ));
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        println!(
            "NATIVE_USER_WRITE_OWNER forced={forced} native={native} foreign=EPERM canaries_preserved=true owner_recovered=true exit=23 done=true"
        );
    }
}

#[test]
fn explicit_ptracer_interfaces_preserve_portable_auto_trait_contracts() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<WaitFuture>();
    send::<OwnedWaitFuture>();
    send::<ExitFuture>();
    send::<TerminalCleanup>();
    sync::<TerminalCleanup>();
    send::<PtracerWaitDriver>();
    send::<PtracerExitDriver>();
    send::<PtracerCleanupDriver>();
    send::<PtracerSyncDriver>();

    // Stable negative auto-trait checks: the inferred marker becomes
    // ambiguous if the concrete interface ever acquires the forbidden trait.
    macro_rules! not_trait {
        ($ty:ty, $bound:path) => {{
            trait Ambiguous<A> {
                fn witness() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            struct Forbidden;
            impl<T: ?Sized + $bound> Ambiguous<Forbidden> for T {}
            let _ = <$ty as Ambiguous<_>>::witness;
        }};
    }
    macro_rules! local {
        ($ty:ty) => {{
            not_trait!($ty, Send);
            not_trait!($ty, Sync);
        }};
    }
    local!(PtracerOwnedWaitFuture);
    local!(PtracerExitFuture);
    local!(PtracerTerminalCleanup);
    local!(PtracerPendingStatusReservation<'static>);
    local!(PtracerSyncWait);
    not_trait!(PtracerWaitDriver, Future);
    not_trait!(PtracerExitDriver, Future);
    not_trait!(PtracerCleanupDriver, Future);
    not_trait!(PtracerSyncDriver, Future);
}

#[test]
#[cfg(not(sanitized))]
fn explicit_attachment_retains_successful_state_and_exact_capture_refusal() {
    if run_legacy_test_outer(
        "explicit_attachment_retains_successful_state_and_exact_capture_refusal",
    ) {
        return;
    }
    for seize in [false, true] {
        for error in [Errno::EMFILE, Errno::EPERM, Errno::EIO] {
            let (root, tid, _release, mut root_cleanup) = legacy_owner_guest();
            let _force = LegacyThreadGroup::new(root);
            CAPTURE_ERRORS.lock().insert(tid.into(), error);
            let running = if seize {
                Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap()
            } else {
                Running::attach_on_ptracer_thread(tid.into()).unwrap()
            };
            assert_eq!(
                worker_proc_snapshot(tid.into()).unwrap().tracer_pid,
                nix::unistd::gettid().into()
            );
            assert!(running.1.event().identity().is_none());
            let original = running.1.event().clone();
            let terminal = running.terminal_cleanup();
            assert_eq!(terminal.ensure_registered(), Err(error));
            assert_eq!(terminal.registration_error(), Some(error));
            assert_eq!(running.interrupt(), Err(error));
            let mut driver = running.wait_owned_on_ptracer_thread().into_driver();
            let waker = futures::task::noop_waker();
            for _ in 0..2 {
                assert!(matches!(
                    driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                    Poll::Ready(Err(OwnedWaitError::Errno(actual))) if actual == error
                ));
                assert_eq!(
                    *driver.inner.inner.as_ref().unwrap().token.event(),
                    original
                );
                assert!(original.identity().is_none());
            }
            // The controlled fixture cannot exec or allocate a replacement.
            // Its real parent's already-retained regular pidfd terminates the
            // group; this raw fixture cleanup consumes only this member's
            // genuine owned stops and final SIGKILL report, never a SDK hint.
            pidfd_send_signal(&root_cleanup.pidfd, libc::SIGKILL).unwrap();
            let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
            loop {
                assert!(
                    Instant::now() < deadline,
                    "original attachment cleanup deadline"
                );
                let flags = WaitPidFlag::from_bits_retain(
                    WaitPidFlag::WEXITED.bits()
                        | WaitPidFlag::WSTOPPED.bits()
                        | WaitPidFlag::WNOHANG.bits()
                        | libc::__WALL
                        | libc::__WNOTHREAD,
                );
                let Some(status) = waitid::wait_raw(waitid::IdType::Pid(tid), flags).unwrap()
                else {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                if libc::WIFSTOPPED(status) {
                    assert_eq!(
                        unsafe {
                            libc::ptrace(
                                libc::PTRACE_CONT,
                                tid.as_raw(),
                                std::ptr::null_mut::<libc::c_void>(),
                                std::ptr::null_mut::<libc::c_void>(),
                            )
                        },
                        0
                    );
                    continue;
                }
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                break;
            }
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_legacy_cache_admits_real_native_sibling_without_another_owner() {
    const NAME: &str = "explicit_legacy_cache_admits_real_native_sibling_without_another_owner";
    const INNER: &str = "SAFEPTRACE_NATIVE_CACHE_CONTROL_INNER";
    const MARKER: &str = "ACTUAL_NATIVE_CACHE_PROMOTION_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_CACHE_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    match pidfd_open_with_flags(tid.into(), libc::O_EXCL) {
        Ok(reference) => drop(reference),
        Err(Errno::EINVAL) => {
            legacy_owner_reap_root(root, &mut root_cleanup);
            println!("NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_CACHE_CONTROL");
            return;
        }
        Err(error) => panic!("native reference acquisition refused: {error}"),
    }
    let force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let generation = running.generation();
    let legacy = running.terminal_cleanup();
    assert_eq!(legacy.has_thread_pidfd(), Ok(false));
    assert_eq!(legacy.request_sigstop(), Err(Errno::EOPNOTSUPP));
    running.interrupt().unwrap();
    // A consumes a genuine original stop before admission. Whether it is
    // still in the consumed-producer queue or already in the published FIFO,
    // B must receive that exact report before the one worker waits natively.
    legacy_owner_until(|| {
        running.1.event().try_assist_legacy_wait().unwrap();
        !running
            .1
            .event()
            .event()
            .legacy_wait
            .lock()
            .consumed
            .is_empty()
            || !legacy.queued_raw_statuses().is_empty()
    });
    let pid = super::Pid::from(tid);
    let stopped = thread::spawn(move || {
        let native_reference = pidfd_open_with_flags(pid, libc::O_EXCL).unwrap();
        assert_eq!(descriptor_is_live(native_reference.as_raw_fd()), Ok(true));
        let native = Running::try_new(pid).unwrap();
        let native_terminal = native.terminal_cleanup();
        assert_eq!(native_terminal.has_thread_pidfd(), Ok(true));
        let reservation = native_terminal
            .reserve_pending_for_cleanup(TRACEE_WAIT_TIMEOUT)
            .expect("actual native shared FIFO reservation");
        let (stopped, event) = reservation.decode().unwrap().assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert!(native_terminal.same_generation(&stopped.terminal_cleanup()));
        reservation.commit();
        drop(native);
        stopped
    })
    .join()
    .unwrap();
    assert_eq!(
        generation,
        stopped.generation(),
        "mode/view does not change generation identity"
    );
    assert!(legacy.same_generation(&stopped.terminal_cleanup()));
    assert_eq!(legacy.has_thread_pidfd(), Ok(false));
    assert_eq!(legacy.request_sigstop(), Err(Errno::EOPNOTSUPP));
    assert_eq!(SPAWN_WORKER_COUNTS.lock().get(&pid).copied(), Some(1));
    // The new facade retains a real native descriptor, including actual
    // exact-thread SIGSTOP and the existing original siginfo contract.
    let native_terminal = stopped.terminal_cleanup();
    assert_eq!(native_terminal.has_thread_pidfd(), Ok(true));
    native_terminal.request_sigstop().unwrap();
    let native = stopped.resume(None).unwrap();
    let stopped = thread::spawn(move || {
        let (stopped, event) = futures::executor::block_on(native.next_state())
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        stopped
    })
    .join()
    .unwrap();
    assert_eq!(stopped.getsiginfo().unwrap().si_signo, libc::SIGSTOP);
    let native = stopped.resume(None).unwrap();
    native.interrupt().unwrap();
    let stopped = thread::spawn(move || {
        let (stopped, event) = futures::executor::block_on(native.next_state())
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        stopped
    })
    .join()
    .unwrap();
    let exit = stopped.exit_event();
    let native = stopped.resume(None).unwrap();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let stopped = thread::spawn(move || futures::executor::block_on(exit).unwrap())
        .join()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    drop(native);
    let native = stopped.resume(None).unwrap();
    assert!(
        matches!(thread::spawn(move || futures::executor::block_on(native.next_state()).unwrap()).join().unwrap(),
        Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into())
    );
    assert!(native_terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert!(legacy.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(
        legacy.observed_exit_status(),
        Ok(Some(crate::ExitStatus::Exited(23)))
    );
    assert_eq!(SPAWN_WORKER_COUNTS.lock().get(&pid).copied(), Some(1));
    drop(force);
    legacy_owner_reap_root(root, &mut root_cleanup);
    assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn native_capture_before_legacy_open_refusal_keeps_native_wait_authority() {
    const NAME: &str = "native_capture_before_legacy_open_refusal_keeps_native_wait_authority";
    const INNER: &str = "SAFEPTRACE_NATIVE_BEFORE_REFUSAL_INNER";
    const MARKER: &str = "ACTUAL_NATIVE_BEFORE_REFUSAL_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_REGISTRATION_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    for local_registration in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let running = match Running::seize(tid.into(), legacy_thread_options()) {
            Ok(running) => running,
            Err(Errno::EINVAL) => {
                legacy_owner_reap_root(root, &mut root_cleanup);
                println!("{UNAVAILABLE}");
                return;
            }
            Err(error) => panic!("original native attachment refused: {error}"),
        };
        let generation = running.generation();
        let original = running.1.event().clone();
        assert!(matches!(
            original.identity().unwrap().pidfd,
            ThreadHandle::Pidfd(_)
        ));
        let force = LegacyThreadGroup::new(root);
        let terminal = if local_registration {
            // Explicit registration may capture a fresh legacy view under
            // this caller's refusal. The already bound native descriptor
            // must remain the worker's exact consuming authority.
            NOTIFIER
                .event_for_policy(tid.into(), &original, WaitPolicy::PtracerThread)
                .unwrap();
            assert!(matches!(
                NOTIFIER
                    .pids
                    .lock()
                    .get(&tid.into())
                    .unwrap()
                    .identity
                    .pidfd,
                ThreadHandle::Pidfd(_)
            ));
            TerminalCleanup::new_unregistered(tid.into(), &running.1)
        } else {
            // A native-bound shared facade preserves the original typed
            // registration EINVAL; it must not silently downgrade to an
            // observer-only worker that the generic waiter cannot progress.
            let terminal = running.terminal_cleanup();
            assert_eq!(terminal.ensure_registered(), Err(Errno::EINVAL));
            assert_eq!(terminal.registration_error(), Some(Errno::EINVAL));
            assert_eq!(
                original.event().worker_state.load(Ordering::Acquire),
                WORKER_NOT_STARTED
            );
            terminal
        };
        assert_eq!(terminal.has_thread_pidfd(), Ok(true));
        running.interrupt().unwrap();
        let owned = running.wait_owned();
        let stopped = thread::spawn(move || {
            let (stopped, event) = futures::executor::block_on(owned).unwrap().assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            stopped
        })
        .join()
        .unwrap();
        assert_eq!(stopped.generation(), generation);
        assert!(terminal.same_generation(&stopped.terminal_cleanup()));
        assert_eq!(terminal.registration_error(), None);
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
            Some(1)
        );
        let exit = stopped.exit_event();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = thread::spawn(move || futures::executor::block_on(exit).unwrap())
            .join()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        let running = stopped.resume(None).unwrap();
        assert!(
            matches!(thread::spawn(move || futures::executor::block_on(running.wait_owned()).unwrap()).join().unwrap(),
            Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into())
        );
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
            Some(1)
        );
        drop(force);
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn explicit_native_cache_admission_preserves_actual_local_sync_claim() {
    const NAME: &str = "explicit_native_cache_admission_preserves_actual_local_sync_claim";
    const INNER: &str = "SAFEPTRACE_NATIVE_SYNC_CLAIM_INNER";
    const MARKER: &str = "ACTUAL_NATIVE_CACHE_SYNC_ARBITRATION_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_SYNC_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
    match pidfd_open_with_flags(tid.into(), libc::O_EXCL) {
        Ok(reference) => drop(reference),
        Err(Errno::EINVAL) => {
            legacy_owner_reap_root(root, &mut root_cleanup);
            println!("{UNAVAILABLE}");
            return;
        }
        Err(error) => panic!("native sync reference refused: {error}"),
    }
    let force = LegacyThreadGroup::new(root);
    let running = Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
    let generation = running.generation();
    let original = running.1.event().clone();
    let legacy = TerminalCleanup::new_unregistered(tid.into(), &running.1);
    running.interrupt().unwrap();
    let claimed = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    SYNC_WAIT_CLAIM_PAUSES.lock().insert(
        tid.into(),
        EventCapturePause {
            captured: claimed.clone(),
            resume: resume.clone(),
        },
    );
    let controller_original = original.clone();
    let controller = thread::spawn(move || {
        claimed.wait();
        assert_eq!(
            controller_original
                .event()
                .wait_owner
                .load(Ordering::Acquire),
            WAIT_OWNER_SYNC
        );
        assert_eq!(
            controller_original
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        let native = Running::try_new(tid.into()).unwrap();
        assert_eq!(*native.1.event(), controller_original);
        assert!(matches!(
            native.1.event().identity().unwrap().pidfd,
            ThreadHandle::Pidfd(_)
        ));
        assert_eq!(
            controller_original
                .event()
                .wait_owner
                .load(Ordering::Acquire),
            WAIT_OWNER_SYNC
        );
        assert_eq!(SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(), None);
        let observe = WaitPidFlag::from_bits_retain(
            WaitPidFlag::WSTOPPED.bits()
                | WaitPidFlag::WNOHANG.bits()
                | WaitPidFlag::WNOWAIT.bits()
                | libc::__WALL,
        );
        let identity = native.1.event().identity().unwrap();
        legacy_owner_until(|| identity.pidfd.wait_status(observe).unwrap().is_some());
        // Admission retains the same actual synchronous claim; no native
        // worker consumes the report before that owner returns its stop.
        assert_eq!(
            controller_original
                .event()
                .wait_owner
                .load(Ordering::Acquire),
            WAIT_OWNER_SYNC
        );
        assert_eq!(
            controller_original
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        resume.wait();
        native
    });
    let mut sync_wait = running.wait_sync_on_ptracer_thread().into_driver();
    let (stopped, event) = sync_wait.wait_on_ptracer_thread().unwrap().assume_stopped();
    assert_eq!(event, crate::Event::Stop);
    assert_eq!(stopped.generation(), generation);
    assert_eq!(
        original.event().wait_owner.load(Ordering::Acquire),
        WAIT_OWNER_NONE
    );
    assert_eq!(SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(), None);
    let native = controller.join().unwrap();
    let running = stopped.resume(None).unwrap();
    running.interrupt().unwrap();
    drop(running);
    let stopped = thread::spawn(move || {
        let (stopped, event) = futures::executor::block_on(native.wait_owned())
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        stopped
    })
    .join()
    .unwrap();
    assert_eq!(stopped.generation(), generation);
    assert_eq!(legacy.has_thread_pidfd(), Ok(false));
    let native_terminal = stopped.terminal_cleanup();
    assert_eq!(native_terminal.has_thread_pidfd(), Ok(true));
    let exit = stopped.exit_event();
    let running = stopped.resume(None).unwrap();
    assert_eq!(
        unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        1
    );
    let stopped = thread::spawn(move || futures::executor::block_on(exit).unwrap())
        .join()
        .unwrap();
    assert_eq!(stopped.getevent().unwrap(), 23 << 8);
    drop(running);
    let running = stopped.resume(None).unwrap();
    assert!(
        matches!(thread::spawn(move || futures::executor::block_on(running.wait_owned()).unwrap()).join().unwrap(),
        Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into())
    );
    assert!(native_terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert!(legacy.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(
        SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
        Some(1)
    );
    drop(force);
    legacy_owner_reap_root(root, &mut root_cleanup);
    assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_cleanup_retains_identity_before_starting_any_wait_owner() {
    if run_legacy_test_outer("explicit_cleanup_retains_identity_before_starting_any_wait_owner") {
        return;
    }
    for forced in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        let original = running.1.event().clone();
        let generation = running.generation();
        let mut cleanup = running.terminal_cleanup_on_ptracer_thread().into_driver();
        assert!(cleanup.shared().event == original);
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert_eq!(
            original.event().wait_owner.load(Ordering::Acquire),
            WAIT_OWNER_NONE
        );
        assert_eq!(SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(), None);
        running.interrupt().unwrap();
        cleanup.progress_on_ptracer_thread().unwrap();
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
            Some(1)
        );
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert_eq!(stopped.generation(), generation);
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        assert!(matches!(tokio::time::timeout(TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()).await.unwrap().unwrap(),
            Wait::Exited(pid, crate::ExitStatus::Exited(23)) if pid == tid.into()));
        assert!(cleanup.wait_on_ptracer_thread(TRACEE_WAIT_TIMEOUT).unwrap());
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_child_capture_policy_follows_each_request_before_parent_commit() {
    const NAME: &str = "explicit_child_capture_policy_follows_each_request_before_parent_commit";
    const INNER: &str = "SAFEPTRACE_CHILD_CAPTURE_POLICY_INNER";
    const MARKER: &str = "ACTUAL_REQUEST_CHILD_CAPTURE_POLICY_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_CHILD_POLICY_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    async fn finish(stopped: Stopped, deadline: Instant) {
        let terminal = stopped.terminal_cleanup();
        let exit = stopped.exit_event_on_ptracer_thread();
        terminal.request_sigkill().unwrap();
        let stopped = tokio::time::timeout_at(deadline.into(), exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), libc::SIGKILL as i64);
        assert_eq!(
            tokio::time::timeout_at(
                deadline.into(),
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (
                terminal.pid,
                crate::ExitStatus::Signaled(Signal::SIGKILL, false)
            )
        );
        assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
        assert!(!std::path::Path::new(&format!("/proc/{}", terminal.pid)).exists());
    }
    for explicit_request in [false, true] {
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                // The genuine event parent is this tracee; CLONE_PARENT gives
                // the harness actual natural-parent reap authority as well.
                if unsafe {
                    libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_PARENT | libc::SIGCHLD,
                        0,
                        0,
                        0,
                        0,
                    )
                } < 0
                {
                    unsafe { libc::_exit(126) };
                }
                loop {
                    unsafe { libc::pause() };
                }
            }
        };
        let mut root_cleanup = TraceeCleanupGuard::new(root).unwrap();
        let initial = waitpid_status_bounded(root, libc::WUNTRACED, TRACEE_WAIT_TIMEOUT).unwrap();
        assert_eq!(initial, (libc::SIGSTOP << 8) | 0x7f);
        match pidfd_open_with_flags(root.into(), libc::O_EXCL) {
            Ok(reference) => drop(reference),
            Err(Errno::EINVAL) => {
                pidfd_send_signal(&root_cleanup.pidfd, libc::SIGKILL).unwrap();
                let killed = waitpid_status_bounded(root, 0, TRACEE_WAIT_TIMEOUT).unwrap();
                assert!(libc::WIFSIGNALED(killed));
                assert_eq!(libc::WTERMSIG(killed), libc::SIGKILL);
                root_cleanup.disarm();
                println!("{UNAVAILABLE}");
                return;
            }
            Err(error) => panic!("native parent descriptor refused: {error}"),
        }
        let stopped = Stopped::new_unchecked(root.into());
        let generation = stopped.generation();
        stopped
            .setoptions(
                Options::PTRACE_O_TRACEFORK
                    | Options::PTRACE_O_TRACEEXIT
                    | Options::PTRACE_O_EXITKILL,
            )
            .unwrap();
        // Merely retaining an explicit facade must not turn a subsequent
        // generic request into an implicit legacy child capture.
        let mut local = stopped.terminal_cleanup_on_ptracer_thread().into_driver();
        let terminal = stopped.terminal_cleanup();
        let running = stopped.resume(None).unwrap();
        root_cleanup.bind_running_notifier(&running).unwrap();
        let fork_status = (libc::PTRACE_EVENT_FORK << 16) | (libc::SIGTRAP << 8) | 0x7f;
        legacy_owner_until(|| terminal.queued_raw_statuses() == [fork_status]);
        let child_pid = super::Pid::from_raw(nix::sys::ptrace::getevent(root).unwrap() as i32);
        let child_native_before = PIDFD_OPEN_ERRORS.lock().insert(child_pid, Errno::EINVAL);
        assert!(child_native_before.is_none());
        let forced = explicit_request.then(|| LegacyThreadGroup::new(child_pid.into()));
        let (parent, child) = if explicit_request {
            let pending = local
                .reserve_pending_on_ptracer_thread(Duration::ZERO)
                .unwrap()
                .unwrap();
            let (parent, event) = pending.decode().unwrap().assume_stopped();
            let crate::Event::NewChild(crate::ChildOp::Fork, child) = event else {
                panic!("real fork request lost its child");
            };
            assert_eq!(child.1.policy, WaitPolicy::PtracerThread);
            assert!(child.1.event().identity().is_some());
            assert!(child.1.ptracer_owner.is_some());
            assert_eq!(
                child
                    .terminal_cleanup_on_ptracer_thread()
                    .shared()
                    .has_thread_pidfd(),
                Ok(false)
            );
            assert_eq!(parent.generation(), generation);
            assert_eq!(
                pending.inner.state.pending.front().copied(),
                Some(fork_status),
                "child identity must be captured before parent FIFO commit"
            );
            pending.commit();
            drop(running);
            (parent, child)
        } else {
            let mut original = running.wait_owned();
            assert!(matches!(
                tokio::time::timeout_at(deadline.into(), &mut original)
                    .await
                    .unwrap(),
                Err(OwnedWaitError::Errno(Errno::EINVAL))
            ));
            assert!(original.inner.is_some());
            assert_eq!(
                original.inner.as_ref().unwrap().token.policy,
                WaitPolicy::Native
            );
            assert_eq!(terminal.queued_raw_statuses(), [fork_status]);
            assert_eq!(terminal.registration_error(), None);
            let (parent, event) = tokio::time::timeout_at(deadline.into(), &mut original)
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
            let crate::Event::NewChild(crate::ChildOp::Fork, child) = event else {
                panic!("generic retry lost its original fork front");
            };
            assert_eq!(child.1.policy, WaitPolicy::Native);
            assert!(matches!(
                child.1.event().identity().unwrap().pidfd,
                ThreadHandle::Pidfd(_)
            ));
            (parent, child)
        };
        assert!(
            PIDFD_OPEN_ERRORS.lock().get(&child_pid).is_none(),
            "actual child thread-open refusal was consumed"
        );
        assert!(terminal.queued_raw_statuses().is_empty());
        assert_eq!(parent.generation(), generation);
        let before_local = child.generation();
        let (child, event) =
            tokio::time::timeout_at(deadline.into(), child.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        assert_eq!(
            child.generation(),
            before_local,
            "generic-native to explicit request keeps original generation equality"
        );
        let mut before_hash = DefaultHasher::new();
        before_local.hash(&mut before_hash);
        let mut after_hash = DefaultHasher::new();
        child.generation().hash(&mut after_hash);
        assert_eq!(before_hash.finish(), after_hash.finish());
        finish(child, deadline).await;
        finish(parent, deadline).await;
        root_cleanup.disarm();
        drop(forced);
        assert!(Instant::now() <= deadline);
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_native_reattach_preserves_current_owner_and_original_driver() {
    const NAME: &str = "explicit_native_reattach_preserves_current_owner_and_original_driver";
    const INNER: &str = "SAFEPTRACE_NATIVE_REATTACH_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_NATIVE_REATTACH_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_REATTACH_CONTROL";
    if env::var_os(INNER).is_none() {
        let output = run_exact_test_bounded(
            &format!("notifier::test::{NAME}"),
            &[(INNER, "1")],
            false,
            Duration::from_secs(5),
        )
        .unwrap();
        match classify_exact_reuse_output(Some(&output.output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => emit_completion_marker(MARKER),
            ExactReuseOutcome::Unavailable => println!("{UNAVAILABLE}"),
        }
        assert!(!output.timed_out);
        return;
    }
    for method in [LegacyAttachMethod::Attach, LegacyAttachMethod::Seize] {
        for changed_owner in [false, true] {
            let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
            match pidfd_open_with_flags(tid.into(), libc::O_EXCL) {
                Ok(reference) => drop(reference),
                Err(Errno::EINVAL) => {
                    legacy_owner_reap_root(root, &mut root_cleanup);
                    println!("{UNAVAILABLE}");
                    return;
                }
                Err(error) => panic!("native reattachment reference refused: {error}"),
            }
            let running =
                Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
            assert_eq!(running.terminal_cleanup().has_thread_pidfd(), Ok(true));
            running.interrupt().unwrap();
            let (stopped, event) =
                tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                    .await
                    .unwrap()
                    .unwrap()
                    .assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            let generation = stopped.generation();
            let terminal = stopped.terminal_cleanup();
            let event = terminal.event.event().clone();
            let count = SPAWN_WORKER_COUNTS
                .lock()
                .get(&tid.into())
                .copied()
                .unwrap();
            let mut original = stopped
                .detach(None)
                .unwrap()
                .wait_owned_on_ptracer_thread()
                .into_driver();
            let original_owner = original.affinity.owner.as_ref().unwrap().tid;
            assert_eq!(original_owner, super::Pid::from(nix::unistd::gettid()));
            let release_fd = release.as_raw_fd();
            if changed_owner {
                let (captured, capture) = mpsc::sync_channel(1);
                let (resume, resumed) = mpsc::sync_channel(1);
                let owner = thread::spawn(move || {
                    let running = if method == LegacyAttachMethod::Attach {
                        Running::attach_on_ptracer_thread(tid.into()).unwrap()
                    } else {
                        let running =
                            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options())
                                .unwrap();
                        running.interrupt().unwrap();
                        running
                    };
                    let current_owner = super::Pid::from(nix::unistd::gettid());
                    let fresh = running.terminal_cleanup();
                    captured.send((current_owner, fresh)).unwrap();
                    resumed.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
                    tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .unwrap()
                        .block_on(legacy_owner_finish_member(running, tid, release_fd, method))
                });
                let (new_owner, fresh) = capture.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
                assert_ne!(new_owner, original_owner);
                assert!(fresh.same_generation(&terminal));
                assert!(Arc::ptr_eq(fresh.event.event(), &event));
                legacy_owner_until(|| !terminal.queued_raw_statuses().is_empty());
                let pending_before = terminal.queued_raw_statuses();
                let waker = futures::task::noop_waker();
                for _ in 0..2 {
                    assert!(matches!(
                        original.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                        Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                    ));
                    assert_eq!(
                        original.inner.inner.as_ref().unwrap().token.event(),
                        &terminal.event
                    );
                    assert_eq!(
                        original.affinity.owner.as_ref().unwrap().tid,
                        original_owner
                    );
                    assert_eq!(
                        terminal.queued_raw_statuses(),
                        pending_before,
                        "old owner's refusal must leave the new owner's actual stop untouched"
                    );
                }
                resume.send(()).unwrap();
                let fresh = owner.join().unwrap();
                assert!(fresh.same_generation(&terminal));
                assert_eq!(
                    fresh.observed_exit_status(),
                    Ok(Some(crate::ExitStatus::Exited(23)))
                );
            } else {
                let running = if method == LegacyAttachMethod::Attach {
                    Running::attach_on_ptracer_thread(tid.into()).unwrap()
                } else {
                    let running =
                        Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options())
                            .unwrap();
                    running.interrupt().unwrap();
                    running
                };
                assert_eq!(running.1.event(), &terminal.event);
                drop(running);
                let (stopped, decoded) = tokio::time::timeout(
                    TRACEE_WAIT_TIMEOUT,
                    futures::future::poll_fn(|cx| original.poll_on_ptracer_thread(cx)),
                )
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
                assert_eq!(
                    decoded,
                    if method == LegacyAttachMethod::Attach {
                        crate::Event::Signal(Signal::SIGSTOP)
                    } else {
                        crate::Event::Stop
                    }
                );
                assert_eq!(stopped.generation(), generation);
                stopped.setoptions(legacy_thread_options()).unwrap();
                let exit = stopped.exit_event_on_ptracer_thread();
                assert_eq!(
                    unsafe { libc::write(release_fd, b"x".as_ptr().cast(), 1) },
                    1
                );
                let running = stopped.resume(None).unwrap();
                let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(stopped.getevent().unwrap(), 23 << 8);
                drop(running);
                assert_eq!(
                    tokio::time::timeout(
                        TRACEE_WAIT_TIMEOUT,
                        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
                    )
                    .await
                    .unwrap()
                    .unwrap()
                    .assume_exited(),
                    (tid.into(), crate::ExitStatus::Exited(23))
                );
            }
            assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
            assert_eq!(
                terminal.observed_exit_status(),
                Ok(Some(crate::ExitStatus::Exited(23)))
            );
            assert_eq!(
                SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
                Some(count)
            );
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
            drop(release);
        }
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_copied_owner_namespace_refuses_before_consuming_any_report() {
    const NAME: &str = "explicit_copied_owner_namespace_refuses_before_consuming_any_report";
    const INNER: &str = "SAFEPTRACE_COPIED_OWNER_NAMESPACE_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_COPIED_OWNER_NAMESPACE_REFUSAL_EXERCISED";
    if env::var_os(INNER).is_none() {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")])
                .expect("start copied-owner namespace control");
        assert!(output.status.success(), "copied-owner control: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == MARKER)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    assert_eq!(nix::unistd::getpid().as_raw(), 1);
    assert_eq!(nix::unistd::gettid().as_raw(), 2);
    for forced in [false, true] {
        for realign_proc in [false, true] {
            let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
            let _force = forced.then(|| LegacyThreadGroup::new(root));
            let running =
                Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
            let terminal = running.terminal_cleanup();
            let native = terminal.has_thread_pidfd().unwrap();
            if forced {
                assert!(
                    !native,
                    "forced copied-owner cell did not select legacy mode"
                );
            }
            terminal.ensure_registered().unwrap();
            let original = running.1.event().clone();
            let sync = Running::from_token(running.0, running.1.clone())
                .wait_sync_on_ptracer_thread()
                .into_driver();
            let exit = running.exit_event_on_ptracer_thread().into_driver();
            let cleanup = running.terminal_cleanup_on_ptracer_thread().into_driver();
            running.interrupt().unwrap();
            let mut owned = running.wait_owned_on_ptracer_thread().into_driver();
            let owner = owned.affinity.owner.as_ref().unwrap().clone();
            assert_eq!(owner.tid.as_raw(), 2);
            assert!(owner.is_current().unwrap());
            assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
            let (resume, capture) = if native {
                legacy_owner_until(|| !terminal.queued_raw_statuses().is_empty());
                (None, None)
            } else {
                // Park the original observer outside its progress/status
                // locks before copying the process. The child never uses
                // the copied observer's channels or publication thread.
                let (captured, capture) = mpsc::sync_channel(1);
                let (resume, resumed) = mpsc::sync_channel(1);
                *original.event().legacy_worker_cycle_pause.lock() = Some(BoundedTestPause {
                    captured,
                    resume: resumed,
                });
                capture.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
                (Some(resume), Some(capture))
            };
            // libc fork first leaves one host thread. Only that intermediate
            // child unshares its own future PID/mount namespace; the original
            // owner A remains live and holds its actual original tracee.
            let intermediate = match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    assert_eq!(
                        unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) },
                        0
                    );
                    assert_eq!(
                        unsafe {
                            libc::mount(
                                std::ptr::null(),
                                c"/".as_ptr(),
                                std::ptr::null(),
                                libc::MS_REC | libc::MS_PRIVATE,
                                std::ptr::null(),
                            )
                        },
                        0
                    );
                    let inner = match unsafe { fork() }.unwrap() {
                        ForkResult::Parent { child } => child,
                        ForkResult::Child => {
                            assert_eq!(nix::unistd::getpid().as_raw(), 1);
                            if realign_proc {
                                assert_eq!(
                                    unsafe {
                                        libc::mount(
                                            c"proc".as_ptr(),
                                            c"/proc".as_ptr(),
                                            c"proc".as_ptr(),
                                            0,
                                            std::ptr::null(),
                                        )
                                    },
                                    0
                                );
                            }
                            let proof = thread::spawn(move || {
                                let mut sync = sync;
                                let mut exit = exit;
                                let mut cleanup = cleanup;
                                assert_eq!(nix::unistd::gettid().as_raw(), owner.tid.as_raw());
                                assert_eq!(nix::unistd::getpid().as_raw(), owner.tgid.as_raw());
                                assert!(
                                    owner.is_live().unwrap(),
                                    "original A retired during the control"
                                );
                                assert_eq!(
                                    original.identity().unwrap().current_tracer_pid(),
                                    Ok(owner.tid)
                                );
                                let target = retained_proc_status(
                                    original.identity().unwrap().proc_dir.as_raw_fd(),
                                )
                                .unwrap();
                                assert_eq!(target.pid, tid.into());
                                assert_eq!(target.tgid, root.into());
                                assert_eq!(target.tracer_pid, owner.tid);
                                // pidfd_send_signal refuses signaling an
                                // ancestor PID namespace from a descendant
                                // with EINVAL before permission/delivery.
                                // Keep that error exact; original liveness
                                // above comes from the retained directory,
                                // not from interpreting this denial.
                                assert_eq!(
                                    original.identity().unwrap().pidfd_is_live(),
                                    Err(Errno::EINVAL)
                                );
                                assert_eq!(
                                    require_aligned_proc_pid_namespace(),
                                    if realign_proc {
                                        Ok(())
                                    } else {
                                        Err(Errno::EXDEV)
                                    }
                                );
                                // Same namespace-relative gettid is not the
                                // same host task in the original pinned mount.
                                assert!(!owner.is_current().unwrap());
                                let (replacement, replacement_cleanup, stop) =
                                    legacy_owner_replacement(Some(tid))
                                        .expect("actual inner same-number child");
                                assert_eq!(replacement, tid);
                                let pending: Vec<_> = original
                                    .event()
                                    .status
                                    .lock()
                                    .pending
                                    .iter()
                                    .copied()
                                    .collect();
                                let exit_epoch =
                                    original.event().exit_epoch.load(Ordering::Acquire);
                                let waker = futures::task::noop_waker();
                                for _ in 0..2 {
                                    assert!(matches!(
                                        owned.poll_on_ptracer_thread(&mut Context::from_waker(
                                            &waker
                                        )),
                                        Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                                    ));
                                    assert!(matches!(
                                        exit.poll_on_ptracer_thread(&mut Context::from_waker(
                                            &waker
                                        )),
                                        Poll::Ready(Err(Error::Errno(Errno::EPERM)))
                                    ));
                                    assert_eq!(
                                        cleanup.progress_on_ptracer_thread(),
                                        Err(Errno::EPERM)
                                    );
                                    assert!(matches!(
                                        cleanup.reserve_pending_on_ptracer_thread(Duration::ZERO),
                                        Err(Errno::EPERM)
                                    ));
                                    assert!(matches!(
                                        sync.wait_on_ptracer_thread(),
                                        Err(OwnedWaitError::Errno(Errno::EPERM))
                                    ));
                                    assert_eq!(
                                        owned.inner.inner.as_ref().unwrap().token.event(),
                                        &original
                                    );
                                    assert_eq!(sync.input.as_ref().unwrap().1.event(), &original);
                                    assert_eq!(
                                        original
                                            .event()
                                            .status
                                            .lock()
                                            .pending
                                            .iter()
                                            .copied()
                                            .collect::<Vec<_>>(),
                                        pending
                                    );
                                    assert_eq!(
                                        original.event().exit_epoch.load(Ordering::Acquire),
                                        exit_epoch
                                    );
                                    assert_eq!(
                                        legacy_owner_observe(replacement, WaitPidFlag::WSTOPPED),
                                        stop,
                                        "copied authority consumed an inner replacement report"
                                    );
                                }
                                // Report preservation above is checked in
                                // the inherited mount as well. Align only
                                // this child's cleanup view afterward so
                                // the unchanged actual-reap/absence helper
                                // names B's reaped child rather than A's
                                // still-live ancestor target.
                                if !realign_proc {
                                    assert_eq!(
                                        unsafe {
                                            libc::mount(
                                                c"proc".as_ptr(),
                                                c"/proc".as_ptr(),
                                                c"proc".as_ptr(),
                                                0,
                                                std::ptr::null(),
                                            )
                                        },
                                        0
                                    );
                                }
                                legacy_owner_finish_replacement(
                                    replacement,
                                    replacement_cleanup,
                                    stop,
                                );
                                assert!(owner.is_live().unwrap());
                                let target = retained_proc_status(
                                    original.identity().unwrap().proc_dir.as_raw_fd(),
                                )
                                .unwrap();
                                assert_eq!(target.pid, tid.into());
                                assert_eq!(target.tgid, root.into());
                                assert_eq!(target.tracer_pid, owner.tid);
                                assert_eq!(
                                    original.identity().unwrap().pidfd_is_live(),
                                    Err(Errno::EINVAL)
                                );
                                println!(
                                    "COPIED_OWNER_REFUSAL native={native} forced={forced} realigned={realign_proc} current_tid={} original_tid={} original_live=true target_live=true ancestor_signal0=EINVAL replacement_stop_preserved=true replacement_exit=42",
                                    nix::unistd::gettid(),
                                    owner.tid
                                );
                            });
                            proof.join().unwrap();
                            unsafe { libc::_exit(0) };
                        }
                    };
                    let status = waitpid_status_bounded(inner, 0, TRACEE_WAIT_TIMEOUT).unwrap();
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 0);
                    unsafe { libc::_exit(0) };
                }
            };
            let status = waitpid_status_bounded(intermediate, 0, TRACEE_WAIT_TIMEOUT).unwrap();
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert!(owner.is_current().unwrap());
            assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
            if let Some(resume) = resume {
                resume.send(()).unwrap();
            }
            drop(capture);
            // A's SAME original driver remains usable after every foreign
            // copy refuses. Finish actual original stop, EXIT23 and DONE.
            let (stopped, event) = tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                futures::future::poll_fn(|cx| owned.poll_on_ptracer_thread(cx)),
            )
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            let exit = stopped.exit_event_on_ptracer_thread();
            let running = stopped.resume(None).unwrap();
            assert_eq!(
                unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
                1
            );
            let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stopped.getevent().unwrap(), 23 << 8);
            drop(running);
            assert_eq!(
                tokio::time::timeout(
                    TRACEE_WAIT_TIMEOUT,
                    stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
                )
                .await
                .unwrap()
                .unwrap()
                .assume_exited(),
                (tid.into(), crate::ExitStatus::Exited(23))
            );
            assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        }
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_original_owner_progresses_through_retained_proc_overmount() {
    const NAME: &str = "explicit_original_owner_progresses_through_retained_proc_overmount";
    const INNER: &str = "SAFEPTRACE_OWNER_PROC_OVERMOUNT_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_OWNER_PROC_OVERMOUNT_EXERCISED";
    if env::var_os(INNER).is_none() {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")])
                .expect("start original-owner overmount control");
        assert!(
            output.status.success(),
            "owner overmount control: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == MARKER)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    for forced in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        let terminal = running.terminal_cleanup();
        terminal.ensure_registered().unwrap();
        let native = terminal.has_thread_pidfd().unwrap();
        if forced {
            assert!(!native, "forced overmount cell did not select legacy mode");
        }
        let generation = running.generation();
        let owner = running.1.ptracer_owner.as_ref().unwrap().clone();
        let mut cleanup = running.terminal_cleanup_on_ptracer_thread().into_driver();
        let mut owned = running.wait_owned_on_ptracer_thread().into_driver();
        assert_eq!(
            unsafe {
                libc::mount(
                    c"tmpfs".as_ptr(),
                    c"/proc".as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    c"size=4096".as_ptr().cast(),
                )
            },
            0
        );
        assert!(
            matches!(fs::read("/proc/thread-self/status"), Err(error) if error.raw_os_error() == Some(libc::ENOENT))
        );
        assert_eq!(require_aligned_proc_pid_namespace(), Err(Errno::EXDEV));
        assert!(
            owner.is_current().unwrap(),
            "a later absolute overmount changed the original host identity"
        );
        assert_eq!(
            owner.proc_root.current_thread_status().unwrap().pid,
            owner.tid
        );
        // Retained root/target/host descriptors permit the actual original
        // owner to register progress, consume a stop, resume and reap.
        let event_handle = owned.inner.inner.as_ref().unwrap().token.event();
        Running::from_token(
            tid.into(),
            owned.inner.inner.as_ref().unwrap().token.clone(),
        )
        .interrupt()
        .unwrap();
        let event_before = event_handle.clone();
        cleanup.progress_on_ptracer_thread().unwrap();
        let (stopped, event) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            futures::future::poll_fn(|cx| owned.poll_on_ptracer_thread(cx)),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert_eq!(stopped.generation(), generation);
        assert_eq!(stopped.1.event(), &event_before);
        let observed = stopped.observation().sample(false);
        assert_eq!(observed.refusal(), None);
        assert_eq!(observed.siginfo().unwrap().unwrap().signo, libc::SIGTRAP);
        assert_eq!(observed.pidfd_live(), Some(Ok(true)));
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (tid.into(), crate::ExitStatus::Exited(23))
        );
        assert!(cleanup.wait_on_ptracer_thread(TRACEE_WAIT_TIMEOUT).unwrap());
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        assert_eq!(
            terminal.event.identity().unwrap().pidfd_is_live(),
            Ok(false)
        );
        assert_eq!(
            unsafe { libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) },
            0
        );
        require_aligned_proc_pid_namespace().unwrap();
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        println!(
            "ORIGINAL_OWNER_OVERMOUNT native={native} forced={forced} actual_exit=23 done=true root_reaped=true member_absent=true"
        );
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_copied_stopped_namespace_refuses_numeric_ptrace() {
    const NAME: &str = "explicit_copied_stopped_namespace_refuses_numeric_ptrace";
    const INNER: &str = "SAFEPTRACE_COPIED_STOPPED_NAMESPACE_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_COPIED_PTRACE_NAMESPACE_REFUSAL_EXERCISED";
    if env::var_os(INNER).is_none() {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")])
                .expect("start copied stopped-state control");
        assert!(
            output.status.success(),
            "copied stopped-state control: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == MARKER)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    assert_eq!(nix::unistd::getpid().as_raw(), 1);
    assert_eq!(nix::unistd::gettid().as_raw(), 2);
    for forced in [false, true] {
        for realign_proc in [false, true] {
            let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
            let _force = forced.then(|| LegacyThreadGroup::new(root));
            let running =
                Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
            running.interrupt().unwrap();
            // A actually consumes the kernel's original stop through the
            // named synchronous API before copying its stopped generation.
            let (stopped, event) = running
                .wait_sync_on_ptracer_thread()
                .wait()
                .unwrap()
                .assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            let generation = stopped.generation();
            let terminal = stopped.terminal_cleanup_on_ptracer_thread().into_driver();
            let native = terminal.shared().has_thread_pidfd().unwrap();
            if forced {
                assert!(
                    !native,
                    "forced copied ptrace cell did not select legacy mode"
                );
            }
            let original = stopped.1.event().clone();
            assert_eq!(
                original.event().worker_state.load(Ordering::Acquire),
                WORKER_NOT_STARTED
            );
            assert_eq!(
                original.event().wait_owner.load(Ordering::Acquire),
                WAIT_OWNER_NONE
            );
            let owner = stopped.1.ptracer_owner.as_ref().unwrap().clone();
            assert!(owner.is_current().unwrap());
            assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
            let original_siginfo = stopped.getsiginfo().unwrap();
            assert_eq!(original_siginfo.si_signo, libc::SIGTRAP);
            assert_eq!(
                original_siginfo.si_code,
                libc::SIGTRAP | (libc::PTRACE_EVENT_STOP << 8)
            );
            let original_regs = stopped.getregs().unwrap();
            let original_observation = stopped.observation().sample(false);
            assert_eq!(original_observation.refusal(), None);
            assert_eq!(
                original_observation.siginfo().unwrap().unwrap().signo,
                libc::SIGTRAP
            );
            assert_eq!(original_observation.pidfd_live(), Some(Ok(true)));
            let copied_generation = generation.clone();
            let intermediate = match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    assert_eq!(
                        unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) },
                        0
                    );
                    assert_eq!(
                        unsafe {
                            libc::mount(
                                std::ptr::null(),
                                c"/".as_ptr(),
                                std::ptr::null(),
                                libc::MS_REC | libc::MS_PRIVATE,
                                std::ptr::null(),
                            )
                        },
                        0
                    );
                    let inner = match unsafe { fork() }.unwrap() {
                        ForkResult::Parent { child } => child,
                        ForkResult::Child => {
                            if realign_proc {
                                assert_eq!(
                                    unsafe {
                                        libc::mount(
                                            c"proc".as_ptr(),
                                            c"/proc".as_ptr(),
                                            c"proc".as_ptr(),
                                            0,
                                            std::ptr::null(),
                                        )
                                    },
                                    0
                                );
                            }
                            let proof = thread::spawn(move || {
                                assert_eq!(nix::unistd::gettid().as_raw(), owner.tid.as_raw());
                                assert_eq!(nix::unistd::getpid().as_raw(), owner.tgid.as_raw());
                                assert!(owner.is_live().unwrap());
                                assert!(!owner.is_current().unwrap());
                                let target = retained_proc_status(
                                    original.identity().unwrap().proc_dir.as_raw_fd(),
                                )
                                .unwrap();
                                assert_eq!(target.pid, tid.into());
                                assert_eq!(target.tgid, root.into());
                                assert_eq!(target.tracer_pid, owner.tid);
                                assert_eq!(
                                    original.identity().unwrap().pidfd_is_live(),
                                    Err(Errno::EINVAL)
                                );
                                assert_eq!(
                                    require_aligned_proc_pid_namespace(),
                                    if realign_proc {
                                        Ok(())
                                    } else {
                                        Err(Errno::EXDEV)
                                    }
                                );
                                let (receipt, emit) = nix::unistd::pipe().unwrap();
                                let emit_fd = emit.as_raw_fd();
                                let (replacement, replacement_cleanup, original_stop) = legacy_owner_replacement_after_stop(Some(tid), move || {
                                    assert_eq!(unsafe { libc::write(emit_fd, b"Q".as_ptr().cast(), 1) }, 1);
                                    assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
                                }).expect("actual same-number replacement with IPC and two real stops");
                                assert_eq!(replacement, tid);
                                let flags = WaitPidFlag::from_bits_retain(
                                    WaitPidFlag::WSTOPPED.bits()
                                        | WaitPidFlag::WNOHANG.bits()
                                        | libc::__WALL
                                        | libc::__WNOTHREAD,
                                );
                                assert_eq!(
                                    waitid::wait_raw(waitid::IdType::Pid(replacement), flags)
                                        .unwrap(),
                                    Some(original_stop)
                                );
                                let own_info = nix::sys::ptrace::getsiginfo(replacement).unwrap();
                                assert_eq!(own_info.si_signo, libc::SIGSTOP);
                                let mut copied = copied_generation.assume_stopped();
                                for _ in 0..2 {
                                    assert!(matches!(
                                        copied.getsiginfo(),
                                        Err(Error::Errno(Errno::EPERM))
                                    ));
                                    // A new observer constructed by B must
                                    // keep the copied explicit token's actual
                                    // owner instead of querying B's child.
                                    let observed = copied.observation().sample(false);
                                    assert_eq!(observed.refusal(), None);
                                    assert_eq!(observed.siginfo(), Some(Err(Errno::EPERM)));
                                    assert_eq!(observed.flags(), None);
                                    assert_eq!(observed.pidfd_live(), Some(Err(Errno::EINVAL)));
                                    let (retained, refusal) =
                                        copied.resume_retaining(None).unwrap_err();
                                    assert_eq!(refusal, Errno::EPERM);
                                    assert_eq!(retained.generation(), copied_generation);
                                    assert_eq!(retained.1.event(), &original);
                                    assert!(Arc::ptr_eq(
                                        retained.1.ptracer_owner.as_ref().unwrap(),
                                        &owner
                                    ));
                                    copied = retained;
                                    let still_held =
                                        nix::sys::ptrace::getsiginfo(replacement).unwrap();
                                    assert_eq!(still_held.si_signo, own_info.si_signo);
                                    assert_eq!(still_held.si_code, own_info.si_code);
                                    assert_eq!(unsafe { still_held.si_pid() }, unsafe {
                                        own_info.si_pid()
                                    });
                                    assert_eq!(
                                        waitid::wait_raw(
                                            waitid::IdType::Pid(replacement),
                                            flags | WaitPidFlag::WNOWAIT
                                        )
                                        .unwrap(),
                                        None
                                    );
                                }
                                // B's own actual authority still resumes its
                                // child, observes real Q IPC and a new STOP,
                                // then consumes/reaps the actual exit42.
                                nix::sys::ptrace::cont(replacement, None).unwrap();
                                let mut readiness = libc::pollfd {
                                    fd: receipt.as_raw_fd(),
                                    events: libc::POLLIN,
                                    revents: 0,
                                };
                                assert_eq!(
                                    unsafe {
                                        libc::poll(
                                            &mut readiness,
                                            1,
                                            TRACEE_WAIT_TIMEOUT.as_millis() as i32,
                                        )
                                    },
                                    1
                                );
                                let mut byte = [0u8; 1];
                                fs::File::from(receipt).read_exact(&mut byte).unwrap();
                                assert_eq!(byte, [b'Q']);
                                let fresh =
                                    legacy_owner_observe(replacement, WaitPidFlag::WSTOPPED);
                                assert!(libc::WIFSTOPPED(fresh));
                                assert_eq!(libc::WSTOPSIG(fresh), libc::SIGSTOP);
                                if !realign_proc {
                                    assert_eq!(
                                        unsafe {
                                            libc::mount(
                                                c"proc".as_ptr(),
                                                c"/proc".as_ptr(),
                                                c"proc".as_ptr(),
                                                0,
                                                std::ptr::null(),
                                            )
                                        },
                                        0
                                    );
                                }
                                legacy_owner_finish_replacement(
                                    replacement,
                                    replacement_cleanup,
                                    fresh,
                                );
                                assert!(owner.is_live().unwrap());
                                assert_eq!(
                                    original.identity().unwrap().current_tracer_pid(),
                                    Ok(owner.tid)
                                );
                                println!(
                                    "COPIED_EXPLICIT_PTRACE_REFUSAL native={native} forced={forced} realigned={realign_proc} original_sync_stop_consumed=true copied_getsiginfo=EPERM copied_observation=EPERM copied_resume=EPERM same_original_stopped_retained=true own_ipc=Q fresh_stop=SIGSTOP actual_replacement_exit=42"
                                );
                            });
                            proof.join().unwrap();
                            unsafe { libc::_exit(0) };
                        }
                    };
                    let status = waitpid_status_bounded(inner, 0, TRACEE_WAIT_TIMEOUT).unwrap();
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 0);
                    unsafe { libc::_exit(0) };
                }
            };
            let status = waitpid_status_bounded(intermediate, 0, TRACEE_WAIT_TIMEOUT).unwrap();
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert!(owner.is_current().unwrap());
            assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
            let still_held = stopped.getsiginfo().unwrap();
            assert_eq!(still_held.si_signo, original_siginfo.si_signo);
            assert_eq!(still_held.si_code, original_siginfo.si_code);
            assert_eq!(unsafe { still_held.si_pid() }, unsafe {
                original_siginfo.si_pid()
            });
            assert_eq!(stopped.getregs().unwrap(), original_regs);
            let observed = stopped.observation().sample(false);
            assert_eq!(observed.refusal(), None);
            assert_eq!(observed.siginfo(), original_observation.siginfo());
            assert_eq!(observed.pidfd_live(), Some(Ok(true)));
            assert_eq!(stopped.generation(), generation);
            let exit = stopped.exit_event_on_ptracer_thread();
            let running = stopped.resume(None).unwrap();
            assert_eq!(
                unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
                1
            );
            let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stopped.getevent().unwrap(), 23 << 8);
            drop(running);
            assert_eq!(
                tokio::time::timeout(
                    TRACEE_WAIT_TIMEOUT,
                    stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
                )
                .await
                .unwrap()
                .unwrap()
                .assume_exited(),
                (tid.into(), crate::ExitStatus::Exited(23))
            );
            let mut terminal = terminal;
            assert!(
                terminal
                    .wait_on_ptracer_thread(TRACEE_WAIT_TIMEOUT)
                    .unwrap()
            );
            assert_eq!(
                terminal.shared().observed_exit_status(),
                Ok(Some(crate::ExitStatus::Exited(23)))
            );
            legacy_owner_reap_root(root, &mut root_cleanup);
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        }
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_first_binding_uses_original_native_event_mount() {
    const NAME: &str = "explicit_first_binding_uses_original_native_event_mount";
    const INNER: &str = "SAFEPTRACE_FIRST_OWNER_NAMESPACE_INNER";
    const MARKER: &str = "ACTUAL_EXPLICIT_NATIVE_FIRST_BINDING_REFUSAL_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_FIRST_BINDING_CONTROL";
    if env::var_os(INNER).is_none() {
        let output =
            run_exact_in_pid_namespace_bounded(&format!("notifier::test::{NAME}"), &[(INNER, "1")])
                .expect("start original native Event first-binding control");
        assert!(output.status.success(), "first-binding control: {output:?}");
        match classify_exact_reuse_output(Some(&output), MARKER, UNAVAILABLE).unwrap() {
            ExactReuseOutcome::Exercised => {}
            ExactReuseOutcome::Unavailable => {}
        }
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    assert_eq!(nix::unistd::getpid().as_raw(), 1);
    assert_eq!(nix::unistd::gettid().as_raw(), 2);
    for realign_proc in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        match pidfd_open_with_flags(tid.into(), libc::O_EXCL) {
            Ok(reference) => drop(reference),
            Err(Errno::EINVAL) => {
                legacy_owner_reap_root(root, &mut root_cleanup);
                println!("{UNAVAILABLE}");
                return;
            }
            Err(error) => panic!("native first-binding reference refused: {error}"),
        }
        // This generic root is an untraced direct child. Keep its original
        // Event passive so the fixture's real parent remains its sole reaper.
        let untraced = Running::try_new(root.into()).unwrap();
        assert!(untraced.1.ptracer_owner.is_none());
        assert_eq!(
            untraced.1.event().current_tracer_pid(),
            Ok(super::Pid::from_raw(0))
        );
        assert!(untraced.1.event().identity().unwrap().proc_root.is_none());
        let untraced_generation = untraced.generation();
        let untraced_token = untraced.1.clone();
        let running = Running::seize(tid.into(), legacy_thread_options()).unwrap();
        assert!(running.1.ptracer_owner.is_none());
        let generation = running.generation();
        let original = running.1.event().clone();
        assert!(original.identity().unwrap().proc_root.is_none());
        let host = LegacyWaitOwner::capture_current().unwrap();
        assert!(host.is_current().unwrap());
        let terminal = running.terminal_cleanup();
        assert_eq!(terminal.has_thread_pidfd(), Ok(true));
        running.interrupt().unwrap();
        legacy_owner_until(|| !terminal.queued_raw_statuses().is_empty());
        let queued = terminal.queued_raw_statuses();
        assert_eq!(queued.len(), 1);
        assert_eq!((queued[0] >> 16) & 0xffff, libc::PTRACE_EVENT_STOP);
        // The genuine generic Native interface retains its original kernel
        // refusal from a sibling. Its token has no explicit-mode owner, and
        // this known physical stop/FIFO stays with A through that refusal.
        let foreign = Stopped::from_token(tid.into(), running.1.clone());
        let expected_siginfo = nix::sys::ptrace::getsiginfo(tid).unwrap();
        let expected_regs = foreign.getregs().unwrap();
        let refusal = thread::spawn(move || foreign.detach(None))
            .join()
            .unwrap()
            .unwrap_err();
        let Error::Died(refused) = refusal else {
            panic!("generic Native foreign detach changed its original refusal");
        };
        assert_eq!(refused.pid(), tid.into());
        assert_eq!(refused.0.1.policy, WaitPolicy::Native);
        assert_eq!(refused.0.1.event(), &original);
        assert!(refused.0.1.ptracer_owner.is_none());
        assert_eq!(refused.0.generation(), generation);
        drop(refused);
        assert_eq!(terminal.queued_raw_statuses(), queued);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        let after = nix::sys::ptrace::getsiginfo(tid).unwrap();
        assert_eq!(after.si_signo, expected_siginfo.si_signo);
        assert_eq!(after.si_code, expected_siginfo.si_code);
        assert_eq!(unsafe { after.si_pid() }, unsafe {
            expected_siginfo.si_pid()
        });
        assert_eq!(
            Stopped::from_token(tid.into(), running.1.clone())
                .getregs()
                .unwrap(),
            expected_regs
        );
        let copied = running.1.clone();
        let intermediate = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) },
                    0
                );
                assert_eq!(
                    unsafe {
                        libc::mount(
                            std::ptr::null(),
                            c"/".as_ptr(),
                            std::ptr::null(),
                            libc::MS_REC | libc::MS_PRIVATE,
                            std::ptr::null(),
                        )
                    },
                    0
                );
                let inner = match unsafe { fork() }.unwrap() {
                    ForkResult::Parent { child } => child,
                    ForkResult::Child => {
                        if realign_proc {
                            assert_eq!(
                                unsafe {
                                    libc::mount(
                                        c"proc".as_ptr(),
                                        c"/proc".as_ptr(),
                                        c"proc".as_ptr(),
                                        0,
                                        std::ptr::null(),
                                    )
                                },
                                0
                            );
                        }
                        let proof = thread::spawn(move || {
                            assert_eq!(nix::unistd::gettid().as_raw(), host.tid.as_raw());
                            assert_eq!(nix::unistd::getpid().as_raw(), host.tgid.as_raw());
                            assert!(host.is_live().unwrap());
                            assert!(!host.is_current().unwrap());
                            assert_eq!(original.current_tracer_pid(), Ok(host.tid));
                            assert_eq!(
                                original.identity().unwrap().pidfd_is_live(),
                                Err(Errno::EINVAL)
                            );
                            assert_eq!(
                                require_aligned_proc_pid_namespace(),
                                if realign_proc {
                                    Ok(())
                                } else {
                                    Err(Errno::EXDEV)
                                }
                            );
                            let (replacement, replacement_cleanup, stop) =
                                legacy_owner_replacement(Some(tid))
                                    .expect("actual first-binding same-number child");
                            assert_eq!(replacement, tid);
                            let before = terminal.queued_raw_statuses();
                            let epoch = original.event().exit_epoch.load(Ordering::Acquire);
                            assert!(copied.ptracer_owner.is_none());
                            let mut driver = Running::from_token(tid.into(), copied)
                                .wait_owned_on_ptracer_thread()
                                .into_driver();
                            let mut cleanup = terminal.on_ptracer_thread().into_driver();
                            let mut zero_tracer = Running::from_token(root.into(), untraced_token)
                                .wait_owned_on_ptracer_thread()
                                .into_driver();
                            let waker = futures::task::noop_waker();
                            for _ in 0..2 {
                                assert_eq!(
                                    original.capture_current_ptracer_owner().unwrap_err(),
                                    Errno::EXDEV
                                );
                                assert_eq!(
                                    zero_tracer
                                        .inner
                                        .inner
                                        .as_ref()
                                        .unwrap()
                                        .token
                                        .event()
                                        .capture_current_constructor_owner()
                                        .unwrap_err(),
                                    Errno::EXDEV
                                );
                                assert!(matches!(
                                    driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                                    Poll::Ready(Err(OwnedWaitError::Errno(Errno::EXDEV)))
                                ));
                                assert!(matches!(
                                    zero_tracer
                                        .poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                                    Poll::Ready(Err(OwnedWaitError::Errno(Errno::EXDEV)))
                                ));
                                assert_eq!(cleanup.progress_on_ptracer_thread(), Err(Errno::EXDEV));
                                assert!(driver.affinity.owner.is_none());
                                assert!(zero_tracer.affinity.owner.is_none());
                                assert!(cleanup.affinity.owner.is_none());
                                let input = driver.inner.inner.as_ref().unwrap();
                                assert_eq!(input.token.event(), &original);
                                assert_eq!(input.token.policy, WaitPolicy::Native);
                                assert!(input.token.ptracer_owner.is_none());
                                assert_eq!(terminal.queued_raw_statuses(), before);
                                assert_eq!(
                                    original.event().exit_epoch.load(Ordering::Acquire),
                                    epoch
                                );
                                assert_eq!(
                                    legacy_owner_observe(replacement, WaitPidFlag::WSTOPPED),
                                    stop,
                                    "first conversion consumed B's actual report"
                                );
                            }
                            if !realign_proc {
                                assert_eq!(
                                    unsafe {
                                        libc::mount(
                                            c"proc".as_ptr(),
                                            c"/proc".as_ptr(),
                                            c"proc".as_ptr(),
                                            0,
                                            std::ptr::null(),
                                        )
                                    },
                                    0
                                );
                            }
                            legacy_owner_finish_replacement(replacement, replacement_cleanup, stop);
                            assert!(host.is_live().unwrap());
                            assert_eq!(original.current_tracer_pid(), Ok(host.tid));
                            assert_eq!(terminal.queued_raw_statuses(), before);
                            println!(
                                "EXPLICIT_NATIVE_FIRST_BINDING_REFUSAL realigned={realign_proc} original_tracer_live=true original_generic_stop_queued=true first_owner=EXDEV zero_tracer_owner=EXDEV original_fifo_preserved=true replacement_stop_preserved=true actual_replacement_exit=42"
                            );
                        });
                        proof.join().unwrap();
                        unsafe { libc::_exit(0) };
                    }
                };
                let status = waitpid_status_bounded(inner, 0, TRACEE_WAIT_TIMEOUT).unwrap();
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                unsafe { libc::_exit(0) };
            }
        };
        let status = waitpid_status_bounded(intermediate, 0, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(terminal.queued_raw_statuses(), queued);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        // A foreign same-namespace constructor also retains owner=None and
        // the same input through its refusal. Return THAT driver to A and
        // finish the already-published original status without recapture.
        let foreign_generation = generation.clone();
        let mut driver = thread::spawn(move || {
            let mut driver = running.wait_owned_on_ptracer_thread().into_driver();
            assert!(driver.affinity.owner.is_none());
            let waker = futures::task::noop_waker();
            for _ in 0..2 {
                assert!(matches!(
                    driver.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                    Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                ));
                assert!(driver.affinity.owner.is_none());
                assert_eq!(driver.generation(), Some(foreign_generation.clone()));
            }
            driver
        })
        .join()
        .unwrap();
        assert!(driver.affinity.owner.is_none());
        let (stopped, event) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            futures::future::poll_fn(|cx| driver.poll_on_ptracer_thread(cx)),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert_eq!(stopped.1.event(), &original);
        assert!(
            stopped
                .1
                .ptracer_owner
                .as_ref()
                .unwrap()
                .is_current()
                .unwrap()
        );
        assert_eq!(stopped.generation(), generation);
        assert!(terminal.queued_raw_statuses().is_empty());
        let local_untraced = Running::new_on_ptracer_thread(root.into()).unwrap();
        assert_eq!(local_untraced.generation(), untraced_generation);
        assert!(
            local_untraced
                .1
                .ptracer_owner
                .as_ref()
                .unwrap()
                .is_current()
                .unwrap()
        );
        assert_eq!(
            local_untraced
                .1
                .event()
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        drop(local_untraced);
        drop(untraced);
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (tid.into(), crate::ExitStatus::Exited(23))
        );
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(
            terminal.observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_untraced_nonleader_constructor_retains_original_host() {
    const NAME: &str = "explicit_untraced_nonleader_constructor_retains_original_host";
    const MARKER: &str = "ACTUAL_EXPLICIT_UNTRACED_NONLEADER_CONSTRUCTOR_EXERCISED";
    if run_legacy_test_outer_with_outcome(NAME, Some(MARKER)) {
        return;
    }
    for forced in [false, true] {
        let (root, tid, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let running = Running::new_on_ptracer_thread(tid.into()).unwrap();
        let generation = running.generation();
        let identity = running.1.event().identity().unwrap();
        assert_eq!(identity.current_tracer_pid(), Ok(super::Pid::from_raw(0)));
        assert!(
            running
                .1
                .ptracer_owner
                .as_ref()
                .unwrap()
                .is_current()
                .unwrap()
        );
        assert_eq!(
            running
                .1
                .event()
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        if forced {
            assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
        }
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        assert_eq!(running.generation(), generation);
        running.interrupt().unwrap();
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert_eq!(stopped.generation(), generation);
        let mut terminal = stopped.terminal_cleanup_on_ptracer_thread().into_driver();
        let native = terminal.shared().has_thread_pidfd().unwrap();
        if forced {
            assert!(!native);
        }
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        drop(running);
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (tid.into(), crate::ExitStatus::Exited(23))
        );
        assert!(
            terminal
                .wait_on_ptracer_thread(TRACEE_WAIT_TIMEOUT)
                .unwrap()
        );
        assert_eq!(
            terminal.shared().observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        legacy_owner_reap_root(root, &mut root_cleanup);
        assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
        println!(
            "EXPLICIT_UNTRACED_NONLEADER native={native} forced={forced} original_host_retained=true original_generation_preserved=true actual_exit=23 done=true root_reaped=true member_absent=true"
        );
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_untraced_wait_requires_original_parent_role() {
    const NAME: &str = "explicit_untraced_wait_requires_original_parent_role";
    const MARKER: &str = "ACTUAL_EXPLICIT_UNTRACED_WAIT_ROLE_EXERCISED";
    const NATIVE_MARKER: &str = "ACTUAL_EXPLICIT_GENERIC_NATIVE_WAIT_ROLE_REFUSAL_EXERCISED";
    if run_explicit_wait_role_outer(NAME, MARKER, "UNTRACED_WAIT_ROLE_REFUSAL ") {
        return;
    }
    let mut native_control_exercised = false;
    for forced in [false, true] {
        let (root, member, release, mut root_cleanup) = legacy_owner_guest();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        // When actually supported, the first Event comes from a genuine
        // generic Native capture. Old kernels/forced EINVAL still run ALL
        // portable explicit cells; only this separate Native control differs.
        let generic = match Running::try_new(root.into()) {
            Ok(running) => {
                assert!(running.1.ptracer_owner.is_none());
                assert_eq!(running.1.policy, WaitPolicy::Native);
                assert!(running.1.event().identity().unwrap().proc_root.is_none());
                Some(running.generation())
            }
            Err(Errno::EINVAL) => None,
            Err(error) => panic!("actual generic acquisition refused unexpectedly: {error}"),
        };
        let running = Running::new_on_ptracer_thread(root.into()).unwrap();
        let original = running.1.event().clone();
        let generation = running.generation();
        let owner = running.1.ptracer_owner.clone().unwrap();
        assert!(owner.is_current().unwrap());
        assert!(running.1.ptracer_wait_role);
        assert_eq!(original.current_tracer_pid(), Ok(super::Pid::from_raw(0)));
        assert_eq!(
            retained_proc_parent(original.identity().unwrap().proc_dir.as_raw_fd()),
            Ok(owner.tgid)
        );
        let terminal = running.terminal_cleanup();
        let native = terminal.has_thread_pidfd().unwrap();
        assert_eq!(generic.is_some(), native);
        if let Some(generic) = &generic {
            assert_eq!(generic, &generation);
        }
        if forced {
            assert!(!native);
            assert!(matches!(
                original.identity().unwrap().pidfd,
                ThreadHandle::LegacyLeader { .. }
            ));
        }
        // A genuine job-control stop of A's untraced direct child is
        // published by the original descriptor waiter, before B is forked.
        pidfd_send_signal(&root_cleanup.pidfd, libc::SIGSTOP).unwrap();
        let raw_stop = (libc::SIGSTOP << 8) | 0x7f;
        legacy_owner_until(|| terminal.queued_raw_statuses() == vec![raw_stop]);
        let epoch = original.event().exit_epoch.load(Ordering::Acquire);
        let child = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                // B is in the SAME PID namespace and aligned proc mount.
                // Its real host identity passes the namespace guard, while
                // the retained target's real parent remains A's TGID.
                require_aligned_proc_pid_namespace().unwrap();
                assert!(owner.is_live().unwrap());
                assert!(!owner.is_current().unwrap());
                assert_eq!(original.current_tracer_pid(), Ok(super::Pid::from_raw(0)));
                assert_eq!(
                    retained_proc_parent(original.identity().unwrap().proc_dir.as_raw_fd()),
                    Ok(owner.tgid)
                );
                assert_ne!(owner.tgid, super::Pid::from(nix::unistd::getpid()));
                assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
                let mut info = mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                assert_eq!(
                    unsafe {
                        libc::waitid(
                            libc::P_PIDFD,
                            root_cleanup.pidfd.as_raw_fd() as u32,
                            info.as_mut_ptr(),
                            libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                        )
                    },
                    -1
                );
                assert_eq!(Errno::last(), Errno::ECHILD);
                // Selecting an untraced nonchild still succeeds and retains
                // the SAME original generation. Host ownership alone does
                // not authorize any of its copied cached wait results.
                let nonchild = Running::new_on_ptracer_thread(root.into()).unwrap();
                assert_eq!(nonchild.generation(), generation);
                assert!(
                    nonchild
                        .1
                        .ptracer_owner
                        .as_ref()
                        .unwrap()
                        .is_current()
                        .unwrap()
                );
                assert!(!nonchild.1.ptracer_wait_role);
                let selected = nonchild.1.clone();
                let mut sync = nonchild.wait_sync_on_ptracer_thread().into_driver();
                let mut wait = Running::from_token(root.into(), selected.clone())
                    .wait_owned_on_ptracer_thread()
                    .into_driver();
                let mut exit = Running::from_token(root.into(), selected.clone())
                    .exit_event_on_ptracer_thread()
                    .into_driver();
                let mut selected_cleanup = Running::from_token(root.into(), selected.clone())
                    .terminal_cleanup_on_ptracer_thread()
                    .into_driver();
                // This shared facade has no previous target-local role. It
                // must also refuse before minting any first local owner.
                let mut unbound_cleanup = terminal.on_ptracer_thread().into_driver();
                assert!(unbound_cleanup.affinity.owner.is_none());
                let mut generic_wait = generic.as_ref().map(|generation| {
                    generation
                        .assume_stopped()
                        .wait_owned_on_ptracer_thread()
                        .into_driver()
                });
                let waker = futures::task::noop_waker();
                for _ in 0..2 {
                    if let Some(wait) = &mut generic_wait {
                        assert!(matches!(
                            wait.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                            Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                        ));
                        assert!(wait.affinity.owner.is_none());
                        assert!(!wait.affinity.wait_role);
                        let input = wait.inner.inner.as_ref().unwrap();
                        assert_eq!(input.token.event(), &original);
                        assert_eq!(input.token.policy, WaitPolicy::Native);
                        assert!(input.token.ptracer_owner.is_none());
                    }
                    assert_eq!(
                        sync.wait_on_ptracer_thread(),
                        Err(OwnedWaitError::Errno(Errno::EPERM))
                    );
                    assert!(matches!(
                        wait.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                        Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
                    ));
                    assert!(matches!(
                        exit.poll_on_ptracer_thread(&mut Context::from_waker(&waker)),
                        Poll::Ready(Err(Error::Errno(Errno::EPERM)))
                    ));
                    for cleanup in [&mut selected_cleanup, &mut unbound_cleanup] {
                        assert_eq!(cleanup.progress_on_ptracer_thread(), Err(Errno::EPERM));
                        assert_eq!(
                            cleanup.wait_on_ptracer_thread(Duration::ZERO),
                            Err(Errno::EPERM)
                        );
                        assert!(matches!(
                            cleanup.reserve_pending_on_ptracer_thread(Duration::ZERO),
                            Err(Errno::EPERM)
                        ));
                        assert!(!cleanup.affinity.wait_role);
                    }
                    assert!(unbound_cleanup.affinity.owner.is_none());
                    assert!(!wait.affinity.wait_role);
                    assert!(!exit.affinity.wait_role);
                    let input = sync.input.as_ref().unwrap();
                    assert_eq!(input.1.event(), &original);
                    assert!(!input.1.ptracer_wait_role);
                    assert_eq!(wait.generation(), Some(generation.clone()));
                    assert_eq!(terminal.queued_raw_statuses(), vec![raw_stop]);
                    assert_eq!(original.event().exit_epoch.load(Ordering::Acquire), epoch);
                }
                println!(
                    "UNTRACED_WAIT_ROLE_REFUSAL native={native} forced={forced} same_namespace=true real_parent={} current_tgid={} kernel_wait=ECHILD constructor_retained=true named_waits=EPERM original_fifo_preserved=true original_epoch_preserved=true",
                    owner.tgid,
                    nix::unistd::getpid()
                );
                unsafe { libc::_exit(0) };
            }
        };
        let status = waitpid_status_bounded(child, 0, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(terminal.queued_raw_statuses(), vec![raw_stop]);
        assert_eq!(original.event().exit_epoch.load(Ordering::Acquire), epoch);
        // A, the genuine original parent thread, still claims THAT stop.
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        assert_eq!(stopped.generation(), generation);
        assert!(stopped.1.ptracer_wait_role);
        assert!(terminal.queued_raw_statuses().is_empty());
        pidfd_send_signal(&root_cleanup.pidfd, libc::SIGCONT).unwrap();
        pidfd_send_signal(&root_cleanup.pidfd, libc::SIGKILL).unwrap();
        let (pid, status) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, stopped.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_exited();
        assert_eq!(pid, root.into());
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(terminal.observed_exit_status(), Ok(Some(status)));
        root_cleanup.disarm();
        drop(release);
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{member}")).exists());
        native_control_exercised |= generic.is_some();
    }
    if native_control_exercised {
        emit_completion_marker(NATIVE_MARKER);
    } else {
        println!("NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_WAIT_ROLE_CONTROL");
    }
    emit_completion_marker(MARKER);
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn explicit_untraced_nonchild_constructor_can_attach() {
    const NAME: &str = "explicit_untraced_nonchild_constructor_can_attach";
    const MARKER: &str = "ACTUAL_EXPLICIT_UNTRACED_NONCHILD_ATTACH_EXERCISED";
    if run_explicit_wait_role_outer(NAME, MARKER, "UNTRACED_NONCHILD_ATTACH ") {
        return;
    }
    for forced in [false, true] {
        let [receipt, send_receipt] = legacy_pipe();
        let [start, release] = legacy_pipe();
        let [natural_receipt, send_natural_receipt] = legacy_pipe();
        let parent = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                let child = match unsafe { fork() }.unwrap() {
                    ForkResult::Parent { child } => child,
                    ForkResult::Child => {
                        let pid = nix::unistd::getpid().as_raw();
                        assert_eq!(
                            unsafe {
                                libc::write(
                                    send_receipt.as_raw_fd(),
                                    (&pid as *const i32).cast(),
                                    4,
                                )
                            },
                            4
                        );
                        let mut byte = 0u8;
                        assert_eq!(
                            unsafe {
                                libc::read(start.as_raw_fd(), (&mut byte as *mut u8).cast(), 1)
                            },
                            1
                        );
                        unsafe { libc::_exit(23) };
                    }
                };
                let status = waitpid_status_bounded(child, 0, TRACEE_WAIT_TIMEOUT).unwrap();
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 23);
                assert_eq!(
                    unsafe {
                        libc::write(
                            send_natural_receipt.as_raw_fd(),
                            (&status as *const i32).cast(),
                            4,
                        )
                    },
                    4
                );
                unsafe { libc::_exit(0) };
            }
        };
        drop((send_receipt, start, send_natural_receipt));
        let mut parent_cleanup = TraceeCleanupGuard::new(parent).unwrap();
        let mut readiness = libc::pollfd {
            fd: receipt.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut readiness, 1, TRACEE_WAIT_TIMEOUT.as_millis() as i32) },
            1
        );
        let mut bytes = [0u8; 4];
        fs::File::from(receipt).read_exact(&mut bytes).unwrap();
        let child = Pid::from_raw(i32::from_ne_bytes(bytes));
        let mut child_cleanup = TraceeCleanupGuard::new(child).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(child));
        let running = Running::new_on_ptracer_thread(child.into()).unwrap();
        let generation = running.generation();
        let owner = running.1.ptracer_owner.as_ref().unwrap();
        assert!(owner.is_current().unwrap());
        assert!(!running.1.ptracer_wait_role);
        assert!(
            generation
                .retained_ptracer_thread_guard()
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            generation.ptracer_thread_guard_for_wait(),
            Err(Errno::EPERM)
        ));
        assert!(!running.1.ptracer_wait_role);
        assert_eq!(
            running.1.event().current_tracer_pid(),
            Ok(super::Pid::from_raw(0))
        );
        assert_eq!(
            retained_proc_parent(running.1.event().identity().unwrap().proc_dir.as_raw_fd()),
            Ok(parent.into())
        );
        let mut refused = running.wait_sync_on_ptracer_thread().into_driver();
        for _ in 0..2 {
            assert_eq!(
                refused.wait_on_ptracer_thread(),
                Err(OwnedWaitError::Errno(Errno::EPERM))
            );
            assert!(!refused.input.as_ref().unwrap().1.ptracer_wait_role);
        }
        // Host selection of an untraced nonchild has preserved its original
        // generation. A successful actual SEIZE now establishes wait role.
        let running =
            Running::seize_on_ptracer_thread(child.into(), legacy_thread_options()).unwrap();
        assert_eq!(running.generation(), generation);
        assert!(running.1.ptracer_wait_role);
        let controller = running
            .generation()
            .retained_ptracer_thread_guard()
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(
            &controller.owner,
            running.1.ptracer_owner.as_ref().unwrap()
        ));
        assert_eq!(controller.check_current(), Ok(()));
        running.interrupt().unwrap();
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        assert!(stopped.1.ptracer_wait_role);
        let mut cleanup = stopped.terminal_cleanup_on_ptracer_thread().into_driver();
        let native = cleanup.shared().has_thread_pidfd().unwrap();
        if forced {
            assert!(!native);
        }
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        assert_eq!(
            unsafe { libc::write(release.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stopped.getevent().unwrap(), 23 << 8);
        assert!(stopped.1.ptracer_wait_role);
        drop(running);
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (child.into(), crate::ExitStatus::Exited(23))
        );
        assert!(cleanup.wait_on_ptracer_thread(TRACEE_WAIT_TIMEOUT).unwrap());
        assert_eq!(
            cleanup.shared().observed_exit_status(),
            Ok(Some(crate::ExitStatus::Exited(23)))
        );
        let mut readiness = libc::pollfd {
            fd: natural_receipt.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut readiness, 1, TRACEE_WAIT_TIMEOUT.as_millis() as i32) },
            1
        );
        fs::File::from(natural_receipt)
            .read_exact(&mut bytes)
            .unwrap();
        let natural = i32::from_ne_bytes(bytes);
        assert!(libc::WIFEXITED(natural));
        assert_eq!(libc::WEXITSTATUS(natural), 23);
        let status = waitpid_status_bounded(parent, 0, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        parent_cleanup.disarm();
        child_cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{child}")).exists());
        assert!(!std::path::Path::new(&format!("/proc/{parent}")).exists());
        println!(
            "UNTRACED_NONCHILD_ATTACH native={native} forced={forced} constructor_retained=true pre_attach_wait=EPERM same_generation=true actual_seize=true actual_exit=23 done=true natural_parent_reaped=true"
        );
    }
    emit_completion_marker(MARKER);
}

#[cfg(not(sanitized))]
fn run_explicit_wait_role_outer(name: &str, marker: &str, cell_prefix: &str) -> bool {
    const INNER: &str = "SAFEPTRACE_LEGACY_THREAD_INNER";
    if env::var(INNER).as_deref() == Ok(name) {
        return false;
    }
    let result = run_exact_test_bounded(
        &format!("notifier::test::{name}"),
        &[(INNER, name)],
        false,
        Duration::from_secs(5),
    )
    .expect("start bounded original wait-role control");
    assert!(!result.timed_out, "wait-role control timed out: {result:?}");
    assert!(
        result.output.status.success(),
        "wait-role control failed: {result:?}"
    );
    let stdout = String::from_utf8_lossy(&result.output.stdout);
    assert_eq!(stdout.lines().filter(|line| *line == marker).count(), 1);
    let cells: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with(cell_prefix))
        .collect();
    assert_eq!(
        cells.len(),
        2,
        "missing actual normal/forced cells: {stdout}"
    );
    for forced in [false, true] {
        assert_eq!(
            cells
                .iter()
                .filter(|line| line.contains(&format!("forced={forced}")))
                .count(),
            1
        );
    }
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&result.output.stderr));
    true
}
