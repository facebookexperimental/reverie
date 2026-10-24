/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(not(sanitized))]
#[test]
fn stop_authentication_is_shared_and_revalidated_after_real_transitions() {
    const NAME: &str = "stop_authentication_is_shared_and_revalidated_after_real_transitions";
    if run_legacy_test_outer_with_outcome(
        NAME,
        Some("ACTUAL_STOP_AUTHENTICATION_CACHE_TRANSITIONS_EXERCISED"),
    ) {
        return;
    }
    for forced in [false, true] {
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                unsafe {
                    libc::raise(libc::SIGTRAP);
                    libc::_exit(23);
                }
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let original = stopped.1.event().clone();
        // Force both optional descriptor proofs to refuse. The unchanged
        // exact read counts below then exercise the strong directory/status
        // fallback and its real transition invalidation on either kernel.
        stopped
            .1
            .ptracer_owner
            .as_ref()
            .unwrap()
            .force_directory_proof
            .store(true, Ordering::Relaxed);
        original
            .event()
            .numeric_auth_force_directory
            .store(true, Ordering::Relaxed);
        let generation = stopped.generation();
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            0
        );
        let registers = stopped.getregs().unwrap();
        for _ in 0..128 {
            assert_eq!(stopped.getregs().unwrap(), registers);
            assert_eq!(stopped.getsiginfo().unwrap().si_signo, libc::SIGSTOP);
        }
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            1
        );
        stopped
            .setoptions(Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXIT)
            .unwrap();
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            1
        );

        // SINGLESTEP and SYSCALL each resume the real stop. Their actual
        // consumed reports must require a new full proof, even though the
        // generation, ptracer and retained proc directory remain the same.
        let running = stopped.step(None).unwrap();
        let (stopped, event) = running
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGTRAP));
        assert_eq!(stopped.generation(), generation);
        let registers = stopped.getregs().unwrap();
        for _ in 0..128 {
            assert_eq!(stopped.getregs().unwrap(), registers);
        }
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            2
        );

        let running = stopped.syscall(None).unwrap();
        let (stopped, event) = running
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        assert_eq!(event, crate::Event::Syscall);
        assert_eq!(stopped.generation(), generation);
        let registers = stopped.getregs().unwrap();
        for _ in 0..128 {
            assert_eq!(stopped.getregs().unwrap(), registers);
        }
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            3
        );

        // DETACH invalidates the proof too and returns reaping to the real
        // parent. The original descriptor still supplies exact cleanup.
        let epoch = original.event().numeric_auth_epoch.load(Ordering::Acquire);
        let _detached = stopped.detach(Signal::SIGKILL).unwrap();
        assert_ne!(
            original.event().numeric_auth_epoch.load(Ordering::Acquire),
            epoch
        );
        let terminal = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSIGNALED(terminal));
        assert_eq!(libc::WTERMSIG(terminal), libc::SIGKILL);
        cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
    }
    emit_completion_marker("ACTUAL_STOP_AUTHENTICATION_CACHE_TRANSITIONS_EXERCISED");
}

#[cfg(not(sanitized))]
#[test]
fn retained_descriptor_proofs_authenticate_the_real_owner_and_target() {
    const NAME: &str = "retained_descriptor_proofs_authenticate_the_real_owner_and_target";
    if run_legacy_test_outer_with_outcome(
        NAME,
        Some("ACTUAL_RETAINED_DESCRIPTOR_AUTHENTICATION_EXERCISED"),
    ) {
        return;
    }
    for forced in [false, true] {
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                unsafe {
                    libc::_exit(23);
                }
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let original = stopped.1.event().clone();
        let owner = stopped.1.ptracer_owner.as_ref().unwrap();
        let owner_fd = owner
            .self_signal_fd
            .as_ref()
            .expect("real cold descriptor proof");
        assert!(descriptor_is_current_task(owner_fd.as_raw_fd()));
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(!descriptor_is_current_task(owner_fd.as_raw_fd()));
                    assert!(!owner.is_current().unwrap());
                })
                .join()
                .unwrap();
        });
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        let registers = stopped.getregs().unwrap();
        for _ in 0..128 {
            assert_eq!(stopped.getregs().unwrap(), registers);
            assert_eq!(stopped.getsiginfo().unwrap().si_signo, libc::SIGSTOP);
        }
        assert_eq!(
            original
                .event()
                .numeric_auth_status_reads
                .load(Ordering::Relaxed),
            0
        );
        let _detached = stopped.detach(Signal::SIGKILL).unwrap();
        let terminal = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSIGNALED(terminal));
        assert_eq!(libc::WTERMSIG(terminal), libc::SIGKILL);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(false));
        cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
    }
    emit_completion_marker("ACTUAL_RETAINED_DESCRIPTOR_AUTHENTICATION_EXERCISED");
}

#[cfg(not(sanitized))]
#[test]
fn owned_cleanup_preserves_original_anchor_without_discarded_capture() {
    const NAME: &str = "owned_cleanup_preserves_original_anchor_without_discarded_capture";
    if run_legacy_test_outer_with_outcome(
        NAME,
        Some("ACTUAL_OWNED_CLEANUP_CAPTURE_REUSE_EXERCISED"),
    ) {
        return;
    }
    for forced in [false, true] {
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                unsafe {
                    libc::_exit(23);
                }
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let original = stopped.1.event().clone();
        let owner = stopped.1.ptracer_owner.as_ref().unwrap();
        let captures = PTRACER_OWNER_CAPTURES.with(Cell::get);
        for _ in 0..128 {
            let local = stopped.terminal_cleanup_on_ptracer_thread();
            assert!(Arc::ptr_eq(
                local.driver.affinity.owner.as_ref().unwrap(),
                owner
            ));
            assert_eq!(local.driver.affinity.wait_role, stopped.1.ptracer_wait_role);
            assert!(
                local
                    .shared()
                    .same_generation(&TerminalCleanup::new_unregistered(root.into(), &stopped.1))
            );
        }
        assert_eq!(PTRACER_OWNER_CAPTURES.with(Cell::get), captures);

        // Dropping a role witness never changes its host anchor. A passive
        // cleanup constructor must retain false, leaving first-operation
        // role authentication to the original operation path.
        let mut constructor_only = stopped.1.clone();
        constructor_only.ptracer_wait_role = false;
        let conservative = PtracerTerminalCleanup::new(root.into(), &constructor_only);
        assert!(!conservative.driver.affinity.wait_role);
        assert!(Arc::ptr_eq(
            conservative.driver.affinity.owner.as_ref().unwrap(),
            owner
        ));
        assert_eq!(PTRACER_OWNER_CAPTURES.with(Cell::get), captures);

        // A shared-only facade genuinely has no host anchor. Keep the cold
        // binding behavior instead of extending the owned-state fast path.
        let shared = TerminalCleanup::new_unregistered(root.into(), &stopped.1);
        let cold = shared.on_ptracer_thread();
        assert!(cold.driver.affinity.owner.is_some());
        assert!(cold.driver.affinity.wait_role);
        assert_eq!(PTRACER_OWNER_CAPTURES.with(Cell::get), captures + 1);
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert!(!*original.event().terminal_reaping.read());
        let registers = stopped.getregs().unwrap();
        assert_eq!(stopped.getregs().unwrap(), registers);
        assert_eq!(stopped.getsiginfo().unwrap().si_signo, libc::SIGSTOP);
        let _detached = stopped.detach(Signal::SIGKILL).unwrap();
        let terminal = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSIGNALED(terminal));
        assert_eq!(libc::WTERMSIG(terminal), libc::SIGKILL);
        cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
    }
    emit_completion_marker("ACTUAL_OWNED_CLEANUP_CAPTURE_REUSE_EXERCISED");
}

#[cfg(not(sanitized))]
#[test]
fn fresh_kernel_attachment_proof_preserves_raw_owner_handoff() {
    const NAME: &str = "fresh_kernel_attachment_proof_preserves_raw_owner_handoff";
    if run_legacy_test_outer_with_outcome(
        NAME,
        Some("ACTUAL_FRESH_KERNEL_ATTACHMENT_PROOF_EXERCISED"),
    ) {
        return;
    }
    for forced in [false, true] {
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                crate::traceme_and_stop().unwrap();
                loop {
                    unsafe { libc::pause() };
                }
            }
        };
        let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
        let _force = forced.then(|| LegacyThreadGroup::new(root));
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let original = stopped.1.event().clone();
        let owner = Arc::clone(stopped.1.ptracer_owner.as_ref().unwrap());
        assert!(stopped.1.ptracer_wait_role);
        let host_proofs = PTRACER_HOST_PROOFS.with(Cell::get);
        for _ in 0..128 {
            let affinity = PtracerAffinity::new(&original, Some(Arc::clone(&owner)), true);
            assert!(Arc::ptr_eq(affinity.owner.as_ref().unwrap(), &owner));
            assert!(affinity.wait_role);
        }
        assert_eq!(PTRACER_HOST_PROOFS.with(Cell::get), host_proofs);
        // A constructor-only role still makes its original eager check and
        // promotion, rather than sharing the established-role optimization.
        let conservative = PtracerAffinity::new(&original, Some(Arc::clone(&owner)), false);
        assert!(conservative.wait_role);
        assert_eq!(PTRACER_HOST_PROOFS.with(Cell::get), host_proofs + 1);
        let mut affinity = PtracerAffinity::new(&original, Some(Arc::clone(&owner)), true);
        affinity.check_host(&original).unwrap();
        let reads = PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get);
        let epoch = original.event().numeric_auth_epoch.load(Ordering::Acquire);
        let registers = stopped.getregs().unwrap();
        for _ in 0..128 {
            affinity.check_attachment(&original).unwrap();
            assert_eq!(stopped.getregs().unwrap(), registers);
            assert_eq!(stopped.getsiginfo().unwrap().si_signo, libc::SIGSTOP);
        }
        assert_eq!(PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get), reads);
        assert_eq!(
            original.event().numeric_auth_epoch.load(Ordering::Acquire),
            epoch
        );

        // Deliberately use raw requests: no SDK epoch invalidation can hide
        // stale ownership. The same live target is now seized by a sibling.
        nix::sys::ptrace::detach(root, None).unwrap();
        let (ready, received) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let copied = original.clone();
        let copied_owner = Arc::clone(&owner);
        let sibling = thread::spawn(move || {
            let mut foreign = PtracerAffinity::new(&copied, Some(copied_owner), true);
            assert_eq!(foreign.check_host(&copied), Err(Errno::EPERM));
            assert!(foreign.wait_role);
            nix::sys::ptrace::seize(root, Options::PTRACE_O_EXITKILL).unwrap();
            nix::sys::ptrace::interrupt(root).unwrap();
            let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
            assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
            let registers = nix::sys::ptrace::getregs(root).unwrap();
            let info = nix::sys::ptrace::getsiginfo(root).unwrap();
            assert!(nix::sys::ptrace::getevent(root).is_ok());
            ready.send(super::Pid::from(nix::unistd::gettid())).unwrap();
            released.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
            assert_eq!(nix::sys::ptrace::getregs(root).unwrap(), registers);
            let after = nix::sys::ptrace::getsiginfo(root).unwrap();
            assert_eq!(
                (after.si_signo, after.si_code),
                (info.si_signo, info.si_code)
            );
            nix::sys::ptrace::detach(root, None).unwrap();
        });
        let current = received.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
        assert_ne!(current, owner.tid);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        assert_eq!(
            original.event().numeric_auth_epoch.load(Ordering::Acquire),
            epoch
        );
        for iteration in 1..=2 {
            affinity.check_host(&original).unwrap();
            assert_eq!(affinity.check_attachment(&original), Err(Errno::EPERM));
            assert_eq!(
                PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get),
                reads + iteration
            );
            assert!(Arc::ptr_eq(affinity.owner.as_ref().unwrap(), &owner));
            assert!(affinity.wait_role);
            assert_eq!(
                original.event().numeric_auth_epoch.load(Ordering::Acquire),
                epoch
            );
            assert!(original.event().pending_is_empty());
        }
        release.send(()).unwrap();
        sibling.join().unwrap();

        // The original owner regains a real stop on the SAME live generation.
        nix::sys::ptrace::seize(root, Options::PTRACE_O_EXITKILL).unwrap();
        nix::sys::ptrace::interrupt(root).unwrap();
        let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert_eq!(status >> 16, libc::PTRACE_EVENT_STOP);
        affinity.check_host(&original).unwrap();
        affinity.check_attachment(&original).unwrap();
        assert_eq!(PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get), reads + 2);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(true));
        assert_eq!(
            original.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert!(!*original.event().terminal_reaping.read());
        // EVENT_STOP is not a signal-delivery stop. Detach first, then send
        // real SIGKILL through the retained descriptor instead of relying on
        // DETACH's signal argument to inject it at that synthetic stop.
        let _detached = stopped.detach(None).unwrap();
        pidfd_send_signal(&original.identity().unwrap().pidfd, libc::SIGKILL).unwrap();
        let terminal = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSIGNALED(terminal));
        assert_eq!(libc::WTERMSIG(terminal), libc::SIGKILL);
        assert_eq!(original.identity().unwrap().pidfd_is_live(), Ok(false));
        cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
    }
    emit_completion_marker("ACTUAL_FRESH_KERNEL_ATTACHMENT_PROOF_EXERCISED");
}
