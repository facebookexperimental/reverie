/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the LICENSE file.
 */
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-925): https://github.com/rrnewton/reverie/issues/916.
use super::*;

fn executor() -> ElfExecutor {
    ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new("/tmp")),
        true,
    )
}
fn adopt(executor: &ElfExecutor) -> Arc<crate::failure::RunFailure> {
    executor
        .backend_signal_control()
        .process
        .enable_parent_death_control()
        .unwrap();
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    executor.install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &run);
    run
}
fn permit(executor: &ElfExecutor, sequence: u64) -> reverie::SignalDeliveryPermit {
    let permit = reverie::SignalDeliveryPermit {
        task: executor.signal_task_identity().unwrap(),
        sequence,
        site: None,
    };
    executor
        .backend_signal_control()
        .process
        .reserve_delivery(permit)
        .unwrap();
    permit
}
fn publish(executor: &ElfExecutor, permit: reverie::SignalDeliveryPermit, exit: ToolProcessExit) {
    let boundary = reverie::SignalBoundaryReceipt {
        permit,
        outcome: exit.signal_boundary_outcome(),
    };
    let outcome = executor
        .backend_signal_control()
        .process
        .publish_parent_death(boundary);
    let reverie::ParentDeathPublicationResult::Committed(receipt) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(receipt.boundary, boundary);
    assert_eq!(receipt.batches.len(), 1);
    assert!(receipt.signals.is_empty());
    executor.check_parent_death_boundary(boundary).unwrap();
    executor
        .backend_signal_control()
        .process
        .release_delivery(permit)
        .unwrap();
}

#[test]
fn finalizer_uses_established_group_winner_for_batch_and_terminal_receipt() {
    let mut leader = executor();
    let _run = adopt(&leader);
    let mut follower = leader.thread_child(2).unwrap();
    let first = permit(&leader, 1);
    let winner = leader.retire_guest_thread(ExitStatus::Exited(29), true);
    publish(&leader, first, winner.into());
    let next = permit(&follower, 2);
    let mut outcome: ToolProcessExit = ProcessExit {
        status: ExitStatus::Exited(37),
        group: true,
    }
    .into();
    // This is the exact finalizer helper, not a separately reconstructed batch.
    outcome.commit_guest_death(&mut follower);
    assert_eq!(outcome.exit.status, ExitStatus::Exited(29));
    assert_eq!(
        outcome.signal_boundary_outcome(),
        reverie::SignalBoundaryOutcome::Terminated {
            group: true,
            wait_status: ExitStatus::Exited(29).into_raw(),
        }
    );
    publish(&follower, next, outcome);
}

#[test]
fn actual_group_wait_follower_with_and_without_permit_never_invents_death_authority() {
    for owns_permit in [false, true] {
        let backend = KvmBackend::new(0x10000).expect("group-wait control requires /dev/kvm");
        let mut leader = executor();
        let _run = adopt(&leader);
        let mut follower = leader.thread_child(2).unwrap();
        let first = permit(&leader, 1);
        let winner = leader.retire_guest_thread(ExitStatus::Exited(29), true);
        publish(&leader, first, winner.into());
        let next = owns_permit.then(|| permit(&follower, 2));
        // Exercise the production GroupExit callback completion path with the
        // real exact-generation winner, including the permit-free case.
        let mut outcome = backend
            .wait_group_exit_status(&mut follower, ExitStatus::Exited(29))
            .unwrap();
        assert_eq!(
            outcome.disposition,
            ToolExitDisposition::CommittedGroupFollower
        );
        assert_eq!(outcome.exit.status, ExitStatus::Exited(29));
        assert!(follower.signal_task_identity().is_none());
        outcome.commit_guest_death(&mut follower);
        follower.check_parent_death_failure().unwrap();
        if let Some(next) = next {
            publish(&follower, next, outcome);
        } else {
            assert!(follower.owned_delivery_permit().is_none());
        }
    }
}

#[test]
fn initial_exec_preflight_requires_original_context_and_keeps_enrollment_after_replacement() {
    let Some(cleanup) = crate::broker_library_tests::CleanupFixture::selected(
        "runtime::parent_death_tests::initial_exec_preflight_requires_original_context_and_keeps_enrollment_after_replacement",
    ) else {
        return;
    };
    let mut backend = KvmBackend::new(0x10000).expect("original-call control requires /dev/kvm");
    let mut executor = cleanup.executor(executor());
    let _run = adopt(&executor);
    executor.enable_signal_dequeues();
    let memory = GuestMemory::new(0, 4096).unwrap();
    executor.bind_address_space(&memory);
    let mut completed = false;
    let original = SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0]);
    let site = executor.begin_signal_callback().unwrap();
    {
        let e = StaticElfSyscallExecutor {
            backend: &mut backend,
            executor: &mut executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::InitialExec(original),
            callback_site: Some(site),
            original_syscall: None,
            signal_guard: SignalGuard::Ordinary,
            last_result: None,
            polled_read_attempt: None,
            process_completed: &mut completed,
        };
        assert_eq!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, original.into_syscall().unwrap()).unwrap(), reverie::ParentDeathSyscallAdmission::Unenrolled);
    }
    assert_eq!(
        executor.execute(
            &SyscallRequest::new(
                libc::SYS_prctl as u64,
                [
                    libc::PR_SET_PDEATHSIG as u64,
                    libc::SIGUSR1 as u64,
                    0,
                    0,
                    0,
                    0
                ]
            ),
            &memory
        ),
        0
    );
    {
        let mut e = StaticElfSyscallExecutor {
            backend: &mut backend,
            executor: &mut executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::InitialExec(original),
            callback_site: Some(site),
            original_syscall: None,
            signal_guard: SignalGuard::Ordinary,
            last_result: None,
            polled_read_attempt: None,
            process_completed: &mut completed,
        };
        assert!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, original.into_syscall().unwrap()).is_err(), "missing original is not an unenrolled proof");
        assert!(
            matches!(
                <StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::execute(
                    &mut e, &original, &memory
                ),
                Err(crate::Error::ParentDeathSignal { .. })
            ),
            "injection cannot bypass the enrolled synthetic-initial refusal"
        );
        assert!(e.last_result.is_none());
        e.process_context =
            ProcessExecutionContext::SyscallBoundary(CompletedSyscallBoundary::for_test());
        e.original_syscall = Some(original);
        assert!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, original.into_syscall().unwrap()).is_err(), "raw original exec without retained image is not authority");
        let ordinary = SyscallRequest::new(libc::SYS_getuid as u64, [0; 6]);
        e.original_syscall = Some(ordinary);
        assert_eq!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, ordinary.into_syscall().unwrap()).unwrap(), reverie::ParentDeathSyscallAdmission::Admitted);
        e.last_result = Some(0);
        assert!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, ordinary.into_syscall().unwrap()).is_err(), "completed injection invalidates original-call proof");
    }
    // Ordinary exec reaches ImageReplaced, not a second synthetic initial
    // syscall. The next real callback must keep enrollment with a fresh nonce.
    let old = site;
    executor.replace_after_exec(crate::executor::native_loaded_state(std::path::Path::new(
        "/tmp",
    )));
    assert!(executor.parent_death_enrolled());
    let site = executor.begin_signal_callback().unwrap();
    assert_ne!(site, old);
    let next = SyscallRequest::new(libc::SYS_getuid as u64, [0; 6]);
    assert!(
        executor
            .parent_death_original_syscall_preflight(old, &next, Some(next), false)
            .is_err()
    );
    assert_eq!(
        executor
            .parent_death_original_syscall_preflight(site, &next, Some(next), false)
            .unwrap(),
        reverie::ParentDeathSyscallAdmission::Admitted
    );
}

#[test]
fn default_preflight_refuses_but_live_unopted_static_executor_continues() {
    let mut backend = KvmBackend::new(0x10000).expect("preflight control requires /dev/kvm");
    let mut executor = executor();
    let memory = GuestMemory::new(0, 4096).unwrap();
    let mut completed = false;
    let original = SyscallRequest::new(libc::SYS_getuid as u64, [0; 6]);
    let site = executor.begin_signal_callback().unwrap();
    {
        let mut e = StaticElfSyscallExecutor {
            backend: &mut backend,
            executor: &mut executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::SyscallBoundary(
                CompletedSyscallBoundary::for_test(),
            ),
            callback_site: Some(site),
            original_syscall: Some(original),
            signal_guard: SignalGuard::Ordinary,
            last_result: None,
            polled_read_attempt: None,
            process_completed: &mut completed,
        };
        assert_eq!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, original.into_syscall().unwrap()).unwrap(), reverie::ParentDeathSyscallAdmission::Unenrolled);
        assert_eq!(
            <StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::execute(
                &mut e, &original, &memory
            )
            .unwrap(),
            0
        );
    }
    for (signal, expected) in [(0, 0), (libc::SIGUSR1, -i64::from(libc::ENOSYS))] {
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(
                    libc::SYS_prctl as u64,
                    [libc::PR_SET_PDEATHSIG as u64, signal as u64, 0, 0, 0, 0]
                ),
                &memory
            ),
            expected
        );
    }
    let mut fail_on_injection = |_request: &SyscallRequest, _memory: &GuestMemory| -> i64 {
        panic!("unsupported executor preflight performed injection")
    };
    let direct = DirectSyscallExecutor {
        executor: &mut fail_on_injection,
        vcpu: &backend.vcpu,
    };
    assert!(matches!(
        <DirectSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &direct,
            original.into_syscall().unwrap()
        ),
        Err(reverie::Error::Errno(Errno::ENOSYS))
    ));
}

#[test]
fn original_exec_callback_drop_revokes_staged_image_without_injection() {
    let Some(cleanup) = crate::broker_library_tests::CleanupFixture::selected(
        "runtime::parent_death_tests::original_exec_callback_drop_revokes_staged_image_without_injection",
    ) else {
        return;
    };
    use std::io::Write;
    use std::os::fd::FromRawFd;
    // A parsed static ELF header suffices for this admission/teardown test;
    // ordinary loader errors remain possible and no image is executed here.
    let mut image = vec![0_u8; 64];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    image[16..18].copy_from_slice(&2_u16.to_le_bytes());
    image[18..20].copy_from_slice(&62_u16.to_le_bytes());
    image[20..24].copy_from_slice(&1_u32.to_le_bytes());
    image[52..54].copy_from_slice(&64_u16.to_le_bytes());
    image[54..56].copy_from_slice(&56_u16.to_le_bytes());
    let raw =
        unsafe { libc::memfd_create(c"pdeath-exec-lifetime-test".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: memfd_create transferred one new owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    file.write_all(&image).unwrap();
    let mut state = crate::executor::native_loaded_state(std::path::Path::new("/tmp"));
    state.executable_file = Some(Arc::new(file));
    state.executable_image = Arc::from(image);
    let mut executor = cleanup.executor(ElfExecutor::new(state, true));
    let _run = adopt(&executor);
    let mut backend =
        KvmBackend::new(0x10000).expect("callback teardown control requires /dev/kvm");
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    memory.write(0x100, b"/proc/self/exe\0").unwrap();
    assert_eq!(
        executor.execute(
            &SyscallRequest::new(
                libc::SYS_prctl as u64,
                [
                    libc::PR_SET_PDEATHSIG as u64,
                    libc::SIGUSR1 as u64,
                    0,
                    0,
                    0,
                    0
                ]
            ),
            &memory
        ),
        0
    );
    executor.bind_address_space(&memory);
    let mut completed = false;
    let original = SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0, 0, 0, 0, 0]);
    let site = executor.begin_signal_callback().unwrap();
    {
        let e = StaticElfSyscallExecutor {
            backend: &mut backend,
            executor: &mut executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::SyscallBoundary(
                CompletedSyscallBoundary::for_test(),
            ),
            callback_site: Some(site),
            original_syscall: Some(original),
            signal_guard: SignalGuard::Ordinary,
            last_result: None,
            polled_read_attempt: None,
            process_completed: &mut completed,
        };
        assert_eq!(<StaticElfSyscallExecutor<'_> as GuestSyscallExecutor<()>>::parent_death_syscall_preflight(
            &e, original.into_syscall().unwrap()).unwrap(), reverie::ParentDeathSyscallAdmission::Admitted);
        // Model an early Tool mode refusal/cancelled callback: no injection.
    }
    assert!(
        executor.signal_task_identity().is_some(),
        "task remains live; it is the callback authority that ended"
    );
    assert!(
        executor
            .parent_death_original_syscall_preflight(site, &original, Some(original), false)
            .is_err()
    );
    assert!(matches!(
        executor.execute_checked(&original, &memory),
        Err(crate::Error::ParentDeathSignal { .. })
    ));
    assert!(!completed);
}
