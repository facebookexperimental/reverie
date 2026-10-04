/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn read_zero_alias_fixture(
    endpoint: std::fs::File,
    rebound: bool,
) -> (ElfExecutor, GuestMemory, i32) {
    let mut state = test_state(&std::env::current_dir().unwrap());
    state.stdin = Some(endpoint);
    let mut executor = ElfExecutor::new(state, false);
    let memory = read_zero_memory();
    let alias = executor.execute(&SyscallRequest::new(libc::SYS_dup as u64, [0; 6]), &memory);
    assert_eq!(alias, 3);
    let fd = if rebound {
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_dup2 as u64, [alias as u64, 0, 0, 0, 0, 0]),
                &memory,
            ),
            0
        );
        assert_eq!(
            executor.execute(
                &SyscallRequest::new(libc::SYS_close as u64, [alias as u64, 0, 0, 0, 0, 0]),
                &memory,
            ),
            0
        );
        0
    } else {
        alias as i32
    };
    assert!(executor.state.files.contains_key(&fd));
    assert!(!is_open_standard(&executor.state, fd));
    (executor, memory, fd)
}

struct ReadZeroEntry {
    raw: i32,
    status_flags: i32,
    descriptor_flags: i32,
    entry: Arc<()>,
    object: Option<Arc<GuestFileIdentity>>,
    cloexec: bool,
    closed_standard: bool,
}

impl ReadZeroEntry {
    fn capture(state: &LoadedStaticElf, fd: i32) -> Self {
        let raw = state.files[&fd].as_raw_fd();
        let status_flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert!(status_flags >= 0 && descriptor_flags >= 0);
        Self {
            raw,
            status_flags,
            descriptor_flags,
            entry: state.fd_entry_ids[&fd].clone(),
            object: state.fd_object_inodes.get(&fd).cloned(),
            cloexec: state.cloexec_fds.contains(&fd),
            closed_standard: state.closed_standard_fds.contains(&fd),
        }
    }

    fn assert_unchanged(&self, state: &LoadedStaticElf, fd: i32) {
        assert_eq!(state.files[&fd].as_raw_fd(), self.raw);
        assert_eq!(
            unsafe { libc::fcntl(self.raw, libc::F_GETFL) },
            self.status_flags
        );
        assert_eq!(
            unsafe { libc::fcntl(self.raw, libc::F_GETFD) },
            self.descriptor_flags
        );
        assert!(Arc::ptr_eq(&state.fd_entry_ids[&fd], &self.entry));
        match (&self.object, state.fd_object_inodes.get(&fd)) {
            (Some(before), Some(after)) => assert!(Arc::ptr_eq(before, after)),
            (None, None) => {}
            _ => panic!("zero read changed descriptor object metadata"),
        }
        assert_eq!(state.cloexec_fds.contains(&fd), self.cloexec);
        assert_eq!(
            state.closed_standard_fds.contains(&fd),
            self.closed_standard
        );
    }
}

fn read_zero_blocking_inotify() -> std::fs::File {
    let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(raw >= 0);
    // SAFETY: successful inotify_init1 transfers one owned descriptor.
    unsafe { std::fs::File::from_raw_fd(raw) }
}

// Public scalar dispatch refuses these potentially blocking endpoints before
// injection; the real Direct/Tool guests independently require that refusal.
// These lifecycle controls explicitly admit one exact owned fd under cfg(test)
// so the real dispatcher still exercises table install, lock release, file
// retirement, and reader ownership. This is not supported guest execution.
fn read_zero_alias_with_test_admission(
    executor: &mut ElfExecutor,
    request: &SyscallRequest,
    memory: &GuestMemory,
    context: &mut crate::terminal_read::ReadContext,
) -> crate::Result<i64> {
    assert_eq!(request.number(), libc::SYS_read as u64);
    assert_eq!(request.args()[2], 0);
    let fd = request.args()[0] as libc::c_int;
    let host_fd = executor.state.files[&fd].as_raw_fd();
    struct Admission;
    impl Drop for Admission {
        fn drop(&mut self) {
            TEST_ZERO_READ_ADMISSION.with(|admitted| admitted.set(None));
        }
    }
    TEST_ZERO_READ_ADMISSION.with(|admitted| {
        assert_eq!(admitted.get(), None, "nested test admission");
        admitted.set(Some(host_fd));
    });
    let admission = Admission;
    let result = executor.execute_checked_with_read_context(request, memory, context);
    drop(admission);
    TEST_ZERO_READ_ADMISSION.with(|admitted| assert_eq!(admitted.get(), None));
    result
}

fn read_zero_alias_blocked_disposal(observer_panic: bool) {
    for rebound in [false, true] {
        let (mut executor, memory, fd) =
            read_zero_alias_fixture(read_zero_blocking_inotify(), rebound);
        let before = ReadZeroEntry::capture(&executor.state, fd);
        assert_eq!(before.status_flags & libc::O_NONBLOCK, 0);
        let shared_raw = executor.file_table.lock().unwrap().files[&fd].as_raw_fd();
        let request = SyscallRequest::new(
            libc::SYS_read as u64,
            [READ_ZERO_HIGH_FD | fd as u64, READ_ZERO_BUFFER, 0, 0, 0, 0],
        );
        let identity = executor.admitted_signal_identity();
        let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
        let observed = Arc::new(Mutex::new(None));
        let stop = registry.clone();
        let evidence = observed.clone();
        let table = executor.file_table.clone();
        let transaction = executor.state.signal_transaction.clone();
        let host_fd = before.raw;
        let mut polls = 0;
        let failure = Box::pin(std::future::poll_fn(move |_| {
            polls += 1;
            if polls == 2 {
                assert!(
                    table.try_lock().is_ok(),
                    "read retained the shared table lock"
                );
                assert!(
                    transaction.try_lock().is_ok(),
                    "read retained the signal lock"
                );
                *evidence.lock().unwrap() =
                    Some(stop.observe_blocked_test_read(identity, request, host_fd));
                if observer_panic {
                    std::panic::resume_unwind(Box::new("alias terminal observer poll"));
                }
                stop.request_exit_group(reverie::ExitStatus::Exited(37));
            }
            std::task::Poll::Pending
        }));
        let panics = Arc::new(crate::failure::tool_panics::ToolPanics::default());
        let mut context = crate::terminal_read::ReadContext::new(
            registry.clone(),
            false,
            crate::entry::driver::EntryDriverWatch::for_memory(&memory),
            Some(failure),
            panics.clone(),
            false,
        );
        let result =
            read_zero_alias_with_test_admission(&mut executor, &request, &memory, &mut context);
        if observer_panic {
            assert!(matches!(
                result.unwrap_err().primary(),
                crate::Error::GuestWorkerPanic
            ));
            let payloads = panics.take();
            assert_eq!(payloads.len(), 1);
            assert_eq!(
                payloads[0].downcast_ref::<&str>(),
                Some(&"alias terminal observer poll")
            );
            assert!(matches!(
                registry.teardown_result().unwrap_err().primary(),
                crate::Error::GuestWorkerPanic
            ));
        } else {
            assert!(matches!(result, Err(crate::Error::TerminalReadCancelled)));
            registry.teardown_result().unwrap();
        }
        observed
            .lock()
            .unwrap()
            .take()
            .expect("no causal read witness")
            .assert_retired(&registry);
        before.assert_unchanged(&executor.state, fd);
        assert!(Arc::ptr_eq(
            &executor.file_table.lock().unwrap().fd_entry_ids[&fd],
            &before.entry
        ));
        assert_eq!(
            executor.file_table.lock().unwrap().files[&fd].as_raw_fd(),
            shared_raw
        );
        assert_read_zero_canaries(&memory);
    }
}

#[test]
fn read_zero_count_alias_test_admission_blocks_then_cancels_and_restores_endpoint() {
    read_zero_alias_blocked_disposal(false);
}

#[test]
fn read_zero_count_alias_test_admission_observer_panic_restores_endpoint() {
    read_zero_alias_blocked_disposal(true);
}

#[test]
fn read_zero_count_alias_native_errors_and_control_refusal_restore_entry() {
    for rebound in [false, true] {
        let raw = unsafe { libc::eventfd(9, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(raw >= 0);
        let endpoint = unsafe { std::fs::File::from_raw_fd(raw) };
        let (mut executor, memory, fd) = read_zero_alias_fixture(endpoint, rebound);
        let before = ReadZeroEntry::capture(&executor.state, fd);
        let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
        // Installing an unchanged table entry must preserve its host fd and
        // need no additional staged clone, even while clone admission refuses.
        executor.state.file_retirement.fail_clone_after(Some(0));
        for high_word in [0, READ_ZERO_HIGH_FD] {
            for address in READ_ZERO_ADDRESSES {
                let expected = native_read_zero(high_word | before.raw as u64, address);
                assert_eq!(
                    expected,
                    negative_errno(if address >= 0x8000_0000_0000_0000 {
                        libc::EFAULT
                    } else {
                        libc::EINVAL
                    })
                );
                let request = SyscallRequest::new(
                    libc::SYS_read as u64,
                    [high_word | fd as u64, address, 0, 0, 0, 0],
                );
                let mut context = read_zero_terminal_context(&memory, registry.clone());
                assert_eq!(
                    executor
                        .execute_checked_with_read_context(&request, &memory, &mut context)
                        .unwrap(),
                    expected
                );
                before.assert_unchanged(&executor.state, fd);
                assert_read_zero_canaries(&memory);
                registry.teardown_result().unwrap();
                registry.rearm_after_exec();
            }
        }
        // This is a real pre-transfer control refusal, not a fabricated errno.
        registry.exhaust_test_generations();
        let mut context = read_zero_terminal_context(&memory, registry);
        let result = executor.execute_checked_with_read_context(
            &SyscallRequest::new(
                libc::SYS_read as u64,
                [fd as u64, READ_ZERO_BUFFER, 0, 0, 0, 0],
            ),
            &memory,
            &mut context,
        );
        assert!(matches!(
            result,
            Err(crate::Error::TerminalReadControl {
                operation: "operation generation exhausted",
                ..
            })
        ));
        before.assert_unchanged(&executor.state, fd);
        executor.state.file_retirement.fail_clone_after(None);
        let mut value = 0_u64;
        assert_eq!(
            unsafe { libc::read(before.raw, (&mut value as *mut u64).cast(), 8) },
            8
        );
        assert_eq!(value, 9);
        assert_eq!(
            unsafe { libc::read(before.raw, (&mut value as *mut u64).cast(), 8) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        assert_read_zero_canaries(&memory);
    }
}

#[test]
fn read_zero_count_alias_test_admission_restore_does_not_resurrect_sibling_replacement() {
    let (mut executor, memory, fd) = read_zero_alias_fixture(read_zero_blocking_inotify(), false);
    let before = ReadZeroEntry::capture(&executor.state, fd);
    let sibling = Arc::new(Mutex::new(executor.thread_child(2).unwrap()));
    let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
    let observed = Arc::new(Mutex::new(None));
    let replaced_entry = Arc::new(Mutex::new(None));
    let request = SyscallRequest::new(
        libc::SYS_read as u64,
        [fd as u64, READ_ZERO_BUFFER, 0, 0, 0, 0],
    );
    let identity = executor.admitted_signal_identity();
    let stop = registry.clone();
    let evidence = observed.clone();
    let replaced = replaced_entry.clone();
    let other = sibling.clone();
    let shared_memory = memory.clone();
    let host_fd = before.raw;
    let mut polls = 0;
    let failure = Box::pin(std::future::poll_fn(move |_| {
        polls += 1;
        if polls == 2 {
            *evidence.lock().unwrap() =
                Some(stop.observe_blocked_test_read(identity, request, host_fd));
            let mut sibling = other.lock().unwrap();
            assert_eq!(
                sibling.execute(
                    &SyscallRequest::new(libc::SYS_close as u64, [fd as u64, 0, 0, 0, 0, 0]),
                    &shared_memory,
                ),
                0
            );
            // A seeded eventfd gives the replacement a distinct endpoint and
            // native read signature, without depending on a filesystem path.
            assert_eq!(
                sibling.execute(
                    &SyscallRequest::new(
                        libc::SYS_eventfd2 as u64,
                        [
                            23,
                            (libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) as u64,
                            0,
                            0,
                            0,
                            0
                        ]
                    ),
                    &shared_memory,
                ),
                fd as i64
            );
            *replaced.lock().unwrap() = Some(sibling.state.fd_entry_ids[&fd].clone());
            stop.request_exit_group(reverie::ExitStatus::Exited(37));
        }
        std::task::Poll::Pending
    }));
    let mut context = crate::terminal_read::ReadContext::new(
        registry.clone(),
        false,
        crate::entry::driver::EntryDriverWatch::for_memory(&memory),
        Some(failure),
        Arc::new(crate::failure::tool_panics::ToolPanics::default()),
        false,
    );
    assert!(matches!(
        read_zero_alias_with_test_admission(&mut executor, &request, &memory, &mut context),
        Err(crate::Error::TerminalReadCancelled)
    ));
    observed
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .assert_retired(&registry);
    before.assert_unchanged(&executor.state, fd);
    let replacement = replaced_entry.lock().unwrap().take().unwrap();
    assert!(!Arc::ptr_eq(&before.entry, &replacement));
    assert!(Arc::ptr_eq(
        &executor.file_table.lock().unwrap().fd_entry_ids[&fd],
        &replacement
    ));
    // The following install must take the sibling's new entry, not republish
    // the old File that the terminal reader returned to its private snapshot.
    assert_eq!(
        executor.execute(&request, &memory),
        negative_errno(libc::EINVAL)
    );
    assert!(Arc::ptr_eq(&executor.state.fd_entry_ids[&fd], &replacement));
    assert_eq!(
        executor.execute(
            &SyscallRequest::new(
                libc::SYS_read as u64,
                [fd as u64, READ_ZERO_BUFFER, 8, 0, 0, 0]
            ),
            &memory,
        ),
        8
    );
    assert_eq!(read_struct::<u64>(&memory, READ_ZERO_BUFFER), 23);
    registry.teardown_result().unwrap();
}

#[test]
fn read_zero_count_private_endpoint_guard_unwind_and_unreturned_owner_control() {
    let (mut executor, _, fd) = read_zero_alias_fixture(read_zero_blocking_inotify(), false);
    let before = ReadZeroEntry::capture(&executor.state, fd);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _endpoint = ReadEndpoint::take(&mut executor.state.files, fd);
        std::panic::resume_unwind(Box::new("outer read unwind"));
    }));
    assert_eq!(
        panic.unwrap_err().downcast_ref::<&str>(),
        Some(&"outer read unwind")
    );
    before.assert_unchanged(&executor.state, fd);

    // Ownership control only: emulate a still-owning inner registry by keeping
    // the moved File. This does not inject or claim a real pthread_join error;
    // terminal_read's existing retained-registry test covers that ledger.
    let retained = {
        let mut endpoint = ReadEndpoint::take(&mut executor.state.files, fd);
        endpoint.endpoint.take().unwrap()
    };
    assert!(!executor.state.files.contains_key(&fd));
    assert!(Arc::ptr_eq(
        &executor.state.fd_entry_ids[&fd],
        &before.entry
    ));
    assert_eq!(retained.as_raw_fd(), before.raw);
    assert!(unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFD) } >= 0);
    assert!(executor.state.files.insert(fd, retained).is_none());
    before.assert_unchanged(&executor.state, fd);
}
