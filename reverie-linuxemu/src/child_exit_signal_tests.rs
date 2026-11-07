// Included in executor::tests to exercise the actual pending-state operation.
fn child_exit_test_event_with_code(
    pid: i32,
    child: i32,
    code: i32,
    status: i32,
    marker: u8,
) -> reverie::SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGCHLD.to_ne_bytes());
    info[8..12].copy_from_slice(&code.to_ne_bytes());
    info[16..20].copy_from_slice(&child.to_ne_bytes());
    info[20..24].copy_from_slice(&65_534_u32.to_ne_bytes());
    info[24..28].copy_from_slice(&status.to_ne_bytes());
    info[32..40].copy_from_slice(&11_i64.to_ne_bytes());
    info[40..48].copy_from_slice(&13_i64.to_ne_bytes());
    info[127] = marker;
    reverie::SignalEvent::new(
        libc::SIGCHLD,
        info,
        reverie::SignalTarget::Process {
            pid: reverie::Pid::from_raw(pid),
        },
    )
    .unwrap()
}

fn child_exit_test_event(pid: i32, child: i32, status: i32, marker: u8) -> reverie::SignalEvent {
    child_exit_test_event_with_code(pid, child, libc::CLD_EXITED, status, marker)
}

#[test]
fn child_exit_signal_accepts_every_terminal_status_class() {
    use reverie::ChildExitSignalDisposition::PendingEligible;
    use reverie::ChildExitSignalOutcome::Accepted;

    let root = TestDir::new();
    for (code, status) in [
        (libc::CLD_EXITED, 0),
        (libc::CLD_EXITED, i32::from(u8::MAX)),
        (libc::CLD_KILLED, 1),
        (libc::CLD_KILLED, 64),
        (libc::CLD_KILLED, libc::SIGSEGV),
        (libc::CLD_DUMPED, libc::SIGQUIT),
        (libc::CLD_DUMPED, libc::SIGSYS),
    ] {
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let event = child_exit_test_event_with_code(executor.state.pid, 41, code, status, 0xa5);
        assert_eq!(
            executor.queue_child_exit_signal(event),
            Accepted {
                disposition: PendingEligible,
                pending_generation: 0,
                coalesced: false,
            },
            "code={code} status={status}",
        );
        let selected = executor
            .take_pending_signal()
            .expect("published child event");
        assert_eq!(selected.event, event);
        assert_eq!(selected.domain, PendingSignalDomain::Process);
        assert_eq!(
            executor.prepare_filtered_signal_delivery(event, selected.domain),
            Ok(Some(selected)),
            "Tool-return validation narrowed code={code} status={status}",
        );
    }
}

#[test]
fn child_exit_signal_preserves_process_ownership_and_first_complete_siginfo() {
    use reverie::ChildExitSignalDisposition::PendingEligible;
    use reverie::ChildExitSignalOutcome::Accepted;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let first = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    let second = child_exit_test_event(executor.state.pid, 42, 9, 0x5a);
    for (event, coalesced) in [(first, false), (second, true)] {
        assert_eq!(
            executor.queue_child_exit_signal(event),
            Accepted {
                disposition: PendingEligible,
                pending_generation: 0,
                coalesced,
            }
        );
        assert!(executor.state.thread_signals.lock().pending.is_empty());
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGCHLD)
        );
    }
    assert_eq!(
        executor.take_pending_signal(),
        Some(PendingSignal {
            event: first,
            domain: PendingSignalDomain::Process,
        })
    );
    assert_eq!(executor.take_pending_signal(), None);
}

#[test]
fn legacy_child_exit_surface_refuses_tool_controlled_runs_before_mutation() {
    use reverie::ChildExitSignalErrorKind::Unsupported;
    use reverie::ChildExitSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;

    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    executor.install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &run);
    let event = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    assert_eq!(
        executor.queue_child_exit_signal(event),
        RejectedBeforeCommit {
            kind: Unsupported,
            errno: Errno::ENOSYS,
        }
    );
    assert!(
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .is_empty()
    );
}

#[test]
fn child_exit_signal_distinguishes_explicit_ignore_blocking_and_tool_eligibility() {
    use reverie::ChildExitSignalDisposition::Ignored;
    use reverie::ChildExitSignalDisposition::PendingBlocked;
    use reverie::ChildExitSignalDisposition::PendingEligible;
    use reverie::ChildExitSignalOutcome::Accepted;
    let root = TestDir::new();
    for handler in [libc::SIG_DFL as u64, libc::SIG_IGN as u64, 0x4321] {
        for blocked in [false, true] {
            for flags in [0, libc::SA_NOCLDWAIT as u64, libc::SA_NOCLDSTOP as u64] {
                let mut executor = ElfExecutor::new(test_state(&root.0), false);
                let action = KernelSigaction {
                    handler,
                    flags,
                    ..Default::default()
                };
                test_install_signal_action(&executor.state, libc::SIGCHLD, action.encode());
                executor.state.thread_signals.lock().observe_ignored = true;
                if blocked {
                    test_block_signal(&mut executor.state, libc::SIGCHLD);
                }
                let event = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
                let disposition = if handler == libc::SIG_IGN as u64 {
                    Ignored
                } else if blocked {
                    PendingBlocked
                } else {
                    PendingEligible
                };
                assert_eq!(
                    executor.queue_child_exit_signal(event),
                    Accepted {
                        disposition,
                        pending_generation: 0,
                        coalesced: false,
                    },
                    "handler={handler} blocked={blocked} flags={flags}"
                );
                assert_eq!(
                    executor
                        .state
                        .thread_signals
                        .lock()
                        .blocked
                        .contains(libc::SIGCHLD),
                    blocked
                );
                let process = executor.state.process_signals.lock().unwrap();
                assert_eq!(process.dispositions[&libc::SIGCHLD], action);
                assert_eq!(
                    process.shared_pending.contains(libc::SIGCHLD),
                    disposition != Ignored
                );
                drop(process);
                assert!(executor.state.thread_signals.lock().pending.is_empty());
                if disposition == PendingEligible {
                    assert_eq!(executor.take_pending_signal().unwrap().event, event);
                } else {
                    assert_eq!(executor.take_pending_signal(), None);
                }
            }
        }
    }
}

#[test]
fn child_exit_signal_invalid_metadata_and_unsupported_classes_do_not_publish() {
    use reverie::ChildExitSignalErrorKind::Invalid;
    use reverie::ChildExitSignalErrorKind::Unsupported;
    use reverie::ChildExitSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let valid = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    let mut cases = Vec::new();
    for code in [
        libc::SI_USER,
        libc::SI_TKILL,
        libc::CLD_STOPPED,
        libc::CLD_CONTINUED,
        libc::CLD_TRAPPED,
    ] {
        let mut info = valid.siginfo();
        info[8..12].copy_from_slice(&code.to_ne_bytes());
        cases.push((info, valid.target(), Unsupported, Errno::ENOSYS));
    }
    for (offset, value) in [(4, 1_i32), (16, 0), (16, -1), (24, -1), (24, 256)] {
        let mut info = valid.siginfo();
        info[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        cases.push((info, valid.target(), Invalid, Errno::EINVAL));
    }
    for (code, status) in [
        (libc::CLD_KILLED, 0_i32),
        (libc::CLD_KILLED, libc::SIGCHLD),
        (libc::CLD_KILLED, libc::SIGCONT),
        (libc::CLD_KILLED, libc::SIGSTOP),
        (libc::CLD_KILLED, libc::SIGTSTP),
        (libc::CLD_KILLED, libc::SIGTTIN),
        (libc::CLD_KILLED, libc::SIGTTOU),
        (libc::CLD_KILLED, libc::SIGURG),
        (libc::CLD_KILLED, libc::SIGWINCH),
        (libc::CLD_KILLED, 65),
        (libc::CLD_DUMPED, 0),
        (libc::CLD_DUMPED, libc::SIGHUP),
        (libc::CLD_DUMPED, 64),
        (libc::CLD_DUMPED, 65),
    ] {
        let mut info = valid.siginfo();
        info[8..12].copy_from_slice(&code.to_ne_bytes());
        info[24..28].copy_from_slice(&status.to_ne_bytes());
        cases.push((info, valid.target(), Invalid, Errno::EINVAL));
    }
    for offset in [32, 40] {
        let mut info = valid.siginfo();
        info[offset..offset + 8].copy_from_slice(&(-1_i64).to_ne_bytes());
        cases.push((info, valid.target(), Invalid, Errno::EINVAL));
    }
    for pid in [-1, 0, executor.state.pid + 1] {
        cases.push((
            valid.siginfo(),
            reverie::SignalTarget::Process {
                pid: reverie::Pid::from_raw(pid),
            },
            Invalid,
            Errno::ESRCH,
        ));
    }
    cases.push((
        valid.siginfo(),
        reverie::SignalTarget::Thread {
            pid: reverie::Pid::from_raw(executor.state.pid),
            tid: reverie::Pid::from_raw(executor.state.tid),
        },
        Unsupported,
        Errno::ENOSYS,
    ));
    for (info, target, kind, errno) in cases {
        let event = reverie::SignalEvent::new(libc::SIGCHLD, info, target).unwrap();
        assert_eq!(
            executor.queue_child_exit_signal(event),
            RejectedBeforeCommit { kind, errno }
        );
        assert_eq!(
            executor.prepare_filtered_signal_delivery(event, PendingSignalDomain::Process),
            Err(errno)
        );
        assert_eq!(executor.take_pending_signal(), None);
        assert!(executor.state.thread_signals.lock().pending.is_empty());
        assert!(
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .is_empty()
        );
    }
    // The original private API still refuses even a coherent child-exit event.
    assert_eq!(executor.defer_signal_delivery(valid), Err(Errno::ENOSYS));
    assert_eq!(executor.take_pending_signal(), None);
    assert!(matches!(
        executor.queue_child_exit_signal(valid),
        reverie::ChildExitSignalOutcome::Accepted { .. }
    ));
}

fn child_exit_test_signalfd(executor: &mut ElfExecutor, memory: &mut GuestMemory) -> i32 {
    let mut mask = KernelSigset::default();
    mask.insert(libc::SIGCHLD);
    memory.write(0x80, &mask.to_bytes()).unwrap();
    let fd = syscall_result(
        memory,
        &mut executor.state,
        libc::SYS_signalfd4,
        [
            u64::MAX,
            0x80,
            KERNEL_SIGSET_SIZE as u64,
            libc::SFD_NONBLOCK as u64,
            0,
            0,
        ],
    );
    assert!(fd >= 0, "signalfd failed: {fd}");
    fd as i32
}

fn child_exit_test_ready(executor: &ElfExecutor, fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: executor.state.files[&fd].as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&mut pfd, 1, 0) } >= 0);
    pfd.revents & libc::POLLIN != 0
}

#[test]
fn child_exit_signal_signalfd_preserves_child_fields_and_complete_output_buffer() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    memory.write(0, &[0xa5; PAGE_SIZE as usize]).unwrap();
    test_block_signal(&mut executor.state, libc::SIGCHLD);
    let fd = child_exit_test_signalfd(&mut executor, &mut memory);
    assert!(!child_exit_test_ready(&executor, fd));
    let first = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    let second = child_exit_test_event(executor.state.pid, 42, 9, 0x5a);
    for (event, coalesced) in [(first, false), (second, true)] {
        assert_eq!(
            executor.queue_child_exit_signal(event),
            reverie::ChildExitSignalOutcome::Accepted {
                disposition: reverie::ChildExitSignalDisposition::PendingBlocked,
                pending_generation: 0,
                coalesced,
            }
        );
        assert!(child_exit_test_ready(&executor, fd));
    }
    let mut expected = vec![0; PAGE_SIZE as usize];
    memory.read(0, &mut expected).unwrap();
    let mut record: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    record.ssi_signo = libc::SIGCHLD as u32;
    record.ssi_code = libc::CLD_EXITED;
    record.ssi_pid = 41;
    record.ssi_uid = 65_534;
    record.ssi_status = 37;
    record.ssi_utime = 11;
    record.ssi_stime = 13;
    assert_eq!(std::mem::size_of_val(&record), 128);
    expected[0x180..0x200].copy_from_slice(&struct_bytes(&record));
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut executor.state,
            libc::SYS_read,
            [fd as u64, 0x180, 128, 0, 0, 0]
        ),
        128
    );
    let mut actual = vec![0; expected.len()];
    memory.read(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    assert!(!child_exit_test_ready(&executor, fd));
    assert_eq!(executor.take_pending_signal(), None);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut executor.state,
            libc::SYS_read,
            [fd as u64, 0x180, 128, 0, 0, 0]
        ),
        negative_errno(libc::EAGAIN)
    );
    memory.read(0, &mut actual).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn child_exit_signal_signalfd_encodes_every_terminal_status_class() {
    for (code, status) in [
        (libc::CLD_EXITED, 37),
        (libc::CLD_KILLED, libc::SIGTERM),
        (libc::CLD_KILLED, libc::SIGSEGV),
        (libc::CLD_DUMPED, libc::SIGABRT),
    ] {
        let event = child_exit_test_event_with_code(3, 41, code, status, 0xa5);
        let mut expected: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        expected.ssi_signo = libc::SIGCHLD as u32;
        expected.ssi_code = code;
        expected.ssi_pid = 41;
        expected.ssi_uid = 65_534;
        expected.ssi_status = status;
        expected.ssi_utime = 11;
        expected.ssi_stime = 13;
        let expected = struct_bytes(&expected);
        assert_eq!(
            encode_signalfd_siginfo(event).as_slice(),
            expected.as_slice(),
            "code={code} status={status}",
        );
    }
}

#[test]
fn child_exit_signal_distinguishes_failure_before_and_after_pending_publication() {
    use reverie::ChildExitSignalErrorKind::Backend;
    use reverie::ChildExitSignalOutcome::FailedAfterCommit;
    use reverie::ChildExitSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    for coalesced in [false, true] {
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let fd = child_exit_test_signalfd(&mut executor, &mut memory);
        let first = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
        let second = child_exit_test_event(executor.state.pid, 42, 9, 0x5a);
        if coalesced {
            assert!(matches!(
                executor.queue_child_exit_signal(first),
                reverie::ChildExitSignalOutcome::Accepted {
                    coalesced: false,
                    ..
                }
            ));
        }
        // A present but unwritable backing descriptor fails the actual host
        // readiness update after publication. The original error is EBADF.
        executor
            .state
            .files
            .insert(fd, std::fs::File::open("/dev/null").unwrap());
        assert_eq!(
            executor.queue_child_exit_signal(second),
            FailedAfterCommit {
                errno: Errno::EBADF,
                pending_generation: 0,
            }
        );
        assert_eq!(
            executor.take_pending_signal(),
            Some(PendingSignal {
                event: if coalesced { first } else { second },
                domain: PendingSignalDomain::Process,
            })
        );
        assert_eq!(executor.take_pending_signal(), None);
        assert!(executor.state.thread_signals.lock().pending.is_empty());
    }
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = child_exit_test_signalfd(&mut executor, &mut memory);
    executor.state.files.remove(&fd);
    let event = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    assert_eq!(
        executor.queue_child_exit_signal(event),
        RejectedBeforeCommit {
            kind: Backend,
            errno: Errno::EBADF,
        }
    );
    assert_eq!(executor.take_pending_signal(), None);
    assert!(
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .is_empty()
    );
}

#[test]
fn child_exit_signal_disposition_generation_discards_old_info_without_replacing_new_info() {
    use reverie::ChildExitSignalDisposition::Ignored;
    use reverie::ChildExitSignalDisposition::PendingBlocked;
    use reverie::ChildExitSignalOutcome::Accepted;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    test_block_signal(&mut executor.state, libc::SIGCHLD);
    let fd = child_exit_test_signalfd(&mut executor, &mut memory);
    let old = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    let first_new = child_exit_test_event(executor.state.pid, 42, 9, 0x5a);
    assert_eq!(
        executor.queue_child_exit_signal(old),
        Accepted {
            disposition: PendingBlocked,
            pending_generation: 0,
            coalesced: false,
        }
    );
    assert!(child_exit_test_ready(&executor, fd));
    memory
        .write(
            0x100,
            &KernelSigaction {
                handler: libc::SIG_IGN as u64,
                ..Default::default()
            }
            .encode(),
        )
        .unwrap();
    assert_eq!(
        rt_sigaction(
            &mut memory,
            &mut executor.state,
            &[
                libc::SIGCHLD as u64,
                0x100,
                0,
                KERNEL_SIGSET_SIZE as u64,
                0,
                0
            ]
        ),
        0
    );
    assert!(!child_exit_test_ready(&executor, fd));
    assert_eq!(
        executor.queue_child_exit_signal(old),
        Accepted {
            disposition: Ignored,
            pending_generation: 1,
            coalesced: false,
        }
    );
    memory
        .write(
            0x100,
            &KernelSigaction {
                handler: 0x4321,
                ..Default::default()
            }
            .encode(),
        )
        .unwrap();
    assert_eq!(
        rt_sigaction(
            &mut memory,
            &mut executor.state,
            &[
                libc::SIGCHLD as u64,
                0x100,
                0,
                KERNEL_SIGSET_SIZE as u64,
                0,
                0
            ]
        ),
        0
    );
    assert_eq!(
        executor.queue_child_exit_signal(first_new),
        Accepted {
            disposition: PendingBlocked,
            pending_generation: 1,
            coalesced: false,
        }
    );
    assert_eq!(
        executor.queue_child_exit_signal(old),
        Accepted {
            disposition: PendingBlocked,
            pending_generation: 1,
            coalesced: true,
        }
    );
    executor
        .state
        .thread_signals
        .lock()
        .blocked
        .remove(libc::SIGCHLD);
    assert_eq!(
        executor.take_pending_signal_for_delivery().unwrap(),
        Some(PendingSignal {
            event: first_new,
            domain: PendingSignalDomain::Process,
        })
    );
    assert!(!child_exit_test_ready(&executor, fd));
    assert_eq!(executor.take_pending_signal(), None);
}

#[test]
fn child_exit_signal_lifecycle_keeps_pending_process_state_private_across_fork_and_exec() {
    use reverie::ChildExitSignalErrorKind::Invalid;
    use reverie::ChildExitSignalErrorKind::Unsupported;
    use reverie::ChildExitSignalOutcome::Accepted;
    use reverie::ChildExitSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let mut sibling = leader.thread_child(7).unwrap();
    let event = child_exit_test_event(leader.state.pid, 41, 37, 0xa5);
    for executor in [&mut leader, &mut sibling] {
        assert_eq!(
            executor.queue_child_exit_signal(event),
            RejectedBeforeCommit {
                kind: Unsupported,
                errno: Errno::ENOSYS,
            }
        );
        assert_eq!(executor.take_pending_signal(), None);
    }
    sibling.cancel_current_thread();
    test_block_signal(&mut leader.state, libc::SIGCHLD);
    assert!(matches!(
        leader.queue_child_exit_signal(event),
        Accepted {
            coalesced: false,
            ..
        }
    ));
    let next_tid = leader.next_pid.load(Ordering::SeqCst);
    assert_eq!(
        leader.prepare_thread(THREAD_CLONE_REQUIRED_FLAGS, Some(0x8000), None, None, None),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(leader.next_pid.load(Ordering::SeqCst), next_tid);
    assert!(leader.process_action.is_none());
    let forked = leader.state.try_clone_for_fork(2).unwrap();
    assert!(
        forked
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .is_empty()
    );
    assert!(forked.thread_signals.lock().pending.is_empty());
    assert!(
        leader
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .contains(libc::SIGCHLD)
    );
    leader.replace_after_exec(test_state(&root.0));
    assert!(
        leader
            .state
            .thread_signals
            .lock()
            .blocked
            .contains(libc::SIGCHLD)
    );
    assert_eq!(leader.take_pending_signal(), None);
    leader
        .state
        .thread_signals
        .lock()
        .blocked
        .remove(libc::SIGCHLD);
    assert_eq!(
        leader.take_pending_signal(),
        Some(PendingSignal {
            event,
            domain: PendingSignalDomain::Process,
        })
    );
    assert_eq!(leader.take_pending_signal(), None);

    // An obsolete callback must not publish under a reused numeric identity.
    let old_generation = leader.task_generation;
    leader
        .state
        .task_lifecycle
        .lock()
        .unwrap()
        .remove(leader.state.tid, old_generation);
    let mut replacement_state = test_state(&root.0);
    replacement_state.task_lifecycle = leader.state.task_lifecycle.clone();
    let mut replacement = ElfExecutor::new(replacement_state, false);
    assert_ne!(replacement.task_generation, old_generation);
    assert_eq!(
        leader.queue_child_exit_signal(event),
        RejectedBeforeCommit {
            kind: Invalid,
            errno: Errno::ESRCH,
        }
    );
    assert_eq!(leader.take_pending_signal(), None);
    assert_eq!(replacement.take_pending_signal(), None);
    assert!(matches!(
        replacement.queue_child_exit_signal(event),
        Accepted {
            coalesced: false,
            ..
        }
    ));
    assert_eq!(replacement.take_pending_signal().unwrap().event, event);
}

#[test]
fn child_exit_signal_tool_return_keeps_process_domain_and_validates_replacements() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let first = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
    let second = child_exit_test_event(executor.state.pid, 42, 9, 0x5a);
    test_block_signal(&mut executor.state, libc::SIGCHLD);
    assert!(matches!(
        executor.queue_child_exit_signal(first),
        reverie::ChildExitSignalOutcome::Accepted { .. }
    ));
    assert_eq!(
        executor.prepare_filtered_signal_delivery(second, PendingSignalDomain::Process),
        Ok(None)
    );
    assert!(executor.state.thread_signals.lock().pending.is_empty());
    executor
        .state
        .thread_signals
        .lock()
        .blocked
        .remove(libc::SIGCHLD);
    assert_eq!(executor.take_pending_signal().unwrap().event, first);
    assert_eq!(
        executor.prepare_filtered_signal_delivery(second, PendingSignalDomain::Process),
        Ok(Some(PendingSignal {
            event: second,
            domain: PendingSignalDomain::Process,
        }))
    );
    assert_eq!(executor.take_pending_signal(), None);
}
