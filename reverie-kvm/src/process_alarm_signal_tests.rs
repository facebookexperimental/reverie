/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests. These are pending-state controls, not VM delivery.
fn process_alarm_event(pid: i32) -> reverie::SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    reverie::SignalEvent::new(
        libc::SIGALRM,
        info,
        reverie::SignalTarget::Process {
            pid: reverie::Pid::from_raw(pid),
        },
    )
    .unwrap()
}

#[derive(Debug, Eq, PartialEq)]
struct ProcessAlarmSnapshot {
    logical_clock_ns: u64,
    process: crate::signal::ProcessSignalState,
    thread: crate::signal::ThreadSignalState,
    readiness: Vec<(i32, Option<i16>)>,
}

fn process_alarm_snapshot(executor: &ElfExecutor) -> ProcessAlarmSnapshot {
    let process = executor.state.process_signals.lock().unwrap().clone();
    let thread = executor.state.thread_signals.lock().clone();
    let readiness = process
        .signalfd_masks
        .keys()
        .map(|&fd| {
            (
                fd,
                executor.state.files.get(&fd).map(|file| {
                    let mut pfd = libc::pollfd {
                        fd: file.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    assert!(unsafe { libc::poll(&mut pfd, 1, 0) } >= 0);
                    pfd.revents
                }),
            )
        })
        .collect();
    ProcessAlarmSnapshot {
        logical_clock_ns: executor.state.logical_clock_ns,
        process,
        thread,
        readiness,
    }
}

fn process_alarm_signalfd(executor: &mut ElfExecutor, memory: &mut GuestMemory) -> i32 {
    let mut mask = KernelSigset::default();
    mask.insert(libc::SIGALRM);
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

#[test]
fn process_alarm_signal_complete_state_for_each_mask_and_disposition() {
    use reverie::ProcessAlarmSignalDisposition::Caught;
    use reverie::ProcessAlarmSignalDisposition::DefaultFatal;
    use reverie::ProcessAlarmSignalDisposition::Ignored;
    let root = TestDir::new();
    for (handler, disposition) in [(0, DefaultFatal), (1, Ignored), (0x4321, Caught)] {
        for blocked in [false, true] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            executor.observe_ignored_signals_with_tool();
            let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
            let fd = process_alarm_signalfd(&mut executor, &mut memory);
            let mut mask = KernelSigset::default();
            mask.insert(libc::SIGUSR1);
            test_install_signal_action(
                &executor.state,
                libc::SIGALRM,
                KernelSigaction {
                    handler,
                    flags: libc::SA_RESTART as u64,
                    mask,
                    ..Default::default()
                }
                .encode(),
            );
            if blocked {
                test_block_signal(&mut executor.state, libc::SIGALRM);
            }
            let unrelated =
                event_for_thread(libc::SIGUSR2, executor.state.pid, executor.state.tid).unwrap();
            executor.defer_signal_delivery(unrelated).unwrap();
            let event = process_alarm_event(executor.state.pid);
            let mut expected = process_alarm_snapshot(&executor);
            assert_eq!(expected.readiness, [(fd, Some(0))]);
            assert!(expected.process.shared_pending.enqueue(event, 0).unwrap());
            expected.readiness = vec![(fd, Some(libc::POLLIN))];
            assert_eq!(
                executor.queue_process_alarm_signal(event),
                reverie::ProcessAlarmSignalOutcome::Accepted(reverie::ProcessAlarmSignalReceipt {
                    blocked,
                    disposition,
                    pending_generation: 0,
                    coalesced: false,
                })
            );
            assert_eq!(process_alarm_snapshot(&executor), expected);
            assert_eq!(
                executor.queue_process_alarm_signal(event),
                reverie::ProcessAlarmSignalOutcome::Accepted(reverie::ProcessAlarmSignalReceipt {
                    blocked,
                    disposition,
                    pending_generation: 0,
                    coalesced: true,
                })
            );
            // A live signalfd remains ready after the idempotent coalesced
            // refresh, with complete queue/mask/action/generation state intact.
            assert_eq!(process_alarm_snapshot(&executor), expected);
            assert!(
                !executor.has_pending_exit(),
                "default-fatal receipt is not delivery"
            );
            assert!(executor.process_action.is_none());
        }
    }
}

#[test]
fn process_alarm_signal_rejects_all_noncanonical_bytes_without_state_changes() {
    use reverie::ProcessAlarmSignalErrorKind::Invalid;
    use reverie::ProcessAlarmSignalErrorKind::Unsupported;
    use reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    process_alarm_signalfd(&mut executor, &mut memory);
    test_block_signal(&mut executor.state, libc::SIGALRM);
    let valid = process_alarm_event(executor.state.pid);
    // Seed both domains to prove refusal does not flush or overwrite pending info.
    executor.defer_signal_delivery(valid).unwrap();
    assert!(matches!(
        executor.queue_process_alarm_signal(valid),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    let before = process_alarm_snapshot(&executor);
    let mut cases = Vec::new();
    for offset in (4..8).chain(12..reverie::SIGNAL_INFO_SIZE) {
        let mut info = valid.siginfo();
        info[offset] = 0xa5;
        cases.push((
            reverie::SignalEvent::new(libc::SIGALRM, info, valid.target()).unwrap(),
            Invalid,
            Errno::EINVAL,
        ));
    }
    for code in [
        libc::SI_USER,
        libc::SI_TKILL,
        libc::SI_TIMER,
        libc::CLD_EXITED,
    ] {
        let mut info = valid.siginfo();
        info[8..12].copy_from_slice(&code.to_ne_bytes());
        cases.push((
            reverie::SignalEvent::new(libc::SIGALRM, info, valid.target()).unwrap(),
            Unsupported,
            Errno::ENOSYS,
        ));
    }
    let mut info = valid.siginfo();
    info[0..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
    cases.push((
        reverie::SignalEvent::new(libc::SIGUSR1, info, valid.target()).unwrap(),
        Unsupported,
        Errno::ENOSYS,
    ));
    for pid in [-1, 0, executor.state.pid + 1] {
        cases.push((
            reverie::SignalEvent::new(
                libc::SIGALRM,
                valid.siginfo(),
                reverie::SignalTarget::Process {
                    pid: reverie::Pid::from_raw(pid),
                },
            )
            .unwrap(),
            Invalid,
            Errno::ESRCH,
        ));
    }
    cases.push((
        reverie::SignalEvent::new(
            libc::SIGALRM,
            valid.siginfo(),
            reverie::SignalTarget::Thread {
                pid: reverie::Pid::from_raw(executor.state.pid),
                tid: reverie::Pid::from_raw(executor.state.tid),
            },
        )
        .unwrap(),
        Unsupported,
        Errno::ENOSYS,
    ));
    for (event, kind, errno) in cases {
        assert_eq!(
            executor.queue_process_alarm_signal(event),
            RejectedBeforeCommit { kind, errno },
            "{event:?}"
        );
        assert_eq!(process_alarm_snapshot(&executor), before);
    }
}

#[test]
fn process_alarm_signal_coalesces_with_first_shared_info_without_changing_private_defers() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let alarm = process_alarm_event(executor.state.pid);
    executor.defer_signal_delivery(alarm).unwrap();
    let mut info = event_for_process(libc::SIGALRM, executor.state.pid)
        .unwrap()
        .siginfo();
    info[127] = 0xa5;
    let software = reverie::SignalEvent::new(libc::SIGALRM, info, alarm.target()).unwrap();
    queue_signal_event(&mut executor.state, software, true).unwrap();
    let before = process_alarm_snapshot(&executor);
    assert_eq!(
        executor.queue_process_alarm_signal(alarm),
        reverie::ProcessAlarmSignalOutcome::Accepted(reverie::ProcessAlarmSignalReceipt {
            blocked: false,
            disposition: reverie::ProcessAlarmSignalDisposition::DefaultFatal,
            pending_generation: 0,
            coalesced: true,
        })
    );
    assert_eq!(process_alarm_snapshot(&executor), before);
    assert_eq!(
        executor.take_pending_signal(),
        Some(PendingSignal {
            event: alarm,
            domain: PendingSignalDomain::Thread
        })
    );
    assert_eq!(
        executor.take_pending_signal(),
        Some(PendingSignal {
            event: software,
            domain: PendingSignalDomain::Process
        })
    );
    assert_eq!(executor.take_pending_signal(), None);
}

fn process_alarm_set_action(executor: &mut ElfExecutor, memory: &mut GuestMemory, handler: u64) {
    memory
        .write(
            0x100,
            &KernelSigaction {
                handler,
                ..Default::default()
            }
            .encode(),
        )
        .unwrap();
    assert_eq!(
        rt_sigaction(
            memory,
            &mut executor.state,
            &[
                libc::SIGALRM as u64,
                0x100,
                0,
                KERNEL_SIGSET_SIZE as u64,
                0,
                0
            ]
        ),
        0
    );
}

#[test]
fn process_alarm_signal_blocked_ignored_generation_differs_from_later_sigign() {
    use reverie::ProcessAlarmSignalDisposition::Caught;
    use reverie::ProcessAlarmSignalDisposition::Ignored;
    use reverie::ProcessAlarmSignalOutcome::Accepted;
    use reverie::ProcessAlarmSignalReceipt;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    test_block_signal(&mut executor.state, libc::SIGALRM);
    let fd = process_alarm_signalfd(&mut executor, &mut memory);
    let event = process_alarm_event(executor.state.pid);
    process_alarm_set_action(&mut executor, &mut memory, libc::SIG_IGN as u64);
    assert_eq!(
        executor.queue_process_alarm_signal(event),
        Accepted(ProcessAlarmSignalReceipt {
            blocked: true,
            disposition: Ignored,
            pending_generation: 1,
            coalesced: false,
        })
    );
    assert_eq!(
        process_alarm_snapshot(&executor).readiness,
        [(fd, Some(libc::POLLIN))]
    );
    process_alarm_set_action(&mut executor, &mut memory, 0x4321);
    assert_eq!(
        executor.queue_process_alarm_signal(event),
        Accepted(ProcessAlarmSignalReceipt {
            blocked: true,
            disposition: Caught,
            pending_generation: 1,
            coalesced: true,
        })
    );
    executor
        .state
        .thread_signals
        .lock()
        .blocked
        .remove(libc::SIGALRM);
    assert_eq!(
        executor.take_pending_signal_for_delivery().unwrap(),
        Some(PendingSignal {
            event,
            domain: PendingSignalDomain::Process,
        })
    );
    assert_eq!(process_alarm_snapshot(&executor).readiness, [(fd, Some(0))]);
    test_block_signal(&mut executor.state, libc::SIGALRM);
    assert!(matches!(
        executor.queue_process_alarm_signal(event),
        Accepted(_)
    ));
    process_alarm_set_action(&mut executor, &mut memory, libc::SIG_IGN as u64);
    let after = process_alarm_snapshot(&executor);
    assert_eq!(after.process.pending_generation(libc::SIGALRM), 2);
    assert!(after.process.shared_pending.is_empty());
    assert!(after.thread.pending.is_empty());
    assert!(after.thread.blocked.contains(libc::SIGALRM));
    assert_eq!(after.readiness, [(fd, Some(0))]);
}

#[test]
fn process_alarm_signal_receiver_lifetime_and_process_actions_refuse_before_mutation() {
    use reverie::ProcessAlarmSignalErrorKind::Invalid;
    use reverie::ProcessAlarmSignalErrorKind::Unsupported;
    use reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    for case in 0..7 {
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let event = process_alarm_event(executor.state.pid);
        let mut sibling = None;
        let (kind, errno) = match case {
            0 => {
                executor.cancel_current_thread();
                (Invalid, Errno::ESRCH)
            }
            1 => {
                sibling = Some(executor.thread_child(7).unwrap());
                (Unsupported, Errno::ENOSYS)
            }
            2 => {
                assert!(
                    executor.prepare_thread(
                        THREAD_CLONE_REQUIRED_FLAGS,
                        Some(0x8000),
                        None,
                        None,
                        None
                    ) > 0
                );
                (Unsupported, Errno::ENOSYS)
            }
            3 => {
                executor.process_action = Some(ProcessAction::Exec {
                    executable_path: root.0.join("pending-exec"),
                    executable_file: None,
                    image: Vec::new(),
                    argv: Vec::new(),
                    envp: Vec::new(),
                });
                (Unsupported, Errno::ENOSYS)
            }
            4 => {
                executor
                    .state
                    .task_lifecycle
                    .lock()
                    .unwrap()
                    .remove(executor.state.tid, executor.task_generation);
                executor.state.task_lifecycle.lock().unwrap().register(
                    executor.state.tid,
                    executor.state.pid,
                    executor.state.pgid,
                    true,
                );
                (Invalid, Errno::ESRCH)
            }
            5 => {
                executor.process_generation += 1;
                (Invalid, Errno::ESRCH)
            }
            6 => {
                assert!(executor.prepare_fork(None, None, None, None, false, false) > 0);
                (Unsupported, Errno::ENOSYS)
            }
            _ => unreachable!(),
        };
        let before = process_alarm_snapshot(&executor);
        let next_pid = executor.next_pid.load(Ordering::SeqCst);
        assert_eq!(
            executor.queue_process_alarm_signal(event),
            RejectedBeforeCommit { kind, errno },
            "case={case}"
        );
        assert_eq!(process_alarm_snapshot(&executor), before, "case={case}");
        assert_eq!(executor.next_pid.load(Ordering::SeqCst), next_pid);
        if let Some(sibling) = sibling.as_mut() {
            let before = process_alarm_snapshot(sibling);
            assert_eq!(
                sibling.queue_process_alarm_signal(event),
                RejectedBeforeCommit {
                    kind: Unsupported,
                    errno: Errno::ENOSYS
                }
            );
            assert_eq!(process_alarm_snapshot(sibling), before);
        }
    }
}

#[test]
fn process_alarm_signal_readiness_failure_distinguishes_pre_and_post_publication() {
    use reverie::ProcessAlarmSignalOutcome::Accepted;
    use reverie::ProcessAlarmSignalOutcome::FailedAfterCommit;
    use reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit;
    use reverie::syscalls::Errno;
    let root = TestDir::new();
    for precommit in [false, true] {
        for coalesced in [false, true] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
            let fd = process_alarm_signalfd(&mut executor, &mut memory);
            let event = process_alarm_event(executor.state.pid);
            if coalesced {
                assert!(matches!(
                    executor.queue_process_alarm_signal(event),
                    Accepted(_)
                ));
            }
            if precommit {
                executor.state.files.remove(&fd);
            } else {
                executor
                    .state
                    .files
                    .insert(fd, std::fs::File::open("/dev/null").unwrap());
            }
            let mut expected = process_alarm_snapshot(&executor);
            let outcome = executor.queue_process_alarm_signal(event);
            if precommit {
                assert_eq!(
                    outcome,
                    RejectedBeforeCommit {
                        kind: reverie::ProcessAlarmSignalErrorKind::Backend,
                        errno: Errno::EBADF
                    }
                );
            } else {
                assert_eq!(
                    outcome,
                    FailedAfterCommit {
                        errno: Errno::EBADF,
                        receipt: reverie::ProcessAlarmSignalReceipt {
                            blocked: false,
                            disposition: reverie::ProcessAlarmSignalDisposition::DefaultFatal,
                            pending_generation: 0,
                            coalesced,
                        },
                    }
                );
                assert_eq!(
                    expected.process.shared_pending.enqueue(event, 0).unwrap(),
                    !coalesced
                );
            }
            assert_eq!(process_alarm_snapshot(&executor), expected);
        }
    }
}

#[test]
fn process_alarm_signal_tool_reblocking_keeps_actual_pending_domain_and_first_info() {
    let root = TestDir::new();
    for domain in [PendingSignalDomain::Thread, PendingSignalDomain::Process] {
        let mut executor = ElfExecutor::new(test_state(&root.0), false);
        let event = process_alarm_event(executor.state.pid);
        if domain == PendingSignalDomain::Thread {
            executor.defer_signal_delivery(event).unwrap();
        } else {
            assert!(matches!(
                executor.queue_process_alarm_signal(event),
                reverie::ProcessAlarmSignalOutcome::Accepted(_)
            ));
        }
        let selected = executor
            .take_pending_signal_for_delivery()
            .unwrap()
            .unwrap();
        assert_eq!(selected.domain, domain);
        test_block_signal(&mut executor.state, libc::SIGALRM);
        // Another signal of the same domain arrives while the Tool owns selected.
        let replacement = event_for_process(libc::SIGALRM, executor.state.pid).unwrap();
        queue_signal_event(
            &mut executor.state,
            replacement,
            domain == PendingSignalDomain::Process,
        )
        .unwrap();
        let before = process_alarm_snapshot(&executor);
        assert_eq!(
            executor.prepare_filtered_signal_delivery(selected.event, selected.domain),
            Ok(None)
        );
        assert_eq!(process_alarm_snapshot(&executor), before);
        executor
            .state
            .thread_signals
            .lock()
            .blocked
            .remove(libc::SIGALRM);
        assert_eq!(
            executor.take_pending_signal_for_delivery().unwrap(),
            Some(PendingSignal {
                event: replacement,
                domain
            })
        );
        assert_eq!(executor.take_pending_signal(), None);
    }
}

#[test]
fn process_alarm_signal_tool_sigchld_replacement_preserves_thread_fault_and_process_domains() {
    let root = TestDir::new();
    for origin in ["thread", "fault", "process"] {
        for blocked in [false, true] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            let alarm = process_alarm_event(executor.state.pid);
            let selected = match origin {
                "fault" => {
                    crate::vm::PageZeroFault::for_test(executor.page_zero_fault_event(0)).pending()
                }
                "thread" | "process" => {
                    if origin == "thread" {
                        executor.defer_signal_delivery(alarm).unwrap();
                    } else {
                        assert!(matches!(
                            executor.queue_process_alarm_signal(alarm),
                            reverie::ProcessAlarmSignalOutcome::Accepted(_)
                        ));
                    }
                    executor
                        .take_pending_signal_for_delivery()
                        .unwrap()
                        .unwrap()
                }
                _ => unreachable!(),
            };
            let domain = if origin == "process" {
                PendingSignalDomain::Process
            } else {
                PendingSignalDomain::Thread
            };
            assert_eq!(selected.domain, domain);
            assert_eq!(
                selected.event.signal(),
                if origin == "fault" {
                    libc::SIGSEGV
                } else {
                    libc::SIGALRM
                }
            );
            test_install_signal_action(
                &executor.state,
                libc::SIGCHLD,
                KernelSigaction {
                    handler: 0x4321,
                    ..Default::default()
                }
                .encode(),
            );
            if blocked {
                test_block_signal(&mut executor.state, libc::SIGCHLD);
            }
            // Process provenance describes the replacement, not ownership of
            // the dequeued event. Faults and private defers stay thread-private.
            let replacement = child_exit_test_event(executor.state.pid, 41, 37, 0xa5);
            let mut expected = process_alarm_snapshot(&executor);
            let actual = executor.prepare_filtered_signal_delivery(replacement, selected.domain);
            if blocked {
                assert_eq!(actual, Ok(None));
                let generation = expected.process.pending_generation(libc::SIGCHLD);
                let pending = if domain == PendingSignalDomain::Thread {
                    &mut expected.thread.pending
                } else {
                    &mut expected.process.shared_pending
                };
                assert!(pending.enqueue(replacement, generation).unwrap());
                assert_eq!(process_alarm_snapshot(&executor), expected);
                assert_eq!(
                    executor.has_shared_pending_signal(),
                    domain == PendingSignalDomain::Process
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
                        event: replacement,
                        domain
                    })
                );
            } else {
                assert_eq!(
                    actual,
                    Ok(Some(PendingSignal {
                        event: replacement,
                        domain
                    }))
                );
                assert_eq!(process_alarm_snapshot(&executor), expected);
            }
            assert_eq!(executor.take_pending_signal(), None);
        }
    }
}

#[test]
fn process_alarm_signal_fork_and_exec_keep_process_pending_lifetime() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    test_block_signal(&mut executor.state, libc::SIGALRM);
    test_install_signal_action(
        &executor.state,
        libc::SIGALRM,
        KernelSigaction {
            handler: 0x4321,
            ..Default::default()
        }
        .encode(),
    );
    let event = process_alarm_event(executor.state.pid);
    assert!(matches!(
        executor.queue_process_alarm_signal(event),
        reverie::ProcessAlarmSignalOutcome::Accepted(_)
    ));
    let before = process_alarm_snapshot(&executor);
    let forked = executor.state.try_clone_for_fork(2).unwrap();
    assert!(
        forked
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .is_empty()
    );
    assert!(forked.thread_signals.lock().pending.is_empty());
    assert_eq!(forked.thread_signals.lock().blocked, before.thread.blocked);
    assert_eq!(
        forked.process_signals.lock().unwrap().dispositions,
        before.process.dispositions
    );
    assert_eq!(process_alarm_snapshot(&executor), before);
    let old_generation = executor.task_generation;
    executor.replace_after_exec(test_state(&root.0));
    assert_eq!(
        executor.task_generation, old_generation,
        "exec preserves the task lifetime"
    );
    let after = process_alarm_snapshot(&executor);
    assert_eq!(after.process.shared_pending, before.process.shared_pending);
    assert_eq!(
        after.process.pending_generations,
        before.process.pending_generations
    );
    assert_eq!(after.thread.blocked, before.thread.blocked);
    assert_eq!(
        executor.signal_disposition(libc::SIGALRM),
        SignalDisposition::Terminate
    );
    assert_eq!(
        executor.queue_process_alarm_signal(event),
        reverie::ProcessAlarmSignalOutcome::Accepted(reverie::ProcessAlarmSignalReceipt {
            blocked: true,
            disposition: reverie::ProcessAlarmSignalDisposition::DefaultFatal,
            pending_generation: 0,
            coalesced: true,
        })
    );
    assert_eq!(executor.take_pending_signal(), None);
    executor
        .state
        .thread_signals
        .lock()
        .blocked
        .remove(libc::SIGALRM);
    assert_eq!(
        executor.take_pending_signal(),
        Some(PendingSignal {
            event,
            domain: PendingSignalDomain::Process
        })
    );
}
