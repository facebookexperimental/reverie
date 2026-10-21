/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the LICENSE file.
 */

fn ready_family_child(parent: &mut ElfExecutor, pid: i32) -> ElfExecutor {
    let mut child = parent.fork_child(pid, false, false).unwrap();
    let child_id = identity(&child);
    child.retire_current_thread(reverie::ExitStatus::Exited(23), false);
    assert!(child.signal_task_identity().is_none());
    assert_eq!(child.retired_process_identity(), child_id);
    parent
        .record_child_completion(
            child_id,
            super::super::ChildCompletion::Waitable(reverie::ExitStatus::Exited(23)),
        )
        .unwrap();
    child
}

#[test]
fn sibling_waits_share_published_children_and_fault_consumption() {
    for waiter_after_exit in [false, true] {
        for use_waitid in [false, true] {
            for fault in [false, true] {
                let mut parent = executor();
                let mut early = (!waiter_after_exit).then(|| parent.thread_child(9).unwrap());
                let child = ready_family_child(&mut parent, 2);
                let _sibling_child = ready_family_child(&mut parent, 3);
                let mut waiter = early
                    .take()
                    .unwrap_or_else(|| parent.thread_child(9).unwrap());
                let memory = GuestMemory::new(0, 8192).unwrap();
                memory.map_user_permissions(0, 8192, true, true).unwrap();
                memory.enable_user_access();
                memory.write_raw(0, &[0xa5; 8192]).unwrap();
                // Peeking never consumes, including from a newly created thread.
                for _ in 0..2 {
                    assert_eq!(
                        waiter
                            .execute_checked(
                                &SyscallRequest::new(
                                    libc::SYS_waitid as u64,
                                    [
                                        libc::P_PID as u64,
                                        2,
                                        0,
                                        (libc::WEXITED | libc::WNOWAIT) as u64,
                                        0,
                                        0
                                    ]
                                ),
                                &memory
                            )
                            .unwrap(),
                        0
                    );
                }
                if fault {
                    memory
                        .map_user_permissions(4096, 4096, true, false)
                        .unwrap();
                }
                let request = if use_waitid {
                    SyscallRequest::new(
                        libc::SYS_waitid as u64,
                        [
                            libc::P_PID as u64,
                            2,
                            0x100,
                            libc::WEXITED as u64,
                            if fault { 0x1100 } else { 0 },
                            0,
                        ],
                    )
                } else {
                    SyscallRequest::new(
                        libc::SYS_wait4 as u64,
                        [2, 0x100, 0, if fault { 0x1100 } else { 0 }, 0, 0],
                    )
                };
                assert_eq!(
                    waiter.execute_checked(&request, &memory).unwrap(),
                    if fault {
                        -i64::from(libc::EFAULT)
                    } else if use_waitid {
                        0
                    } else {
                        2
                    }
                );
                assert!(waiter.state.consumed_child_wait.is_none());
                assert!(
                    parent
                        .signal_registry
                        .family
                        .lock()
                        .unwrap()
                        .wait_receipts
                        .is_empty()
                );
                for executor in [&mut parent, &mut waiter] {
                    assert_eq!(
                        executor
                            .execute_checked(
                                &SyscallRequest::new(
                                    libc::SYS_wait4 as u64,
                                    [2, 0, libc::WNOHANG as u64, 0, 0, 0]
                                ),
                                &memory
                            )
                            .unwrap(),
                        -i64::from(libc::ECHILD)
                    );
                    assert!(executor.state.children.contains_key(&3));
                }
                let mut expected = [0xa5; 8192];
                if !use_waitid {
                    expected[0x100..0x104].copy_from_slice(&(23_i32 << 8).to_le_bytes());
                } else if !fault {
                    for (offset, value) in [0, 4, 8, 16, 20, 24].into_iter().zip([
                        libc::SIGCHLD,
                        0,
                        libc::CLD_EXITED,
                        2,
                        0,
                        23,
                    ]) {
                        expected[0x100 + offset..0x104 + offset]
                            .copy_from_slice(&value.to_le_bytes());
                    }
                }
                let mut actual = [0; 8192];
                memory.read_raw(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(child.retired_process_identity().tgid.as_raw(), 2);
            }
        }
    }
}

#[test]
fn competing_sibling_waits_commit_once_before_late_owner_collection() {
    for fault in [false, true] {
        let mut parent = executor();
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        child.retire_current_thread(reverie::ExitStatus::Exited(23), false);
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        parent
            .publish_child_wait(
                child_id,
                super::super::ChildCompletion::Waitable(reverie::ExitStatus::Exited(23)),
                &slot,
                false,
            )
            .unwrap();
        let (start, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let handle = super::super::ChildThread::spawn(move || {
            assert_eq!(
                started.recv().unwrap(),
                super::super::ChildStartCommand::Start
            );
            released.recv().unwrap();
            Ok(())
        });
        parent.register_child_process_with_gate(
            2,
            super::super::ChildStartGate::new(start),
            slot,
            handle,
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = [8, 9]
            .into_iter()
            .map(|tid| {
                let mut worker = parent.thread_child(tid).unwrap();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let memory = GuestMemory::new(0, 4096).unwrap();
                    barrier.wait();
                    let result = worker
                        .execute_checked(
                            &SyscallRequest::new(
                                libc::SYS_wait4 as u64,
                                [
                                    2,
                                    if fault { 4096 } else { 0 },
                                    libc::WNOHANG as u64,
                                    0,
                                    0,
                                    0,
                                ],
                            ),
                            &memory,
                        )
                        .unwrap();
                    assert!(worker.state.consumed_child_wait.is_none());
                    result
                })
            })
            .collect();
        let mut results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        results.sort();
        let mut expected = vec![
            -i64::from(libc::ECHILD),
            if fault { -i64::from(libc::EFAULT) } else { 2 },
        ];
        expected.sort();
        assert_eq!(results, expected);
        assert!(
            parent
                .signal_registry
                .family
                .lock()
                .unwrap()
                .wait_receipts
                .is_empty()
        );
        release.send(()).unwrap();
        parent.join_all_child_processes().unwrap();
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert_eq!(
            parent
                .execute_checked(
                    &SyscallRequest::new(
                        libc::SYS_wait4 as u64,
                        [2, 0, libc::WNOHANG as u64, 0, 0, 0]
                    ),
                    &memory
                )
                .unwrap(),
            -i64::from(libc::ECHILD)
        );
        assert!(
            parent.state.children.is_empty(),
            "physical collection must not republish a consumed child"
        );
    }
}

#[test]
fn sibling_wnohang_waits_for_publication_fence_and_failure_broadcast() {
    for failure_mode in 0..3 {
        let failed = failure_mode != 0;
        let parent = executor();
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        if failure_mode == 2 {
            parent.install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &run);
        }
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        child.retire_current_thread(reverie::ExitStatus::Exited(23), false);
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        parent
            .begin_child_wait_publication(child_id, &slot)
            .unwrap();
        let mut sibling = parent.thread_child(9).unwrap();
        let waiter = std::thread::spawn(move || {
            let memory = GuestMemory::new(0, 4096).unwrap();
            sibling.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [
                        libc::P_PID as u64,
                        2,
                        0,
                        (libc::WEXITED | libc::WNOHANG) as u64,
                        0,
                        0,
                    ],
                ),
                &memory,
            )
        });
        assert!(parent.signal_registry.wait_for_guest_waiter());
        assert!(!waiter.is_finished());
        if failure_mode == 2 {
            crate::failure::FailureContext::new(
                run,
                identity(&parent).tgid,
                identity(&parent).tgid,
            )
            .publish(
                "cross-thread wait failure control",
                crate::Error::GuestClock("forced run failure".to_owned()),
            );
        } else if failed {
            assert!(slot.fail_if_pending());
            parent.fail_child_wait_publication(child_id);
        } else {
            parent
                .publish_child_wait(
                    child_id,
                    super::super::ChildCompletion::Waitable(reverie::ExitStatus::Exited(23)),
                    &slot,
                    true,
                )
                .unwrap();
        }
        let result = waiter.join().unwrap();
        if failed {
            assert!(matches!(result, Err(crate::Error::RunAborted)));
            if failure_mode == 1 {
                assert!(
                    parent
                        .publish_child_wait(
                            child_id,
                            super::super::ChildCompletion::Waitable(reverie::ExitStatus::Exited(
                                23
                            )),
                            &slot,
                            true
                        )
                        .is_err()
                );
            }
            assert!(!parent.state.children.contains_key(&2));
        } else {
            assert_eq!(result.unwrap(), 0);
        }
    }
}

#[test]
fn family_wait_receipt_is_exact_and_survives_parent_teardown() {
    let mut parent = outside_init_root();
    let _child = ready_family_child(&mut parent, 2);
    let sibling = parent.thread_child(9).unwrap();
    let ChildWaitSelection::Ready(selected) =
        parent.state.children.select(Some(2), true, true).unwrap()
    else {
        panic!("ready child");
    };
    let receipt = selected.receipt.unwrap();
    assert!(matches!(
        sibling.state.children.acknowledge(receipt.clone()),
        Err(crate::Error::FamilyWaitLedgerMismatch { .. })
    ));
    parent.retire_current_thread(reverie::ExitStatus::SUCCESS, true);
    parent.state.children.acknowledge(receipt.clone()).unwrap();
    assert!(matches!(
        parent.state.children.acknowledge(receipt),
        Err(crate::Error::FamilyWaitLedgerMismatch { .. })
    ));
    assert!(
        parent
            .signal_registry
            .family
            .lock()
            .unwrap()
            .wait_receipts
            .is_empty()
    );
}

#[test]
fn old_generation_acknowledgement_cannot_consume_reused_pid() {
    let mut parent = executor();
    let child = ready_family_child(&mut parent, 2);
    let old_id = child.retired_process_identity();
    let ChildWaitSelection::Ready(selected) =
        parent.state.children.select(Some(2), true, true).unwrap()
    else {
        panic!("ready child");
    };
    let receipt = selected.receipt.unwrap();
    drop(child);
    // The production allocator never reissues a PID. Explicit construction
    // exercises the ledger's stronger exact-generation boundary nonetheless.
    let replacement = ready_family_child(&mut parent, 2);
    assert_ne!(replacement.retired_process_identity(), old_id);
    parent.state.children.acknowledge(receipt).unwrap();
    parent
        .signal_registry
        .validate_owned_child_wait(
            identity(&parent),
            old_id,
            super::super::ChildCompletion::Waitable(reverie::ExitStatus::Exited(23)),
        )
        .unwrap();
    assert!(parent.state.children.contains_key(&2));
    let memory = GuestMemory::new(0, 4096).unwrap();
    assert_eq!(
        parent
            .execute_checked(
                &SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [2, 0, libc::WNOHANG as u64, 0, 0, 0]
                ),
                &memory
            )
            .unwrap(),
        2
    );
    assert!(parent.state.children.is_empty());
    assert!(
        parent
            .signal_registry
            .family
            .lock()
            .unwrap()
            .wait_receipts
            .is_empty()
    );
}

#[test]
fn fork_wait_domains_are_isolated_while_threads_share_one() {
    let mut parent = executor();
    let _child = ready_family_child(&mut parent, 2);
    let mut fork = parent.fork_child(3, false, false).unwrap();
    let mut thread = parent.thread_child(9).unwrap();
    let memory = GuestMemory::new(0, 4096).unwrap();
    let peek = SyscallRequest::new(
        libc::SYS_waitid as u64,
        [
            libc::P_PID as u64,
            2,
            0,
            (libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) as u64,
            0,
            0,
        ],
    );
    assert_eq!(
        fork.execute_checked(&peek, &memory).unwrap(),
        -i64::from(libc::ECHILD)
    );
    assert_eq!(thread.execute_checked(&peek, &memory).unwrap(), 0);
    assert_eq!(parent.execute_checked(&peek, &memory).unwrap(), 0);
    assert_eq!(
        thread
            .execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [
                        libc::P_PID as u64,
                        2,
                        0,
                        (libc::WEXITED | libc::__WNOTHREAD) as u64,
                        0,
                        0
                    ]
                ),
                &memory
            )
            .unwrap(),
        -i64::from(libc::EINVAL)
    );
    assert!(
        parent.state.children.contains_key(&2),
        "unsupported flags do not consume"
    );
}

#[test]
fn parent_teardown_wakes_fenced_sibling_without_republishing_child() {
    for group_status in [
        reverie::ExitStatus::SUCCESS,
        reverie::ExitStatus::Exited(37),
        reverie::ExitStatus::Signaled(reverie::Signal::SIGTERM, false),
    ] {
        let mut parent = outside_init_root();
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        child.retire_current_thread(reverie::ExitStatus::Exited(23), false);
        let slot = Arc::new(super::super::ChildCompletionSlot::default());
        parent
            .begin_child_wait_publication(child_id, &slot)
            .unwrap();
        let mut sibling = parent.thread_child(9).unwrap();
        let waiter = std::thread::spawn(move || {
            let memory = GuestMemory::new(0, 4096).unwrap();
            memory.write_raw(0, &[0xa5; 4096]).unwrap();
            let result = sibling.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [2, 0x100, libc::WNOHANG as u64, 0x200, 0, 0],
                ),
                &memory,
            );
            let mut bytes = [0; 4096];
            memory.read_raw(0, &mut bytes).unwrap();
            assert_eq!(bytes, [0xa5; 4096], "termination is not a wait return");
            assert!(matches!(
                result,
                Err(crate::Error::ChildWaitGroupExit { status }) if status == group_status
            ));
            assert!(sibling.state.consumed_child_wait.is_none());
            let exit = sibling.retire_child_wait_group_exit(group_status).unwrap();
            assert_eq!(exit.status, group_status);
            assert!(exit.group);
        });
        assert!(parent.signal_registry.wait_for_guest_waiter());
        assert!(!waiter.is_finished());
        parent.retire_current_thread(group_status, true);
        waiter.join().unwrap();
        parent
            .publish_child_wait(
                child_id,
                super::super::ChildCompletion::AutoReaped(reverie::ExitStatus::Exited(23)),
                &slot,
                true,
            )
            .unwrap();
        assert!(parent.state.children.is_empty());
        assert_eq!(parent.process_exit_status(), Some(group_status));
    }
}

#[test]
fn wait_group_exit_requires_live_generation_and_nonfailed_owner() {
    for failure in [false, true] {
        let mut parent = outside_init_root();
        let mut sibling = parent.thread_child(9).unwrap();
        let mut failed_peer = failure.then(|| parent.thread_child(10).unwrap());
        let identity = sibling.state.children.task_identity().unwrap();
        let lifecycle = sibling.state.task_lifecycle.clone();
        assert_eq!(
            lifecycle
                .lock()
                .unwrap()
                .live_task_group_exit_status(identity),
            None
        );
        parent.retire_current_thread(reverie::ExitStatus::Exited(37), true);
        {
            let table = lifecycle.lock().unwrap();
            assert_eq!(
                table.live_task_group_exit_status(identity),
                Some(reverie::ExitStatus::Exited(37))
            );
            for wrong in [
                reverie::SignalTaskIdentity {
                    task_generation: identity.task_generation + 1,
                    ..identity
                },
                reverie::SignalTaskIdentity {
                    process: SignalProcessId {
                        generation: identity.process.generation + 1,
                        ..identity.process
                    },
                    ..identity
                },
                reverie::SignalTaskIdentity {
                    tid: reverie::Pid::from_raw(99),
                    ..identity
                },
            ] {
                assert_eq!(table.live_task_group_exit_status(wrong), None);
            }
        }
        if let Some(peer) = failed_peer.as_mut() {
            peer.retire_failed_thread();
            assert!(
                lifecycle
                    .lock()
                    .unwrap()
                    .get(identity.tid.as_raw())
                    .is_some()
            );
        } else {
            assert!(matches!(
                sibling.retire_child_wait_group_exit(reverie::ExitStatus::SUCCESS),
                Err(crate::Error::RunAborted)
            ));
            assert!(
                sibling
                    .retire_child_wait_group_exit(reverie::ExitStatus::Exited(37))
                    .unwrap()
                    .group
            );
        }
        assert_eq!(
            lifecycle
                .lock()
                .unwrap()
                .live_task_group_exit_status(identity),
            None
        );
        assert!(matches!(
            sibling.retire_child_wait_group_exit(reverie::ExitStatus::Exited(37)),
            Err(crate::Error::RunAborted)
        ));
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert!(matches!(
            sibling.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [2, 0, libc::WNOHANG as u64, 0, 0, 0]
                ),
                &memory,
            ),
            Err(crate::Error::RunAborted)
        ));
    }
}

#[test]
fn committed_wait_failure_precedes_clean_parent_group_exit() {
    // Exercise production family mutations, not an invented final-state map.
    for failure_kind in [0, 1, 2] {
        let mut parent = outside_init_root();
        let global = Arc::new(());
        let run = crate::failure::RunFailure::new(&global);
        if failure_kind == 2 {
            parent.install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &run);
        }
        let mut child = parent.fork_child(2, false, false).unwrap();
        let child_id = identity(&child);
        let mut sibling = parent.thread_child(9).unwrap();
        match failure_kind {
            0 => parent.fail_child_wait_publication(child_id),
            1 => child.retire_failed_thread(),
            2 => {
                crate::failure::FailureContext::new(
                    run.clone(),
                    identity(&parent).tgid,
                    identity(&parent).tgid,
                )
                .publish(
                    "group wait failure precedence",
                    crate::Error::GuestClock("forced primary".to_owned()),
                );
            }
            _ => unreachable!(),
        }
        parent.retire_current_thread(reverie::ExitStatus::SUCCESS, true);
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert!(matches!(
            sibling.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [libc::P_PID as u64, 2, 0, libc::WEXITED as u64, 0, 0]
                ),
                &memory,
            ),
            Err(crate::Error::RunAborted)
        ));
        assert!(sibling.state.consumed_child_wait.is_none());
        if failure_kind == 0 {
            assert_eq!(
                parent
                    .signal_registry
                    .family
                    .lock()
                    .unwrap()
                    .wait_publications[&process_key(child_id)]
                    .phase,
                WaitPhase::Failed
            );
        }
    }
}

#[test]
fn direct_family_failure_precedes_ready_wait_without_consumption() {
    for (ready_pid, failed_pid) in [(2, 3), (3, 2)] {
        for mode in ["wait4", "waitid", "waitid-nowait"] {
            let mut parent = executor();
            let _ready = ready_family_child(&mut parent, ready_pid);
            let failed_child = parent.fork_child(failed_pid, false, false).unwrap();
            let failed_id = identity(&failed_child);
            let mut failed_worker = failed_child.thread_child(10).unwrap();
            let mut waiter = parent.thread_child(9).unwrap();
            let registry = parent.signal_registry.clone();
            assert!(registry.run_failure.lock().unwrap().upgrade().is_none());
            let group = Arc::new(crate::vm::GuestThreadGroup::default());
            let worker_group = group.clone();
            let cause = Arc::new(crate::Error::GuestClock(
                "direct child worker failure".to_owned(),
            ));
            let worker_cause = cause.clone();
            let (committed, observed) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                // Use the real Direct outcome/retirement path, without a Tool
                // RunFailure. Hold physical return after the family commit.
                let result: crate::Result<(reverie::ExitStatus, Vec<u8>, Vec<u8>)> =
                    crate::vm::finish_host_worker_outcome(
                        None,
                        reverie::Pid::from_raw(10),
                        Err(crate::Error::SharedFailure(worker_cause)),
                        |failed| {
                            assert!(failed);
                            failed_worker.retire_failed_thread();
                            worker_group.record_worker_failure(10);
                            committed.send(()).unwrap();
                            released.recv().unwrap();
                        },
                    );
                result
            });
            group.add_worker_handle(10, handle);
            observed
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("worker did not commit its family failure");
            let memory = GuestMemory::new(0, 8192).unwrap();
            memory.map_user_permissions(0, 8192, true, true).unwrap();
            memory.enable_user_access();
            memory.write_raw(0, &[0xa5; 8192]).unwrap();
            let options = libc::WEXITED
                | if mode == "waitid-nowait" {
                    libc::WNOWAIT
                } else {
                    0
                };
            let request = if mode == "wait4" {
                SyscallRequest::new(libc::SYS_wait4 as u64, [u64::MAX, 0x100, 0, 0x400, 0, 0])
            } else {
                SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [libc::P_ALL as u64, 0, 0x100, options as u64, 0x400, 0],
                )
            };
            let family_state = || {
                let family = registry.family.lock().unwrap();
                (
                    family.direct_children.clone(),
                    family.terminal.clone(),
                    family
                        .wait_publications
                        .iter()
                        .map(|(key, publication)| (*key, publication.parent, publication.phase))
                        .collect::<Vec<_>>(),
                    family.wait_receipts.len(),
                    family.wait_failed,
                    family.wait_failure_notified,
                )
            };
            let before = family_state();
            let result = waiter.execute_checked(&request, &memory);
            let after = family_state();
            let mut actual = [0; 8192];
            memory.read_raw(0, &mut actual).unwrap();
            // Always release and collect the real worker before asserting the
            // wait result, so the old selector's expected failure cannot strand it.
            release.send(()).unwrap();
            group.join_workers();
            let terminal = group.teardown_result().unwrap_err();
            assert!(terminal.retains_primary(&cause));
            assert!(group.teardown_result().unwrap_err().retains_primary(&cause));
            assert!(!group.has_worker_handles());
            assert!(
                matches!(&result, Err(crate::Error::RunAborted)),
                "{ready_pid}/{failed_pid} {mode}: {result:?}"
            );
            assert_eq!(
                actual, [0xa5; 8192],
                "failure must precede every output write"
            );
            assert_eq!(
                after, before,
                "failure must not change eligibility or receipts"
            );
            assert_eq!(before.3, 0);
            assert!(
                !before.4 && !before.5,
                "this is the Direct family-failure path"
            );
            assert!(waiter.state.consumed_child_wait.is_none());
            assert!(parent.state.children.has_ready(Some(ready_pid)).unwrap());
            {
                let family = registry.family.lock().unwrap();
                assert_eq!(
                    family.terminal[&process_key(failed_id)],
                    ProcessFamilyExit::Failed
                );
                assert_eq!(
                    family.wait_publications[&process_key(failed_id)].phase,
                    WaitPhase::Failed
                );
            }

            // Exact-PID filtering is preserved: an unrelated failed child does
            // not change this narrowly selected child's wait contract.
            let exact = if mode == "wait4" {
                SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [ready_pid as u64, 0x100, 0, 0x400, 0, 0],
                )
            } else {
                SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [
                        libc::P_PID as u64,
                        ready_pid as u64,
                        0x100,
                        options as u64,
                        0x400,
                        0,
                    ],
                )
            };
            assert_eq!(
                waiter.execute_checked(&exact, &memory).unwrap(),
                if mode == "wait4" {
                    i64::from(ready_pid)
                } else {
                    0
                }
            );
            let mut expected = [0xa5; 8192];
            if mode == "wait4" {
                expected[0x100..0x104].copy_from_slice(&(23_i32 << 8).to_le_bytes());
            } else {
                for (offset, value) in [0, 4, 8, 16, 20, 24].into_iter().zip([
                    libc::SIGCHLD,
                    0,
                    libc::CLD_EXITED,
                    ready_pid,
                    0,
                    23,
                ]) {
                    expected[0x100 + offset..0x104 + offset].copy_from_slice(&value.to_le_bytes());
                }
            }
            expected[0x400..0x400 + std::mem::size_of::<libc::rusage>()].fill(0);
            memory.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                parent.state.children.has_ready(Some(ready_pid)).unwrap(),
                mode == "waitid-nowait"
            );
            assert!(waiter.state.consumed_child_wait.is_none());
            assert!(registry.family.lock().unwrap().wait_receipts.is_empty());
        }
    }

    // Completing the scan must not replace the first Ready with a later one.
    let mut parent = executor();
    let _later = ready_family_child(&mut parent, 3);
    let _first = ready_family_child(&mut parent, 2);
    let memory = GuestMemory::new(0, 4096).unwrap();
    let ChildWaitSelection::Ready(peek) = parent.state.children.select(None, false, true).unwrap()
    else {
        panic!("two ready children must produce a selection");
    };
    assert_eq!(peek.child.tgid.as_raw(), 2);
    assert!(peek.receipt.is_none());
    assert_eq!(
        parent
            .execute_checked(
                &SyscallRequest::new(libc::SYS_wait4 as u64, [u64::MAX, 0, 0, 0, 0, 0]),
                &memory
            )
            .unwrap(),
        2
    );
    assert!(parent.state.children.has_ready(Some(3)).unwrap());
    assert!(!parent.state.children.has_ready(Some(2)).unwrap());
}
