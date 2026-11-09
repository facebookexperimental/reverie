/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Linux kernel/exit.c's raw waitid wrapper copies event rusage first, then
// six scalar siginfo fields. It leaves padding and non-SIGCHLD fields alone.
// These backend tests deliberately retain the existing zero-rusage personality;
// no equality with native Linux's changing accounting counters is assumed.
const WAITID_COPYOUT_BASE: u64 = 0x1_0000;
const WAITID_COPYOUT_BYTES: usize = 3 * PAGE_SIZE as usize;
const WAITID_EXIT3_FIELDS: [i32; 6] = [libc::SIGCHLD, 0, libc::CLD_EXITED, 7, 0, 3];

fn waitid_copyout_memory(base: u64) -> GuestMemory {
    let memory = GuestMemory::new(base, WAITID_COPYOUT_BYTES).unwrap();
    memory
        .map_user_permissions(base, 3 * PAGE_SIZE, true, true)
        .unwrap();
    memory.enable_user_access();
    memory
        .write_raw(base, &vec![0xa5; WAITID_COPYOUT_BYTES])
        .unwrap();
    memory
}

fn waitid_expected_fields(
    expected: &mut [u8],
    base: u64,
    info: u64,
    fields: [i32; 6],
    writable_prefix: usize,
) {
    if info == 0 {
        return;
    }
    for (offset, value) in [0, 4, 8, 16, 20, 24].into_iter().zip(fields) {
        if offset + 4 > writable_prefix {
            break;
        }
        let start = (info - base) as usize + offset;
        expected[start..start + 4].copy_from_slice(&value.to_ne_bytes());
    }
}

fn assert_waitid_arena(memory: &GuestMemory, base: u64, expected: &[u8]) {
    let mut actual = vec![0; expected.len()];
    memory.read_raw(base, &mut actual).unwrap();
    assert_eq!(actual, expected, "waitid changed unexpected output bytes");
}

fn assert_waitid_terminal_effects(
    memory: &mut GuestMemory,
    base: u64,
    args: [u64; 6],
    status: ExitStatus,
    result: i64,
    expected: &[u8],
) {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    state.children.insert(7, status);
    state.children.insert(8, ExitStatus::Exited(4));
    assert_eq!(waitid(memory, &mut state, &args), result, "{args:?}");
    assert_waitid_arena(memory, base, expected);
    if args[3] & libc::WNOWAIT as u64 != 0 {
        assert_eq!(state.children.get(&7), Some(status));
        assert_eq!(state.children.len(), 2);
        assert!(state.consumed_child_wait.is_none());
        // Another protected-output EFAULT could hide ECHILD. A successful
        // NULL-output WNOWAIT independently proves that this child remains.
        assert_eq!(
            waitid(
                memory,
                &mut state,
                &[
                    libc::P_PID as u64,
                    7,
                    0,
                    (libc::WEXITED | libc::WNOWAIT) as u64,
                    0,
                    0,
                ],
            ),
            0
        );
        assert!(state.consumed_child_wait.is_none());
        assert_eq!(
            waitid(
                memory,
                &mut state,
                &[libc::P_PID as u64, 7, 0, libc::WEXITED as u64, 0, 0],
            ),
            0
        );
    }
    // Scalar-only tests acknowledge the effect that execute_checked drains.
    let receipt = state
        .consumed_child_wait
        .take()
        .expect("consuming wait retained its receipt");
    assert_eq!(receipt.child_pid(), 7);
    state.children.acknowledge(receipt).unwrap();
    assert!(!state.children.contains_key(&7));
    assert_eq!(state.children.len(), 1);
    assert_eq!(state.children.get(&8), Some(ExitStatus::Exited(4)));
    assert_eq!(
        waitid(
            memory,
            &mut state,
            &[libc::P_PID as u64, 7, 0, libc::WEXITED as u64, 0, 0],
        ),
        negative_errno(libc::ECHILD)
    );
    assert!(state.consumed_child_wait.is_none());
    assert_eq!(state.children.len(), 1);
    assert_eq!(state.children.get(&8), Some(ExitStatus::Exited(4)));
    assert_waitid_arena(memory, base, expected);
}

#[test]
fn waitid_writable_and_null_outputs_preserve_nonfields() {
    let base = WAITID_COPYOUT_BASE;
    // Both outputs cross a fully writable page boundary; the scalar is unaligned.
    let info = base + PAGE_SIZE - 2;
    let usage = base + 2 * PAGE_SIZE - 64;
    for (status, fields) in [
        (ExitStatus::Exited(3), WAITID_EXIT3_FIELDS),
        (
            ExitStatus::Signaled(Signal::SIGTERM, false),
            [libc::SIGCHLD, 0, libc::CLD_KILLED, 7, 0, libc::SIGTERM],
        ),
        (
            ExitStatus::Signaled(Signal::SIGABRT, true),
            [libc::SIGCHLD, 0, libc::CLD_DUMPED, 7, 0, libc::SIGABRT],
        ),
    ] {
        for keep in [0, libc::WNOWAIT] {
            for write_info in [true, false] {
                for write_usage in [true, false] {
                    let mut memory = waitid_copyout_memory(base);
                    let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
                    if write_info {
                        waitid_expected_fields(&mut expected, base, info, fields, 28);
                    }
                    if write_usage {
                        let start = (usage - base) as usize;
                        expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
                    }
                    assert_waitid_terminal_effects(
                        &mut memory,
                        base,
                        [
                            libc::P_PID as u64,
                            7,
                            if write_info { info } else { 0 },
                            (libc::WEXITED | keep) as u64,
                            if write_usage { usage } else { 0 },
                            0,
                        ],
                        status,
                        0,
                        &expected,
                    );
                }
            }
        }
    }
}

#[test]
fn waitid_read_only_outputs_reap_or_preserve_wnowait_in_order() {
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    let usage = base + PAGE_SIZE + 0x100;
    for accessible in [true, false] {
        for (info_fault, usage_fault) in [(true, false), (false, true), (true, true)] {
            for keep in [0, libc::WNOWAIT] {
                let mut memory = waitid_copyout_memory(base);
                if info_fault {
                    memory
                        .map_user_permissions(base, PAGE_SIZE, accessible, false)
                        .unwrap();
                }
                if usage_fault {
                    memory
                        .map_user_permissions(base + PAGE_SIZE, PAGE_SIZE, accessible, false)
                        .unwrap();
                }
                let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
                if !usage_fault {
                    let start = (usage - base) as usize;
                    expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
                }
                assert_waitid_terminal_effects(
                    &mut memory,
                    base,
                    [
                        libc::P_PID as u64,
                        7,
                        info,
                        (libc::WEXITED | keep) as u64,
                        usage,
                        0,
                    ],
                    ExitStatus::Exited(3),
                    negative_errno(libc::EFAULT),
                    &expected,
                );
            }
        }
    }
}

#[test]
fn waitid_siginfo_split_fields_are_nonpartial_and_ordered() {
    let base = WAITID_COPYOUT_BASE;
    let usage = base + 2 * PAGE_SIZE + 0x100;
    for accessible in [true, false] {
        for prefix in [1, 3, 5, 9, 17, 21, 25, 28] {
            for keep in [0, libc::WNOWAIT] {
                let mut memory = waitid_copyout_memory(base);
                memory
                    .map_user_permissions(base + PAGE_SIZE, PAGE_SIZE, accessible, false)
                    .unwrap();
                let info = base + PAGE_SIZE - prefix as u64;
                let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
                let start = (usage - base) as usize;
                expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
                waitid_expected_fields(&mut expected, base, info, WAITID_EXIT3_FIELDS, prefix);
                // At28 all six scalars fit. The protected128-byte structure's
                // tail is never accessed; an all-structure probe is incorrect.
                let result = if prefix == 28 {
                    0
                } else {
                    negative_errno(libc::EFAULT)
                };
                assert_waitid_terminal_effects(
                    &mut memory,
                    base,
                    [
                        libc::P_PID as u64,
                        7,
                        info,
                        (libc::WEXITED | keep) as u64,
                        usage,
                        0,
                    ],
                    ExitStatus::Exited(3),
                    result,
                    &expected,
                );
            }
        }
    }
}

#[test]
fn waitid_split_rusage_fault_precedes_siginfo() {
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    for accessible in [true, false] {
        for prefix in [1, 8, 64] {
            for keep in [0, libc::WNOWAIT] {
                let mut memory = waitid_copyout_memory(base);
                memory
                    .map_user_permissions(base + 2 * PAGE_SIZE, PAGE_SIZE, accessible, false)
                    .unwrap();
                let usage = base + 2 * PAGE_SIZE - prefix as u64;
                let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
                let start = (usage - base) as usize;
                expected[start..start + prefix].fill(0);
                assert_waitid_terminal_effects(
                    &mut memory,
                    base,
                    [
                        libc::P_PID as u64,
                        7,
                        info,
                        (libc::WEXITED | keep) as u64,
                        usage,
                        0,
                    ],
                    ExitStatus::Exited(3),
                    negative_errno(libc::EFAULT),
                    &expected,
                );
            }
        }
    }
}

#[test]
fn waitid_errors_store_only_six_zero_fields() {
    let root = TestDir::new();
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    let usage = base + PAGE_SIZE + 0x100;
    for (which, pid, options, errno) in [
        (libc::P_PID as u64, 99, libc::WEXITED, libc::ECHILD),
        (libc::P_PID as u64, 7, 0, libc::EINVAL),
        (libc::P_PID as u64, 7, libc::WNOHANG, libc::EINVAL),
        (libc::P_PID as u64, 7, libc::WEXITED | 0x40, libc::EINVAL),
        (u64::MAX, 7, libc::WEXITED, libc::EINVAL),
    ] {
        // NULL, writable, read-only and inaccessible siginfo destinations.
        for output in [1, 2, 3, 0] {
            for high in [0, 0xdead_beef_u64 << 32] {
                let mut memory = waitid_copyout_memory(base);
                if output >= 2 {
                    memory
                        .map_user_permissions(base, PAGE_SIZE, output == 2, false)
                        .unwrap();
                }
                let mut state = test_state(&root.0);
                state.children.insert(7, ExitStatus::Exited(3));
                state.children.insert(8, ExitStatus::Exited(4));
                let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
                if output == 1 {
                    waitid_expected_fields(&mut expected, base, info, [0; 6], 28);
                }
                assert_eq!(
                    waitid(
                        &mut memory,
                        &mut state,
                        &[
                            which,
                            pid,
                            if output == 0 { 0 } else { info },
                            high | options as u64,
                            usage,
                            0,
                        ],
                    ),
                    negative_errno(if output >= 2 { libc::EFAULT } else { errno })
                );
                assert!(state.consumed_child_wait.is_none());
                assert_eq!(state.children.len(), 2);
                assert_eq!(state.children.get(&7), Some(ExitStatus::Exited(3)));
                assert_eq!(state.children.get(&8), Some(ExitStatus::Exited(4)));
                assert_waitid_arena(&memory, base, &expected);
            }
        }
    }
}

#[test]
fn waitid_options_use_linux_int_width() {
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    let usage = base + PAGE_SIZE + 0x100;
    for low in [
        libc::WEXITED,
        libc::WEXITED | libc::WNOHANG,
        libc::WEXITED | libc::WNOWAIT,
    ] {
        for high in [0xdead_beef_u64 << 32, u64::from(u32::MAX) << 32, 0] {
            let mut memory = waitid_copyout_memory(base);
            let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
            waitid_expected_fields(&mut expected, base, info, WAITID_EXIT3_FIELDS, 28);
            let start = (usage - base) as usize;
            expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
            assert_waitid_terminal_effects(
                &mut memory,
                base,
                [libc::P_PID as u64, 7, info, high | low as u64, usage, 0],
                ExitStatus::Exited(3),
                0,
                &expected,
            );
        }
    }
}

#[test]
fn waitid_numeric_copyout_boundaries_preserve_field_order() {
    let limit = X86_64_GUEST_USER_LIMIT;
    // Deliberately map a synthetic page beyond the architectural user limit.
    // GuestMemory writability alone must not permit stores into this guard.
    let base = limit - 2 * PAGE_SIZE;
    let usage = base + 0x100;
    for (info, writable_prefix) in [
        (limit - 128, 128),
        (limit - 127, 127),
        (limit - 28, 28),
        (limit - 25, 25),
        (limit - 24, 24),
        (limit - 21, 21),
        (limit - 20, 20),
        (limit - 17, 17),
        (limit - 16, 16),
        (limit - 9, 9),
        (limit - 8, 8),
        (limit - 5, 5),
        (limit - 4, 4),
        (limit - 1, 1),
        (limit, 0),
        (limit + PAGE_SIZE - 28, 0),
        (u64::MAX - 31, 0),
        (1_u64 << 63, 0),
    ] {
        for keep in [0, libc::WNOWAIT] {
            let mut memory = waitid_copyout_memory(base);
            let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
            let start = (usage - base) as usize;
            expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
            waitid_expected_fields(
                &mut expected,
                base,
                info,
                WAITID_EXIT3_FIELDS,
                writable_prefix,
            );
            assert_waitid_terminal_effects(
                &mut memory,
                base,
                [
                    libc::P_PID as u64,
                    7,
                    info,
                    (libc::WEXITED | keep) as u64,
                    usage,
                    0,
                ],
                ExitStatus::Exited(3),
                if writable_prefix >= 28 {
                    0
                } else {
                    negative_errno(libc::EFAULT)
                },
                &expected,
            );
        }
    }

    // Linux v7.1's dynamic rusage range accepts end == limit. The measured
    // T-145/T-144 successes and T-143/64/8/1 faults have no accounting-equality
    // premise; this backend separately retains its explicit zero personality.
    let info = base + 0x100;
    for (usage, valid) in [
        (limit - 145, true),
        (limit - 144, true),
        (limit - 143, false),
        (limit - 64, false),
        (limit - 8, false),
        (limit - 1, false),
        (limit, false),
        (limit + PAGE_SIZE - 144, false),
        (u64::MAX - 31, false),
        (1_u64 << 63, false),
    ] {
        for keep in [0, libc::WNOWAIT] {
            let mut memory = waitid_copyout_memory(base);
            let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
            if valid {
                let start = (usage - base) as usize;
                expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
                waitid_expected_fields(&mut expected, base, info, WAITID_EXIT3_FIELDS, 28);
            }
            assert_waitid_terminal_effects(
                &mut memory,
                base,
                [
                    libc::P_PID as u64,
                    7,
                    info,
                    (libc::WEXITED | keep) as u64,
                    usage,
                    0,
                ],
                ExitStatus::Exited(3),
                if valid {
                    0
                } else {
                    negative_errno(libc::EFAULT)
                },
                &expected,
            );
        }
    }
}

#[test]
fn waitid_wnohang_checks_options_before_starting_child() {
    let root = TestDir::new();
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    let usage = base + PAGE_SIZE + 0x100;
    // Both invalid forms are nonblocking even on the unfixed synchronizer.
    // No sleep/watchdog is needed to rescue a deliberately invalid test call.
    for low in [libc::WNOHANG, libc::WEXITED | libc::WNOHANG | 0x40] {
        for high in [0, 0xdead_beef_u64 << 32] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            let (start_sender, start_receiver) = std::sync::mpsc::channel();
            let (release_sender, release_receiver) = std::sync::mpsc::channel();
            let completion = executor.mock_child_completion(7);
            let child_completion = completion.clone();
            let handle = ChildThread::spawn(move || {
                release_receiver.recv().unwrap();
                assert!(child_completion.publish(ChildCompletion::Waitable(ExitStatus::Exited(9))));
                Ok(())
            });
            executor.register_mock_child_process(7, start_sender, completion, handle);
            let memory = waitid_copyout_memory(base);
            let result = executor.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [libc::P_PID as u64, 7, info, high | low as u64, usage, 0],
                ),
                &memory,
            );
            let not_started = matches!(
                start_receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            let still_pending = executor.has_pending_child_process(7);
            let unconsumed = executor.state.consumed_child_wait.is_none();
            // Retire the real helper before assertions that intentionally fail
            // on the base. Its start channel remains available to join_all.
            release_sender.send(()).unwrap();
            executor.join_all_child_processes().unwrap();
            assert_eq!(result.unwrap(), negative_errno(libc::EINVAL));
            assert!(not_started, "invalid options released the child start gate");
            assert!(still_pending, "invalid options collected a child");
            assert!(unconsumed);
            let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
            waitid_expected_fields(&mut expected, base, info, [0; 6], 28);
            assert_waitid_arena(&memory, base, &expected);
        }
    }
}

#[test]
fn waitid_wnohang_writes_only_fields_without_consuming() {
    let root = TestDir::new();
    let base = WAITID_COPYOUT_BASE;
    let info = base + 0x100;
    let usage = base + PAGE_SIZE + 0x100;
    for output in [1, 2, 3, 0] {
        for high in [0, 0xdead_beef_u64 << 32] {
            let mut executor = ElfExecutor::new(test_state(&root.0), false);
            let (start_sender, start_receiver) = std::sync::mpsc::channel();
            let (running_sender, running_receiver) = std::sync::mpsc::channel();
            let (release_sender, release_receiver) = std::sync::mpsc::channel();
            let completion = executor.mock_child_completion(7);
            let child_completion = completion.clone();
            let handle = ChildThread::spawn(move || {
                running_sender.send(()).unwrap();
                start_receiver.recv().unwrap();
                release_receiver.recv().unwrap();
                assert!(child_completion.publish(ChildCompletion::Waitable(ExitStatus::Exited(9))));
                Ok(())
            });
            executor.register_mock_child_process(7, start_sender, completion, handle);
            running_receiver.recv().unwrap();
            let memory = waitid_copyout_memory(base);
            if output >= 2 {
                memory
                    .map_user_permissions(base, PAGE_SIZE, output == 2, false)
                    .unwrap();
            }
            let poll = executor.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [
                        libc::P_PID as u64,
                        7,
                        if output == 0 { 0 } else { info },
                        high | (libc::WEXITED | libc::WNOHANG) as u64,
                        usage,
                        0,
                    ],
                ),
                &memory,
            );
            let mut observed = vec![0; WAITID_COPYOUT_BYTES];
            memory.read_raw(base, &mut observed).unwrap();
            let no_terminal = executor.state.children.is_empty();
            let no_consumption = executor.state.consumed_child_wait.is_none();
            let still_pending = executor.has_pending_child_process(7);
            release_sender.send(()).unwrap();
            let reap = executor.execute_checked(
                &SyscallRequest::new(
                    libc::SYS_waitid as u64,
                    [libc::P_PID as u64, 7, 0, libc::WEXITED as u64, 0, 0],
                ),
                &memory,
            );
            executor.join_all_child_processes().unwrap();
            assert_eq!(
                poll.unwrap(),
                if output >= 2 {
                    negative_errno(libc::EFAULT)
                } else {
                    0
                }
            );
            assert!(no_terminal && no_consumption && still_pending);
            let mut expected = vec![0xa5; WAITID_COPYOUT_BYTES];
            if output == 1 {
                waitid_expected_fields(&mut expected, base, info, [0; 6], 28);
            }
            assert_eq!(observed, expected);
            assert_eq!(reap.unwrap(), 0);
            assert!(executor.state.children.is_empty());
            assert!(executor.state.consumed_child_wait.is_none());
            assert_waitid_arena(&memory, base, &expected);
            assert_eq!(
                executor
                    .execute_checked(
                        &SyscallRequest::new(
                            libc::SYS_waitid as u64,
                            [libc::P_PID as u64, 7, 0, libc::WEXITED as u64, 0, 0],
                        ),
                        &memory,
                    )
                    .unwrap(),
                negative_errno(libc::ECHILD)
            );
        }
    }
}
