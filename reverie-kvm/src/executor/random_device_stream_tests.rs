/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests to exercise the real dispatcher and descriptor
// lifecycle using its existing fixtures. Expected bytes come from the original
// immutable carrier, independently of the generated-read implementation.

fn random_stream_carrier_bytes(
    state: &LoadedStaticElf,
    fd: i64,
    offset: u64,
    length: usize,
) -> Vec<u8> {
    let mut expected = vec![0; length];
    state.files[&(fd as i32)]
        .read_exact_at(&mut expected, offset)
        .unwrap();
    expected
}

fn random_stream_read(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    fd: i64,
    address: u64,
    length: usize,
) -> i64 {
    syscall_result(
        memory,
        state,
        libc::SYS_read,
        [fd as u64, address, length as u64, 0, 0, 0],
    )
}

fn random_stream_bytes(memory: &GuestMemory, address: u64, length: usize) -> Vec<u8> {
    let mut result = vec![0; length];
    memory.read(address, &mut result).unwrap();
    result
}

#[test]
fn random_device_stream_partitions_and_aliases_preserve_original_bytes() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
    for path in ["/dev/random", "/dev/urandom"] {
        let fd = open_readonly(&mut memory, &mut state, path);
        let expected = random_stream_carrier_bytes(&state, fd, 0, 101);
        assert_eq!(
            random_stream_read(&mut memory, &mut state, fd, 0x300, 13),
            13
        );
        let alias = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        );
        write_guest_iovecs(&mut memory, 0x100, &[(0x30d, 7), (0, 0), (0x314, 33)]);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [alias as u64, 0x100, 3, 0, 0, 0]
            ),
            40
        );
        let fcntl_alias = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [fd as u64, libc::F_DUPFD as u64, 20, 0, 0, 0],
        );
        assert!(fcntl_alias >= 20);
        assert_eq!(
            random_stream_read(&mut memory, &mut state, fcntl_alias, 0x335, 48),
            48
        );
        assert_eq!(random_stream_bytes(&memory, 0x300, 101), expected);
        assert_eq!(close(&mut state, fd as u64), 0);
        assert_eq!(close(&mut state, alias as u64), 0);
        assert_eq!(close(&mut state, fcntl_alias as u64), 0);
    }
}

#[test]
fn random_device_stream_seed_is_fixed_at_open_and_opens_are_independent() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    state.random_seed = 0x8877_6655_4433_2211;
    let first = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected_first = random_stream_carrier_bytes(&state, first, 0, 19);
    // Literal golden bytes from the original nonzero-seed contract, independent
    // of both the refactored carrier helper and the generated read helper.
    assert_eq!(
        expected_first,
        [
            0x38, 0x50, 0x88, 0x40, 0x18, 0xf0, 0xa8, 0xa0, 0x60, 0x98, 0x30, 0x08, 0xc0, 0xb8,
            0x50, 0xf8, 0xa8, 0x20, 0x78
        ]
    );
    state.random_seed = 0x1020_3040_5060_7080;
    let second = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected_second = random_stream_carrier_bytes(&state, second, 0, 19);
    assert_ne!(expected_first, expected_second);
    assert_eq!(
        random_stream_read(&mut memory, &mut state, first, 0x300, 19),
        19
    );
    assert_eq!(
        random_stream_read(&mut memory, &mut state, second, 0x400, 19),
        19
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 19), expected_first);
    assert_eq!(random_stream_bytes(&memory, 0x400, 19), expected_second);
}

#[test]
fn random_device_stream_copy_faults_advance_only_the_returned_prefix() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 3 * PAGE_SIZE as usize).unwrap();
    memory
        .map_user_permissions(0, 3 * PAGE_SIZE, true, true)
        .unwrap();
    memory
        .map_user_permissions(2 * PAGE_SIZE, PAGE_SIZE, true, false)
        .unwrap();
    memory.enable_user_access();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 0, 64);
    memory.write(2 * PAGE_SIZE, &[0xa5; 32]).unwrap();
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 2 * PAGE_SIZE, 9),
        negative_errno(libc::EFAULT)
    );
    assert_eq!(
        random_stream_bytes(&memory, 2 * PAGE_SIZE, 32),
        vec![0xa5; 32]
    );
    memory
        .map_user_permissions(2 * PAGE_SIZE, PAGE_SIZE, false, false)
        .unwrap();
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 2 * PAGE_SIZE, 9),
        negative_errno(libc::EFAULT)
    );
    memory
        .map_user_permissions(2 * PAGE_SIZE, PAGE_SIZE, true, false)
        .unwrap();
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 2 * PAGE_SIZE - 13, 33),
        13
    );
    assert_eq!(
        random_stream_bytes(&memory, 2 * PAGE_SIZE - 13, 13),
        expected[..13]
    );
    write_guest_iovecs(
        &mut memory,
        0x100,
        &[(0x400, 7), (2 * PAGE_SIZE, 9), (0x500, 3)],
    );
    memory.write(0x500, &[0xa5; 3]).unwrap();
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [fd as u64, 0x100, 3, 0, 0, 0]
        ),
        7
    );
    assert_eq!(random_stream_bytes(&memory, 0x400, 7), expected[13..20]);
    assert_eq!(random_stream_bytes(&memory, 0x500, 3), vec![0xa5; 3]);
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x600, 19),
        19
    );
    assert_eq!(random_stream_bytes(&memory, 0x600, 19), expected[20..39]);
}

#[test]
fn random_device_stream_iovec_errors_and_zero_work_do_not_consume_bytes() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 0, 17);
    for (address, count, error) in [(0x100, 1025, libc::EINVAL), (PAGE_SIZE, 1, libc::EFAULT)] {
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [fd as u64, address, count, 0, 0, 0]
            ),
            negative_errno(error)
        );
    }
    write_guest_iovecs(&mut memory, 0x100, &[(0x300, 7), (0x400, usize::MAX)]);
    memory.write(0x300, &[0xa5; 7]).unwrap();
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [fd as u64, 0x100, 2, 0, 0, 0]
        ),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 7), vec![0xa5; 7]);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [fd as u64, u64::MAX, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(random_stream_read(&mut memory, &mut state, fd, 0, 0), 0);
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x300, 17),
        17
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 17), expected);
}

#[test]
fn random_device_stream_cursor_commit_failure_is_a_backend_error() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 0, 17);
    state.random_device_descriptions[&(fd as i32)]
        .fail_cursor_commit
        .store(true, Ordering::SeqCst);
    let mut executor = ElfExecutor::new(state, false);
    let result = executor.execute_checked(
        &SyscallRequest::new(libc::SYS_read as u64, [fd as u64, 0x300, 17, 0, 0, 0]),
        &memory,
    );
    assert!(
        matches!(result, Err(crate::Error::HostIo(ref error)) if error.raw_os_error() == Some(libc::EIO))
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 17), expected);
}

#[test]
fn random_device_stream_proc_reopen_refuses_without_mutation() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    for path in ["/dev/random", "/dev/urandom"] {
        let fd = open_readonly(&mut memory, &mut state, path);
        let expected = random_stream_carrier_bytes(&state, fd, 0, 17);
        let carrier = random_stream_carrier_bytes(&state, fd, 0, 65536);
        let entries = state.files.keys().copied().collect::<Vec<_>>();
        for prefix in [
            "/dev/fd",
            "/proc/self/fd",
            "/proc/thread-self/fd",
            "/proc/1/fd",
        ] {
            for flags in [
                libc::O_RDONLY,
                libc::O_RDWR,
                libc::O_RDONLY | libc::O_TRUNC,
                libc::O_PATH,
            ] {
                assert_eq!(
                    open_with_flags(&mut memory, &mut state, &format!("{prefix}/{fd}"), flags),
                    negative_errno(libc::ENOSYS),
                    "{path} {prefix} {flags:#x}"
                );
                assert_eq!(state.files.keys().copied().collect::<Vec<_>>(), entries);
                assert_eq!(state.files[&(fd as i32)].metadata().unwrap().len(), 65536);
                assert_eq!(random_stream_carrier_bytes(&state, fd, 0, 65536), carrier);
                assert_eq!(
                    unsafe {
                        libc::lseek(state.files[&(fd as i32)].as_raw_fd(), 0, libc::SEEK_CUR)
                    },
                    0
                );
            }
        }
        assert_eq!(
            random_stream_read(&mut memory, &mut state, fd, 0x300, 17),
            17
        );
        assert_eq!(random_stream_bytes(&memory, 0x300, 17), expected);
    }
}

fn random_stream_position(state: &LoadedStaticElf, fd: i64) -> i64 {
    // SAFETY: the table owns this live carrier; SEEK_CUR does not alter it.
    unsafe { libc::lseek(state.files[&(fd as i32)].as_raw_fd(), 0, libc::SEEK_CUR) }
}

#[test]
fn random_device_stream_crosses_carrier_end_with_exact_nonperiodic_partitions() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 20 * PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    // Independent oracle: the immutable old carrier defines the preserved
    // 256-byte period, including bytes past the former 64 KiB end.
    let period = random_stream_carrier_bytes(&state, fd, 0, 256);
    let expected: Vec<_> = period.iter().copied().cycle().take(70001).collect();
    let alias = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x1000, 65523),
        65523
    );
    write_guest_iovecs(
        &mut memory,
        0x100,
        &[(0x1000 + 65523, 29), (0x1000 + 65552, 333)],
    );
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [alias as u64, 0x100, 2, 0, 0, 0]
        ),
        362
    );
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x1000 + 65885, 4116),
        4116
    );
    assert_eq!(random_stream_bytes(&memory, 0x1000, 70001), expected);
    assert_eq!(random_stream_position(&state, fd), 70001);
    assert_eq!(
        state.files[&(fd as i32)].metadata().unwrap().len(),
        65536,
        "carrier must stay bounded"
    );
}

#[test]
fn random_device_stream_rebinding_fork_exec_and_thread_table_keep_identity() {
    let root = TestDir::new();
    std::fs::write(root.0.join("ordinary"), b"ordinary").unwrap();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 0, 100);
    let description = state.random_device_descriptions[&(fd as i32)].clone();
    let ordinary = open_readonly(&mut memory, &mut state, "ordinary");
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup2,
            [fd as u64, ordinary as u64, 0, 0, 0, 0]
        ),
        ordinary
    );
    let cloexec = 20;
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup3,
            [fd as u64, cloexec, libc::O_CLOEXEC as u64, 0, 0, 0]
        ),
        cloexec as i64
    );
    assert!(Arc::ptr_eq(
        &description,
        &state.random_device_descriptions[&(ordinary as i32)]
    ));
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x400, 13),
        13
    );
    let mut forked = state.try_clone_for_fork(2).unwrap();
    assert!(Arc::ptr_eq(
        &description,
        &forked.random_device_descriptions[&(fd as i32)]
    ));
    assert_eq!(
        random_stream_read(&mut memory, &mut forked, ordinary, 0x40d, 17),
        17
    );
    let mut replacement = test_state(&root.0);
    replacement.inherit_process_state(forked);
    assert!(
        !replacement
            .random_device_descriptions
            .contains_key(&(cloexec as i32))
    );
    assert!(!replacement.files.contains_key(&(cloexec as i32)));
    assert!(Arc::ptr_eq(
        &description,
        &replacement.random_device_descriptions[&(fd as i32)]
    ));
    assert_eq!(
        random_stream_read(&mut memory, &mut replacement, fd, 0x41e, 19),
        19
    );
    assert_eq!(random_stream_bytes(&memory, 0x400, 49), expected[..49]);
    // Rebind a random slot to an ordinary file, then close/reuse the old slot.
    let plain = open_readonly(&mut memory, &mut state, "ordinary");
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup2,
            [plain as u64, ordinary as u64, 0, 0, 0, 0]
        ),
        ordinary
    );
    assert!(
        !state
            .random_device_descriptions
            .contains_key(&(ordinary as i32))
    );
    assert!(!state.random_device_fds.contains(&(ordinary as i32)));
    assert_eq!(close(&mut state, fd as u64), 0);
    assert_eq!(open_readonly(&mut memory, &mut state, "ordinary"), fd);
    assert!(!state.random_device_descriptions.contains_key(&(fd as i32)));
    assert_eq!(random_stream_read(&mut memory, &mut state, fd, 0x500, 8), 8);
    assert_eq!(random_stream_bytes(&memory, 0x500, 8), b"ordinary");
    // Real checked executors exercise the shared-table install/update path.
    let mut leader = ElfExecutor::new(replacement, false);
    let mut sibling = leader.thread_child(3).unwrap();
    let alias = leader
        .execute_checked(
            &SyscallRequest::new(libc::SYS_dup as u64, [fd as u64, 0, 0, 0, 0, 0]),
            &memory,
        )
        .unwrap();
    assert_eq!(
        sibling
            .execute_checked(
                &SyscallRequest::new(libc::SYS_read as u64, [alias as u64, 0x600, 23, 0, 0, 0]),
                &memory
            )
            .unwrap(),
        23
    );
    assert_eq!(random_stream_bytes(&memory, 0x600, 23), expected[49..72]);
    assert!(Arc::ptr_eq(
        &description,
        &sibling.state.random_device_descriptions[&(alias as i32)]
    ));
    assert_eq!(
        leader
            .execute_checked(
                &SyscallRequest::new(libc::SYS_close as u64, [alias as u64, 0, 0, 0, 0, 0]),
                &memory
            )
            .unwrap(),
        0
    );
    assert_eq!(
        sibling
            .execute_checked(
                &SyscallRequest::new(libc::SYS_read as u64, [alias as u64, 0x600, 1, 0, 0, 0]),
                &memory
            )
            .unwrap(),
        negative_errno(libc::EBADF)
    );
    assert!(
        !sibling
            .state
            .random_device_descriptions
            .contains_key(&(alias as i32))
    );
}

#[test]
fn random_device_stream_mixed_positions_overflow_and_finite_consumer_limits() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 0, 128);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_lseek,
            [fd as u64, 7, libc::SEEK_SET as u64, 0, 0, 0]
        ),
        7
    );
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x300, 13),
        13
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 13), expected[7..20]);
    write_guest_iovecs(&mut memory, 0x100, &[(0x300, 17)]);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_preadv2,
            [fd as u64, 0x100, 1, u64::MAX, 0, 0]
        ),
        17
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 17), expected[20..37]);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_pread64,
            [fd as u64, 0x300, 11, 3, 0, 0]
        ),
        11
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 11), expected[3..14]);
    assert_eq!(random_stream_position(&state, fd), 37);
    let mut output = CapturedOutput::default();
    assert_eq!(
        syscall_result_with_output(
            &mut memory,
            &mut state,
            &mut output,
            libc::SYS_sendfile,
            [1, fd as u64, 0, 19, 0, 0]
        ),
        19
    );
    assert_eq!(output.take().0, expected[37..56]);
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x300, 23),
        23
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 23), expected[56..79]);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_lseek,
            [
                fd as u64,
                i64::MAX as u64 - 3,
                libc::SEEK_SET as u64,
                0,
                0,
                0
            ]
        ),
        i64::MAX - 3
    );
    memory.write(0x300, &[0xa5; 9]).unwrap();
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x300, 9),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(random_stream_bytes(&memory, 0x300, 9), vec![0xa5; 9]);
    assert_eq!(random_stream_position(&state, fd), i64::MAX - 3);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_lseek,
            [fd as u64, 65530, libc::SEEK_SET as u64, 0, 0, 0]
        ),
        65530
    );
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x300, 19),
        19
    );
    assert_eq!(random_stream_position(&state, fd), 65549);
    // Deliberate residual: this repair extends only read/readv. Other carrier
    // consumers retain the pre-existing finite EOF, without moving the cursor.
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_preadv2,
            [fd as u64, 0x100, 1, u64::MAX, 0, 0]
        ),
        0
    );
    assert_eq!(
        syscall_result_with_output(
            &mut memory,
            &mut state,
            &mut output,
            libc::SYS_sendfile,
            [1, fd as u64, 0, 19, 0, 0]
        ),
        0
    );
    assert_eq!(random_stream_position(&state, fd), 65549);
}

#[test]
fn random_device_stream_status_and_mutation_refusals_preserve_carrier() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let carrier = random_stream_carrier_bytes(&state, fd, 0, 65536);
    write_guest_iovecs(&mut memory, 0x100, &[(0x300, 17)]);
    write_c_string(&mut memory, 0x200, &format!("/proc/self/fd/{fd}"));
    for (number, args, error) in [
        (
            libc::SYS_write,
            [fd as u64, 0x300, 17, 0, 0, 0],
            libc::EBADF,
        ),
        (
            libc::SYS_writev,
            [fd as u64, 0x100, 1, 0, 0, 0],
            libc::EBADF,
        ),
        (
            libc::SYS_pwrite64,
            [fd as u64, 0x300, 17, 0, 0, 0],
            libc::EBADF,
        ),
        (
            libc::SYS_pwritev2,
            [fd as u64, 0x100, 1, u64::MAX, 0, 0],
            libc::EBADF,
        ),
        (
            libc::SYS_sendfile,
            [fd as u64, fd as u64, 0, 17, 0, 0],
            libc::EBADF,
        ),
        (
            libc::SYS_ftruncate,
            [fd as u64, 0, 0, 0, 0, 0],
            libc::EINVAL,
        ),
        (
            libc::SYS_fallocate,
            [fd as u64, 0, 0, 17, 0, 0],
            libc::EBADF,
        ),
        (libc::SYS_truncate, [0x200, 0, 0, 0, 0, 0], libc::EINVAL),
    ] {
        assert_eq!(
            syscall_result(&mut memory, &mut state, number, args),
            negative_errno(error),
            "syscall {number}"
        );
        assert_eq!(random_stream_position(&state, fd), 0);
        assert_eq!(state.files[&(fd as i32)].metadata().unwrap().len(), 65536);
        assert_eq!(random_stream_carrier_bytes(&state, fd, 0, 65536), carrier);
    }
    let original_flags = file_status_flags(&state.files[&(fd as i32)]).unwrap();
    let untouched = random_stream_bytes(&memory, 0x300, 32);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [
                fd as u64,
                libc::F_SETFL as u64,
                (libc::O_RDWR | libc::O_DIRECT | libc::O_NONBLOCK) as u64,
                0,
                0,
                0
            ]
        ),
        negative_errno(libc::EINVAL)
    );
    let flags = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_fcntl,
        [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
    );
    // Random devices lack FMODE_CAN_ODIRECT even if their tmpfs carrier
    // accepts it. The mixed request must not change NONBLOCK or access either.
    assert_eq!(flags, i64::from(original_flags));
    assert_eq!(
        file_status_flags(&state.files[&(fd as i32)]).unwrap(),
        original_flags
    );
    assert_eq!(random_stream_position(&state, fd), 0);
    assert_eq!(random_stream_carrier_bytes(&state, fd, 0, 65536), carrier);
    assert_eq!(random_stream_bytes(&memory, 0x300, 32), untouched);
    let mut positioned = [0; 17];
    state.files[&(fd as i32)]
        .read_exact_at(&mut positioned, 3)
        .unwrap();
    assert_eq!(positioned, carrier[3..20]);
    assert_eq!(
        random_stream_read(&mut memory, &mut state, fd, 0x303, 17),
        17
    );
    assert_eq!(random_stream_bytes(&memory, 0x303, 17), carrier[..17]);
    write_guest_iovecs(&mut memory, 0x100, &[(0x300, MAX_HOST_IO + 1)]);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [fd as u64, 0x100, 1, 0, 0, 0]
        ),
        PAGE_SIZE as i64 - 0x300
    );
    let partial = PAGE_SIZE as usize - 0x300;
    let expected: Vec<u8> = (17..17 + partial)
        .map(|i| ((i * 73 + 41) & 255) as u8)
        .collect();
    assert_eq!(random_stream_bytes(&memory, 0x300, partial), expected);
    assert_eq!(random_stream_position(&state, fd), 17 + partial as i64);
    assert_eq!(random_stream_carrier_bytes(&state, fd, 0, 65536), carrier);

    // Keep an actual capacity assertion on the supported buffered path: with
    // the entire destination accessible, MAX_HOST_IO + 1 still copies only
    // MAX_HOST_IO and leaves the extra byte untouched. The ordinary-file
    // vectored_direct_io_above_staging_limit_is_refused_without_effects test
    // separately retains the direct-I/O EOPNOTSUPP contract for all six routes.
    let mut large = GuestMemory::new(0, MAX_HOST_IO + 2 * PAGE_SIZE as usize).unwrap();
    large
        .write(PAGE_SIZE, &vec![0xa5; MAX_HOST_IO + 1])
        .unwrap();
    write_guest_iovecs(&mut large, 0x100, &[(PAGE_SIZE, MAX_HOST_IO + 1)]);
    let position = random_stream_position(&state, fd);
    assert_eq!(
        syscall_result(
            &mut large,
            &mut state,
            libc::SYS_readv,
            [fd as u64, 0x100, 1, 0, 0, 0]
        ),
        MAX_HOST_IO as i64
    );
    let expected: Vec<u8> = (position as usize..position as usize + MAX_HOST_IO)
        .map(|i| ((i * 73 + 41) & 255) as u8)
        .collect();
    assert_eq!(
        random_stream_bytes(&large, PAGE_SIZE, MAX_HOST_IO),
        expected
    );
    assert_eq!(
        random_stream_bytes(&large, PAGE_SIZE + MAX_HOST_IO as u64, 1),
        [0xa5]
    );
    assert_eq!(
        random_stream_position(&state, fd),
        position + MAX_HOST_IO as i64
    );
    assert_eq!(random_stream_carrier_bytes(&state, fd, 0, 65536), carrier);
}

#[test]
fn random_device_stream_admission_failure_keeps_original_cause_and_partial_effects() {
    for (number, count, after_copy) in [
        (libc::SYS_readv, 1, false),
        (libc::SYS_readv, 0, false),
        (libc::SYS_read, 0, false),
        (libc::SYS_read, 4109, true),
    ] {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 3 * PAGE_SIZE as usize).unwrap();
        let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
        let expected = random_stream_carrier_bytes(&state, fd, 0, 4096);
        write_guest_iovecs(&mut memory, 0x100, &[(0x1000, 17)]);
        memory.write(0x1000, &[0xa5; 4109]).unwrap();
        let cause = Arc::new(crate::Error::EntryControl {
            operation: "random stream copy test",
            source: std::io::Error::other("controlled failure"),
        });
        if after_copy {
            *state.random_device_descriptions[&(fd as i32)]
                .poison_after_copy
                .lock()
                .unwrap() = Some(cause.clone());
        } else {
            memory
                .entry_gate()
                .poison(None, crate::Error::SharedFailure(cause.clone()));
        }
        let mut executor = ElfExecutor::new(state, false);
        let address = if number == libc::SYS_readv {
            0x100
        } else {
            0x1000
        };
        let result = executor.execute_checked(
            &SyscallRequest::new(number as u64, [fd as u64, address, count, 0, 0, 0]),
            &memory,
        );
        match result {
            Err(error) => assert!(error.retains_primary(&cause), "wrong failure: {error}"),
            Ok(value) => panic!("admission failure became guest result {value}"),
        }
        // A test-only observer reads the still-owned RAM after the executor
        // stopped. Ordinary GuestMemory reads intentionally reject this poison.
        let observed = unsafe {
            std::slice::from_raw_parts((memory.host_address() + 0x1000) as *const u8, 4109)
        };
        if after_copy {
            assert_eq!(&observed[..4096], expected);
            assert_eq!(&observed[4096..], &[0xa5; 13]);
        } else {
            assert_eq!(observed, &[0xa5; 4109]);
        }
        assert_eq!(
            random_stream_position(&executor.state, fd),
            0,
            "terminal failure cannot fabricate a committed guest result"
        );
    }
}

#[test]
fn random_device_stream_scm_rights_refuses_entire_message_before_effects() {
    use std::os::unix::net::UnixDatagram;
    let root = TestDir::new();
    std::fs::write(root.0.join("ordinary"), b"ordinary").unwrap();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    receiver.set_nonblocking(true).unwrap();
    let socket = insert_file_with_flags(
        &mut state,
        std::fs::File::from(std::os::fd::OwnedFd::from(sender)),
        false,
        None,
    );
    let plain = open_readonly(&mut memory, &mut state, "ordinary");
    memory.write(0x200, b"x").unwrap();
    for path in ["/dev/random", "/dev/urandom"] {
        let random = open_readonly(&mut memory, &mut state, path);
        // open_readonly uses 0x100 as its temporary pathname buffer.
        write_guest_iovecs(&mut memory, 0x100, &[(0x200, 1)]);
        let alias = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup,
            [random as u64, 0, 0, 0, 0, 0],
        );
        let before = random_stream_carrier_bytes(&state, random, 0, 65536);
        for rights in [
            vec![random as i32],
            vec![alias as i32],
            vec![plain as i32, alias as i32],
            vec![alias as i32, plain as i32],
        ] {
            let control = rights_control(&rights);
            memory.write(0x300, &control).unwrap();
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = 0x100 as *mut libc::iovec;
            message.msg_iovlen = 1;
            message.msg_control = 0x300 as *mut libc::c_void;
            message.msg_controllen = control.len();
            assert_eq!(write_struct(&mut memory, 0x400, &message), 0);
            let entries = state.files.keys().copied().collect::<Vec<_>>();
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_sendmsg,
                    [socket as u64, 0x400, 0, 0, 0, 0]
                ),
                negative_errno(libc::ENOSYS)
            );
            assert_eq!(random_stream_bytes(&memory, 0x300, control.len()), control);
            assert_eq!(state.files.keys().copied().collect::<Vec<_>>(), entries);
            assert_eq!(random_stream_position(&state, random), 0);
            assert_eq!(
                state.files[&(random as i32)].metadata().unwrap().len(),
                65536
            );
            assert_eq!(
                random_stream_carrier_bytes(&state, random, 0, 65536),
                before
            );
            assert_eq!(
                receiver.recv(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "refused message sent payload or rights"
            );
        }
    }
    // Ordinary rights remain supported, and the receiver installs the host fd.
    let control = rights_control(&[plain as i32]);
    memory.write(0x300, &control).unwrap();
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = 0x100 as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = 0x300 as *mut libc::c_void;
    message.msg_controllen = control.len();
    assert_eq!(write_struct(&mut memory, 0x400, &message), 0);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_sendmsg,
            [socket as u64, 0x400, 0, 0, 0, 0]
        ),
        1
    );
    let received = random_stream_receive_right(&receiver);
    let mut ordinary = [0; 8];
    received.read_exact_at(&mut ordinary, 0).unwrap();
    assert_eq!(&ordinary, b"ordinary");
}

fn random_stream_receive_right(receiver: &std::os::unix::net::UnixDatagram) -> std::fs::File {
    let mut byte = 0u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: all host buffers remain live and initialized for recvmsg.
    assert_eq!(
        unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) },
        1
    );
    assert_eq!(byte, b'x');
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    // SAFETY: recvmsg supplied this aligned header and its one int payload.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!((*header).cmsg_len, libc::CMSG_LEN(4) as usize);
        std::fs::File::from_raw_fd(libc::CMSG_DATA(header).cast::<i32>().read_unaligned())
    }
}

#[test]
fn random_device_stream_native_aliases_are_supported_linux_distinction() {
    use std::os::unix::net::UnixDatagram;
    // These positive controls deliberately assert Linux supports routes that
    // the virtual backend refuses until it can retain their stream metadata.
    for path in ["/dev/random", "/dev/urandom"] {
        let source = std::fs::File::open(path).unwrap();
        let reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", source.as_raw_fd()))
            .unwrap();
        let mut bytes = [0; 17];
        assert_eq!(
            unsafe { libc::read(reopened.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) },
            17
        );
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let control_bytes = rights_control(&[source.as_raw_fd()]);
        let mut control = [0usize; 8];
        unsafe {
            std::ptr::copy_nonoverlapping(
                control_bytes.as_ptr(),
                control.as_mut_ptr().cast::<u8>(),
                control_bytes.len(),
            )
        };
        let mut byte = b'x';
        let mut vector = libc::iovec {
            iov_base: (&mut byte as *mut u8).cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_bytes.len();
        assert_eq!(unsafe { libc::sendmsg(sender.as_raw_fd(), &message, 0) }, 1);
        let received = random_stream_receive_right(&receiver);
        assert_eq!(
            unsafe { libc::read(received.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) },
            17
        );
    }
}

#[test]
fn random_device_stream_sendfile_releases_position_before_blocked_output() {
    use std::time::Duration;
    use std::time::Instant;
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_readonly(&mut memory, &mut state, "/dev/urandom");
    let expected = random_stream_carrier_bytes(&state, fd, 3, 17);
    let observer = state.files[&(fd as i32)].try_clone().unwrap();
    let (writer, reader) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    let buffer = [0x5au8; 4096];
    loop {
        let written =
            unsafe { libc::write(writer.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
        if written < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
        assert!(written > 0);
    }
    writer.set_nonblocking(false).unwrap();
    reader.set_nonblocking(true).unwrap();
    state.stdin = Some(std::fs::File::from(std::os::fd::OwnedFd::from(writer)));
    let mut sibling = state.try_clone_for_fork(2).unwrap();
    let (sent, completed) = std::sync::mpsc::channel();
    let send_thread = std::thread::spawn(move || {
        let result = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_sendfile,
            [0, fd as u64, 0, 3, 0, 0],
        );
        sent.send(result).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while unsafe { libc::lseek(observer.as_raw_fd(), 0, libc::SEEK_CUR) } == 0
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    let input_consumed = unsafe { libc::lseek(observer.as_raw_fd(), 0, libc::SEEK_CUR) } == 3;
    let output_still_blocked = matches!(
        completed.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let (read_sent, read_completed) = std::sync::mpsc::channel();
    let read_thread = std::thread::spawn(move || {
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let count = random_stream_read(&mut memory, &mut sibling, fd, 0x300, 17);
        read_sent
            .send((count, random_stream_bytes(&memory, 0x300, 17)))
            .unwrap();
    });
    let early = read_completed.recv_timeout(Duration::from_secs(2));
    // Always rescue the output before asserting, so a regressed guard lifetime
    // fails this test instead of leaving a blocked worker behind.
    let mut drain = [0; 65536];
    loop {
        let count = unsafe {
            libc::recv(
                reader.as_raw_fd(),
                drain.as_mut_ptr().cast(),
                drain.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
        if count == 0 {
            break;
        }
    }
    send_thread.join().unwrap();
    read_thread.join().unwrap();
    assert!(
        input_consumed,
        "sendfile must reach the blocked-output interval"
    );
    assert!(output_still_blocked, "fixture did not block output");
    let (count, bytes) = early.expect("random read waited for unrelated output completion");
    assert_eq!(count, 17);
    assert_eq!(bytes, expected);
    assert_eq!(completed.recv_timeout(Duration::from_secs(2)).unwrap(), 3);
}
