/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests. These calls reach the checked syscall dispatcher,
// without Detcore satisfying managed-pipe FIONBIO only in its logical FD state.
struct FionbioFixture {
    executor: ElfExecutor,
    memory: GuestMemory,
    root: TestDir,
}

impl FionbioFixture {
    fn new() -> Self {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("kvm-fionbio-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        // Construct the existing RAII fixture directly: its old new() chooses
        // host /tmp rather than the caller's physical TMPDIR.
        let root = TestDir(path);
        let carrier = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(root.0.join("stdout"))
            .unwrap();
        let mut state = test_state(&root.0);
        state.files.insert(1, carrier);
        state.cloexec_fds.insert(1);
        set_output_alias(&mut state, 1, Some(OutputAlias::Stdout));
        Self {
            executor: ElfExecutor::new(state, true),
            memory: GuestMemory::new(0, PAGE_SIZE as usize).unwrap(),
            root,
        }
    }

    fn call(&mut self, number: libc::c_long, args: [u64; 6]) -> i64 {
        self.executor
            .execute(&SyscallRequest::new(number as u64, args), &self.memory)
    }

    fn ioctl_at(&mut self, fd: u64, request: u64, address: u64) -> i64 {
        let raw = SyscallRequest::new(libc::SYS_ioctl as u64, [fd, request, address, 0, 0, 0]);
        let transported = SyscallRequest::from_syscall(raw.into_syscall().unwrap());
        assert_eq!(transported, raw, "the transport must retain the ABI words");
        self.executor.execute(&transported, &self.memory)
    }

    fn set(&mut self, fd: i64, value: i32) -> i64 {
        self.memory.write(0x201, &value.to_ne_bytes()).unwrap();
        self.ioctl_at(fd as u64, libc::FIONBIO, 0x201)
    }

    fn flags(&mut self, fd: i64) -> i32 {
        let guest = self.call(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        );
        assert!(guest >= 0, "F_GETFL({fd}): {guest}");
        let physical = fd_status_flags(host_fd(&self.executor.state, fd as i32).unwrap()).unwrap();
        assert_eq!(
            guest,
            i64::from(physical),
            "dispatcher/physical flags for {fd}"
        );
        physical
    }

    fn fd_flags(&mut self, fd: i64) -> i64 {
        self.call(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
        )
    }

    fn dup(&mut self, fd: i64, minimum: u64) -> i64 {
        let result = self.call(
            libc::SYS_fcntl,
            [fd as u64, libc::F_DUPFD_CLOEXEC as u64, minimum, 0, 0, 0],
        );
        assert!(result >= minimum as i64, "F_DUPFD_CLOEXEC: {result}");
        result
    }

    fn open(&mut self, flags: i32) -> i64 {
        self.memory.write(0x100, b"stdout\0").unwrap();
        let result = self.call(
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, 0x100, flags as u64, 0, 0, 0],
        );
        assert!(result >= 3, "open owned fixture: {result}");
        result
    }

    fn captured_stat(&mut self, fd: i64) -> libc::stat {
        assert_eq!(
            self.call(libc::SYS_fstat, [fd as u64, 0x600, 0, 0, 0, 0]),
            0
        );
        read_struct(&self.memory, 0x600)
    }
}

#[test]
fn ioctl_fionbio_reads_one_int_and_changes_only_nonblocking() {
    let mut f = FionbioFixture::new();
    assert!(f.root.0.starts_with(std::env::temp_dir()));
    assert!(f.executor.state.files[&1].metadata().unwrap().is_file());
    let before = f.flags(1);
    assert_ne!(before & libc::O_APPEND, 0);
    assert_eq!(before & libc::O_NONBLOCK, 0);
    let descriptor_flags = f.fd_flags(1);
    let captured = f.captured_stat(1);
    assert_eq!(captured.st_mode & libc::S_IFMT, libc::S_IFIFO);
    for address in [0x101, PAGE_SIZE - 4] {
        for value in [1_i32, -1, i32::MIN, 0] {
            let mut expected = vec![0xa5; PAGE_SIZE as usize];
            expected[address as usize..address as usize + 4].copy_from_slice(&value.to_ne_bytes());
            f.memory.write_raw(0, &expected).unwrap();
            let high = 0x5a5a_a5a5_u64 << 32;
            assert_eq!(
                f.ioctl_at(high | 1, high | libc::FIONBIO, address),
                0,
                "one signed int at {address:#x}, value {value}"
            );
            let expected_flags = if value == 0 {
                before & !libc::O_NONBLOCK
            } else {
                before | libc::O_NONBLOCK
            };
            assert_eq!(f.flags(1), expected_flags);
            assert_eq!(f.fd_flags(1), descriptor_flags);
            let mut actual = vec![0; expected.len()];
            f.memory.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected, "FIONBIO is input-only");
        }
    }
    let after = f.captured_stat(1);
    assert_eq!(
        (after.st_mode, after.st_dev, after.st_ino),
        (captured.st_mode, captured.st_dev, captured.st_ino),
        "capture identity must survive a backing status change"
    );
}

#[test]
fn ioctl_fionbio_aliases_share_description_and_fd_reuse_is_independent() {
    let mut f = FionbioFixture::new();
    let alias = f.dup(1, 7);
    let independent = f.open(libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC);
    let before = f.flags(1);
    let independent_before = f.flags(independent);
    assert_eq!(f.set(alias, -1), 0);
    assert_eq!(f.flags(1), before | libc::O_NONBLOCK);
    assert_eq!(f.flags(alias), before | libc::O_NONBLOCK);
    assert_eq!(f.flags(independent), independent_before);
    assert_eq!(f.fd_flags(alias), i64::from(libc::FD_CLOEXEC));
    assert_eq!(f.call(libc::SYS_close, [1, 0, 0, 0, 0, 0]), 0);
    assert_eq!(f.set(alias, 0), 0);
    assert_eq!(f.flags(alias), before & !libc::O_NONBLOCK);
    assert_eq!(
        f.call(libc::SYS_dup2, [independent as u64, 1, 0, 0, 0, 0]),
        1
    );
    assert_eq!(f.set(alias, 1), 0);
    assert_eq!(f.flags(alias), before | libc::O_NONBLOCK);
    assert_eq!(f.flags(1), independent_before);
    assert_eq!(f.flags(independent), independent_before);
    assert_eq!(
        f.fd_flags(1),
        0,
        "dup2 clears only the new descriptor's flag"
    );
    assert_eq!(f.fd_flags(alias), i64::from(libc::FD_CLOEXEC));
}

#[test]
fn ioctl_fionbio_bad_descriptors_and_faults_do_not_mutate_flags() {
    let mut f = FionbioFixture::new();
    let alias = f.dup(1, 7);
    let path = f.open(libc::O_PATH | libc::O_CLOEXEC);
    let before = f.flags(1);
    for fd in [u64::MAX, 99, path as u64] {
        assert_eq!(
            f.ioctl_at(fd, libc::FIONBIO, u64::MAX),
            negative_errno(libc::EBADF),
            "descriptor validity precedes copying the int"
        );
    }
    for address in [PAGE_SIZE - 3, PAGE_SIZE - 1, PAGE_SIZE, u64::MAX] {
        assert_eq!(
            f.ioctl_at(1, libc::FIONBIO, address),
            negative_errno(libc::EFAULT),
            "complete four-byte input at {address:#x}"
        );
        assert_eq!(f.flags(1), before);
        assert_eq!(f.flags(alias), before);
    }
    assert_eq!(
        f.ioctl_at(1, libc::FIONBIO ^ 0x100, u64::MAX),
        negative_errno(libc::ENOTTY),
        "unknown requests keep their existing refusal"
    );
    assert_eq!(f.flags(1), before);
    assert_eq!(f.call(libc::SYS_close, [1, 0, 0, 0, 0, 0]), 0);
    assert_eq!(
        f.ioctl_at(1, libc::FIONBIO, u64::MAX),
        negative_errno(libc::EBADF)
    );
    assert_eq!(f.flags(alias), before);
}

#[test]
fn ioctl_fionbio_preserves_pipe_owner_guards_and_endpoint_scope() {
    let mut f = FionbioFixture::new();
    assert_eq!(
        f.call(libc::SYS_pipe2, [0x100, libc::O_CLOEXEC as u64, 0, 0, 0, 0]),
        0
    );
    let [reader, writer]: [i32; 2] = read_struct(&f.memory, 0x100);
    let reader = i64::from(reader);
    let writer = i64::from(writer);
    let pid = f.executor.state.pid;
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [reader as u64, libc::F_SETOWN as u64, pid as u64, 0, 0, 0]
        ),
        0
    );
    let before = f.flags(reader);
    let writer_before = f.flags(writer);
    assert_eq!(f.set(reader, -1), 0);
    assert_eq!(f.flags(reader), before | libc::O_NONBLOCK);
    assert_eq!(f.flags(writer), writer_before);
    assert_eq!(
        f.call(libc::SYS_read, [reader as u64, 0x500, 1, 0, 0, 0]),
        negative_errno(libc::EAGAIN),
        "the empty pipe must really be physically nonblocking"
    );
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [
                reader as u64,
                libc::F_SETFL as u64,
                (before | libc::O_NONBLOCK | libc::O_ASYNC) as u64,
                0,
                0,
                0
            ]
        ),
        negative_errno(libc::ENOSYS),
        "FIONBIO must not relax managed-pipe fasync admission"
    );
    assert_eq!(f.flags(reader), before | libc::O_NONBLOCK);
    assert_eq!(f.set(reader, 0), 0);
    assert_eq!(f.flags(reader), before & !libc::O_NONBLOCK);
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [reader as u64, libc::F_GETOWN as u64, 0, 0, 0, 0]
        ),
        i64::from(pid)
    );
    let host = host_fd(&f.executor.state, reader as i32).unwrap();
    // SAFETY: host is an owned pipe. F_GETOWN has no pointer argument and must
    // remain zero: this virtual owner must never configure a supervisor PID.
    assert_eq!(unsafe { libc::fcntl(host, libc::F_GETOWN) }, 0);
    assert!(f.executor.state.pipe_owners[&(reader as i32)].configuration_available_for_test());
}

#[test]
fn ioctl_fionbio_keeps_virtual_signalfd_physically_nonblocking() {
    let mut f = FionbioFixture::new();
    f.memory
        .write(0x400, &KernelSigset::default().to_bytes())
        .unwrap();
    let fd = f.call(
        libc::SYS_signalfd4,
        [
            u64::MAX,
            0x400,
            KERNEL_SIGSET_SIZE as u64,
            (libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) as u64,
            0,
            0,
        ],
    );
    assert!(fd >= 3, "create virtual signalfd: {fd}");
    let alias = f.dup(fd, 7);
    let before = f.flags(fd);
    assert_ne!(before & libc::O_NONBLOCK, 0);
    assert_eq!(f.set(alias, 1), 0);
    assert_eq!(
        f.ioctl_at(alias as u64, libc::FIONBIO, u64::MAX),
        negative_errno(libc::EFAULT),
        "input copy precedes the blocking-mode guard"
    );
    assert_eq!(f.set(alias, 0), negative_errno(libc::ENOSYS));
    assert_eq!(f.flags(fd), before);
    assert_eq!(f.flags(alias), before);
    assert_eq!(f.fd_flags(fd), i64::from(libc::FD_CLOEXEC));
    assert_eq!(f.fd_flags(alias), i64::from(libc::FD_CLOEXEC));
    assert!(signalfd_mask(&f.executor.state, alias as i32).is_some());
}
