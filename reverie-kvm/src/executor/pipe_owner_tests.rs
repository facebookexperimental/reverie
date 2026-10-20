/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn owner_test_pipe(state: &mut LoadedStaticElf) -> [i32; 2] {
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        syscall_result(
            &mut memory,
            state,
            libc::SYS_pipe2,
            [0x100, libc::O_NONBLOCK as u64, 0, 0, 0, 0]
        ),
        0
    );
    read_struct(&memory, 0x100)
}

fn owner_test_call(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    fd: i32,
    command: i32,
    argument: u64,
) -> i64 {
    syscall_result(
        memory,
        state,
        libc::SYS_fcntl,
        [fd as u64, command as u64, argument, 0, 0, 0],
    )
}

fn owner_native_call(fd: i32, command: i32, argument: u64) -> i64 {
    // SAFETY: callers own the fd/argument storage or deliberately pass an
    // invalid kernel-checked pointer. No host standard descriptor is changed.
    let result = unsafe { libc::syscall(libc::SYS_fcntl, fd, command, argument) };
    if result == -1 {
        io_error(std::io::Error::last_os_error())
    } else {
        result
    }
}

fn owner_native_pipe() -> [std::fs::File; 2] {
    let mut fds = [-1; 2];
    // SAFETY: fds is writable for both returned descriptors.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    // SAFETY: pipe2 returned two distinct, uniquely owned descriptors.
    fds.map(|fd| unsafe { std::fs::File::from_raw_fd(fd) })
}

#[test]
fn fcntl_owner_initial_self_clear_and_signal_width_match_native() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let [read, write] = owner_test_pipe(&mut state);
    let native = owner_native_pipe();
    let host = native[0].as_raw_fd();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, libc::F_GETOWN, u64::MAX),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, LINUX_F_GETSIG, u64::MAX),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, LINUX_F_GETOWN_EX, 0x200),
        0
    );
    assert_eq!(read_struct::<[i32; 2]>(&memory, 0x200), [0, 0]);
    for argument in [
        0,
        libc::SIGUSR1 as u64,
        64,
        65,
        u64::MAX,
        (1_u64 << 32) | libc::SIGUSR2 as u64,
        1_u64 << 32,
        0x8000_0000,
    ] {
        let before = owner_native_call(host, LINUX_F_GETSIG, 0);
        let native_result = owner_native_call(host, LINUX_F_SETSIG, argument);
        assert_eq!(
            owner_test_call(&mut memory, &mut state, read, LINUX_F_SETSIG, argument),
            native_result,
            "SETSIG argument={argument:#x}"
        );
        let after = owner_native_call(host, LINUX_F_GETSIG, 0);
        if native_result < 0 {
            assert_eq!(after, before);
        }
        assert_eq!(
            owner_test_call(&mut memory, &mut state, read, LINUX_F_GETSIG, 0),
            after
        );
    }
    // SETSIG alone keeps the initial TID/0 owner type, and pipe ends are distinct.
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, LINUX_F_GETOWN_EX, 0x200),
        0
    );
    assert_eq!(read_struct::<[i32; 2]>(&memory, 0x200), [0, 0]);
    assert_eq!(
        owner_test_call(&mut memory, &mut state, write, LINUX_F_GETSIG, 0),
        0
    );
    let pid = state.pid;
    let high = 0x5a5a_a5a5_u64 << 32;
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_fcntl,
            [
                high | read as u64,
                high | libc::F_SETOWN as u64,
                high | pid as u64,
                0,
                0,
                0
            ]
        ),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, libc::F_GETOWN, 0),
        i64::from(pid)
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, LINUX_F_GETOWN_EX, 0x200),
        0
    );
    assert_eq!(read_struct::<[i32; 2]>(&memory, 0x200), [1, pid]);
    // The actual host pipe must never target the virtual guest PID.
    assert_eq!(
        owner_native_call(host_fd(&state, read).unwrap(), libc::F_GETOWN, 0),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, libc::F_SETOWN, 0),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, read, LINUX_F_GETOWN_EX, 0x200),
        0
    );
    assert_eq!(read_struct::<[i32; 2]>(&memory, 0x200), [1, 0]);
    let flags = fd_status_flags(host_fd(&state, read).unwrap()).unwrap();
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut state,
            read,
            libc::F_SETFL,
            (flags | libc::O_ASYNC | libc::O_APPEND) as u64
        ),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        fd_status_flags(host_fd(&state, read).unwrap()).unwrap(),
        flags
    );
}

#[test]
fn fcntl_owner_input_errors_preserve_state_and_linux_order() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let [fd, _] = owner_test_pipe(&mut state);
    let native = owner_native_pipe();
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let pid = state.pid;
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_SETOWN, pid as u64),
        0
    );
    for (kind, owner, expected) in [
        (3, 0, libc::EINVAL),
        (-1, -1, libc::EINVAL),
        (1, -1, libc::ESRCH),
        (0, -1, libc::ESRCH),
        (2, -1, libc::ESRCH),
    ] {
        let input: [i32; 2] = [kind, owner];
        memory.write(0x201, &struct_bytes(&input)).unwrap();
        assert_eq!(
            owner_native_call(
                native[0].as_raw_fd(),
                LINUX_F_SETOWN_EX,
                input.as_ptr() as u64
            ),
            negative_errno(expected)
        );
        assert_eq!(
            owner_test_call(&mut memory, &mut state, fd, LINUX_F_SETOWN_EX, 0x201),
            negative_errno(expected)
        );
        assert_eq!(
            owner_test_call(&mut memory, &mut state, fd, libc::F_GETOWN, 0),
            i64::from(pid)
        );
    }
    for command in [LINUX_F_SETOWN_EX, LINUX_F_GETOWN_EX] {
        for raw in [u64::MAX, X86_64_GUEST_USER_LIMIT - 4] {
            assert_eq!(
                owner_test_call(&mut memory, &mut state, fd, command, raw),
                negative_errno(libc::EFAULT)
            );
            assert_eq!(
                owner_test_call(&mut memory, &mut state, -1, command, raw),
                negative_errno(libc::EBADF)
            );
        }
    }
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut state,
            fd,
            libc::F_SETOWN,
            i32::MIN as u32 as u64
        ),
        negative_errno(libc::EINVAL)
    );
    for requested in [-123_i32, pid + 1] {
        assert_eq!(
            owner_test_call(
                &mut memory,
                &mut state,
                fd,
                libc::F_SETOWN,
                requested as u64
            ),
            negative_errno(libc::ENOSYS)
        );
    }
    let path = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open("/dev/null")
        .unwrap();
    let path_fd = insert_file_with_flags(&mut state, path, false, None) as i32;
    for command in [
        libc::F_GETOWN,
        libc::F_SETOWN,
        LINUX_F_GETOWN_EX,
        LINUX_F_SETOWN_EX,
        LINUX_F_SETSIG,
        LINUX_F_GETSIG,
    ] {
        assert_eq!(
            owner_native_call(host_fd(&state, path_fd).unwrap(), command, u64::MAX),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            owner_test_call(&mut memory, &mut state, path_fd, command, u64::MAX),
            negative_errno(libc::EBADF)
        );
    }
    // A straddling SETOWN_EX must never apply even its readable type word.
    memory
        .map_user_permissions(0, PAGE_SIZE, true, true)
        .unwrap();
    memory
        .map_user_permissions(PAGE_SIZE, PAGE_SIZE, false, false)
        .unwrap();
    memory.enable_user_access();
    memory
        .write_raw(PAGE_SIZE - 4, &struct_bytes(&[1_i32, 0]))
        .unwrap();
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut state,
            fd,
            LINUX_F_SETOWN_EX,
            PAGE_SIZE - 4
        ),
        negative_errno(libc::EFAULT)
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_GETOWN, 0),
        i64::from(pid)
    );
}

#[test]
fn fcntl_owner_getown_ex_copyout_matches_complete_native_arenas() {
    for (offset, page, protection, expected) in [
        (0x201, 1, libc::PROT_READ | libc::PROT_WRITE, 0),
        (0x201, 0, libc::PROT_READ, negative_errno(libc::EFAULT)),
        (
            PAGE_SIZE - 1,
            1,
            libc::PROT_NONE,
            negative_errno(libc::EFAULT),
        ),
        (
            PAGE_SIZE - 4,
            1,
            libc::PROT_NONE,
            negative_errno(libc::EFAULT),
        ),
        (
            PAGE_SIZE - 6,
            1,
            libc::PROT_READ,
            negative_errno(libc::EFAULT),
        ),
    ] {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        // Only the native oracle's private pipe receives the real self PID.
        state.pid = unsafe { libc::getpid() };
        let pid = state.pid;
        let [fd, _] = owner_test_pipe(&mut state);
        let native = owner_native_pipe();
        let mut buffer = SocketQueryCopyoutBuffer::new();
        assert_eq!(
            owner_test_call(
                &mut buffer.guest,
                &mut state,
                fd,
                libc::F_SETOWN,
                pid as u64
            ),
            0
        );
        assert_eq!(
            owner_native_call(native[0].as_raw_fd(), libc::F_SETOWN, pid as u64),
            0
        );
        buffer.protect_page(page, protection);
        assert_eq!(
            owner_native_call(
                native[0].as_raw_fd(),
                LINUX_F_GETOWN_EX,
                buffer.pointer(offset) as u64
            ),
            expected
        );
        assert_eq!(
            owner_test_call(&mut buffer.guest, &mut state, fd, LINUX_F_GETOWN_EX, offset),
            expected
        );
        // SAFETY: restore readability of our allocation only after both calls.
        assert_eq!(
            unsafe {
                libc::mprotect(
                    buffer.native,
                    SocketQueryCopyoutBuffer::LENGTH,
                    libc::PROT_READ,
                )
            },
            0
        );
        let actual = buffer.bytes();
        let native_bytes = unsafe {
            std::slice::from_raw_parts(buffer.native.cast::<u8>(), SocketQueryCopyoutBuffer::LENGTH)
        };
        assert_eq!(
            actual, native_bytes,
            "offset={offset} protection={protection}"
        );
        let count = if expected == 0 {
            8
        } else if page == 0 {
            0
        } else {
            (PAGE_SIZE - offset) as usize
        };
        let owner = [1_i32.to_ne_bytes(), pid.to_ne_bytes()].concat();
        let mut explicit = vec![0xa5; SocketQueryCopyoutBuffer::LENGTH];
        explicit[offset as usize..offset as usize + count].copy_from_slice(&owner[..count]);
        assert_eq!(actual, explicit, "exact copied prefix and untouched suffix");
    }
}

#[test]
fn fcntl_owner_copyout_notifies_after_releasing_configuration_lock() {
    struct OwnerWake {
        owner: Arc<pipe_owner::PipeOwner>,
        calls: AtomicU64,
    }
    impl std::task::Wake for OwnerWake {
        fn wake(self: Arc<Self>) {
            Self::wake_by_ref(&self);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            assert!(
                self.owner.configuration_available_for_test(),
                "pipe owner lock held during guest copy notification"
            );
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }
    for writable in [true, false] {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let [fd, _] = owner_test_pipe(&mut state);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        memory.write_raw(0x200, &[0xa5; 8]).unwrap();
        memory
            .map_user_permissions(0, PAGE_SIZE, true, writable)
            .unwrap();
        memory.enable_user_access();
        let observer = Arc::new(OwnerWake {
            owner: state.pipe_owners[&fd].clone(),
            calls: AtomicU64::new(0),
        });
        use std::future::Future;
        let mut notification = Box::pin(memory.entry_gate().subscribe());
        let waker = std::task::Waker::from(observer.clone());
        assert!(
            notification
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(
            owner_test_call(&mut memory, &mut state, fd, LINUX_F_GETOWN_EX, 0x200),
            if writable {
                0
            } else {
                negative_errno(libc::EFAULT)
            }
        );
        assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
        // Subscription destruction occurs here, never inside its own wake.
        drop(notification);
        let mut actual = [0; 8];
        memory.read_raw(0x200, &mut actual).unwrap();
        assert_eq!(actual, if writable { [0; 8] } else { [0xa5; 8] });
    }
}

#[test]
fn fcntl_owner_dup_close_reuse_and_snapshots_preserve_description_identity() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let [fd, other] = owner_test_pipe(&mut state);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let pid = state.pid;
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_SETOWN, pid as u64),
        0
    );
    let duplicate = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    ) as i32;
    let fcntl_duplicate =
        owner_test_call(&mut memory, &mut state, fd, libc::F_DUPFD_CLOEXEC, 30) as i32;
    assert_eq!(fcntl_duplicate, 30);
    let retained = state.pipe_owners[&fd].clone();
    let snapshot = FileTableState::try_from_elf(&state).unwrap();
    snapshot.install(&mut state).unwrap();
    drop(snapshot);
    for alias in [fd, duplicate, fcntl_duplicate] {
        assert!(Arc::ptr_eq(&retained, &state.pipe_owners[&alias]));
        assert_eq!(
            owner_test_call(&mut memory, &mut state, alias, libc::F_GETOWN, 0),
            i64::from(pid)
        );
    }
    assert!(!Arc::ptr_eq(&retained, &state.pipe_owners[&other]));
    assert_eq!(
        owner_test_call(&mut memory, &mut state, other, libc::F_GETOWN, 0),
        0
    );
    assert_eq!(close(&mut state, fd as u64), 0);
    let [replacement, _] = owner_test_pipe(&mut state);
    assert_eq!(replacement, fd);
    assert!(!Arc::ptr_eq(&retained, &state.pipe_owners[&replacement]));
    assert_eq!(
        owner_test_call(&mut memory, &mut state, replacement, libc::F_GETOWN, 0),
        0
    );
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_dup2,
            [replacement as u64, duplicate as u64, 0, 0, 0, 0]
        ),
        i64::from(duplicate)
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, duplicate, libc::F_GETOWN, 0),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fcntl_duplicate, libc::F_GETOWN, 0),
        i64::from(pid)
    );
}

#[test]
fn fcntl_owner_fork_keeps_permanent_guards_after_creator_is_dropped() {
    let root = TestDir::new();
    let mut parent = test_state(&root.0);
    let [fd, _] = owner_test_pipe(&mut parent);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let pid = parent.pid;
    assert_eq!(
        owner_test_call(&mut memory, &mut parent, fd, libc::F_SETOWN, pid as u64),
        0
    );
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut parent,
            fd,
            LINUX_F_SETSIG,
            libc::SIGUSR1 as u64
        ),
        0
    );
    let mut child = parent.try_clone_for_fork(pid + 1).unwrap();
    assert!(Arc::ptr_eq(
        &parent.pipe_owners[&fd],
        &child.pipe_owners[&fd]
    ));
    assert!(!Arc::ptr_eq(
        &parent.pipe_owner_process,
        &child.pipe_owner_process
    ));
    // Clearing the owner is a state update, not authorization to forget guards.
    assert_eq!(
        owner_test_call(&mut memory, &mut parent, fd, libc::F_SETOWN, 0),
        0
    );
    drop(parent);
    memory
        .write(0x200, &struct_bytes(&[1_i32, child.pid]))
        .unwrap();
    for (command, argument) in [
        (libc::F_SETOWN, child.pid as u64),
        (libc::F_GETOWN, 0),
        (LINUX_F_SETOWN_EX, 0x200),
        (LINUX_F_GETOWN_EX, 0x200),
        (LINUX_F_SETSIG, libc::SIGUSR2 as u64),
        (LINUX_F_GETSIG, 0),
    ] {
        assert_eq!(
            owner_test_call(&mut memory, &mut child, fd, command, argument),
            negative_errno(libc::ENOSYS)
        );
    }
    let flags = fd_status_flags(host_fd(&child, fd).unwrap()).unwrap();
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut child,
            fd,
            libc::F_SETFL,
            (flags | libc::O_ASYNC) as u64
        ),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        fd_status_flags(host_fd(&child, fd).unwrap()).unwrap(),
        flags
    );
    assert_eq!(
        translate_outgoing_rights(&mut rights_control(&[fd]), &child, &mut Vec::new()),
        Err(negative_errno(libc::ENOSYS))
    );
    let [independent, _] = owner_test_pipe(&mut child);
    let pid = child.pid;
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut child,
            independent,
            libc::F_SETOWN,
            pid as u64
        ),
        0
    );
}

#[test]
fn fcntl_owner_threads_and_exec_preserve_creator_and_cloexec_filtering() {
    let mut f = FdinfoFixture::new(false);
    let [fd, _] = owner_test_pipe(&mut f.executor.state);
    f.executor
        .file_table
        .lock()
        .unwrap()
        .update_from_elf(&f.executor.state)
        .unwrap();
    let pid = f.executor.state.pid;
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [fd as u64, libc::F_SETOWN as u64, pid as u64, 0, 0, 0]
        ),
        0
    );
    let duplicate = f.call(
        libc::SYS_fcntl,
        [fd as u64, libc::F_DUPFD_CLOEXEC as u64, 40, 0, 0, 0],
    );
    assert_eq!(duplicate, 40);
    let mut thread = f.executor.thread_child(pid + 10).unwrap();
    assert!(Arc::ptr_eq(
        &f.executor.state.pipe_owner_process,
        &thread.state.pipe_owner_process
    ));
    assert_eq!(
        thread.execute(
            &SyscallRequest::new(
                libc::SYS_fcntl as u64,
                [
                    fd as u64,
                    LINUX_F_SETSIG as u64,
                    libc::SIGUSR2 as u64,
                    0,
                    0,
                    0
                ]
            ),
            &f.memory
        ),
        0
    );
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [fd as u64, LINUX_F_GETSIG as u64, 0, 0, 0, 0]
        ),
        i64::from(libc::SIGUSR2)
    );
    drop(thread);
    let creator = f.executor.state.pipe_owner_process.clone();
    let description = f.executor.state.pipe_owners[&fd].clone();
    f.executor.replace_after_exec(test_state(&f.root.0));
    assert!(Arc::ptr_eq(&creator, &f.executor.state.pipe_owner_process));
    assert!(Arc::ptr_eq(
        &description,
        &f.executor.state.pipe_owners[&fd]
    ));
    assert!(!f.executor.state.pipe_owners.contains_key(&40));
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETOWN as u64, 0, 0, 0, 0]
        ),
        i64::from(pid)
    );
    assert_eq!(
        f.call(
            libc::SYS_fcntl,
            [
                fd as u64,
                libc::F_SETFL as u64,
                libc::O_ASYNC as u64,
                0,
                0,
                0
            ]
        ),
        negative_errno(libc::ENOSYS)
    );
}

#[test]
fn fcntl_owner_failed_export_poison_is_shared_but_managed_export_delivers_nothing() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let [fresh, _] = owner_test_pipe(&mut state);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let alias = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_dup,
        [fresh as u64, 0, 0, 0, 0, 0],
    ) as i32;
    assert_eq!(
        translate_outgoing_rights(&mut rights_control(&[fresh, -1]), &state, &mut Vec::new()),
        Err(negative_errno(libc::EBADF))
    );
    for fd in [fresh, alias] {
        assert_eq!(
            owner_test_call(&mut memory, &mut state, fd, libc::F_SETOWN, 0),
            negative_errno(libc::ENOSYS)
        );
    }
    let [managed, _] = owner_test_pipe(&mut state);
    assert_eq!(
        owner_test_call(&mut memory, &mut state, managed, libc::F_SETOWN, 0),
        0
    );
    let (socket, peer) = UnixStream::pair().unwrap();
    let file = unsafe { std::fs::File::from_raw_fd(std::os::fd::IntoRawFd::into_raw_fd(socket)) };
    let socket = insert_file_with_flags(&mut state, file, false, None);
    let control = rights_control(&[managed]);
    memory.write(0x300, &control).unwrap();
    memory.write(0x400, b"X").unwrap();
    let iov = libc::iovec {
        iov_base: 0x400_usize as *mut libc::c_void,
        iov_len: 1,
    };
    assert_eq!(write_struct(&mut memory, 0x200, &iov), 0);
    // SAFETY: all-zero is a valid empty Linux msghdr. Guest pointers below are
    // translated by sendmsg; Rust never dereferences them as host addresses.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = 0x200_usize as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = 0x300_usize as *mut libc::c_void;
    message.msg_controllen = control.len();
    assert_eq!(write_struct(&mut memory, 0x100, &message), 0);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_sendmsg,
            [socket as u64, 0x100, libc::MSG_NOSIGNAL as u64, 0, 0, 0]
        ),
        negative_errno(libc::ENOSYS)
    );
    let mut byte = 0_u8;
    // SAFETY: private peer is open; MSG_DONTWAIT prevents a host-blocking read.
    assert_eq!(
        unsafe {
            libc::recv(
                peer.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN)
    );

    // A complete translation followed by a real host EPIPE also permanently
    // removes the positive configuration witness from every sending alias.
    let [unsent, _] = owner_test_pipe(&mut state);
    let unsent_alias = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_dup,
        [unsent as u64, 0, 0, 0, 0, 0],
    ) as i32;
    memory.write(0x300, &rights_control(&[unsent])).unwrap();
    drop(peer);
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_sendmsg,
            [socket as u64, 0x100, libc::MSG_NOSIGNAL as u64, 0, 0, 0]
        ),
        negative_errno(libc::EPIPE)
    );
    for fd in [unsent, unsent_alias] {
        assert_eq!(
            owner_test_call(&mut memory, &mut state, fd, libc::F_GETOWN, 0),
            negative_errno(libc::ENOSYS)
        );
    }
}

#[test]
fn fcntl_owner_unknown_reopened_async_and_unshare_histories_refuse() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let [fd, _] = owner_test_pipe(&mut state);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let native = owner_native_pipe();
    let [import, _peer] = native;
    let imported = insert_file_with_flags(&mut state, import, false, None) as i32;
    let reopened = open_guest_fd_path(
        &mut state,
        fd,
        libc::O_RDONLY as u64 | libc::O_NONBLOCK as u64,
        false,
    ) as i32;
    assert!(reopened >= 0);
    for unknown in [imported, reopened, 1, 2] {
        assert_eq!(
            owner_test_call(&mut memory, &mut state, unknown, libc::F_GETOWN, 0),
            negative_errno(libc::ENOSYS)
        );
    }
    let flags = fd_status_flags(host_fd(&state, fd).unwrap()).unwrap();
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut state,
            fd,
            libc::F_SETFL,
            (flags | libc::O_ASYNC) as u64
        ),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_SETOWN, 0),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_SETFL, flags as u64),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_SETOWN, 0),
        0
    );
    assert_eq!(
        close_range(&mut state, &[100, 100, (1 << 1) | (1 << 2), 0, 0, 0]),
        0
    );
    assert_eq!(
        owner_test_call(&mut memory, &mut state, fd, libc::F_GETOWN, 0),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        owner_test_call(
            &mut memory,
            &mut state,
            fd,
            libc::F_SETFL,
            (flags | libc::O_ASYNC) as u64
        ),
        negative_errno(libc::ENOSYS)
    );
}
