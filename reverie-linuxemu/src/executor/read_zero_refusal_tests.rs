/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests so the native oracle and memory canaries remain
// identical to the admitted zero-read tests. Refusal is a backend error, not
// claimed equivalence to the native result of the unsupported operation.
mod read_zero_refusal_tests {
    use super::*;

    fn inotify_cases(nonblocking: bool) {
        // Keep the first mutant diagnostic bound to socket=false. Sockets are
        // admitted below: Linux sock_read_iter returns before sock_recvmsg when
        // count is zero, independently of the mutable O_NONBLOCK flag.
        let socket = false;
        for inherited in [false, true] {
            for with_context in [false, true] {
                let raw = unsafe {
                    libc::inotify_init1(
                        libc::IN_CLOEXEC
                            | if nonblocking { libc::IN_NONBLOCK } else { 0 },
                    )
                };
                assert!(raw >= 0);
                let file = unsafe { std::fs::File::from_raw_fd(raw) };
                let flags = file_status_flags(&file).unwrap();
                assert_eq!(flags & libc::O_NONBLOCK != 0, nonblocking);
                let mut state = test_state(&std::env::current_dir().unwrap());
                let fd = if inherited {
                    state.stdin = Some(file);
                    0
                } else {
                    state.files.insert(3, file);
                    3
                };
                let entries = state.fd_entry_ids.clone();
                let mut memory = read_zero_memory();
                let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
                for high in [0, READ_ZERO_HIGH_FD] {
                    for address in [
                        0,
                        READ_ZERO_BUFFER,
                        READ_ZERO_PROTECTED,
                        2 * PAGE_SIZE,
                        X86_64_GUEST_USER_LIMIT,
                    ] {
                        let request = SyscallRequest::new(
                            libc::SYS_read as u64,
                            [high | fd as u64, address, 0, 0, 0, 0],
                        );
                        let mut context = read_zero_terminal_context(&memory, registry.clone());
                        let action = execute_basic_syscall_with_read_context(
                            &mut memory,
                            &mut state,
                            &request,
                            None,
                            None,
                            with_context.then_some((&mut context, read_zero_task())),
                        );
                        assert!(
                            matches!(
                                action,
                                SyscallAction::Failure(
                                    crate::Error::PotentiallyBlockingZeroRead { fd: actual }
                                ) if actual == fd
                            ),
                            "expected named refusal: socket={socket} inherited={inherited} context={with_context} nonblocking={nonblocking} address={address:#x}"
                        );
                        registry.assert_no_test_read_started();
                        registry.teardown_result().unwrap();
                        let retained = if inherited {
                            state.stdin.as_ref().unwrap()
                        } else {
                            state.files.get(&3).unwrap()
                        };
                        assert_eq!(retained.as_raw_fd(), raw);
                        assert_eq!(file_status_flags(retained).unwrap(), flags);
                        assert!(same_entries(&state.fd_entry_ids, &entries));
                        assert_read_zero_canaries(&memory);
                    }
                }
            }
        }
    }

    #[test]
    fn read_zero_blocking_external_endpoints_are_refused_before_reader_creation() {
        inotify_cases(false);
    }

    #[test]
    fn read_zero_nonblocking_flag_does_not_admit_external_endpoint() {
        // Inotify's flag is mutable through outside aliases. A guard-removal
        // mutant can use this exact test without starting a blocking read.
        inotify_cases(true);
    }

    #[test]
    fn read_zero_stream_and_datagram_sockets_preserve_results_payload_and_endpoint() {
        const PAYLOAD: &[u8; 8] = b"SOCKET!!";
        for datagram in [false, true] {
            for nonblocking in [false, true] {
                for inherited in [false, true] {
                    for with_context in [false, true] {
                        let (file, mut peer) = if datagram {
                            let (socket, peer) =
                                std::os::unix::net::UnixDatagram::pair().unwrap();
                            socket.set_nonblocking(nonblocking).unwrap();
                            let socket: std::os::fd::OwnedFd = socket.into();
                            let peer: std::os::fd::OwnedFd = peer.into();
                            (std::fs::File::from(socket), std::fs::File::from(peer))
                        } else {
                            let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
                            socket.set_nonblocking(nonblocking).unwrap();
                            let socket: std::os::fd::OwnedFd = socket.into();
                            let peer: std::os::fd::OwnedFd = peer.into();
                            (std::fs::File::from(socket), std::fs::File::from(peer))
                        };
                        let raw = file.as_raw_fd();
                        let flags = file_status_flags(&file).unwrap();
                        let descriptor_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
                        assert!(descriptor_flags >= 0);
                        assert_eq!(flags & libc::O_NONBLOCK != 0, nonblocking);
                        assert_eq!(file_mode(&file).unwrap() & libc::S_IFMT, libc::S_IFSOCK);
                        let mut state = test_state(&std::env::current_dir().unwrap());
                        let fd = if inherited {
                            state.stdin = Some(file);
                            state.stdin_entry_id = Arc::new(());
                            0
                        } else {
                            state.files.insert(3, file);
                            state.fd_entry_ids
                                .insert(3, Arc::new(crate::elf::FdEntry::default()));
                            3
                        };
                        let entries = state.fd_entry_ids.clone();
                        let stdin_entry = state.stdin_entry_id.clone();
                        let mut memory = read_zero_memory();
                        let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
                        for queued in [false, true] {
                            if queued {
                                peer.write_all(PAYLOAD).unwrap();
                            }
                            for high in [0, READ_ZERO_HIGH_FD] {
                                for address in [
                                    0,
                                    READ_ZERO_BUFFER,
                                    READ_ZERO_PROTECTED,
                                    2 * PAGE_SIZE,
                                    X86_64_GUEST_USER_LIMIT,
                                    X86_64_GUEST_USER_LIMIT + 1,
                                    u64::MAX,
                                ] {
                                    let expected = if address <= X86_64_GUEST_USER_LIMIT {
                                        0
                                    } else {
                                        negative_errno(libc::EFAULT)
                                    };
                                    // The exact guest ceiling remains accepted. A
                                    // host with a wider user range is not an oracle
                                    // for either side of this guest-only boundary.
                                    if address != X86_64_GUEST_USER_LIMIT
                                        && address != X86_64_GUEST_USER_LIMIT + 1
                                    {
                                        assert_eq!(
                                            native_read_zero(high | raw as u64, address),
                                            expected,
                                            "native socket: datagram={datagram} nonblocking={nonblocking} queued={queued} address={address:#x}"
                                        );
                                    }
                                    let request = SyscallRequest::new(
                                        libc::SYS_read as u64,
                                        [high | fd as u64, address, 0, 0, 0, 0],
                                    );
                                    let mut context =
                                        read_zero_terminal_context(&memory, registry.clone());
                                    let action = execute_basic_syscall_with_read_context(
                                        &mut memory,
                                        &mut state,
                                        &request,
                                        None,
                                        None,
                                        with_context.then_some((&mut context, read_zero_task())),
                                    );
                                    match action {
                                        SyscallAction::Continue {
                                            result,
                                            segment: None,
                                        } => assert_eq!(
                                            result,
                                            expected,
                                            "guest socket: datagram={datagram} inherited={inherited} context={with_context} nonblocking={nonblocking} queued={queued} fd={:#x} address={address:#x}",
                                            high | fd as u64,
                                        ),
                                        SyscallAction::Continue { .. } => {
                                            panic!("zero socket read changed segment")
                                        }
                                        SyscallAction::Exit(status) => {
                                            panic!("zero socket read exited: {status:?}")
                                        }
                                        SyscallAction::Failure(error) => {
                                            panic!("zero socket read failed: {error}")
                                        }
                                    }
                                    let retained = if inherited {
                                        state.stdin.as_ref().unwrap()
                                    } else {
                                        state.files.get(&3).unwrap()
                                    };
                                    assert_eq!(retained.as_raw_fd(), raw);
                                    assert_eq!(file_status_flags(retained).unwrap(), flags);
                                    assert_eq!(
                                        unsafe { libc::fcntl(raw, libc::F_GETFD) },
                                        descriptor_flags
                                    );
                                    assert_eq!(state.fd_entry_ids.len(), entries.len());
                                    for (entry_fd, original) in &entries {
                                        assert!(Arc::ptr_eq(&state.fd_entry_ids[entry_fd], original));
                                    }
                                    assert!(Arc::ptr_eq(&state.stdin_entry_id, &stdin_entry));
                                    assert_read_zero_canaries(&memory);
                                    registry.teardown_result().unwrap();
                                    // Context reads use the owned helper. This
                                    // existing API asserts its registration is
                                    // gone after physical retirement; the exact
                                    // File and entry identity are restored above.
                                    registry.rearm_after_exec();
                                    let mut observed = [0_u8; PAYLOAD.len()];
                                    // Per-call nonblocking peeks bound this check
                                    // without changing the endpoint's status flags.
                                    let count = unsafe {
                                        libc::recv(
                                            raw,
                                            observed.as_mut_ptr().cast(),
                                            observed.len(),
                                            libc::MSG_PEEK | libc::MSG_DONTWAIT,
                                        )
                                    };
                                    if queued {
                                        assert_eq!(count, PAYLOAD.len() as isize);
                                        assert_eq!(&observed, PAYLOAD, "zero read consumed payload");
                                    } else {
                                        assert_eq!(count, -1);
                                        assert_eq!(
                                            std::io::Error::last_os_error().raw_os_error(),
                                            Some(libc::EAGAIN)
                                        );
                                    }
                                }
                            }
                        }
                        let mut observed = [0_u8; PAYLOAD.len()];
                        assert_eq!(
                            unsafe {
                                libc::recv(
                                    raw,
                                    observed.as_mut_ptr().cast(),
                                    observed.len(),
                                    libc::MSG_DONTWAIT,
                                )
                            },
                            PAYLOAD.len() as isize
                        );
                        assert_eq!(&observed, PAYLOAD);
                        assert_eq!(
                            unsafe {
                                libc::recv(
                                    raw,
                                    observed.as_mut_ptr().cast(),
                                    observed.len(),
                                    libc::MSG_DONTWAIT,
                                )
                            },
                            -1
                        );
                        assert_eq!(
                            std::io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        assert_eq!(fd_status_flags(raw).unwrap(), flags);
                    }
                }
            }
        }
    }

    #[test]
    fn read_zero_external_invalid_address_retains_native_efault() {
        for inherited in [false, true] {
            let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
            assert!(raw >= 0);
            let file = unsafe { std::fs::File::from_raw_fd(raw) };
            let mut state = test_state(&std::env::current_dir().unwrap());
            let fd = if inherited {
                state.stdin = Some(file);
                0
            } else {
                state.files.insert(3, file);
                3
            };
            let mut memory = read_zero_memory();
            for address in [X86_64_GUEST_USER_LIMIT + 1, u64::MAX] {
                // The host's architecture may allow addresses above the guest
                // ceiling. UINTPTR_MAX is rejected on both; the guest boundary
                // expectation remains the existing four-level address policy.
                assert_eq!(native_read_zero(raw as u64, u64::MAX), negative_errno(libc::EFAULT));
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_read,
                        [fd, address, 0, 0, 0, 0],
                    ),
                    negative_errno(libc::EFAULT)
                );
                assert_read_zero_canaries(&memory);
            }
        }
    }

    #[test]
    fn read_zero_intrinsic_nonwaiting_endpoints_keep_native_results_with_blocking_flags() {
        for kind in ["pipe", "eventfd", "timerfd", "signalfd", "epoll", "null", "zero"] {
            let (file, _writer) = match kind {
                "pipe" => {
                    let mut fds = [-1; 2];
                    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
                    unsafe {
                        (std::fs::File::from_raw_fd(fds[0]), Some(std::fs::File::from_raw_fd(fds[1])))
                    }
                }
                "null" | "zero" => (std::fs::File::open(format!("/dev/{kind}")).unwrap(), None),
                _ => {
                    let raw = match kind {
                        "eventfd" => unsafe { libc::eventfd(9, libc::EFD_CLOEXEC) },
                        "epoll" => unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) },
                        "timerfd" => unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) },
                        "signalfd" => {
                            let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
                            assert_eq!(unsafe { libc::sigemptyset(mask.as_mut_ptr()) }, 0);
                            unsafe { libc::signalfd(-1, mask.as_ptr(), libc::SFD_CLOEXEC) }
                        }
                        _ => unreachable!(),
                    };
                    assert!(raw >= 0, "create {kind}");
                    (unsafe { std::fs::File::from_raw_fd(raw) }, None)
                }
            };
            let raw = file.as_raw_fd();
            assert_eq!(file_status_flags(&file).unwrap() & libc::O_NONBLOCK, 0);
            let mut state = test_state(&std::env::current_dir().unwrap());
            state.files.insert(3, file);
            let mut memory = read_zero_memory();
            for address in [0, READ_ZERO_PROTECTED, u64::MAX] {
                let native = native_read_zero(raw as u64, address);
                let expected = if kind == "epoll" {
                    // Epoll has no read operation: EINVAL precedes access_ok.
                    negative_errno(libc::EINVAL)
                } else if address == u64::MAX {
                    negative_errno(libc::EFAULT)
                } else if matches!(kind, "eventfd" | "timerfd" | "signalfd") {
                    negative_errno(libc::EINVAL)
                } else {
                    0
                };
                assert_eq!(native, expected, "native {kind} address={address:#x}");
                assert_eq!(
                    syscall_result(&mut memory, &mut state, libc::SYS_read, [3, address, 0, 0, 0, 0]),
                    native,
                    "guest {kind} address={address:#x}"
                );
                assert_read_zero_canaries(&memory);
            }
            assert_eq!(fd_status_flags(raw).unwrap() & libc::O_NONBLOCK, 0);
            if kind == "eventfd" {
                let mut value = 0_u64;
                assert_eq!(unsafe { libc::read(raw, (&mut value as *mut u64).cast(), 8) }, 8);
                assert_eq!(value, 9, "zero-count calls consumed the counter");
            }
        }
    }

    #[test]
    fn read_zero_unknown_regular_filesystem_is_not_admitted_by_mode_or_bad_address() {
        // Procfs presents regular modes too. It is deliberately outside the
        // finite local-file admission set; a generic S_IFREG classification or
        // an EFAULT prediction cannot grant an unknown file-operation contract.
        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert_eq!(file_mode(&file).unwrap() & libc::S_IFMT, libc::S_IFREG);
        let mut state = test_state(&std::env::current_dir().unwrap());
        state.files.insert(3, file);
        let mut memory = read_zero_memory();
        let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
        for address in [0, READ_ZERO_BUFFER, u64::MAX] {
            let request = SyscallRequest::new(libc::SYS_read as u64, [3, address, 0, 0, 0, 0]);
            let mut context = read_zero_terminal_context(&memory, registry.clone());
            assert!(matches!(
                execute_basic_syscall_with_read_context(
                    &mut memory,
                    &mut state,
                    &request,
                    None,
                    None,
                    Some((&mut context, read_zero_task())),
                ),
                SyscallAction::Failure(crate::Error::PotentiallyBlockingZeroRead { fd: 3 })
            ));
            registry.assert_no_test_read_started();
            assert_read_zero_canaries(&memory);
        }
    }

    #[test]
    fn read_zero_local_filesystem_set_admits_overlayfs_and_no_pseudo_filesystem() {
        // The mount-free half of the overlayfs admission: the same finite set
        // admit_host_read_zero consults, by superblock magic.
        for f_type in [
            libc::TMPFS_MAGIC,
            libc::EXT4_SUPER_MAGIC,
            libc::BTRFS_SUPER_MAGIC,
            libc::OVERLAYFS_SUPER_MAGIC,
        ] {
            assert!(
                zero_read_local_filesystem(f_type),
                "local filesystem {f_type:#x}"
            );
        }
        for f_type in [
            libc::PROC_SUPER_MAGIC,
            libc::SYSFS_MAGIC,
            libc::DEBUGFS_MAGIC,
            libc::CGROUP2_SUPER_MAGIC,
            libc::FUSE_SUPER_MAGIC,
            libc::NFS_SUPER_MAGIC,
            ANON_INODE_FS_MAGIC,
        ] {
            assert!(
                !zero_read_local_filesystem(f_type),
                "filesystem {f_type:#x} must stay outside the local-file admission"
            );
        }
    }

    /// Each overlayfs descriptor the mount test opens: a name, a path below
    /// the private tmpfs, and its open flags. Lower-only `lfile` is opened only
    /// for reading, so it stays lower-only; a write-only open copies `wfile` up.
    const OVERLAY_CASES: [(&str, &str, libc::c_int); 11] = [
        ("lower-only file", "merged/lfile", libc::O_RDONLY),
        (
            "lower-only file nonblocking",
            "merged/lfile",
            libc::O_RDONLY | libc::O_NONBLOCK,
        ),
        (
            "lower-only file noatime",
            "merged/lfile",
            libc::O_RDONLY | libc::O_NOATIME,
        ),
        ("lower-only file path", "merged/lfile", libc::O_PATH),
        ("copied-up file write-only", "merged/wfile", libc::O_WRONLY),
        (
            "copied-up file write-only append",
            "merged/wfile",
            libc::O_WRONLY | libc::O_APPEND,
        ),
        ("upper file read-write", "merged/ufile", libc::O_RDWR),
        (
            "upper file read-write append",
            "merged/ufile",
            libc::O_RDWR | libc::O_APPEND,
        ),
        ("empty upper file", "merged/empty", libc::O_RDONLY),
        (
            "lower-only directory",
            "merged/ldir",
            libc::O_RDONLY | libc::O_DIRECTORY,
        ),
        (
            "upper directory nonblocking",
            "merged/udir",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
        ),
    ];

    /// Setup steps whose refusal means this host cannot mount overlayfs
    /// rootlessly; any other failure is a test failure.
    const OVERLAY_CAPABILITY_STEPS: [&str; 6] = [
        "unshare(CLONE_NEWUSER | CLONE_NEWNS)",
        "write /proc/self/setgroups",
        "write /proc/self/uid_map",
        "write /proc/self/gid_map",
        "mount tmpfs",
        "mount overlay",
    ];
    const OVERLAY_SETUP_STEPS: [&str; 4] = [
        "mkdir layer",
        "create layer file",
        "open overlay file",
        "sendmsg",
    ];

    struct OverlayFixture {
        files: Vec<(&'static str, libc::c_int, std::fs::File)>,
        /// O_PATH upper-layer directory, to observe copy-up.
        upper: std::fs::File,
        _mount_point: TestDir,
    }

    /// Opens OVERLAY_CASES in a forked child that has its own user and mount
    /// namespaces, on overlayfs whose layers are a private tmpfs, and returns
    /// them over SCM_RIGHTS. An open file keeps its detached mount alive after
    /// the child exits. Err names the refused step when the host cannot mount
    /// overlayfs without privilege.
    fn overlay_fixture() -> Result<OverlayFixture, String> {
        use std::ffi::CString;
        use std::os::fd::OwnedFd;
        use std::os::unix::ffi::OsStrExt;

        let mount_point = TestDir::new();
        let root = mount_point.0.as_os_str().as_bytes().to_vec();
        let path = |suffix: &str| {
            let mut bytes = root.clone();
            bytes.push(b'/');
            bytes.extend_from_slice(suffix.as_bytes());
            CString::new(bytes).unwrap()
        };
        let root_path = CString::new(root.clone()).unwrap();
        let directories = [
            "lower",
            "lower/ldir",
            "upper",
            "upper/udir",
            "work",
            "merged",
        ]
        .map(path);
        let layer_files = [
            ("lower/lfile", b"ABCDEFGH".as_slice()),
            ("lower/wfile", b"ABCDEFGH".as_slice()),
            ("upper/ufile", b"ABCDEFGH".as_slice()),
            ("upper/empty", b"".as_slice()),
        ]
        .map(|(name, contents)| (path(name), contents));
        let merged = path("merged");
        let display = mount_point.0.display();
        let options = CString::new(format!(
            "lowerdir={display}/lower,upperdir={display}/upper,workdir={display}/work"
        ))
        .unwrap();
        let opens: Vec<(CString, libc::c_int)> = OVERLAY_CASES
            .iter()
            .map(|(_, suffix, flags)| (path(suffix), *flags))
            .chain(std::iter::once((
                path("upper"),
                libc::O_PATH | libc::O_DIRECTORY,
            )))
            .collect();
        // SAFETY: geteuid and getegid have no preconditions.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let uid_map = format!("0 {uid} 1").into_bytes();
        let gid_map = format!("0 {gid} 1").into_bytes();
        let mut opened = vec![-1_i32; opens.len()];
        let rights = std::mem::size_of_val(opened.as_slice()) as u32;
        // SAFETY: CMSG_SPACE is a pure size computation.
        let space = unsafe { libc::CMSG_SPACE(rights) } as usize;
        let mut control = vec![0_u64; space.div_ceil(8)];
        let mut sockets = [-1; 2];
        // SAFETY: sockets has room for both new descriptors.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: each new descriptor is owned exactly once.
        let (parent_socket, child_socket) = unsafe {
            (
                OwnedFd::from_raw_fd(sockets[0]),
                OwnedFd::from_raw_fd(sockets[1]),
            )
        };

        // SAFETY: the child makes only system calls on buffers built above,
        // then leaves through _exit; it never allocates, unwinds or returns.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", std::io::Error::last_os_error());
        if child == 0 {
            unsafe {
                let socket = child_socket.as_raw_fd();
                let send = |words: [i32; 2], fds: &[i32], control: &mut [u64]| {
                    let mut iov = libc::iovec {
                        iov_base: words.as_ptr() as *mut libc::c_void,
                        iov_len: std::mem::size_of_val(&words),
                    };
                    let mut message: libc::msghdr = std::mem::zeroed();
                    message.msg_iov = &mut iov;
                    message.msg_iovlen = 1;
                    if !fds.is_empty() {
                        message.msg_control = control.as_mut_ptr().cast();
                        message.msg_controllen = libc::CMSG_SPACE(rights) as usize;
                        let header = libc::CMSG_FIRSTHDR(&message);
                        (*header).cmsg_level = libc::SOL_SOCKET;
                        (*header).cmsg_type = libc::SCM_RIGHTS;
                        (*header).cmsg_len = libc::CMSG_LEN(rights) as usize;
                        std::ptr::copy_nonoverlapping(
                            fds.as_ptr(),
                            libc::CMSG_DATA(header).cast::<i32>(),
                            fds.len(),
                        );
                    }
                    libc::sendmsg(socket, &message, 0) == std::mem::size_of_val(&words) as isize
                };
                let fail = |step: i32, control: &mut [u64]| -> ! {
                    let errno = *libc::__errno_location();
                    send([step + 1, errno], &[], control);
                    libc::_exit(0)
                };
                let write_all = |name: &std::ffi::CStr, bytes: &[u8]| {
                    let fd = libc::open(name.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                    fd >= 0
                        && libc::write(fd, bytes.as_ptr().cast(), bytes.len())
                            == bytes.len() as isize
                        && libc::close(fd) == 0
                };
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                    fail(0, &mut control);
                }
                if !write_all(c"/proc/self/setgroups", b"deny") {
                    fail(1, &mut control);
                }
                if !write_all(c"/proc/self/uid_map", &uid_map) {
                    fail(2, &mut control);
                }
                if !write_all(c"/proc/self/gid_map", &gid_map) {
                    fail(3, &mut control);
                }
                if libc::mount(
                    c"tmpfs".as_ptr(),
                    root_path.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV,
                    c"size=1m".as_ptr().cast(),
                ) != 0
                {
                    fail(4, &mut control);
                }
                for directory in &directories {
                    if libc::mkdir(directory.as_ptr(), 0o755) != 0 {
                        fail(6, &mut control);
                    }
                }
                for (name, contents) in &layer_files {
                    let fd = libc::open(
                        name.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                        0o644,
                    );
                    if fd < 0
                        || libc::write(fd, contents.as_ptr().cast(), contents.len())
                            != contents.len() as isize
                        || libc::close(fd) != 0
                    {
                        fail(7, &mut control);
                    }
                }
                if libc::mount(
                    c"overlay".as_ptr(),
                    merged.as_ptr(),
                    c"overlay".as_ptr(),
                    0,
                    options.as_ptr().cast(),
                ) != 0
                {
                    fail(5, &mut control);
                }
                for (slot, (name, flags)) in opened.iter_mut().zip(&opens) {
                    *slot = libc::open(name.as_ptr(), *flags | libc::O_CLOEXEC);
                    if *slot < 0 {
                        fail(8, &mut control);
                    }
                }
                if !send([0, 0], &opened, &mut control) {
                    fail(9, &mut control);
                }
                libc::_exit(0);
            }
        }
        drop(child_socket);
        let mut words = [0_i32; 2];
        let mut iov = libc::iovec {
            iov_base: words.as_mut_ptr().cast(),
            iov_len: std::mem::size_of_val(&words),
        };
        // SAFETY: zeroed is a valid empty msghdr; every pointer set below
        // refers to a live local buffer of the stated length.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        // SAFETY: message describes writable local buffers.
        let received = unsafe {
            libc::recvmsg(
                parent_socket.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC,
            )
        };
        let received_error = std::io::Error::last_os_error();
        let mut status = 0;
        // SAFETY: child is this test's own unreaped child.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "overlay fixture child status {status:#x}"
        );
        assert_eq!(
            received,
            std::mem::size_of_val(&words) as isize,
            "overlay fixture reply: {received_error}"
        );
        if words[0] != 0 {
            let step = (words[0] - 1) as usize;
            let error = std::io::Error::from_raw_os_error(words[1]);
            if let Some(name) = OVERLAY_CAPABILITY_STEPS.get(step) {
                return Err(format!("{name} failed: {error}"));
            }
            panic!(
                "overlay fixture {} failed: {error}",
                OVERLAY_SETUP_STEPS[step - OVERLAY_CAPABILITY_STEPS.len()]
            );
        }
        assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
        // SAFETY: recvmsg filled message's control buffer.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null());
            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!((*header).cmsg_len, libc::CMSG_LEN(rights) as usize);
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(header).cast::<i32>(),
                opened.as_mut_ptr(),
                opened.len(),
            );
        }
        // SAFETY: SCM_RIGHTS installed each descriptor anew in this process.
        let mut files: Vec<std::fs::File> = opened
            .iter()
            .map(|&fd| unsafe { std::fs::File::from_raw_fd(fd) })
            .collect();
        let upper = files.pop().unwrap();
        Ok(OverlayFixture {
            files: OVERLAY_CASES
                .iter()
                .zip(files)
                .map(|((name, _, flags), file)| (*name, *flags, file))
                .collect(),
            upper,
            _mount_point: mount_point,
        })
    }

    #[test]
    fn read_zero_overlayfs_files_and_directories_are_admitted_with_native_results() {
        // https://github.com/rrnewton/reverie/issues/1354: diffutils' cmp -n
        // ends with read(fd, buf, 0) on a file that may live on overlayfs.
        let fixture = match overlay_fixture() {
            Ok(fixture) => fixture,
            Err(reason) => {
                println!(
                    "SKIP read_zero_overlayfs: this host cannot mount overlayfs without privilege ({reason}); \
                     read_zero_local_filesystem_set_admits_overlayfs_and_no_pseudo_filesystem still checks the admission"
                );
                return;
            }
        };
        for (name, flags, file) in &fixture.files {
            let raw = file.as_raw_fd();
            let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            // SAFETY: the fixture owns raw; statfs storage is writable.
            assert_eq!(unsafe { libc::fstatfs(raw, filesystem.as_mut_ptr()) }, 0);
            let filesystem = unsafe { filesystem.assume_init() };
            assert_eq!(filesystem.f_type, libc::OVERLAYFS_SUPER_MAGIC, "{name}");
            let path = flags & libc::O_PATH != 0;
            let directory = flags & libc::O_DIRECTORY != 0;
            let readable = !path && flags & libc::O_ACCMODE != libc::O_WRONLY;
            let seekable = !path && !directory;
            // A nonzero position must survive every zero-count read.
            let position = if seekable {
                // SAFETY: raw is a live descriptor owned by the fixture.
                let end = unsafe { libc::lseek(raw, 0, libc::SEEK_END) };
                assert!(end >= 0);
                unsafe { libc::lseek(raw, end.min(3), libc::SEEK_SET) }
            } else {
                -1
            };
            for inherited in [false, true] {
                for with_context in [false, true] {
                    // A dup shares the open-file description and its position,
                    // so the host takes the shared-position lock.
                    let alias = file.try_clone().unwrap();
                    let alias_raw = alias.as_raw_fd();
                    let mut state = test_state(&std::env::current_dir().unwrap());
                    let fd = if inherited {
                        state.stdin = Some(alias);
                        state.stdin_entry_id = Arc::new(());
                        0
                    } else {
                        state.files.insert(3, alias);
                        state
                            .fd_entry_ids
                            .insert(3, Arc::new(crate::elf::FdEntry::default()));
                        3
                    };
                    let mut memory = read_zero_memory();
                    let registry = Arc::new(crate::terminal_read::ReadRegistry::default());
                    for high in [0, READ_ZERO_HIGH_FD] {
                        for address in READ_ZERO_ADDRESSES {
                            let expected = if !readable {
                                negative_errno(libc::EBADF)
                            } else if address >= 0x8000_0000_0000_0000 {
                                negative_errno(libc::EFAULT)
                            } else if directory {
                                negative_errno(libc::EISDIR)
                            } else {
                                0
                            };
                            assert_eq!(
                                native_read_zero(high | alias_raw as u64, address),
                                expected,
                                "native {name} address={address:#x}"
                            );
                            let request = SyscallRequest::new(
                                libc::SYS_read as u64,
                                [high | fd as u64, address, 0, 0, 0, 0],
                            );
                            let mut context = read_zero_terminal_context(&memory, registry.clone());
                            let action = execute_basic_syscall_with_read_context(
                                &mut memory,
                                &mut state,
                                &request,
                                None,
                                None,
                                with_context.then_some((&mut context, read_zero_task())),
                            );
                            let label = format!(
                                "{name}: inherited={inherited} context={with_context} fd={:#x} address={address:#x}",
                                high | fd as u64
                            );
                            match action {
                                SyscallAction::Continue {
                                    result,
                                    segment: None,
                                } => assert_eq!(result, expected, "{label}"),
                                SyscallAction::Continue { .. } => {
                                    panic!("{label}: zero read changed segment")
                                }
                                SyscallAction::Exit(status) => {
                                    panic!("{label}: zero read exited: {status:?}")
                                }
                                SyscallAction::Failure(error) => {
                                    panic!("{label}: zero read failed: {error}")
                                }
                            }
                            registry.teardown_result().unwrap();
                            registry.rearm_after_exec();
                            assert_read_zero_canaries(&memory);
                            if seekable {
                                // SAFETY: raw is a live descriptor owned by the fixture.
                                assert_eq!(
                                    unsafe { libc::lseek(raw, 0, libc::SEEK_CUR) },
                                    position,
                                    "{label}: position"
                                );
                            }
                        }
                    }
                    let retained = if inherited {
                        state.stdin.as_ref()
                    } else {
                        state.files.get(&3)
                    };
                    assert_eq!(retained.unwrap().as_raw_fd(), alias_raw, "{name}");
                }
            }
        }
        let in_upper = |entry: &std::ffi::CStr| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
            // SAFETY: upper is an O_PATH directory the fixture owns; entry is
            // NUL-terminated and stat is writable.
            unsafe {
                libc::fstatat(
                    fixture.upper.as_raw_fd(),
                    entry.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                ) == 0
            }
        };
        // ovl_read_iter returns before it opens the real file: nothing above
        // copied the lower-only entries up. The write-only open did.
        assert!(
            !in_upper(c"lfile"),
            "a zero-count read copied up a lower-only file"
        );
        assert!(
            !in_upper(c"ldir"),
            "a zero-count read copied up a lower-only directory"
        );
        assert!(in_upper(c"wfile"), "fixture: a write-only open copies up");
    }
}
