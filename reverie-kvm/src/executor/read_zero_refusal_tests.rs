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
                        libc::IN_CLOEXEC | if nonblocking { libc::IN_NONBLOCK } else { 0 },
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
                        assert_eq!(state.fd_entry_ids, entries);
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
                            let (socket, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
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
                        let entry_id = Arc::new(());
                        let fd = if inherited {
                            state.stdin = Some(file);
                            state.stdin_entry_id = entry_id.clone();
                            0
                        } else {
                            state.files.insert(3, file);
                            state.fd_entry_ids.insert(3, entry_id.clone());
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
                                        assert!(Arc::ptr_eq(
                                            &state.fd_entry_ids[entry_fd],
                                            original
                                        ));
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
                                        assert_eq!(
                                            &observed, PAYLOAD,
                                            "zero read consumed payload"
                                        );
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
                assert_eq!(
                    native_read_zero(raw as u64, u64::MAX),
                    negative_errno(libc::EFAULT)
                );
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
        for kind in [
            "pipe", "eventfd", "timerfd", "signalfd", "epoll", "null", "zero",
        ] {
            let (file, _writer) = match kind {
                "pipe" => {
                    let mut fds = [-1; 2];
                    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
                    unsafe {
                        (
                            std::fs::File::from_raw_fd(fds[0]),
                            Some(std::fs::File::from_raw_fd(fds[1])),
                        )
                    }
                }
                "null" | "zero" => (std::fs::File::open(format!("/dev/{kind}")).unwrap(), None),
                _ => {
                    let raw = match kind {
                        "eventfd" => unsafe { libc::eventfd(9, libc::EFD_CLOEXEC) },
                        "epoll" => unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) },
                        "timerfd" => unsafe {
                            libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC)
                        },
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
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_read,
                        [3, address, 0, 0, 0, 0]
                    ),
                    native,
                    "guest {kind} address={address:#x}"
                );
                assert_read_zero_canaries(&memory);
            }
            assert_eq!(fd_status_flags(raw).unwrap() & libc::O_NONBLOCK, 0);
            if kind == "eventfd" {
                let mut value = 0_u64;
                assert_eq!(
                    unsafe { libc::read(raw, (&mut value as *mut u64).cast(), 8) },
                    8
                );
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
}
