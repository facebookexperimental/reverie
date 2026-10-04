/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included inside vm::tests to reuse its private minimal ELF builder.
// These cases deliberately withdraw the former blocked-read success claim:
// potentially blocking external zero reads are refused before host injection.
// Refusal is a reduced supported contract, not native-equivalent execution.
mod read_zero_guest_tests {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    use reverie::GlobalTool;
    use reverie::Guest;
    use reverie::Tool;
    use reverie::syscalls::Syscall;

    use super::*;

    const RETURNED_READ: u32 = 99;
    const HIGH_FD: u64 = 0x5a5a_5a5a_0000_0000;
    const ADDRESS: u64 = 0x100;
    const READ_RESULT_SENTINEL: [u8; 8] = *b"READSTOP";
    const WAIT: Duration = Duration::from_secs(30);

    #[derive(Default)]
    struct ForwardLog {
        requests: Mutex<Vec<SyscallRequest>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for ForwardLog {
        type Request = (u64, [u64; 6]);
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _: Pid, (number, arguments): Self::Request) {
            self.requests
                .lock()
                .unwrap()
                .push(SyscallRequest::new(number, arguments));
        }
    }

    #[derive(Default)]
    struct ForwardTool;

    #[reverie::tool]
    impl Tool for ForwardTool {
        type GlobalState = ForwardLog;
        type ThreadState = ();

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            let request = SyscallRequest::from_syscall(syscall);
            // Record before injection: the refused read must never return to
            // this callback or the guest. Recording only afterwards misses it.
            guest.send_rpc((request.number(), *request.args())).await;
            if matches!(syscall, Syscall::Exit(_) | Syscall::ExitGroup(_)) {
                guest.tail_inject(syscall).await
            }
            if request.number() == libc::SYS_read as u64 {
                assert!(
                    request
                        == SyscallRequest::new(
                            libc::SYS_read as u64,
                            [HIGH_FD | 3, ADDRESS, 0, 0, 0, 0],
                        )
                        || request
                            == SyscallRequest::new(
                                libc::SYS_read as u64,
                                [HIGH_FD, ADDRESS, 0, 0, 0, 0],
                            ),
                    "unexpected read in the selected guest: {request:?}"
                );
                let returned = guest.inject(syscall).await;
                // This must be synchronous and precede `?` or any other await:
                // fatal admission could suppress a later observation, and
                // both Ok and Err returns violate this read's run-level refusal.
                panic!("selected refused zero-read injection returned: {returned:?}");
            }
            Ok(guest.inject(syscall).await?)
        }
    }

    fn guest(rebound: bool) -> (Vec<u8>, SyscallRequest) {
        let mut code = Vec::new();
        let mut failures = Vec::new();
        // Clear all six argument registers, then dup(0). The guest verifies
        // the actual descriptor result before reaching the selected read.
        code.extend_from_slice(&[
            0x31, 0xff, // xor edi,edi
            0x31, 0xf6, // xor esi,esi
            0x31, 0xd2, // xor edx,edx
            0x45, 0x31, 0xd2, // xor r10d,r10d
            0x45, 0x31, 0xc0, // xor r8d,r8d
            0x45, 0x31, 0xc9, // xor r9d,r9d
            0xb8, 32, 0, 0, 0, // mov eax,SYS_dup
            0x0f, 0x05, // syscall
            0x83, 0xf8, 3, // cmp eax,3
            0x0f, 0x85, 0, 0, 0, 0, // jne failure
        ]);
        failures.push(code.len() - 4);
        if rebound {
            code.extend_from_slice(&[
                0xb8, 33, 0, 0, 0, // mov eax,SYS_dup2
                0xbf, 3, 0, 0, 0, // mov edi,3
                0x31, 0xf6, // xor esi,esi
                0x0f, 0x05, // syscall
                0x85, 0xc0, // test eax,eax
                0x0f, 0x85, 0, 0, 0, 0, // jne failure
            ]);
            failures.push(code.len() - 4);
            code.extend_from_slice(&[
                0xb8, 3, 0, 0, 0, // mov eax,SYS_close
                0xbf, 3, 0, 0, 0, // mov edi,3
                0x0f, 0x05, // syscall
                0x85, 0xc0, // test eax,eax
                0x0f, 0x85, 0, 0, 0, 0, // jne failure
            ]);
            failures.push(code.len() - 4);
        }
        let fd = HIGH_FD | if rebound { 0 } else { 3 };
        code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi,fd
        code.extend_from_slice(&fd.to_le_bytes());
        code.push(0xbe); // mov esi,address
        code.extend_from_slice(&(ADDRESS as u32).to_le_bytes());
        code.extend_from_slice(&[
            0x31, 0xd2, // xor edx,edx: literal zero count
            0x45, 0x31, 0xd2, // xor r10d,r10d
            0x45, 0x31, 0xc0, // xor r8d,r8d
            0x45, 0x31, 0xc9, // xor r9d,r9d
            0x31, 0xc0, // xor eax,eax: SYS_read
            0x0f, 0x05, // syscall
        ]);
        // Every returned read, even a fabricated zero/EINTR, is a failure.
        let failure = code.len();
        code.extend_from_slice(&[0xb8, 231, 0, 0, 0, 0xbf]); // exit_group(99)
        code.extend_from_slice(&RETURNED_READ.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]); // syscall; ud2
        for operand in failures {
            let displacement = i32::try_from(failure - (operand + 4)).unwrap();
            code[operand..operand + 4].copy_from_slice(&displacement.to_le_bytes());
        }
        (
            minimal_test_elf(&code),
            SyscallRequest::new(libc::SYS_read as u64, [fd, ADDRESS, 0, 0, 0, 0]),
        )
    }

    type Outcome = Result<(Result<i32>, Vec<SyscallRequest>)>;

    struct GuestRun {
        group: Arc<GuestThreadGroup>,
        thread: Option<std::thread::JoinHandle<(KvmBackend, Outcome)>>,
    }

    impl Drop for GuestRun {
        fn drop(&mut self) {
            if let Some(thread) = self.thread.take() {
                // A failed observation must not detach the running guest. This
                // requests real cleanup, then keeps its owner through join.
                // If that cleanup itself regresses, the outer bounded test
                // process remains the containment boundary; no timeout here
                // is relabelled as proof of retirement.
                self.group.request_exit_group(ExitStatus::Exited(255));
                let joined = thread.join();
                if !std::thread::panicking() {
                    assert!(joined.is_ok(), "guest cleanup thread panicked");
                }
            }
        }
    }

    fn run_case(tool: bool, rebound: bool) {
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(raw >= 0, "create blocking inherited inotify");
        // SAFETY: inotify_init1 returned this test's owned descriptor.
        let endpoint = unsafe { File::from_raw_fd(raw) };
        let status_flags = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_GETFL) };
        assert!(status_flags >= 0);
        assert_eq!(status_flags & libc::O_NONBLOCK, 0);
        let mut backend = KvmBackend::new_with_stdin(16 * 1024 * 1024, Some(endpoint))
            .expect("real zero-read guest requires /dev/kvm");
        let (image, request) = guest(rebound);
        backend
            .install_static_elf(&image, "/bin/read-zero-alias")
            .unwrap();
        let loaded = backend.static_elf.as_ref().unwrap();
        // The Tool also observes the already-installed image's initial exec.
        // Derive its expected arguments independently from the known fixture
        // stack before the runner starts, including the exact path and both
        // pointer-array terminators.
        let initial_stack = loaded.stack_pointer;
        let read_stack_word = |address| {
            let mut bytes = [0_u8; 8];
            backend.memory.user().read(address, &mut bytes).unwrap();
            u64::from_le_bytes(bytes)
        };
        assert_eq!(read_stack_word(initial_stack), 1, "fixture argc");
        let initial_argv = initial_stack.checked_add(8).unwrap();
        let initial_envp = initial_stack.checked_add(24).unwrap();
        let initial_path = read_stack_word(initial_argv);
        assert_eq!(read_stack_word(initial_argv.checked_add(8).unwrap()), 0);
        assert_eq!(read_stack_word(initial_envp), 0);
        let mut initial_path_bytes = [0_u8; b"/bin/read-zero-alias\0".len()];
        backend
            .memory
            .user()
            .read(initial_path, &mut initial_path_bytes)
            .unwrap();
        assert_eq!(&initial_path_bytes, b"/bin/read-zero-alias\0");
        let initial_exec = SyscallRequest::new(
            libc::SYS_execve as u64,
            [initial_path, initial_argv, initial_envp, 0, 0, 0],
        );
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let group = backend.thread_group.clone();
        let registry = group.terminal_reads.clone();
        let frame_memory = backend.memory.clone();
        let frame_address = backend.syscall_frame_address;
        let result_address =
            frame_address + (crate::syscall::RESULT_WORD * std::mem::size_of::<u64>()) as u64;
        let request_words = frame_memory
            .user()
            .retain_translated_range(
                frame_address,
                crate::syscall::RESULT_WORD * std::mem::size_of::<u64>(),
            )
            .unwrap();
        let result_word = frame_memory
            .user()
            .retain_translated_range(result_address, READ_RESULT_SENTINEL.len())
            .unwrap();
        // Initialize and retain the actual transport operands before the run.
        // Retention owns their mapping without holding a copy token or
        // preventing physical teardown.
        frame_memory
            .write_raw(result_address, &READ_RESULT_SENTINEL)
            .unwrap();
        let mut stored = [0; READ_RESULT_SENTINEL.len()];
        frame_memory.read_raw(result_address, &mut stored).unwrap();
        assert_eq!(stored, READ_RESULT_SENTINEL);
        let read_dispatches = Arc::new(AtomicUsize::new(0));
        let observed_dispatches = read_dispatches.clone();
        // dup[/dup2/close] legitimately publish earlier results into this same
        // word. Re-arm it at the selected read's existing dispatch hook, before
        // endpoint admission, while its sole vCPU is stopped. This is not a
        // blocked-reader witness and neither performs nor cancels a host read.
        backend
            .memory
            .set_test_syscall_dispatch_observer(Arc::new(move |observed| {
                if observed.number() == libc::SYS_read as u64 {
                    assert_eq!(*observed, request, "exact refused read arguments");
                    assert_eq!(
                        observed_dispatches.fetch_add(1, Ordering::SeqCst),
                        0,
                        "selected read must dispatch exactly once"
                    );
                    assert_eq!(
                        SyscallRequest::read_from(&frame_memory, frame_address).unwrap(),
                        request,
                        "the stopped transport frame must belong to the selected read"
                    );
                    frame_memory
                        .write_raw(result_address, &READ_RESULT_SENTINEL)
                        .unwrap();
                }
            }));
        registry.assert_no_test_read_started();
        let (finished, completion) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let result: Outcome = if tool {
                futures::executor::block_on(
                    backend.run_static_elf_with_tool_completion::<ForwardTool>((), true),
                )
                .map(|completion| {
                    let result = completion.result.map(|(status, stdout, stderr)| {
                        assert!(stdout.is_empty() && stderr.is_empty());
                        status
                    });
                    (
                        result,
                        completion.global_state.requests.into_inner().unwrap(),
                    )
                })
            } else {
                Ok((backend.run_static_elf(), Vec::new()))
            };
            let _ = finished.send(());
            (backend, result)
        });
        let mut run = GuestRun {
            group: group.clone(),
            thread: Some(thread),
        };
        completion
            .recv_timeout(WAIT)
            .expect("pre-injection refusal did not return the real guest run");
        let (backend, result) = run.thread.take().unwrap().join().unwrap();
        let (result, forwarded) = result.expect("Tool global state must survive runtime refusal");
        let error =
            result.expect_err("refused read must not return a guest exit status, including 99");
        let expected_fd = if rebound { 0 } else { 3 };
        assert!(
            matches!(error.primary(), Error::PotentiallyBlockingZeroRead { fd } if *fd == expected_fd),
            "expected pre-injection refusal for guest fd {expected_fd}, got {error:?}"
        );
        assert_eq!(read_dispatches.load(Ordering::SeqCst), 1);
        registry.assert_no_test_read_started();
        assert!(!group.has_worker_handles());
        backend.guest_worker_teardown_result().unwrap();
        assert_eq!(
            exits
                .snapshot()
                .count(crate::stats::KvmExitReason::Hypercall),
            if rebound { 4 } else { 2 },
            "guest must execute dup[/dup2/close]/read and never the exit(99)"
        );
        if tool {
            let mut expected = vec![
                initial_exec,
                SyscallRequest::new(libc::SYS_dup as u64, [0; 6]),
            ];
            if rebound {
                expected.push(SyscallRequest::new(
                    libc::SYS_dup2 as u64,
                    [3, 0, 0, 0, 0, 0],
                ));
                expected.push(SyscallRequest::new(
                    libc::SYS_close as u64,
                    [3, 0, 0, 0, 0, 0],
                ));
            }
            expected.push(request);
            assert_eq!(
                forwarded, expected,
                "exact initial exec and guest request sequence"
            );
            assert_eq!(forwarded.last(), Some(&request));
        } else {
            assert!(forwarded.is_empty());
        }
        drop(backend);
        // SAFETY: the runner has joined, no host read started, and backend
        // teardown has completed. No guest or host writer remains. The retained
        // operand owns the exact mapping and prevents
        // its replacement, so this check does not depend on post-terminal
        // admission or on a pointer into the now-dropped backend.
        let words = unsafe { request_words.read_volatile::<[u64; 7]>() };
        assert_eq!(
            SyscallRequest::new(words[0], words[1..].try_into().unwrap()),
            request,
            "the final transport must still name the exact refused read"
        );
        // SAFETY: the same joined, writer-free state applies to this separately
        // retained result operand after the backend has been dropped.
        assert_eq!(
            unsafe { result_word.read_volatile::<[u8; 8]>() },
            READ_RESULT_SENTINEL,
            "pre-injection refusal stored a fabricated syscall result"
        );
        drop(request_words);
        drop(result_word);
        println!("ZERO_READ_GUEST_REFUSED tool={tool} rebound={rebound} fd={expected_fd}");
    }

    #[test]
    fn host_dup_zero_read_is_refused_before_injection() {
        run_case(false, false);
    }

    #[test]
    fn host_rebound_zero_read_is_refused_before_injection() {
        run_case(false, true);
    }

    #[test]
    fn tool_dup_zero_read_is_refused_before_injection() {
        run_case(true, false);
    }

    #[test]
    fn tool_rebound_zero_read_is_refused_before_injection() {
        run_case(true, true);
    }
}
