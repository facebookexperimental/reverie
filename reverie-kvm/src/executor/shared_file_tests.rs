// Source-only dispatcher controls for ordinary-file shared mappings. The real
// KVM integration tests separately exercise the one-stopped-vCPU admission.
mod shared_file_dispatch_tests {
    use super::*;

    struct Fixture {
        memory: GuestMemory,
        state: LoadedStaticElf,
        path: PathBuf,
        expected: Vec<u8>,
        // Drop the backing handles before removing their directory.
        root: TestDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_stack_window(0)
        }

        /// The fixture with `stack_pages` more pages above mmap_limit, placed as
        /// a mapped stack window at the top of the user address space.
        fn with_stack_window(stack_pages: u64) -> Self {
            let root = TestDir::new();
            let mut state = test_state(&root.0);
            state.brk_limit = BOOT_RESERVED_END + 4 * PAGE_SIZE;
            state.mmap_base = state.brk_limit;
            state.mmap_next = state.mmap_base;
            state.mmap_limit = state.mmap_base + 16 * PAGE_SIZE;
            let size = state.mmap_limit + stack_pages * PAGE_SIZE;
            let memory = GuestMemory::new(0, size as usize).unwrap();
            memory.write_raw(0, &vec![0xa5; size as usize]).unwrap();
            memory
                .map_user_permissions(0, BOOT_RESERVED_END, true, true)
                .unwrap();
            if stack_pages != 0 {
                memory
                    .establish_user_stack_window(stack_pages * PAGE_SIZE)
                    .unwrap();
                memory
                    .map_user_permissions(state.mmap_limit, stack_pages * PAGE_SIZE, true, true)
                    .unwrap();
            }
            memory.enable_user_access();
            memory.set_allocation_cursors(AllocationCursors::from_elf(&state));
            let path = root.0.join("ordinary-file");
            let expected: Vec<u8> = (0..3 * PAGE_SIZE as usize)
                .map(|i| (i.wrapping_mul(17).wrapping_add(29)) as u8)
                .collect();
            std::fs::write(&path, &expected).unwrap();
            Self {
                memory,
                state,
                path,
                expected,
                root,
            }
        }

        /// A 16 MiB fixture with Linux's layout, so mappings without MAP_FIXED
        /// land in the mmap window, at user addresses that are not physical.
        fn with_linux_layout() -> Self {
            const SIZE: u64 = 16 * 1024 * 1024;
            let root = TestDir::new();
            let mut state = test_state(&root.0);
            let mut memory = GuestMemory::new(0, SIZE as usize).unwrap();
            let layout = crate::elf::establish_linux_layout(
                &mut memory,
                BOOT_RESERVED_END + PAGE_SIZE,
                1024 * 1024,
                None,
            )
            .unwrap()
            .unwrap();
            state.brk_limit = layout.identity_end;
            state.mmap_base = layout.identity_end;
            state.mmap_next = layout.identity_end;
            state.mmap_limit = layout.mmap_end;
            memory.write_raw(0, &vec![0xa5; SIZE as usize]).unwrap();
            memory
                .map_user_permissions(0, BOOT_RESERVED_END, true, true)
                .unwrap();
            memory.enable_user_access();
            memory.set_allocation_cursors(AllocationCursors::from_elf(&state));
            let path = root.0.join("ordinary-file");
            let expected: Vec<u8> = (0..3 * PAGE_SIZE as usize)
                .map(|i| (i.wrapping_mul(17).wrapping_add(29)) as u8)
                .collect();
            std::fs::write(&path, &expected).unwrap();
            Self {
                memory,
                state,
                path,
                expected,
                root,
            }
        }

        fn open(&mut self, writable: bool) -> i64 {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(writable)
                .open(&self.path)
                .unwrap();
            let fd = insert_file_with_flags(&mut self.state, file, false, None);
            assert!(fd >= 3);
            fd
        }

        fn shared(&mut self, fd: i64, address: u64, offset: u64, writable: bool) -> u64 {
            let expected = if address == 0 {
                self.state.mmap_next
            } else {
                address
            };
            let flags = libc::MAP_SHARED | if address == 0 { 0 } else { libc::MAP_FIXED };
            let protection = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
            let result = syscall_result(
                &mut self.memory,
                &mut self.state,
                libc::SYS_mmap,
                [
                    address,
                    PAGE_SIZE,
                    protection as u64,
                    flags as u64,
                    fd as u64,
                    offset,
                ],
            );
            assert_eq!(result, expected as i64);
            assert!(
                self.memory
                    .range_contains_shared_file(expected, PAGE_SIZE as usize)
            );
            expected
        }

        fn private(&mut self) -> u64 {
            let address = self.state.mmap_next;
            assert_eq!(
                syscall_result(
                    &mut self.memory,
                    &mut self.state,
                    libc::SYS_mmap,
                    [
                        0,
                        PAGE_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                        u64::MAX,
                        0
                    ]
                ),
                address as i64
            );
            address
        }

        fn take_executor(&mut self) -> ElfExecutor {
            let replacement = test_state(&self.root.0);
            ElfExecutor::new(std::mem::replace(&mut self.state, replacement), false)
        }
    }

    // After a terminal refusal, the public copy APIs correctly refuse reentry.
    // This independent kernel copy observes unchanged HVA bytes without asking
    // the poisoned guest-copy path to succeed. These fixtures own every byte,
    // never truncate a file and have no concurrent writer or mapping mutation.
    // The separate truncation test reads the surviving file bytes instead.
    fn hva_bytes(memory: &GuestMemory) -> Vec<u8> {
        let length = (memory.guest_end() - memory.guest_base()) as usize;
        let mut bytes = vec![0; length];
        let local = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: length,
        };
        let remote = libc::iovec {
            iov_base: memory.host_address() as usize as *mut libc::c_void,
            iov_len: length,
        };
        // SAFETY: local owns length writable bytes; the kernel validates the
        // remote range, whose lifetime is retained by memory for this call.
        let count = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
        assert_eq!(
            count,
            length as isize,
            "HVA snapshot: {}",
            std::io::Error::last_os_error()
        );
        bytes
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Layout {
        hva: u64,
        bytes: Vec<u8>,
        cursors: Option<AllocationCursors>,
        elf_cursors: AllocationCursors,
        pages: Vec<(Option<RegionKind>, bool)>,
        backed: usize,
        shared_domain: bool,
    }

    fn layout(memory: &GuestMemory, state: &LoadedStaticElf) -> Layout {
        Layout {
            hva: memory.host_address(),
            bytes: hva_bytes(memory),
            cursors: memory.allocation_cursors(),
            elf_cursors: AllocationCursors::from_elf(state),
            pages: (memory.guest_base()..memory.guest_end())
                .step_by(PAGE_SIZE as usize)
                .map(|address| {
                    (
                        memory.reservation_kind(address),
                        memory.user_range_is_mapped(address, PAGE_SIZE),
                    )
                })
                .collect(),
            backed: memory.separately_backed_pages(),
            shared_domain: memory.entry_gate().single_member_domain_active(),
        }
    }

    fn capability(error: &crate::Error, operation: &str, reason: &str) {
        match error.primary() {
            crate::Error::SharedFileCapability {
                operation: actual,
                reason: actual_reason,
            } => {
                assert_eq!(*actual, operation);
                assert_eq!(*actual_reason, reason);
            }
            other => {
                panic!("expected exact shared-file capability {operation}: {reason}; got {other:?}")
            }
        }
    }

    fn failure(action: SyscallAction) -> crate::Error {
        match action {
            SyscallAction::Failure(error) => error,
            SyscallAction::Continue { result, .. } => {
                panic!("terminal refusal became syscall result {result}")
            }
            SyscallAction::Exit(status) => panic!("terminal refusal became exit {status:?}"),
        }
    }

    #[test]
    fn pipe2_truncated_shared_copy_notifies_after_actual_file_table_unlock() {
        struct Observation {
            table_keys: Option<Vec<i32>>,
            copies: usize,
            failure: Option<Arc<crate::entry::PendingFailure>>,
        }
        struct TableWake {
            table: Arc<Mutex<FileTableState>>,
            memory: GuestMemory,
            rows: Mutex<Vec<Observation>>,
        }
        impl std::task::Wake for TableWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                // Record rather than panic under a lock if the regression
                // fires. The assertions below report the original failure.
                let table_keys = self
                    .table
                    .try_lock()
                    .ok()
                    .map(|table| table.files.keys().copied().collect());
                let gate = self.memory.entry_gate();
                self.rows.lock().unwrap().push(Observation {
                    table_keys,
                    copies: gate.test_state().copies,
                    failure: gate.pending_failure(),
                });
            }
        }

        let mut f = Fixture::new();
        let fd = f.open(true);
        let address = f.state.mmap_next;
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [
                    0,
                    2 * PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    libc::MAP_SHARED as u64,
                    fd as u64,
                    0,
                ],
            ),
            address as i64
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&f.path)
            .unwrap();
        file.set_len(PAGE_SIZE).unwrap();
        let output = address + PAGE_SIZE - 2;
        let mut executor = f.take_executor();
        let first_new_fd = (0..GUEST_NOFILE_LIMIT)
            .find(|fd| {
                !is_open_standard(&executor.state, *fd) && !executor.state.files.contains_key(fd)
            })
            .unwrap();
        let original_keys = executor.state.files.keys().copied().collect::<Vec<_>>();
        let original_identities = executor.state.fd_object_inodes.clone();
        let original_cloexec = executor.state.cloexec_fds.clone();
        let cursors = f.memory.allocation_cursors();
        let elf_cursors = AllocationCursors::from_elf(&executor.state);
        let hva = f.memory.host_address();
        let backed = f.memory.separately_backed_pages();
        let gate = f.memory.entry_gate();
        let observer = Arc::new(TableWake {
            table: executor.file_table.clone(),
            memory: f.memory.clone(),
            rows: Mutex::new(Vec::new()),
        });
        let waker = std::task::Waker::from(observer.clone());
        let mut changed = Box::pin(gate.subscribe());
        assert!(
            changed
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        let error = executor
            .execute_checked(
                &SyscallRequest::new(
                    libc::SYS_pipe2 as u64,
                    [output, libc::O_CLOEXEC as u64, 0, 0, 0, 0],
                ),
                &f.memory,
            )
            .unwrap_err();
        assert!(matches!(error.primary(), crate::Error::SharedFileCopy {
            operation: "write", address: actual, requested: 8,
            transferred: 2, prior_transferred: 0, source,
        } if *actual == output && source.raw_os_error() == Some(libc::EFAULT)));
        let pending = gate
            .pending_failure()
            .expect("copy failure was not terminal");
        let causes = pending.causes();
        assert_eq!(causes.len(), 1);
        assert!(error.retains_primary(&causes[0]));
        assert!(
            changed
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_ready()
        );
        let rows = observer.rows.lock().unwrap();
        assert!(!rows.is_empty(), "copy retirement lost its notification");
        for row in rows.iter() {
            assert_eq!(row.table_keys.as_ref(), Some(&original_keys));
            assert_eq!(row.copies, 0);
            assert!(Arc::ptr_eq(row.failure.as_ref().unwrap(), &pending));
        }
        drop(rows);

        // The prefix really reached the file. Do not demand rollback of that
        // write, or of the identity allocator used by the temporary pipe.
        let mut expected = f.expected[..PAGE_SIZE as usize].to_vec();
        expected[PAGE_SIZE as usize - 2..].copy_from_slice(&first_new_fd.to_ne_bytes()[..2]);
        assert_eq!(std::fs::read(&f.path).unwrap(), expected);
        assert_eq!(file.metadata().unwrap().len(), PAGE_SIZE);
        assert_eq!(
            executor.state.files.keys().copied().collect::<Vec<_>>(),
            original_keys
        );
        assert_eq!(executor.state.cloexec_fds, original_cloexec);
        assert_eq!(
            executor.state.fd_object_inodes.len(),
            original_identities.len()
        );
        for (fd, identity) in original_identities {
            assert!(Arc::ptr_eq(
                &executor.state.fd_object_inodes[&fd],
                &identity
            ));
        }
        assert_eq!(f.memory.host_address(), hva);
        assert_eq!(f.memory.allocation_cursors(), cursors);
        assert_eq!(AllocationCursors::from_elf(&executor.state), elf_cursors);
        assert_eq!(f.memory.separately_backed_pages(), backed);
        assert!(f.memory.user_range_is_mapped(address, 2 * PAGE_SIZE));
        assert!(gate.single_member_domain_active());
        assert!(executor.take_process_action().is_none());
        assert!(executor.pending_processes.is_empty());
        assert!(executor.state.consumed_child_wait.is_none());
    }

    #[test]
    fn ordinary_file_is_immediately_coherent_and_survives_descriptor_reuse() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let first = f.shared(fd, 0, PAGE_SIZE, true);
        let second = f.shared(fd, 0, PAGE_SIZE, true);
        let observer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&f.path)
            .unwrap();
        f.memory.user().copy_to_user(first + 7, b"map").unwrap();
        f.expected[PAGE_SIZE as usize + 7..PAGE_SIZE as usize + 10].copy_from_slice(b"map");
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        assert_eq!(observer.write_at(b"fd", PAGE_SIZE + 31).unwrap(), 2);
        f.expected[PAGE_SIZE as usize + 31..PAGE_SIZE as usize + 33].copy_from_slice(b"fd");
        for address in [first, second] {
            let mut actual = vec![0; PAGE_SIZE as usize];
            f.memory.user().read(address, &mut actual).unwrap();
            assert_eq!(
                actual,
                f.expected[PAGE_SIZE as usize..2 * PAGE_SIZE as usize]
            );
        }
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        let replacement = f.root.0.join("replacement");
        let replacement_bytes = vec![0x72; 3 * PAGE_SIZE as usize];
        std::fs::write(&replacement, &replacement_bytes).unwrap();
        let replacement_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&replacement)
            .unwrap();
        assert_eq!(
            insert_file_with_flags(&mut f.state, replacement_file, false, None),
            fd
        );
        f.memory
            .user()
            .copy_to_user(second + 43, b"retained")
            .unwrap();
        f.expected[PAGE_SIZE as usize + 43..PAGE_SIZE as usize + 51].copy_from_slice(b"retained");
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_msync,
                [first, PAGE_SIZE, libc::MS_SYNC as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        assert_eq!(std::fs::read(replacement).unwrap(), replacement_bytes);
    }

    /// MAP_FIXED_NOREPLACE of an ordinary file maps a shared view exactly at a
    /// vacant address and refuses one over a mapped page (EEXIST), keeping
    /// it (https://github.com/rrnewton/hermit/issues/4428).
    #[test]
    fn noreplace_maps_a_shared_file_view_only_at_a_vacant_address() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let noreplace = |f: &mut Fixture, address: u64| {
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [
                    address,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE) as u64,
                    fd as u64,
                    0,
                ],
            )
        };
        let vacant = f.state.mmap_base + 8 * PAGE_SIZE;
        assert_eq!(noreplace(&mut f, vacant), vacant as i64);
        assert!(
            f.memory
                .range_contains_shared_file(vacant, PAGE_SIZE as usize)
        );
        let mut actual = vec![0; PAGE_SIZE as usize];
        f.memory.user().read(vacant, &mut actual).unwrap();
        assert_eq!(actual, f.expected[..PAGE_SIZE as usize]);
        // Over that view, and over a private page.
        assert_eq!(noreplace(&mut f, vacant), negative_errno(libc::EEXIST));
        let private = f.private();
        f.memory.user().copy_to_user(private, b"private!").unwrap();
        assert_eq!(noreplace(&mut f, private), negative_errno(libc::EEXIST));
        let mut kept = [0; 8];
        f.memory.user().read(private, &mut kept).unwrap();
        assert_eq!(&kept, b"private!");
    }

    /// MAP_FIXED_NOREPLACE's refusals in Linux's order: an unaligned offset
    /// first (EINVAL), then a bad or O_PATH descriptor (EBADF), an overlap,
    /// a stack page above the mapping range included (EEXIST), and only
    /// then MAP_SHARED_VALIDATE's refusal of the flag (EOPNOTSUPP).
    #[test]
    fn noreplace_refusals_follow_linux_order() {
        let mut f = Fixture::with_stack_window(2);
        let fd = f.open(true);
        let call = |f: &mut Fixture, address: u64, flags: libc::c_int, fd: i64, offset: u64| {
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [
                    address,
                    PAGE_SIZE,
                    libc::PROT_READ as u64,
                    (flags | libc::MAP_FIXED_NOREPLACE) as u64,
                    fd as u64,
                    offset,
                ],
            )
        };
        let private = f.private();
        let past_task_size = 0x8000_0000_0000_u64;
        assert_eq!(
            call(&mut f, past_task_size, libc::MAP_PRIVATE, fd, 1),
            negative_errno(libc::EINVAL)
        );
        let located = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&f.path)
            .unwrap();
        let located = insert_file_with_flags(&mut f.state, located, false, None);
        assert_eq!(
            call(&mut f, private, libc::MAP_PRIVATE, located, 0),
            negative_errno(libc::EBADF)
        );
        // A page of the stack window, above the mapping range (at the top of
        // the user address space).
        let stack_page = f.memory.physical_to_user(f.state.mmap_limit).unwrap();
        assert_eq!(
            call(&mut f, stack_page, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0),
            negative_errno(libc::EEXIST)
        );
        let validate = libc::MAP_SHARED_VALIDATE;
        assert_eq!(
            call(&mut f, private, validate, fd, 0),
            negative_errno(libc::EEXIST)
        );
        let vacant = f.state.mmap_base + 10 * PAGE_SIZE;
        assert_eq!(
            call(&mut f, vacant, validate, fd, 0),
            negative_errno(libc::EOPNOTSUPP)
        );
        assert!(
            !f.memory
                .range_contains_shared_file(vacant, PAGE_SIZE as usize)
        );
    }

    #[test]
    fn readonly_shared_mprotect_write_denial_preserves_image_and_generation() {
        let mut f = Fixture::new();
        let fd = f.open(false);
        let address = f.shared(fd, 0, 0, false);
        let before = layout(&f.memory, &f.state);
        let generation = f.memory.backing_generation();
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mprotect,
                [
                    address,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    0,
                    0,
                    0
                ]
            ),
            negative_errno(libc::EACCES)
        );
        assert_eq!(
            f.memory
                .user()
                .user_writable_prefix(address, PAGE_SIZE as usize)
                .unwrap(),
            0
        );
        assert_eq!(layout(&f.memory, &f.state), before);
        assert_eq!(f.memory.backing_generation(), generation);
        assert!(f.memory.entry_gate().pending_failure().is_none());
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    #[test]
    fn executable_shared_mprotect_refuses_before_memory_effects() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let address = f.shared(fd, 0, 0, true);
        let before = layout(&f.memory, &f.state);
        let error = failure(execute_basic_syscall(
            &mut f.memory,
            &mut f.state,
            &SyscallRequest::new(
                libc::SYS_mprotect as u64,
                [
                    address,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_EXEC) as u64,
                    0,
                    0,
                    0,
                ],
            ),
        ));
        capability(
            &error,
            "mprotect",
            "executable ordinary shared-file mappings are not implemented",
        );
        assert_eq!(layout(&f.memory, &f.state), before);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    #[test]
    fn synthetic_and_captured_backings_refuse_before_mapping_or_cursor_change() {
        for captured in [false, true] {
            let mut f = Fixture::new();
            let mut output = CapturedOutput::default();
            let fd = if captured {
                let file = std::fs::File::open(&f.path).unwrap();
                insert_file_with_flags(&mut f.state, file, false, Some(OutputAlias::Stdout))
            } else {
                let fd = open_readonly(&mut f.memory, &mut f.state, "/proc/stat");
                assert!(fd >= 3);
                assert!(f.state.proc_files.contains_key(&(fd as i32)));
                fd
            };
            let before = layout(&f.memory, &f.state);
            let error = failure(execute_basic_syscall_with_output(
                &mut f.memory,
                &mut f.state,
                &SyscallRequest::new(
                    libc::SYS_mmap as u64,
                    [
                        0,
                        PAGE_SIZE,
                        libc::PROT_READ as u64,
                        libc::MAP_SHARED as u64,
                        fd as u64,
                        0,
                    ],
                ),
                None,
                captured.then_some(&mut output),
            ));
            capability(&error, "mmap", "synthetic or captured backing");
            assert_eq!(layout(&f.memory, &f.state), before);
            assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        }
    }

    #[test]
    fn reserved_memfd_names_refuse_even_without_private_side_table_marks() {
        for name in [
            "reverie-kvm-proc",
            "reverie-kvm.proc-carrier.v1.forged",
            "reverie-kvm.capture-transfer.v1",
        ] {
            let mut f = Fixture::new();
            let mut file = syncfs_memfd(name);
            file.write_all(&f.expected).unwrap();
            let observer = file.try_clone().unwrap();
            let fd = insert_file_with_flags(&mut f.state, file, false, None);
            assert!(fd >= 3);
            assert!(!f.state.proc_files.contains_key(&(fd as i32)));
            assert!(output_alias(&f.state, fd as i32).is_none());
            let before = layout(&f.memory, &f.state);
            let error = failure(execute_basic_syscall(
                &mut f.memory,
                &mut f.state,
                &SyscallRequest::new(
                    libc::SYS_mmap as u64,
                    [
                        0,
                        PAGE_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        libc::MAP_SHARED as u64,
                        fd as u64,
                        0,
                    ],
                ),
            ));
            capability(&error, "mmap", "reserved private memfd backing");
            assert_eq!(layout(&f.memory, &f.state), before);
            let mut bytes = vec![0; f.expected.len()];
            assert_eq!(observer.read_at(&mut bytes, 0).unwrap(), bytes.len());
            assert_eq!(bytes, f.expected);
        }
    }

    // Only a run that reports host metadata timestamps creates a memfd named
    // reverie-kvm-virtual-file. Elsewhere a guest memfd with that name is an
    // ordinary shared file backing.
    #[test]
    fn virtual_file_carrier_name_is_reserved_only_when_the_backend_creates_it() {
        for host_metadata_timestamps in [false, true] {
            let mut f = Fixture::new();
            f.state.host_metadata_timestamps = host_metadata_timestamps;
            let mut file = syncfs_memfd("reverie-kvm-virtual-file");
            file.write_all(&f.expected).unwrap();
            let fd = insert_file_with_flags(&mut f.state, file, false, None);
            assert!(fd >= 3);
            if !host_metadata_timestamps {
                let address = f.shared(fd, 0, 0, true);
                let mut actual = vec![0; PAGE_SIZE as usize];
                f.memory.user().read(address, &mut actual).unwrap();
                assert_eq!(actual, f.expected[..PAGE_SIZE as usize]);
                continue;
            }
            let before = layout(&f.memory, &f.state);
            let error = failure(execute_basic_syscall(
                &mut f.memory,
                &mut f.state,
                &SyscallRequest::new(
                    libc::SYS_mmap as u64,
                    [
                        0,
                        PAGE_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        libc::MAP_SHARED as u64,
                        fd as u64,
                        0,
                    ],
                ),
            ));
            capability(&error, "mmap", "reserved private memfd backing");
            assert_eq!(layout(&f.memory, &f.state), before);
        }
    }

    #[test]
    fn shared_anonymous_replacement_refuses_before_retiring_file_domain() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let address = f.shared(fd, 0, PAGE_SIZE, true);
        let before = layout(&f.memory, &f.state);
        let error = failure(execute_basic_syscall(
            &mut f.memory,
            &mut f.state,
            &SyscallRequest::new(
                libc::SYS_mmap as u64,
                [
                    address,
                    PAGE_SIZE,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64,
                    u64::MAX,
                    0,
                ],
            ),
        ));
        capability(
            &error,
            "mmap",
            "shared anonymous replacement requires independent fork-sharing ownership",
        );
        assert_eq!(layout(&f.memory, &f.state), before);
        assert!(f.memory.contains_shared_file());
        assert!(f.memory.entry_gate().single_member_domain_active());
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    #[test]
    fn shared_source_or_destination_mremap_refuses_before_effects() {
        for shared_source in [true, false] {
            let mut f = Fixture::new();
            let private = f.private();
            let fd = f.open(true);
            let shared = f.shared(fd, 0, 0, true);
            f.memory.write_raw(private, b"private canary").unwrap();
            let before = layout(&f.memory, &f.state);
            let args = if shared_source {
                [
                    shared,
                    PAGE_SIZE,
                    2 * PAGE_SIZE,
                    libc::MREMAP_MAYMOVE as u64,
                    0,
                    0,
                ]
            } else {
                [
                    private,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                    shared,
                    0,
                ]
            };
            let error = failure(execute_basic_syscall(
                &mut f.memory,
                &mut f.state,
                &SyscallRequest::new(libc::SYS_mremap as u64, args),
            ));
            capability(
                &error,
                "mremap",
                "this layout operation intersects an ordinary shared-file view",
            );
            assert_eq!(layout(&f.memory, &f.state), before);
            assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        }
    }

    /// A stack-window source remapped onto a shared-file destination is refused
    /// before any effect: the source bytes, the layout and the file stay as
    /// they were.
    #[test]
    fn stack_window_mremap_onto_shared_file_refuses_before_effects() {
        let mut f = Fixture::with_stack_window(4);
        let fd = f.open(true);
        let shared = f.shared(fd, 0, 0, true);
        let source = crate::memory::USER_ADDRESS_END - 4 * PAGE_SIZE;
        f.memory.user().write(source, b"stack canary").unwrap();
        let before = layout(&f.memory, &f.state);
        let error = failure(execute_basic_syscall(
            &mut f.memory,
            &mut f.state,
            &SyscallRequest::new(
                libc::SYS_mremap as u64,
                [
                    source,
                    PAGE_SIZE,
                    PAGE_SIZE,
                    (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                    shared,
                    0,
                ],
            ),
        ));
        capability(
            &error,
            "mremap",
            "this layout operation intersects an ordinary shared-file view",
        );
        // The layout includes every byte of guest memory, the source's too.
        assert_eq!(layout(&f.memory, &f.state), before);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    /// As on Linux, brk does not grow over a mapping, a shared file view
    /// included: it returns the old break and changes nothing.
    #[test]
    fn heap_growth_over_shared_file_returns_the_old_break_unchanged() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let address = f.state.heap_base + PAGE_SIZE;
        f.shared(fd, address, PAGE_SIZE, true);
        let before = layout(&f.memory, &f.state);
        let old_break = f.state.program_break;
        for requested in [address + PAGE_SIZE, address + 17] {
            assert_eq!(
                syscall_result(
                    &mut f.memory,
                    &mut f.state,
                    libc::SYS_brk,
                    [requested, 0, 0, 0, 0, 0],
                ),
                old_break as i64,
                "brk({requested:#x})"
            );
            assert_eq!(layout(&f.memory, &f.state), before);
            assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        }
    }

    #[test]
    fn heap_shrink_over_replaced_shared_page_is_typed_and_pre_effect() {
        let mut f = Fixture::new();
        let original_break = f.state.heap_base + 3 * PAGE_SIZE;
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_brk,
                [original_break, 0, 0, 0, 0, 0],
            ),
            original_break as i64
        );
        let fd = f.open(true);
        let address = f.state.heap_base + PAGE_SIZE;
        assert_eq!(f.shared(fd, address, PAGE_SIZE, true), address);
        let before = layout(&f.memory, &f.state);
        let requested = f.state.heap_base + 17;
        let error = failure(execute_basic_syscall(
            &mut f.memory,
            &mut f.state,
            &SyscallRequest::new(libc::SYS_brk as u64, [requested, 0, 0, 0, 0, 0]),
        ));
        capability(
            &error,
            "brk",
            "this layout operation intersects an ordinary shared-file view",
        );
        assert_eq!(layout(&f.memory, &f.state), before);
        assert_eq!(f.state.program_break, original_break);
        assert!(
            f.memory
                .range_contains_shared_file(address, PAGE_SIZE as usize)
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    #[test]
    fn disjoint_private_remap_still_moves_with_a_live_shared_file() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let shared = f.shared(fd, 0, PAGE_SIZE, true);
        let private = f.private();
        let blocker = f.private();
        assert_eq!(blocker, private + PAGE_SIZE);
        let pattern = vec![0x39; PAGE_SIZE as usize];
        f.memory.user().copy_to_user(private, &pattern).unwrap();
        let moved = blocker + PAGE_SIZE;
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mremap,
                [
                    private,
                    PAGE_SIZE,
                    2 * PAGE_SIZE,
                    libc::MREMAP_MAYMOVE as u64,
                    0,
                    0
                ]
            ),
            moved as i64
        );
        let mut actual = vec![0xff; 2 * PAGE_SIZE as usize];
        f.memory.user().read(moved, &mut actual).unwrap();
        let mut expected = pattern;
        expected.resize(2 * PAGE_SIZE as usize, 0);
        assert_eq!(actual, expected);
        assert!(!f.memory.user_range_is_mapped(private, PAGE_SIZE));
        assert!(
            f.memory
                .range_contains_shared_file(shared, PAGE_SIZE as usize)
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        assert!(f.memory.entry_gate().pending_failure().is_none());
    }

    #[test]
    fn shared_file_fork_and_non_vm_clone_admit_exact_private_snapshot() {
        for number in [libc::SYS_fork, libc::SYS_clone, libc::SYS_clone3] {
            let mut f = Fixture::new();
            let fd = f.open(true);
            let shared = f.shared(fd, 0, PAGE_SIZE, true);
            let private = f.private();
            f.memory.write_raw(private, b"parent").unwrap();
            let args = if number == libc::SYS_clone {
                [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]
            } else if number == libc::SYS_clone3 {
                let mut raw = [0_u8; 88];
                raw[32..40].copy_from_slice(&(libc::SIGCHLD as u64).to_ne_bytes());
                f.memory.write_raw(0x100, &raw).unwrap();
                [0x100, 88, 0, 0, 0, 0]
            } else { [0; 6] };
            let mut executor = f.take_executor();
            let before = layout(&f.memory, &executor.state);
            let next = executor.next_pid.load(Ordering::SeqCst);
            assert_eq!(executor.execute_checked(&SyscallRequest::new(number as u64, args), &f.memory).unwrap(), i64::from(next));
            assert_eq!(executor.next_pid.load(Ordering::SeqCst), next + 1);
            match executor.take_process_action() {
                Some(ProcessAction::Fork { child_pid, share_address_space, parent_tid, child_tid, .. }) => {
                    assert_eq!(child_pid, next);
                    assert!(!share_address_space);
                    assert_eq!((parent_tid, child_tid), (None, None));
                }
                _ => panic!("non-VM fork must publish exactly one process action"),
            }
            assert_eq!(layout(&f.memory, &executor.state), before);
            let snapshot = f.memory.snapshot().unwrap();
            snapshot.write_raw(private, b"child!").unwrap();
            snapshot.write_raw(shared + 17, b"shared").unwrap();
            let mut bytes = [0; 6];
            f.memory.read_raw(private, &mut bytes).unwrap();
            assert_eq!(&bytes, b"parent");
            f.memory.read_raw(shared + 17, &mut bytes).unwrap();
            assert_eq!(&bytes, b"shared");
            let file = std::fs::read(&f.path).unwrap();
            assert_eq!(&file[PAGE_SIZE as usize + 17..PAGE_SIZE as usize + 23], b"shared");
            assert_eq!(&file[..PAGE_SIZE as usize], &f.expected[..PAGE_SIZE as usize]);
            assert!(f.memory.entry_gate().pending_failure().is_none());
            assert!(snapshot.entry_gate().pending_failure().is_none());
        }
    }

    #[test]
    fn shared_file_vm_and_thread_clone_refuse_before_ids_copyout_or_process_action() {
        for (number, flags) in [
            (libc::SYS_vfork, 0),
            (libc::SYS_clone, libc::CLONE_VM),
            (libc::SYS_clone, libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND),
            (libc::SYS_clone3, libc::CLONE_VM),
            (libc::SYS_clone3, libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND),
        ] {
            let mut f = Fixture::new();
            let fd = f.open(true);
            f.shared(fd, 0, 0, true);
            let args = if number == libc::SYS_clone {
                [(flags | libc::CLONE_PARENT_SETTID | libc::CLONE_CHILD_SETTID) as u64,
                    0, 0x100, 0x108, 0, 0]
            } else if number == libc::SYS_clone3 {
                let mut raw = [0_u8; 88];
                raw[..8].copy_from_slice(&(flags as u64).to_ne_bytes());
                f.memory.write_raw(0x100, &raw).unwrap();
                [0x100, 88, 0, 0, 0, 0]
            } else { [0; 6] };
            let mut executor = f.take_executor();
            let before = layout(&f.memory, &executor.state);
            let next = executor.next_pid.load(Ordering::SeqCst);
            assert!(executor.state.task_lifecycle.lock().unwrap().get(next).is_none());
            let error = executor.execute_checked(&SyscallRequest::new(number as u64, args), &f.memory).unwrap_err();
            capability(&error, "CLONE_VM/thread creation",
                "ordinary shared-file views require one vCPU per address space");
            assert_eq!(executor.next_pid.load(Ordering::SeqCst), next);
            assert!(executor.take_process_action().is_none());
            assert!(executor.pending_processes.is_empty());
            assert!(executor.state.task_lifecycle.lock().unwrap().get(next).is_none());
            assert_eq!(layout(&f.memory, &executor.state), before);
            assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
        }
    }

    #[test]
    fn shared_file_clone3_invalid_copyin_has_no_process_effect() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        f.shared(fd, 0, 0, true);
        let mut executor = f.take_executor();
        let before = layout(&f.memory, &executor.state);
        let next = executor.next_pid.load(Ordering::SeqCst);
        assert_eq!(executor.execute_checked(&SyscallRequest::new(libc::SYS_clone3 as u64,
            [u64::MAX, 88, 0, 0, 0, 0]), &f.memory).unwrap(), negative_errno(libc::EFAULT));
        assert_eq!(executor.next_pid.load(Ordering::SeqCst), next);
        assert!(executor.take_process_action().is_none());
        assert!(executor.pending_processes.is_empty());
        assert_eq!(layout(&f.memory, &executor.state), before);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    #[test]
    fn last_shared_view_retirement_restores_fork_and_private_snapshot() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        let address = f.shared(fd, 0, 0, true);
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_munmap,
                [address, PAGE_SIZE, 0, 0, 0, 0]
            ),
            0
        );
        assert!(!f.memory.contains_shared_file());
        assert!(!f.memory.entry_gate().single_member_domain_active());
        let snapshot = f.memory.snapshot().unwrap();
        assert_eq!(hva_bytes(&snapshot), hva_bytes(&f.memory));
        let mut executor = f.take_executor();
        let next = executor.next_pid.load(Ordering::SeqCst);
        assert_eq!(
            executor
                .execute_checked(
                    &SyscallRequest::new(libc::SYS_fork as u64, [0; 6]),
                    &f.memory
                )
                .unwrap(),
            i64::from(next)
        );
        match executor.take_process_action() {
            Some(ProcessAction::Fork {
                child_pid,
                parent_tid,
                child_tid,
                clear_child_tid,
                share_address_space,
                ..
            }) => {
                assert_eq!(child_pid, next);
                assert_eq!(parent_tid, None);
                assert_eq!(child_tid, None);
                assert_eq!(clear_child_tid, None);
                assert!(!share_address_space);
            }
            _ => panic!("ordinary fork did not publish the expected action"),
        }
        let child = executor.fork_child(next, false, false).unwrap();
        assert_eq!(
            (child.state.pid, child.state.tid, child.state.ppid),
            (next, next, executor.state.pid)
        );
        assert_eq!(executor.next_pid.load(Ordering::SeqCst), next + 1);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    fn wait_shared_refusal(waitid_call: bool, later_field: bool, checked: bool) {
        let mut f = Fixture::new();
        let private = f.private();
        let fd = f.open(true);
        let shared = f.shared(fd, 0, 0, true);
        assert_eq!(shared, private + PAGE_SIZE);
        let output = if later_field {
            shared - 16
        } else {
            shared + 16
        };
        let (number, args) = if waitid_call {
            (
                libc::SYS_waitid,
                [
                    libc::P_PID as u64,
                    7,
                    output,
                    libc::WEXITED as u64,
                    0x200,
                    0,
                ],
            )
        } else {
            (libc::SYS_wait4, [7, output, 0, 0x200, 0, 0])
        };
        let mut executor = f.take_executor();
        executor.state.children.insert(7, ExitStatus::Exited(3));
        executor.state.children.insert(8, ExitStatus::Exited(4));
        let before = layout(&f.memory, &executor.state);
        let request = SyscallRequest::new(number as u64, args);
        let error = if checked {
            executor.execute_checked(&request, &f.memory).unwrap_err()
        } else {
            failure(execute_basic_syscall(
                &mut f.memory,
                &mut executor.state,
                &request,
            ))
        };
        capability(
            &error,
            "atomic scalar store",
            "truncate-capable file backing has no proven fault-contained atomic store",
        );
        assert_eq!(executor.state.children.get(&7), Some(ExitStatus::Exited(3)));
        assert_eq!(executor.state.children.get(&8), Some(ExitStatus::Exited(4)));
        assert!(executor.state.consumed_child_wait.is_none());
        assert!(executor.take_process_action().is_none());
        assert_eq!(layout(&f.memory, &executor.state), before);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    /// The wait output preflight checks the shared-file metadata of the
    /// physical page behind a window address, so a status field in a shared
    /// mapping in the mmap window is refused before a ready child is consumed.
    #[test]
    fn wait_shared_refusal_in_the_mmap_window_precedes_child_consumption() {
        for (waitid_call, later_field) in [(false, false), (true, false), (true, true)] {
            for checked in [false, true] {
                let mut f = Fixture::with_linux_layout();
                let fd = f.open(true);
                let flags = (libc::MAP_SHARED) as u64;
                let protection = (libc::PROT_READ | libc::PROT_WRITE) as u64;
                let shared = syscall_result(
                    &mut f.memory,
                    &mut f.state,
                    libc::SYS_mmap,
                    [0, PAGE_SIZE, protection, flags, fd as u64, 0],
                ) as u64;
                assert_eq!(shared, crate::memory::MMAP_BASE - PAGE_SIZE);
                let physical = f.memory.user_range_to_guest(shared, PAGE_SIZE).unwrap();
                assert_ne!(physical, shared);
                assert!(f.memory.user_range_contains_shared_file(shared, PAGE_SIZE));
                // A private page below it holds the earlier waitid fields.
                let private = syscall_result(
                    &mut f.memory,
                    &mut f.state,
                    libc::SYS_mmap,
                    [
                        0,
                        PAGE_SIZE,
                        protection,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                        u64::MAX,
                        0,
                    ],
                ) as u64;
                assert_eq!(private, shared - PAGE_SIZE);
                let output = if later_field {
                    shared - 16
                } else {
                    shared + 16
                };
                let (number, args) = if waitid_call {
                    (
                        libc::SYS_waitid,
                        [
                            libc::P_PID as u64,
                            7,
                            output,
                            libc::WEXITED as u64,
                            0x200,
                            0,
                        ],
                    )
                } else {
                    (libc::SYS_wait4, [7, output, 0, 0x200, 0, 0])
                };
                let mut executor = f.take_executor();
                executor.state.children.insert(7, ExitStatus::Exited(3));
                let before = layout(&f.memory, &executor.state);
                let request = SyscallRequest::new(number as u64, args);
                let error = if checked {
                    executor.execute_checked(&request, &f.memory).unwrap_err()
                } else {
                    failure(execute_basic_syscall(
                        &mut f.memory,
                        &mut executor.state,
                        &request,
                    ))
                };
                capability(
                    &error,
                    "atomic scalar store",
                    "truncate-capable file backing has no proven fault-contained atomic store",
                );
                assert_eq!(executor.state.children.get(&7), Some(ExitStatus::Exited(3)));
                assert!(executor.state.consumed_child_wait.is_none());
                assert!(executor.take_process_action().is_none());
                assert_eq!(layout(&f.memory, &executor.state), before);
                assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
            }
        }
    }

    #[test]
    fn wait4_shared_scalar_refuses_before_ready_child_consumption() {
        for checked in [false, true] {
            wait_shared_refusal(false, false, checked);
        }
    }

    #[test]
    fn wait4_without_a_result_does_not_access_shared_status_or_poison() {
        for checked in [false, true] {
            for live_child in [false, true] {
                let mut f = Fixture::new();
                let fd = f.open(true);
                let mut executor = f.take_executor();
                // Register a real logical child before creating the file view.
                // No child host thread, exit status or completion is fabricated.
                let _child = live_child.then(|| executor.fork_child(7, false, false).unwrap());
                let address = executor.state.mmap_next;
                assert_eq!(
                    syscall_result(
                        &mut f.memory,
                        &mut executor.state,
                        libc::SYS_mmap,
                        [
                            0,
                            PAGE_SIZE,
                            (libc::PROT_READ | libc::PROT_WRITE) as u64,
                            libc::MAP_SHARED as u64,
                            fd as u64,
                            0,
                        ],
                    ),
                    address as i64
                );
                let before = layout(&f.memory, &executor.state);
                let generation = f.memory.entry_gate().generation().unwrap();
                let requested = if live_child { Some(7) } else { None };
                let predicate = executor
                    .state
                    .children
                    .select(requested, false, true)
                    .unwrap();
                assert!(match predicate {
                    ChildWaitSelection::Pending => live_child,
                    ChildWaitSelection::NoChild => !live_child,
                    _ => false,
                });
                let request = SyscallRequest::new(
                    libc::SYS_wait4 as u64,
                    [
                        if live_child { 7 } else { u64::MAX },
                        address + 16,
                        if live_child { libc::WNOHANG as u64 } else { 0 },
                        0x200,
                        0,
                        0,
                    ],
                );
                let result = if checked {
                    executor.execute_checked(&request, &f.memory).unwrap()
                } else {
                    match execute_basic_syscall(&mut f.memory, &mut executor.state, &request) {
                        SyscallAction::Continue {
                            result,
                            segment: None,
                        } => result,
                        _ => panic!("no-result wait4 did not return an ordinary syscall result"),
                    }
                };
                assert_eq!(
                    result,
                    if live_child {
                        0
                    } else {
                        negative_errno(libc::ECHILD)
                    }
                );
                let predicate = executor
                    .state
                    .children
                    .select(requested, false, true)
                    .unwrap();
                assert!(match predicate {
                    ChildWaitSelection::Pending => live_child,
                    ChildWaitSelection::NoChild => !live_child,
                    _ => false,
                });
                assert!(f.memory.entry_gate().pending_failure().is_none());
                assert_eq!(f.memory.entry_gate().generation().unwrap(), generation);
                assert_eq!(layout(&f.memory, &executor.state), before);
                assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
                assert!(executor.state.consumed_child_wait.is_none());
                assert!(executor.take_process_action().is_none());
                assert!(executor.pending_processes.is_empty());
            }
        }
    }

    #[test]
    fn waitid_shared_scalar_refuses_before_any_field_usage_or_child_consumption() {
        for checked in [false, true] {
            for later_field in [false, true] {
                wait_shared_refusal(true, later_field, checked);
            }
        }
    }

    #[test]
    fn ordinary_private_wait4_copyout_fault_still_consumes_with_unrelated_shared_view() {
        let mut f = Fixture::new();
        let fd = f.open(true);
        f.shared(fd, 0, 0, true);
        f.memory
            .map_user_permissions(0, PAGE_SIZE, true, false)
            .unwrap();
        f.state.children.insert(7, ExitStatus::Exited(3));
        f.state.children.insert(8, ExitStatus::Exited(4));
        let before = layout(&f.memory, &f.state);
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_wait4,
                [7, 0x100, 0, 0x200, 0, 0]
            ),
            negative_errno(libc::EFAULT)
        );
        assert!(!f.state.children.contains_key(&7));
        assert_eq!(f.state.children.get(&8), Some(ExitStatus::Exited(4)));
        assert_eq!(
            f.state
                .consumed_child_wait
                .as_ref()
                .map(|receipt| receipt.child_pid()),
            Some(7)
        );
        assert_eq!(layout(&f.memory, &f.state), before);
        assert!(f.memory.entry_gate().pending_failure().is_none());
        assert_eq!(std::fs::read(&f.path).unwrap(), f.expected);
    }

    /// gettimeofday(2) and time(2) store into a writable MAP_SHARED file
    /// mapping, as they did through `UserMemory::write` before they followed
    /// `put_user`'s writability rule: whole words, across a private page and
    /// a shared page too, without a capability refusal or a pending failure.
    /// A read-only shared mapping faults with nothing stored.
    #[test]
    fn gettimeofday_and_time_store_into_a_writable_shared_file_mapping() {
        let mut f = Fixture::new();
        f.state.logical_clock_ns = 9_000_000_000;
        let private = f.private();
        let fd = f.open(true);
        let shared = f.shared(fd, 0, 0, true);
        assert_eq!(shared, private + PAGE_SIZE);
        let call = |f: &mut Fixture, number: libc::c_long, a0: u64, a1: u64| {
            syscall_result(&mut f.memory, &mut f.state, number, [a0, a1, 0, 0, 0, 0])
        };

        f.memory.write_raw(shared - 16, &[0xa5; 16]).unwrap();
        assert_eq!(call(&mut f, libc::SYS_time, shared + 0x10, 0), 9);
        assert_eq!(
            call(&mut f, libc::SYS_gettimeofday, shared + 0x100, shared + 0x200),
            0
        );
        // tv_sec on the private page, tv_usec on the shared page.
        assert_eq!(call(&mut f, libc::SYS_gettimeofday, shared - 8, 0), 0);
        // tloc straddles the private page and the shared page.
        assert_eq!(call(&mut f, libc::SYS_time, shared - 4, 0), 9);
        assert!(f.memory.entry_gate().pending_failure().is_none());

        let seconds = 9_u64.to_ne_bytes();
        let mut expected = f.expected.clone();
        expected[..4].copy_from_slice(&seconds[4..]);
        expected[4..8].fill(0);
        expected[0x10..0x18].copy_from_slice(&seconds);
        expected[0x100..0x110].fill(0);
        expected[0x200..0x208].fill(0);
        assert_eq!(std::fs::read(&f.path).unwrap(), expected);
        assert_eq!(read_struct::<[u8; 8]>(&f.memory, shared - 16), [0xa5; 8]);
        assert_eq!(read_struct::<[u8; 4]>(&f.memory, shared - 8), [0; 4]);
        assert_eq!(read_struct::<[u8; 4]>(&f.memory, shared - 4)[..], seconds[..4]);

        // A read-only shared mapping of the same file: EFAULT, nothing stored.
        let read_only = f.shared(fd, shared + PAGE_SIZE, 0, false);
        assert_eq!(
            call(&mut f, libc::SYS_time, read_only + 0x20, 0),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            call(&mut f, libc::SYS_gettimeofday, read_only + 0x20, 0),
            negative_errno(libc::EFAULT)
        );
        assert!(f.memory.entry_gate().pending_failure().is_none());
        assert_eq!(std::fs::read(&f.path).unwrap(), expected);
    }

    /// Host pages of guest-physical `[physical, physical + length)` that are
    /// resident, by mincore over the fixture's host mapping (guest base 0).
    fn resident_pages(memory: &GuestMemory, physical: u64, length: u64) -> usize {
        let host = memory.host_address() + physical;
        let mut residency = vec![0u8; (length / PAGE_SIZE) as usize];
        // SAFETY: the range lies in the fixture's live guest-memory mapping,
        // and `residency` has one byte per page of it.
        let result = unsafe {
            libc::mincore(
                host as *mut libc::c_void,
                length as usize,
                residency.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        residency.iter().filter(|page| *page & 1 != 0).count()
    }

    /// An anonymous PROT_NONE MAP_NORESERVE reservation reads as zeros
    /// without becoming resident in the host, as on Linux, and munmap gives
    /// back the pages a guest touched. Writing zeros over a new mapping made
    /// every reserved byte resident, so V8's 512 MiB reservations cost their
    /// whole size (https://github.com/rrnewton/hermit/issues/4366).
    #[test]
    fn an_anonymous_reservation_is_zero_without_becoming_resident() {
        const LENGTH: u64 = crate::memory::LAZY_ZERO_MIN_BYTES as u64;
        let mut f = Fixture::with_linux_layout();
        let flags = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE) as u64;
        let user = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [0, LENGTH, libc::PROT_NONE as u64, flags, u64::MAX, 0],
        );
        assert!(user > 0, "mmap returned {user}");
        let physical = f
            .memory
            .user_range_to_guest(user as u64, LENGTH)
            .unwrap();
        // The fixture wrote 0xa5 over all of guest memory, so every page of
        // this range was resident before the reservation.
        assert_eq!(resident_pages(&f.memory, physical, LENGTH), 0);
        let mut bytes = vec![0xff; LENGTH as usize];
        f.memory.read_raw(physical, &mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_munmap,
                [user as u64, LENGTH, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(resident_pages(&f.memory, physical, LENGTH), 0);
    }

    /// A MAP_FIXED anonymous mapping over live data reads as zeros, both a
    /// small one (written with zeros) and a large one (discarded). Checked on
    /// its own, so a mapping that is discarded without being zeroed fails
    /// here rather than at a residency check.
    #[test]
    fn a_fixed_anonymous_mapping_over_live_data_reads_as_zeros() {
        for length in [4 * PAGE_SIZE, crate::memory::LAZY_ZERO_MIN_BYTES as u64] {
            fixed_anonymous_mapping_over_live_data_reads_as_zeros(length);
        }
    }

    fn fixed_anonymous_mapping_over_live_data_reads_as_zeros(length: u64) {
        let mut f = Fixture::with_linux_layout();
        let private = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        let user = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [0, length, read_write, private, u64::MAX, 0],
        );
        assert!(user > 0, "mmap returned {user}");
        let physical = f
            .memory
            .user_range_to_guest(user as u64, length)
            .unwrap();
        f.memory
            .write_raw(physical, &vec![0x3c; length as usize])
            .unwrap();
        let fixed = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [
                user as u64,
                length,
                libc::PROT_READ as u64,
                private | libc::MAP_FIXED as u64,
                u64::MAX,
                0,
            ],
        );
        assert_eq!(fixed, user);
        let physical = f
            .memory
            .user_range_to_guest(user as u64, length)
            .unwrap();
        let mut bytes = vec![0xff; length as usize];
        f.memory.read_raw(physical, &mut bytes).unwrap();
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    /// MADV_DONTNEED over private anonymous pages leaves them reading as
    /// zeros; a large run is discarded, so it is no longer resident, and a
    /// small run is written. Node drops its whole 512 MiB V8 reservation
    /// this way (https://github.com/rrnewton/reverie/issues/1058).
    #[test]
    fn dontneed_drops_private_anonymous_pages_without_writing_large_runs() {
        for (length, resident_after) in [
            (crate::memory::LAZY_ZERO_MIN_BYTES as u64, Some(0)),
            (4 * PAGE_SIZE, None),
        ] {
            let mut f = Fixture::with_linux_layout();
            let private = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
            let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64;
            let user = syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [0, length, read_write, private, u64::MAX, 0],
            );
            assert!(user > 0, "mmap returned {user}");
            let physical = f.memory.user_range_to_guest(user as u64, length).unwrap();
            f.memory
                .write_raw(physical, &vec![0x6b; length as usize])
                .unwrap();
            assert_eq!(
                syscall_result(
                    &mut f.memory,
                    &mut f.state,
                    libc::SYS_madvise,
                    [user as u64, length, libc::MADV_DONTNEED as u64, 0, 0, 0],
                ),
                0
            );
            if let Some(expected) = resident_after {
                assert_eq!(resident_pages(&f.memory, physical, length), expected);
            }
            let mut bytes = vec![0xff; length as usize];
            f.memory.read_raw(physical, &mut bytes).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0), "{length} bytes");
        }
    }

    /// MADV_DONTNEED over [2 MiB private | one MAP_SHARED anonymous page |
    /// 2 MiB private] drops both private runs, leaving neither resident, and
    /// keeps the shared page, whose contents Linux keeps: a run must never
    /// span a page that is not private anonymous. Residency is checked before
    /// the bytes are read back, since reading a discarded page makes it
    /// resident again (https://github.com/rrnewton/reverie/issues/1058).
    #[test]
    fn dontneed_keeps_a_shared_page_between_two_lazy_private_runs() {
        let mut f = Fixture::with_linux_layout();
        let big = crate::memory::LAZY_ZERO_MIN_BYTES as u64;
        let total = 2 * big + PAGE_SIZE;
        let private = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let shared = (libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64;
        let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64;
        let user = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [0, total, read_write, private, u64::MAX, 0],
        );
        assert!(user > 0, "mmap returned {user}");
        let user = user as u64;
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [user + big, PAGE_SIZE, read_write, shared, u64::MAX, 0],
            ) as u64,
            user + big
        );
        let physical = f.memory.user_range_to_guest(user, total).unwrap();
        f.memory
            .write_raw(physical, &vec![0x6b; total as usize])
            .unwrap();
        assert_eq!(
            syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_madvise,
                [user, total, libc::MADV_DONTNEED as u64, 0, 0, 0],
            ),
            0
        );
        assert_eq!(resident_pages(&f.memory, physical, big), 0);
        assert_eq!(
            resident_pages(&f.memory, physical + big + PAGE_SIZE, big),
            0
        );
        let mut low = vec![0xff; big as usize];
        f.memory.read_raw(physical, &mut low).unwrap();
        let mut high = vec![0xff; big as usize];
        f.memory
            .read_raw(physical + big + PAGE_SIZE, &mut high)
            .unwrap();
        let mut middle = vec![0; PAGE_SIZE as usize];
        f.memory.read_raw(physical + big, &mut middle).unwrap();
        assert!(low.iter().all(|byte| *byte == 0));
        assert!(high.iter().all(|byte| *byte == 0));
        assert!(
            middle.iter().all(|byte| *byte == 0x6b),
            "the shared page lost its contents"
        );
    }

    /// A private mapping of a file larger than one read chunk is streamed
    /// into guest memory chunk by chunk: its bytes are exact, from offset 0
    /// and from a page offset, and the tail past the end of the file is zero
    /// (https://github.com/rrnewton/reverie/issues/1063).
    #[test]
    fn a_private_file_mapping_spanning_several_read_chunks_is_byte_exact() {
        let file_len: usize = 200 * 1024 + 100;
        let contents: Vec<u8> = (0..file_len)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        for offset in [0, PAGE_SIZE] {
            let mut f = Fixture::with_linux_layout();
            std::fs::write(&f.path, &contents).unwrap();
            let fd = f.open(false);
            let length = 256 * 1024u64;
            let user = syscall_result(
                &mut f.memory,
                &mut f.state,
                libc::SYS_mmap,
                [
                    0,
                    length,
                    libc::PROT_READ as u64,
                    libc::MAP_PRIVATE as u64,
                    fd as u64,
                    offset,
                ],
            );
            assert!(user > 0, "offset {offset}: mmap returned {user}");
            let physical = f.memory.user_range_to_guest(user as u64, length).unwrap();
            let mut bytes = vec![0xff; length as usize];
            f.memory.read_raw(physical, &mut bytes).unwrap();
            let expected = &contents[offset as usize..];
            assert_eq!(&bytes[..expected.len()], expected, "offset {offset}");
            assert!(
                bytes[expected.len()..].iter().all(|byte| *byte == 0),
                "offset {offset}: the tail past the end of the file is not zero"
            );
        }
    }

    /// A MAP_FIXED file mapping whose read fails after the first chunk has
    /// replaced the old range must not leave it accessible with changed bytes:
    /// Linux leaves such a range unmapped: once the old contents are gone, a
    /// failed MAP_FIXED mmap completes the munmap and leaves a gap
    /// (mm/vma.c, vms_abort_munmap_vmas), and reverie-kvm's zero_lazily has
    /// destroyed them by then. Host /proc/self/mem is a regular file whose
    /// read of an empty memfd mapping, past its end, fails with EIO, so the
    /// first 64 KiB chunk reads and the second fails after the reservation.
    #[test]
    fn a_fixed_file_mapping_whose_read_fails_mid_stream_leaves_no_partial_range() {
        const CHUNK: usize = 64 * 1024;
        // SAFETY: an anonymous host mapping owned by this test.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(host, libc::MAP_FAILED);
        // SAFETY: the first chunk is mapped and writable.
        unsafe { std::ptr::write_bytes(host as *mut u8, 0x5c, CHUNK) };
        // An empty memfd mapped over the second half: a read of it through
        // /proc/self/mem is past the memfd's end and fails, and the address
        // stays occupied, so no mapping another test thread makes can land
        // there and make the read succeed.
        // SAFETY: the fixed name is nul-terminated; the fd is owned at once.
        let raw = unsafe { libc::memfd_create(c"eio-hole".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(raw >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        let hole = unsafe { std::fs::File::from_raw_fd(raw) };
        // SAFETY: replaces the second half of this test's own mapping.
        let mapped = unsafe {
            libc::mmap(
                (host as usize + CHUNK) as *mut _,
                CHUNK,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_FIXED,
                hole.as_raw_fd(),
                0,
            )
        };
        assert_eq!(mapped as usize, host as usize + CHUNK);
        let mut f = Fixture::with_linux_layout();
        let mem = std::fs::File::open("/proc/self/mem").unwrap();
        assert!(mem.metadata().unwrap().is_file());
        let fd = insert_file_with_flags(&mut f.state, mem, false, None);
        let length = (2 * CHUNK) as u64;
        let user = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [
                0,
                length,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                (-1i64) as u64,
                0,
            ],
        );
        assert!(user > 0, "anonymous mmap returned {user}");
        let user = user as u64;
        f.memory.user().write(user, &vec![0xab; length as usize]).unwrap();
        let physical = f.memory.user_range_to_guest(user, length).unwrap();
        assert_eq!(f.memory.reservation_kind(physical), Some(RegionKind::Mmap));
        let result = syscall_result(
            &mut f.memory,
            &mut f.state,
            libc::SYS_mmap,
            [
                user,
                length,
                libc::PROT_READ as u64,
                (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
                fd as u64,
                host as u64,
            ],
        );
        assert_eq!(result, -(libc::EIO as i64));
        // As munmap leaves it: every page is unreserved, and refuses both a
        // read and a write.
        let mut byte = [0u8; 1];
        for page in (0..length).step_by(PAGE_SIZE as usize) {
            assert_eq!(
                f.memory.reservation_kind(physical + page),
                None,
                "page {page:#x} of the failed mapping is still reserved"
            );
            assert!(
                f.memory.user().read(user + page, &mut byte).is_err(),
                "page {page:#x} of the failed mapping is still readable"
            );
            assert!(
                f.memory.user().write(user + page, &byte).is_err(),
                "page {page:#x} of the failed mapping is still writable"
            );
        }
        // SAFETY: both halves are this test's own mappings.
        unsafe { libc::munmap(host, 2 * CHUNK) };
    }
}
