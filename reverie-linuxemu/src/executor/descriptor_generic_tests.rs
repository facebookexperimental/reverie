// Descriptor operations whose Linux answers do not depend on what the
// descriptor names, exercised through the production syscall dispatcher on
// the random devices and on an ordinary file (and, for mmap, on /dev/null,
// which has no mmap operation either). The guest fixtures in
// tests/descriptor_access.rs and tests/descriptor_identity.rs compare the
// same operations with native runs.

const DESCRIPTOR_DEVICES: [&str; 4] = ["/dev/random", "/dev/urandom", "/dev//random", "/dev/./urandom"];

/// Creates an ordinary file named `name` in `root` holding 8192 known bytes.
fn descriptor_regular_file(root: &TestDir, name: &str) -> String {
    let bytes: Vec<u8> = (0..8192u32).map(|index| (index * 7 + 3) as u8).collect();
    std::fs::write(root.0.join(name), bytes).unwrap();
    name.to_owned()
}

/// A native call's result, or the negative errno of its failure.
fn descriptor_native_outcome(result: i64) -> i64 {
    if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result
    }
}

#[test]
fn descriptor_access_modes_reject_io_before_bad_guest_memory() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    for path in DESCRIPTOR_DEVICES.into_iter().chain([regular.as_str()]) {
        for mode in [libc::O_WRONLY, libc::O_PATH, libc::O_ACCMODE] {
            let fd = open_with_flags(&mut memory, &mut state, path, mode);
            assert!(fd >= 0, "{path} mode {mode:#x}: {fd}");
            for (number, args) in [
                (libc::SYS_read, [fd as u64, u64::MAX, 0, 0, 0, 0]),
                (libc::SYS_readv, [fd as u64, u64::MAX, 1025, 0, 0, 0]),
                (libc::SYS_pread64, [fd as u64, u64::MAX, 0, 0, 0, 0]),
                (libc::SYS_preadv, [fd as u64, u64::MAX, 1025, 0, 0, 0]),
            ] {
                assert_eq!(
                    syscall_result(&mut memory, &mut state, number, args),
                    negative_errno(libc::EBADF),
                    "{path} mode {mode:#x} syscall {number}"
                );
            }
            assert_eq!(close(&mut state, fd as u64), 0);
        }
    }
}

/// Linux's import_iovec takes the vector count as an unsigned int, so the
/// register's upper 32 bits are ignored; the vector-write validation that
/// follows is the same for any writable object.
#[test]
fn descriptor_vector_writes_take_the_low_32_bit_count() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    for path in ["/dev/urandom", "/dev/random", regular.as_str()] {
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_RDWR);
        assert!(fd >= 0, "{path}: {fd}");
        write_guest_iovecs(&mut memory, 0x100, &[(0x300, 7), (0x400, 11)]);
        for number in [libc::SYS_writev, libc::SYS_pwritev, libc::SYS_pwritev2] {
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [fd as u64, 0x100, (1 << 32) + 2, 0, 0, 0]
                ),
                18,
                "{path} syscall {number}"
            );
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [fd as u64, u64::MAX, 1 << 32, 0, 0, u32::MAX as u64]
                ),
                0,
                "{path} syscall {number}"
            );
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [fd as u64, u64::MAX, 1025, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL),
                "{path} syscall {number}"
            );
        }
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, 0x300, 7, 0, 0, 0]
            ),
            7
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pwritev2,
                [fd as u64, 0x100, 1, i64::MAX as u64, 0, 0x8000]
            ),
            negative_errno(libc::EINVAL),
            "{path}"
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_pwritev2,
                [fd as u64, 0x100, 1, 0, 0, 0x8000]
            ),
            negative_errno(libc::EOPNOTSUPP),
            "{path}"
        );
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

/// `count` bytes written natively from a buffer whose last
/// `count - readable` bytes are on a PROT_NONE page, with `number`
/// (write, pwrite64 at offset 101, or writev of three vectors with the
/// middle one unreadable), to a fresh descriptor for `path`.
fn descriptor_native_prefix_write(path: &std::path::Path, number: libc::c_long, readable: usize, count: usize) -> i64 {
    let page = PAGE_SIZE as usize;
    // SAFETY: an anonymous private mapping owned until the munmap below.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            3 * page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    let base = mapping.cast::<u8>();
    // SAFETY: the first two pages are writable and the third is ours.
    unsafe {
        std::ptr::write_bytes(base, 0x61, 2 * page);
        assert_eq!(libc::mprotect(base.add(2 * page).cast(), page, libc::PROT_NONE), 0);
    }
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is NUL-terminated; the descriptor is closed below.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    assert!(fd >= 0);
    // SAFETY: every buffer lies in the mapping above; reads past its readable
    // part fault in the kernel and are reported, never touched here.
    let result = unsafe {
        match number {
            libc::SYS_write => libc::write(fd, base.add(2 * page - readable).cast(), count) as i64,
            libc::SYS_pwrite64 => {
                libc::pwrite(fd, base.add(2 * page - readable).cast(), count, 101) as i64
            }
            _ => {
                let vectors = [
                    libc::iovec { iov_base: base.add(0x400).cast(), iov_len: 7 },
                    libc::iovec { iov_base: base.add(2 * page).cast(), iov_len: 8 },
                    libc::iovec { iov_base: base.add(0x500).cast(), iov_len: 9 },
                ];
                libc::writev(fd, vectors.as_ptr(), 3) as i64
            }
        }
    };
    let result = descriptor_native_outcome(result);
    // SAFETY: fd and the mapping are owned here.
    unsafe {
        libc::close(fd);
        libc::munmap(mapping, 3 * page);
    }
    result
}

/// Write admission: the access mode (access mode 3 grants no write), the
/// buffer's address range for the whole count (even zero), and a buffer that
/// becomes unreadable part way, whose readable prefix reaches the host kernel
/// with the same shape, so the object's own answer (a short count for a
/// random device, its filesystem's answer for an ordinary file) is returned.
/// pwrite64 leaves the shared offset where it was.
#[test]
fn descriptor_write_admission_and_partially_readable_buffers() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 3 * PAGE_SIZE as usize).unwrap();
    memory
        .map_user_permissions(0, 2 * PAGE_SIZE, true, true)
        .unwrap();
    memory
        .map_user_permissions(2 * PAGE_SIZE, PAGE_SIZE, false, false)
        .unwrap();
    memory.enable_user_access();
    memory.write(0, &[0x61; 2 * PAGE_SIZE as usize]).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    descriptor_regular_file(&root, "native-regular");
    for (path, native_path) in [
        ("/dev/random", "/dev/random".to_owned()),
        ("/dev/urandom", "/dev/urandom".to_owned()),
        (regular.as_str(), root.0.join("native-regular").to_str().unwrap().to_owned()),
    ] {
        let native_path = std::path::Path::new(&native_path);
        let device = path.starts_with("/dev/");
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_RDWR);
        assert!(fd >= 0, "{path}: {fd}");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_write,
                [fd as u64, u64::MAX, 0, 0, 0, 0]
            ),
            negative_errno(libc::EFAULT),
            "{path}: a buffer beyond the user address range"
        );
        let offset = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_lseek,
            [fd as u64, 0, libc::SEEK_CUR as u64, 0, 0, 0],
        );
        for number in [libc::SYS_write, libc::SYS_pwrite64] {
            let partial = syscall_result(
                &mut memory,
                &mut state,
                number,
                [fd as u64, 2 * PAGE_SIZE - 7, 15, 101, 0, 0],
            );
            assert_eq!(
                partial,
                descriptor_native_prefix_write(native_path, number, 7, 15),
                "{path} syscall {number}: 7 readable bytes of 15"
            );
            if device {
                assert_eq!(partial, 7, "{path} syscall {number}");
            }
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    number,
                    [fd as u64, 2 * PAGE_SIZE, 1, 101, 0, 0]
                ),
                negative_errno(libc::EFAULT),
                "{path} syscall {number}: no readable byte"
            );
        }
        if !device {
            // Only the scalar write moved the offset, by what it wrote.
            let written = descriptor_native_prefix_write(native_path, libc::SYS_write, 7, 15).max(0);
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_lseek,
                    [fd as u64, 0, libc::SEEK_CUR as u64, 0, 0, 0],
                ),
                offset + written,
                "{path}"
            );
        }
        write_guest_iovecs(
            &mut memory,
            0x100,
            &[(0x400, 7), (2 * PAGE_SIZE, 8), (0x500, 9)],
        );
        let vector = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_writev,
            [fd as u64, 0x100, 3, 0, 0, 0],
        );
        assert_eq!(
            vector,
            descriptor_native_prefix_write(native_path, libc::SYS_writev, 0, 0),
            "{path}"
        );
        if device {
            assert_eq!(vector, 7, "{path}");
        }
        assert_eq!(close(&mut state, fd as u64), 0);
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_ACCMODE);
        assert!(fd >= 0, "{path}: {fd}");
        for number in [libc::SYS_write, libc::SYS_pwrite64] {
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [fd as u64, 0x400, 0, 0, 0, 0]),
                negative_errno(libc::EBADF),
                "{path} syscall {number}: access mode 3"
            );
        }
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

/// ioctl's fdget refuses an O_PATH descriptor, so every command fails with
/// EBADF before FIOCLEX or FIONCLEX could change the guest's close-on-exec
/// flag; Detcore adopts a successful change, so the refusal must come first.
#[test]
fn descriptor_o_path_ioctls_refuse_before_any_flag_change() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    let native_regular = root.0.join("regular");
    for (path, native_path) in [
        ("/dev/urandom", std::path::PathBuf::from("/dev/urandom")),
        ("/dev/random", std::path::PathBuf::from("/dev/random")),
        (regular.as_str(), native_regular),
        ("/", std::path::PathBuf::from("/")),
    ] {
        for opened in [libc::O_PATH, libc::O_PATH | libc::O_CLOEXEC] {
            let fd = open_with_flags(&mut memory, &mut state, path, opened);
            assert!(fd >= 0, "{path}: {fd}");
            let cloexec = state.cloexec_fds.contains(&(fd as i32));
            let native_path = CString::new(native_path.as_os_str().as_bytes()).unwrap();
            // SAFETY: path is NUL-terminated; the descriptor is closed below.
            let native = unsafe { libc::open(native_path.as_ptr(), opened | libc::O_CLOEXEC) };
            assert!(native >= 0);
            for request in [libc::FIOCLEX, libc::FIONCLEX, libc::TCGETS, 0x7fff] {
                // SAFETY: an O_PATH descriptor is refused before the argument
                // is read; it names a live local in any case.
                let mut scratch = [0_u8; 64];
                let expected = descriptor_native_outcome(unsafe {
                    libc::ioctl(native, request, scratch.as_mut_ptr())
                } as i64);
                assert_eq!(expected, negative_errno(libc::EBADF));
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_ioctl,
                        [fd as u64, request, 0x200, 0, 0, 0]
                    ),
                    expected,
                    "{path} request {request:#x}"
                );
                assert_eq!(state.cloexec_fds.contains(&(fd as i32)), cloexec, "{path}");
            }
            // SAFETY: native is owned here.
            unsafe { libc::close(native) };
            assert_eq!(close(&mut state, fd as u64), 0);
        }
    }
}

/// Every valid flock operation takes the common refusal (ENOSYS), and
/// malformed operations and LOCK_MAND get the kernel's own answers, for any
/// descriptor, O_PATH ones and dup aliases included.
#[test]
fn descriptor_flock_takes_the_common_refusal_and_validation() {
    const LOCK_MAND: libc::c_int = 32;
    let root = TestDir::new();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    for path in ["/dev/urandom", regular.as_str()] {
        for mode in [libc::O_RDONLY, libc::O_WRONLY, libc::O_PATH] {
            let mut state = test_state(&root.0);
            let fd = open_with_flags(&mut memory, &mut state, path, mode);
            assert!(fd >= 0, "{path} mode {mode:#x}: {fd}");
            let alias = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup,
                [fd as u64, 0, 0, 0, 0, 0],
            );
            assert!(alias >= 0);
            for guest_fd in [fd, alias] {
                for operation in [
                    libc::LOCK_SH,
                    libc::LOCK_EX,
                    libc::LOCK_UN,
                    libc::LOCK_SH | libc::LOCK_NB,
                    libc::LOCK_EX | libc::LOCK_NB,
                    libc::LOCK_UN | libc::LOCK_NB,
                ] {
                    assert_eq!(
                        syscall_result(
                            &mut memory,
                            &mut state,
                            libc::SYS_flock,
                            [guest_fd as u64, operation as u64, 0, 0, 0, 0],
                        ),
                        negative_errno(libc::ENOSYS),
                        "{path} mode {mode:#x} fd {guest_fd} operation {operation:#x}"
                    );
                }
                for operation in [0, libc::LOCK_SH | libc::LOCK_EX, LOCK_MAND, LOCK_MAND | libc::LOCK_EX] {
                    // SAFETY: fd -1 names no description.
                    let expected = zero_or_errno(unsafe { libc::flock(-1, operation) });
                    assert_eq!(
                        syscall_result(
                            &mut memory,
                            &mut state,
                            libc::SYS_flock,
                            [guest_fd as u64, operation as u64, 0, 0, 0, 0],
                        ),
                        expected,
                        "{path} mode {mode:#x} fd {guest_fd} operation {operation:#x}"
                    );
                }
            }
        }
    }
}

/// Runs `cases` (address, length, flags, offset, Linux's errno for a readable
/// descriptor of an object without an mmap operation) as mmap of
/// /dev/random, /dev/urandom and /dev/null opened in every access mode, and
/// checks that each refusal leaves guest memory, the mmap cursor and the
/// descriptor's status flags unchanged. The errno is adjusted as Linux
/// adjusts it: an unaligned offset is EINVAL before anything else, an O_PATH
/// descriptor is EBADF, and the object's ENODEV becomes EACCES for a
/// descriptor without read access.
fn descriptor_mmap_cases(cases: &[(u64, u64, u64, u64, i32)]) {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, (BOOT_RESERVED_END + 4 * PAGE_SIZE) as usize).unwrap();
    state.mmap_base = BOOT_RESERVED_END;
    state.mmap_next = BOOT_RESERVED_END;
    state.mmap_limit = BOOT_RESERVED_END + 4 * PAGE_SIZE;
    memory
        .map_user_permissions(BOOT_RESERVED_END, PAGE_SIZE, true, true)
        .unwrap();
    memory
        .write(BOOT_RESERVED_END, &[0xa5; PAGE_SIZE as usize])
        .unwrap();
    for path in ["/dev/random", "/dev/urandom", "/dev/null"] {
        for mode in [
            libc::O_RDONLY,
            libc::O_WRONLY,
            libc::O_RDWR,
            3,
            libc::O_PATH,
        ] {
            let fd = open_with_flags(&mut memory, &mut state, path, mode);
            assert!(fd >= 0);
            let flags_before = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
            );
            for &(address, length, flags, offset, error) in cases {
                let error = if !offset.is_multiple_of(PAGE_SIZE) {
                    libc::EINVAL
                } else if mode == libc::O_PATH {
                    libc::EBADF
                } else if error == libc::ENODEV && (mode == libc::O_WRONLY || mode == 3) {
                    libc::EACCES
                } else {
                    error
                };
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_mmap,
                        [
                            address,
                            length,
                            libc::PROT_READ as u64,
                            flags,
                            fd as u64,
                            offset
                        ]
                    ),
                    negative_errno(error),
                    "{path} mode={mode:#x} address={address:#x} length={length:#x} flags={flags:#x} offset={offset:#x}"
                );
                assert_eq!(state.mmap_next, BOOT_RESERVED_END);
                let mut page = vec![0; PAGE_SIZE as usize];
                memory.read(BOOT_RESERVED_END, &mut page).unwrap();
                assert_eq!(page, [0xa5; PAGE_SIZE as usize]);
                assert!(memory.user_range_is_mapped(BOOT_RESERVED_END, PAGE_SIZE));
                for page in 1..4 {
                    assert!(
                        !memory
                            .user_range_is_mapped(BOOT_RESERVED_END + page * PAGE_SIZE, PAGE_SIZE)
                    );
                }
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_fcntl,
                        [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
                    ),
                    flags_before
                );
            }
            assert_eq!(close(&mut state, fd as u64), 0);
        }
    }
}

fn descriptor_low_word_mmap_cases(cases: &[(u64, u64, i32, u64, i32)]) {
    // Preserve the low-word cases' raw sign extension, as full-width operands.
    let cases: Vec<_> = cases
        .iter()
        .map(|&(a, n, f, o, e)| (a, n, f as u64, o, e))
        .collect();
    descriptor_mmap_cases(&cases);
}

#[test]
fn descriptor_mmap_refusals_keep_memory_and_cursor_unchanged() {
    descriptor_low_word_mmap_cases(&[
        (BOOT_RESERVED_END, 0, libc::MAP_PRIVATE, 0, libc::EINVAL),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            0,
            libc::ENODEV,
        ),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED_NOREPLACE,
            0,
            libc::EEXIST,
        ),
    ]);
}

#[test]
fn descriptor_mmap_hugetlb_precedes_mapping_errors() {
    let flags = libc::MAP_PRIVATE | libc::MAP_HUGETLB;
    descriptor_low_word_mmap_cases(&[
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            flags | libc::MAP_FIXED,
            0,
            libc::EINVAL,
        ),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            flags | libc::MAP_FIXED_NOREPLACE,
            0,
            libc::EINVAL,
        ),
        (
            u64::MAX - PAGE_SIZE + 1,
            PAGE_SIZE,
            flags | libc::MAP_FIXED,
            0,
            libc::EINVAL,
        ),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            flags | libc::MAP_FIXED,
            u64::MAX - PAGE_SIZE + 1,
            libc::EINVAL,
        ),
        (
            BOOT_RESERVED_END,
            u64::MAX,
            flags | libc::MAP_FIXED,
            0,
            libc::EINVAL,
        ),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            flags | libc::MAP_FIXED,
            1,
            libc::EINVAL,
        ),
    ]);
}

#[test]
fn descriptor_mmap_invalid_type_follows_address_and_overflow() {
    descriptor_low_word_mmap_cases(&[
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_TYPE | libc::MAP_FIXED_NOREPLACE,
            0,
            libc::EEXIST,
        ),
        (
            u64::MAX - PAGE_SIZE + 1,
            PAGE_SIZE,
            libc::MAP_TYPE | libc::MAP_FIXED,
            0,
            libc::ENOMEM,
        ),
        (
            BOOT_RESERVED_END + PAGE_SIZE,
            PAGE_SIZE,
            libc::MAP_TYPE | libc::MAP_FIXED,
            u64::MAX - PAGE_SIZE + 1,
            libc::EOVERFLOW,
        ),
        (
            BOOT_RESERVED_END + PAGE_SIZE,
            PAGE_SIZE,
            libc::MAP_TYPE | libc::MAP_FIXED,
            0,
            libc::EINVAL,
        ),
        // Mapping type 0 (neither type bit): placement refusals still come
        // first, and the type is refused only at a free placement.
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_FIXED_NOREPLACE,
            0,
            libc::EEXIST,
        ),
        (u64::MAX - PAGE_SIZE + 1, PAGE_SIZE, libc::MAP_FIXED, 0, libc::ENOMEM),
        (
            BOOT_RESERVED_END + PAGE_SIZE,
            PAGE_SIZE,
            libc::MAP_FIXED,
            0,
            libc::EINVAL,
        ),
    ]);
}

/// A high offset that does not overflow with the length is the object's to
/// judge, after placement: a placement refusal wins, and at a free placement a
/// device without an mmap operation answers ENODEV (an ordinary file would
/// answer EOVERFLOW from its extent limit, which a device does not have).
#[test]
fn descriptor_mmap_high_offset_follows_placement() {
    let high = 1_u64 << 63;
    descriptor_low_word_mmap_cases(&[
        (
            BOOT_RESERVED_END + PAGE_SIZE,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            high,
            libc::ENODEV,
        ),
        (
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED_NOREPLACE,
            high,
            libc::EEXIST,
        ),
        (
            u64::MAX - PAGE_SIZE + 1,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            high,
            libc::ENOMEM,
        ),
        (
            0x1001,
            PAGE_SIZE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            high,
            libc::EINVAL,
        ),
    ]);
}

#[test]
fn descriptor_mmap_legacy_mask_matches_x86_linux() {
    let mut cases = Vec::new();
    // v6.18 x86 LEGACY_MAP_MASK includes these exact bits, even without
    // MAP_HUGETLB. This is a bitmask, not a list of permitted hugepage sizes.
    for legacy in [libc::MAP_GROWSDOWN, 0x04000000, 0x80, 21 << 26, 30 << 26] {
        cases.push((
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_SHARED_VALIDATE | libc::MAP_FIXED | legacy,
            0,
            libc::ENODEV,
        ));
    }
    for extension in [libc::MAP_SYNC, i32::MIN, 0x02000000] {
        cases.push((
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::MAP_SHARED_VALIDATE | libc::MAP_FIXED | extension,
            0,
            libc::EOPNOTSUPP,
        ));
    }
    cases.push((
        BOOT_RESERVED_END + PAGE_SIZE,
        PAGE_SIZE,
        libc::MAP_SHARED_VALIDATE | libc::MAP_FIXED_NOREPLACE,
        0,
        libc::EOPNOTSUPP,
    ));
    cases.push((
        BOOT_RESERVED_END,
        PAGE_SIZE,
        libc::MAP_SHARED_VALIDATE | libc::MAP_FIXED_NOREPLACE,
        0,
        libc::EEXIST,
    ));
    descriptor_low_word_mmap_cases(&cases);
}

#[test]
fn descriptor_mmap_high_word_flags_keep_linux_error_order() {
    let mut cases = Vec::new();
    let fixed = libc::MAP_FIXED as u64;
    let validate = libc::MAP_SHARED_VALIDATE as u64;
    // Raw x86-64 SYS_mmap takes unsigned long flags. Ordinary SHARED/PRIVATE
    // ignore unknown bits; only SHARED_VALIDATE rejects them.
    for extra in [0, 1_u64 << 32, 1_u64 << 63] {
        for kind in [
            libc::MAP_SHARED,
            libc::MAP_PRIVATE,
            libc::MAP_SHARED_VALIDATE,
        ] {
            cases.push((
                BOOT_RESERVED_END,
                PAGE_SIZE,
                kind as u64 | fixed | extra,
                0,
                if kind == libc::MAP_SHARED_VALIDATE && extra != 0 {
                    libc::EOPNOTSUPP
                } else {
                    libc::ENODEV
                },
            ));
        }
        if extra == 0 {
            continue;
        }
        let flags = validate | extra;
        cases.extend([
            (BOOT_RESERVED_END, PAGE_SIZE, flags | fixed, 1, libc::EINVAL),
            (
                BOOT_RESERVED_END,
                PAGE_SIZE,
                flags | fixed | libc::MAP_HUGETLB as u64,
                0,
                libc::EINVAL,
            ),
            (BOOT_RESERVED_END, 0, flags | fixed, 0, libc::EINVAL),
            (BOOT_RESERVED_END, u64::MAX, flags | fixed, 0, libc::ENOMEM),
            (
                u64::MAX - PAGE_SIZE + 1,
                PAGE_SIZE,
                flags | fixed,
                0,
                libc::ENOMEM,
            ),
            (
                BOOT_RESERVED_END,
                PAGE_SIZE,
                flags | libc::MAP_FIXED_NOREPLACE as u64,
                0,
                libc::EEXIST,
            ),
            (
                BOOT_RESERVED_END,
                PAGE_SIZE,
                flags | fixed,
                u64::MAX - PAGE_SIZE + 1,
                libc::EOVERFLOW,
            ),
            (
                BOOT_RESERVED_END,
                PAGE_SIZE,
                libc::MAP_TYPE as u64 | fixed | extra,
                0,
                libc::EINVAL,
            ),
        ]);
    }
    descriptor_mmap_cases(&cases);
}

#[test]
fn descriptor_mmap_fixed_range_errors_precede_alignment() {
    descriptor_mmap_cases(&[
        // An upper address below Linux's encoded-error interval and a length
        // beyond both 4-level and 5-level x86 user address spaces.
        (
            u64::MAX - 2 * PAGE_SIZE + 2,
            PAGE_SIZE,
            (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
            0,
            libc::ENOMEM,
        ),
        (
            0x1001,
            1_u64 << 63,
            (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
            0,
            libc::ENOMEM,
        ),
        (
            BOOT_RESERVED_END + 1,
            PAGE_SIZE,
            (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
            0,
            libc::EINVAL,
        ),
        // A Linux-valid high address outside the finite guest backing: that
        // backing limit, like the lower reservation, follows alignment.
        (
            0x7f0000001001,
            PAGE_SIZE,
            (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
            0,
            libc::EINVAL,
        ),
        (
            0x1001,
            PAGE_SIZE,
            (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
            0,
            libc::EINVAL,
        ),
    ]);
}

/// A zero-byte read of an object other than a regular file or directory: a
/// descriptor without read access fails with EBADF before anything could
/// wait, whatever the device; a readable random device returns zero (the
/// host's pool is initialized long before a test runs).
#[test]
fn descriptor_zero_byte_reads_follow_access_before_blocking_admission() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    for path in ["/dev/full", "/dev/urandom", "/dev/random"] {
        for mode in [libc::O_WRONLY, libc::O_ACCMODE] {
            let fd = open_with_flags(&mut memory, &mut state, path, mode);
            assert!(fd >= 0, "{path} mode {mode:#x}: {fd}");
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_read,
                    [fd as u64, 0x200, 0, 0, 0, 0]
                ),
                negative_errno(libc::EBADF),
                "{path} mode {mode:#x}"
            );
            assert_eq!(close(&mut state, fd as u64), 0);
        }
    }
    for path in ["/dev/urandom", "/dev/random"] {
        let fd = open_readonly(&mut memory, &mut state, path);
        assert!(fd >= 0, "{path}: {fd}");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_read,
                [fd as u64, 0x200, 0, 0, 0, 0]
            ),
            0,
            "{path}"
        );
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

/// fcntl lets an O_PATH descriptor run only its descriptor-flag, status-flag
/// and duplication commands: a lock command fails with EBADF before its flock
/// structure is copied, so even an unreadable structure gives EBADF; a
/// descriptor open for I/O copies the structure first (EFAULT).
#[test]
fn descriptor_o_path_lock_commands_refuse_before_copying_the_lock() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    let native_regular = root.0.join("regular");
    for (path, native_path) in [
        ("/dev/urandom", std::path::PathBuf::from("/dev/urandom")),
        (regular.as_str(), native_regular),
    ] {
        for (opened, expected) in [(libc::O_PATH, libc::EBADF), (libc::O_RDWR, libc::EFAULT)] {
            let fd = open_with_flags(&mut memory, &mut state, path, opened);
            assert!(fd >= 0, "{path}: {fd}");
            let native_name = CString::new(native_path.as_os_str().as_bytes()).unwrap();
            // SAFETY: the name is NUL-terminated; the descriptor is closed below.
            let native = unsafe { libc::open(native_name.as_ptr(), opened | libc::O_CLOEXEC) };
            assert!(native >= 0);
            for command in [
                libc::F_SETLK,
                libc::F_SETLKW,
                libc::F_OFD_SETLK,
                libc::F_GETLK,
                libc::F_OFD_GETLK,
            ] {
                // SAFETY: an address the kernel refuses to read (it fails with
                // EFAULT or, for O_PATH, before reading it).
                let native_result = descriptor_native_outcome(unsafe {
                    libc::fcntl(native, command, usize::MAX as *mut libc::flock)
                } as i64);
                assert_eq!(native_result, negative_errno(expected), "{path} {command}");
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_fcntl,
                        [fd as u64, command as u64, u64::MAX, 0, 0, 0]
                    ),
                    native_result,
                    "{path} opened={opened:#x} command={command}"
                );
            }
            // SAFETY: native is owned here.
            unsafe { libc::close(native) };
            assert_eq!(close(&mut state, fd as u64), 0);
        }
    }
}

/// mmap ignores protection bits other than read, write and execute (PROT_SEM
/// and unknown bits included): a random device still answers ENODEV, an
/// ordinary file maps, each as natively.
#[test]
fn descriptor_mmap_ignores_unknown_protection_bits() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, (BOOT_RESERVED_END + 8 * PAGE_SIZE) as usize).unwrap();
    state.mmap_base = BOOT_RESERVED_END + PAGE_SIZE;
    state.mmap_next = state.mmap_base;
    state.mmap_limit = BOOT_RESERVED_END + 8 * PAGE_SIZE;
    let regular = descriptor_regular_file(&root, "regular");
    for (path, native_path) in [
        ("/dev/urandom", std::path::PathBuf::from("/dev/urandom")),
        (regular.as_str(), root.0.join("regular")),
    ] {
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_RDONLY);
        assert!(fd >= 0, "{path}: {fd}");
        let native_name = CString::new(native_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the name is NUL-terminated; the descriptor is closed below.
        let native = unsafe { libc::open(native_name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(native >= 0);
        for prot in [
            libc::PROT_READ | 0x8,
            libc::PROT_READ | 0x10,
            libc::PROT_READ | libc::PROT_GROWSDOWN,
            libc::PROT_READ | i32::MIN,
        ] {
            // SAFETY: a kernel-placed mapping of a live descriptor, unmapped below.
            let mapped = unsafe {
                libc::mmap(std::ptr::null_mut(), PAGE_SIZE as usize, prot, libc::MAP_PRIVATE, native, 0)
            };
            let expected = if mapped == libc::MAP_FAILED {
                io_error(std::io::Error::last_os_error())
            } else {
                // SAFETY: the mapping above is one page and is not used again.
                assert_eq!(unsafe { libc::munmap(mapped, PAGE_SIZE as usize) }, 0);
                0
            };
            let result = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mmap,
                [0, PAGE_SIZE, prot as u32 as u64, libc::MAP_PRIVATE as u64, fd as u64, 0],
            );
            if expected < 0 {
                assert_eq!(result, expected, "{path} prot={prot:#x}");
            } else {
                assert!(result > 0, "{path} prot={prot:#x}: {result}");
                assert_eq!(
                    syscall_result(&mut memory, &mut state, libc::SYS_munmap, [result as u64, PAGE_SIZE, 0, 0, 0, 0]),
                    0
                );
            }
        }
        // SAFETY: native is owned here.
        unsafe { libc::close(native) };
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

/// pwrite64 refuses an object without positioned writes (ESPIPE) before it
/// checks the access mode and the buffer, as natively: a pipe's write end and
/// a socket, with a readable buffer and an absurd count, and with an
/// unreadable buffer and a zero count.
#[test]
fn descriptor_pwrite64_seekability_precedes_buffer_checks() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        syscall_result(&mut memory, &mut state, libc::SYS_pipe2, [0x300, 0, 0, 0, 0, 0]),
        0
    );
    let mut pipe = [0_u8; 8];
    memory.read(0x300, &mut pipe).unwrap();
    let pipe_write = i32::from_ne_bytes(pipe[4..8].try_into().unwrap());
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_socketpair,
            [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0x310, 0, 0]
        ),
        0
    );
    let mut sockets = [0_u8; 8];
    memory.read(0x310, &mut sockets).unwrap();
    let socket = i32::from_ne_bytes(sockets[0..4].try_into().unwrap());
    let mut native_pipe = [0; 2];
    let mut native_sockets = [0; 2];
    // SAFETY: both arrays have room for two descriptors, closed below.
    unsafe {
        assert_eq!(libc::pipe2(native_pipe.as_mut_ptr(), libc::O_CLOEXEC), 0);
        assert_eq!(
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, native_sockets.as_mut_ptr()),
            0
        );
    }
    let buffer = [0x5a_u8; 64];
    for (label, guest, native) in [("pipe", pipe_write, native_pipe[1]), ("socket", socket, native_sockets[0])] {
        for (address, native_address, count) in [
            (0x200_u64, buffer.as_ptr() as usize, u64::MAX),
            (u64::MAX, usize::MAX, 0),
        ] {
            // SAFETY: the kernel refuses the call before reading the buffer.
            let expected = descriptor_native_outcome(unsafe {
                libc::syscall(libc::SYS_pwrite64, native, native_address, count, 0_i64)
            });
            assert_eq!(expected, negative_errno(libc::ESPIPE), "{label}");
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_pwrite64,
                    [guest as u64, address, count, 0, 0, 0]
                ),
                expected,
                "{label} address={address:#x} count={count:#x}"
            );
        }
    }
    // SAFETY: the native descriptors are owned here.
    unsafe {
        for fd in native_pipe.into_iter().chain(native_sockets) {
            libc::close(fd);
        }
    }
}

/// An O_PATH descriptor is refused (EBADF) by the filtered descriptor lookup
/// of fallocate, readahead and sync_file_range before their ranges are
/// checked, and by the xattr calls after they import their name (and, for
/// fsetxattr, validate their flags and import their value) but before the
/// attribute's namespace is resolved, as natively.
#[test]
fn descriptor_o_path_admission_precedes_range_and_namespace_checks() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let regular = descriptor_regular_file(&root, "regular");
    let names: [(&str, &[u8]); 4] = [
        ("trusted", b"trusted.x\0"),
        ("user", b"user.x\0"),
        ("security", b"security.x\0"),
        ("acl", b"system.posix_acl_access\0"),
    ];
    for (path, native_path) in [
        ("/dev/urandom", std::path::PathBuf::from("/dev/urandom")),
        (regular.as_str(), root.0.join("regular")),
    ] {
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_PATH);
        assert!(fd >= 0, "{path}: {fd}");
        let native_name = CString::new(native_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the name is NUL-terminated; the descriptor is closed below.
        let native = unsafe { libc::open(native_name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(native >= 0);
        let mut cases: Vec<(String, libc::c_long, [u64; 6], [usize; 6])> = vec![
            (
                "fallocate".into(),
                libc::SYS_fallocate,
                [fd as u64, 0, u64::MAX, 1, 0, 0],
                [native as usize, 0, usize::MAX, 1, 0, 0],
            ),
            (
                "readahead".into(),
                libc::SYS_readahead,
                [fd as u64, u64::MAX, 0, 0, 0, 0],
                [native as usize, usize::MAX, 0, 0, 0, 0],
            ),
            (
                "sync_file_range".into(),
                libc::SYS_sync_file_range,
                [fd as u64, u64::MAX, 0, 0, 0, 0],
                [native as usize, usize::MAX, 0, 0, 0, 0],
            ),
        ];
        let value = [0x76_u8; 1];
        for (label, name) in names {
            memory.write(0x100, name).unwrap();
            let native_name = name.as_ptr() as usize;
            cases.push((
                format!("fgetxattr {label}"),
                libc::SYS_fgetxattr,
                [fd as u64, 0x100, 0, 0, 0, 0],
                [native as usize, native_name, 0, 0, 0, 0],
            ));
            cases.push((
                format!("fremovexattr {label}"),
                libc::SYS_fremovexattr,
                [fd as u64, 0x100, 0, 0, 0, 0],
                [native as usize, native_name, 0, 0, 0, 0],
            ));
            cases.push((
                format!("fsetxattr {label}"),
                libc::SYS_fsetxattr,
                [fd as u64, 0x100, 0x180, 1, 0, 0],
                [native as usize, native_name, value.as_ptr() as usize, 1, 0, 0],
            ));
            cases.push((
                format!("fsetxattr {label} bad flags"),
                libc::SYS_fsetxattr,
                [fd as u64, 0x100, 0x180, 1, 0x10, 0],
                [native as usize, native_name, value.as_ptr() as usize, 1, 0x10, 0],
            ));
            cases.push((
                format!("fsetxattr {label} bad value"),
                libc::SYS_fsetxattr,
                [fd as u64, 0x100, u64::MAX, 1, 0, 0],
                [native as usize, native_name, usize::MAX, 1, 0, 0],
            ));
            // Every case is run here, after its name is in guest memory.
            for (label, number, guest, native_args) in cases.drain(..) {
                // SAFETY: every pointer is a live local or an address the
                // kernel refuses to read.
                let expected = descriptor_native_outcome(unsafe {
                    libc::syscall(
                        number,
                        native_args[0],
                        native_args[1],
                        native_args[2],
                        native_args[3],
                        native_args[4],
                    )
                });
                assert_eq!(
                    syscall_result(&mut memory, &mut state, number, guest),
                    expected,
                    "{path} {label}"
                );
            }
        }
        // SAFETY: a fault reading the name is reported before the lookup.
        let expected = descriptor_native_outcome(unsafe {
            libc::syscall(libc::SYS_fgetxattr, native, usize::MAX, 0_usize, 0_usize)
        });
        assert_eq!(expected, negative_errno(libc::EFAULT));
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_fgetxattr, [fd as u64, u64::MAX, 0, 0, 0, 0]),
            expected,
            "{path} fgetxattr bad name"
        );
        // SAFETY: native is owned here.
        unsafe { libc::close(native) };
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

/// Every object-probe refusal is the guest's answer for its original request,
/// ENOMEM included, and the copy never runs without a successful probe: with
/// the probe's answer forced to ENOMEM, a MAP_FIXED mapping of /dev/zero
/// (which the host otherwise maps) fails with ENOMEM, privately and shared,
/// leaving the bytes it would have replaced, the mmap cursor and the
/// descriptor's status and position unchanged. The same request without the
/// injection maps, as a control.
#[test]
fn descriptor_mmap_object_probe_errors_are_final() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, (BOOT_RESERVED_END + 4 * PAGE_SIZE) as usize).unwrap();
    state.mmap_base = BOOT_RESERVED_END;
    state.mmap_next = BOOT_RESERVED_END;
    state.mmap_limit = BOOT_RESERVED_END + 4 * PAGE_SIZE;
    memory
        .map_user_permissions(BOOT_RESERVED_END, PAGE_SIZE, true, true)
        .unwrap();
    memory
        .write(BOOT_RESERVED_END, &[0xa5; PAGE_SIZE as usize])
        .unwrap();
    let fd = open_with_flags(&mut memory, &mut state, "/dev/zero", libc::O_RDWR);
    assert!(fd >= 0);
    let status = |memory: &mut GuestMemory, state: &mut LoadedStaticElf| {
        (
            syscall_result(memory, state, libc::SYS_fcntl, [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0]),
            syscall_result(memory, state, libc::SYS_lseek, [fd as u64, 0, libc::SEEK_CUR as u64, 0, 0, 0]),
        )
    };
    let before = status(&mut memory, &mut state);
    for kind in [libc::MAP_PRIVATE, libc::MAP_SHARED] {
        let args = [
            BOOT_RESERVED_END,
            PAGE_SIZE,
            libc::PROT_READ as u64,
            (kind | libc::MAP_FIXED) as u64,
            fd as u64,
            0,
        ];
        let guard = inject_host_mmap_probe_answer(negative_errno(libc::ENOMEM));
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_mmap, args),
            negative_errno(libc::ENOMEM),
            "kind={kind:#x}"
        );
        drop(guard);
        let mut page = vec![0; PAGE_SIZE as usize];
        memory.read(BOOT_RESERVED_END, &mut page).unwrap();
        assert_eq!(page, [0xa5; PAGE_SIZE as usize], "kind={kind:#x}");
        assert_eq!(state.mmap_next, BOOT_RESERVED_END);
        assert_eq!(status(&mut memory, &mut state), before);
    }
    // Control: the host maps /dev/zero privately, and the copy runs.
    assert_eq!(
        syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_mmap,
            [
                BOOT_RESERVED_END,
                PAGE_SIZE,
                libc::PROT_READ as u64,
                (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
                fd as u64,
                0,
            ]
        ),
        BOOT_RESERVED_END as i64
    );
    let mut page = vec![0xff; PAGE_SIZE as usize];
    memory.read(BOOT_RESERVED_END, &mut page).unwrap();
    assert_eq!(page, [0; PAGE_SIZE as usize]);
}

/// x86-64's sys_mmap refuses an unaligned offset before anything else, for an
/// anonymous mapping too, and mmap ignores PROT_SEM: an aligned anonymous
/// PROT_READ|PROT_SEM mapping maps, an offset of 1 is EINVAL and leaves the
/// fixed range's bytes, privately and shared, as natively.
#[test]
fn descriptor_anonymous_mmap_checks_the_offset_first() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, (BOOT_RESERVED_END + 4 * PAGE_SIZE) as usize).unwrap();
    state.mmap_base = BOOT_RESERVED_END + PAGE_SIZE;
    state.mmap_next = state.mmap_base;
    state.mmap_limit = BOOT_RESERVED_END + 4 * PAGE_SIZE;
    memory
        .map_user_permissions(BOOT_RESERVED_END, PAGE_SIZE, true, true)
        .unwrap();
    memory
        .write(BOOT_RESERVED_END, &[0xa5; PAGE_SIZE as usize])
        .unwrap();
    let prot = (libc::PROT_READ | 0x8) as u64;
    for kind in [libc::MAP_PRIVATE, libc::MAP_SHARED] {
        let flags = kind | libc::MAP_ANONYMOUS;
        // SAFETY: kernel-placed anonymous mappings, unmapped below.
        let (native_unaligned, native_aligned) = unsafe {
            let unaligned = libc::syscall(libc::SYS_mmap, 0_usize, PAGE_SIZE, prot, flags, -1_i64, 1_u64);
            let unaligned = descriptor_native_outcome(unaligned);
            let aligned = libc::syscall(libc::SYS_mmap, 0_usize, PAGE_SIZE, prot, flags, -1_i64, 0_u64);
            assert!(aligned > 0);
            libc::munmap(aligned as *mut libc::c_void, PAGE_SIZE as usize);
            (unaligned, aligned)
        };
        assert_eq!(native_unaligned, negative_errno(libc::EINVAL));
        assert!(native_aligned > 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_mmap,
                [BOOT_RESERVED_END, PAGE_SIZE, prot, (flags | libc::MAP_FIXED) as u64, u64::MAX, 1]
            ),
            native_unaligned,
            "kind={kind:#x}"
        );
        let mut page = vec![0; PAGE_SIZE as usize];
        memory.read(BOOT_RESERVED_END, &mut page).unwrap();
        assert_eq!(page, [0xa5; PAGE_SIZE as usize], "kind={kind:#x}");
        let mapped = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_mmap,
            [0, PAGE_SIZE, prot, flags as u64, u64::MAX, 0],
        );
        assert!(mapped > 0, "kind={kind:#x}: {mapped}");
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_munmap, [mapped as u64, PAGE_SIZE, 0, 0, 0, 0]),
            0
        );
    }
}

/// pwrite64's admission runs no write callback of the object: on /dev/full an
/// unreadable buffer is EFAULT (vfs_write's access_ok comes before the
/// device's write), and a readable one is the device's ENOSPC, as natively.
#[test]
fn descriptor_pwrite64_admission_runs_no_write_callback() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = open_with_flags(&mut memory, &mut state, "/dev/full", libc::O_WRONLY);
    assert!(fd >= 0);
    let native = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap();
    let byte = [0x5a_u8];
    for (address, native_address, label) in [
        (u64::MAX, usize::MAX, "unreadable buffer"),
        (0x200, byte.as_ptr() as usize, "readable buffer"),
    ] {
        // SAFETY: the kernel reads at most one byte from a live local, or
        // refuses the unreadable address.
        let expected = descriptor_native_outcome(unsafe {
            libc::syscall(libc::SYS_pwrite64, native.as_raw_fd(), native_address, 1_usize, 0_i64)
        });
        assert_eq!(
            syscall_result(&mut memory, &mut state, libc::SYS_pwrite64, [fd as u64, address, 1, 0, 0, 0]),
            expected,
            "{label}"
        );
    }
    assert_eq!(
        descriptor_native_outcome(unsafe {
            libc::syscall(libc::SYS_pwrite64, native.as_raw_fd(), usize::MAX, 1_usize, 0_i64)
        }),
        negative_errno(libc::EFAULT)
    );
}

/// Under host-owned threads, read and readv are backend-owned unless the read
/// is Tool-visible. A random device's reads stay Tool-visible through every
/// alias (the Tool answers them), as regular files' do; another character
/// device's do not.
#[test]
fn random_device_reads_are_tool_visible_after_duplication() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    for path in ["/dev/urandom", "/dev/random", "/dev//urandom"] {
        let fd = open_readonly(&mut memory, &mut state, path);
        assert!(fd >= 0, "{path}: {fd}");
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_dup3,
                [fd as u64, 0, 0, 0, 0, 0],
            ),
            0
        );
        assert_eq!(close(&mut state, fd as u64), 0);
    }
    let null = open_readonly(&mut memory, &mut state, "/dev/null");
    assert!(null >= 0);
    let executor = ElfExecutor::new(state, false);
    for number in [libc::SYS_read, libc::SYS_readv] {
        assert!(executor.is_tool_visible_read(&SyscallRequest::new(
            number as u64,
            [0, 0x200, 1, 0, 0, 0],
        )));
        assert!(!executor.is_tool_visible_read(&SyscallRequest::new(
            number as u64,
            [null as u64, 0x200, 1, 0, 0, 0],
        )));
    }
}
