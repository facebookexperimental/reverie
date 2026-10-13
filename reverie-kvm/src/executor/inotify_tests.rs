/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests. Every observable result of the dispatched
// inotify operations is compared with an independent native instance that
// watches the same directory, so the native kernel is the oracle for return
// values, record bytes, read sizing, EINVAL/EFAULT and the remaining queue.
mod inotify_tests {
    use std::ffi::OsStr;

    use super::*;

    const BUFFER: u64 = 0x100;
    const PATH: u64 = 0x2000;

    fn native_instance() -> std::fs::File {
        // SAFETY: successful inotify_init1 returns a new owned descriptor.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(raw >= 0, "native inotify setup failed");
        // SAFETY: this is the only owner of the new descriptor.
        unsafe { std::fs::File::from_raw_fd(raw) }
    }

    fn native_watch(file: &std::fs::File, path: &Path, mask: u32) -> i64 {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and file is a live inotify instance.
        let result = unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), mask) };
        if result < 0 {
            io_error(std::io::Error::last_os_error())
        } else {
            i64::from(result)
        }
    }

    fn native_read(fd: RawFd, address: *mut u8, count: usize) -> i64 {
        // SAFETY: callers pass a live mapping; a protected suffix is
        // intentional, so the kernel performs the copy rather than Rust.
        let result = unsafe { libc::read(fd, address.cast(), count) };
        if result < 0 {
            io_error(std::io::Error::last_os_error())
        } else {
            result as i64
        }
    }

    fn queued(fd: RawFd) -> i32 {
        let mut queued = -1_i32;
        // SAFETY: queued is one live writable int.
        assert_eq!(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut queued) }, 0);
        queued
    }

    fn drain(fd: RawFd) -> (i64, Vec<u8>) {
        let mut bytes = vec![0_u8; 4096];
        let result = native_read(fd, bytes.as_mut_ptr(), bytes.len());
        bytes.truncate(result.max(0) as usize);
        (result, bytes)
    }

    fn set_path(memory: &mut GuestMemory, path: &[u8]) {
        let mut bytes = path.to_vec();
        bytes.push(0);
        assert_eq!(write_bytes(memory, PATH, &bytes), 0);
    }

    fn create(state: &mut LoadedStaticElf, memory: &mut GuestMemory) -> i64 {
        let fd = syscall_result(
            memory,
            state,
            libc::SYS_inotify_init1,
            [(libc::IN_NONBLOCK | libc::IN_CLOEXEC) as u64, 0, 0, 0, 0, 0],
        );
        assert!(fd >= 3, "inotify_init1 returned {fd}");
        fd
    }

    fn add_watch(
        state: &mut LoadedStaticElf,
        memory: &mut GuestMemory,
        fd: u64,
        path: &[u8],
        mask: u32,
    ) -> i64 {
        set_path(memory, path);
        syscall_result(
            memory,
            state,
            libc::SYS_inotify_add_watch,
            [fd, PATH, u64::from(mask), 0, 0, 0],
        )
    }

    fn guest_read(
        state: &mut LoadedStaticElf,
        memory: &mut GuestMemory,
        fd: u64,
        count: usize,
    ) -> (i64, Vec<u8>) {
        let result = syscall_result(
            memory,
            state,
            libc::SYS_read,
            [fd, BUFFER, count as u64, 0, 0, 0],
        );
        let mut bytes = vec![0_u8; result.max(0) as usize];
        memory.read(BUFFER, &mut bytes).unwrap();
        (result, bytes)
    }

    fn cookies(records: &[u8]) -> Vec<(u32, u32)> {
        let mut result = Vec::new();
        let mut offset = 0;
        while offset < records.len() {
            let mask = u32::from_ne_bytes(records[offset + 4..offset + 8].try_into().unwrap());
            let cookie = u32::from_ne_bytes(records[offset + 8..offset + 12].try_into().unwrap());
            let length =
                u32::from_ne_bytes(records[offset + 12..offset + 16].try_into().unwrap()) as usize;
            result.push((mask, cookie));
            offset += 16 + length;
        }
        result
    }

    fn without_cookies(records: &[u8]) -> Vec<u8> {
        let mut bytes = records.to_vec();
        let mut offset = 0;
        while offset < bytes.len() {
            let length =
                u32::from_ne_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
            bytes[offset + 8..offset + 12].fill(0);
            offset += 16 + length;
        }
        bytes
    }

    #[test]
    fn inotify_descriptor_detection_names_only_inotify() {
        let root = TestDir::new();
        let inotify = native_instance();
        assert_eq!(host_fd_is_inotify(inotify.as_raw_fd()), Ok(true));
        // SAFETY: eventfd returns a new owned descriptor.
        let eventfd = unsafe { std::fs::File::from_raw_fd(libc::eventfd(0, libc::EFD_CLOEXEC)) };
        assert_eq!(host_fd_is_inotify(eventfd.as_raw_fd()), Ok(false));
        let regular = std::fs::File::create(root.0.join("regular")).unwrap();
        assert_eq!(host_fd_is_inotify(regular.as_raw_fd()), Ok(false));
        let directory = std::fs::File::open(&root.0).unwrap();
        assert_eq!(host_fd_is_inotify(directory.as_raw_fd()), Ok(false));
    }

    #[test]
    fn inotify_creation_validates_flags_and_refuses_blocking_mode() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        assert!(mutates_file_table(libc::SYS_inotify_init as u64));
        assert!(mutates_file_table(libc::SYS_inotify_init1 as u64));
        // Undefined flags are EINVAL before the blocking-mode refusal, as the
        // native kernel rejects them.
        // SAFETY: an invalid flag word fails without creating a descriptor.
        assert_eq!(unsafe { libc::inotify_init1(libc::O_RDWR) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_inotify_init1,
                [libc::O_RDWR as u64, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::EINVAL)
        );
        for (number, flags) in [
            (libc::SYS_inotify_init, 0),
            (libc::SYS_inotify_init1, 0),
            (libc::SYS_inotify_init1, libc::IN_CLOEXEC as u64),
        ] {
            assert_eq!(
                syscall_result(&mut memory, &mut state, number, [flags, 0, 0, 0, 0, 0]),
                negative_errno(libc::ENOSYS)
            );
        }
        assert!(
            state.files.is_empty(),
            "a refused creation installed a descriptor"
        );

        let cloexec = create(&mut state, &mut memory);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [cloexec as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
            ),
            i64::from(libc::FD_CLOEXEC)
        );
        let plain = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_inotify_init1,
            [libc::IN_NONBLOCK as u64, 0, 0, 0, 0, 0],
        );
        assert!(plain > cloexec);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [plain as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
            ),
            0
        );
        let host = host_fd(&state, plain as i32).unwrap();
        assert_eq!(host_fd_is_inotify(host), Ok(true));
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        // The supervisor descriptor stays private regardless of guest CLOEXEC.
        // SAFETY: host is live and F_GETFD takes no argument.
        assert_eq!(
            unsafe { libc::fcntl(host, libc::F_GETFD) },
            libc::FD_CLOEXEC
        );
    }

    #[test]
    fn inotify_blocking_mode_switches_and_reads_are_refused() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let fd = create(&mut state, &mut memory) as u64;
        let host = host_fd(&state, fd as i32).unwrap();
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd, libc::F_SETFL as u64, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOSYS)
        );
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        assert_eq!(write_struct(&mut memory, BUFFER, &0_i32), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioctl,
                [fd, libc::FIONBIO, BUFFER, 0, 0, 0]
            ),
            negative_errno(libc::ENOSYS)
        );
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        // Keeping or setting nonblocking mode remains a native operation.
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd, libc::F_SETFL as u64, libc::O_NONBLOCK as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(write_struct(&mut memory, BUFFER, &1_i32), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioctl,
                [fd, libc::FIONBIO, BUFFER, 0, 0, 0]
            ),
            0
        );

        // An instance that reached the table in blocking mode (it cannot be
        // created through the dispatcher) is refused rather than waited on,
        // through both the scalar and vectored read paths.
        // SAFETY: successful inotify_init1 returns a new owned descriptor.
        let blocking = unsafe { std::fs::File::from_raw_fd(libc::inotify_init1(libc::IN_CLOEXEC)) };
        let blocking = insert_file_with_flags(&mut state, blocking, true, None) as u64;
        assert_eq!(
            guest_read(&mut state, &mut memory, blocking, 64).0,
            negative_errno(libc::ENOSYS)
        );
        let iovec = libc::iovec {
            iov_base: BUFFER as *mut libc::c_void,
            iov_len: 64,
        };
        assert_eq!(write_struct(&mut memory, PATH, &iovec), 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [blocking, PATH, 1, 0, 0, 0]
            ),
            negative_errno(libc::ENOSYS)
        );
    }

    #[test]
    fn inotify_watch_lifecycle_and_errors_match_native() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut memory) as u64;
        let root_bytes = root.0.as_os_str().as_bytes().to_vec();
        std::fs::create_dir(root.0.join("dir")).unwrap();
        std::fs::write(root.0.join("file"), b"x").unwrap();
        let mask = libc::IN_CREATE | libc::IN_DELETE;

        // The first watch on each fresh instance receives the same number.
        let wd = add_watch(&mut state, &mut memory, fd, &root_bytes, mask);
        assert_eq!(wd, native_watch(&native, &root.0, mask));
        assert!(wd >= 1);
        // Relative paths resolve from the guest's working directory and name
        // the same inode, so the existing watch descriptor is returned.
        assert_eq!(add_watch(&mut state, &mut memory, fd, b".", mask), wd);
        assert_eq!(native_watch(&native, &root.0.join("."), mask), wd);
        // IN_MASK_CREATE on an existing watch, IN_ONLYDIR on a regular file,
        // a missing path and a missing parent all keep the native errno.
        for (path, mask) in [
            (b"dir".as_slice(), libc::IN_CREATE | libc::IN_MASK_CREATE),
            (b"dir", libc::IN_CREATE | libc::IN_MASK_CREATE),
            (b"file", libc::IN_MODIFY | libc::IN_ONLYDIR),
            (b"file/", libc::IN_MODIFY),
            (b"missing", libc::IN_MODIFY),
            (b"missing/child", libc::IN_MODIFY),
            // Invalid masks: undefined bits, and both create and add.
            (b"file", 0x0800_0000),
            (
                b"file",
                libc::IN_MODIFY | libc::IN_MASK_ADD | libc::IN_MASK_CREATE,
            ),
        ] {
            let mut absolute = root.0.clone().into_os_string().into_vec();
            absolute.push(b'/');
            absolute.extend_from_slice(path);
            let expected = native_watch(&native, Path::new(OsStr::from_bytes(&absolute)), mask);
            assert_eq!(
                add_watch(&mut state, &mut memory, fd, path, mask),
                expected,
                "path {:?} mask {mask:#x}",
                OsStr::from_bytes(path)
            );
        }
        // An empty pathname, an unmapped pathname and a too-long pathname.
        assert_eq!(
            add_watch(&mut state, &mut memory, fd, b"", mask),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_inotify_add_watch,
                [fd, 64 * PAGE_SIZE, u64::from(mask), 0, 0, 0],
            ),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(
            add_watch(
                &mut state,
                &mut memory,
                fd,
                &vec![b'a'; libc::PATH_MAX as usize],
                mask
            ),
            negative_errno(libc::ENAMETOOLONG)
        );

        // Descriptor errors precede pathname errors; mask errors precede both.
        let regular = insert_file_with_flags(
            &mut state,
            std::fs::File::open(root.0.join("file")).unwrap(),
            false,
            None,
        ) as u64;
        assert_eq!(
            add_watch(&mut state, &mut memory, 99, b"missing", mask),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            add_watch(&mut state, &mut memory, regular, b"missing", mask),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            add_watch(&mut state, &mut memory, 99, b"missing", 0x0800_0000),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_inotify_add_watch,
                [regular, 64 * PAGE_SIZE, u64::from(mask), 0, 0, 0],
            ),
            negative_errno(libc::EINVAL)
        );

        // Removal reports IN_IGNORED, and a second removal is EINVAL.
        let rm = |state: &mut LoadedStaticElf, memory: &mut GuestMemory, fd: u64, wd: i64| {
            syscall_result(
                memory,
                state,
                libc::SYS_inotify_rm_watch,
                [fd, wd as u64, 0, 0, 0, 0],
            )
        };
        assert_eq!(rm(&mut state, &mut memory, fd, wd), 0);
        // SAFETY: native is a live inotify instance.
        assert_eq!(
            unsafe { libc::inotify_rm_watch(native.as_raw_fd(), wd as i32) },
            0
        );
        assert_eq!(
            rm(&mut state, &mut memory, fd, wd),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            rm(&mut state, &mut memory, 99, wd),
            negative_errno(libc::EBADF)
        );
        assert_eq!(
            rm(&mut state, &mut memory, regular, wd),
            negative_errno(libc::EINVAL)
        );
        let host = host_fd(&state, fd as i32).unwrap();
        assert_eq!(drain(host), drain(native.as_raw_fd()));
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_close,
                [fd, 0, 0, 0, 0, 0]
            ),
            0
        );
    }

    #[test]
    fn inotify_watch_dont_follow_selects_the_symlink_itself() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        std::fs::write(root.0.join("target"), b"x").unwrap();
        std::os::unix::fs::symlink("target", root.0.join("link")).unwrap();
        let mask = libc::IN_ATTRIB;
        let mut results = Vec::new();
        for dont_follow in [false, true] {
            let native = native_instance();
            let fd = create(&mut state, &mut memory) as u64;
            let mask = mask | if dont_follow { libc::IN_DONT_FOLLOW } else { 0 };
            let wd = add_watch(&mut state, &mut memory, fd, b"link", mask);
            assert_eq!(wd, native_watch(&native, &root.0.join("link"), mask));
            assert!(wd >= 1);
            let host = host_fd(&state, fd as i32).unwrap();
            // Change the target, then the link itself.
            std::fs::set_permissions(
                root.0.join("target"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let target_change = (drain(host), drain(native.as_raw_fd()));
            let link = CString::new(root.0.join("link").as_os_str().as_bytes()).unwrap();
            // SAFETY: link is NUL-terminated; null times mean "now".
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        link.as_ptr(),
                        std::ptr::null(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0
            );
            let link_change = (drain(host), drain(native.as_raw_fd()));
            assert_eq!(target_change.0, target_change.1);
            assert_eq!(link_change.0, link_change.1);
            results.push((target_change.0.0 > 0, link_change.0.0 > 0));
        }
        // Following watches the target; IN_DONT_FOLLOW watches only the link.
        assert_eq!(results, [(true, false), (false, true)]);
    }

    #[test]
    fn inotify_reads_match_native_records_sizing_and_queue() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut memory) as u64;
        let host = host_fd(&state, fd as i32).unwrap();
        let mask = libc::IN_CREATE | libc::IN_MODIFY;
        assert_eq!(
            add_watch(
                &mut state,
                &mut memory,
                fd,
                root.0.as_os_str().as_bytes(),
                mask
            ),
            native_watch(&native, &root.0, mask)
        );
        let mut native_buffer = vec![0_u8; 4096];
        let mut compare = |state: &mut LoadedStaticElf, memory: &mut GuestMemory, count: usize| {
            let native_result = native_read(native.as_raw_fd(), native_buffer.as_mut_ptr(), count);
            let native_bytes = native_buffer[..native_result.max(0) as usize].to_vec();
            let guest = guest_read(state, memory, fd, count);
            assert_eq!(guest, (native_result, native_bytes), "count {count}");
            assert_eq!(queued(host), queued(native.as_raw_fd()), "count {count}");
            guest.0
        };

        // Empty queue: EAGAIN.
        assert_eq!(
            compare(&mut state, &mut memory, 64),
            negative_errno(libc::EAGAIN)
        );
        // Six back-to-back writes coalesce into one queued IN_MODIFY, after one
        // IN_CREATE for "alpha" and one for the longer "bravo-name".
        let mut file = std::fs::File::create(root.0.join("alpha")).unwrap();
        std::fs::File::create(root.0.join("bravo-name-that-needs-two-blocks")).unwrap();
        for _ in 0..6 {
            file.write_all(b"x").unwrap();
        }
        assert_eq!(queued(host), queued(native.as_raw_fd()));
        // A count smaller than the first record is EINVAL without consuming.
        assert_eq!(
            compare(&mut state, &mut memory, 16),
            negative_errno(libc::EINVAL)
        );
        assert_eq!(
            compare(&mut state, &mut memory, 31),
            negative_errno(libc::EINVAL)
        );
        // A count that fits one record returns exactly that record.
        assert_eq!(compare(&mut state, &mut memory, 63), 32);
        // The next record has a 48-byte name area; the remaining 31 bytes are
        // not enough for the record after it, so only whole records return.
        assert_eq!(compare(&mut state, &mut memory, 95), 64);
        // The last record, then the drained queue.
        assert_eq!(compare(&mut state, &mut memory, 4096), 32);
        assert_eq!(
            compare(&mut state, &mut memory, 4096),
            negative_errno(libc::EAGAIN)
        );
    }

    #[test]
    fn inotify_faulting_reads_match_native_copy_and_consumption() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let native = native_instance();
        let fd = {
            let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
            let fd = create(&mut state, &mut memory) as u64;
            assert_eq!(
                add_watch(
                    &mut state,
                    &mut memory,
                    fd,
                    root.0.as_os_str().as_bytes(),
                    libc::IN_CREATE
                ),
                native_watch(&native, &root.0, libc::IN_CREATE)
            );
            fd
        };
        let host = host_fd(&state, fd as i32).unwrap();
        // Guest page 1 is writable and page 2 is inaccessible.
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        memory.write(PAGE_SIZE - 64, &[0xa5; 64]).unwrap();
        memory.enable_user_access();
        memory.map_user_range(0, 2 * PAGE_SIZE, false).unwrap();
        memory
            .map_user_range(2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();
        let native_fault = NativeFaultBuffer::new();

        let mut compare = |memory: &mut GuestMemory, writable: usize, count: usize| {
            let guest_address = 2 * PAGE_SIZE - writable as u64;
            // SAFETY: the writable prefix lies in the native buffer's first page.
            let native_address = unsafe { native_fault.invalid.sub(writable) };
            // SAFETY: only the live writable prefix is initialized.
            unsafe { std::ptr::write_bytes(native_address, 0xa5, writable) };
            memory
                .write_raw(guest_address, &vec![0xa5; writable])
                .unwrap();
            let native_result = native_read(native.as_raw_fd(), native_address, count);
            let guest_result = syscall_result(
                memory,
                &mut state,
                libc::SYS_read,
                [fd, guest_address, count as u64, 0, 0, 0],
            );
            let mut native_prefix = vec![0_u8; writable];
            // SAFETY: copy only the writable prefix, never the protected page.
            unsafe {
                std::ptr::copy_nonoverlapping(native_address, native_prefix.as_mut_ptr(), writable)
            };
            let mut guest_prefix = vec![0_u8; writable];
            memory.read(guest_address, &mut guest_prefix).unwrap();
            assert_eq!(
                (guest_result, guest_prefix, queued(host)),
                (native_result, native_prefix, queued(native.as_raw_fd())),
                "writable {writable} count {count}"
            );
            guest_result
        };

        // An empty queue keeps EAGAIN ahead of the inaccessible destination.
        assert_eq!(compare(&mut memory, 0, 64), negative_errno(libc::EAGAIN));
        // Two 32-byte IN_CREATE records with distinct names do not coalesce.
        for name in ["alpha", "bravo", "charlie"] {
            std::fs::File::create(root.0.join(name)).unwrap();
        }
        assert_eq!(queued(host), 96);
        // A record that fits the count but crosses into the protected page
        // consumes it and fails EFAULT, after writing the records before it.
        assert_eq!(compare(&mut memory, 40, 64), negative_errno(libc::EFAULT));
        assert_eq!(queued(host), 32);
        // Nothing writable at all: the first record faults and is consumed.
        assert_eq!(compare(&mut memory, 0, 64), negative_errno(libc::EFAULT));
        assert_eq!(queued(host), 0);
    }

    #[test]
    fn inotify_rename_cookies_are_virtual_and_paired() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut memory) as u64;
        let second = create(&mut state, &mut memory) as u64;
        let mask = libc::IN_MOVED_FROM | libc::IN_MOVED_TO | libc::IN_CREATE;
        std::fs::create_dir(root.0.join("other")).unwrap();
        assert_eq!(
            add_watch(
                &mut state,
                &mut memory,
                fd,
                root.0.as_os_str().as_bytes(),
                mask
            ),
            native_watch(&native, &root.0, mask)
        );
        // A second instance watches only the destination directory.
        assert_eq!(
            add_watch(&mut state, &mut memory, second, b"other", mask),
            1
        );
        std::fs::write(root.0.join("a"), b"").unwrap();
        std::fs::rename(root.0.join("a"), root.0.join("b")).unwrap();
        std::fs::rename(root.0.join("b"), root.0.join("other/c")).unwrap();

        let (native_result, native_records) = drain(native.as_raw_fd());
        let (guest_result, guest_records) = guest_read(&mut state, &mut memory, fd, 4096);
        assert_eq!(guest_result, native_result);
        // Apart from cookies, the records are the native records.
        assert_eq!(
            without_cookies(&guest_records),
            without_cookies(&native_records)
        );
        let native_cookies = cookies(&native_records);
        assert_eq!(native_cookies.len(), 4);
        assert_eq!(native_cookies[0].1, 0, "IN_CREATE has no cookie");
        assert_ne!(native_cookies[1].1, 0);
        assert_eq!(native_cookies[1].1, native_cookies[2].1);
        // The guest sees cookies numbered by first observation.
        assert_eq!(
            cookies(&guest_records),
            [
                (libc::IN_CREATE, 0),
                (libc::IN_MOVED_FROM, 1),
                (libc::IN_MOVED_TO, 1),
                (libc::IN_MOVED_FROM, 2),
            ]
        );
        // The destination half, read through another instance and readv,
        // pairs with the source half's virtual cookie.
        let iovec = libc::iovec {
            iov_base: BUFFER as *mut libc::c_void,
            iov_len: 4096,
        };
        assert_eq!(write_struct(&mut memory, PATH, &iovec), 0);
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [second, PATH, 1, 0, 0, 0],
        );
        assert_eq!(count, 32);
        let mut records = vec![0_u8; count as usize];
        memory.read(BUFFER, &mut records).unwrap();
        assert_eq!(cookies(&records), [(libc::IN_MOVED_TO, 2)]);
    }

    #[test]
    fn inotify_cookie_table_is_stable_and_bounded() {
        let mut table = InotifyCookieTable::default();
        assert_eq!(table.virtualize(0), 0);
        assert_eq!(table.virtualize(0xdead_beef), 1);
        assert_eq!(table.virtualize(7), 2);
        assert_eq!(table.virtualize(0xdead_beef), 1);
        for host in 0..INOTIFY_COOKIE_CAPACITY as u32 {
            table.virtualize(0x1000_0000 + host);
        }
        assert_eq!(table.host_by_age.len(), INOTIFY_COOKIE_CAPACITY);
        assert_eq!(table.virtual_by_host.len(), INOTIFY_COOKIE_CAPACITY);
        // The two oldest entries were evicted in first-observation order.
        assert!(!table.virtual_by_host.contains_key(&0xdead_beef));
        assert!(!table.virtual_by_host.contains_key(&7));

        // A partial trailing record restores any partly written cookie bytes.
        let mut table = InotifyCookieTable::default();
        let mut record = [0_u8; 32];
        record[8..12].copy_from_slice(&0x1234_5678_u32.to_ne_bytes());
        record[12..16].copy_from_slice(&16_u32.to_ne_bytes());
        let mut bytes = record.to_vec();
        bytes.extend_from_slice(&record[..10]);
        let original = vec![0xa5_u8; bytes.len()];
        virtualize_inotify_cookies(&mut bytes, Some(&original), &mut table);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 1);
        assert_eq!(&bytes[32 + 8..], &[0xa5, 0xa5]);
    }
}
