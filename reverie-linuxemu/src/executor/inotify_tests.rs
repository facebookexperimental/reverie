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
        assert_eq!(write_bytes(&mut ProviderMemory(memory), PATH, &bytes), 0);
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

    fn guest_status_flags(state: &mut LoadedStaticElf, memory: &mut GuestMemory, fd: u64) -> i64 {
        syscall_result(
            memory,
            state,
            libc::SYS_fcntl,
            [fd, libc::F_GETFL as u64, 0, 0, 0, 0],
        )
    }

    #[test]
    fn inotify_creation_validates_flags_and_keeps_every_host_instance_nonblocking() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        assert!(mutates_file_table(libc::SYS_inotify_init as u64));
        assert!(mutates_file_table(libc::SYS_inotify_init1 as u64));
        // Undefined flags are EINVAL, as the native kernel rejects them.
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
        assert!(
            state.files.is_empty(),
            "a refused creation installed a descriptor"
        );
        // A blocking instance, from inotify_init or inotify_init1 without
        // IN_NONBLOCK, is created with a nonblocking host instance: a read
        // that finds nothing queued answers EAGAIN, as a native nonblocking
        // instance does, which reports to the Tool that it would block. Guest
        // CLOEXEC is still the guest's.
        let native = native_instance();
        for (number, flags) in [
            (libc::SYS_inotify_init, 0),
            (libc::SYS_inotify_init1, 0),
            (libc::SYS_inotify_init1, libc::IN_CLOEXEC as u64),
            (libc::SYS_inotify_init1, libc::IN_NONBLOCK as u64),
        ] {
            let fd = syscall_result(&mut memory, &mut state, number, [flags, 0, 0, 0, 0, 0]);
            assert!(fd >= 3, "{number} with flags {flags:#x} returned {fd}");
            let host = host_fd(&state, fd as i32).unwrap();
            assert_eq!(host_fd_is_inotify(host), Ok(true));
            assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
            assert_ne!(
                guest_status_flags(&mut state, &mut memory, fd as u64)
                    & i64::from(libc::O_NONBLOCK),
                0
            );
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_fcntl,
                    [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
                ),
                if flags == libc::IN_CLOEXEC as u64 {
                    i64::from(libc::FD_CLOEXEC)
                } else {
                    0
                }
            );
            let mut native_bytes = [0_u8; 64];
            assert_eq!(
                guest_read(&mut state, &mut memory, fd as u64, 64).0,
                native_read(native.as_raw_fd(), native_bytes.as_mut_ptr(), 64)
            );
            assert_eq!(
                guest_read(&mut state, &mut memory, fd as u64, 64).0,
                negative_errno(libc::EAGAIN)
            );
            // The supervisor descriptor stays private regardless of guest
            // CLOEXEC.
            // SAFETY: host is live and F_GETFD takes no argument.
            assert_eq!(
                unsafe { libc::fcntl(host, libc::F_GETFD) },
                libc::FD_CLOEXEC
            );
        }
    }

    #[test]
    fn inotify_blocking_mode_switches_keep_the_host_instance_nonblocking() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut memory) as u64;
        let host = host_fd(&state, fd as i32).unwrap();
        let root_bytes = root.0.as_os_str().as_bytes().to_vec();
        let wd = add_watch(&mut state, &mut memory, fd, &root_bytes, libc::IN_CREATE);
        assert_eq!(wd, native_watch(&native, &root.0, libc::IN_CREATE));
        // Clearing O_NONBLOCK succeeds and leaves the host nonblocking; the
        // other flags apply as natively (O_APPEND here).
        // SAFETY: native is live; F_SETFL consumes one int flag word.
        let native_result =
            unsafe { libc::fcntl(native.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) };
        assert_eq!(native_result, 0);
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd, libc::F_SETFL as u64, libc::O_APPEND as u64, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            fd_status_flags(host).unwrap(),
            fd_status_flags(native.as_raw_fd()).unwrap() | libc::O_NONBLOCK
        );
        // SAFETY: as above, back to the native instance's nonblocking mode.
        assert_eq!(
            unsafe { libc::fcntl(native.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_fcntl,
                [fd, libc::F_SETFL as u64, 0, 0, 0, 0]
            ),
            0
        );
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        assert_eq!(
            write_struct(&mut ProviderMemory(&memory), BUFFER, &0_i32),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioctl,
                [fd, libc::FIONBIO, BUFFER, 0, 0, 0]
            ),
            0
        );
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        // Reads of the "blocking" descriptor never wait: with nothing queued
        // they answer EAGAIN through both the scalar and vectored paths.
        let iovec = libc::iovec {
            iov_base: BUFFER as *mut libc::c_void,
            iov_len: 64,
        };
        assert_eq!(write_struct(&mut ProviderMemory(&memory), PATH, &iovec), 0);
        assert_eq!(
            guest_read(&mut state, &mut memory, fd, 64).0,
            negative_errno(libc::EAGAIN)
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [fd, PATH, 1, 0, 0, 0]
            ),
            negative_errno(libc::EAGAIN)
        );
        // With an event queued they return it, as the native instance does.
        std::fs::write(root.0.join("created"), b"x").unwrap();
        let (result, bytes) = guest_read(&mut state, &mut memory, fd, 64);
        assert_eq!((result, bytes), drain(native.as_raw_fd()));
        assert!(result > 0);
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
        assert_eq!(
            write_struct(&mut ProviderMemory(&memory), BUFFER, &1_i32),
            0
        );
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_ioctl,
                [fd, libc::FIONBIO, BUFFER, 0, 0, 0]
            ),
            0
        );
        assert_ne!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn a_read_of_an_instance_blocking_on_the_host_is_refused_before_any_host_call() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        // An instance that reached the table blocking on the host, as one
        // received from outside the guest can (this executor creates none),
        // with an event queued, which a host read would take.
        // SAFETY: successful inotify_init1 returns a new owned descriptor.
        let blocking = unsafe { std::fs::File::from_raw_fd(libc::inotify_init1(libc::IN_CLOEXEC)) };
        let host = blocking.as_raw_fd();
        let path = CString::new(root.0.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is NUL-terminated and host is a live inotify instance.
        assert!(unsafe { libc::inotify_add_watch(host, path.as_ptr(), libc::IN_CREATE) } >= 0);
        std::fs::write(root.0.join("created"), b"x").unwrap();
        let queued_before = queued(host);
        assert!(queued_before > 0);
        let fd = insert_file_with_flags(&mut state, blocking, true, None);
        assert!(fd >= 3);
        let iovec = libc::iovec {
            iov_base: BUFFER as *mut libc::c_void,
            iov_len: 64,
        };
        assert_eq!(write_struct(&mut ProviderMemory(&memory), PATH, &iovec), 0);
        let refused = |action: SyscallAction| {
            matches!(
                action,
                SyscallAction::Failure(crate::Error::BlockingInotifyRead { fd: actual })
                    if i64::from(actual) == fd
            )
        };
        for (number, args) in [
            (libc::SYS_read, [fd as u64, BUFFER, 64, 0, 0, 0]),
            (libc::SYS_readv, [fd as u64, PATH, 1, 0, 0, 0]),
            (libc::SYS_preadv2, [fd as u64, PATH, 1, u64::MAX, 0, 0]),
            (
                libc::SYS_preadv2,
                [fd as u64, PATH, 1, u64::MAX, 0, libc::RWF_HIPRI as u64],
            ),
        ] {
            let action = execute_basic_syscall(
                &mut memory,
                &mut state,
                &SyscallRequest::new(number as u64, args),
            );
            assert!(refused(action), "{number} {args:?} was not refused by name");
            assert_eq!(queued(host), queued_before, "{number} took an event");
        }
        // A positioned preadv2, or one with a flag Linux refuses first, never
        // reads, and answers as a native blocking instance does.
        // SAFETY: successful inotify_init1 returns a new owned descriptor.
        let native = unsafe { std::fs::File::from_raw_fd(libc::inotify_init1(libc::IN_CLOEXEC)) };
        let mut native_bytes = [0_u8; 64];
        let native_iovec = libc::iovec {
            iov_base: native_bytes.as_mut_ptr().cast(),
            iov_len: native_bytes.len(),
        };
        for (offset, flags) in [(0_u64, 0_u64), (u64::MAX, libc::RWF_NOWAIT as u64)] {
            // SAFETY: native_iovec names native_bytes, which outlive the call;
            // neither call reads (ESPIPE and EOPNOTSUPP come first).
            let native_result = unsafe {
                libc::syscall(
                    libc::SYS_preadv2,
                    native.as_raw_fd(),
                    &native_iovec as *const libc::iovec,
                    1,
                    offset,
                    0,
                    flags,
                )
            };
            let native_result = if native_result < 0 {
                io_error(std::io::Error::last_os_error())
            } else {
                native_result
            };
            assert!(native_result < 0, "native preadv2 read {native_result}");
            assert_eq!(
                syscall_result(
                    &mut memory,
                    &mut state,
                    libc::SYS_preadv2,
                    [fd as u64, PATH, 1, offset, 0, flags]
                ),
                native_result
            );
        }
        assert_eq!(queued(host), queued_before);
        assert_eq!(fd_status_flags(host).unwrap() & libc::O_NONBLOCK, 0);
        // An instance this executor made is never refused: with nothing
        // queued its read answers EAGAIN.
        let made = create(&mut state, &mut memory) as u64;
        assert_eq!(
            guest_read(&mut state, &mut memory, made, 64).0,
            negative_errno(libc::EAGAIN)
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

    /// Rename cookies reach the guest as the host kernel wrote them: what the
    /// guest sees of them is the Tool's decision. A read, and a readv through a
    /// second instance that watches only the destination, return exactly the
    /// native instance's records, cookies included.
    #[test]
    fn inotify_rename_cookies_reach_the_guest_as_the_host_wrote_them() {
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
        let native_cookies = cookies(&native_records);
        assert_eq!(native_cookies.len(), 4);
        assert_eq!(
            native_cookies[0],
            (libc::IN_CREATE, 0),
            "IN_CREATE has no cookie"
        );
        assert_eq!(native_cookies[1].0, libc::IN_MOVED_FROM);
        assert_ne!(native_cookies[1].1, 0);
        assert_eq!(native_cookies[2], (libc::IN_MOVED_TO, native_cookies[1].1));
        assert_eq!(native_cookies[3].0, libc::IN_MOVED_FROM);
        assert_ne!(native_cookies[3].1, native_cookies[1].1);
        // Every byte is the host kernel's, the host cookies included.
        assert_eq!(
            guest_read(&mut state, &mut memory, fd, 4096),
            (native_result, native_records)
        );
        // The destination half, read through the other instance with readv,
        // carries its rename's host cookie.
        let iovec = libc::iovec {
            iov_base: BUFFER as *mut libc::c_void,
            iov_len: 4096,
        };
        assert_eq!(write_struct(&mut ProviderMemory(&memory), PATH, &iovec), 0);
        let count = syscall_result(
            &mut memory,
            &mut state,
            libc::SYS_readv,
            [second, PATH, 1, 0, 0, 0],
        );
        assert_eq!(count, 32);
        let mut records = vec![0_u8; count as usize];
        memory.read(BUFFER, &mut records).unwrap();
        assert_eq!(
            cookies(&records),
            [(libc::IN_MOVED_TO, native_cookies[3].1)]
        );
    }

    /// Guest memory whose pages 0 and 1 are writable and page 2 inaccessible,
    /// so a buffer that ends at 2 * PAGE_SIZE faults there, as a native buffer
    /// that ends at `NativeFaultBuffer::invalid` does.
    fn fault_memory() -> GuestMemory {
        let memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        memory.enable_user_access();
        memory.map_user_range(0, 2 * PAGE_SIZE, false).unwrap();
        memory
            .map_user_range(2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();
        memory
    }

    /// One guest read of `count` bytes from `fd`, and one native read of the
    /// same count from `native`, each into `writable` bytes filled with 0xa5
    /// before an inaccessible page: the results, the writable bytes and the
    /// queues afterwards must be equal.
    fn compare_faulting_read(
        state: &mut LoadedStaticElf,
        fd: u64,
        native: &std::fs::File,
        writable: usize,
        count: usize,
    ) -> i64 {
        let host = host_fd(state, fd as i32).unwrap();
        let mut memory = fault_memory();
        let native_fault = NativeFaultBuffer::new();
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
            &mut memory,
            state,
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
    }

    /// Reads that fault inside an event leave exactly the bytes the kernel
    /// copied before the fault: whole events with their host cookies, then the
    /// next event's header as far as it was written (a rename cookie written
    /// whole, or only its first bytes), or the zeros of an IN_IGNORED event's
    /// cookie. Nothing is renumbered, cleared or put back.
    #[test]
    fn inotify_faulting_reads_leave_the_bytes_the_kernel_copied() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut setup = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut setup) as u64;
        let root_bytes = root.0.as_os_str().as_bytes().to_vec();
        let mask = libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
        let wd = add_watch(&mut state, &mut setup, fd, &root_bytes, mask);
        assert_eq!(wd, native_watch(&native, &root.0, mask));
        let host = host_fd(&state, fd as i32).unwrap();
        // Three renames queue six 32-byte events: every name has two
        // characters, which Linux pads to 16 bytes.
        std::fs::write(root.0.join("f0"), b"").unwrap();
        for (from, to) in [("f0", "f1"), ("f1", "f2"), ("f2", "f3")] {
            std::fs::rename(root.0.join(from), root.0.join(to)).unwrap();
        }
        assert_eq!(queued(host), 192);
        assert_eq!(queued(native.as_raw_fd()), 192);
        // 40 writable bytes: one event, then the next event's wd and mask.
        assert_eq!(
            compare_faulting_read(&mut state, fd, &native, 40, 64),
            negative_errno(libc::EFAULT)
        );
        // 44: the next event's cookie written whole, its length cut.
        assert_eq!(
            compare_faulting_read(&mut state, fd, &native, 44, 64),
            negative_errno(libc::EFAULT)
        );
        // 42: the next event's cookie cut after two bytes.
        assert_eq!(
            compare_faulting_read(&mut state, fd, &native, 42, 64),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(queued(host), 0);

        // An IN_IGNORED event, whose cookie is 0, cut inside its cookie: the
        // two cookie bytes the kernel wrote are zeros.
        assert_eq!(
            add_watch(&mut state, &mut setup, fd, &root_bytes, libc::IN_ATTRIB),
            wd
        );
        assert_eq!(native_watch(&native, &root.0, libc::IN_ATTRIB), wd);
        assert_eq!(
            syscall_result(
                &mut setup,
                &mut state,
                libc::SYS_inotify_rm_watch,
                [fd, wd as u64, 0, 0, 0, 0],
            ),
            0
        );
        // SAFETY: native is a live inotify instance and wd its watch.
        assert_eq!(
            unsafe { libc::inotify_rm_watch(native.as_raw_fd(), wd as i32) },
            0
        );
        assert_eq!(
            compare_faulting_read(&mut state, fd, &native, 10, 16),
            negative_errno(libc::EFAULT)
        );
        assert_eq!(queued(host), 0);
    }

    /// Where an iovec of a readv lies: in its own buffer, or `k` bytes before
    /// the inaccessible page.
    #[derive(Clone, Copy, Debug)]
    enum IovecPlace {
        Separate,
        BeforeFault(usize),
    }

    /// One readv of an instance that has seen `renames` renames, after a read
    /// of `before` bytes: its two iovecs, and the count it returns.
    struct ReadvCase {
        iovecs: [(IovecPlace, usize); 2],
        renames: usize,
        before: usize,
        count: i64,
    }

    /// A readv whose second iovec faults after the first one filled returns the
    /// first iovec's count, and the events inotify_read copied into the second
    /// iovec before its fault stay there, as on the native instance, whether or
    /// not the iovecs overlap. A second iovec whose read copied nothing (no
    /// event left, or the next one longer than the iovec) keeps its bytes, so a
    /// first iovec that it overlaps keeps the event it received.
    #[test]
    fn inotify_readv_leaves_the_events_copied_into_a_faulting_later_iovec() {
        use IovecPlace::BeforeFault;
        use IovecPlace::Separate;
        const IOV: u64 = 0x400;
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let root_bytes = root.0.as_os_str().as_bytes().to_vec();
        let mask = libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
        let cases = [
            // The second iovec holds one event and the next one's wd and mask.
            ReadvCase {
                iovecs: [(Separate, 32), (BeforeFault(40), 64)],
                renames: 2,
                before: 0,
                count: 32,
            },
            // The same, overlapping the first iovec, whose event it overwrites.
            ReadvCase {
                iovecs: [(BeforeFault(48), 32), (BeforeFault(40), 64)],
                renames: 2,
                before: 0,
                count: 32,
            },
            // No event left for the overlapping second iovec.
            ReadvCase {
                iovecs: [(BeforeFault(48), 32), (BeforeFault(40), 64)],
                renames: 2,
                before: 96,
                count: 32,
            },
            // The next event is longer than the second iovec: EINVAL there.
            ReadvCase {
                iovecs: [(Separate, 32), (BeforeFault(8), 16)],
                renames: 2,
                before: 0,
                count: 32,
            },
            // The same, with the second iovec overlapping the first.
            ReadvCase {
                iovecs: [(BeforeFault(36), 32), (BeforeFault(8), 16)],
                renames: 2,
                before: 0,
                count: 32,
            },
        ];
        for (index, case) in cases.into_iter().enumerate() {
            let ReadvCase {
                iovecs,
                renames,
                before,
                count: expected,
            } = case;
            let mut setup = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
            let native = native_instance();
            let fd = create(&mut state, &mut setup) as u64;
            assert_eq!(
                add_watch(&mut state, &mut setup, fd, &root_bytes, mask),
                native_watch(&native, &root.0, mask)
            );
            let host = host_fd(&state, fd as i32).unwrap();
            let first = format!("c{index}");
            std::fs::write(root.0.join(&first), b"").unwrap();
            let mut name = first;
            for step in 0..renames {
                let next = format!("c{index}{step}");
                std::fs::rename(root.0.join(&name), root.0.join(&next)).unwrap();
                name = next;
            }
            if before != 0 {
                let mut native_bytes = vec![0_u8; before];
                let native_result =
                    native_read(native.as_raw_fd(), native_bytes.as_mut_ptr(), before);
                assert_eq!(
                    guest_read(&mut state, &mut setup, fd, before),
                    (native_result, native_bytes)
                );
            }

            let native_fault = NativeFaultBuffer::new();
            let mut native_separate = vec![0xa5_u8; 64];
            let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
            let place = |(where_, length): (IovecPlace, usize)| match where_ {
                Separate => (BUFFER, length.min(64), length),
                BeforeFault(k) => (2 * PAGE_SIZE - k as u64, k.min(length), length),
            };
            let guest_vectors: Vec<(u64, usize)> = iovecs
                .iter()
                .map(|&iovec| {
                    let (address, _, length) = place(iovec);
                    (address, length)
                })
                .collect();
            for &iovec in &iovecs {
                let (address, writable, _) = place(iovec);
                memory.write(address, &vec![0xa5; writable]).unwrap();
            }
            write_guest_iovecs(&mut memory, IOV, &guest_vectors);
            memory.enable_user_access();
            memory.map_user_range(0, 2 * PAGE_SIZE, false).unwrap();
            memory
                .map_user_range(2 * PAGE_SIZE, PAGE_SIZE, true)
                .unwrap();
            let separate = native_separate.as_mut_ptr();
            let invalid = native_fault.invalid;
            let native_place = move |where_: IovecPlace| -> *mut u8 {
                match where_ {
                    Separate => separate,
                    // SAFETY: k bytes before the inaccessible page lie in the
                    // buffer's writable first page.
                    BeforeFault(k) => unsafe { invalid.sub(k) },
                }
            };
            let mut native_iovecs: Vec<libc::iovec> = iovecs
                .iter()
                .map(|&(where_, length)| libc::iovec {
                    iov_base: native_place(where_).cast(),
                    iov_len: length,
                })
                .collect();
            for &(where_, length) in &iovecs {
                if let BeforeFault(k) = where_ {
                    // SAFETY: only the live writable bytes are initialized.
                    unsafe { std::ptr::write_bytes(native_place(where_), 0xa5, k.min(length)) };
                }
            }
            let native_result =
                raw_vectored_call(libc::SYS_readv, native.as_raw_fd(), &mut native_iovecs);
            let guest_result = syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_readv,
                [fd, IOV, 2, 0, 0, 0],
            );
            assert_eq!((index, guest_result), (index, native_result));
            assert_eq!((index, guest_result), (index, expected));
            assert_eq!((index, queued(host)), (index, queued(native.as_raw_fd())));
            for &(where_, length) in &iovecs {
                let (address, writable, _) = place((where_, length));
                let mut guest_bytes = vec![0_u8; writable];
                memory.read(address, &mut guest_bytes).unwrap();
                let mut native_bytes = vec![0_u8; writable];
                // SAFETY: copy only the live writable bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        native_place(where_),
                        native_bytes.as_mut_ptr(),
                        writable,
                    )
                };
                assert_eq!(
                    guest_bytes, native_bytes,
                    "case {index} iovec at {where_:?}"
                );
            }
        }
    }

    /// FIONREAD on an inotify descriptor is the host instance's count of
    /// queued bytes, as on the native instance, through a duplicate too. A
    /// destination the guest cannot write is EFAULT, and the query consumes
    /// nothing.
    #[test]
    fn inotify_fionread_reports_the_host_instance_queue() {
        let root = TestDir::new();
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, 4 * PAGE_SIZE as usize).unwrap();
        let native = native_instance();
        let fd = create(&mut state, &mut memory) as u64;
        let mask = libc::IN_CREATE;
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
        let fionread =
            |state: &mut LoadedStaticElf, memory: &mut GuestMemory, fd: u64, address: u64| {
                syscall_result(
                    memory,
                    state,
                    libc::SYS_ioctl,
                    [fd, libc::FIONREAD, address, 0, 0, 0],
                )
            };
        let count = |state: &mut LoadedStaticElf, memory: &mut GuestMemory, fd: u64| {
            assert_eq!(fionread(state, memory, fd, BUFFER), 0);
            let mut bytes = [0_u8; 4];
            memory.read(BUFFER, &mut bytes).unwrap();
            i32::from_ne_bytes(bytes)
        };
        assert_eq!(count(&mut state, &mut memory, fd), 0);
        assert_eq!(queued(native.as_raw_fd()), 0);
        // A short name and one that needs a second 16-byte block.
        std::fs::File::create(root.0.join("alpha")).unwrap();
        std::fs::File::create(root.0.join("bravo-name-that-needs-two-blocks")).unwrap();
        let expected = queued(native.as_raw_fd());
        assert_eq!(expected, 32 + 64);
        assert_eq!(count(&mut state, &mut memory, fd), expected);
        let duplicate = syscall_result(&mut memory, &mut state, libc::SYS_dup, [fd, 0, 0, 0, 0, 0]);
        assert!(duplicate > fd as i64);
        assert_eq!(count(&mut state, &mut memory, duplicate as u64), expected);
        // An unwritable destination is EFAULT, natively too.
        assert_eq!(
            fionread(&mut state, &mut memory, fd, 64 * PAGE_SIZE),
            negative_errno(libc::EFAULT)
        );
        let native_fault = NativeFaultBuffer::new();
        // SAFETY: the kernel checks the destination; this one is inaccessible.
        assert_eq!(
            unsafe { libc::ioctl(native.as_raw_fd(), libc::FIONREAD, native_fault.invalid) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EFAULT)
        );
        // Nothing was consumed: one read returns every record, as native, and
        // the counts drop to zero together.
        assert_eq!(
            guest_read(&mut state, &mut memory, fd, 4096),
            drain(native.as_raw_fd())
        );
        assert_eq!(count(&mut state, &mut memory, fd), 0);
        assert_eq!(queued(native.as_raw_fd()), 0);
    }
}
