/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included in executor::tests so the guest memory fixture and canaries are the
// ones the zero-read tests use.
mod descriptor_check_order_tests {
    use std::ffi::CStr;

    use super::*;

    fn open_fixture(path: &CStr, flags: libc::c_int) -> std::fs::File {
        // SAFETY: path is terminated and a successful open returns a new fd.
        let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
        assert!(fd >= 0, "open {path:?}");
        // SAFETY: the descriptor was just opened and is owned here.
        unsafe { std::fs::File::from_raw_fd(fd) }
    }

    fn epoll_fixture() -> std::fs::File {
        // SAFETY: epoll_create1 returns a new descriptor on success.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: the descriptor was just created and is owned here.
        unsafe { std::fs::File::from_raw_fd(fd) }
    }

    /// An O_PATH handle to an inotify instance, reopened through its proc
    /// link: the access check must refuse it before any inotify handling.
    fn inotify_path_fixture() -> std::fs::File {
        // SAFETY: inotify_init1 returns a new descriptor on success.
        let inotify = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(inotify >= 0);
        // SAFETY: the descriptor was just created and is owned here.
        let inotify = unsafe { std::fs::File::from_raw_fd(inotify) };
        let link = std::ffi::CString::new(format!("/proc/self/fd/{}", inotify.as_raw_fd())).unwrap();
        open_fixture(&link, libc::O_PATH)
    }

    /// A scalar read refuses a descriptor before it looks at the destination,
    /// with one access-mode query and one fstat that the inotify probe
    /// shares. For every descriptor the checks refuse, every destination,
    /// valid or not, gives the checks' error.
    #[test]
    fn scalar_read_descriptor_errors_do_not_depend_on_the_destination() {
        let directory = open_fixture(c".", libc::O_RDONLY | libc::O_DIRECTORY);
        assert_read_zero_fixture_filesystem(&directory);
        for (name, file) in [
            ("directory", directory),
            ("path", open_fixture(c".", libc::O_PATH)),
            ("write-only", open_fixture(c"/dev/null", libc::O_WRONLY)),
            ("epoll", epoll_fixture()),
            ("inotify-path", inotify_path_fixture()),
        ] {
            let expected = ensure_read_capable(&file)
                .and_then(|()| ensure_readable(&file))
                .expect_err("each fixture is refused by the descriptor checks");
            let mut state = test_state(&std::env::current_dir().unwrap());
            state.files.insert(3, file);
            let mut memory = read_zero_memory();
            for address in READ_ZERO_ADDRESSES {
                // Linux checks the address (access_ok) before a directory's
                // read op, so it answers EFAULT for these two noncanonical
                // addresses where the checked path answers EISDIR. That
                // existing difference is not this test's subject, and the
                // test does not pin either answer.
                if name == "directory" && address >= 0x8000_0000_0000_0000 {
                    continue;
                }
                assert_eq!(
                    syscall_result(
                        &mut memory,
                        &mut state,
                        libc::SYS_read,
                        [3, address, 16, 0, 0, 0],
                    ),
                    expected,
                    "{name} address={address:#x}"
                );
                assert_read_zero_canaries(&memory);
            }
        }
    }

    /// A `recvmmsg` timeout Linux cannot use is EINVAL before the
    /// descriptor is checked, as is `MSG_CMSG_COMPAT`, and an unreadable
    /// timeout pointer is EFAULT first (`do_recvmmsg`,
    /// net/socket.c:2934-2947 at v6.17): with a descriptor that does not
    /// exist, a usable or absent timeout is the only way to reach EBADF.
    /// Before this the executor never read the argument, so an invalid
    /// timeout became a would-block the caller polled on forever.
    #[test]
    fn recvmmsg_argument_errors_precede_the_descriptor_check() {
        const TIMEOUT: u64 = 0x200;
        const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
        let einval = -(libc::EINVAL as i64);
        let ebadf = -(libc::EBADF as i64);
        let efault = -(libc::EFAULT as i64);
        let mut state = test_state(&std::env::current_dir().unwrap());
        let mut memory = read_zero_memory();
        let recvmmsg = |memory: &mut GuestMemory, state: &mut LoadedStaticElf, flags, timeout| {
            syscall_result(
                memory,
                state,
                libc::SYS_recvmmsg,
                [99, 0x300, 1, flags, timeout, 0],
            )
        };
        assert_eq!(recvmmsg(&mut memory, &mut state, MSG_CMSG_COMPAT, 0), einval);
        assert_eq!(recvmmsg(&mut memory, &mut state, 0, 0), ebadf);
        assert_eq!(
            recvmmsg(&mut memory, &mut state, 0, READ_ZERO_PROTECTED),
            efault
        );
        for (label, tv_sec, tv_nsec, expected) in [
            ("both negative", -1_i64, -1_i64, einval),
            ("negative seconds", -1, 0, einval),
            ("nsec too large", 0, 1_000_000_000, einval),
            ("nsec negative", 0, -1, einval),
            ("zero", 0, 0, ebadf),
            ("one second", 1, 999_999_999, ebadf),
        ] {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&tv_sec.to_ne_bytes());
            bytes[8..].copy_from_slice(&tv_nsec.to_ne_bytes());
            memory.write(TIMEOUT, &bytes).unwrap();
            assert_eq!(
                recvmmsg(&mut memory, &mut state, 0, TIMEOUT),
                expected,
                "{label}"
            );
        }
    }
}
