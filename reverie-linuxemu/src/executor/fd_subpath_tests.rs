/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Guest paths below an fd link (`/proc/self/fd/<n>/<rest>`) resolve below
// the guest descriptor they name, with native Linux answers, and never
// reach the supervisor process's own descriptor table. The supervisor
// plants a secret at a known descriptor number the guest does not hold:
// before the executor parsed fd-link prefixes, the literal spelling was
// forwarded to a host openat2 and read that descriptor (or answered
// ENOENT/ELOOP by supervisor occupancy timing).

/// Open `path` in the guest at guest address 0x100 with `flags`.
fn guest_open(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    path: &str,
    flags: libc::c_int,
) -> i64 {
    write_c_string(memory, 0x100, path);
    syscall_result(
        memory,
        state,
        libc::SYS_openat,
        [libc::AT_FDCWD as u64, 0x100, flags as u64, 0, 0, 0],
    )
}

/// Read up to 64 bytes from guest descriptor `fd` at guest address 0x300.
fn guest_read(memory: &mut GuestMemory, state: &mut LoadedStaticElf, fd: i64) -> Vec<u8> {
    let count = syscall_result(
        memory,
        state,
        libc::SYS_read,
        [fd as u64, 0x300, 64, 0, 0, 0],
    );
    assert!(count >= 0, "read from guest fd {fd}: {count}");
    let mut bytes = vec![0u8; count as usize];
    memory.read(0x300, &mut bytes).unwrap();
    bytes
}

/// Stat `path` in the guest (result only; the stat buffer is at 0x400).
fn guest_stat(memory: &mut GuestMemory, state: &mut LoadedStaticElf, path: &str) -> i64 {
    write_c_string(memory, 0x100, path);
    syscall_result(
        memory,
        state,
        libc::SYS_newfstatat,
        [libc::AT_FDCWD as u64, 0x100, 0x400, 0, 0, 0],
    )
}

#[test]
fn fd_link_subpaths_resolve_below_the_guest_descriptor() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sentinel")).unwrap();
    std::fs::write(root.0.join("sentinel/marker"), b"guest-marker").unwrap();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();

    let dir = guest_open(&mut memory, &mut state, "sentinel", libc::O_RDONLY);
    assert!(dir >= 0, "open sentinel dir: {dir}");
    let opened = guest_open(
        &mut memory,
        &mut state,
        &format!("/proc/self/fd/{dir}/marker"),
        libc::O_RDONLY,
    );
    assert!(opened >= 0, "open below dir fd link: {opened}");
    assert_eq!(guest_read(&mut memory, &mut state, opened), b"guest-marker");
    assert_eq!(
        guest_stat(
            &mut memory,
            &mut state,
            &format!("/proc/self/fd/{dir}/marker")
        ),
        0
    );

    // The same through an O_PATH directory descriptor: the kernel
    // resolves the magic link to the directory and continues below it.
    let dir = guest_open(
        &mut memory,
        &mut state,
        "sentinel",
        libc::O_PATH | libc::O_DIRECTORY,
    );
    assert!(dir >= 0, "open sentinel dir O_PATH: {dir}");
    let opened = guest_open(
        &mut memory,
        &mut state,
        &format!("/proc/self/fd/{dir}/marker"),
        libc::O_RDONLY,
    );
    assert!(opened >= 0, "open below O_PATH dir fd link: {opened}");
    assert_eq!(guest_read(&mut memory, &mut state, opened), b"guest-marker");

    // Below a regular-file descriptor the kernel answers ENOTDIR.
    let file = guest_open(
        &mut memory,
        &mut state,
        "sentinel/marker",
        libc::O_RDONLY,
    );
    assert!(file >= 0, "open marker file: {file}");
    assert_eq!(
        guest_open(
            &mut memory,
            &mut state,
            &format!("/proc/self/fd/{file}/marker"),
            libc::O_RDONLY
        ),
        negative_errno(libc::ENOTDIR)
    );
}

/// Every kernel-equivalent spelling of a path below an fd link answers
/// as the native kernel answers for the same spelling on a native
/// descriptor (the oracle runs in this test process), and every
/// spelling answers ENOENT for a descriptor number only the supervisor
/// holds.
#[test]
fn fd_link_spellings_match_the_native_oracle() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("sentinel")).unwrap();
    std::fs::write(root.0.join("sentinel/marker"), b"guest-marker").unwrap();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let guest_dir = guest_open(&mut memory, &mut state, "sentinel", libc::O_RDONLY);
    assert!(guest_dir >= 0, "open sentinel dir: {guest_dir}");

    // The supervisor's plant, at a number the guest does not hold:
    // F_DUPFD_CLOEXEC from 4000 picks a free number atomically, so
    // parallel tests in this process cannot plant at the same one.
    let secret = std::fs::File::open(root.0.join("sentinel")).unwrap();
    // SAFETY: fcntl duplicates the descriptor `secret` owns; it returns a new descriptor or -1.
    let planted = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4000) };
    assert!(planted >= 4000, "planting supervisor descriptor: {planted}");
    // SAFETY: fcntl just returned this new descriptor (checked above), and nothing else owns it.
    let _planted =
        unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(planted) };

    // The native oracle descriptor: this process's own dir fd.
    let native_dir = std::fs::File::open(root.0.join("sentinel")).unwrap();
    let native_fd = native_dir.as_raw_fd();
    // SAFETY: gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };

    // Spelling templates over a dir fd; `F` is the descriptor number and
    // `T` the caller's tid (guest tid 1, native this thread's).
    let templates = [
        "/proc/self/fd/F/marker",
        "//proc/self/fd/F/marker",
        "/proc//self/fd/F/marker",
        "/proc/./self/fd/F/marker",
        "/proc/self/./fd/F/marker",
        "/proc/self/fd//F/marker",
        "/proc/self/fd/./F/marker",
        "/proc/self/fd/../fd/F/marker",
        "/proc/self/fd/F//marker",
        "/proc/self/task/T/fd/F/marker",
        "/proc/self/task/424242/fd/F/marker",
        "/proc/thread-self/task/T/fd/F/marker",
        "/proc/self/fd/0F/marker",
    ];
    for template in templates {
        let guest_path = template
            .replace('F', &guest_dir.to_string())
            .replace('T', "1");
        let native_path = template
            .replace('F', &native_fd.to_string())
            .replace('T', &tid.to_string());
        // Native outcome: read the marker, or the errno.
        let native = std::fs::read(&native_path).map_err(|err| err.raw_os_error());
        let guest_fd = guest_open(&mut memory, &mut state, &guest_path, libc::O_RDONLY);
        match (native, guest_fd) {
            (Ok(bytes), fd) if fd >= 0 => {
                assert_eq!(
                    guest_read(&mut memory, &mut state, fd),
                    bytes,
                    "{template}"
                );
            }
            (Err(Some(errno)), fd) => {
                assert_eq!(fd, negative_errno(errno), "{template}");
            }
            (native, fd) => panic!("{template}: native {native:?}, guest fd {fd}"),
        }
        // The planted supervisor number answers ENOENT through the same
        // spelling, whatever the oracle says for its own descriptor.
        let planted_path = template
            .replace('F', &planted.to_string())
            .replace('T', "1");
        assert_eq!(
            guest_open(&mut memory, &mut state, &planted_path, libc::O_RDONLY),
            negative_errno(libc::ENOENT),
            "{template} reached the supervisor's descriptor {planted}"
        );
    }
}

/// The /dev/fd ".." escape: /dev/fd is a symlink to /proc/self/fd, so
/// the kernel resolves /dev/fd/../task/<tid>/fd/<n> through the
/// caller's own task spellings. With the supervisor's real tid and a
/// planted supervisor directory descriptor, the literal forward this
/// used to take read the supervisor's marker; the guest must now
/// answer ENOENT for open and stat.
#[test]
fn dev_fd_dotdot_task_spellings_never_reach_the_supervisor() {
    let root = TestDir::new();
    std::fs::create_dir(root.0.join("planted-dir")).unwrap();
    std::fs::write(root.0.join("planted-dir/secret"), b"supervisor-secret").unwrap();
    let secret = std::fs::File::open(root.0.join("planted-dir")).unwrap();
    // SAFETY: fcntl duplicates the descriptor `secret` owns; it returns a new descriptor or -1.
    let planted = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4000) };
    assert!(planted >= 4000, "planting supervisor descriptor: {planted}");
    // SAFETY: fcntl just returned this new descriptor (checked above), and nothing else owns it.
    let _planted =
        unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(planted) };
    // SAFETY: gettid takes no arguments and cannot fail.
    let supervisor_tid = unsafe { libc::syscall(libc::SYS_gettid) };

    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    for spelling in [
        format!("/dev/fd/../task/{supervisor_tid}/fd/{planted}"),
        format!("/dev/fd/../task/{supervisor_tid}/fd/{planted}/secret"),
        format!("/dev/stdin/../task/{supervisor_tid}/fd/{planted}/secret"),
        format!("/dev/stdout/../task/{supervisor_tid}/fd/{planted}"),
    ] {
        assert_eq!(
            guest_open(&mut memory, &mut state, &spelling, libc::O_RDONLY),
            negative_errno(libc::ENOENT),
            "{spelling} reached the supervisor's descriptor {planted}"
        );
        assert_eq!(
            guest_stat(&mut memory, &mut state, &spelling),
            negative_errno(libc::ENOENT),
            "{spelling} reached the supervisor's descriptor {planted}"
        );
    }
}

#[test]
fn fd_link_spellings_never_reach_the_supervisors_descriptors() {
    let root = TestDir::new();
    std::fs::write(root.0.join("supervisor-secret"), b"supervisor-secret").unwrap();
    // Plant the secret at a supervisor (this process) descriptor number
    // the guest does not hold: F_DUPFD_CLOEXEC from 4000 picks a free
    // number atomically, far above anything the guest allocates here.
    let secret = std::fs::File::open(root.0.join("supervisor-secret")).unwrap();
    // SAFETY: fcntl duplicates the descriptor `secret` owns; it returns a new descriptor or -1.
    let planted_fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4000) };
    assert!(planted_fd >= 4000, "planting supervisor descriptor: {planted_fd}");
    // Owns only the planted number; `secret` keeps its own descriptor.
    // SAFETY: fcntl just returned this new descriptor (checked above), and nothing else owns it.
    let _planted =
        unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(planted_fd) };

    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    for spelling in [
        format!("/proc/self/fd/{planted_fd}"),
        format!("/proc/self/fd/{planted_fd}/anything"),
        format!("/proc/1/fd/{planted_fd}"),
        format!("/proc/424242/fd/{planted_fd}"),
        format!("/proc/424242/fd/{planted_fd}/anything"),
    ] {
        assert_eq!(
            guest_open(&mut memory, &mut state, &spelling, libc::O_RDONLY),
            negative_errno(libc::ENOENT),
            "{spelling} reached the supervisor's descriptor {planted_fd}"
        );
        assert_eq!(
            guest_stat(&mut memory, &mut state, &spelling),
            negative_errno(libc::ENOENT),
            "{spelling} reached the supervisor's descriptor {planted_fd}"
        );
    }
}

/// An exact fd-link spelling (`/proc/self/fd/<n>`, `/dev/fd/<n>`) splits on
/// whether the guest holds descriptor `<n>`. Exec opens its path without
/// following magic links, so a held descriptor is refused with ELOOP, the
/// errno Linux gives a magic link it will not follow; stat answers for the
/// held descriptor's file. A number only the supervisor holds is ENOENT for
/// both, as Linux answers for an fd that is not open. The image reader is
/// checked directly too: a `#!` interpreter is read through it.
#[test]
fn exact_fd_link_exec_and_stat_split_on_whether_the_guest_holds_the_descriptor() {
    let root = TestDir::new();
    std::fs::write(root.0.join("program"), b"program image").unwrap();
    // The supervisor's plant, at a number the guest does not hold.
    let secret = std::fs::File::open(root.0.join("program")).unwrap();
    // SAFETY: fcntl duplicates the descriptor `secret` owns; it returns a new descriptor or -1.
    let planted = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4000) };
    assert!(planted >= 4000, "planting supervisor descriptor: {planted}");
    // SAFETY: fcntl just returned this new descriptor (checked above), and nothing else owns it.
    let _planted =
        unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(planted) };

    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, 2 * PAGE_SIZE as usize).unwrap();
    let held = guest_open(&mut memory, &mut state, "program", libc::O_RDONLY);
    assert!(held >= 0, "open program: {held}");
    let envp = Vec::new();
    let spellings = |fd: i64| [format!("/proc/self/fd/{fd}"), format!("/dev/fd/{fd}")];

    for spelling in spellings(held) {
        assert_eq!(
            resolve_guest_exec_image(&state, spelling.clone().into_bytes(), &envp, &mut None)
                .err(),
            Some(negative_errno(libc::ELOOP)),
            "exec {spelling} of a held descriptor"
        );
        assert_eq!(
            read_executable_file(&state, std::path::Path::new(&spelling), &mut None).err(),
            Some(negative_errno(libc::ELOOP)),
            "read image {spelling} of a held descriptor"
        );
        assert_eq!(
            guest_stat(&mut memory, &mut state, &spelling),
            0,
            "stat {spelling} of a held descriptor"
        );
    }
    for spelling in spellings(i64::from(planted)) {
        assert_eq!(
            resolve_guest_exec_image(&state, spelling.clone().into_bytes(), &envp, &mut None)
                .err(),
            Some(negative_errno(libc::ENOENT)),
            "exec {spelling} reached the supervisor's descriptor {planted}"
        );
        assert_eq!(
            read_executable_file(&state, std::path::Path::new(&spelling), &mut None).err(),
            Some(negative_errno(libc::ENOENT)),
            "read image {spelling} reached the supervisor's descriptor {planted}"
        );
        assert_eq!(
            guest_stat(&mut memory, &mut state, &spelling),
            negative_errno(libc::ENOENT),
            "stat {spelling} reached the supervisor's descriptor {planted}"
        );
    }
}
