// These controls qualify only ordinary syncfs and conservative ENOSYS refusal.
// PR610's authenticated carrier/EBADMSG contract remains separate.

fn syncfs_memfd(name: &str) -> std::fs::File {
    let name = CString::new(name).unwrap();
    // SAFETY: name is terminated; successful memfd_create transfers one fd.
    let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(raw >= 0);
    unsafe { std::fs::File::from_raw_fd(raw) }
}

fn syncfs_call(memory: &mut GuestMemory, state: &mut LoadedStaticElf, fd: u64) -> i64 {
    syscall_result(memory, state, libc::SYS_syncfs, [fd, 0, 0, 0, 0, 0])
}

#[test]
fn syncfs_dispatch_one_translated_host_call_preserves_each_errno() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut ordinary = syncfs_memfd("syncfs-ordinary");
    ordinary.write_all(SYSTEM_STAT_CONTENT).unwrap();
    let memfd = insert_file_with_flags(&mut state, ordinary, false, None);
    let [reader, _writer] = pipe_fionread_host_pipe();
    let pipe = insert_file_with_flags(&mut state, reader, false, None);
    let (socket, _peer) = UnixStream::pair().unwrap();
    let socket = insert_file_with_flags(
        &mut state,
        std::fs::File::from(std::os::fd::OwnedFd::from(socket)),
        false,
        None,
    );
    let path = root.0.join("ordinary");
    std::fs::write(&path, b"ordinary").unwrap();
    let regular =
        insert_file_with_flags(&mut state, std::fs::File::open(&path).unwrap(), false, None);
    let directory = insert_file_with_flags(
        &mut state,
        std::fs::File::open(&root.0).unwrap(),
        false,
        None,
    );
    let fds = [memfd, pipe, socket, regular, directory];
    let hosts: Vec<_> = fds
        .iter()
        .map(|fd| host_fd(&state, *fd as i32).unwrap())
        .collect();
    assert_ne!(
        hosts[0], fds[0] as i32,
        "misdirection control must distinguish guest and host numbers"
    );
    // Native controls make the admitted backing-type contract explicit.
    for &host in &hosts {
        assert_eq!(unsafe { libc::syncfs(host) }, 0);
    }
    let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = calls.clone();
    let results = [0, libc::EIO, libc::ENOSPC, libc::EDQUOT, libc::EINTR];
    let _hook = install_syncfs_test_hook(move |actual| {
        let index = observed.borrow().len();
        observed.borrow_mut().push(actual);
        let error = results[index];
        if error == 0 {
            0
        } else {
            unsafe { *libc::__errno_location() = error };
            -1
        }
    });
    for (&fd, error) in fds.iter().zip(results) {
        assert_eq!(
            syncfs_call(&mut memory, &mut state, (0xa5a5_5a5a_u64 << 32) | fd as u64),
            -i64::from(error),
        );
    }
    assert_eq!(
        *calls.borrow(),
        hosts,
        "one call to each translated host, including EINTR"
    );
}

#[test]
fn syncfs_closed_and_path_only_precede_private_refusal_without_host_call() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let _hook = install_syncfs_test_hook(|_| panic!("invalid fd reached host syncfs"));
    for raw in [
        u64::MAX,
        u32::MAX as u64,
        i32::MIN as u32 as u64,
        i32::MAX as u64,
        GUEST_NOFILE_LIMIT as u64,
    ] {
        assert_eq!(
            syncfs_call(&mut memory, &mut state, raw),
            negative_errno(libc::EBADF)
        );
    }
    for path in ["/proc/stat", root.0.to_str().unwrap()] {
        let fd = open_with_flags(&mut memory, &mut state, path, libc::O_PATH);
        assert!(fd >= 0);
        assert_eq!(
            unsafe { libc::syncfs(host_fd(&state, fd as i32).unwrap()) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            syncfs_call(&mut memory, &mut state, fd as u64),
            negative_errno(libc::EBADF)
        );
        assert_eq!(close(&mut state, fd as u64), 0);
        assert_eq!(
            syncfs_call(&mut memory, &mut state, fd as u64),
            negative_errno(libc::EBADF)
        );
    }
}

// The backend creates a memfd named reverie-kvm-virtual-file only in a run that
// reports host metadata timestamps. In any other run the name belongs to the
// guest, and the guest's memfd is an ordinary file that Linux syncfs serves.
#[test]
fn syncfs_reserves_the_virtual_file_carrier_name_only_when_the_backend_creates_it() {
    let root = TestDir::new();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    for host_metadata_timestamps in [false, true] {
        let mut state = test_state(&root.0);
        state.host_metadata_timestamps = host_metadata_timestamps;
        let mut file = syncfs_memfd("reverie-kvm-virtual-file");
        file.write_all(b"guest bytes\n").unwrap();
        let host = file.as_raw_fd();
        let fd = insert_file_with_flags(&mut state, file, false, None);
        let seen = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = seen.clone();
        let hook = install_syncfs_test_hook(move |actual| {
            assert_eq!(actual, host);
            observed.set(observed.get() + 1);
            0
        });
        let (expected, calls) = if host_metadata_timestamps {
            (negative_errno(libc::ENOSYS), 0)
        } else {
            (0, 1)
        };
        assert_eq!(
            syncfs_call(&mut memory, &mut state, fd as u64),
            expected,
            "host_metadata_timestamps={host_metadata_timestamps}"
        );
        assert_eq!(
            seen.get(),
            calls,
            "host_metadata_timestamps={host_metadata_timestamps}"
        );
        drop(hook);
        assert_eq!(close(&mut state, fd as u64), 0);
    }
}

#[test]
fn syncfs_reserved_names_deny_without_authenticating_payload_or_seals() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let _hook = install_syncfs_test_hook(|_| panic!("reserved private name reached host syncfs"));
    for name in [
        "reverie-kvm-proc",
        "reverie-kvm-virtual",
        "reverie-kvm-guest-memory",
        "reverie-kvm.proc-carrier.v1",
        "reverie-kvm.proc-carrier.v1.forged",
        "reverie-kvm.capture-transfer.v1",
        "reverie-kvm.capture-transfer.v1.forged",
    ] {
        let mut file = syncfs_memfd(name);
        file.write_all(b"not authenticated\n").unwrap();
        let fd = insert_file_with_flags(&mut state, file, false, None);
        assert!(!state.proc_files.contains_key(&(fd as i32)));
        assert_eq!(
            syncfs_call(&mut memory, &mut state, fd as u64),
            negative_errno(libc::ENOSYS),
            "{name}"
        );
        assert_eq!(close(&mut state, fd as u64), 0);
    }
    drop(_hook);
    for name in [
        "syncfs-ordinary",
        "reverie-kvm-proc-ordinary",
        "reverie-kvm-virtual-ordinary",
    ] {
        let mut file = syncfs_memfd(name);
        file.write_all(SYSTEM_STAT_CONTENT).unwrap();
        let host = file.as_raw_fd();
        let fd = insert_file_with_flags(&mut state, file, false, None);
        let seen = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = seen.clone();
        let _hook = install_syncfs_test_hook(move |actual| {
            assert_eq!(actual, host);
            observed.set(observed.get() + 1);
            0
        });
        assert_eq!(syncfs_call(&mut memory, &mut state, fd as u64), 0, "{name}");
        assert_eq!(
            seen.get(),
            1,
            "ordinary payload is not a synthetic identity"
        );
    }
}

// Real SCM_RIGHTS, through the production outgoing and received translators.
// Close and reuse the sender slot while the kernel message owns the old file.
fn syncfs_transfer_after_sender_close(
    state: &mut LoadedStaticElf,
    fd: i32,
    replacement: &Path,
) -> i32 {
    let (sender, receiver) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let mut control = [0_usize; 4];
    let mut byte = b'x';
    let mut vector = libc::iovec {
        iov_base: std::ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(4) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<i32>(), fd);
    }
    let outgoing = unsafe {
        std::slice::from_raw_parts_mut(message.msg_control.cast::<u8>(), message.msg_controllen)
    };
    translate_outgoing_control(outgoing, state).unwrap();
    assert_eq!(unsafe { libc::sendmsg(sender.as_raw_fd(), &message, 0) }, 1);
    assert_eq!(close(state, fd as u64), 0);
    assert_eq!(
        insert_file_with_flags(
            state,
            std::fs::File::open(replacement).unwrap(),
            false,
            None
        ),
        i64::from(fd)
    );
    control.fill(0);
    message.msg_controllen = std::mem::size_of_val(&control);
    assert_eq!(
        unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) },
        1
    );
    assert_eq!(message.msg_flags, libc::MSG_CMSG_CLOEXEC);
    let received = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!((*header).cmsg_len, libc::CMSG_LEN(4) as usize);
        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>())
    };
    assert!(received >= 0);
    let mut guest_control = [0_u8; 4];
    let installed = install_received_rights(
        state,
        &mut guest_control,
        vec![PendingReceivedRight {
            control_offset: 0,
            file: unsafe { std::fs::File::from_raw_fd(received) },
        }],
        false,
        false,
    )
    .unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0], i32::from_ne_bytes(guest_control));
    installed[0]
}

#[test]
fn syncfs_private_rights_remain_refused_after_sender_reuse_dup_fork_exec() {
    let root = TestDir::new();
    let replacement = root.0.join("replacement");
    std::fs::write(&replacement, SYSTEM_STAT_CONTENT).unwrap();
    for path in [
        "/proc/stat",
        "/proc/self/loginuid",
        "/proc/self/stat",
        "/proc/self/status",
    ] {
        let mut state = test_state(&root.0);
        let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
        let original = open_readonly(&mut memory, &mut state, path) as i32;
        assert!(original >= 0, "{path}");
        let original_key = host_file_key(host_fd(&state, original).unwrap()).unwrap();
        let received = syncfs_transfer_after_sender_close(&mut state, original, &replacement);
        assert_eq!(
            host_file_key(host_fd(&state, received).unwrap()).unwrap(),
            original_key
        );
        if matches!(path, "/proc/stat" | "/proc/self/loginuid") {
            assert!(
                !state.proc_files.contains_key(&received),
                "real transfer loses fixed/virtual metadata"
            );
            assert!(!state.fdinfo_files.contains_key(&received));
        }
        let alias = duplicate_fd(&mut state, received as u64, None, 0, false) as i32;
        assert!(alias > received);
        let mut child = state.try_clone_for_fork(2).unwrap();
        assert_eq!(close(&mut state, received as u64), 0);
        assert_eq!(close(&mut state, alias as u64), 0);
        let _hook = install_syncfs_test_hook(|_| panic!("private transfer reached host syncfs"));
        for fd in [received, alias] {
            assert_eq!(
                syncfs_call(&mut memory, &mut child, fd as u64),
                negative_errno(libc::ENOSYS),
                "{path} fork fd={fd}"
            );
        }
        let mut exec = test_state(&root.0);
        exec.inherit_process_state(child);
        for fd in [received, alias] {
            assert_eq!(
                syncfs_call(&mut memory, &mut exec, fd as u64),
                negative_errno(libc::ENOSYS),
                "{path} exec fd={fd}"
            );
        }
        drop(_hook);
        // Reusing the sender's guest slot for ordinary same-content storage
        // must not poison that slot, even while old aliases remain refused.
        let expected = host_fd(&exec, original).unwrap();
        let _hook = install_syncfs_test_hook(move |host| {
            assert_eq!(host, expected);
            0
        });
        assert_eq!(syncfs_call(&mut memory, &mut exec, original as u64), 0);
    }
}

#[test]
fn syncfs_known_private_descriptions_are_refused_without_host_call() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut fds = Vec::new();
    for path in [
        "/proc/stat",
        "/proc/self/stat",
        "/proc/self/status",
        "/proc",
        "/dev/urandom",
        "/proc/self/loginuid",
    ] {
        let fd = open_readonly(&mut memory, &mut state, path);
        assert!(fd >= 0, "{path}: {fd}");
        fds.push(fd);
    }
    memory.write(0x100, &[0; KERNEL_SIGSET_SIZE]).unwrap();
    let signal = syscall_result(
        &mut memory,
        &mut state,
        libc::SYS_signalfd4,
        [
            u64::MAX,
            0x100,
            KERNEL_SIGSET_SIZE as u64,
            libc::SFD_NONBLOCK as u64,
            0,
            0,
        ],
    );
    assert!(signal >= 0);
    fds.push(signal);
    let _hook = install_syncfs_test_hook(|_| panic!("known private object reached host syncfs"));
    for fd in fds {
        assert_eq!(
            syncfs_call(&mut memory, &mut state, fd as u64),
            negative_errno(libc::ENOSYS),
            "fd={fd}"
        );
    }
    // Fdinfo needs a live executor table; a standalone test_state deliberately
    // cannot open one. Exercise the actual executor binding, not a forged map.
    let mut fixture = FdinfoFixture::new(true);
    let target = fixture.open("a", libc::O_RDONLY);
    let info = fixture.info(target);
    assert_eq!(
        fixture.call(libc::SYS_syncfs, [info as u64, 0, 0, 0, 0, 0]),
        negative_errno(libc::ENOSYS)
    );
}

#[test]
fn syncfs_owned_fork_snapshot_keeps_the_target_after_sender_close_reuse() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let fd = insert_file_with_flags(&mut state, syncfs_memfd("old-ordinary"), false, None) as i32;
    let original = host_file_key(host_fd(&state, fd).unwrap()).unwrap();
    let mut child = state.try_clone_for_fork(2).unwrap();
    assert_eq!(close(&mut state, fd as u64), 0);
    assert_eq!(
        insert_file_with_flags(&mut state, syncfs_memfd("new-ordinary"), false, None),
        i64::from(fd)
    );
    assert_ne!(
        host_file_key(host_fd(&state, fd).unwrap()).unwrap(),
        original
    );
    let called = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = called.clone();
    let _hook = install_syncfs_test_hook(move |host| {
        assert!(!observed.replace(true));
        assert_eq!(host_file_key(host).unwrap(), original);
        0
    });
    assert_eq!(syncfs_call(&mut memory, &mut child, fd as u64), 0);
    assert!(called.get());
}

#[test]
fn syncfs_capture_backings_and_missing_identity_fail_closed_but_replacements_work() {
    const TEST: &str = "executor::tests::syncfs_capture_backings_and_missing_identity_fail_closed_but_replacements_work";
    let Ok(mode) = std::env::var("REVERIE_SYNCFS_CAPTURE_CHILD") else {
        for mode in ["regular", "pipe", "socket", "character", "missing"] {
            let record = TestDir::new();
            let log = record.0.join("libtest.log");
            let output = std::process::Command::new("timeout")
                .args(["--kill-after=2s", "10s"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--logfile"])
                .arg(&log)
                .env("REVERIE_SYNCFS_CAPTURE_CHILD", mode)
                .output()
                .unwrap();
            assert!(output.status.success(), "mode={mode}: {output:?}");
            assert_eq!(
                std::fs::read_to_string(log).unwrap(),
                format!("ok {TEST}\n"),
                "mode={mode}"
            );
        }
        return;
    };
    let root = TestDir::new();
    let replacement = root.0.join("ordinary-replacement");
    std::fs::write(&replacement, b"ordinary").unwrap();
    let backing = root.0.join("captured-backing");
    std::fs::write(&backing, b"supervisor output").unwrap();
    let [pipe_reader, pipe_writer] = pipe_fionread_host_pipe();
    let (socket, socket_peer) = UnixStream::pair().unwrap();
    let endpoint = match mode.as_str() {
        "pipe" => pipe_writer,
        "socket" => std::fs::File::from(std::os::fd::OwnedFd::from(socket)),
        "character" => std::fs::File::open("/dev/null").unwrap(),
        _ => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backing)
            .unwrap(),
    };
    let stdout_restore = RedirectedStandardFd::new(1, &endpoint);
    let stderr_restore = RedirectedStandardFd::new(2, &endpoint);
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut output = CapturedOutput::default();
    // First export a captured alias. The actual send/receive drops alias
    // metadata; host stdio retains the original object after guest close/reuse.
    let alias = duplicate_fd(&mut state, 1, None, 0, false) as i32;
    assert!(alias >= 3);
    let received = syncfs_transfer_after_sender_close(&mut state, alias, &replacement);
    assert!(output_alias(&state, received).is_none());
    let received_alias = duplicate_fd(&mut state, received as u64, None, 0, false) as i32;
    let _hook = install_syncfs_test_hook(|_| panic!("captured backing reached host syncfs"));
    for fd in [1, 2, received, received_alias] {
        assert_eq!(
            syscall_result_with_output(
                &mut memory,
                &mut state,
                &mut output,
                libc::SYS_syncfs,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            negative_errno(libc::ENOSYS)
        );
    }
    // Ordinary replacements of both guest standard numbers are admitted even
    // in capture mode; stale implicit/alias metadata cannot decide by number.
    for fd in [1, 2] {
        assert_eq!(close(&mut state, fd), 0);
        assert_eq!(
            insert_file_with_flags(
                &mut state,
                std::fs::File::open(&replacement).unwrap(),
                false,
                None
            ),
            fd as i64
        );
    }
    let child = state.try_clone_for_fork(2).unwrap();
    let mut exec = test_state(&root.0);
    exec.inherit_process_state(child);
    for fd in [received, received_alias] {
        assert_eq!(
            sync_filesystem(&exec, fd as u64, true),
            negative_errno(libc::ENOSYS)
        );
    }
    if mode == "missing" {
        assert_eq!(unsafe { libc::close(2) }, 0);
        // No allocation or executor snapshot after close: it must remain
        // missing, rather than be reused for an unrelated cloned descriptor.
        assert_eq!(
            sync_filesystem(&exec, 1, true),
            negative_errno(libc::ENOSYS)
        );
    } else {
        drop(_hook);
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed = calls.clone();
        let _hook = install_syncfs_test_hook(move |host| {
            observed.borrow_mut().push(host);
            0
        });
        for fd in [1, 2] {
            assert_eq!(sync_filesystem(&exec, fd, true), 0);
        }
        assert_eq!(
            *calls.borrow(),
            vec![host_fd(&exec, 1).unwrap(), host_fd(&exec, 2).unwrap()]
        );
    }
    drop(stderr_restore);
    drop(stdout_restore);
    drop(pipe_reader);
    drop(socket_peer);
}
