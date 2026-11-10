// pidfds for other guest processes (`executor/pidfd.rs`) and the shadow sockets
// that show their readiness (`pidfd_shadow.rs`): Linux's answers from
// kernel/pid.c, kernel/exit.c and fs/pidfs.c, and the shadow's privacy: it is
// never a guest descriptor, every alias of the pidfd shares it, and it closes
// with the pidfd's last descriptor.

const PIDFD_TEST_MEMORY: usize = 4 * PAGE_SIZE as usize;
const PIDFD_TEST_POLL: u64 = 0x100;
const PIDFD_TEST_INFO: u64 = 0x200;
const PIDFD_TEST_STAT: u64 = 0x400;
const PIDFD_TEST_EVENT: u64 = 0x600;
const PIDFD_TEST_EVENTS: u64 = 0x700;
const PIDFD_TEST_PAIR: u64 = 0x800;
const PIDFD_TEST_MESSAGE: u64 = 0x900;
const PIDFD_TEST_IOV: u64 = 0xa00;
const PIDFD_TEST_CONTROL: u64 = 0xb00;
const PIDFD_TEST_BYTE: u64 = 0xc00;
/// Every event a pidfd reports, and every other event poll can be asked for,
/// which a pidfd never reports; its shadow socket would report `POLLOUT`,
/// `POLLWRNORM` and, once hung up, `POLLRDHUP`.
const PIDFD_TEST_EVENTS_ASKED: libc::c_short = libc::POLLIN
    | libc::POLLRDNORM
    | libc::POLLRDBAND
    | libc::POLLPRI
    | libc::POLLOUT
    | libc::POLLWRNORM
    | libc::POLLWRBAND
    | libc::POLLRDHUP;
const PIDFD_TEST_EXITED: libc::c_short = libc::POLLIN | libc::POLLRDNORM;
const PIDFD_TEST_REAPED: libc::c_short = libc::POLLIN | libc::POLLRDNORM | libc::POLLHUP;

fn pidfd_test_memory() -> GuestMemory {
    let memory = GuestMemory::new(0, PIDFD_TEST_MEMORY).unwrap();
    memory
        .map_user_permissions(0, PIDFD_TEST_MEMORY as u64, true, true)
        .unwrap();
    memory.enable_user_access();
    memory
}

/// A process with a live child process `child_pid`.
fn pidfd_test_family(root: &TestDir, child_pid: i32) -> (ElfExecutor, ElfExecutor) {
    let parent = ElfExecutor::new(test_state(&root.0), false);
    let child = parent.fork_child(child_pid, false, false).unwrap();
    (parent, child)
}

fn pidfd_test_call(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    number: libc::c_long,
    args: [u64; 6],
) -> i64 {
    executor.execute(&SyscallRequest::new(number as u64, args), memory)
}

fn pidfd_test_open(executor: &mut ElfExecutor, memory: &GuestMemory, pid: i64, flags: u64) -> i64 {
    pidfd_test_call(
        executor,
        memory,
        libc::SYS_pidfd_open,
        [pid as u64, flags, 0, 0, 0, 0],
    )
}

/// The events a zero-timeout poll of `fd` reports, asked for
/// `PIDFD_TEST_EVENTS_ASKED`.
fn pidfd_test_poll(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64) -> libc::c_short {
    let poll_fd = libc::pollfd {
        fd: fd as libc::c_int,
        events: PIDFD_TEST_EVENTS_ASKED,
        revents: 0,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_POLL, &poll_fd),
        0
    );
    let ready = pidfd_test_call(
        executor,
        memory,
        libc::SYS_poll,
        [PIDFD_TEST_POLL, 1, 0, 0, 0, 0],
    );
    let polled: libc::pollfd = read_struct(memory, PIDFD_TEST_POLL);
    assert_eq!(ready, i64::from(polled.revents != 0), "poll of {fd}");
    polled.revents
}

/// Ends `child`, its process's only task, with status 7, and publishes the
/// exit to its parent, which can then wait for it.
fn pidfd_test_exit(parent: &mut ElfExecutor, child: &mut ElfExecutor) {
    let identity = child.signal_task_identity().unwrap().process;
    child.retire_current_thread(reverie::ExitStatus::Exited(7), false);
    parent
        .record_child_completion(
            identity,
            ChildCompletion::Waitable(reverie::ExitStatus::Exited(7)),
        )
        .unwrap();
}

/// Reaps the exited child `child_pid`.
fn pidfd_test_reap(parent: &mut ElfExecutor, memory: &GuestMemory, child_pid: i32) {
    assert_eq!(
        pidfd_test_call(
            parent,
            memory,
            libc::SYS_waitid,
            [
                libc::P_PID as u64,
                child_pid as u64,
                PIDFD_TEST_INFO,
                libc::WEXITED as u64,
                0,
                0
            ],
        ),
        0
    );
}

/// The guest descriptors of `executor`'s table.
fn pidfd_test_guest_fds(executor: &ElfExecutor) -> BTreeMap<i32, RawFd> {
    executor
        .state
        .files
        .copies()
        .iter()
        .map(|(&fd, file)| (fd, file.as_raw_fd()))
        .collect()
}

/// The (file type, inode) of host descriptor `fd`.
fn pidfd_test_host_identity(fd: RawFd) -> (libc::mode_t, u64) {
    // SAFETY: stat is plain data and fstat fills it.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fstat of a live descriptor into a stat of this frame.
    assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0, "fstat of {fd}");
    (stat.st_mode & libc::S_IFMT, stat.st_ino)
}

/// The shadow socket of a pidfd for another process is the supervisor's
/// alone. Opening the pidfd adds exactly one guest descriptor, the stand-in,
/// which takes the lowest free guest number, as Linux's pidfd_open does,
/// whatever host numbers the shadow took; the next descriptor the guest opens
/// takes the next one. The shadow, which the pidfd holds, and its write end,
/// which the registry holds, are sockets above the standard descriptors and
/// close-on-exec; neither is any guest descriptor's host descriptor or the
/// same socket as one, and a guest call that names the host number of either
/// names the guest's own descriptor of that number or none.
#[test]
fn a_pidfd_shadow_socket_never_enters_the_guest_descriptor_table() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    // The two lowest free guest numbers, found by a pipe that is then closed.
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_pipe2,
            [PIDFD_TEST_PAIR, 0, 0, 0, 0, 0]
        ),
        0
    );
    let mut ends = [0_u8; 8];
    memory.read_raw(PIDFD_TEST_PAIR, &mut ends).unwrap();
    let lowest = [
        i32::from_ne_bytes(ends[..4].try_into().unwrap()),
        i32::from_ne_bytes(ends[4..].try_into().unwrap()),
    ];
    for fd in lowest {
        assert_eq!(
            pidfd_test_call(
                &mut parent,
                &memory,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
    let before = pidfd_test_guest_fds(&parent);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert_eq!(
        fd,
        i64::from(lowest[0]),
        "pidfd_open takes the lowest free number"
    );
    let after = pidfd_test_guest_fds(&parent);
    let added: Vec<_> = after.keys().filter(|fd| !before.contains_key(fd)).collect();
    assert_eq!(added, [&(fd as i32)], "pidfd_open adds the stand-in alone");
    assert!(before.keys().all(|existing| after.contains_key(existing)));
    let shared: BTreeMap<i32, RawFd> = parent
        .file_table
        .lock()
        .unwrap()
        .files
        .iter()
        .map(|(&fd, file)| (fd, file.as_raw_fd()))
        .collect();
    assert_eq!(
        shared.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "the shared table holds the guest descriptors and no others"
    );
    // The stand-in reads as Linux names every pidfd.
    assert!(fd_link_target_is(
        after[&(fd as i32)],
        b"anon_inode:[pidfd]"
    ));

    let pidfd = parent.state.foreign_pidfds[&(fd as i32)].clone();
    let writers = parent.signal_registry.pidfd_shadow_writers(pidfd.target());
    assert_eq!(writers.len(), 1, "the registry holds the one write end");
    let shadow_fds = [pidfd.readiness_fd(), writers[0].as_raw_fd()];
    let shadows = shadow_fds.map(pidfd_test_host_identity);
    for (&end, identity) in shadow_fds.iter().zip(shadows) {
        assert_eq!(identity.0, libc::S_IFSOCK, "shadow descriptor {end}");
        assert!(end > libc::STDERR_FILENO, "shadow descriptor {end}");
        // SAFETY: F_GETFD of a live descriptor.
        let flags = unsafe { libc::fcntl(end, libc::F_GETFD) };
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "shadow descriptor {end}"
        );
    }
    for (&guest, &host) in after.iter().chain(&shared) {
        assert!(
            !shadow_fds.contains(&host),
            "guest descriptor {guest} is a shadow descriptor"
        );
        assert!(
            !shadows.contains(&pidfd_test_host_identity(host)),
            "guest descriptor {guest} is a shadow socket"
        );
    }

    let next = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        next,
        i64::from(lowest[1]),
        "the next descriptor takes the next number"
    );
    for end in shadow_fds {
        let named = pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_fstat,
            [end as u64, PIDFD_TEST_STAT, 0, 0, 0, 0],
        );
        if named == 0 {
            let stat: libc::stat = read_struct(&memory, PIDFD_TEST_STAT);
            assert!(
                !shadows.contains(&(stat.st_mode & libc::S_IFMT, stat.st_ino)),
                "guest descriptor {end} reached a shadow socket"
            );
        } else {
            assert_eq!(named, negative_errno(libc::EBADF), "guest fstat of {end}");
        }
    }
}

/// Every alias of a pidfd, from dup, dup2, dup3, F_DUPFD and fork, shares one
/// record and one shadow socket, so every alias in every process reports the
/// process's exit and its reaping, and closing one leaves the others
/// reporting. Two aliases go into one epoll set, as on Linux, where each
/// descriptor number is a registration of its own.
#[test]
fn dup_and_fork_of_a_pidfd_keep_one_shadow_socket() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let dup = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let dup2 = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup2,
        [fd as u64, 20, 0, 0, 0, 0],
    );
    let dup3 = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup3,
        [fd as u64, 21, libc::O_CLOEXEC as u64, 0, 0, 0],
    );
    let dupfd = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_fcntl,
        [fd as u64, libc::F_DUPFD as u64, 30, 0, 0, 0],
    );
    assert_eq!((dup2, dup3), (20, 21));
    assert!(dup >= 0 && dupfd >= 30);
    let aliases = [fd, dup, dup2, dup3, dupfd];
    let record = parent.state.foreign_pidfds[&(fd as i32)].clone();
    for alias in aliases {
        assert!(
            Arc::ptr_eq(&parent.state.foreign_pidfds[&(alias as i32)], &record),
            "alias {alias}"
        );
    }
    // A second child, forked after the pidfd was opened, holds it too.
    let mut sibling = parent.fork_child(3, false, false).unwrap();
    for alias in aliases {
        assert!(
            Arc::ptr_eq(&sibling.state.foreign_pidfds[&(alias as i32)], &record),
            "forked alias {alias}"
        );
    }

    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert!(epoll >= 0);
    for (data, alias) in [(11_u64, fd), (12, dup)] {
        let event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: data,
        };
        assert_eq!(
            write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_EVENT, &event),
            0
        );
        assert_eq!(
            pidfd_test_call(
                &mut parent,
                &memory,
                libc::SYS_epoll_ctl,
                [
                    epoll as u64,
                    libc::EPOLL_CTL_ADD as u64,
                    alias as u64,
                    PIDFD_TEST_EVENT,
                    0,
                    0
                ],
            ),
            0,
            "epoll_ctl ADD of alias {alias}"
        );
    }
    let epoll_wait = |parent: &mut ElfExecutor| {
        let ready = pidfd_test_call(
            parent,
            &memory,
            libc::SYS_epoll_wait,
            [epoll as u64, PIDFD_TEST_EVENTS, 4, 0, 0, 0],
        );
        (0..ready.max(0) as u64)
            .map(|index| {
                let event: libc::epoll_event = read_struct(
                    &memory,
                    PIDFD_TEST_EVENTS + index * std::mem::size_of::<libc::epoll_event>() as u64,
                );
                (event.u64, event.events)
            })
            .collect::<BTreeMap<_, _>>()
    };

    for alias in aliases {
        assert_eq!(
            pidfd_test_poll(&mut parent, &memory, alias),
            0,
            "alias {alias}"
        );
        assert_eq!(pidfd_test_poll(&mut sibling, &memory, alias), 0);
    }
    assert!(epoll_wait(&mut parent).is_empty());

    pidfd_test_exit(&mut parent, &mut child);
    for alias in aliases {
        assert_eq!(
            pidfd_test_poll(&mut parent, &memory, alias),
            PIDFD_TEST_EXITED,
            "alias {alias} after the exit"
        );
        assert_eq!(
            pidfd_test_poll(&mut sibling, &memory, alias),
            PIDFD_TEST_EXITED,
            "forked alias {alias} after the exit"
        );
    }
    let exited = libc::EPOLLIN as u32;
    assert_eq!(
        epoll_wait(&mut parent),
        BTreeMap::from([(11, exited), (12, exited)])
    );

    // Closing one alias leaves every other one reporting.
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [dup as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    pidfd_test_reap(&mut parent, &memory, 2);
    for alias in [fd, dup2, dup3, dupfd] {
        assert_eq!(
            pidfd_test_poll(&mut parent, &memory, alias),
            PIDFD_TEST_REAPED,
            "alias {alias} after the reap"
        );
    }
    assert_eq!(
        pidfd_test_poll(&mut sibling, &memory, dup),
        PIDFD_TEST_REAPED
    );
    // The closed alias's registration stays as long as the pidfd does, as
    // Linux keeps it until the open file description is released.
    let reaped = (libc::EPOLLIN | libc::EPOLLHUP) as u32;
    assert_eq!(
        epoll_wait(&mut parent),
        BTreeMap::from([(11, reaped), (12, reaped)])
    );
}

/// The shadow socket closes with the pidfd's last descriptor, in whichever
/// process that is, and only then; so do the descriptors that stand for the
/// pidfd in an epoll set. The registry then drops the write end.
#[test]
fn closing_the_last_descriptor_of_a_pidfd_closes_its_shadow_socket() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let record = parent.state.foreign_pidfds[&(fd as i32)].clone();
    let target = record.target();
    let shadow = record.shadow();
    drop(record);
    let dup = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let event = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 1,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_EVENT, &event),
        0
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_epoll_ctl,
            [
                epoll as u64,
                libc::EPOLL_CTL_ADD as u64,
                dup as u64,
                PIDFD_TEST_EVENT,
                0,
                0
            ],
        ),
        0
    );
    let mut sibling = parent.fork_child(3, false, false).unwrap();
    let close = |executor: &mut ElfExecutor, fd: i64| {
        assert_eq!(
            pidfd_test_call(
                executor,
                &memory,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
    };

    close(&mut parent, fd);
    assert!(shadow.upgrade().is_some(), "the dup still holds the shadow");
    close(&mut parent, dup);
    assert!(
        shadow.upgrade().is_some(),
        "the forked child still holds the shadow"
    );
    close(&mut sibling, fd);
    assert!(
        shadow.upgrade().is_some(),
        "the forked child's dup still holds the shadow"
    );
    close(&mut sibling, dup);
    assert!(
        shadow.upgrade().is_none(),
        "the pidfd's last descriptor closed its shadow socket"
    );
    // The epoll set no longer reports the pidfd.
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_epoll_wait,
            [epoll as u64, PIDFD_TEST_EVENTS, 4, 0, 0, 0],
        ),
        0
    );
    parent.signal_registry.sync_pidfd_shadows();
    assert_eq!(parent.signal_registry.pidfd_shadow_writers(target).len(), 0);
}

/// `pidfd_open` names processes as Linux's does (kernel/pid.c): EINVAL for a
/// pid of 0 or less and for a thread that leads no thread group, ESRCH for a
/// pid no process has, including a reaped child's. An exited child that has
/// not been reaped gets a pidfd, readable at once.
#[test]
fn pidfd_open_names_another_process_as_linux_does() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let _thread = parent.thread_child(9).unwrap();
    for (pid, flags, expected) in [
        (0, 0, negative_errno(libc::EINVAL)),
        (-1, 0, negative_errno(libc::EINVAL)),
        (2, 0x100, negative_errno(libc::EINVAL)),
        (9, 0, negative_errno(libc::EINVAL)),
        (99, 0, negative_errno(libc::ESRCH)),
    ] {
        assert_eq!(
            pidfd_test_open(&mut parent, &memory, pid, flags),
            expected,
            "pidfd_open({pid}, {flags:#x})"
        );
    }
    pidfd_test_exit(&mut parent, &mut child);
    let zombie = pidfd_test_open(&mut parent, &memory, 2, libc::O_NONBLOCK as u64);
    assert!(zombie >= 0, "pidfd_open of an unreaped child: {zombie}");
    assert_eq!(
        pidfd_test_poll(&mut parent, &memory, zombie),
        PIDFD_TEST_EXITED
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_fcntl,
            [zombie as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        ),
        i64::from(libc::O_RDWR | libc::O_NONBLOCK)
    );
    pidfd_test_reap(&mut parent, &memory, 2);
    assert_eq!(
        pidfd_test_poll(&mut parent, &memory, zombie),
        PIDFD_TEST_REAPED
    );
    assert_eq!(
        pidfd_test_open(&mut parent, &memory, 2, 0),
        negative_errno(libc::ESRCH)
    );
}

/// A pidfd for another process is readable to select and pselect6 exactly
/// when its process has exited, and never writable or exceptional.
#[test]
fn select_reports_a_pidfd_for_another_process_as_readable_once_it_exits() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!((0..64).contains(&fd));
    let sets = |parent: &mut ElfExecutor, number: libc::c_long| {
        let bit = 1_u64 << fd;
        for set in 0..3 {
            memory
                .write_raw(PIDFD_TEST_INFO + set * 8, &bit.to_ne_bytes())
                .unwrap();
        }
        let ready = pidfd_test_call(
            parent,
            &memory,
            number,
            [
                fd as u64 + 1,
                PIDFD_TEST_INFO,
                PIDFD_TEST_INFO + 8,
                PIDFD_TEST_INFO + 16,
                // A zero timeout.
                PIDFD_TEST_STAT,
                0,
            ],
        );
        let read = |set: u64| {
            let mut word = [0; 8];
            memory
                .read_raw(PIDFD_TEST_INFO + set * 8, &mut word)
                .unwrap();
            u64::from_ne_bytes(word) == bit
        };
        (ready, [read(0), read(1), read(2)])
    };
    memory.write_raw(PIDFD_TEST_STAT, &[0; 16]).unwrap();
    for number in [libc::SYS_select, libc::SYS_pselect6] {
        assert_eq!(
            sets(&mut parent, number),
            (0, [false; 3]),
            "syscall {number}"
        );
    }
    pidfd_test_exit(&mut parent, &mut child);
    for number in [libc::SYS_select, libc::SYS_pselect6] {
        assert_eq!(
            sets(&mut parent, number),
            (1, [true, false, false]),
            "syscall {number}"
        );
    }
}

/// Pidfds for one process report one inode number, as Linux's pidfs gives
/// each process one inode (fs/pidfs.c); a pidfd for the caller itself, or for
/// another process, reports another.
#[test]
fn pidfds_report_one_inode_for_each_process() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let _sibling = parent.fork_child(3, false, false).unwrap();
    let inode = |parent: &mut ElfExecutor, fd: i64| {
        assert_eq!(
            pidfd_test_call(
                parent,
                &memory,
                libc::SYS_fstat,
                [fd as u64, PIDFD_TEST_STAT, 0, 0, 0, 0],
            ),
            0
        );
        read_struct::<libc::stat>(&memory, PIDFD_TEST_STAT).st_ino
    };
    let first = pidfd_test_open(&mut parent, &memory, 2, 0);
    let second = pidfd_test_open(&mut parent, &memory, 2, 0);
    let other = pidfd_test_open(&mut parent, &memory, 3, 0);
    let own_pid = i64::from(parent.state.pid);
    let own = pidfd_test_open(&mut parent, &memory, own_pid, 0);
    let [first, second, other, own] = [first, second, other, own].map(|fd| inode(&mut parent, fd));
    assert_eq!(first, second);
    assert_ne!(first, other);
    assert_ne!(first, own);
    assert_ne!(other, own);
}

/// Sending a pidfd for another process in an `SCM_RIGHTS` message is refused
/// by name before anything is sent: the receiver would get only the stand-in.
#[test]
fn a_pidfd_for_another_process_is_refused_in_scm_rights() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_socketpair,
            [
                libc::AF_UNIX as u64,
                libc::SOCK_STREAM as u64,
                0,
                PIDFD_TEST_PAIR,
                0,
                0
            ],
        ),
        0
    );
    let mut pair = [0_u8; 8];
    memory.read_raw(PIDFD_TEST_PAIR, &mut pair).unwrap();
    let sender = i32::from_ne_bytes(pair[..4].try_into().unwrap());
    let receiver = i32::from_ne_bytes(pair[4..].try_into().unwrap());
    memory.write_raw(PIDFD_TEST_BYTE, b"x").unwrap();
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as *mut libc::c_void,
        iov_len: 1,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_IOV, &iov),
        0
    );
    // SAFETY: CMSG_SPACE and CMSG_LEN compute sizes from an integer.
    let (space, length) = unsafe {
        (
            libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize,
            libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize,
        )
    };
    let mut control = vec![0_u8; space];
    let header = libc::cmsghdr {
        cmsg_len: length,
        cmsg_level: libc::SOL_SOCKET,
        cmsg_type: libc::SCM_RIGHTS,
    };
    // SAFETY: control holds a cmsghdr followed by one int.
    unsafe {
        std::ptr::write_unaligned(control.as_mut_ptr().cast(), header);
        std::ptr::write_unaligned(
            control
                .as_mut_ptr()
                .add(std::mem::size_of::<libc::cmsghdr>())
                .cast(),
            fd as libc::c_int,
        );
    }
    memory.write_raw(PIDFD_TEST_CONTROL, &control).unwrap();
    // SAFETY: msghdr is plain data; a zeroed one names nothing.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = PIDFD_TEST_CONTROL as *mut libc::c_void;
    message.msg_controllen = space;
    assert_eq!(
        write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_MESSAGE, &message),
        0
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_sendmsg,
            [sender as u64, PIDFD_TEST_MESSAGE, 0, 0, 0, 0],
        ),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        parent.take_unsupported_refusal(),
        Some(reverie::UnsupportedRefusal::new(
            reverie::UnsupportedOperation::Pidfd,
            reverie::Errno::ENOSYS,
            PIDFD_RIGHTS_REFUSAL,
        ))
    );
    // Nothing reached the receiver.
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_recvfrom,
            [
                receiver as u64,
                PIDFD_TEST_BYTE,
                1,
                libc::MSG_DONTWAIT as u64,
                0,
                0
            ],
        ),
        negative_errno(libc::EAGAIN)
    );
}

/// The executor's own `waitid(P_PIDFD)` resolves the descriptor as Linux does
/// (kernel/exit.c): EINVAL for a negative descriptor, EBADF for one that is
/// not a pidfd, ECHILD for a pidfd for no child of the caller; a nonblocking
/// pidfd for a live child answers EAGAIN where WNOHANG answers 0, and the
/// pidfd's child is reaped once it has exited.
#[test]
fn waitid_waits_for_the_child_a_pidfd_names() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let mut sibling = parent.fork_child(3, false, false).unwrap();
    let blocking = pidfd_test_open(&mut parent, &memory, 2, 0);
    let nonblocking = pidfd_test_open(&mut parent, &memory, 2, libc::O_NONBLOCK as u64);
    let own_pid = i64::from(parent.state.pid);
    let own = pidfd_test_open(&mut parent, &memory, own_pid, 0);
    // The sibling's pidfd for its sibling names no child of the sibling.
    let not_a_child = pidfd_test_open(&mut sibling, &memory, 2, 0);
    let pipe = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_pipe2,
        [PIDFD_TEST_PAIR, 0, 0, 0, 0, 0],
    );
    assert_eq!(pipe, 0);
    let mut ends = [0_u8; 4];
    memory.read_raw(PIDFD_TEST_PAIR, &mut ends).unwrap();
    let pipe_fd = i32::from_ne_bytes(ends);
    let waitid = |executor: &mut ElfExecutor, fd: i64, options: libc::c_int| {
        pidfd_test_call(
            executor,
            &memory,
            libc::SYS_waitid,
            [
                libc::P_PIDFD as u64,
                fd as u64,
                PIDFD_TEST_INFO,
                options as u64,
                0,
                0,
            ],
        )
    };
    assert_eq!(
        waitid(&mut parent, -1, libc::WEXITED),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(
        waitid(&mut parent, i64::from(pipe_fd), libc::WEXITED),
        negative_errno(libc::EBADF)
    );
    assert_eq!(
        waitid(&mut parent, 1000, libc::WEXITED),
        negative_errno(libc::EBADF)
    );
    assert_eq!(
        waitid(&mut parent, own, libc::WEXITED),
        negative_errno(libc::ECHILD)
    );
    assert_eq!(
        waitid(&mut sibling, not_a_child, libc::WEXITED),
        negative_errno(libc::ECHILD)
    );
    assert_eq!(
        waitid(&mut parent, nonblocking, libc::WEXITED),
        negative_errno(libc::EAGAIN)
    );
    assert_eq!(
        waitid(&mut parent, blocking, libc::WEXITED | libc::WNOHANG),
        0
    );
    assert_eq!(
        waitid(&mut parent, nonblocking, libc::WEXITED | libc::WNOHANG),
        0
    );

    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(waitid(&mut parent, nonblocking, libc::WEXITED), 0);
    let info: GuestWaitidSiginfo = read_struct(&memory, PIDFD_TEST_INFO);
    assert_eq!(
        (info.si_signo, info.si_code, info.si_pid, info.si_status),
        (libc::SIGCHLD, libc::CLD_EXITED, 2, 7)
    );
    // Reaped: no child is left to wait for.
    assert_eq!(
        waitid(&mut parent, blocking, libc::WEXITED),
        negative_errno(libc::ECHILD)
    );
}

/// The events that `epoll_wait` with a zero timeout reports for `epoll`, by
/// registration data.
fn pidfd_test_epoll_wait(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    epoll: i64,
) -> BTreeMap<u64, u32> {
    let ready = pidfd_test_call(
        executor,
        memory,
        libc::SYS_epoll_wait,
        [epoll as u64, PIDFD_TEST_EVENTS, 4, 0, 0, 0],
    );
    assert!(ready >= 0, "epoll_wait: {ready}");
    (0..ready as u64)
        .map(|index| {
            let event: libc::epoll_event = read_struct(
                memory,
                PIDFD_TEST_EVENTS + index * std::mem::size_of::<libc::epoll_event>() as u64,
            );
            (event.u64, event.events)
        })
        .collect()
}

/// `epoll_ctl(epoll, operation, fd)` with `events` and data `data`.
fn pidfd_test_epoll_ctl(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    epoll: i64,
    operation: libc::c_int,
    fd: i64,
    events: u32,
    data: u64,
) -> i64 {
    let event = libc::epoll_event { events, u64: data };
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_EVENT, &event),
        0
    );
    pidfd_test_call(
        executor,
        memory,
        libc::SYS_epoll_ctl,
        [
            epoll as u64,
            operation as u64,
            fd as u64,
            PIDFD_TEST_EVENT,
            0,
            0,
        ],
    )
}

/// The reap hangs a pidfd up even while another copy of its shadow's write
/// end is open, as a fork of the supervisor's process leaves one in the child
/// until the child's exec closes it: a pipe's hangup would wait for that
/// copy, a socket's shutdown does not. Poll and epoll both see the hangup at
/// once.
#[test]
fn a_reap_hangs_a_pidfd_up_while_a_copy_of_its_write_end_is_open() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let target = parent.state.foreign_pidfds[&(fd as i32)].target();
    let writers = parent.signal_registry.pidfd_shadow_writers(target);
    assert_eq!(writers.len(), 1);
    // SAFETY: F_DUPFD_CLOEXEC of a live descriptor returns a new one, which
    // the OwnedFd then owns.
    let copy = unsafe {
        std::os::fd::OwnedFd::from_raw_fd(libc::fcntl(
            writers[0].as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            0,
        ))
    };
    assert!(copy.as_raw_fd() >= 0);
    drop(writers);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            5
        ),
        0
    );

    pidfd_test_exit(&mut parent, &mut child);
    pidfd_test_reap(&mut parent, &memory, 2);
    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), PIDFD_TEST_REAPED);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(5, (libc::EPOLLIN | libc::EPOLLHUP) as u32)])
    );
    assert_eq!(parent.signal_registry.pidfd_shadow_writers(target).len(), 0);
    drop(copy);
}

/// A pidfd reports only what Linux's `pidfd_poll` reports, never the
/// writability, priority data or `POLLRDHUP` its shadow socket would show:
/// poll asked for every event, select's write and exception sets, and epoll
/// registrations asking for `EPOLLOUT` or `EPOLLRDHUP` see `POLLIN`-type
/// readiness and the hangup alone, alive, exited and reaped. Linux refuses
/// `EPOLLEXCLUSIVE` with `EPOLLRDHUP` and accepts it with `EPOLLOUT`.
#[test]
fn a_pidfd_reports_only_what_pidfd_poll_reports() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!((0..64).contains(&fd));
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let alias = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let exclusive = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    for (registered, events, data) in [
        (
            fd,
            (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLPRI) as u32,
            1,
        ),
        (alias, (libc::EPOLLOUT | libc::EPOLLWRNORM) as u32, 2),
    ] {
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                registered,
                events,
                data
            ),
            0
        );
    }
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            exclusive,
            (libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLEXCLUSIVE) as u32,
            3
        ),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            exclusive,
            (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLEXCLUSIVE) as u32,
            3
        ),
        0
    );
    let select_sets = |parent: &mut ElfExecutor| {
        let bit = 1_u64 << fd;
        for set in 0..3 {
            memory
                .write_raw(PIDFD_TEST_INFO + set * 8, &bit.to_ne_bytes())
                .unwrap();
        }
        memory.write_raw(PIDFD_TEST_STAT, &[0; 16]).unwrap();
        let ready = pidfd_test_call(
            parent,
            &memory,
            libc::SYS_select,
            [
                fd as u64 + 1,
                PIDFD_TEST_INFO,
                PIDFD_TEST_INFO + 8,
                PIDFD_TEST_INFO + 16,
                PIDFD_TEST_STAT,
                0,
            ],
        );
        let set = |index: u64| {
            let mut word = [0; 8];
            memory
                .read_raw(PIDFD_TEST_INFO + index * 8, &mut word)
                .unwrap();
            u64::from_ne_bytes(word) == bit
        };
        (ready, [set(0), set(1), set(2)])
    };

    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), 0);
    assert_eq!(select_sets(&mut parent), (0, [false; 3]));
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());

    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), PIDFD_TEST_EXITED);
    assert_eq!(select_sets(&mut parent), (1, [true, false, false]));
    let exited = libc::EPOLLIN as u32;
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(1, exited), (3, exited)])
    );

    pidfd_test_reap(&mut parent, &memory, 2);
    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), PIDFD_TEST_REAPED);
    assert_eq!(select_sets(&mut parent), (1, [true, false, false]));
    let reaped = (libc::EPOLLIN | libc::EPOLLHUP) as u32;
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(1, reaped), (2, libc::EPOLLHUP as u32), (3, reaped)])
    );
}
