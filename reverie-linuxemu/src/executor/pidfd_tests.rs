// pidfds for guest processes (`executor/pidfd.rs`) and the shadow sockets that
// show their readiness (`pidfd_shadow.rs`): Linux's answers from kernel/pid.c,
// kernel/fork.c, kernel/exit.c, fs/pidfs.c and fs/eventpoll.c; the shadow's
// privacy: it is never a guest descriptor, and every alias of the pidfd shares
// it; and its lifetime, the pidfd's open file description's: it closes with
// the pidfd's last descriptor, whatever another thread of the process is
// doing, and a call that found the pidfd keeps it until the call ends.

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
const PIDFD_TEST_STATX: u64 = 0xd00;
const PIDFD_TEST_EMPTY_PATH: u64 = 0xf00;
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

/// The record of `executor`'s guest descriptor `fd`, a pidfd for a guest
/// process, which its table holds.
fn pidfd_test_record(executor: &ElfExecutor, fd: i64) -> Arc<GuestPidfd> {
    executor.state.guest_pidfds[&(fd as i32)]
        .upgrade()
        .expect("the table holds the pidfd's record")
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

    let pidfd = pidfd_test_record(&parent, fd);
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
    let record = pidfd_test_record(&parent, fd);
    for alias in aliases {
        assert!(
            Arc::ptr_eq(&pidfd_test_record(&parent, alias), &record),
            "alias {alias}"
        );
    }
    // A second child, forked after the pidfd was opened, holds it too.
    let mut sibling = parent.fork_child(3, false, false).unwrap();
    for alias in aliases {
        assert!(
            Arc::ptr_eq(&pidfd_test_record(&sibling, alias), &record),
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
    let record = pidfd_test_record(&parent, fd);
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

/// `pidfd_open` names processes as Linux's does (kernel/pid.c and
/// kernel/fork.c in v6.17): EINVAL for a pid of 0 or less, ENOENT for a
/// thread that leads no thread group, ESRCH for a pid no process has,
/// including a reaped child's. An exited child that has not been reaped gets
/// a pidfd, readable at once.
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
        (9, 0, negative_errno(libc::ENOENT)),
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

/// So is sending a pidfd for the caller itself, whose stand-in names the
/// supervisor too.
#[test]
fn a_pidfd_for_the_caller_itself_is_refused_in_scm_rights() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let own_pid = i64::from(parent.state.pid);
    let own = pidfd_test_open(&mut parent, &memory, own_pid, 0);
    assert!(own >= 0);
    let mut control = rights_control(&[own as i32]);
    assert_eq!(
        translate_outgoing_control(&mut control, &mut parent.state),
        Err(negative_errno(libc::ENOSYS))
    );
    assert_eq!(parent.state.pidfd_refusal, Some(PIDFD_RIGHTS_REFUSAL));
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

/// A thread's waitid(P_PIDFD) finds a pidfd that another thread of its
/// process opened since the waiter's last call, in their shared table: a
/// nonblocking pidfd for a live child gives EAGAIN, not EBADF. Reviewer
/// regression from https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn waitid_of_a_pidfd_another_thread_opened_finds_it() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let mut sibling = parent.thread_child(9).unwrap();
    let fd = pidfd_test_open(&mut parent, &memory, 2, libc::O_NONBLOCK as u64);
    assert!(fd >= 0);
    assert_eq!(
        pidfd_test_call(
            &mut sibling,
            &memory,
            libc::SYS_waitid,
            [
                libc::P_PIDFD as u64,
                fd as u64,
                PIDFD_TEST_INFO,
                libc::WEXITED as u64,
                0,
                0
            ]
        ),
        -(libc::EAGAIN as i64),
        "the sibling shares the newly opened pidfd"
    );
}

/// A thread's waitid(P_PIDFD) waits for the process that its descriptor
/// names in the shared table now, though another thread replaced the
/// descriptor with a pidfd for another child after the waiter's last call.
#[test]
fn waitid_of_a_pidfd_another_thread_replaced_waits_for_the_new_process() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _living) = pidfd_test_family(&root, 2);
    let mut exiting = parent.fork_child(3, false, false).unwrap();
    let mut sibling = parent.thread_child(9).unwrap();
    let fd = pidfd_test_open(&mut parent, &memory, 2, libc::O_NONBLOCK as u64);
    // The sibling's last call before its wait: its table has `fd`, naming
    // the live child 2.
    let flags = pidfd_test_call(
        &mut sibling,
        &memory,
        libc::SYS_fcntl,
        [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
    );
    assert_ne!(flags & i64::from(libc::O_NONBLOCK), 0);
    let replacement = pidfd_test_open(&mut parent, &memory, 3, libc::O_NONBLOCK as u64);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_dup2,
            [replacement as u64, fd as u64, 0, 0, 0, 0]
        ),
        fd
    );
    pidfd_test_exit(&mut parent, &mut exiting);
    assert_eq!(
        pidfd_test_call(
            &mut sibling,
            &memory,
            libc::SYS_waitid,
            [
                libc::P_PIDFD as u64,
                fd as u64,
                PIDFD_TEST_INFO,
                libc::WEXITED as u64,
                0,
                0
            ]
        ),
        0
    );
    let info: GuestWaitidSiginfo = read_struct(&memory, PIDFD_TEST_INFO);
    assert_eq!(
        (info.si_signo, info.si_code, info.si_pid, info.si_status),
        (libc::SIGCHLD, libc::CLD_EXITED, 3, 7)
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
    let target = pidfd_test_record(&parent, fd).target();
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

/// How many of this process's descriptors are of the socket whose
/// `/proc/self/fd` link is `link`: a shadow and its epoll keys.
fn pidfd_test_socket_descriptors(link: &std::path::Path) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| std::fs::read_link(entry.path()).ok().as_deref() == Some(link))
        .count()
}

/// The `/proc/self/fd` link of the shadow of `executor`'s pidfd `fd`.
fn pidfd_test_shadow_link(executor: &ElfExecutor, fd: i64) -> std::path::PathBuf {
    let raw = pidfd_test_record(executor, fd).readiness_fd();
    std::fs::read_link(format!("/proc/self/fd/{raw}")).unwrap()
}

/// Every pidfd for one process reports one inode, whoever opened it: a
/// child's pidfd for itself and its parent's pidfd for it alike, as Linux
/// gives each process one pidfs inode (`pidfs_add_pid`, fs/pidfs.c), and
/// another process's pidfd for itself reports another; statx agrees with
/// fstat. Reviewer regression from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn a_pidfd_reports_its_process_inode_whoever_opened_it() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let mut sibling = parent.fork_child(3, false, false).unwrap();
    let foreign = pidfd_test_open(&mut parent, &memory, 2, 0);
    let own = pidfd_test_open(&mut child, &memory, 2, 0);
    let sibling_own = pidfd_test_open(&mut sibling, &memory, 3, 0);
    assert!(foreign >= 0 && own >= 0 && sibling_own >= 0);
    let inode = |task: &mut ElfExecutor, fd: i64| {
        assert_eq!(
            pidfd_test_call(
                task,
                &memory,
                libc::SYS_fstat,
                [fd as u64, PIDFD_TEST_STAT, 0, 0, 0, 0]
            ),
            0
        );
        read_struct::<libc::stat>(&memory, PIDFD_TEST_STAT).st_ino
    };
    assert_eq!(
        inode(&mut parent, foreign),
        inode(&mut child, own),
        "same guest process must have one pidfs inode irrespective of opener"
    );
    assert_ne!(
        inode(&mut child, own),
        inode(&mut sibling, sibling_own),
        "two processes' own pidfds must have different inodes"
    );
    let statx_inode = |task: &mut ElfExecutor, fd: i64| {
        memory.write_raw(PIDFD_TEST_EMPTY_PATH, &[0]).unwrap();
        assert_eq!(
            pidfd_test_call(
                task,
                &memory,
                libc::SYS_statx,
                [
                    fd as u64,
                    PIDFD_TEST_EMPTY_PATH,
                    libc::AT_EMPTY_PATH as u64,
                    libc::STATX_INO as u64,
                    PIDFD_TEST_STATX,
                    0
                ]
            ),
            0
        );
        read_struct::<libc::statx>(&memory, PIDFD_TEST_STATX).stx_ino
    };
    assert_eq!(statx_inode(&mut child, own), inode(&mut child, own));
    assert_eq!(statx_inode(&mut parent, foreign), inode(&mut child, own));
}

/// The last close of a pidfd ends its epoll registration and closes its
/// shadow even while another thread of the process, which shares the
/// table, makes no call: that thread names the pidfd and holds nothing.
/// Reviewer regression from https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn the_last_close_of_a_pidfd_ends_it_beside_an_idle_thread() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            91
        ),
        0
    );
    let shadow = pidfd_test_record(&parent, fd).shadow();
    let link = pidfd_test_shadow_link(&parent, fd);
    let _idle_thread = parent.thread_child(9).unwrap();
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [fd as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        pidfd_test_socket_descriptors(&link),
        0,
        "the closed pidfd's shadow and epoll key are closed"
    );
    pidfd_test_exit(&mut parent, &mut child);
    pidfd_test_reap(&mut parent, &memory, 2);
    let events = pidfd_test_epoll_wait(&mut parent, &memory, epoll);
    assert!(
        events.is_empty(),
        "last closed pidfd still reports {:?}; shadow_alive={}",
        events,
        shadow.upgrade().is_some()
    );
    assert!(shadow.upgrade().is_none());
}

/// So do a dup2 over a pidfd's last descriptor and a close_range of it,
/// beside an idle thread.
#[test]
fn replacing_or_closing_a_range_over_a_pidfd_ends_it_beside_an_idle_thread() {
    for operation in [libc::SYS_dup2, libc::SYS_close_range] {
        let root = TestDir::new();
        let memory = pidfd_test_memory();
        let (mut parent, mut child) = pidfd_test_family(&root, 2);
        let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
        let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                92
            ),
            0
        );
        let shadow = pidfd_test_record(&parent, fd).shadow();
        let link = pidfd_test_shadow_link(&parent, fd);
        let _idle_thread = parent.thread_child(9).unwrap();
        let args = if operation == libc::SYS_dup2 {
            [epoll as u64, fd as u64, 0, 0, 0, 0]
        } else {
            [fd as u64, fd as u64, 0, 0, 0, 0]
        };
        let expected = if operation == libc::SYS_dup2 { fd } else { 0 };
        assert_eq!(
            pidfd_test_call(&mut parent, &memory, operation, args),
            expected,
            "syscall {operation}"
        );
        assert!(
            !parent.state.guest_pidfds.contains_key(&(fd as i32)),
            "syscall {operation}"
        );
        assert_eq!(
            pidfd_test_socket_descriptors(&link),
            0,
            "syscall {operation}"
        );
        assert!(shadow.upgrade().is_none(), "syscall {operation}");
        pidfd_test_exit(&mut parent, &mut child);
        pidfd_test_reap(&mut parent, &memory, 2);
        assert!(
            pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty(),
            "syscall {operation}"
        );
    }
}

/// A call that found a pidfd keeps it until the call ends, even when another
/// thread closes it meanwhile, as Linux's `fdget` keeps the file: its poll
/// shows the pidfd's readiness, never a stand-in's or a closed descriptor's.
/// The pidfd's shadow goes when the call ends.
#[test]
fn a_call_that_found_a_pidfd_keeps_it_when_another_thread_closes_it() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (parent, mut child) = pidfd_test_family(&root, 2);
    let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
    let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
    let mut thread = parent.borrow().thread_child(9).unwrap();
    pidfd_test_exit(&mut parent.borrow_mut(), &mut child);
    let shadow = pidfd_test_record(&parent.borrow(), fd).shadow();
    let closer = parent.clone();
    COPY_REACHED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let memory = pidfd_test_memory();
            assert_eq!(
                pidfd_test_call(
                    &mut closer.borrow_mut(),
                    &memory,
                    libc::SYS_close,
                    [fd as u64, 0, 0, 0, 0, 0]
                ),
                0
            );
        }))
    });
    assert_eq!(
        pidfd_test_poll(&mut thread, &memory, fd),
        PIDFD_TEST_EXITED,
        "the poll found the pidfd before the close"
    );
    assert!(
        COPY_REACHED_TEST_HOOK.with(|hook| hook.borrow().is_none()),
        "the close ran inside the poll"
    );
    assert!(shadow.upgrade().is_none(), "the shadow goes with the call");
    assert_eq!(pidfd_test_poll(&mut thread, &memory, fd), libc::POLLNVAL);
}

/// A call that had not found a pidfd when another thread closed it finds it
/// closed, and the pidfd is gone at once.
#[test]
fn a_call_that_had_not_found_a_pidfd_finds_it_closed() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (parent, mut child) = pidfd_test_family(&root, 2);
    let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
    let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
    let mut thread = parent.borrow().thread_child(9).unwrap();
    pidfd_test_exit(&mut parent.borrow_mut(), &mut child);
    let shadow = pidfd_test_record(&parent.borrow(), fd).shadow();
    let closer = parent.clone();
    let closed_shadow = shadow.clone();
    TABLE_RELEASED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let memory = pidfd_test_memory();
            assert_eq!(
                pidfd_test_call(
                    &mut closer.borrow_mut(),
                    &memory,
                    libc::SYS_close,
                    [fd as u64, 0, 0, 0, 0, 0]
                ),
                0
            );
            assert!(
                closed_shadow.upgrade().is_none(),
                "a call that has not found the pidfd holds nothing of it"
            );
        }))
    });
    assert_eq!(pidfd_test_poll(&mut thread, &memory, fd), libc::POLLNVAL);
    assert!(
        TABLE_RELEASED_TEST_HOOK.with(|hook| hook.borrow().is_none()),
        "the close ran inside the poll"
    );
    assert!(shadow.upgrade().is_none());
}

/// A dup2 of a pidfd onto itself, and duplications that fail, leave the
/// pidfd as it was.
#[test]
fn dup2_onto_itself_and_failed_duplications_keep_a_pidfd() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let record = pidfd_test_record(&parent, fd);
    let fd_arg = fd as u64;
    for (number, args, expected) in [
        (libc::SYS_dup2, [fd_arg, fd_arg, 0, 0, 0, 0], fd),
        (
            libc::SYS_dup3,
            [fd_arg, fd_arg, 0, 0, 0, 0],
            negative_errno(libc::EINVAL),
        ),
        (
            libc::SYS_dup2,
            [fd_arg, 1 << 20, 0, 0, 0, 0],
            negative_errno(libc::EBADF),
        ),
        (
            libc::SYS_fcntl,
            [fd_arg, libc::F_DUPFD as u64, u64::MAX, 0, 0, 0],
            negative_errno(libc::EINVAL),
        ),
    ] {
        assert_eq!(
            pidfd_test_call(&mut parent, &memory, number, args),
            expected,
            "syscall {number} {args:?}"
        );
        assert!(
            Arc::ptr_eq(&pidfd_test_record(&parent, fd), &record),
            "syscall {number} {args:?}"
        );
    }
    drop(record);
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), PIDFD_TEST_EXITED);
}

/// A descriptor number reused after a pidfd's close reports its new file,
/// in every thread of the process, never the closed pidfd's readiness.
#[test]
fn a_number_reused_after_a_pidfd_closes_reports_its_new_file() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let mut thread = parent.thread_child(9).unwrap();
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [fd as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        pidfd_test_call(&mut parent, &memory, libc::SYS_eventfd2, [0; 6]),
        fd,
        "the eventfd takes the pidfd's number"
    );
    pidfd_test_exit(&mut parent, &mut child);
    // An eventfd with a zero count is writable and not readable
    // (`eventfd_poll`, fs/eventfd.c).
    assert_eq!(pidfd_test_poll(&mut parent, &memory, fd), libc::POLLOUT);
    assert_eq!(pidfd_test_poll(&mut thread, &memory, fd), libc::POLLOUT);
}

/// The last task's exit ends its table's pidfds, as Linux's `exit_files`
/// closes them, even while something else holds the table.
#[test]
fn the_last_tasks_exit_ends_its_pidfds_while_an_observer_holds_its_table() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let shadow = pidfd_test_record(&parent, fd).shadow();
    let link = pidfd_test_shadow_link(&parent, fd);
    let _observer = parent.file_table.clone();
    parent.release_files_on_exit();
    assert!(shadow.upgrade().is_none());
    assert_eq!(pidfd_test_socket_descriptors(&link), 0);
}

/// An epoll registration of a pidfd lasts as Linux's does: one epoll's DEL
/// leaves the pidfd's registration in another, a registration by a closed
/// descriptor number lasts while another descriptor of the pidfd is open,
/// and the host descriptor that stands for a number in epoll closes with the
/// number's last registration.
#[test]
fn epoll_registrations_of_a_pidfd_last_as_linux_registrations_do() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let alias = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let link = pidfd_test_shadow_link(&parent, fd);
    let first = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let second = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    for (epoll, target, data) in [(first, fd, 1), (second, fd, 2), (second, alias, 3)] {
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                target,
                libc::EPOLLIN as u32,
                data
            ),
            0
        );
    }
    // The shadow, and a key for each of the two numbers.
    assert_eq!(pidfd_test_socket_descriptors(&link), 3);
    assert_eq!(
        pidfd_test_epoll_ctl(&mut parent, &memory, first, libc::EPOLL_CTL_DEL, fd, 0, 0),
        0
    );
    // The second epoll still names `fd`'s number.
    assert_eq!(pidfd_test_socket_descriptors(&link), 3);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [alias as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    pidfd_test_exit(&mut parent, &mut child);
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, first).is_empty());
    let exited = libc::EPOLLIN as u32;
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, second),
        BTreeMap::from([(2, exited), (3, exited)]),
        "the closed number's registration lasts while the pidfd is open"
    );
    assert_eq!(
        pidfd_test_epoll_ctl(&mut parent, &memory, second, libc::EPOLL_CTL_DEL, fd, 0, 0),
        0
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 2);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_dup2,
            [fd as u64, alias as u64, 0, 0, 0, 0]
        ),
        alias
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            second,
            libc::EPOLL_CTL_DEL,
            alias,
            0,
            0
        ),
        0
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, second).is_empty());
}

/// The end of a pidfd removes its epoll registrations, as Linux's
/// `eventpoll_release` does when it releases the pidfd's open file
/// description, though a copy of its shadow is still open, as a fork of the
/// supervisor's process holds one until it execs: the host alone would keep
/// the registrations while the copy keeps the shadow's description, and
/// show the reap through them.
#[test]
fn a_closed_pidfd_leaves_no_epoll_registration_while_a_copy_of_its_shadow_is_open() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
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
    let shadow = pidfd_test_record(&parent, fd).readiness_fd();
    // SAFETY: the shadow is live; F_DUPFD_CLOEXEC returns a new descriptor.
    let copy = unsafe { libc::fcntl(shadow, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    assert!(copy >= 0);
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    let copy = unsafe { std::fs::File::from_raw_fd(copy) };
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [fd as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    pidfd_test_exit(&mut parent, &mut child);
    pidfd_test_reap(&mut parent, &memory, 2);
    assert!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty(),
        "the closed pidfd's registration is gone"
    );
    drop(copy);
}

/// The close of an epoll's last descriptor ends its registrations of a
/// pidfd beside an idle thread, whose snapshot still names the epoll: they
/// go with the epoll's open file description, not with the last reference
/// to it, and so do their host descriptors of the epoll.
#[test]
fn closing_an_epoll_ends_its_pidfd_registrations_beside_an_idle_thread() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            3
        ),
        0
    );
    let _idle_thread = parent.thread_child(9).unwrap();
    assert_eq!(pidfd_test_socket_descriptors(&link), 2);
    assert_eq!(pidfd_test_record(&parent, fd).epoll_registrations(), 1);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [epoll as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
    assert_eq!(pidfd_test_record(&parent, fd).epoll_registrations(), 0);
}

/// So does the exit of a fork whose table held the epoll's last
/// descriptor, beside the parent's idle thread, whose snapshot still names
/// the epoll.
#[test]
fn a_forks_exit_with_an_epolls_last_descriptor_ends_its_pidfd_registrations() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            2
        ),
        0
    );
    let _idle_thread = parent.thread_child(9).unwrap();
    let mut forked = parent.fork_child(3, false, false).unwrap();
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [epoll as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        pidfd_test_socket_descriptors(&link),
        2,
        "the fork's descriptor keeps the epoll"
    );
    forked.release_files_on_exit();
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
}

/// A call that found an epoll before another thread closed its last
/// descriptor still makes its ADD of a pidfd, as Linux's `fdget` keeps the
/// epoll for the call, but the registration ends with the epoll's open file
/// description: no host descriptor of the shadow or the epoll stays behind.
#[test]
fn an_add_of_a_pidfd_to_an_epoll_another_thread_closed_meanwhile_leaves_nothing() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (parent, _child) = pidfd_test_family(&root, 2);
    let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
    let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent.borrow(), fd);
    let epoll = pidfd_test_call(
        &mut parent.borrow_mut(),
        &memory,
        libc::SYS_epoll_create1,
        [0; 6],
    );
    let mut thread = parent.borrow().thread_child(9).unwrap();
    let closer = parent.clone();
    COPY_REACHED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let memory = pidfd_test_memory();
            assert_eq!(
                pidfd_test_call(
                    &mut closer.borrow_mut(),
                    &memory,
                    libc::SYS_close,
                    [epoll as u64, 0, 0, 0, 0, 0]
                ),
                0
            );
        }))
    });
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut thread,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1
        ),
        0
    );
    assert!(
        COPY_REACHED_TEST_HOOK.with(|hook| hook.borrow().is_none()),
        "the close ran during the ADD"
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
    assert_eq!(
        pidfd_test_record(&parent.borrow(), fd).epoll_registrations(),
        0
    );
}

/// Sends `fd` in an `SCM_RIGHTS` message through a new socket pair, and
/// returns the descriptor that receiving it gives.
fn pidfd_test_pass_right(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64) -> i64 {
    assert_eq!(
        pidfd_test_call(
            executor,
            memory,
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
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_IOV, &iov),
        0
    );
    let control = rights_control(&[fd as libc::c_int]);
    // SAFETY: msghdr is plain data; a zeroed one names nothing.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = PIDFD_TEST_CONTROL as *mut libc::c_void;
    message.msg_controllen = control.len();
    for (socket, number, contents) in [
        (sender, libc::SYS_sendmsg, control.clone()),
        (receiver, libc::SYS_recvmsg, vec![0; control.len()]),
    ] {
        memory.write_raw(PIDFD_TEST_CONTROL, &contents).unwrap();
        assert_eq!(
            write_struct(&mut ProviderMemory(memory), PIDFD_TEST_MESSAGE, &message),
            0
        );
        assert_eq!(
            pidfd_test_call(
                executor,
                memory,
                number,
                [socket as u64, PIDFD_TEST_MESSAGE, 0, 0, 0, 0]
            ),
            1,
            "syscall {number}"
        );
    }
    let mut received = [0_u8; 4];
    memory
        .read_raw(
            PIDFD_TEST_CONTROL + std::mem::size_of::<libc::cmsghdr>() as u64,
            &mut received,
        )
        .unwrap();
    for socket in [sender, receiver] {
        assert_eq!(
            pidfd_test_call(
                executor,
                memory,
                libc::SYS_close,
                [socket as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
    i64::from(i32::from_ne_bytes(received))
}

/// An epoll that an `SCM_RIGHTS` message carried outlives every descriptor
/// of it in the sender's table while the receiver holds it, and so does its
/// registration of a pidfd, as Linux's does: the received descriptor's ADD
/// finds it (EEXIST), its DEL removes it, a new ADD makes one registration,
/// not two, and the receiver's last close ends the epoll and its
/// registration.
#[test]
fn a_pidfd_registration_in_an_epoll_passed_in_scm_rights_lasts_until_the_receivers_last_close() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let control = |parent: &mut ElfExecutor, epoll: i64, operation: libc::c_int, data: u64| {
        pidfd_test_epoll_ctl(
            parent,
            &memory,
            epoll,
            operation,
            fd,
            libc::EPOLLIN as u32,
            data,
        )
    };
    assert_eq!(control(&mut parent, epoll, libc::EPOLL_CTL_ADD, 4), 0);
    let received = pidfd_test_pass_right(&mut parent, &memory, epoll);
    assert!(received >= 0);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [epoll as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        pidfd_test_socket_descriptors(&link),
        2,
        "the received epoll keeps the registration"
    );
    assert_eq!(
        control(&mut parent, received, libc::EPOLL_CTL_ADD, 5),
        negative_errno(libc::EEXIST)
    );
    assert_eq!(control(&mut parent, received, libc::EPOLL_CTL_DEL, 0), 0);
    assert_eq!(control(&mut parent, received, libc::EPOLL_CTL_ADD, 5), 0);
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, received),
        BTreeMap::from([(5, libc::EPOLLIN as u32)])
    );
    pidfd_test_close(&mut parent, &memory, received);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1),
        "the receiver's last close ends the epoll and its registration"
    );
}

/// An `SCM_RIGHTS` message makes another descriptor of the same epoll open
/// file description, so closing the epoll's original descriptor leaves the
/// pidfd's registration, and its ADD/DEL identity, to the received one: its
/// DEL removes it, a new ADD replaces it, and the exit and the reap show
/// through the replacement alone. Reviewer regression from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn an_epoll_passed_in_scm_rights_keeps_its_pidfd_registration_after_its_original_closes() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let pidfd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(pidfd >= 0);
    let original = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert!(original >= 0);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            original,
            libc::EPOLL_CTL_ADD,
            pidfd,
            libc::EPOLLIN as u32,
            141,
        ),
        0
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_socketpair,
            [
                libc::AF_UNIX as u64,
                libc::SOCK_DGRAM as u64,
                0,
                PIDFD_TEST_PAIR,
                0,
                0,
            ],
        ),
        0
    );
    let [sender, receiver]: [libc::c_int; 2] = read_struct(&memory, PIDFD_TEST_PAIR);
    memory.write_raw(PIDFD_TEST_BYTE, b"x").unwrap();
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as usize as *mut libc::c_void,
        iov_len: 1,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_IOV, &iov),
        0
    );
    let control = rights_control(&[original as libc::c_int]);
    assert!(control.len() <= RIGHTS_CONTROL_CAPACITY);
    memory.write_raw(PIDFD_TEST_CONTROL, &control).unwrap();
    // SAFETY: msghdr is plain data, and its pointer fields below name guest
    // addresses which the executor copies before calling the host.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as usize as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = PIDFD_TEST_CONTROL as usize as *mut libc::c_void;
    message.msg_controllen = control.len();
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
        1,
        "sending the epoll transfers its open file description"
    );

    memory
        .write_raw(PIDFD_TEST_CONTROL, &[0_u8; RIGHTS_CONTROL_CAPACITY])
        .unwrap();
    message.msg_controllen = RIGHTS_CONTROL_CAPACITY;
    assert_eq!(
        write_struct(&mut ProviderMemory(&memory), PIDFD_TEST_MESSAGE, &message),
        0
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_recvmsg,
            [
                receiver as u64,
                PIDFD_TEST_MESSAGE,
                libc::MSG_DONTWAIT as u64,
                0,
                0,
                0,
            ],
        ),
        1
    );
    let received: libc::msghdr = read_struct(&memory, PIDFD_TEST_MESSAGE);
    assert_eq!(received.msg_flags & libc::MSG_CTRUNC, 0);
    let mut control = vec![0_u8; received.msg_controllen];
    memory.read_raw(PIDFD_TEST_CONTROL, &mut control).unwrap();
    let rights = control_rights(&control);
    assert_eq!(rights.len(), 1);
    let imported = i64::from(rights[0]);
    assert_ne!(imported, original);
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, imported).is_empty());

    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [original as u64, 0, 0, 0, 0, 0],
        ),
        0
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            imported,
            libc::EPOLL_CTL_DEL,
            pidfd,
            0,
            0,
        ),
        0,
        "the received epoll must still find the original pidfd registration"
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            imported,
            libc::EPOLL_CTL_ADD,
            pidfd,
            libc::EPOLLIN as u32,
            142,
        ),
        0
    );
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, imported),
        BTreeMap::from([(142, libc::EPOLLIN as u32)]),
        "the replacement registration reports the exit, without the deleted one"
    );
    pidfd_test_reap(&mut parent, &memory, 2);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, imported),
        BTreeMap::from([(142, (libc::EPOLLIN | libc::EPOLLHUP) as u32)])
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            imported,
            libc::EPOLL_CTL_DEL,
            pidfd,
            0,
            0,
        ),
        0
    );
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, imported).is_empty());
}

/// An ADD of a pidfd that cannot keep its host descriptor of the epoll, for
/// the pidfd's end to remove the registration through, fails as Linux's
/// `epoll_ctl` fails an allocation, ENOMEM, and leaves nothing behind.
#[test]
fn an_epoll_add_of_a_pidfd_that_cannot_keep_its_epoll_fails_with_enomem() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let add = |parent: &mut ElfExecutor| {
        pidfd_test_epoll_ctl(
            parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            6,
        )
    };
    EPOLL_COPY_FAILS_TEST_HOOK.with(|fails| fails.set(true));
    assert_eq!(add(&mut parent), negative_errno(libc::ENOMEM));
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
    assert_eq!(pidfd_test_record(&parent, fd).epoll_registrations(), 0);
    pidfd_test_exit(&mut parent, &mut child);
    assert!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty(),
        "the failed ADD registered nothing"
    );
    assert_eq!(add(&mut parent), 0);
    assert_eq!(pidfd_test_socket_descriptors(&link), 2);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(6, libc::EPOLLIN as u32)])
    );
}

/// Epoll controls of a pidfd that fail leave no host descriptor of its
/// shadow behind, as Linux's leave nothing: here 32 DELs of numbers the
/// epoll does not name. Reviewer regression from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn failed_epoll_controls_of_a_pidfd_leave_no_shadow_descriptor() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let raw = pidfd_test_record(&parent, fd).readiness_fd();
    let link = std::fs::read_link(format!("/proc/self/fd/{raw}")).unwrap();
    let count = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&link))
            .count()
    };
    let before = count();
    for alias in 100..132 {
        assert_eq!(
            pidfd_test_call(
                &mut parent,
                &memory,
                libc::SYS_dup2,
                [fd as u64, alias as u64, 0, 0, 0, 0]
            ),
            alias
        );
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_DEL,
                alias,
                0,
                0
            ),
            negative_errno(libc::ENOENT)
        );
        assert_eq!(
            pidfd_test_call(
                &mut parent,
                &memory,
                libc::SYS_close,
                [alias as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
    assert_eq!(
        count(),
        before,
        "failed DELs must not retain shadow duplicates"
    );
    // Nor do a MOD of a number the epoll does not name, or an ADD that fails.
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_MOD,
            fd,
            libc::EPOLLIN as u32,
            0
        ),
        negative_errno(libc::ENOENT)
    );
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            (libc::EPOLLIN | libc::EPOLLEXCLUSIVE | libc::EPOLLRDHUP) as u32,
            0
        ),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(count(), before);
}

/// An epoll that closes without a DEL ends its registrations of a pidfd, as
/// Linux frees an eventpoll's registrations with it, and with them the host
/// descriptors that stood for the registrations' numbers: here 32 epolls,
/// each closed before its registration's number. Reviewer regression from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn closed_epolls_leave_no_shadow_descriptor_of_a_pidfd() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
    for alias in 100..132 {
        assert_eq!(
            pidfd_test_call(
                &mut parent,
                &memory,
                libc::SYS_dup2,
                [fd as u64, alias, 0, 0, 0, 0]
            ),
            alias as i64
        );
        let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert!(epoll >= 0);
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                alias as i64,
                libc::EPOLLIN as u32,
                alias
            ),
            0
        );
        for closing in [epoll as u64, alias] {
            assert_eq!(
                pidfd_test_call(
                    &mut parent,
                    &memory,
                    libc::SYS_close,
                    [closing, 0, 0, 0, 0, 0]
                ),
                0
            );
        }
    }
    assert_eq!(
        pidfd_test_socket_descriptors(&link),
        1,
        "closed epolls must not leave shadow keys behind"
    );
}

/// A registration of a pidfd lasts while any descriptor of its epoll does,
/// a dup's or a fork's, as Linux's eventpoll lives while its file does, and
/// ends with the last of them, though the registration's own number closed
/// first; the end of one epoll leaves the number's registration in another.
#[test]
fn an_epoll_registration_of_a_pidfd_lasts_while_an_alias_of_the_epoll_does() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let alias = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let other = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let add = |parent: &mut ElfExecutor, target: i64, data: u64| {
        assert_eq!(
            pidfd_test_epoll_ctl(
                parent,
                &memory,
                target,
                libc::EPOLL_CTL_ADD,
                alias,
                libc::EPOLLIN as u32,
                data
            ),
            0
        );
    };
    let close = |parent: &mut ElfExecutor, closing: i64| {
        assert_eq!(
            pidfd_test_call(
                parent,
                &memory,
                libc::SYS_close,
                [closing as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
    };
    add(&mut parent, epoll, 7);
    let epoll_dup = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [epoll as u64, 0, 0, 0, 0, 0],
    );
    close(&mut parent, alias);
    close(&mut parent, epoll);
    // The shadow, and the key of the closed number, which only the epoll's
    // dup still names.
    assert_eq!(
        pidfd_test_socket_descriptors(&link),
        2,
        "the epoll's dup keeps the registration"
    );
    // The number again, now also in the other epoll.
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_dup2,
            [fd as u64, alias as u64, 0, 0, 0, 0]
        ),
        alias
    );
    add(&mut parent, other, 8);
    let mut forked = parent.fork_child(3, false, false).unwrap();
    pidfd_test_exit(&mut parent, &mut child);
    let exited = libc::EPOLLIN as u32;
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll_dup),
        BTreeMap::from([(7, exited)])
    );
    close(&mut parent, epoll_dup);
    // The fork's descriptor of the first epoll ends with its files, and the
    // first epoll with it; the other epoll's registration remains.
    forked.release_files_on_exit();
    assert_eq!(pidfd_test_socket_descriptors(&link), 2);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, other),
        BTreeMap::from([(8, exited)])
    );
    close(&mut parent, other);
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
}

/// The last task's exit ends its epolls' registrations of a pidfd, as
/// Linux's `exit_files` frees the epolls, even while something else holds
/// its table and another process holds the pidfd.
#[test]
fn the_last_tasks_exit_ends_its_epolls_pidfd_registrations_while_an_observer_holds_its_table() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let mut forked = parent.fork_child(3, false, false).unwrap();
    let epoll = pidfd_test_call(&mut forked, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut forked,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            0
        ),
        0
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 2);
    let _observer = forked.file_table.clone();
    forked.release_files_on_exit();
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
}

/// Exec keeps a pidfd's descriptors that are not close-on-exec, and the
/// pidfd with them. Reviewer test from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn exec_keeps_the_pidfds_that_are_not_close_on_exec() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let keep = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let clo = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_fcntl,
        [fd as u64, libc::F_DUPFD_CLOEXEC as u64, 30, 0, 0, 0],
    );
    let shadow = pidfd_test_record(&parent, fd).shadow();
    parent.replace_after_exec(test_state(&root.0)).unwrap();
    assert!(!parent.state.guest_pidfds.contains_key(&(fd as i32)));
    assert!(!parent.state.guest_pidfds.contains_key(&(clo as i32)));
    assert!(parent.state.guest_pidfds.contains_key(&(keep as i32)));
    assert!(shadow.upgrade().is_some());
    assert_eq!(pidfd_test_poll(&mut parent, &memory, keep), 0);
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_poll(&mut parent, &memory, keep),
        PIDFD_TEST_EXITED
    );
    pidfd_test_reap(&mut parent, &memory, 2);
    assert_eq!(
        pidfd_test_poll(&mut parent, &memory, keep),
        PIDFD_TEST_REAPED
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_close,
            [keep as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
    assert!(shadow.upgrade().is_none());
}

/// Edge-triggered and one-shot epoll registrations of a pidfd report the
/// exit once and the reap once, and a MOD rearms a one-shot registration;
/// none reports what a pidfd never does. Reviewer test from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn epoll_edge_and_one_shot_registrations_of_a_pidfd_report_as_linux_does() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let alias = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [fd as u64, 0, 0, 0, 0, 0],
    );
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let mask = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLPRI) as u32;
    for (target, modifier, data) in [(fd, libc::EPOLLET, 1), (alias, libc::EPOLLONESHOT, 2)] {
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                target,
                mask | modifier as u32,
                data
            ),
            0
        );
    }
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(1, libc::EPOLLIN as u32), (2, libc::EPOLLIN as u32)])
    );
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());
    pidfd_test_reap(&mut parent, &memory, 2);
    let reaped = (libc::EPOLLIN | libc::EPOLLHUP) as u32;
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(1, reaped)])
    );
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_MOD,
            alias,
            mask | libc::EPOLLONESHOT as u32,
            2
        ),
        0
    );
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epoll),
        BTreeMap::from([(2, reaped)])
    );
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());
}

/// The refusal of a pidfd in an `SCM_RIGHTS` message changes nothing, as
/// the typed refusal promises: a pipe right earlier in the same message is
/// not marked as exported, so its owner can still be set. Reviewer
/// regression from https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn a_refused_pidfd_right_leaves_the_rights_before_it_unexported() {
    let root = TestDir::new();
    let mut memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let [pipe, _] = owner_test_pipe(&mut parent.state);
    let mut control = rights_control(&[pipe, fd as i32]);
    assert_eq!(
        translate_outgoing_control(&mut control, &mut parent.state),
        Err(negative_errno(libc::ENOSYS))
    );
    assert_eq!(parent.state.pidfd_refusal, Some(PIDFD_RIGHTS_REFUSAL));
    assert_eq!(
        owner_test_call(&mut memory, &mut parent.state, pipe, libc::F_SETOWN, 0),
        0,
        "typed pidfd refusal promises changed nothing"
    );
}

/// `pidfd_open` of a live thread that leads no thread group is ENOENT, as
/// Linux's `pidfd_prepare` answers when the pid has no thread group leader
/// link (kernel/fork.c:1844 in v6.17,
/// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/fork.c?h=v6.17#n1844);
/// a native probe of a live thread measures errno 2. Reviewer regression
/// from https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn pidfd_open_of_a_thread_that_leads_no_group_is_enoent() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let _thread = parent.thread_child(9).unwrap();
    assert_eq!(
        pidfd_test_open(&mut parent, &memory, 9, 0),
        negative_errno(libc::ENOENT)
    );
}
#[test]
fn astra_aa_transferred_epoll_close_releases_private_descriptors() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll_link = std::path::Path::new("anon_inode:[eventpoll]");
    let before = pidfd_test_socket_descriptors(epoll_link);
    for _ in 0..32 {
        let original = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert!(original >= 0);
        assert_eq!(pidfd_test_epoll_ctl(&mut parent, &memory, original,
            libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, 1), 0);
        let received = pidfd_test_pass_right(&mut parent, &memory, original);
        for closing in [original, received] {
            assert_eq!(pidfd_test_call(&mut parent, &memory, libc::SYS_close,
                [closing as u64, 0, 0, 0, 0, 0]), 0);
        }
    }
    assert_eq!((pidfd_test_record(&parent, fd).epoll_registrations(),
        pidfd_test_socket_descriptors(epoll_link) - before,
        pidfd_test_socket_descriptors(&link)), (0, 0, 1),
        "no transferred epoll survives, so no private registration or epoll descriptor may remain");
}

#[test]
fn astra_aa_del_through_imported_epoll_releases_its_record() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let original = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(pidfd_test_epoll_ctl(&mut parent, &memory, original,
        libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, 1), 0);
    let received = pidfd_test_pass_right(&mut parent, &memory, original);
    assert_eq!(pidfd_test_call(&mut parent, &memory, libc::SYS_close,
        [original as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(pidfd_test_epoll_ctl(&mut parent, &memory, received,
        libc::EPOLL_CTL_DEL, fd, 0, 0), 0);
    assert_eq!((pidfd_test_record(&parent, fd).epoll_registrations(),
        pidfd_test_socket_descriptors(&link)), (0, 1),
        "successful imported DEL must release the original registration and key");
}

#[test]
fn astra_aa_distinct_imported_epolls_keep_the_correct_cleanup_record() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let mut imported = Vec::new();
    for _ in 0..2 {
        let original = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        let received = pidfd_test_pass_right(&mut parent, &memory, original);
        assert_eq!(pidfd_test_call(&mut parent, &memory, libc::SYS_close,
            [original as u64, 0, 0, 0, 0, 0]), 0);
        imported.push(received);
    }
    for (index, epoll) in imported.iter().enumerate() {
        assert_eq!(pidfd_test_epoll_ctl(&mut parent, &memory, *epoll,
            libc::EPOLL_CTL_ADD, fd, libc::EPOLLIN as u32, 101 + index as u64), 0);
    }
    assert_eq!(pidfd_test_epoll_ctl(&mut parent, &memory, imported[1],
        libc::EPOLL_CTL_DEL, fd, 0, 0), 0);
    let shadow = pidfd_test_record(&parent, fd).readiness_fd();
    // SAFETY: duplicate the live shadow, as a fork of the supervisor would.
    let raw_copy = unsafe { libc::fcntl(shadow, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(raw_copy >= 0);
    // SAFETY: the duplicate is new and owned by this frame.
    let _copy = unsafe { std::fs::File::from_raw_fd(raw_copy) };
    assert_eq!(pidfd_test_call(&mut parent, &memory, libc::SYS_close,
        [fd as u64, 0, 0, 0, 0, 0]), 0);
    pidfd_test_exit(&mut parent, &mut child);
    pidfd_test_reap(&mut parent, &memory, 2);
    assert!(pidfd_test_epoll_wait(&mut parent, &memory, imported[1]).is_empty());
    let events = pidfd_test_epoll_wait(&mut parent, &memory, imported[0]);
    assert!(events.is_empty(), "last-closed pidfd still registered in first imported epoll: {events:?}");
}
// Reviewer regressions for https://github.com/rrnewton/reverie/pull/1410.
// Include in the existing executor tests module beside pidfd_tests.rs.
// Linux's fdget keeps an epoll and its existing registrations alive for a
// control operation that acquired it before another thread's last close.
fn reviewer_inflight_epoll_control_survives_last_close(operation: libc::c_int) {
    assert!(matches!(operation, libc::EPOLL_CTL_MOD | libc::EPOLL_CTL_DEL));
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (parent, _child) = pidfd_test_family(&root, 2);
    let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
    let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
    assert!(fd >= 0);
    let link = pidfd_test_shadow_link(&parent.borrow(), fd);
    let epoll = pidfd_test_call(
        &mut parent.borrow_mut(),
        &memory,
        libc::SYS_epoll_create1,
        [0; 6],
    );
    assert!(epoll >= 0);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent.borrow_mut(),
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0,
        "the registration exists before the control call starts"
    );
    assert_eq!(
        pidfd_test_record(&parent.borrow(), fd).epoll_registrations(),
        1
    );
    // The thread shares the table and sees the already-registered epoll.
    let mut thread = parent.borrow().thread_child(9).unwrap();
    let closer = parent.clone();
    let closed = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_closed = closed.clone();
    COPY_REACHED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let memory = pidfd_test_memory();
            assert_eq!(
                pidfd_test_call(
                    &mut closer.borrow_mut(),
                    &memory,
                    libc::SYS_close,
                    [epoll as u64, 0, 0, 0, 0, 0],
                ),
                0
            );
            hook_closed.set(true);
        }));
    });
    // epoll_ctl first reaches epoll_fd. The hook closes its last table
    // entry at that point, while the caller still owns its fdget copy.
    let result = pidfd_test_epoll_ctl(
        &mut thread,
        &memory,
        epoll,
        operation,
        fd,
        libc::EPOLLIN as u32,
        2,
    );
    assert!(closed.get(), "the last close ran inside operation {operation}");
    assert!(COPY_REACHED_TEST_HOOK.with(|hook| hook.borrow().is_none()));
    assert_eq!(
        result, 0,
        "operation {operation} must find the registration in its fdget-kept epoll"
    );
    assert_eq!(
        pidfd_test_record(&parent.borrow(), fd).epoll_registrations(),
        0,
        "the epoll and its registrations end after the in-flight call returns"
    );
    assert_eq!(pidfd_test_socket_descriptors(&link), 1);
}

#[test]
fn reviewer_inflight_epoll_mod_survives_last_logical_close() {
    reviewer_inflight_epoll_control_survives_last_close(libc::EPOLL_CTL_MOD);
}

#[test]
fn reviewer_inflight_epoll_del_survives_last_logical_close() {
    reviewer_inflight_epoll_control_survives_last_close(libc::EPOLL_CTL_DEL);
}
/// An epoll_wait that has reached the epoll holds its open file description
/// for the call. Closing the last guest epoll descriptor must not discard the
/// pidfd's cleanup registration while that call can still observe the epoll.
/// The subsequent final pidfd close removes its interest, including when a
/// supervisor fork would keep a native copy of the private shadow alive.
/// Reviewer regression for https://github.com/rrnewton/reverie/pull/1410 at
/// aa559a3ab9baf8c672d7643862b4de4d5d310691.
#[test]
fn reviewer_inflight_epoll_wait_has_no_pidfd_ghost_after_both_logical_closes() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (parent, mut child) = pidfd_test_family(&root, 2);
    let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
    let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
    assert!(fd >= 0);
    let epoll = pidfd_test_call(
        &mut parent.borrow_mut(),
        &memory,
        libc::SYS_epoll_create1,
        [0; 6],
    );
    assert!(epoll >= 0);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent.borrow_mut(),
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            0x1410,
        ),
        0
    );

    // A native File duplicate keeps the socket OFD, not the Rust pidfd
    // record. Holding an Arc<GuestPidfd> here would delay the logical close
    // legitimately and would fail to exercise the defect.
    let record = pidfd_test_record(&parent.borrow(), fd);
    let shadow = record.shadow();
    // SAFETY: the record owns a live shadow descriptor; fcntl returns a new
    // descriptor owned by this test alone.
    let copied = unsafe {
        libc::fcntl(
            record.readiness_fd(),
            libc::F_DUPFD_CLOEXEC,
            libc::STDERR_FILENO + 1,
        )
    };
    assert!(copied >= 0);
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    let shadow_copy = unsafe { std::fs::File::from_raw_fd(copied) };
    drop(record);

    let mut thread = parent.borrow().thread_child(9).unwrap();
    pidfd_test_exit(&mut parent.borrow_mut(), &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent.borrow_mut(), &memory, epoll),
        BTreeMap::from([(0x1410, libc::EPOLLIN as u32)]),
        "positive control: the existing interest reports the exited child"
    );

    let closer = parent.clone();
    COPY_REACHED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let close_memory = pidfd_test_memory();
            // epoll_wait reaches E before it calls native epoll_wait. The
            // shared table's retirement must leave that reached copy to the
            // active call, as Linux fdget does.
            for closing in [epoll, fd] {
                assert_eq!(
                    pidfd_test_call(
                        &mut closer.borrow_mut(),
                        &close_memory,
                        libc::SYS_close,
                        [closing as u64, 0, 0, 0, 0, 0],
                    ),
                    0,
                    "close of {closing} during the epoll wait"
                );
            }
            assert!(
                shadow.upgrade().is_none(),
                "the pidfd really reached its final logical release"
            );
        }));
    });
    let observed = pidfd_test_epoll_wait(&mut thread, &memory, epoll);
    assert!(
        COPY_REACHED_TEST_HOOK.with(|hook| hook.borrow().is_none()),
        "the two closes ran after this wait reached its epoll"
    );

    // The socket remains readable: an empty result must come from removing
    // the closed pidfd's interest, not from draining/closing the shadow.
    let mut pollfd = libc::pollfd {
        fd: shadow_copy.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd is initialized and writable, and its fd remains live.
    assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
    assert_ne!(pollfd.revents & libc::POLLIN, 0);
    assert_eq!(
        observed,
        BTreeMap::new(),
        "a wait holding the epoll after its last guest close must not observe \
         the pidfd after that pidfd's final close, even while a native shadow \
         copy keeps its socket OFD alive"
    );
}

/// The guest descriptor of the host socket through which a test sends from
/// outside the run.
const PIDFD_TEST_OUTSIDE: i32 = 40;

/// A connected pair of guest Unix sockets of `kind`: the sender, then the
/// receiver.
fn pidfd_test_socket_pair(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    kind: libc::c_int,
) -> (i64, i64) {
    assert_eq!(
        pidfd_test_call(
            executor,
            memory,
            libc::SYS_socketpair,
            [libc::AF_UNIX as u64, kind as u64, 0, PIDFD_TEST_PAIR, 0, 0],
        ),
        0
    );
    let [sender, receiver]: [libc::c_int; 2] = read_struct(memory, PIDFD_TEST_PAIR);
    (i64::from(sender), i64::from(receiver))
}

/// Points the test message at its one-byte buffer, with room for
/// `control_length` bytes of control data.
fn pidfd_test_message(memory: &GuestMemory, control_length: usize) {
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as usize as *mut libc::c_void,
        iov_len: 1,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_IOV, &iov),
        0
    );
    // SAFETY: msghdr is plain data; a zeroed one names nothing.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as usize as *mut libc::iovec;
    message.msg_iovlen = 1;
    if control_length != 0 {
        message.msg_control = PIDFD_TEST_CONTROL as usize as *mut libc::c_void;
    }
    message.msg_controllen = control_length;
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_MESSAGE, &message),
        0
    );
}

/// What a sendmsg of one byte with `fds` in `SCM_RIGHTS` on guest socket
/// `socket` returns.
fn pidfd_test_send_rights(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    socket: i64,
    fds: &[libc::c_int],
) -> i64 {
    memory.write_raw(PIDFD_TEST_BYTE, b"x").unwrap();
    let control = rights_control(fds);
    memory.write_raw(PIDFD_TEST_CONTROL, &control).unwrap();
    pidfd_test_message(memory, control.len());
    pidfd_test_call(
        executor,
        memory,
        libc::SYS_sendmsg,
        [socket as u64, PIDFD_TEST_MESSAGE, 0, 0, 0, 0],
    )
}

/// A recvmsg of one byte on guest socket `socket` with `flags` and room for
/// `capacity` bytes of control data: its result, the rights it got and its
/// message flags.
fn pidfd_test_receive_rights(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    socket: i64,
    flags: libc::c_int,
    capacity: usize,
) -> (i64, Vec<libc::c_int>, libc::c_int) {
    assert!(capacity <= RIGHTS_CONTROL_CAPACITY);
    memory
        .write_raw(PIDFD_TEST_CONTROL, &[0_u8; RIGHTS_CONTROL_CAPACITY])
        .unwrap();
    pidfd_test_message(memory, capacity);
    let result = pidfd_test_call(
        executor,
        memory,
        libc::SYS_recvmsg,
        [
            socket as u64,
            PIDFD_TEST_MESSAGE,
            (flags | libc::MSG_DONTWAIT) as u64,
            0,
            0,
            0,
        ],
    );
    let received: libc::msghdr = read_struct(memory, PIDFD_TEST_MESSAGE);
    let mut control = vec![0_u8; received.msg_controllen.min(capacity)];
    memory.read_raw(PIDFD_TEST_CONTROL, &mut control).unwrap();
    (result, control_rights(&control), received.msg_flags)
}

fn pidfd_test_close(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64) {
    assert_eq!(
        pidfd_test_call(executor, memory, libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]),
        0,
        "close of {fd}"
    );
}

/// The identity of `executor`'s epoll `fd`.
fn pidfd_test_epoll_identity(executor: &ElfExecutor, fd: i64) -> Arc<EpollIdentity> {
    match native_poll_description(&executor.state, fd as i32) {
        Some(NativePollDescription::Epoll(identity)) => identity,
        _ => panic!("descriptor {fd} is no epoll with an identity"),
    }
}

/// Cycles of a registration of one pidfd made through one descriptor of an
/// epoll and removed through another, which an `SCM_RIGHTS` message made:
/// both name one open file description, so each DEL removes the
/// registration and its key, and nothing grows from cycle to cycle.
fn pidfd_test_cross_descriptor_cycles(add_through_received: bool) {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    for cycle in 0..8 {
        let original = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert!(original >= 0);
        let received = pidfd_test_pass_right(&mut parent, &memory, original);
        assert!(received >= 0);
        let (adding, deleting) = if add_through_received {
            (received, original)
        } else {
            (original, received)
        };
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                adding,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                cycle,
            ),
            0
        );
        if !add_through_received {
            pidfd_test_close(&mut parent, &memory, original);
        }
        assert_eq!(
            pidfd_test_epoll_ctl(&mut parent, &memory, deleting, libc::EPOLL_CTL_DEL, fd, 0, 0),
            0
        );
        assert_eq!(
            (
                pidfd_test_record(&parent, fd).epoll_registrations(),
                pidfd_test_socket_descriptors(&link),
            ),
            (0, 1),
            "cycle {cycle}: the DEL removed the registration and its key"
        );
        if add_through_received {
            pidfd_test_close(&mut parent, &memory, original);
        }
        pidfd_test_close(&mut parent, &memory, received);
    }
    assert_eq!(epoll_rights_in_flight(&parent.state), 0);
}

/// ADD through the original, pass, close the original, DEL through the
/// received descriptor. Reviewer regression from
/// https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn a_del_through_a_received_epoll_removes_the_pidfd_registration_its_original_added() {
    pidfd_test_cross_descriptor_cycles(false);
}

/// ADD through the received descriptor, DEL through the original. Reviewer
/// regression from https://github.com/rrnewton/reverie/pull/1410.
#[test]
fn a_del_through_an_epoll_removes_the_pidfd_registration_its_received_descriptor_added() {
    pidfd_test_cross_descriptor_cycles(true);
}

/// An `SCM_RIGHTS` message in flight owns the epoll it carries, as Linux's
/// message holds the files it carries, so closing the sender's last
/// descriptor before the receive leaves the epoll, its pidfd registration
/// and the registration's ADD/DEL identity to the receiver
/// (`EpollTransfer`): the received descriptor finds the registration, and
/// the epoll ends with the receiver's last close.
#[test]
fn an_epoll_closed_while_its_message_is_in_flight_keeps_its_pidfd_registration_for_the_receiver() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    let control = |parent: &mut ElfExecutor, epoll: i64, operation: libc::c_int, data: u64| {
        pidfd_test_epoll_ctl(parent, &memory, epoll, operation, fd, libc::EPOLLIN as u32, data)
    };
    assert_eq!(control(&mut parent, epoll, libc::EPOLL_CTL_ADD, 7), 0);
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    assert_eq!(epoll_rights_in_flight(&parent.state), 1);
    pidfd_test_close(&mut parent, &memory, epoll);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (1, 2),
        "the message in flight keeps the epoll and its registration"
    );
    let (result, rights, flags) =
        pidfd_test_receive_rights(&mut parent, &memory, receiver, 0, RIGHTS_CONTROL_CAPACITY);
    assert_eq!((result, rights.len(), flags & libc::MSG_CTRUNC), (1, 1, 0));
    let received = i64::from(rights[0]);
    assert_eq!(epoll_rights_in_flight(&parent.state), 0);
    assert_eq!(
        control(&mut parent, received, libc::EPOLL_CTL_ADD, 8),
        negative_errno(libc::EEXIST)
    );
    assert_eq!(control(&mut parent, received, libc::EPOLL_CTL_DEL, 0), 0);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1)
    );
    assert_eq!(control(&mut parent, received, libc::EPOLL_CTL_ADD, 9), 0);
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, received),
        BTreeMap::from([(9, libc::EPOLLIN as u32)])
    );
    pidfd_test_close(&mut parent, &memory, received);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1),
        "the epoll ends with the receiver's last close"
    );
    for socket in [sender, receiver] {
        pidfd_test_close(&mut parent, &memory, socket);
    }
}

/// A send that the host refuses queues no right, so it leaves nothing in
/// flight: the epoll ends with its last close, as an epoll never sent does.
#[test]
fn a_failed_send_of_an_epoll_leaves_no_right_in_flight() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    pidfd_test_close(&mut parent, &memory, receiver);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        negative_errno(libc::EPIPE)
    );
    assert_eq!(epoll_rights_in_flight(&parent.state), 0);
    pidfd_test_close(&mut parent, &memory, epoll);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1)
    );
    pidfd_test_close(&mut parent, &memory, sender);
}

/// A peek leaves its message queued, so its rights stay in flight: the
/// peeked descriptor and the received one are both descriptors of the
/// sender's epoll, whose registration lasts until the last of them goes.
#[test]
fn a_peek_of_an_epoll_right_leaves_it_in_flight_for_the_receive() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    let (result, peeked, _) = pidfd_test_receive_rights(
        &mut parent,
        &memory,
        receiver,
        libc::MSG_PEEK,
        RIGHTS_CONTROL_CAPACITY,
    );
    assert_eq!((result, peeked.len()), (1, 1));
    assert_eq!(
        epoll_rights_in_flight(&parent.state),
        1,
        "a peek leaves the right in flight"
    );
    let (result, rights, _) =
        pidfd_test_receive_rights(&mut parent, &memory, receiver, 0, RIGHTS_CONTROL_CAPACITY);
    assert_eq!((result, rights.len()), (1, 1));
    assert_eq!(epoll_rights_in_flight(&parent.state), 0);
    for closing in [epoll, i64::from(peeked[0])] {
        pidfd_test_close(&mut parent, &memory, closing);
    }
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (1, 2),
        "the received descriptor keeps the epoll"
    );
    let received = i64::from(rights[0]);
    assert_eq!(
        pidfd_test_epoll_ctl(&mut parent, &memory, received, libc::EPOLL_CTL_DEL, fd, 0, 0),
        0
    );
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1)
    );
    for closing in [received, sender, receiver] {
        pidfd_test_close(&mut parent, &memory, closing);
    }
}

/// A right that a receive takes from the host but drops, as one that faults
/// copying out or finds no descriptor free does, leaves flight
/// (`release_dropped_rights`): its epoll ends with the sender's last close.
#[test]
fn an_epoll_right_that_a_receive_drops_leaves_flight() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    // The host descriptor such a receive gets: another of the same epoll.
    let raw = host_fd(&parent.state, epoll as libc::c_int).unwrap();
    // SAFETY: raw is the parent's live host descriptor of the epoll;
    // F_DUPFD_CLOEXEC returns a new one, which this frame owns.
    let dropped = unsafe {
        std::fs::File::from_raw_fd(libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3))
    };
    release_dropped_rights(&parent.state, [&dropped], true);
    assert_eq!(
        epoll_rights_in_flight(&parent.state),
        1,
        "a peek's drop leaves the right queued"
    );
    release_dropped_rights(&parent.state, [&dropped], false);
    assert_eq!(epoll_rights_in_flight(&parent.state), 0);
    drop(dropped);
    pidfd_test_close(&mut parent, &memory, epoll);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1)
    );
    for socket in [sender, receiver] {
        pidfd_test_close(&mut parent, &memory, socket);
    }
}

/// The bound of epoll rights in flight (`EpollTransfer`): a right the host
/// discards unreceived never leaves flight. Here the receiving socket closes
/// with the message unread, and the registry still counts the right, whose
/// record keeps the epoll and its pidfd registration past the sender's last
/// close, as procfs rights are kept. Releasing such rights with the
/// receiving socket's queue will change this test.
#[test]
fn an_epoll_right_sent_to_a_socket_closed_unread_stays_in_flight() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    for closing in [receiver, sender, epoll] {
        pidfd_test_close(&mut parent, &memory, closing);
    }
    assert_eq!(
        (
            epoll_rights_in_flight(&parent.state),
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (1, 1, 2),
        "a right discarded unreceived stays in flight, with its epoll"
    );
}

/// The bound itself (`EpollTransfer`): each right that the host discards
/// unreceived stays in flight, so after `PROC_TRANSFER_LIMIT` of them every
/// later send of an epoll fails with ETOOMANYREFS, where Linux's succeeds. A
/// right this backend does not track still goes.
#[test]
fn after_the_bound_of_epoll_rights_discarded_unreceived_a_send_of_an_epoll_fails() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let mut parent = ElfExecutor::new(test_state(&root.0), false);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert!(epoll >= 0);
    for _ in 0..PROC_TRANSFER_LIMIT {
        let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
        assert_eq!(
            pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
            1
        );
        for closing in [receiver, sender] {
            pidfd_test_close(&mut parent, &memory, closing);
        }
    }
    assert_eq!(epoll_rights_in_flight(&parent.state), PROC_TRANSFER_LIMIT);
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        negative_errno(libc::ETOOMANYREFS)
    );
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_pipe2,
            [PIDFD_TEST_PAIR, 0, 0, 0, 0, 0]
        ),
        0
    );
    let [read_end, write_end]: [libc::c_int; 2] = read_struct(&memory, PIDFD_TEST_PAIR);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[read_end]),
        1
    );
    for closing in [
        i64::from(read_end),
        i64::from(write_end),
        sender,
        receiver,
        epoll,
    ] {
        pidfd_test_close(&mut parent, &memory, closing);
    }
}

/// A receive whose control buffer has no room for the right gets the
/// message without it, with MSG_CTRUNC, as Linux's does, and the right leaves
/// flight: the host receives with room for every right, so this backend
/// sees the one the guest's room drops (`truncate_received_control`).
#[test]
fn an_epoll_right_that_a_truncated_receive_drops_leaves_flight() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    pidfd_test_close(&mut parent, &memory, epoll);
    let (result, rights, flags) = pidfd_test_receive_rights(&mut parent, &memory, receiver, 0, 0);
    assert_eq!(
        (result, rights.len(), flags & libc::MSG_CTRUNC),
        (1, 0, libc::MSG_CTRUNC)
    );
    assert_eq!(
        (
            epoll_rights_in_flight(&parent.state),
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 0, 1),
        "the dropped right was the epoll's last owner"
    );
    for socket in [sender, receiver] {
        pidfd_test_close(&mut parent, &memory, socket);
    }
}

/// An epoll received from outside the run matches no right in flight, so it
/// gets an identity of its own (`received_epoll`), and two of them keep their
/// registrations of one pidfd apart: a DEL through one removes its own, and
/// the pidfd's last close removes the other's, though a copy of the shadow,
/// as a fork of the supervisor holds, stays open.
#[test]
fn epolls_received_from_outside_the_run_keep_their_pidfd_registrations_apart() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let mut state = test_state(&root.0);
    let (outside, inside) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(
        state
            .insert_file(PIDFD_TEST_OUTSIDE, std::fs::File::from(std::os::fd::OwnedFd::from(inside)))
            .is_empty()
    );
    let mut parent = ElfExecutor::new(state, false);
    let mut child = parent.fork_child(2, false, false).unwrap();
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    assert!(fd >= 0);
    let mut imported = Vec::new();
    for _ in 0..2 {
        // SAFETY: epoll_create1 has no memory arguments.
        let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(raw >= 0);
        // SAFETY: epoll_create1 returned a new descriptor that this frame owns.
        let epoll = unsafe { std::fs::File::from_raw_fd(raw) };
        let mut control = rights_control(&[epoll.as_raw_fd()]);
        let mut byte = *b"x";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        // SAFETY: msghdr is plain data; a zeroed one names nothing.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        // SAFETY: the header names live buffers of the lengths it gives.
        assert_eq!(unsafe { libc::sendmsg(outside.as_raw_fd(), &message, 0) }, 1);
        drop(epoll);
        let (result, rights, _) = pidfd_test_receive_rights(
            &mut parent,
            &memory,
            i64::from(PIDFD_TEST_OUTSIDE),
            0,
            RIGHTS_CONTROL_CAPACITY,
        );
        assert_eq!((result, rights.len()), (1, 1));
        imported.push(i64::from(rights[0]));
    }
    assert!(!Arc::ptr_eq(
        &pidfd_test_epoll_identity(&parent, imported[0]),
        &pidfd_test_epoll_identity(&parent, imported[1])
    ));
    for (index, epoll) in imported.iter().enumerate() {
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                *epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                101 + index as u64,
            ),
            0
        );
    }
    assert_eq!(
        pidfd_test_epoll_ctl(&mut parent, &memory, imported[1], libc::EPOLL_CTL_DEL, fd, 0, 0),
        0
    );
    assert_eq!(pidfd_test_record(&parent, fd).epoll_registrations(), 1);
    let shadow = pidfd_test_record(&parent, fd).readiness_fd();
    // SAFETY: duplicate the live shadow, as a fork of the supervisor would.
    let raw_copy = unsafe { libc::fcntl(shadow, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(raw_copy >= 0);
    // SAFETY: the duplicate is new and owned by this frame.
    let _copy = unsafe { std::fs::File::from_raw_fd(raw_copy) };
    pidfd_test_close(&mut parent, &memory, fd);
    pidfd_test_exit(&mut parent, &mut child);
    pidfd_test_reap(&mut parent, &memory, 2);
    for epoll in imported {
        assert!(pidfd_test_epoll_wait(&mut parent, &memory, epoll).is_empty());
    }
}

/// Without `kcmp`, a received epoll gets an identity of its own, and no right
/// stays in flight (`EpollTransfer`): a send whose comparison fails records
/// none, and a receive whose comparison fails releases every right in
/// flight, as no receive could find their records. Either way the sender's
/// registration ends with its last close.
#[test]
fn a_received_epoll_that_kcmp_cannot_compare_gets_an_identity_of_its_own() {
    for fail_at_receive in [false, true] {
        let root = TestDir::new();
        let memory = pidfd_test_memory();
        let (mut parent, _child) = pidfd_test_family(&root, 2);
        let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
        let link = pidfd_test_shadow_link(&parent, fd);
        let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                1,
            ),
            0
        );
        let identity = pidfd_test_epoll_identity(&parent, epoll);
        let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
        let fails = |at: bool| {
            if at {
                mapping_list::KCMP_FAILS_TEST_HOOK.with(|fails| fails.set(true));
            }
        };
        fails(!fail_at_receive);
        assert_eq!(
            pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
            1
        );
        assert_eq!(
            epoll_rights_in_flight(&parent.state),
            usize::from(fail_at_receive),
            "a send that cannot compare records nothing"
        );
        fails(fail_at_receive);
        let (result, rights, _) =
            pidfd_test_receive_rights(&mut parent, &memory, receiver, 0, RIGHTS_CONTROL_CAPACITY);
        assert!(
            !mapping_list::KCMP_FAILS_TEST_HOOK.with(std::cell::Cell::get),
            "the failing comparison ran"
        );
        assert_eq!((result, rights.len()), (1, 1));
        let received = i64::from(rights[0]);
        assert!(!Arc::ptr_eq(
            &pidfd_test_epoll_identity(&parent, received),
            &identity
        ));
        assert_eq!(epoll_rights_in_flight(&parent.state), 0);
        pidfd_test_close(&mut parent, &memory, epoll);
        assert_eq!(
            (
                pidfd_test_record(&parent, fd).epoll_registrations(),
                pidfd_test_socket_descriptors(&link),
            ),
            (0, 1),
            "kcmp fails at the receive: {fail_at_receive}"
        );
        for closing in [received, sender, receiver] {
            pidfd_test_close(&mut parent, &memory, closing);
        }
    }
}

/// The two ends of a new native pipe.
fn pidfd_test_native_pipe() -> (std::fs::File, std::fs::File) {
    let mut ends = [0; 2];
    // SAFETY: ends is writable for two descriptors.
    assert_eq!(unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: pipe2 returned two new descriptors that this frame owns.
    unsafe {
        (
            std::fs::File::from_raw_fd(ends[0]),
            std::fs::File::from_raw_fd(ends[1]),
        )
    }
}

/// A native sendmsg of one byte with `fds` in `SCM_RIGHTS` on `socket`.
fn pidfd_test_native_send_rights(socket: RawFd, fds: &[libc::c_int]) {
    let mut control = rights_control(fds);
    let mut byte = *b"x";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: msghdr is plain data; a zeroed one names nothing.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: the header names live buffers of the lengths it gives.
    assert_eq!(unsafe { libc::sendmsg(socket, &message, 0) }, 1);
}

/// A native recvmsg of one byte on `socket` with room for `capacity` bytes of
/// control data: its result, how many rights it got, which it closes, its
/// control length and its message flags.
fn pidfd_test_native_receive(socket: RawFd, capacity: usize) -> (isize, usize, usize, libc::c_int) {
    let mut byte = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = vec![0_u8; capacity];
    // SAFETY: msghdr is plain data; a zeroed one names nothing.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = capacity;
    // SAFETY: the header names live buffers of the lengths it gives.
    let result = unsafe {
        libc::recvmsg(
            socket,
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    let received = if result < 0 {
        0
    } else {
        message.msg_controllen.min(capacity)
    };
    let rights = control_rights(&control[..received]);
    for fd in &rights {
        // SAFETY: the receive installed each right once, for this frame.
        drop(unsafe { std::fs::File::from_raw_fd(*fd) });
    }
    (result, rights.len(), message.msg_controllen, message.msg_flags)
}

/// A receive with room for one of a message's two rights gets the first,
/// with the record's length and MSG_CTRUNC, as Linux's does
/// (`scm_detach_fds`), and the other leaves flight: it was its epoll's last
/// owner, so that epoll ends with its pidfd registration, while the received
/// descriptor keeps the first epoll and its registration.
#[test]
fn a_receive_with_room_for_one_of_two_epoll_rights_drops_the_second() {
    // SAFETY: CMSG_LEN is arithmetic on its argument.
    let room = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let (native_sender, native_receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let (first, second) = pidfd_test_native_pipe();
    pidfd_test_native_send_rights(
        native_sender.as_raw_fd(),
        &[first.as_raw_fd(), second.as_raw_fd()],
    );
    let (result, rights, length, flags) = pidfd_test_native_receive(native_receiver.as_raw_fd(), room);
    assert_eq!(
        (result, rights, length, flags & libc::MSG_CTRUNC),
        (1, 1, room, libc::MSG_CTRUNC),
        "Linux's receive"
    );
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let mut epolls = Vec::new();
    for data in [1, 2] {
        let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                data,
            ),
            0
        );
        epolls.push(epoll);
    }
    let first = pidfd_test_epoll_identity(&parent, epolls[0]);
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(
            &mut parent,
            &memory,
            sender,
            &[epolls[0] as libc::c_int, epolls[1] as libc::c_int],
        ),
        1
    );
    for epoll in &epolls {
        pidfd_test_close(&mut parent, &memory, *epoll);
    }
    let census = |parent: &ElfExecutor| {
        (
            epoll_rights_in_flight(&parent.state),
            pidfd_test_record(parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        )
    };
    assert_eq!(census(&parent), (2, 2, 2));
    let (result, rights, flags) = pidfd_test_receive_rights(&mut parent, &memory, receiver, 0, room);
    let received: libc::msghdr = read_struct(&memory, PIDFD_TEST_MESSAGE);
    assert_eq!(
        (
            result,
            rights.len(),
            received.msg_controllen,
            flags & libc::MSG_CTRUNC
        ),
        (1, 1, room, libc::MSG_CTRUNC),
        "as Linux's receive"
    );
    assert_eq!(
        census(&parent),
        (0, 1, 2),
        "the dropped right was its epoll's last owner"
    );
    let received = i64::from(rights[0]);
    assert!(Arc::ptr_eq(
        &pidfd_test_epoll_identity(&parent, received),
        &first
    ));
    drop(first);
    pidfd_test_close(&mut parent, &memory, received);
    assert_eq!(census(&parent), (0, 0, 1));
    for socket in [sender, receiver] {
        pidfd_test_close(&mut parent, &memory, socket);
    }
}

/// What a call of syscall `number` (read, readv, preadv2 at the current
/// position, or recvfrom with no flags and no address) for `length` bytes
/// from guest socket `socket` into the test byte returns.
fn pidfd_test_read_socket(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    number: libc::c_long,
    socket: i64,
    length: usize,
) -> i64 {
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as usize as *mut libc::c_void,
        iov_len: length,
    };
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_IOV, &iov),
        0
    );
    let args = match number {
        libc::SYS_readv => [socket as u64, PIDFD_TEST_IOV, 1, 0, 0, 0],
        libc::SYS_preadv2 => [socket as u64, PIDFD_TEST_IOV, 1, -1_i64 as u64, 0, 0],
        _ => [socket as u64, PIDFD_TEST_BYTE, length as u64, 0, 0, 0],
    };
    pidfd_test_call(executor, memory, number, args)
}

/// Whether the call `pidfd_test_read_socket` makes, on a native Unix stream
/// socket, discards the rights of the message it reaches.
fn pidfd_test_native_read_discards_rights(number: libc::c_long, length: usize) -> bool {
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let (right, _write) = pidfd_test_native_pipe();
    pidfd_test_native_send_rights(sender.as_raw_fd(), &[right.as_raw_fd()]);
    let socket = receiver.as_raw_fd();
    let mut byte = [0_u8; 1];
    let iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: length,
    };
    // SAFETY: the byte and its iovec are live for `length` bytes.
    let result = unsafe {
        match number {
            libc::SYS_readv => libc::readv(socket, &iov, 1),
            libc::SYS_preadv2 => {
                libc::syscall(
                    libc::SYS_preadv2,
                    libc::c_long::from(socket),
                    &iov as *const libc::iovec,
                    1 as libc::c_long,
                    -1 as libc::c_long,
                    0 as libc::c_long,
                    0 as libc::c_long,
                ) as isize
            }
            libc::SYS_recvfrom => libc::recv(socket, byte.as_mut_ptr().cast(), length, 0),
            _ => libc::read(socket, byte.as_mut_ptr().cast(), length),
        }
    };
    assert_eq!(result, length as isize);
    let (_, rights, _, _) = pidfd_test_native_receive(socket, RIGHTS_CONTROL_CAPACITY);
    rights == 0
}

/// A read, readv, preadv2 at the current position or recvfrom of a socket
/// asks for no control data, so Linux discards the rights of the message it
/// consumes, and this backend, which receives them with room for all,
/// releases them (`receive_discarding_rights`). A read, readv or preadv2 of
/// no byte never reaches the socket (`sock_read_iter`), so its right stays
/// in flight for the next receive; a recvfrom of no byte takes a stream
/// message's rights (`unix_stream_read_generic`). Each case is Linux's own.
#[test]
fn a_read_of_a_socket_releases_the_epoll_rights_linux_discards() {
    for number in [
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_preadv2,
        libc::SYS_recvfrom,
    ] {
        for length in [1, 0] {
            let case = format!("syscall {number} of {length} bytes");
            let discards = pidfd_test_native_read_discards_rights(number, length);
            assert_eq!(
                discards,
                length != 0 || number == libc::SYS_recvfrom,
                "{case}, natively"
            );
            let root = TestDir::new();
            let memory = pidfd_test_memory();
            let (mut parent, _child) = pidfd_test_family(&root, 2);
            let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
            let link = pidfd_test_shadow_link(&parent, fd);
            let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
            assert_eq!(
                pidfd_test_epoll_ctl(
                    &mut parent,
                    &memory,
                    epoll,
                    libc::EPOLL_CTL_ADD,
                    fd,
                    libc::EPOLLIN as u32,
                    1,
                ),
                0
            );
            let (sender, receiver) =
                pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
            assert_eq!(
                pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
                1
            );
            pidfd_test_close(&mut parent, &memory, epoll);
            assert_eq!(
                pidfd_test_read_socket(&mut parent, &memory, number, receiver, length),
                length as i64,
                "{case}"
            );
            let census = |parent: &ElfExecutor| {
                (
                    epoll_rights_in_flight(&parent.state),
                    pidfd_test_record(parent, fd).epoll_registrations(),
                    pidfd_test_socket_descriptors(&link),
                )
            };
            if discards {
                assert_eq!(census(&parent), (0, 0, 1), "{case}");
            } else {
                assert_eq!(census(&parent), (1, 1, 2), "{case}");
                let (result, rights, _) = pidfd_test_receive_rights(
                    &mut parent,
                    &memory,
                    receiver,
                    0,
                    RIGHTS_CONTROL_CAPACITY,
                );
                assert_eq!((result, rights.len()), (1, 1), "{case}");
                pidfd_test_close(&mut parent, &memory, i64::from(rights[0]));
                assert_eq!(
                    census(&parent),
                    (0, 0, 1),
                    "{case}: the received descriptor was the epoll's"
                );
            }
            for socket in [sender, receiver] {
                pidfd_test_close(&mut parent, &memory, socket);
            }
        }
    }
}

/// A peek that another process's receive races: the other receive takes the
/// message, and with it the right, and closes what it got, after the peek's
/// host receive and before the peek looks its epoll up
/// (`EPOLL_RECEIVED_TEST_HOOK`). The peek holds the epolls in flight from
/// before its host receive (`hold_epolls_in_flight`), so the epoll, its
/// record and its pin outlive that close, and the peeked descriptor joins the
/// sender's epoll, with its pidfd registration.
#[test]
fn a_peek_raced_by_another_processs_receive_keeps_the_senders_epoll() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let identity = pidfd_test_epoll_identity(&parent, epoll);
    let (sender, receiver) = pidfd_test_socket_pair(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        pidfd_test_send_rights(&mut parent, &memory, sender, &[epoll as libc::c_int]),
        1
    );
    let racer = std::rc::Rc::new(std::cell::RefCell::new(
        parent.fork_child(3, false, false).unwrap(),
    ));
    pidfd_test_close(&mut parent, &memory, epoll);
    pidfd_test_close(&mut racer.borrow_mut(), &pidfd_test_memory(), epoll);
    let census = |parent: &ElfExecutor| {
        (
            epoll_rights_in_flight(&parent.state),
            pidfd_test_record(parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        )
    };
    assert_eq!(census(&parent), (1, 1, 2), "the message owns the epoll");
    let hook_racer = racer.clone();
    let raced = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_raced = raced.clone();
    poll::EPOLL_RECEIVED_TEST_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let memory = pidfd_test_memory();
            let mut racer = hook_racer.borrow_mut();
            let (result, rights, _) =
                pidfd_test_receive_rights(&mut racer, &memory, receiver, 0, RIGHTS_CONTROL_CAPACITY);
            assert_eq!((result, rights.len()), (1, 1));
            pidfd_test_close(&mut racer, &memory, i64::from(rights[0]));
            hook_raced.set(true);
        }));
    });
    let (result, peeked, _) = pidfd_test_receive_rights(
        &mut parent,
        &memory,
        receiver,
        libc::MSG_PEEK,
        RIGHTS_CONTROL_CAPACITY,
    );
    assert!(raced.get(), "the other receive ran inside the peek");
    assert_eq!((result, peeked.len()), (1, 1));
    let peeked = i64::from(peeked[0]);
    assert!(Arc::ptr_eq(
        &pidfd_test_epoll_identity(&parent, peeked),
        &identity
    ));
    drop(identity);
    assert_eq!(
        census(&parent),
        (0, 1, 2),
        "the peeked descriptor keeps the sender's epoll"
    );
    assert_eq!(
        pidfd_test_epoll_ctl(&mut parent, &memory, peeked, libc::EPOLL_CTL_DEL, fd, 0, 0),
        0
    );
    assert_eq!(census(&parent), (0, 0, 1));
    for closing in [peeked, sender, receiver] {
        pidfd_test_close(&mut parent, &memory, closing);
    }
    for socket in [sender, receiver] {
        pidfd_test_close(&mut racer.borrow_mut(), &pidfd_test_memory(), socket);
    }
}

/// Exec closes an epoll's close-on-exec descriptors: an epoll whose last
/// descriptor that was ends with its pidfd registration by the time the exec
/// is done (`replace_after_exec`), and one whose descriptor is not
/// close-on-exec keeps its registration, which reports the exit.
#[test]
fn exec_ends_the_pidfd_registration_of_an_epoll_it_closes_and_keeps_the_others() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, mut child) = pidfd_test_family(&root, 2);
    let opened = pidfd_test_open(&mut parent, &memory, 2, 0);
    // pidfd_open's descriptor is close-on-exec; dup's is not.
    let fd = pidfd_test_call(
        &mut parent,
        &memory,
        libc::SYS_dup,
        [opened as u64, 0, 0, 0, 0, 0],
    );
    let link = pidfd_test_shadow_link(&parent, fd);
    let mut epolls = Vec::new();
    for (flags, data) in [(libc::EPOLL_CLOEXEC, 1), (0, 2)] {
        let epoll = pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_epoll_create1,
            [flags as u64, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent,
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                data,
            ),
            0
        );
        epolls.push(epoll);
    }
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (2, 2)
    );
    parent.replace_after_exec(test_state(&root.0)).unwrap();
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (1, 2),
        "the close-on-exec epoll ended with the exec"
    );
    pidfd_test_exit(&mut parent, &mut child);
    assert_eq!(
        pidfd_test_epoll_wait(&mut parent, &memory, epolls[1]),
        BTreeMap::from([(2, libc::EPOLLIN as u32)])
    );
    pidfd_test_close(&mut parent, &memory, epolls[1]);
    assert_eq!(
        (
            pidfd_test_record(&parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        ),
        (0, 1)
    );
    pidfd_test_close(&mut parent, &memory, fd);
}

/// A call that has reached an epoll owns it until the call ends, so the epoll
/// outlives a sibling thread's close of its last descriptor. If the thread
/// exits before its call ends, as a thread that an exit_group takes in a
/// wait does, its exit releases the epoll (`PrivateCopyGate::close`), which
/// then ends with its pidfd registration.
#[test]
fn a_threads_exit_releases_the_epoll_that_its_unfinished_call_reached() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let fd = pidfd_test_open(&mut parent, &memory, 2, 0);
    let link = pidfd_test_shadow_link(&parent, fd);
    let epoll = pidfd_test_call(&mut parent, &memory, libc::SYS_epoll_create1, [0; 6]);
    assert_eq!(
        pidfd_test_epoll_ctl(
            &mut parent,
            &memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            fd,
            libc::EPOLLIN as u32,
            1,
        ),
        0
    );
    let mut thread = parent.thread_child(9).unwrap();
    // The thread's call reaches its copy of the epoll, as epoll_wait's fdget
    // does, and has not ended when the thread exits.
    let scope = thread.state.private_copy_gate.call_scope();
    assert!(host_fd(&thread.state, epoll as libc::c_int).is_some());
    pidfd_test_close(&mut parent, &memory, epoll);
    let census = |parent: &ElfExecutor| {
        (
            pidfd_test_record(parent, fd).epoll_registrations(),
            pidfd_test_socket_descriptors(&link),
        )
    };
    assert_eq!(census(&parent), (1, 2), "the call owns the epoll");
    thread.release_files_on_exit();
    assert_eq!(census(&parent), (0, 1), "the exit released it");
    assert!(scope.end(9).is_ok());
    assert_eq!(census(&parent), (0, 1));
}

/// A control call that fails owned the epoll it reached all the same: when
/// a sibling closes the epoll's last descriptor during an ADD that Linux
/// refuses with EEXIST, or a MOD with EPOLLEXCLUSIVE that it refuses with
/// EINVAL, the epoll and its pidfd registration last until the call returns
/// its error, and end then.
#[test]
fn a_failed_control_call_releases_the_epoll_it_reached_when_it_returns() {
    for (operation, events, error) in [
        (libc::EPOLL_CTL_ADD, libc::EPOLLIN, libc::EEXIST),
        (
            libc::EPOLL_CTL_MOD,
            libc::EPOLLIN | libc::EPOLLEXCLUSIVE,
            libc::EINVAL,
        ),
    ] {
        let root = TestDir::new();
        let memory = pidfd_test_memory();
        let (parent, _child) = pidfd_test_family(&root, 2);
        let parent = std::rc::Rc::new(std::cell::RefCell::new(parent));
        let fd = pidfd_test_open(&mut parent.borrow_mut(), &memory, 2, 0);
        let link = pidfd_test_shadow_link(&parent.borrow(), fd);
        let epoll = pidfd_test_call(
            &mut parent.borrow_mut(),
            &memory,
            libc::SYS_epoll_create1,
            [0; 6],
        );
        assert_eq!(
            pidfd_test_epoll_ctl(
                &mut parent.borrow_mut(),
                &memory,
                epoll,
                libc::EPOLL_CTL_ADD,
                fd,
                libc::EPOLLIN as u32,
                1,
            ),
            0
        );
        let mut thread = parent.borrow().thread_child(9).unwrap();
        let closer = parent.clone();
        let hook_link = link.clone();
        let closed = std::rc::Rc::new(std::cell::Cell::new(false));
        let hook_closed = closed.clone();
        COPY_REACHED_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let memory = pidfd_test_memory();
                let mut closer = closer.borrow_mut();
                pidfd_test_close(&mut closer, &memory, epoll);
                assert_eq!(
                    (
                        pidfd_test_record(&closer, fd).epoll_registrations(),
                        pidfd_test_socket_descriptors(&hook_link),
                    ),
                    (1, 2),
                    "the call owns the epoll"
                );
                hook_closed.set(true);
            }));
        });
        assert_eq!(
            pidfd_test_epoll_ctl(&mut thread, &memory, epoll, operation, fd, events as u32, 2),
            negative_errno(error),
            "operation {operation}"
        );
        assert!(closed.get(), "the close ran inside operation {operation}");
        assert_eq!(
            (
                pidfd_test_record(&parent.borrow(), fd).epoll_registrations(),
                pidfd_test_socket_descriptors(&link),
            ),
            (0, 1),
            "operation {operation}: the epoll ended when the call returned"
        );
    }
}
// Reviewer regressions for https://github.com/rrnewton/reverie/pull/1410.
// Include beside pidfd_tests.rs in the existing executor tests module.
// Run serially: the eventpoll descriptor count observes /proc/self/fd.

struct ReviewerDiscardedEpoll {
    pidfd: i64,
    epoll: i64,
    sender: libc::c_int,
    receiver: libc::c_int,
    shadow: std::path::PathBuf,
    eventpolls_before: usize,
}

fn reviewer_discarded_epoll_setup(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    socket_kind: libc::c_int,
) -> ReviewerDiscardedEpoll {
    let pidfd = pidfd_test_open(executor, memory, 2, 0);
    assert!(pidfd >= 0);
    let shadow = pidfd_test_shadow_link(executor, pidfd);
    assert_eq!(pidfd_test_socket_descriptors(&shadow), 1);
    let eventpolls_before =
        pidfd_test_socket_descriptors(std::path::Path::new("anon_inode:[eventpoll]"));
    let epoll = pidfd_test_call(executor, memory, libc::SYS_epoll_create1, [0; 6]);
    assert!(epoll >= 0);
    assert_eq!(
        pidfd_test_epoll_ctl(
            executor,
            memory,
            epoll,
            libc::EPOLL_CTL_ADD,
            pidfd,
            libc::EPOLLIN as u32,
            0x1410,
        ),
        0
    );
    assert_eq!(pidfd_test_record(executor, pidfd).epoll_registrations(), 1);
    assert_eq!(
        pidfd_test_call(
            executor,
            memory,
            libc::SYS_socketpair,
            [
                libc::AF_UNIX as u64,
                (socket_kind | libc::SOCK_NONBLOCK) as u64,
                0,
                PIDFD_TEST_PAIR,
                0,
                0,
            ],
        ),
        0
    );
    let [sender, receiver]: [libc::c_int; 2] = read_struct(memory, PIDFD_TEST_PAIR);
    assert!(sender >= 0 && receiver >= 0);
    assert_ne!(sender, receiver);
    ReviewerDiscardedEpoll {
        pidfd,
        epoll,
        sender,
        receiver,
        shadow,
        eventpolls_before,
    }
}

fn reviewer_discarded_epoll_close(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    fd: i64,
) {
    assert_eq!(
        pidfd_test_call(executor, memory, libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]),
        0,
        "close of guest descriptor {fd}"
    );
}

fn reviewer_discarded_epoll_send(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    case: &ReviewerDiscardedEpoll,
    payload_length: usize,
) -> i64 {
    assert!(payload_length <= 1);
    memory.write_raw(PIDFD_TEST_BYTE, b"x").unwrap();
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as usize as *mut libc::c_void,
        iov_len: payload_length,
    };
    assert_eq!(write_struct(&mut ProviderMemory(memory), PIDFD_TEST_IOV, &iov), 0);
    let control = rights_control(&[case.epoll as libc::c_int]);
    assert!(control.len() <= RIGHTS_CONTROL_CAPACITY);
    memory.write_raw(PIDFD_TEST_CONTROL, &control).unwrap();
    // SAFETY: msghdr is plain data; its pointers below name guest memory.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as usize as *mut libc::iovec;
    message.msg_iovlen = 1;
    message.msg_control = PIDFD_TEST_CONTROL as usize as *mut libc::c_void;
    message.msg_controllen = control.len();
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_MESSAGE, &message),
        0
    );
    pidfd_test_call(
        executor,
        memory,
        libc::SYS_sendmsg,
        [case.sender as u64, PIDFD_TEST_MESSAGE, libc::MSG_DONTWAIT as u64, 0, 0, 0],
    )
}

fn reviewer_discarded_epoll_prepare_receive(memory: &GuestMemory, control_capacity: usize) {
    assert!(control_capacity <= RIGHTS_CONTROL_CAPACITY);
    memory.write_raw(PIDFD_TEST_BYTE, b"?").unwrap();
    let iov = libc::iovec {
        iov_base: PIDFD_TEST_BYTE as usize as *mut libc::c_void,
        iov_len: 1,
    };
    assert_eq!(write_struct(&mut ProviderMemory(memory), PIDFD_TEST_IOV, &iov), 0);
    memory
        .write_raw(PIDFD_TEST_CONTROL, &[0_u8; RIGHTS_CONTROL_CAPACITY])
        .unwrap();
    // SAFETY: msghdr is plain data; its pointers below name guest memory.
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = PIDFD_TEST_IOV as usize as *mut libc::iovec;
    message.msg_iovlen = 1;
    if control_capacity != 0 {
        message.msg_control = PIDFD_TEST_CONTROL as usize as *mut libc::c_void;
    }
    message.msg_controllen = control_capacity;
    assert_eq!(
        write_struct(&mut ProviderMemory(memory), PIDFD_TEST_MESSAGE, &message),
        0
    );
}

fn reviewer_discarded_epoll_assert_released(
    executor: &ElfExecutor,
    case: &ReviewerDiscardedEpoll,
) {
    assert_eq!(
        (
            pidfd_test_record(executor, case.pidfd).epoll_registrations(),
            pidfd_test_socket_descriptors(&case.shadow),
            pidfd_test_socket_descriptors(std::path::Path::new("anon_inode:[eventpoll]")),
        ),
        (0, 1, case.eventpolls_before),
        "after every guest epoll/socket alias and queued right is gone, no \
         registration, private shadow key, or host eventpoll descriptor may remain"
    );
}

#[test]
#[ignore = "dh-dk4cg1: in-flight rights are not released when the receiving socket's queue is destroyed"]
fn reviewer_closing_socket_with_unread_epoll_right_releases_pidfd_registration() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let case = reviewer_discarded_epoll_setup(&mut parent, &memory, libc::SOCK_DGRAM);
    assert_eq!(reviewer_discarded_epoll_send(&mut parent, &memory, &case, 1), 1);
    assert_ne!(
        pidfd_test_poll(&mut parent, &memory, i64::from(case.receiver)) & libc::POLLIN,
        0,
        "the receiving socket has the unread message"
    );
    reviewer_discarded_epoll_close(&mut parent, &memory, case.epoll);
    reviewer_discarded_epoll_close(&mut parent, &memory, i64::from(case.sender));
    assert_eq!(
        pidfd_test_record(&parent, case.pidfd).epoll_registrations(),
        1,
        "the queued right still owns the epoll before the receiver closes"
    );
    reviewer_discarded_epoll_close(&mut parent, &memory, i64::from(case.receiver));
    reviewer_discarded_epoll_assert_released(&parent, &case);
}

#[test]
fn reviewer_recvmsg_without_control_discards_epoll_right_and_releases_registration() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let case = reviewer_discarded_epoll_setup(&mut parent, &memory, libc::SOCK_DGRAM);
    assert_eq!(reviewer_discarded_epoll_send(&mut parent, &memory, &case, 1), 1);
    reviewer_discarded_epoll_close(&mut parent, &memory, case.epoll);
    reviewer_discarded_epoll_prepare_receive(&memory, 0);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_recvmsg,
            [case.receiver as u64, PIDFD_TEST_MESSAGE, libc::MSG_DONTWAIT as u64, 0, 0, 0],
        ),
        1,
        "the datagram is consumed even though its right cannot be returned"
    );
    let received: libc::msghdr = read_struct(&memory, PIDFD_TEST_MESSAGE);
    assert_eq!(received.msg_controllen, 0);
    assert_eq!(received.msg_flags & libc::MSG_CTRUNC, libc::MSG_CTRUNC);
    let mut payload = [0_u8; 1];
    memory.read_raw(PIDFD_TEST_BYTE, &mut payload).unwrap();
    assert_eq!(payload, *b"x");
    for socket in [case.sender, case.receiver] {
        reviewer_discarded_epoll_close(&mut parent, &memory, i64::from(socket));
    }
    reviewer_discarded_epoll_assert_released(&parent, &case);
}

#[test]
fn reviewer_zero_byte_stream_send_queues_no_epoll_right_and_releases_registration() {
    let root = TestDir::new();
    let memory = pidfd_test_memory();
    let (mut parent, _child) = pidfd_test_family(&root, 2);
    let case = reviewer_discarded_epoll_setup(&mut parent, &memory, libc::SOCK_STREAM);
    assert_eq!(
        reviewer_discarded_epoll_send(&mut parent, &memory, &case, 0),
        0,
        "Linux accepts a zero-byte stream send but does not queue its rights"
    );
    reviewer_discarded_epoll_prepare_receive(&memory, RIGHTS_CONTROL_CAPACITY);
    assert_eq!(
        pidfd_test_call(
            &mut parent,
            &memory,
            libc::SYS_recvmsg,
            [case.receiver as u64, PIDFD_TEST_MESSAGE, libc::MSG_DONTWAIT as u64, 0, 0, 0],
        ),
        negative_errno(libc::EAGAIN),
        "with the sender still open, no payload or epoll right was queued"
    );
    for fd in [case.epoll, i64::from(case.sender), i64::from(case.receiver)] {
        reviewer_discarded_epoll_close(&mut parent, &memory, fd);
    }
    reviewer_discarded_epoll_assert_released(&parent, &case);
}
