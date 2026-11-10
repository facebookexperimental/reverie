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

/// An epoll that an `SCM_RIGHTS` message carried may outlive every
/// descriptor of it that the sender's table counts, so its registration of
/// a pidfd outlives them too, until its DEL, as Linux's lasts while the
/// receiver holds the epoll: the received descriptor's ADD finds it
/// (EEXIST), its DEL removes it, and a new ADD makes one registration, not
/// two.
#[test]
fn a_pidfd_registration_in_an_epoll_passed_in_scm_rights_lasts_until_its_del() {
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
