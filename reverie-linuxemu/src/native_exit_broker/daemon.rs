//! Raw daemon: no Rust allocation/Drop and no guest descriptors. Job rights go
//! directly to a private worker; this process receives only internal channels.
use super::*;

#[repr(C)]
struct Session {
    next: *mut Session,
    fd: RawFd,
    nonce: [u8; 32],
    adopted: bool,
    poll_index: usize,
}

unsafe fn now_ns() -> u64 {
    let mut time: libc::timespec = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        syscall(
            libc::SYS_clock_gettime,
            libc::CLOCK_MONOTONIC as usize,
            (&mut time as *mut libc::timespec) as usize,
            0,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        unsafe { exit(125) }
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}

unsafe fn allocate(bytes: usize) -> *mut u8 {
    let rc = unsafe {
        syscall(
            libc::SYS_mmap,
            0,
            bytes,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
            usize::MAX,
            0,
        )
    };
    if (-4095..0).contains(&rc) {
        core::ptr::null_mut()
    } else {
        rc as *mut u8
    }
}

unsafe fn spawn_job(
    frame: &Frame,
    rights: &[RawFd; MAX_RIGHTS],
    received: usize,
    nodes: &mut *mut Node,
    next_job: &mut u64,
) {
    if frame.kind != START
        || received != 2
        || frame.job != 0
        || frame.sequence != 0
        || frame.count != 0
        || frame.status != 0
        || *next_job == u64::MAX
    {
        unsafe { exit(126) }
    }
    let node = unsafe { allocate_node() };
    if node.is_null() {
        unsafe {
            setup_error(rights[1], libc::ENOMEM, 0);
            close(rights[0]);
            close(rights[1]);
        }
        return;
    }
    let job = *next_job;
    *next_job += 1;
    // The daemon alone changes its private SIGCHLD action. Worker fork has
    // normal SIGCHLD; its sole parent waits it exactly. The launcher disposition
    // remains untouched; the daemon itself is a clone0 child of that launcher.
    let expected_parent = unsafe { syscall(libc::SYS_getpid, 0, 0, 0, 0, 0, 0) } as libc::pid_t;
    let child = unsafe { syscall(libc::SYS_fork, 0, 0, 0, 0, 0, 0) };
    if child == 0 {
        unsafe { worker(rights[0], job, expected_parent) }
    }
    if child < 0 {
        unsafe {
            setup_error(rights[1], -child as i32, 0);
            close(rights[0]);
            close(rights[1]);
            free_node(node);
        }
        return;
    }
    unsafe {
        close(rights[0]);
        node.write(Node {
            next: *nodes,
            pid: child as i32,
            completion: rights[1],
            job,
            count: 0,
            wait_status: 0,
            reaped: false,
            failed: false,
        });
    }
    *nodes = node;
}

unsafe fn reap(nodes: &mut *mut Node) -> bool {
    let mut retry_completion = false;
    let mut link = nodes as *mut *mut Node;
    while !unsafe { *link }.is_null() {
        let node = unsafe { *link };
        if !unsafe { (*node).reaped } {
            let rc = unsafe {
                syscall(
                    libc::SYS_wait4,
                    (*node).pid as usize,
                    core::ptr::addr_of_mut!((*node).wait_status) as usize,
                    libc::WNOHANG as usize,
                    0,
                    0,
                    0,
                )
            };
            if rc == unsafe { (*node).pid } as isize {
                unsafe {
                    (*node).reaped = true;
                }
            } else if rc < 0 && rc != -(libc::EINTR as isize) {
                unsafe {
                    (*node).reaped = true;
                    (*node).failed = true;
                    (*node).wait_status = -rc as i32;
                }
            }
        }
        if unsafe { (*node).reaped } {
            // count=0 is deliberate: START reserves an EMPTY worker. This
            // receipt proves only the job's native wait. The parent binds the
            // transferred count from its worker's final ACK, not this daemon.
            let mut frame = unsafe {
                Frame::new(
                    if (*node).failed { ERROR } else { DONE },
                    (*node).job,
                    (*node).pid as u64,
                    0,
                )
            };
            frame.status = unsafe { (*node).wait_status } as i64;
            let rc = unsafe { send_frame((*node).completion, &frame, core::ptr::null(), 0, true) };
            if rc == -libc::EAGAIN || rc == -libc::EINTR || rc == -libc::ENOMEM {
                retry_completion = true;
                link = unsafe { core::ptr::addr_of_mut!((*node).next) };
            } else {
                unsafe {
                    close((*node).completion);
                    *link = (*node).next;
                    free_node(node);
                }
            }
        } else {
            link = unsafe { core::ptr::addr_of_mut!((*node).next) };
        }
    }
    retry_completion
}

/// Peek does not consume a queued SCM list. Omitted ancillary output in the
/// peek can drop only temporary copies; the original queued references remain.
/// Only this daemon consumes its endpoints, so the envelope cannot be replaced
/// between peek and receive. Peek identifies zero-right EOF/shutdown/adoption,
/// avoiding a full-fd-table deadlock while trying to receive a close notice.
unsafe fn peek(fd: RawFd, frame: &mut Frame) -> i32 {
    let rc = unsafe {
        syscall(
            libc::SYS_recvfrom,
            fd as usize,
            (frame as *mut Frame) as usize,
            size_of::<Frame>(),
            (libc::MSG_PEEK | libc::MSG_DONTWAIT) as usize,
            0,
            0,
        )
    };
    if rc < 0 {
        return rc as i32;
    }
    if rc == 0 {
        return -libc::ECONNRESET;
    }
    if rc != size_of::<Frame>() as isize || !frame.valid() {
        -libc::EPROTO
    } else {
        0
    }
}

unsafe fn request(
    fd: RawFd,
    frame: &mut Frame,
    rights: &mut [RawFd; MAX_RIGHTS],
    received: &mut usize,
) -> i32 {
    let rc = unsafe { peek(fd, frame) };
    if rc != 0 {
        return rc;
    }
    let slots = if frame.kind == START || frame.kind == EXPORT_CLIENT {
        2
    } else {
        0
    };
    let rc = unsafe { provision_receive_slots(fd, slots) };
    if rc != 0 {
        return rc;
    }
    unsafe { receive_frame(fd, frame, rights.as_mut_ptr(), MAX_RIGHTS, received, true) }
}

pub(super) unsafe fn run(control: RawFd) -> ! {
    let close_rc = unsafe { close_except(control) };
    if close_rc != 0 {
        unsafe {
            setup_error(control, -close_rc, 0);
            exit(124)
        }
    }
    #[repr(C)]
    struct KernelAction {
        handler: usize,
        flags: usize,
        restorer: usize,
        mask: u64,
    }
    let action = KernelAction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let rc = unsafe {
        syscall(
            libc::SYS_rt_sigaction,
            libc::SIGCHLD as usize,
            (&action as *const KernelAction) as usize,
            0,
            size_of::<u64>(),
            0,
            0,
        )
    };
    if rc < 0 {
        unsafe {
            setup_error(control, -rc as i32, 0);
            exit(124)
        }
    }
    let mask: u64 = 1 << (libc::SIGCHLD - 1);
    let sigfd = unsafe {
        syscall(
            libc::SYS_signalfd4,
            usize::MAX,
            (&mask as *const u64) as usize,
            size_of::<u64>(),
            (libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) as usize,
            0,
            0,
        )
    };
    if sigfd < 0 {
        unsafe {
            setup_error(control, -sigfd as i32, 0);
            exit(124)
        }
    }
    // A retained self pidfd is transferred only after the dedicated session
    // nonce proof. SO_PEERPIDFD on that session would identify its launcher,
    // not this daemon, because the launcher created the session socketpair.
    let broker_pid = unsafe { syscall(libc::SYS_getpid, 0, 0, 0, 0, 0, 0) };
    let broker_pidfd = unsafe { syscall(libc::SYS_pidfd_open, broker_pid as usize, 0, 0, 0, 0, 0) };
    if broker_pidfd < 0 {
        unsafe {
            setup_error(control, -broker_pidfd as i32, 0);
            exit(124)
        }
    }
    let mut poll_bytes = NODE_BYTES;
    let mut polls = unsafe { allocate(poll_bytes) }.cast::<libc::pollfd>();
    if polls.is_null() {
        unsafe {
            setup_error(control, libc::ENOMEM, 0);
            exit(124)
        }
    }
    let boot = Frame::new(BOOT, 0, 0, 0);
    if unsafe { send_blocking(control, &boot) } != 0 {
        unsafe { exit(124) }
    }
    let mut nodes = core::ptr::null_mut();
    let mut sessions: *mut Session = core::ptr::null_mut();
    let mut session_count = 0usize;
    let mut next_job = 1u64;
    let mut shutting_down = false;
    let mut blocked_until = 0u64;
    let mut backoff_ms = 1u64;
    loop {
        let retry_completion = unsafe { reap(&mut nodes) };
        if shutting_down && nodes.is_null() {
            unsafe { exit(0) }
        }
        let now = unsafe { now_ns() };
        let blocked = now < blocked_until;
        unsafe {
            polls.add(0).write(libc::pollfd {
                fd: if shutting_down || blocked {
                    -1
                } else {
                    control
                },
                events: libc::POLLIN,
                revents: 0,
            });
            polls.add(1).write(libc::pollfd {
                fd: sigfd as i32,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let mut used = 2usize;
        let mut session = sessions;
        while !session.is_null() {
            unsafe {
                (*session).poll_index = used;
                polls.add(used).write(libc::pollfd {
                    fd: if shutting_down || blocked {
                        -1
                    } else {
                        (*session).fd
                    },
                    events: libc::POLLIN,
                    revents: 0,
                });
                session = (*session).next;
            }
            used += 1;
        }
        let mut timeout = if retry_completion { 50isize } else { -1 };
        if blocked {
            let remaining = (blocked_until - now).div_ceil(1_000_000).min(1000) as isize;
            timeout = if timeout < 0 {
                remaining
            } else {
                timeout.min(remaining)
            };
        }
        let rc = unsafe {
            syscall(
                libc::SYS_poll,
                polls as usize,
                used,
                timeout as usize,
                0,
                0,
                0,
            )
        };
        if rc < 0 {
            if rc == -(libc::EINTR as isize) {
                continue;
            } else {
                unsafe { exit(125) }
            }
        }
        if unsafe { (*polls.add(1)).revents } != 0 {
            let mut info = [0u8; 128];
            while unsafe {
                syscall(
                    libc::SYS_read,
                    sigfd as usize,
                    info.as_mut_ptr() as usize,
                    info.len(),
                    0,
                    0,
                    0,
                )
            } > 0
            {}
        }
        let mut retry_resource = false;
        if unsafe { (*polls).revents } != 0 {
            let mut frame = Frame::new(0, 0, 0, 0);
            let mut rights = [-1; MAX_RIGHTS];
            let mut received = 0;
            let rc = unsafe { request(control, &mut frame, &mut rights, &mut received) };
            if resource_error(rc) {
                retry_resource = true;
            } else if rc == -libc::ECONNRESET {
                shutting_down = true;
            } else if rc != 0 {
                unsafe { exit(126) }
            } else if frame.kind == SHUTDOWN
                && received == 0
                && frame.job == 0
                && frame.sequence == 0
                && frame.count == 0
                && frame.status == 0
            {
                shutting_down = true;
            } else if frame.kind == EXPORT_CLIENT && received == 2 {
                let next_count = session_count.saturating_add(1);
                let needed = next_count
                    .checked_add(2)
                    .and_then(|n| n.checked_mul(size_of::<libc::pollfd>()))
                    .unwrap_or(usize::MAX);
                let mut ok = needed != usize::MAX;
                if ok && needed > poll_bytes {
                    let new_bytes = needed
                        .checked_add(NODE_BYTES - 1)
                        .map(|n| n & !(NODE_BYTES - 1))
                        .unwrap_or(0);
                    let new_polls = if new_bytes == 0 {
                        core::ptr::null_mut()
                    } else {
                        unsafe { allocate(new_bytes) }.cast::<libc::pollfd>()
                    };
                    if new_polls.is_null() {
                        ok = false;
                    } else {
                        // No old poll pointer is used for new sessions this
                        // turn. Existing revents are copied before releasing.
                        unsafe {
                            core::ptr::copy_nonoverlapping(polls, new_polls, used);
                            syscall(libc::SYS_munmap, polls as usize, poll_bytes, 0, 0, 0, 0);
                        }
                        polls = new_polls;
                        poll_bytes = new_bytes;
                    }
                }
                let new_session = if ok {
                    unsafe { allocate(NODE_BYTES) }.cast::<Session>()
                } else {
                    core::ptr::null_mut()
                };
                if new_session.is_null() {
                    unsafe {
                        setup_error(rights[1], libc::ENOMEM, 0);
                        close(rights[0]);
                        close(rights[1]);
                    }
                } else {
                    unsafe {
                        new_session.write(Session {
                            next: sessions,
                            fd: rights[0],
                            nonce: frame.nonce(),
                            adopted: false,
                            poll_index: usize::MAX,
                        });
                    }
                    sessions = new_session;
                    session_count = next_count;
                    let ready = Frame::with_nonce(EXPORT_READY, frame.nonce());
                    let sent = unsafe { send_blocking(rights[1], &ready) };
                    unsafe {
                        close(rights[1]);
                    }
                    if sent != 0 {
                        unsafe {
                            sessions = (*new_session).next;
                            close((*new_session).fd);
                            syscall(
                                libc::SYS_munmap,
                                new_session as usize,
                                NODE_BYTES,
                                0,
                                0,
                                0,
                                0,
                            );
                        }
                        session_count -= 1;
                    }
                }
            } else {
                unsafe {
                    spawn_job(&frame, &rights, received, &mut nodes, &mut next_job);
                }
            }
        }
        let mut link = &mut sessions as *mut *mut Session;
        while !unsafe { *link }.is_null() {
            let session = unsafe { *link };
            let index = unsafe { (*session).poll_index };
            if index >= used || unsafe { (*polls.add(index)).revents } == 0 {
                link = unsafe { core::ptr::addr_of_mut!((*session).next) };
                continue;
            }
            let mut frame = Frame::new(0, 0, 0, 0);
            let mut rights = [-1; MAX_RIGHTS];
            let mut received = 0;
            let rc = unsafe { request((*session).fd, &mut frame, &mut rights, &mut received) };
            let mut remove = false;
            if resource_error(rc) {
                retry_resource = true;
            } else if rc == -libc::ECONNRESET {
                remove = true;
            } else if rc != 0 {
                unsafe { exit(126) }
            } else if !unsafe { (*session).adopted } {
                if received == 0
                    && frame.kind == ADOPT_CLIENT
                    && frame.job == 0
                    && frame.sequence == 0
                    && frame.count == 0
                    && frame.status == 0
                {
                    // Server-first proof: the child did NOT send the expected
                    // nonce. This registered private endpoint supplies it once.
                    let reply = unsafe { Frame::with_nonce(ADOPTED_CLIENT, (*session).nonce) };
                    if unsafe { send_blocking((*session).fd, &reply) } == 0 {
                        let identity = Frame::new(BROKER_IDENTITY, broker_pid as u64, 0, 1);
                        let right = broker_pidfd as RawFd;
                        let sent = loop {
                            let rc =
                                unsafe { send_frame((*session).fd, &identity, &right, 1, false) };
                            if rc != -libc::EINTR {
                                break rc;
                            }
                        };
                        if sent == 0 {
                            unsafe {
                                (*session).adopted = true;
                            }
                        } else {
                            remove = true;
                        }
                    } else {
                        remove = true;
                    }
                } else {
                    remove = true;
                }
            } else if frame.kind == START {
                unsafe {
                    spawn_job(&frame, &rights, received, &mut nodes, &mut next_job);
                }
            } else {
                remove = true;
            }
            if remove {
                // A valid client endpoint holds only internal START channels.
                // Unexpected installed rights are not ordinarily destroyed.
                if received != 0 {
                    unsafe { exit(126) }
                }
                unsafe {
                    close((*session).fd);
                    *link = (*session).next;
                    syscall(libc::SYS_munmap, session as usize, NODE_BYTES, 0, 0, 0, 0);
                }
                session_count -= 1;
            } else {
                link = unsafe { core::ptr::addr_of_mut!((*session).next) };
            }
        }
        if retry_resource {
            blocked_until = unsafe { now_ns() }.saturating_add(backoff_ms * 1_000_000);
            backoff_ms = (backoff_ms * 2).min(1000);
        }
    }
}
