//! Native child implementation: raw syscalls, fixed stack messages and mmap
//! bookkeeping only. No allocator, Rust destructors, locks, logging or callbacks
//! run after fork. This candidate is for the crate's x86-64 Linux host ABI.

use std::os::fd::RawFd;

pub(super) const MAX_RIGHTS: usize = 253;
const MAGIC: u64 = 0x7265766578697431;
const VERSION: u32 = 1;
pub(super) const BOOT: u32 = 1;
pub(super) const START: u32 = 2;
pub(super) const READY: u32 = 3;
pub(super) const RIGHTS: u32 = 4;
pub(super) const ACK: u32 = 5;
pub(super) const GO: u32 = 6;
pub(super) const DONE: u32 = 7;
pub(super) const ERROR: u32 = 8;
pub(super) const SHUTDOWN: u32 = 9;
pub(super) const BEGIN: u32 = 10;
pub(super) const CHUNK_ACK: u32 = 11;
pub(super) const ABORT: u32 = 12;
pub(super) const INCOMPLETE: u32 = 13;
pub(super) const ANCILLARY_INCOMPLETE: i32 = 1;
pub(super) const EXPORT_CLIENT: u32 = 14;
pub(super) const EXPORT_READY: u32 = 15;
pub(super) const ADOPT_CLIENT: u32 = 16;
pub(super) const ADOPTED_CLIENT: u32 = 17;
pub(super) const BROKER_IDENTITY: u32 = 18;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(super) struct Frame {
    magic: u64,
    version: u32,
    pub kind: u32,
    pub job: u64,
    pub sequence: u64,
    pub count: u64,
    pub status: i64,
}

impl Frame {
    pub fn valid(&self) -> bool {
        self.magic == MAGIC && self.version == VERSION
    }

    pub fn with_nonce(kind: u32, nonce: [u8; 32]) -> Self {
        let words: [u64; 4] = core::array::from_fn(|i| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&nonce[i * 8..i * 8 + 8]);
            u64::from_ne_bytes(bytes)
        });
        Self {
            magic: MAGIC,
            version: VERSION,
            kind,
            job: words[0],
            sequence: words[1],
            count: words[2],
            status: words[3] as i64,
        }
    }

    pub fn nonce(&self) -> [u8; 32] {
        let words = [self.job, self.sequence, self.count, self.status as u64];
        let mut nonce = [0; 32];
        for (i, word) in words.iter().enumerate() {
            nonce[i * 8..i * 8 + 8].copy_from_slice(&word.to_ne_bytes());
        }
        nonce
    }

    pub fn new(kind: u32, job: u64, sequence: u64, count: u64) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            kind,
            job,
            sequence,
            count,
            status: 0,
        }
    }
}

const WORD: usize = size_of::<usize>();
const HEADER: usize = size_of::<libc::cmsghdr>();
const CONTROL_WORDS: usize = (HEADER + MAX_RIGHTS * size_of::<i32>()).div_ceil(WORD);
const NODE_BYTES: usize = 4096;

#[inline]
pub(super) unsafe fn syscall(
    number: libc::c_long,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> isize {
    let result: isize;
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") number as isize => result,
                        in("rdi") a, in("rsi") b, in("rdx") c,
                        in("r10") d, in("r8") e, in("r9") f,
                        lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    result
}

pub(super) unsafe fn send_frame(
    fd: RawFd,
    frame: &Frame,
    rights: *const RawFd,
    count: usize,
    nonblocking: bool,
) -> i32 {
    if count > MAX_RIGHTS {
        return -libc::EINVAL;
    }
    let mut control = [0usize; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: (frame as *const Frame).cast_mut().cast(),
        iov_len: size_of::<Frame>(),
    };
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if count != 0 {
        let hdr = control.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*hdr).cmsg_len = HEADER + count * size_of::<RawFd>();
            (*hdr).cmsg_level = libc::SOL_SOCKET;
            (*hdr).cmsg_type = libc::SCM_RIGHTS;
            core::ptr::copy_nonoverlapping(
                rights,
                control.as_mut_ptr().cast::<u8>().add(HEADER).cast(),
                count,
            );
        }
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = (HEADER + count * size_of::<RawFd>() + WORD - 1) & !(WORD - 1);
    }
    let flags = libc::MSG_NOSIGNAL | if nonblocking { libc::MSG_DONTWAIT } else { 0 };
    let rc = unsafe {
        syscall(
            libc::SYS_sendmsg,
            fd as usize,
            (&msg as *const libc::msghdr) as usize,
            flags as usize,
            0,
            0,
            0,
        )
    };
    if rc == size_of::<Frame>() as isize {
        0
    } else if rc < 0 {
        rc as i32
    } else {
        -libc::EPROTO
    }
}

/// Installs every returned right into `rights`; `received` is valid even on a
/// later frame error. The caller owns those installed descriptors in all cases.
pub(super) unsafe fn receive_frame(
    fd: RawFd,
    frame: &mut Frame,
    rights: *mut RawFd,
    capacity: usize,
    received: &mut usize,
    nonblocking: bool,
) -> i32 {
    *received = 0;
    if capacity != MAX_RIGHTS {
        return -libc::EINVAL;
    }
    let mut control = [0usize; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: (frame as *mut Frame).cast(),
        iov_len: size_of::<Frame>(),
    };
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of_val(&control);
    let flags = libc::MSG_CMSG_CLOEXEC | if nonblocking { libc::MSG_DONTWAIT } else { 0 };
    let rc = unsafe {
        syscall(
            libc::SYS_recvmsg,
            fd as usize,
            (&mut msg as *mut libc::msghdr) as usize,
            flags as usize,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return rc as i32;
    }
    let mut offset = 0;
    let mut bad = false;
    while offset + HEADER <= msg.msg_controllen {
        let hdr = unsafe {
            &*control
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<libc::cmsghdr>()
        };
        let len = hdr.cmsg_len;
        if len < HEADER || len > msg.msg_controllen - offset {
            bad = true;
            break;
        }
        if hdr.cmsg_level != libc::SOL_SOCKET
            || hdr.cmsg_type != libc::SCM_RIGHTS
            || !(len - HEADER).is_multiple_of(size_of::<RawFd>())
        {
            bad = true;
        } else {
            let n = (len - HEADER) / size_of::<RawFd>();
            if n > capacity.saturating_sub(*received) {
                // Parent and native callers always provide MAX_RIGHTS space.
                // A smaller capacity is not used for untrusted control data.
                bad = true;
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        control
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + HEADER)
                            .cast::<RawFd>(),
                        rights.add(*received),
                        n,
                    );
                }
                *received += n;
            }
        }
        offset += (len + WORD - 1) & !(WORD - 1);
    }
    if rc == 0 && *received == 0 {
        return -libc::ECONNRESET;
    }
    if bad
        || msg.msg_flags & libc::MSG_TRUNC != 0
        || rc != size_of::<Frame>() as isize
        || frame.magic != MAGIC
        || frame.version != VERSION
    {
        -libc::EPROTO
    } else if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        ANCILLARY_INCOMPLETE
    } else {
        0
    }
}

unsafe fn close(fd: RawFd) {
    if fd >= 0 {
        let _ = unsafe { syscall(libc::SYS_close, fd as usize, 0, 0, 0, 0, 0) };
    }
}

pub(super) unsafe fn close_except(fd: RawFd) -> i32 {
    if fd < 0 {
        return -libc::EBADF;
    }
    if fd > 0 {
        let rc = unsafe { syscall(libc::SYS_close_range, 0, fd as usize - 1, 0, 0, 0, 0) };
        if rc < 0 {
            return rc as i32;
        }
    }
    let rc = unsafe {
        syscall(
            libc::SYS_close_range,
            fd as usize + 1,
            u32::MAX as usize,
            0,
            0,
            0,
            0,
        )
    };
    if rc < 0 { rc as i32 } else { 0 }
}

pub(super) unsafe fn exit(status: i32) -> ! {
    let _ = unsafe { syscall(libc::SYS_exit_group, status as usize, 0, 0, 0, 0, 0) };
    // SYS_exit_group cannot return on the supported native ABI. Avoid unwinding
    // arbitrary inherited Rust frames even under an impossible syscall failure.
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

unsafe fn send_blocking(fd: RawFd, frame: &Frame) -> i32 {
    loop {
        let rc = unsafe { send_frame(fd, frame, core::ptr::null(), 0, false) };
        if rc != -libc::EINTR {
            return rc;
        }
    }
}

unsafe fn receive_blocking(
    fd: RawFd,
    frame: &mut Frame,
    rights: &mut [RawFd; MAX_RIGHTS],
    received: &mut usize,
) -> i32 {
    loop {
        let rc =
            unsafe { receive_frame(fd, frame, rights.as_mut_ptr(), MAX_RIGHTS, received, false) };
        if rc != -libc::EINTR {
            return rc;
        }
    }
}

// x86-64 asm-generic UAPI; require the real option, never a uname or PID lookup.
const SO_PEERPIDFD: usize = 77;

unsafe fn peer_pidfd(fd: RawFd) -> Result<RawFd, i32> {
    let mut pidfd: RawFd = -1;
    let mut length = size_of::<RawFd>() as libc::socklen_t;
    let rc = unsafe {
        syscall(
            libc::SYS_getsockopt,
            fd as usize,
            libc::SOL_SOCKET as usize,
            SO_PEERPIDFD,
            (&mut pidfd as *mut RawFd) as usize,
            (&mut length as *mut libc::socklen_t) as usize,
            0,
        )
    };
    if rc < 0 {
        return Err(rc as i32);
    }
    if length as usize != size_of::<RawFd>() || pidfd < 0 {
        return Err(-libc::EPROTO);
    }
    Ok(pidfd)
}

/// Only the retained whole-process pidfd's readable result authorizes orphan
/// cleanup. A channel HUP, leader/thread exit, stop, or observer error does not.
unsafe fn worker_poll(fd: RawFd, peer: RawFd, events: i16, timeout: i32) -> i32 {
    loop {
        let mut fds = [
            libc::pollfd {
                fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: peer,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe {
            syscall(
                libc::SYS_poll,
                fds.as_mut_ptr() as usize,
                fds.len(),
                timeout as usize,
                0,
                0,
                0,
            )
        };
        if rc == -(libc::EINTR as isize) {
            continue;
        }
        if rc < 0 {
            return rc as i32;
        }
        let observed = fds[1].revents;
        if observed & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return -libc::EIO;
        }
        if observed & (libc::POLLIN | libc::POLLRDNORM) != 0 {
            unsafe { exit(0) }
        }
        if observed != 0 {
            return -libc::EPROTO;
        }
        if fds[0].revents & libc::POLLNVAL != 0 {
            return -libc::EBADF;
        }
        return 0;
    }
}

unsafe fn worker_send(fd: RawFd, peer: RawFd, frame: &Frame) -> i32 {
    if peer < 0 {
        return unsafe { send_blocking(fd, frame) };
    }
    let mut delay = 1;
    loop {
        let rc = unsafe { send_frame(fd, frame, core::ptr::null(), 0, true) };
        if rc == -libc::EINTR {
            continue;
        }
        let wait = if rc == -libc::EAGAIN {
            unsafe { worker_poll(fd, peer, libc::POLLOUT, -1) }
        } else if rc == -libc::ENOMEM || rc == -libc::ENOBUFS {
            let wait = unsafe { worker_poll(-1, peer, 0, delay) };
            delay = (delay * 2).min(1000);
            wait
        } else {
            return rc;
        };
        if wait != 0 {
            return wait;
        }
    }
}

unsafe fn worker_receive(
    fd: RawFd,
    peer: RawFd,
    frame: &mut Frame,
    rights: &mut [RawFd; MAX_RIGHTS],
    received: &mut usize,
) -> i32 {
    if peer < 0 {
        return unsafe { receive_blocking(fd, frame, rights, received) };
    }
    loop {
        let rc =
            unsafe { receive_frame(fd, frame, rights.as_mut_ptr(), MAX_RIGHTS, received, true) };
        if rc == -libc::EINTR {
            continue;
        }
        if rc != -libc::EAGAIN {
            return rc;
        }
        let wait = unsafe { worker_poll(fd, peer, libc::POLLIN, -1) };
        if wait != 0 {
            return wait;
        }
    }
}

/// After ACK, loss of the protocol alone cannot authorize release. Watch only
/// the process pidfd, avoiding a permanent EOF busy loop. A broken observer is
/// an explicit retained adverse-host failure, not a guessed successful exit.
unsafe fn retain_until_client_death(peer: RawFd) -> ! {
    loop {
        if unsafe { worker_poll(-1, peer, 0, -1) } != 0 {
            loop {
                let _ = unsafe { syscall(libc::SYS_pause, 0, 0, 0, 0, 0, 0) };
            }
        }
    }
}

fn abort_frame(frame: &Frame, job: u64, received: usize) -> bool {
    received == 0
        && frame.kind == ABORT
        && frame.job == job
        && frame.sequence == 0
        && frame.count == 0
        && frame.status == 0
}

/// A pre-retirement error keeps its installed prefix until the parent requests
/// ABORT. The parent still holds every original; native abort exit therefore
/// cannot perform a last release of a transferred socket. No reuse of a partial
/// worker is attempted: actual wait precedes a new reservation/transfer.
unsafe fn wait_abort(fd: RawFd, peer: RawFd, job: u64, count: u64, kind: u32, errno: i32) -> ! {
    let mut report = Frame::new(kind, job, 0, count);
    report.status = errno as i64;
    if unsafe { worker_send(fd, peer, &report) } != 0 {
        unsafe { exit(122) }
    }
    loop {
        let mut frame = Frame::new(0, 0, 0, 0);
        let mut rights = [-1; MAX_RIGHTS];
        let mut received = 0;
        let rc = unsafe { worker_receive(fd, peer, &mut frame, &mut rights, &mut received) };
        if rc == 0 && abort_frame(&frame, job, received) {
            unsafe { exit(0) }
        }
        if rc == -libc::ECONNRESET {
            unsafe { exit(122) }
        }
        // Trusted-protocol violations do not release received owners. There is
        // no guest receipt and no allocator/destructor unwind on this path.
        if unsafe { worker_send(fd, peer, &report) } != 0 {
            unsafe { exit(122) }
        }
    }
}

unsafe fn worker(fd: RawFd, job: u64, expected_parent: libc::pid_t) -> ! {
    // First raw action in the native fork child, before any inherited close.
    let armed = unsafe { arm_parent_death(expected_parent) };
    if armed != 0 {
        unsafe { wait_abort(fd, -1, job, 0, ERROR, -armed) }
    }
    if unsafe { close_except(fd) } != 0 {
        unsafe { exit(120) }
    }
    // The socketpair was created in the adopting client itself; SCM transport
    // retains that peer TGID identity. No runtime numeric-PID reopen occurs.
    // This is the last permanent descriptor allocation before READY.
    let peer = match unsafe { peer_pidfd(fd) } {
        Ok(peer) => peer,
        Err(rc) => unsafe { wait_abort(fd, -1, job, 0, ERROR, -rc) },
    };
    let pid = unsafe { syscall(libc::SYS_getpid, 0, 0, 0, 0, 0, 0) };
    let ready = Frame::new(READY, job, pid as u64, 0);
    if unsafe { worker_send(fd, peer, &ready) } != 0 {
        unsafe { exit(121) }
    }
    let mut begin = Frame::new(0, 0, 0, 0);
    let mut rights = [-1; MAX_RIGHTS];
    let mut received = 0;
    let rc = unsafe { worker_receive(fd, peer, &mut begin, &mut rights, &mut received) };
    if rc == 0 && abort_frame(&begin, job, received) {
        unsafe { exit(0) }
    }
    if rc != 0
        || received != 0
        || begin.kind != BEGIN
        || begin.job != job
        || begin.sequence != 0
        || begin.count > i32::MAX as u64
        || begin.status != 0
    {
        unsafe { exit(122) }
    }
    let count = begin.count;
    let mut got = 0u64;
    while got < count {
        let wanted = (count - got).min(MAX_RIGHTS as u64) as usize;
        let provision = unsafe { provision_receive_slots(fd, wanted) };
        if provision != 0 {
            unsafe { wait_abort(fd, peer, job, count, ERROR, -provision) }
        }
        let mut frame = Frame::new(0, 0, 0, 0);
        let mut rights = [-1; MAX_RIGHTS];
        let mut received = 0;
        let rc = unsafe { worker_receive(fd, peer, &mut frame, &mut rights, &mut received) };
        if rc == 0 && abort_frame(&frame, job, received) {
            unsafe { exit(0) }
        }
        if rc == ANCILLARY_INCOMPLETE
            && frame.kind == RIGHTS
            && frame.job == job
            && frame.sequence == got
            && frame.count > 0
            && frame.count <= count - got
            && received as u64 <= frame.count
        {
            unsafe { wait_abort(fd, peer, job, count, INCOMPLETE, 0) }
        }
        if rc < 0 {
            if rc == -libc::ECONNRESET {
                unsafe { exit(122) }
            }
            unsafe { wait_abort(fd, peer, job, count, ERROR, -rc) }
        }
        if rc != 0
            || frame.kind != RIGHTS
            || frame.job != job
            || frame.sequence != got
            || frame.count == 0
            || frame.count != received as u64
            || frame.count > count - got
            || frame.status != 0
        {
            unsafe { wait_abort(fd, peer, job, count, ERROR, libc::EPROTO) }
        }
        got += received as u64;
        let chunk_ack = Frame::new(CHUNK_ACK, job, got, count);
        if unsafe { worker_send(fd, peer, &chunk_ack) } != 0 {
            unsafe { exit(122) }
        }
        // All installed rights remain in this private native fdtable. The
        // parent sends the next <=253 chunk only after consuming this ACK.
    }
    let ack = Frame::new(ACK, job, got, count);
    if unsafe { worker_send(fd, peer, &ack) } != 0 {
        unsafe { exit(123) }
    }
    loop {
        let mut frame = Frame::new(0, 0, 0, 0);
        let mut rights = [-1; MAX_RIGHTS];
        let mut received = 0;
        let rc = unsafe { worker_receive(fd, peer, &mut frame, &mut rights, &mut received) };
        // Parent may abort before CONSUMING the complete ACK, while originals
        // are still owned. After it retires originals it can only send GO.
        if rc == 0 && abort_frame(&frame, job, received) {
            unsafe { exit(0) }
        }
        if rc == 0
            && received == 0
            && frame.kind == GO
            && frame.job == job
            && frame.sequence == count
            && frame.count == count
            && frame.status == 0
        {
            unsafe { exit(0) }
        }
        let mut error = Frame::new(ERROR, job, got, count);
        error.status = if rc >= 0 {
            libc::EPROTO as i64
        } else {
            -rc as i64
        };
        if unsafe { worker_send(fd, peer, &error) } != 0 {
            // ACK may already have permitted parent retirement. Channel loss
            // alone is never death. Whole-client pidfd completion occurs only
            // after its native exit_files/task-work; native cleanup is then
            // safe, and is not a guest success or substitute for broker wait.
            unsafe { retain_until_client_death(peer) }
        }
    }
}

#[repr(C)]
struct Node {
    next: *mut Node,
    pid: i32,
    completion: i32,
    job: u64,
    count: u64,
    wait_status: i32,
    reaped: bool,
    failed: bool,
}

unsafe fn allocate_node() -> *mut Node {
    let rc = unsafe {
        syscall(
            libc::SYS_mmap,
            0,
            NODE_BYTES,
            (libc::PROT_READ | libc::PROT_WRITE) as usize,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
            usize::MAX,
            0,
        )
    };
    if (-4095..0).contains(&rc) {
        core::ptr::null_mut()
    } else {
        rc as *mut Node
    }
}

unsafe fn free_node(node: *mut Node) {
    let _ = unsafe { syscall(libc::SYS_munmap, node as usize, NODE_BYTES, 0, 0, 0, 0) };
}

unsafe fn setup_error(fd: RawFd, errno: i32, count: u64) {
    let mut error = Frame::new(ERROR, 0, 0, count);
    error.status = errno as i64;
    let _ = unsafe { send_frame(fd, &error, core::ptr::null(), 0, true) };
}

#[path = "daemon.rs"]
mod daemon;

pub(super) unsafe fn broker(control: RawFd, expected_parent: libc::pid_t) -> ! {
    // The bootstrap caller is single-threaded and remains the original native
    // creator with unchanged credentials until reap. No arbitrary embedding
    // creator-thread reparenting is inferred from a numeric getppid alone.
    let armed = unsafe { arm_parent_death(expected_parent) };
    if armed != 0 {
        unsafe {
            setup_error(control, -armed, 0);
            exit(124)
        }
    }
    unsafe { daemon::run(control) }
}

unsafe fn arm_parent_death(expected_parent: libc::pid_t) -> i32 {
    let rc = unsafe {
        syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG as usize,
            libc::SIGKILL as usize,
            0,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return rc as i32;
    }
    let parent = unsafe { syscall(libc::SYS_getppid, 0, 0, 0, 0, 0, 0) };
    if parent != expected_parent as isize {
        unsafe { exit(127) }
    }
    0
}

fn resource_error(rc: i32) -> bool {
    matches!(
        -rc,
        libc::EINTR
            | libc::EAGAIN
            | libc::EMFILE
            | libc::ENFILE
            | libc::ENOMEM
            | libc::ETOOMANYREFS
    )
}

/// Grow the private fdtable and prove enough free slots before consuming a
/// rights message. No host rlimit/sysctl changes. Each temporary descriptor is
/// another reference to this internal socket (no .flush); the original stays
/// live. The native process has one thread, a private fdtable and no handlers.
unsafe fn provision_receive_slots(control: RawFd, count: usize) -> i32 {
    if count > MAX_RIGHTS {
        return -libc::EINVAL;
    }
    let mut reserved = [-1; MAX_RIGHTS];
    let mut n = 0;
    let mut error = 0;
    while n < count {
        let fd = unsafe {
            syscall(
                libc::SYS_fcntl,
                control as usize,
                libc::F_DUPFD_CLOEXEC as usize,
                0,
                0,
                0,
                0,
            )
        };
        if fd < 0 {
            error = fd as i32;
            break;
        }
        reserved[n] = fd as i32;
        n += 1;
    }
    for fd in &reserved[..n] {
        unsafe {
            close(*fd);
        }
    }
    error
}
