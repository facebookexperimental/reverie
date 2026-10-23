//! Native F1 SEND and F3 UPDATE-prefix controls, after mapped setup fd closure.
//! These are ordinary owned kernel operations, without instrumentation or guards.
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

#[repr(C)]
#[derive(Default)]
struct Offsets {
    head: u32,
    tail: u32,
    mask: u32,
    entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    reserved: u32,
    user: u64,
}
#[repr(C)]
#[derive(Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    cpu: u32,
    idle: u32,
    features: u32,
    wq_fd: u32,
    reserved: [u32; 3],
    sq: Offsets,
    cq: Offsets,
}
struct Ring {
    fd: OwnedFd,
    params: Params,
    sq: *mut u8,
    cq: *mut u8,
    sqes: *mut u8,
    sq_len: usize,
    cq_len: usize,
    sqes_len: usize,
}

unsafe fn map(fd: i32, len: usize, offset: libc::off_t) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            offset,
        )
    };
    assert_ne!(
        p,
        libc::MAP_FAILED,
        "native ring mapping: {}",
        std::io::Error::last_os_error()
    );
    p.cast()
}
impl Ring {
    fn new() -> Self {
        let mut params = Params::default();
        assert_eq!(std::mem::size_of::<Params>(), 120);
        let raw = unsafe { libc::syscall(libc::SYS_io_uring_setup, 4u32, &mut params) };
        assert!(
            raw >= 0,
            "native io_uring_setup unavailable/failed: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        assert_eq!(params.flags, 0);
        let mut sq_len = params.sq.array as usize + params.sq_entries as usize * 4;
        // CQ offsets: overflow at +16, cqes at +20, flags at +24.
        let mut cq_len = params.cq.dropped as usize + params.cq_entries as usize * 16;
        let (sq, cq) = if params.features & 1 != 0 {
            sq_len = sq_len.max(cq_len);
            cq_len = sq_len;
            let sq = unsafe { map(fd.as_raw_fd(), sq_len, 0) };
            (sq, sq)
        } else {
            unsafe {
                (
                    map(fd.as_raw_fd(), sq_len, 0),
                    map(fd.as_raw_fd(), cq_len, 0x0800_0000),
                )
            }
        };
        let sqes_len = params.sq_entries as usize * 64;
        let sqes = unsafe { map(fd.as_raw_fd(), sqes_len, 0x1000_0000) };
        Self {
            fd,
            params,
            sq,
            cq,
            sqes,
            sq_len,
            cq_len,
            sqes_len,
        }
    }
    fn send(&mut self, fd: i32, peer: i32, bytes: &[u8], token: u64) {
        unsafe {
            let head = &*self
                .sq
                .add(self.params.sq.head as usize)
                .cast::<AtomicU32>();
            let tail = &*self
                .sq
                .add(self.params.sq.tail as usize)
                .cast::<AtomicU32>();
            let old_tail = tail.load(Ordering::Relaxed);
            assert!(old_tail.wrapping_sub(head.load(Ordering::Acquire)) < self.params.sq_entries);
            let mask = self
                .sq
                .add(self.params.sq.mask as usize)
                .cast::<u32>()
                .read();
            let index = old_tail & mask;
            let sqe = self.sqes.add(index as usize * 64);
            std::ptr::write_bytes(sqe, 0, 64);
            *sqe = 26; // IORING_OP_SEND, without IOSQE_FIXED_FILE.
            sqe.add(4).cast::<i32>().write(fd);
            sqe.add(16).cast::<u64>().write(bytes.as_ptr() as u64);
            sqe.add(24).cast::<u32>().write(bytes.len() as u32);
            sqe.add(28).cast::<u32>().write(libc::MSG_NOSIGNAL as u32);
            sqe.add(32).cast::<u64>().write(token);
            println!(
                "native SEND SQE={:02x?}",
                std::slice::from_raw_parts(sqe, 64)
            );
            self.sq
                .add(self.params.sq.array as usize)
                .cast::<u32>()
                .add(index as usize)
                .write(index);
            tail.store(old_tail.wrapping_add(1), Ordering::Release);
            assert_eq!(
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    self.fd.as_raw_fd(),
                    1u32,
                    1u32,
                    1u32,
                    0usize,
                    0usize
                ),
                1
            );
            let cq_head = &*self
                .cq
                .add(self.params.cq.head as usize)
                .cast::<AtomicU32>();
            let cq_tail = &*self
                .cq
                .add(self.params.cq.tail as usize)
                .cast::<AtomicU32>();
            let old_head = cq_head.load(Ordering::Relaxed);
            assert_eq!(cq_tail.load(Ordering::Acquire).wrapping_sub(old_head), 1);
            let cq_mask = self
                .cq
                .add(self.params.cq.mask as usize)
                .cast::<u32>()
                .read();
            let cqe = self
                .cq
                .add(self.params.cq.dropped as usize + (old_head & cq_mask) as usize * 16);
            assert_eq!(cqe.cast::<u64>().read(), token);
            assert_eq!(cqe.add(8).cast::<i32>().read(), bytes.len() as i32);
            assert_eq!(cqe.add(12).cast::<u32>().read(), 0);
            println!(
                "native SEND CQE={:02x?}",
                std::slice::from_raw_parts(cqe, 16)
            );
            cq_head.store(old_head.wrapping_add(1), Ordering::Release);
            let mut received = [0u8; 128];
            let count = libc::recv(
                peer,
                received.as_mut_ptr().cast(),
                received.len(),
                libc::MSG_DONTWAIT,
            );
            assert_eq!(count, bytes.len() as isize);
            assert_eq!(
                &received[..count as usize],
                bytes,
                "native SEND peer bytes changed"
            );
            assert_eq!(
                libc::recv(
                    peer,
                    received.as_mut_ptr().cast(),
                    received.len(),
                    libc::MSG_DONTWAIT
                ),
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            println!("native SEND completed token={token} bytes={bytes:?}");
        }
    }
}
impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sqes.cast(), self.sqes_len);
            if self.cq != self.sq {
                libc::munmap(self.cq.cast(), self.cq_len);
            }
            libc::munmap(self.sq.cast(), self.sq_len);
        }
    }
}
fn packet_pair() -> [OwnedFd; 2] {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        },
        0
    );
    fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}
pub fn run() {
    let ordinary = packet_pair();
    let reused = packet_pair();
    let mut ring = Ring::new();
    ring.send(
        ordinary[0].as_raw_fd(),
        ordinary[1].as_raw_fd(),
        b"ordinary-ring-control",
        101,
    );
    ring.send(
        reused[0].as_raw_fd(),
        reused[1].as_raw_fd(),
        b"forged-log-data\n",
        102,
    );
    drop(ring);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/mapped-rpc-implementation/native");
    std::fs::create_dir_all(&dir).unwrap();
    let dir = std::fs::canonicalize(dir).unwrap();
    for op in [6u64, 14] {
        let mut params = [0u64; 32];
        let raw = unsafe { libc::syscall(libc::SYS_io_uring_setup, 2u32, params.as_mut_ptr()) };
        assert!(
            raw >= 0,
            "native prefix setup failed: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let paths = ["old0", "old1", "new0"]
            .map(|name| dir.join(format!("{name}-{op}-{}", std::process::id())));
        let files = paths.each_ref().map(|p| std::fs::File::create(p).unwrap());
        let initial = [files[0].as_raw_fd(), files[1].as_raw_fd()];
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_io_uring_register,
                    fd.as_raw_fd(),
                    2u32,
                    initial.as_ptr(),
                    2u32,
                )
            },
            0
        );
        let fdinfo = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
        let before = std::fs::read_to_string(&fdinfo).unwrap();
        let update = [files[2].as_raw_fd(), -12345];
        let header = [0u64, update.as_ptr() as u64, 0, 2];
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                fd.as_raw_fd(),
                op,
                header.as_ptr(),
                if op == 6 { 2u32 } else { 32u32 },
            )
        };
        let after = std::fs::read_to_string(&fdinfo).unwrap();
        assert_eq!(
            result, 1,
            "native UPDATE prefix return changed, opcode {op}"
        );
        let slots = |text: &str| {
            text.lines()
                .filter(|line| line.starts_with("    ") && line.contains(": "))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            slots(&before),
            vec![
                format!("    0: {}", paths[0].display()),
                format!("    1: {}", paths[1].display())
            ]
        );
        assert_eq!(
            slots(&after),
            vec![format!("    0: {}", paths[2].display())],
            "native UPDATE slot replacement/removal changed"
        );
        println!("native UPDATE opcode={op} result={result}\nbefore:\n{before}after:\n{after}");
    }
}
