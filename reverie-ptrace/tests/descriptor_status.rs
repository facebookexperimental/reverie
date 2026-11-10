/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::descriptor_status` on a traced guest is the kernel's own `fdinfo`
//! for the guest's descriptor: an eventfd's count, a Unix socket's queued
//! `SCM_RIGHTS` descriptors, and each lock class held through a description,
//! with the locked file's device and inode. A descriptor the guest does not
//! hold is `EBADF`.
//!
//! The guest asks at numbered points with `tuxcall`, which Linux does not
//! implement; the tool answers it, and records the fact it read then.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

use reverie::DescriptorStatus;
use reverie::Errno;
use reverie::Error;
use reverie::FactError;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::LockClass;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// The first argument of a guest's `tuxcall` that asks for a fact.
const ASK: u64 = 0x6664_696e_666f;

const EVENTFD_WRITTEN: u64 = 1;
const EVENTFD_READ: u64 = 2;
const SOCKET_SENDER: u64 = 3;
const SOCKET_RECEIVER: u64 = 4;
const SOCKET_RECEIVED: u64 = 5;
const RECORD_LOCKS: u64 = 6;
const FLOCK: u64 = 7;
const LEASE: u64 = 8;
const CLOSED: u64 = 9;
const NEGATIVE: u64 = 10;

type Fact = Result<DescriptorStatus, FactError>;

/// The facts the tool read, by the guest's point number.
#[derive(Default)]
struct FactLog(Mutex<BTreeMap<u64, (i32, Fact)>>);

#[reverie::global_tool]
impl GlobalTool for FactLog {
    type Request = (u64, i32, Fact);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) {
        let (point, fd, fact) = request;
        let previous = self.0.lock().unwrap().insert(point, (fd, fact));
        assert!(previous.is_none(), "point {point} asked twice");
    }
}

#[derive(Default)]
struct FactTool;

#[reverie::tool]
impl Tool for FactTool {
    type GlobalState = FactLog;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::tuxcall].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (_, args) = syscall.into_parts();
        if args.arg0 as u64 != ASK {
            return Ok(guest.inject(syscall).await?);
        }
        let (fd, point) = (args.arg1 as i32, args.arg2 as u64);
        let fact = guest.descriptor_status(fd);
        guest.send_rpc((point, fd, fact)).await;
        Ok(0)
    }
}

/// Asks the tool for descriptor `fd`'s status at `point`.
fn ask(point: u64, fd: i32) {
    // SAFETY: tuxcall takes no pointers; only the tool answers it.
    unsafe { libc::syscall(libc::SYS_tuxcall, ASK, fd as libc::c_long, point) };
}

fn check(result: libc::c_long, what: &str) -> libc::c_long {
    assert!(result >= 0, "{what}: {}", std::io::Error::last_os_error());
    result
}

fn transfer_u64(fd: i32, value: u64, write: bool) {
    let mut bytes = value.to_ne_bytes();
    // SAFETY: bytes is a live eight-byte buffer, as eventfd I/O requires.
    let done = unsafe {
        if write {
            libc::write(fd, bytes.as_ptr().cast(), 8)
        } else {
            libc::read(fd, bytes.as_mut_ptr().cast(), 8)
        }
    };
    assert_eq!(done, 8, "{}", std::io::Error::last_os_error());
}

/// Sends one byte with `fds` attached as `SCM_RIGHTS`, or receives such a
/// message and closes the descriptors it carried.
fn rights(socket: i32, fds: &[i32], send: bool) {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let payload = std::mem::size_of_val(fds) as u32;
    // SAFETY: CMSG_SPACE only computes a size.
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(payload) } as usize];
    // SAFETY: msghdr is plain data; an all-zero value is valid.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: the header names live buffers of the declared lengths, and the
    // control buffer has room for one header with `payload` bytes.
    unsafe {
        if send {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(payload) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
            check(
                libc::sendmsg(socket, &message, 0) as libc::c_long,
                "sendmsg",
            );
        } else {
            check(
                libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) as libc::c_long,
                "recvmsg",
            );
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null(), "no rights received");
            let mut received = vec![0i32; fds.len()];
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(header).cast::<i32>(),
                received.as_mut_ptr(),
                fds.len(),
            );
            for fd in received {
                libc::close(fd);
            }
        }
    }
}

fn open(path: &Path, flags: i32) -> i32 {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a terminated string.
    check(
        unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0o600) } as libc::c_long,
        "open",
    ) as i32
}

fn record_lock(fd: i32, command: i32, kind: i32, start: i64, length: i64) {
    // SAFETY: flock is plain data; an all-zero value is valid.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind as i16;
    lock.l_whence = libc::SEEK_SET as i16;
    lock.l_start = start;
    lock.l_len = length;
    // SAFETY: lock is a live flock value the call only reads.
    check(
        unsafe { libc::fcntl(fd, command, &lock) } as libc::c_long,
        "fcntl lock",
    );
}

/// The device Linux prints for files under `path`'s mount: its superblock's,
/// which `/proc/self/mountinfo` lists, and which on btrfs is not `st_dev`.
fn superblock_device(path: &Path) -> u64 {
    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: statx is plain data; an all-zero value is valid.
    let mut status: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: name is terminated and status is writable.
    let result = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            name.as_ptr(),
            0,
            libc::STATX_MNT_ID,
            &mut status,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    assert_ne!(status.stx_mask & libc::STATX_MNT_ID, 0);
    let mount = status.stx_mnt_id.to_string();
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let line = mountinfo
        .lines()
        .find(|line| line.split(' ').next() == Some(mount.as_str()))
        .unwrap();
    let (major, minor) = line.split(' ').nth(2).unwrap().split_once(':').unwrap();
    libc::makedev(major.parse().unwrap(), minor.parse().unwrap())
}

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn status(facts: &BTreeMap<u64, (i32, Fact)>, point: u64) -> &DescriptorStatus {
    match &facts[&point].1 {
        Ok(status) => status,
        Err(error) => panic!("point {point}: {error:?}"),
    }
}

/// The lock of `class` the status lists, after checking that it names
/// `path`'s file.
fn lock_of(status: &DescriptorStatus, class: LockClass, path: &Path) -> reverie::HeldLockFact {
    let lock = *status
        .locks
        .iter()
        .find(|lock| lock.class == class)
        .unwrap_or_else(|| panic!("no {class:?} lock in {status:?}"));
    assert_eq!(lock.raw_inode, std::fs::metadata(path).unwrap().ino());
    assert_eq!(lock.raw_device, superblock_device(path));
    assert!(!lock.mandatory);
    lock
}

#[test]
fn a_traced_guest_reports_its_own_descriptor_status() {
    let directory = Directory(std::env::temp_dir().join(format!(
        "reverie-ptrace-descriptor-status-{}",
        std::process::id()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let locked = directory.0.join("locked");
    let flocked = directory.0.join("flocked");
    let leased = directory.0.join("leased");
    // A read lease needs a file that no one has open for writing.
    std::fs::write(&leased, b"leased").unwrap();
    let (locked_path, flocked_path, leased_path) =
        (locked.clone(), flocked.clone(), leased.clone());

    let log = reverie_ptrace::testing::check_fn::<FactTool, _>(move || {
        // SAFETY: eventfd takes no pointers.
        let eventfd = check(
            unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) } as libc::c_long,
            "eventfd",
        ) as i32;
        transfer_u64(eventfd, 3, true);
        transfer_u64(eventfd, 4, true);
        ask(EVENTFD_WRITTEN, eventfd);
        transfer_u64(eventfd, 0, false);
        ask(EVENTFD_READ, eventfd);

        let mut pair = [0i32; 2];
        // SAFETY: pair has room for the two descriptors.
        check(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            } as libc::c_long,
            "socketpair",
        );
        rights(pair[0], &[eventfd, eventfd], true);
        ask(SOCKET_SENDER, pair[0]);
        ask(SOCKET_RECEIVER, pair[1]);
        rights(pair[1], &[0, 0], false);
        ask(SOCKET_RECEIVED, pair[1]);

        let file = open(&locked_path, libc::O_RDWR | libc::O_CREAT);
        record_lock(file, libc::F_SETLK, libc::F_WRLCK, 0, 10);
        record_lock(file, libc::F_OFD_SETLK, libc::F_RDLCK, 100, 0);
        ask(RECORD_LOCKS, file);

        let flocked = open(&flocked_path, libc::O_RDWR | libc::O_CREAT);
        // SAFETY: flock takes no pointers.
        check(
            unsafe { libc::flock(flocked, libc::LOCK_EX) } as libc::c_long,
            "flock",
        );
        ask(FLOCK, flocked);

        let leased = open(&leased_path, libc::O_RDONLY);
        // SAFETY: F_SETLEASE takes an integer argument.
        check(
            unsafe { libc::fcntl(leased, libc::F_SETLEASE, libc::F_RDLCK) } as libc::c_long,
            "F_SETLEASE",
        );
        ask(LEASE, leased);

        // SAFETY: the descriptor is this guest's own.
        check(unsafe { libc::close(flocked) } as libc::c_long, "close");
        ask(CLOSED, flocked);
        ask(NEGATIVE, -1);
    });
    let facts = log.0.into_inner().unwrap();
    assert_eq!(facts.len(), 10, "{facts:?}");

    let written = status(&facts, EVENTFD_WRITTEN);
    assert_eq!(written.eventfd_count, Some(7));
    assert_eq!(written.scm_fds, None);
    assert!(written.locks.is_empty());
    assert_eq!(status(&facts, EVENTFD_READ).eventfd_count, Some(0));

    assert_eq!(status(&facts, SOCKET_SENDER).scm_fds, Some(0));
    let receiver = status(&facts, SOCKET_RECEIVER);
    assert_eq!(receiver.scm_fds, Some(2));
    assert_eq!(receiver.eventfd_count, None);
    assert_eq!(status(&facts, SOCKET_RECEIVED).scm_fds, Some(0));

    let records = status(&facts, RECORD_LOCKS);
    assert_eq!(records.locks.len(), 2, "{records:?}");
    let posix = lock_of(records, LockClass::Posix, &locked);
    assert!(posix.write);
    assert_eq!((posix.start, posix.end), (0, Some(9)));
    let ofd = lock_of(records, LockClass::OpenFileDescription, &locked);
    assert!(!ofd.write);
    assert_eq!((ofd.start, ofd.end), (100, None));

    let flocks = status(&facts, FLOCK);
    assert_eq!(flocks.locks.len(), 1, "{flocks:?}");
    let flock = lock_of(flocks, LockClass::Flock, &flocked);
    assert!(flock.write);
    assert_eq!((flock.start, flock.end), (0, None));

    let leases = status(&facts, LEASE);
    assert_eq!(leases.locks.len(), 1, "{leases:?}");
    let lease = lock_of(leases, LockClass::Lease, &leased);
    assert!(!lease.write);
    assert_eq!((lease.start, lease.end), (0, None));

    for point in [CLOSED, NEGATIVE] {
        assert_eq!(
            facts[&point].1,
            Err(FactError::Errno(Errno::EBADF)),
            "point {point}"
        );
    }
}
