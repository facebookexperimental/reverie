/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! These tests exercise the Rust primary-stream lease and fixed release hook.
//! Native mask restoration, helper parking and runtime cleanup need live tests.

use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::TryLockError;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use super::GUEST_CLIENT;
use super::GuestConnection;
use super::MappingCapturePrimary;
use super::RPC_SOCKET_ENV;
use super::borrow_mapping_capture_primary;
use super::is_runtime_owned_fd;
use super::protect_guest_operation;
use super::release_mapping_capture_primary;

const CHILD: &str = "REVERIE_DBT_MAPPING_CAPTURE_PRIMARY_TEST_CHILD";

fn isolated(name: &str, exercise: fn()) {
    if let Some(child) = std::env::var_os(CHILD) {
        assert_eq!(child, name);
        exercise();
        println!("mapping-capture-primary-complete:{name}");
        return;
    }
    let full_name = format!("sync_rpc::mapping_capture_tests::{name}");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &full_name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name)
        .env_remove(RPC_SOCKET_ENV)
        .env("RUST_BACKTRACE", "0")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut exceeded = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            exceeded = true;
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!exceeded, "primary lease blocked: {output:?}");
    assert!(output.status.success(), "{output:?}");
    let completed = format!("mapping-capture-primary-complete:{name}");
    assert!(
        output
            .stdout
            .windows(completed.len())
            .any(|bytes| bytes == completed.as_bytes()),
        "selected child did not execute its checks: {output:?}"
    );
}

fn primary_fact(pid: u32, fd: i32) -> u64 {
    (u64::from(pid) << 32) | u64::from(fd as u32)
}

struct SocketFixture {
    primary: UnixStream,
    peer: UnixStream,
    other: UnixStream,
    other_peer: UnixStream,
    identity: (libc::dev_t, libc::ino_t),
}

impl SocketFixture {
    fn install() -> Self {
        assert_eq!(GUEST_CLIENT.primary.load(Ordering::Acquire), 0);
        assert!(GUEST_CLIENT.connection.lock().unwrap().is_none());
        let (primary, peer) = UnixStream::pair().unwrap();
        let (other, other_peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let fd = primary.as_raw_fd();
        let identity = socket_identity(fd);
        assert_ne!(identity, socket_identity(other.as_raw_fd()));
        // Install a real already-connected primary. Connection establishment
        // and authentication are covered by shared_client_tests. This path
        // must never be consulted or used for a replacement by capture.
        *GUEST_CLIENT.connection.lock().unwrap() = Some(GuestConnection {
            pid: std::process::id(),
            path: PathBuf::from("/mapping-capture-must-not-reconnect/rpc"),
            fd,
            usable: true,
        });
        GUEST_CLIENT
            .primary
            .store(primary_fact(std::process::id(), fd), Ordering::Release);
        Self {
            primary,
            peer,
            other,
            other_peer,
            identity,
        }
    }

    fn fd(&self) -> i32 {
        self.primary.as_raw_fd()
    }

    fn check_identity(&self) {
        assert_eq!(socket_identity(self.fd()), self.identity);
        assert_eq!(
            unsafe { libc::fcntl(self.fd(), libc::F_GETFD) },
            libc::FD_CLOEXEC
        );
        assert_ne!(socket_identity(self.other.as_raw_fd()), self.identity);
    }

    fn exchange(&mut self, fd: i32) {
        assert_eq!(fd, self.fd());
        self.check_identity();
        self.peer.write_all(b"primary-in").unwrap();
        self.other_peer.write_all(b"other-in").unwrap();
        let mut bytes = [0_u8; 10];
        assert_eq!(
            unsafe {
                libc::recv(
                    fd,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            },
            bytes.len() as isize
        );
        assert_eq!(&bytes, b"primary-in");
        let mut other = [0_u8; 8];
        assert_eq!(
            unsafe {
                libc::recv(
                    self.other.as_raw_fd(),
                    other.as_mut_ptr().cast(),
                    other.len(),
                    libc::MSG_DONTWAIT,
                )
            },
            other.len() as isize
        );
        assert_eq!(&other, b"other-in");
        assert_eq!(
            unsafe {
                libc::send(
                    fd,
                    b"primary-out".as_ptr().cast(),
                    11,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            },
            11
        );
        let mut reply = [0; 11];
        self.peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"primary-out");
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let mut slot = match GUEST_CLIENT.connection.try_lock() {
            Ok(slot) => slot,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => panic!("test left the primary lease held"),
        };
        GUEST_CLIENT.primary.store(0, Ordering::Release);
        *slot = None;
        // The streams close only after removing the test's published owner.
    }
}

fn socket_identity(fd: i32) -> (libc::dev_t, libc::ino_t) {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
    let stat = unsafe { stat.assume_init() };
    assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFSOCK);
    (stat.st_dev, stat.st_ino)
}

// Applied only in an isolated child, after installing the sockets. Existing
// socket I/O and fstat still work, while socket/dup/open cannot allocate an FD.
struct NoNewDescriptors(libc::rlimit);

impl NoNewDescriptors {
    fn enter() -> Self {
        let mut saved = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, saved.as_mut_ptr()) },
            0
        );
        let saved = unsafe { saved.assume_init() };
        let blocked = libc::rlimit {
            rlim_cur: 0,
            rlim_max: saved.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &blocked) }, 0);
        let guard = Self(saved);
        match UnixStream::pair() {
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EMFILE)),
            Ok(_) => panic!("new socket allocation was not blocked"),
        }
        guard
    }
}

impl Drop for NoNewDescriptors {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
    }
}

unsafe extern "C" fn record_unexpected_invocation(
    context: usize,
    _number: i64,
    _args: *const u64,
    _purpose: u32,
) -> i64 {
    let calls = unsafe { &*(context as *const AtomicUsize) };
    calls.fetch_add(1, Ordering::SeqCst);
    -i64::from(libc::EIO)
}

fn check_protection(fd: i32, unowned: i32) {
    // Reading the atomic owner must not take the leased exchange mutex.
    assert!(is_runtime_owned_fd(fd));
    assert!(!is_runtime_owned_fd(unowned));
    assert_eq!(GUEST_CLIENT.descriptor(std::process::id()), Some(fd));
    let calls = AtomicUsize::new(0);
    for (number, args, before_tool) in [
        (libc::SYS_read, [fd as u64, 0, 0, 0, 0, 0], true),
        (libc::SYS_write, [fd as u64, 0, 0, 0, 0, 0], true),
        (
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
            true,
        ),
        (libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0], false),
    ] {
        assert_eq!(
            protect_guest_operation(
                &calls as *const AtomicUsize as usize,
                record_unexpected_invocation,
                number,
                &args,
                before_tool,
            ),
            Some(-i64::from(libc::EBADF))
        );
    }
    assert_eq!(
        protect_guest_operation(
            &calls as *const AtomicUsize as usize,
            record_unexpected_invocation,
            libc::SYS_read,
            &[unowned as u64, 0, 0, 0, 0, 0],
            true,
        ),
        None
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

fn refuse_borrow() {
    assert!(matches!(
        borrow_mapping_capture_primary(),
        Err(reverie::MappingCaptureError::Connection)
    ));
}

fn release(lease: &mut MappingCapturePrimary, usable: i32) {
    unsafe {
        release_mapping_capture_primary(lease as *mut MappingCapturePrimary as usize, usable)
    };
    // This observes the fixed hook's return boundary, not native mask ordering.
    assert!(lease.is_released());
}

#[test]
fn capture_primary_borrows_existing_socket_and_releases_once() {
    isolated(
        "capture_primary_borrows_existing_socket_and_releases_once",
        || {
            let mut sockets = SocketFixture::install();
            let _no_new_fds = NoNewDescriptors::enter();
            let mut first = borrow_mapping_capture_primary().unwrap();
            assert_eq!(first.fd(), sockets.fd());
            assert!(!first.is_released());
            assert!(matches!(
                GUEST_CLIENT.connection.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            check_protection(first.fd(), sockets.other.as_raw_fd());
            sockets.exchange(first.fd());
            release(&mut first, 1);
            assert!(
                GUEST_CLIENT
                    .connection
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .usable
            );
            sockets.check_identity();

            // A stale second release cannot unlock or retire the next lease. The
            // original lease value remains alive, so this is not a dangling call.
            let mut second = borrow_mapping_capture_primary().unwrap();
            release(&mut first, 0);
            assert!(matches!(
                GUEST_CLIENT.connection.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            check_protection(second.fd(), sockets.other.as_raw_fd());
            sockets.exchange(second.fd());
            release(&mut second, 1);
            assert!(
                GUEST_CLIENT
                    .connection
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .usable
            );
            sockets.check_identity();
        },
    );
}

#[test]
fn capture_primary_failed_release_retires_stream_without_reusing_fd() {
    isolated(
        "capture_primary_failed_release_retires_stream_without_reusing_fd",
        || {
            let mut sockets = SocketFixture::install();
            let _no_new_fds = NoNewDescriptors::enter();
            let mut lease = borrow_mapping_capture_primary().unwrap();
            sockets.exchange(lease.fd());
            release(&mut lease, 0);
            assert!(
                !GUEST_CLIENT
                    .connection
                    .try_lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .usable
            );
            refuse_borrow();
            // A late success cannot rehabilitate a failed stream or free its
            // protected numeric slot. The original socket is still kernel-live.
            release(&mut lease, 1);
            refuse_borrow();
            check_protection(sockets.fd(), sockets.other.as_raw_fd());
            sockets.exchange(sockets.fd());
        },
    );
}

#[test]
fn capture_primary_refuses_missing_busy_wrong_pid_and_owner_facts() {
    isolated(
        "capture_primary_refuses_missing_busy_wrong_pid_and_owner_facts",
        || {
            {
                let _no_new_fds = NoNewDescriptors::enter();
                refuse_borrow();
                assert!(GUEST_CLIENT.connection.try_lock().unwrap().is_none());
                assert_eq!(GUEST_CLIENT.primary.load(Ordering::Acquire), 0);
            }
            let mut sockets = SocketFixture::install();
            let _no_new_fds = NoNewDescriptors::enter();
            let pid = std::process::id();
            let other_pid = if pid == u32::MAX { pid - 1 } else { pid + 1 };
            {
                let _held = GUEST_CLIENT.connection.lock().unwrap();
                refuse_borrow();
                check_protection(sockets.fd(), sockets.other.as_raw_fd());
            }
            GUEST_CLIENT
                .connection
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .pid = other_pid;
            refuse_borrow();
            assert_eq!(
                GUEST_CLIENT
                    .connection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .pid,
                other_pid
            );
            GUEST_CLIENT
                .connection
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .pid = pid;

            for fact in [
                0,
                primary_fact(other_pid, sockets.fd()),
                primary_fact(pid, sockets.other.as_raw_fd()),
            ] {
                GUEST_CLIENT.primary.store(fact, Ordering::Release);
                refuse_borrow();
                assert_eq!(GUEST_CLIENT.primary.load(Ordering::Acquire), fact);
                assert_eq!(
                    GUEST_CLIENT.connection.lock().unwrap().as_ref().unwrap().fd,
                    sockets.fd()
                );
                sockets.check_identity();
            }
            GUEST_CLIENT
                .primary
                .store(primary_fact(pid, sockets.fd()), Ordering::Release);
            GUEST_CLIENT
                .connection
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .usable = false;
            refuse_borrow();
            assert!(
                !GUEST_CLIENT
                    .connection
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .usable
            );
            check_protection(sockets.fd(), sockets.other.as_raw_fd());
            sockets.exchange(sockets.fd());
        },
    );
}

#[test]
fn capture_primary_refuses_poison_without_connection_recovery() {
    isolated(
        "capture_primary_refuses_poison_without_connection_recovery",
        || {
            let mut sockets = SocketFixture::install();
            let _no_new_fds = NoNewDescriptors::enter();
            let panic = std::panic::catch_unwind(|| {
                let _held = GUEST_CLIENT.connection.lock().unwrap();
                panic!("intentional primary-connection poison");
            });
            assert!(panic.is_err());
            assert!(GUEST_CLIENT.connection.is_poisoned());
            refuse_borrow();
            assert!(GUEST_CLIENT.connection.is_poisoned());
            check_protection(sockets.fd(), sockets.other.as_raw_fd());
            sockets.exchange(sockets.fd());
        },
    );
}
