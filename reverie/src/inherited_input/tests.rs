/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use super::InheritedInput;

fn descriptor_stat(fd: RawFd) -> libc::stat {
    let mut stat = std::mem::MaybeUninit::uninit();
    // SAFETY: stat points to writable storage, and the caller owns the descriptor.
    assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
    // SAFETY: successful fstat initialized the complete result.
    unsafe { stat.assume_init() }
}

fn descriptor_flags(fd: RawFd, command: i32) -> i32 {
    // SAFETY: both callers use a no-argument descriptor query.
    let flags = unsafe { libc::fcntl(fd, command) };
    assert_ne!(flags, -1);
    flags
}

fn readiness(fd: RawFd) -> i16 {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor is live for this immediate, nonblocking readiness query.
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    assert!(matches!(result, 0 | 1));
    descriptor.revents
}

fn read_one(fd: RawFd) -> (isize, u8) {
    let mut byte = 0;
    // SAFETY: byte provides one writable byte and the caller owns fd. Tests call
    // this only after writing a byte or observing HUP, so a leaked writer fails
    // the readiness assertion instead of leaving the test blocked in read.
    let count = unsafe { libc::read(fd, std::ptr::from_mut(&mut byte).cast(), 1) };
    (count, byte)
}

fn write_one_without_sigpipe(fd: RawFd, byte: u8) -> io::Result<usize> {
    // Block SIGPIPE only in this test thread. Do not alter the process-wide
    // disposition or consume a signal that was already pending on entry.
    // No assertion or potentially panicking test code runs between installing
    // and restoring the mask.
    // SAFETY: the signal sets and byte are valid for their synchronous calls;
    // the descriptor remains owned by the test, and the original mask is
    // restored before inspecting the result with assertions.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old_mask: libc::sigset_t = std::mem::zeroed();
        let mut pending: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        assert_eq!(libc::sigaddset(&mut set, libc::SIGPIPE), 0);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old_mask),
            0
        );
        let pending_result = libc::sigpending(&mut pending);
        let already_pending = libc::sigismember(&pending, libc::SIGPIPE) == 1;
        let count = libc::write(fd, std::ptr::from_ref(&byte).cast(), 1);
        let error = (count < 0).then(io::Error::last_os_error);
        let drain_result = if !already_pending
            && error.as_ref().and_then(io::Error::raw_os_error) == Some(libc::EPIPE)
        {
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            Some(loop {
                let signal = libc::sigtimedwait(&set, std::ptr::null_mut(), &timeout);
                if signal != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break signal;
                }
            })
        } else {
            None
        };
        let restore_result =
            libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut());
        assert_eq!(pending_result, 0);
        assert_eq!(restore_result, 0);
        if let Some(signal) = drain_result {
            assert_eq!(signal, libc::SIGPIPE);
        }
        error.map_or_else(|| Ok(count as usize), Err)
    }
}

#[test]
fn constructor_identity_is_the_actual_blocking_read_endpoint() {
    let input = InheritedInput::pipe(17).unwrap();
    let read_fd = input.reader.as_raw_fd();
    let write_fd = input.writer.as_raw_fd();
    let stat = descriptor_stat(read_fd);
    let flags = descriptor_flags(read_fd, libc::F_GETFL);
    let identity = input.identity();

    assert_eq!(identity.guest_fd(), 17);
    assert_eq!(identity.dev(), stat.st_dev);
    assert_eq!(identity.inode(), stat.st_ino);
    assert_eq!(identity.rdev(), stat.st_rdev);
    assert_eq!(identity.access_mode(), libc::O_RDONLY);
    assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
    assert_eq!(flags & (libc::O_ACCMODE | libc::O_NONBLOCK), libc::O_RDONLY);
    assert!(identity.matches(&stat, flags));
    assert!(!identity.matches(
        &descriptor_stat(write_fd),
        descriptor_flags(write_fd, libc::F_GETFL),
    ));
    for fd in [read_fd, write_fd] {
        assert_ne!(descriptor_flags(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
        assert_eq!(descriptor_flags(fd, libc::F_GETFL) & libc::O_NONBLOCK, 0);
    }
}

#[test]
fn identity_refuses_another_pipe_and_a_reused_descriptor() {
    let input = InheritedInput::pipe(0).unwrap();
    let other = InheritedInput::pipe(0).unwrap();
    let null = File::open("/dev/null").unwrap();
    let original_fd = input.reader.as_raw_fd();
    let other_fd = other.reader.as_raw_fd();
    for fd in [other_fd, null.as_raw_fd()] {
        assert!(
            !input
                .identity()
                .matches(&descriptor_stat(fd), descriptor_flags(fd, libc::F_GETFL),)
        );
    }

    // Both OwnedFds remain live: dup2 replaces the original slot with the other
    // pipe, without giving another parallel test a chance to allocate the slot.
    assert_ne!(original_fd, other_fd);
    // SAFETY: both descriptors are owned by this test and remain live.
    assert_eq!(unsafe { libc::dup2(other_fd, original_fd) }, original_fd);
    let replacement_stat = descriptor_stat(original_fd);
    let replacement_flags = descriptor_flags(original_fd, libc::F_GETFL);
    assert!(
        !input
            .identity()
            .matches(&replacement_stat, replacement_flags)
    );
    assert!(
        other
            .identity()
            .matches(&replacement_stat, replacement_flags)
    );
}

#[test]
fn read_lease_lives_until_handoff_then_releases_the_last_reader() {
    let input = InheritedInput::pipe(0).unwrap();
    let lease = input.lease().unwrap();
    assert_eq!(lease.identity().guest_fd(), input.identity().guest_fd());
    assert_eq!(lease.identity().inode(), input.identity().inode());
    assert!(lease.identity().matches(
        &descriptor_stat(lease.reader.as_raw_fd()),
        descriptor_flags(lease.reader.as_raw_fd(), libc::F_GETFL),
    ));
    assert_ne!(
        descriptor_flags(lease.reader.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC,
        0,
        "the temporary read lease must not survive child exec",
    );
    let (child_stdin, writer) = input.into_reader_and_writer();
    drop(child_stdin);
    assert_eq!(
        write_one_without_sigpipe(writer.as_raw_fd(), b'x').unwrap(),
        1
    );
    assert_eq!(read_one(lease.reader.as_raw_fd()), (1, b'x'));

    drop(lease);
    assert_eq!(
        write_one_without_sigpipe(writer.as_raw_fd(), b'x')
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPIPE),
    );
}

#[test]
fn read_lease_does_not_keep_a_writer_alive_or_invent_early_eof() {
    let input = InheritedInput::pipe(0).unwrap();
    let lease = input.lease().unwrap();
    let (child_stdin, writer) = input.into_reader_and_writer();
    drop(child_stdin);
    let fd = lease.reader.as_raw_fd();
    assert_eq!(
        readiness(fd),
        0,
        "a live empty writer must not look like EOF"
    );
    assert_eq!(
        write_one_without_sigpipe(writer.as_raw_fd(), b'z').unwrap(),
        1
    );
    assert_eq!(read_one(fd), (1, b'z'));
    assert_eq!(readiness(fd), 0, "draining bytes must not close the writer");

    drop(writer);
    assert_ne!(
        readiness(fd) & libc::POLLHUP,
        0,
        "no writer may leak into the lease"
    );
    assert_eq!(read_one(fd).0, 0);
}

#[test]
fn negative_guest_destination_is_refused() {
    for destination in [-1, i32::MIN] {
        assert!(InheritedInput::pipe(destination).is_err());
    }
}
