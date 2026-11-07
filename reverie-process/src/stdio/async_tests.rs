/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Descriptor-only controls: no process creation or wait ownership.

use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use super::*;

fn owned(fd: Fd) -> OwnedFd {
    // SAFETY: into_raw_fd transfers the one owned descriptor without closing.
    unsafe { OwnedFd::from_raw_fd(fd.into_raw_fd()) }
}

fn status_flags(fd: i32) -> i32 {
    // SAFETY: inspect only the live descriptor retained by this test.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0);
    flags
}

fn descriptor_flags(fd: i32) -> i32 {
    // SAFETY: inspect only the live descriptor retained by this test.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    flags
}

fn registration_refuses_regular_file<T: Debug>(
    convert: fn(OwnedFd) -> Result<T, (OwnedFd, io::Error)>,
) {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"actual-file").unwrap();
    file.seek(SeekFrom::Start(2)).unwrap();
    let mut observer = file.try_clone().unwrap();
    let fd = file.as_raw_fd();
    let flags = status_flags(fd);
    let fd_flags = descriptor_flags(fd);
    assert_eq!(flags & libc::O_NONBLOCK, 0);

    let (returned, error) = convert(file.into()).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(returned.as_raw_fd(), fd, "return the original descriptor");
    assert_eq!(status_flags(fd), flags);
    assert_eq!(descriptor_flags(fd), fd_flags);
    assert_eq!(observer.stream_position().unwrap(), 2);
    let mut returned = File::from(returned);
    assert_eq!(returned.stream_position().unwrap(), 2);
    let mut byte = [0];
    returned.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [b't']);
    assert_eq!(
        observer.stream_position().unwrap(),
        3,
        "retain the same OFD"
    );
    assert_eq!(status_flags(returned.as_raw_fd()), flags);
}

#[tokio::test(flavor = "current_thread")]
async fn registration_failure_returns_exact_file_flags_and_shared_offset() {
    registration_refuses_regular_file(ChildStdout::try_from_owned_fd);
    registration_refuses_regular_file(ChildStderr::try_from_owned_fd);
}

async fn pipe_read_and_eof<T: AsyncRead + Unpin + Debug>(
    convert: fn(OwnedFd) -> Result<T, (OwnedFd, io::Error)>,
) {
    let (reader, writer) = pipe().unwrap();
    let read_fd = reader.as_raw_fd();
    let write_fd = writer.as_raw_fd();
    let writer_flags = status_flags(write_fd);
    let reader_fd_flags = descriptor_flags(read_fd);
    assert_eq!(writer_flags & libc::O_NONBLOCK, 0);
    let mut reader = convert(owned(reader)).unwrap();
    assert_ne!(status_flags(read_fd) & libc::O_NONBLOCK, 0);
    assert_eq!(descriptor_flags(read_fd), reader_fd_flags);
    assert_eq!(status_flags(write_fd), writer_flags);
    let mut writer = File::from(writer);
    let mut bytes = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    tokio::time::timeout_at(deadline, async {
        let write = async {
            // Let the real reader reach Pending before data becomes available.
            tokio::task::yield_now().await;
            assert_eq!(status_flags(write_fd), writer_flags);
            writer.write_all(b"actual-pipe\0\xff").unwrap();
            drop(writer);
        };
        let read = reader.read_to_end(&mut bytes);
        let ((), count) = tokio::join!(write, read);
        assert_eq!(count.unwrap(), 13);
    })
    .await
    .unwrap();
    assert_eq!(bytes, b"actual-pipe\0\xff");
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout_at(deadline, reader.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0,
        "actual EOF",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stdout_pipe_reads_real_bytes_and_eof_without_nonblocking_child_writer() {
    pipe_read_and_eof(ChildStdout::try_from_owned_fd).await;
}

#[tokio::test(flavor = "current_thread")]
async fn stderr_pipe_reads_real_bytes_and_eof_without_nonblocking_child_writer() {
    pipe_read_and_eof(ChildStderr::try_from_owned_fd).await;
}

#[tokio::test(flavor = "current_thread")]
async fn second_registration_failure_keeps_first_reader_owned_and_usable() {
    let (reader, writer) = pipe().unwrap();
    let read_fd = reader.as_raw_fd();
    let mut stdout = ChildStdout::try_from_owned_fd(owned(reader)).unwrap();
    let first_flags = descriptor_flags(read_fd);
    let file = tempfile::tempfile().unwrap();
    let second_fd = file.as_raw_fd();
    let (stderr, error) = ChildStderr::try_from_owned_fd(file.into()).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(stderr.as_raw_fd(), second_fd);
    assert_eq!(descriptor_flags(read_fd), first_flags);
    assert_eq!(status_flags(writer.as_raw_fd()) & libc::O_NONBLOCK, 0);
    let mut writer = File::from(writer);
    writer.write_all(b"retained-first").unwrap();
    drop(writer);
    let mut bytes = Vec::new();
    let count = tokio::time::timeout(Duration::from_secs(1), stdout.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 14);
    assert_eq!(bytes, b"retained-first");
    assert_eq!(
        descriptor_flags(stderr.as_raw_fd()) & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    // The refused stderr fd remains owned while the first stream reaches EOF.
    drop(stderr);
}
