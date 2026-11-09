/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! [`reverie::Guest::descriptor_status`] of a traced thread: the kernel's
//! `/proc/<tid>/fdinfo/<fd>` for it, which the tracer reads while the thread
//! is stopped in the tool's callback.
//!
//! A traced guest thread is a host task, and the tracer shares the guest's
//! `/proc` view, so this is the thread's own `fdinfo`, every line of it
//! Linux's: record locks are listed only when the thread's process holds
//! them, as Linux lists them for that process.

use std::io::Read;

use reverie::DescriptorStatus;
use reverie::Errno;
use reverie::FactError;
use reverie::Pid;

/// The most `fdinfo` text read for one descriptor. An epoll descriptor lists
/// one line for every descriptor it watches, so its text has no fixed bound;
/// a longer one is not provided.
const FDINFO_LIMIT: u64 = 1024 * 1024;

/// Reads and parses descriptor `fd` of thread `tid`.
pub(crate) fn read(tid: Pid, fd: i32) -> Result<DescriptorStatus, FactError> {
    // Linux names no descriptor below zero; fdinfo has no entry to look up.
    if fd < 0 {
        return Err(FactError::Errno(Errno::EBADF));
    }
    let tid = tid.as_raw();
    let path = format!("/proc/{tid}/fdinfo/{fd}");
    let text = {
        // The guard ends before anything else runs.
        let _open = crate::launch_window::TransientOpen::begin();
        read_bounded(&path)
    };
    match text {
        Ok(Some(text)) => DescriptorStatus::from_fdinfo(&text),
        Ok(None) => Err(FactError::NotProvided),
        Err(error) => Err(FactError::Errno(read_errno(tid, &error))),
    }
}

/// The whole of `path`, or `None` when it is longer than [`FDINFO_LIMIT`].
fn read_bounded(path: &str) -> std::io::Result<Option<Vec<u8>>> {
    let mut text = Vec::new();
    std::fs::File::open(path)?
        .take(FDINFO_LIMIT + 1)
        .read_to_end(&mut text)?;
    Ok((text.len() as u64 <= FDINFO_LIMIT).then_some(text))
}

/// What a failed read of thread `tid`'s `fdinfo` entry means. Linux answers
/// `ENOENT` both for a descriptor the thread's table does not hold (at the
/// open, or at the read when the descriptor was closed since) and for a
/// thread that is gone; the thread's own `fdinfo` directory tells the two
/// apart. Any other error is the kernel's answer to the tracer's read.
fn read_errno(tid: i32, error: &std::io::Error) -> Errno {
    match error.raw_os_error() {
        Some(libc::ENOENT) if std::fs::metadata(format!("/proc/{tid}/fdinfo")).is_ok() => {
            Errno::EBADF
        }
        Some(libc::ENOENT) => Errno::ESRCH,
        Some(errno) => Errno::new(errno),
        None => Errno::EIO,
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    use reverie::LockClass;

    use super::*;

    fn this_thread() -> Pid {
        // SAFETY: gettid takes no arguments and cannot fail.
        Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32)
    }

    /// The tracer's read is the kernel's fdinfo, here for this process's own
    /// thread: an eventfd's count, then a flock lock on a file.
    #[test]
    fn a_thread_reads_its_own_descriptors() {
        // SAFETY: eventfd takes no pointers and returns a new descriptor.
        let raw = unsafe { libc::eventfd(5, libc::EFD_CLOEXEC) };
        assert!(raw >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: eventfd returned this new descriptor, which nothing else owns.
        let eventfd = unsafe { std::fs::File::from_raw_fd(raw) };
        let status = read(this_thread(), eventfd.as_raw_fd()).unwrap();
        assert_eq!(status.eventfd_count, Some(5));
        assert_eq!(status.scm_fds, None);
        assert!(status.locks.is_empty());

        let directory = std::env::temp_dir().join(format!(
            "reverie-ptrace-descriptor-status-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("locked");
        let file = std::fs::File::create(&path).unwrap();
        // SAFETY: flock takes no pointers; the descriptor is open.
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
        let status = read(this_thread(), file.as_raw_fd()).unwrap();
        assert_eq!(status.locks.len(), 1, "{status:?}");
        assert_eq!(status.locks[0].class, LockClass::Flock);
        assert!(status.locks[0].write);
        assert_eq!(
            status.locks[0].raw_inode,
            std::os::unix::fs::MetadataExt::ino(&file.metadata().unwrap())
        );
        drop(file);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A descriptor the thread does not hold, below zero or above every open
    /// one, is EBADF; a thread that does not exist is ESRCH. No task has the
    /// number `pid_max`: Linux hands out numbers below it.
    #[test]
    fn closed_descriptors_and_absent_threads_are_named() {
        assert_eq!(read(this_thread(), -1), Err(FactError::Errno(Errno::EBADF)));
        assert_eq!(
            read(this_thread(), i32::MAX),
            Err(FactError::Errno(Errno::EBADF))
        );
        let pid_max: i32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(
            read(Pid::from_raw(pid_max), 0),
            Err(FactError::Errno(Errno::ESRCH))
        );
    }
}
