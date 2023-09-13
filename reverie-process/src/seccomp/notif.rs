/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![allow(missing_docs)]

use core::pin::Pin;
use core::task::Context;
use core::task::Poll;
use std::io;
use std::os::unix::io::AsRawFd;

use syscalls::Errno;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::fd::Fd;

/// The format the BPF program executes over.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct seccomp_data {
    /// The system call number.
    pub nr: i32,

    /// Indicates system call convention as an AUDIT_ARCH_* value.
    pub arch: u32,

    /// The instruction pointer at the time of the system call.
    pub instruction_pointer: u64,

    /// Up to 6 system call arguments  always stored as 64-bit values regardless
    /// of the architecture.
    pub args: [u64; 6],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct seccomp_notif_sizes {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
}

/// An incoming seccomp notification.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct seccomp_notif {
    /// This is a cookie for the notification. Each such cookie is guaranteed to
    /// be unique for the corresponding seccomp filter.
    ///
    ///  * The cookie can be used with the SECCOMP_IOCTL_NOTIF_ID_VALID ioctl(2)
    ///    operation.
    ///  * When returning a notification response to the kernel, the supervisor
    ///    must include the cookie value in the `seccomp_notif_resp` strucutre
    ///    that is specified as the argument of the `SECCOMP_IOCTL_NOTIF_SEND`
    ///    operation.
    pub id: u64,

    /// This is the thread ID of the target thread that triggered the
    /// notification event.
    pub pid: u32,

    /// This is a bit mask of flags providing further information on the event.
    /// In the current implementation, this field is always zero.
    pub flags: u32,

    /// This struct contains information abou tht esystem call that triggered
    /// the notification. This is the same structure that is passed to the
    /// seccomp filter. See `seccomp(2)` for details on this structure.
    pub data: seccomp_data,
}

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1u32 << 0;

/// A response to a seccomp notification.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct seccomp_notif_resp {
    /// This is a cookie value associated with this response. This cookie value
    /// allows the kernel to correctly associate this response with the system
    /// call that triggered the user-space notification.
    pub id: u64,

    /// This is the value that will be used for a spoofed success return for the
    /// target's system call.
    pub val: i64,

    /// This is the value that will be used as the error number for a spoofed
    /// error return for the target's system call.
    pub error: i32,

    /// This is a bit mask that includes zero or more of the following flags:
    ///
    ///  - `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (since Linux 5.5).
    pub flags: u32,
}

pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1u32 << 0;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1u32 << 1;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct seccomp_notif_addfd {
    /// This field should be set to the notification ID (cookie value) that was
    /// obtained via [`seccomp_notif_resp`].
    pub id: u64,

    /// This field is a bit mask of flags tha tmodify the behavior of the
    /// operation. Currently two flags are supported:
    ///  - [`SECCOMP_ADDFD_FLAG_SETFD`]: When allocating the file descriptor in
    ///    the target, use the file descriptor number specified in the `newfd`
    ///    field.
    ///  - [`SECCOMP_ADDFD_FLAG_SEND`]: Perform the equivalent of
    ///    [`SeccompNotif::addfd`] plus [`SeccompNotif::send`] as an atomic
    ///    operation. On success, the target process's `errno` will be 0 and the
    ///    return value will be the file descriptor number that was allocated in
    ///    the target. If allocating the file descriptor in the target fails,
    ///    the target's system call continues to be blocked until a successful
    ///    response is sent.
    pub flags: u32,

    /// This field should be set to the number of the file descriptor in the
    /// supervisor that is to be duplicated.
    pub srcfd: u32,

    /// This field determines which file descriptor number is allocated in the
    /// target. If the `SECCOMP_ADDFD_FLAG_SETFD` flag is set, then this field
    /// specifies which file descriptor number should be allocated. If this file
    /// descriptor number is already open in the target, it is atomically closed
    /// and reused. If the descriptor duplication fails due to an LSM check, or
    /// if `srcfd` is not a valid file descriptor, the file descriptor `newfd`
    /// will not be closed in the target process.
    ///
    /// If the `SECCOMP_ADDFD_FLAG_SETFD` flag is not set, then this field must
    /// be 0, and the kernel allocates the lowest unused file descriptor number
    /// in the target.
    pub newfd: u32,

    /// This field is a bit mask specifying flags that should be set on the file
    /// descriptor that is received in the target process. Currently, only the
    /// following flag is implemented:
    ///
    ///  - `O_CLOEXEC`: Set the close-on-exec flag on the received file
    ///    descriptor.
    pub newfd_flags: u32,
}

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xc0502100;
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xc0182101;
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = 0x40082102;
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = 0x40182103;

/// Represents a stream and sink of seccomp notifications.
#[derive(Debug)]
pub struct SeccompNotif(AsyncFd<Fd>);

impl SeccompNotif {
    pub(crate) fn new(fd: Fd) -> Result<Self, Errno> {
        fd.set_nonblocking()?;

        // TODO: Use SECCOMP_GET_NOTIF_SIZES to find the size of each struct.
        // Otherwise, we could have buffer overruns when kernel structures
        // change.

        Ok(Self(
            AsyncFd::with_interest(fd, Interest::READABLE).unwrap(),
        ))
    }

    pub fn poll_recv(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<seccomp_notif>> {
        loop {
            let mut guard = futures::ready!(self.0.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| seccomp_notif_recv(inner.get_mut())) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    /// This is used to send a notification response back to the kernel.
    ///
    /// NOTE: This is only available since Linux 5.0.
    pub fn send(&mut self, response: &seccomp_notif_resp) -> Result<(), Errno> {
        Errno::result(unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_SEND,
                response as *const _,
            )
        })
        .map(drop)
    }

    /// This is used to check that a notification ID returned by an earlier
    /// [`SeccompNotif::poll_recv`] operation is still valid (i.e., that the
    /// target still exists and its system call is still blocked waiting for a
    /// response).
    ///
    /// This operation is necessary to avoid race conditions that can occur when the
    /// `pid` returned by [`SeccompNotif::poll_recv`] operation terminates, and
    /// that process ID is reused by another process. An example of this kind of
    /// race is the following:
    ///
    ///  1. A notification is generated on the listening file descriptor. The
    ///     returned `seccomp_notif` contains the TID of the target thread (in the
    ///     `pid` field of the structure).
    ///  2. The target terminates.
    ///  3. Another thread or process is created on the system that by chance reuses
    ///     the TID that was freed when the target terminated.
    ///  4. The supervisor `open(2)`s the `/proc/[tid]/mem` file for the TID
    ///     obtained in step 1, with the intention of (say) inspecting the memory
    ///     location(s) that containing hte argument(s) of the system call that
    ///     triggered the notification in step 1.
    ///
    /// In the above scenario, the risk is that the supervisor may try to access the
    /// memory of a process other than the target. This race can be avoided by
    /// following the call to `open(2)` with a call to [`SeccompNotif::id_valid`] to
    /// verify that the process that generated the notification is still alive.
    /// (Note that if the target terminates after the latter step, a subsequent
    /// `read(2)` from the file descriptor may return 0, indicating end of file.)
    ///
    /// On success (i.e., the notification ID is still valid), this function returns
    /// `Ok(())`. On failure (i.e., the notification ID is no longer valid),
    /// `Err(Errno::ENOENT)` is returned.
    ///
    /// NOTE: This is only available since Linux 5.0.
    pub fn id_valid(&mut self, id: u64) -> Result<(), Errno> {
        Errno::result(unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_ID_VALID,
                &id as *const _,
            )
        })
        .map(drop)
    }

    /// This is used to allow the supervisor to install a file descriptor into the
    /// target's file descriptor table. This operation is semantically equivalent to
    /// duplicating a file descriptor from the supervisor's file descriptor table
    /// into the target's file descriptor table.
    ///
    /// This operation permits the supervisor to emulate a target system call (such
    /// as `socket(2)` or `openat(2)`) that generates a file descriptor. The
    /// supervisor can perform the system call that generates the file descriptor
    /// (and associated open file description) and then use this operation to
    /// allocate a file descriptor that refers to the same open file description in
    /// the target.
    ///
    /// Once this operation has been performed, the supervisor can close its copy of
    /// the file descriptopr.
    pub fn addfd(&mut self, addfd: &seccomp_notif_addfd) -> Result<(), Errno> {
        Errno::result(unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                SECCOMP_IOCTL_NOTIF_ADDFD,
                addfd as *const _,
            )
        })
        .map(drop)
    }
}

impl futures::stream::Stream for SeccompNotif {
    type Item = io::Result<seccomp_notif>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // This is an infinite stream and shall never return `None`.
        self.poll_recv(cx).map(Some)
    }
}

/// This is used to obtain a user-space notification event. If no such event is
/// currently pending, the operation blocks until an event occurs.
///
/// NOTE: This is only available since Linux 5.0.
fn seccomp_notif_recv(fd: &Fd) -> io::Result<seccomp_notif> {
    // According to the docs, this struct must be zeroed out first.
    let mut response = core::mem::MaybeUninit::<seccomp_notif>::zeroed();

    match Errno::result(unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            SECCOMP_IOCTL_NOTIF_RECV,
            &mut response as *mut _,
        )
    }) {
        Err(Errno::EINTR) => Err(Errno::EAGAIN),
        result => result,
    }?;

    Ok(unsafe { response.assume_init() })
}
