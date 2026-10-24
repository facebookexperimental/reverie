/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The one rule for the descriptors a backend keeps for itself, shared by
//! every backend that runs inside the guest process (the in-guest runtime and
//! LiteInst, SaBRe and e9patch's tool host): which syscalls name a descriptor,
//! how the kernel reads a descriptor argument, what a guest `epoll_wait` on a
//! descriptor it does not have returns, and how a guest `close_range` closes
//! everything in its range except the reserved descriptors.
//!
//! To the guest a reserved descriptor is not open. Each backend decides which
//! numbers it reserves and keeps its own registry of them; this module only
//! answers questions about a syscall and a number, and runs `close_range`
//! through the caller's raw syscall entry, so it allocates nothing and is safe
//! to call while dispatching a guest syscall.

/// Syscall argument `index` as the kernel reads a descriptor, a `close_range`
/// bound or its flags: the low 32 bits of the register. Comparing the full
/// register would let `fd | 1 << 32` reach a reserved descriptor.
pub fn descriptor_arg(args: &[u64; 6], index: usize) -> u64 {
    u64::from(args[index] as u32)
}

/// Whether syscall `number` with `args` operates on descriptor `fd` through
/// one of its descriptor arguments: reads and writes, fcntl, ioctl, dup, mmap
/// of a file, splice, sendfile, epoll_ctl and the other descriptor calls listed
/// below. It does not cover the socket calls ([`socket_call_names_descriptor`]),
/// `close`, `close_range` or epoll readiness ([`epoll_wait_result`]).
pub fn names_descriptor(number: i64, args: &[u64; 6], fd: u64) -> bool {
    let is = |index| descriptor_arg(args, index) == fd;
    match number {
        libc::SYS_read
        | libc::SYS_readv
        | libc::SYS_pread64
        | libc::SYS_preadv
        | libc::SYS_preadv2
        | libc::SYS_write
        | libc::SYS_writev
        | libc::SYS_pwrite64
        | libc::SYS_pwritev
        | libc::SYS_pwritev2
        | libc::SYS_vmsplice
        | libc::SYS_fcntl
        | libc::SYS_ioctl
        | libc::SYS_dup
        // Operations that change, lock or describe the open file itself.
        | libc::SYS_ftruncate
        | libc::SYS_fallocate
        | libc::SYS_fchmod
        | libc::SYS_fchown
        | libc::SYS_fsetxattr
        | libc::SYS_fremovexattr
        | libc::SYS_fgetxattr
        | libc::SYS_flistxattr
        | libc::SYS_flock
        | libc::SYS_fsync
        | libc::SYS_fdatasync
        | libc::SYS_sync_file_range
        | libc::SYS_lseek
        | libc::SYS_fstat
        | libc::SYS_fstatfs
        | libc::SYS_fadvise64
        | libc::SYS_readahead
        | libc::SYS_getdents64
        | libc::SYS_getdents
        | libc::SYS_syncfs
        | libc::SYS_fchdir
        // Descriptors of special kinds: a reserved number is not one, and to
        // the guest it is not open at all.
        | libc::SYS_signalfd
        | libc::SYS_signalfd4
        | libc::SYS_timerfd_settime
        | libc::SYS_timerfd_gettime
        | libc::SYS_inotify_add_watch
        | libc::SYS_inotify_rm_watch
        | libc::SYS_fanotify_mark
        | libc::SYS_setns
        | libc::SYS_pidfd_send_signal
        | libc::SYS_process_madvise
        | libc::SYS_process_mrelease
        | libc::SYS_finit_module
        | libc::SYS_fsmount
        | libc::SYS_quotactl_fd
        | libc::SYS_landlock_add_rule
        | libc::SYS_landlock_restrict_self => is(0),
        libc::SYS_sendfile => is(0) || is(1),
        libc::SYS_epoll_ctl => is(0) || is(2),
        // waitid(P_PIDFD, fd, ...).
        libc::SYS_waitid => args[0] as u32 == 3 && is(1),
        // A file mapping of the descriptor.
        libc::SYS_mmap => args[3] & libc::MAP_ANONYMOUS as u64 == 0 && is(4),
        libc::SYS_dup2 | libc::SYS_dup3 => is(0) || is(1),
        libc::SYS_splice | libc::SYS_copy_file_range => is(0) || is(2),
        libc::SYS_tee => is(0) || is(1),
        // The pidfd, and the number it copies from the target's table, which
        // aliases a reserved descriptor when the target is this process or a
        // fork of it.
        libc::SYS_pidfd_getfd => is(0) || is(1),
        // Calls whose descriptor argument is always one.
        libc::SYS_io_uring_enter | libc::SYS_io_uring_register | libc::SYS_fsconfig => is(0),
        // `*at` calls that act on the directory descriptor itself when given
        // `AT_EMPTY_PATH` (glibc's `fstat` is `newfstatat(fd, "", ...,
        // AT_EMPTY_PATH)`), or `utimensat` with a null path. Without either
        // the descriptor is used only for a relative path, which would take a
        // guest-memory read to tell from an absolute one, so those calls are
        // not checked and run as Linux runs them.
        libc::SYS_newfstatat | libc::SYS_fchmodat2 => empty_path(args[3]) && is(0),
        libc::SYS_statx | libc::SYS_open_tree => empty_path(args[2]) && is(0),
        libc::SYS_execveat
        | libc::SYS_fchownat
        | libc::SYS_linkat
        | libc::SYS_name_to_handle_at => empty_path(args[4]) && is(0),
        libc::SYS_faccessat2 => empty_path(args[3]) && is(0),
        libc::SYS_utimensat => args[1] == 0 && is(0),
        // fspick(FSPICK_EMPTY_PATH); move_mount(MOVE_MOUNT_F_EMPTY_PATH) for
        // its source and MOVE_MOUNT_T_EMPTY_PATH for its target.
        libc::SYS_fspick => args[2] & FSPICK_EMPTY_PATH != 0 && is(0),
        libc::SYS_move_mount => {
            (args[4] & MOVE_MOUNT_F_EMPTY_PATH != 0 && is(0))
                || (args[4] & MOVE_MOUNT_T_EMPTY_PATH != 0 && is(2))
        }
        _ => false,
    }
}

const FSPICK_EMPTY_PATH: u64 = 0x8;
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;

/// Whether `*at` flags `flags` hold `AT_EMPTY_PATH`.
fn empty_path(flags: u64) -> bool {
    flags & libc::AT_EMPTY_PATH as u64 != 0
}

/// Whether syscall `number` shuts down, configures, connects, or sends or
/// receives on socket `fd`. Backends check these for guest syscalls only, when
/// their own client uses the reserved socket through the same calls.
pub fn socket_call_names_descriptor(number: i64, args: &[u64; 6], fd: u64) -> bool {
    match number {
        libc::SYS_shutdown
        | libc::SYS_getsockopt
        | libc::SYS_setsockopt
        | libc::SYS_sendto
        | libc::SYS_recvfrom
        | libc::SYS_sendmsg
        | libc::SYS_recvmsg
        | libc::SYS_sendmmsg
        | libc::SYS_recvmmsg
        | libc::SYS_connect
        | libc::SYS_bind
        | libc::SYS_listen
        | libc::SYS_accept
        | libc::SYS_accept4
        | libc::SYS_getsockname
        | libc::SYS_getpeername => descriptor_arg(args, 0) == fd,
        _ => false,
    }
}

/// The result Linux gives `epoll_wait`, `epoll_pwait` or `epoll_pwait2` on
/// `fd`, a number the caller does not have open: `EBADF`, after Linux's own
/// `EINVAL` check of the event count. `None` for any other call. (`poll`,
/// `ppoll`, `select` and `pselect6` name descriptors inside guest memory, and
/// `*at` calls use their directory argument only for some paths; checking them
/// would cost correct programs' calls a guest-memory read, so a buggy program
/// that passes a reserved number there is a known limit.)
pub fn epoll_wait_result(number: i64, args: &[u64; 6], fd: u64) -> Option<i64> {
    match number {
        libc::SYS_epoll_wait | libc::SYS_epoll_pwait | libc::SYS_epoll_pwait2
            if descriptor_arg(args, 0) == fd =>
        {
            let events = args[2] as i32;
            let most = i32::MAX / core::mem::size_of::<libc::epoll_event>() as i32;
            Some(-i64::from(if events <= 0 || events > most {
                libc::EINVAL
            } else {
                libc::EBADF
            }))
        }
        _ => None,
    }
}

/// Whether a `close_range` with `args` covers one of `reserved`.
pub fn close_range_covers(args: &[u64; 6], reserved: &[u64]) -> bool {
    let (first, last) = (descriptor_arg(args, 0), descriptor_arg(args, 1));
    reserved.iter().any(|&fd| first <= fd && fd <= last)
}

/// The ranges of `[first, last]` that lie between the descriptors of
/// `reserved`, which must be sorted ascending (duplicates are allowed), in
/// order. Empty when `first > last`.
pub fn close_range_gaps(first: u32, last: u32, reserved: &[u64]) -> CloseRangeGaps<'_> {
    CloseRangeGaps {
        next: Some(u64::from(first)),
        last: u64::from(last),
        reserved,
    }
}

/// The iterator [`close_range_gaps`] returns.
pub struct CloseRangeGaps<'a> {
    /// The lowest descriptor not yet covered, or `None` past `u32::MAX`.
    next: Option<u64>,
    last: u64,
    reserved: &'a [u64],
}

impl Iterator for CloseRangeGaps<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<(u32, u32)> {
        loop {
            let start = self.next?;
            if start > self.last {
                return None;
            }
            match self.reserved.split_first() {
                Some((&fd, rest)) if fd <= self.last => {
                    self.reserved = rest;
                    if fd < start {
                        continue;
                    }
                    self.next = (fd < u64::from(u32::MAX)).then_some(fd + 1);
                    if start < fd {
                        return Some((start as u32, (fd - 1) as u32));
                    }
                }
                _ => {
                    self.next = None;
                    return Some((start as u32, self.last as u32));
                }
            }
        }
    }
}

/// Runs a `close_range` with `args` without closing any of `reserved` (sorted
/// ascending), through `syscall`, the caller's raw syscall entry, which takes a
/// syscall number and its six arguments and returns the kernel's result. The
/// checks come first, in the kernel's order: flags other than
/// `CLOSE_RANGE_UNSHARE` and `CLOSE_RANGE_CLOEXEC`, then `first > last`, both
/// `EINVAL`. `CLOSE_RANGE_UNSHARE` unshares the descriptor table once, and then
/// each gap between the reserved descriptors is closed with the remaining
/// flags. Returns 0, or the first error.
///
/// # Safety
///
/// `args` must be a `close_range` the guest asked for, run in the guest's own
/// descriptor table: every descriptor in its range other than `reserved` is
/// closed. The caller must hold no live owner or borrow (`OwnedFd`, `File`,
/// `BorrowedFd` and the like) of a descriptor the call closes.
pub unsafe fn close_range_sparing(
    args: &[u64; 6],
    reserved: &[u64],
    mut syscall: impl FnMut(i64, [u64; 6]) -> i64,
) -> i64 {
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;

    let first = descriptor_arg(args, 0);
    let last = descriptor_arg(args, 1);
    let mut flags = descriptor_arg(args, 2);
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return -i64::from(libc::EINVAL);
    }
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        let result = syscall(libc::SYS_unshare, [libc::CLONE_FILES as u64, 0, 0, 0, 0, 0]);
        if result < 0 {
            return result;
        }
        flags &= !CLOSE_RANGE_UNSHARE;
    }
    for (gap_first, gap_last) in close_range_gaps(first as u32, last as u32, reserved) {
        let result = syscall(
            libc::SYS_close_range,
            [u64::from(gap_first), u64::from(gap_last), flags, 0, 0, 0],
        );
        if result < 0 {
            return result;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gaps(first: u32, last: u32, reserved: &[u64]) -> Vec<(u32, u32)> {
        close_range_gaps(first, last, reserved).collect()
    }

    #[test]
    fn close_range_gaps_skip_every_reserved_descriptor() {
        assert_eq!(
            gaps(10, 20, &[12, 15, 20]),
            vec![(10, 11), (13, 14), (16, 19)]
        );
        assert_eq!(gaps(10, 12, &[9, 13]), vec![(10, 12)]);
        assert_eq!(gaps(10, 12, &[10, 10, 11]), vec![(12, 12)]);
        assert_eq!(
            gaps(0, u32::MAX, &[1024]),
            vec![(0, 1023), (1025, u32::MAX)]
        );
        assert!(gaps(u32::MAX, u32::MAX, &[u64::from(u32::MAX)]).is_empty());
        assert!(gaps(5, 4, &[]).is_empty());
        assert_eq!(gaps(3, 3, &[]), vec![(3, 3)]);
    }

    #[test]
    fn a_descriptor_argument_is_its_low_32_bits() {
        let args = [1024 | (1 << 32), 0, 0, 0, 0, 0];
        assert_eq!(descriptor_arg(&args, 0), 1024);
        assert!(names_descriptor(libc::SYS_read, &args, 1024));
        assert!(socket_call_names_descriptor(libc::SYS_sendto, &args, 1024));
    }

    #[test]
    fn only_a_file_mapping_names_its_descriptor() {
        let file = [0, 4096, 1, libc::MAP_PRIVATE as u64, 7, 0];
        let anonymous = [
            0,
            4096,
            1,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            7,
            0,
        ];
        assert!(names_descriptor(libc::SYS_mmap, &file, 7));
        assert!(!names_descriptor(libc::SYS_mmap, &anonymous, 7));
    }

    #[test]
    fn an_at_call_names_its_descriptor_only_when_it_acts_on_it() {
        let empty = libc::AT_EMPTY_PATH as u64;
        // glibc's fstat.
        assert!(names_descriptor(
            libc::SYS_newfstatat,
            &[9, 0, 0, empty, 0, 0],
            9
        ));
        // A path relative to, or ignoring, the descriptor: run as Linux runs it.
        assert!(!names_descriptor(
            libc::SYS_newfstatat,
            &[9, 0, 0, 0, 0, 0],
            9
        ));
        assert!(!names_descriptor(libc::SYS_openat, &[9, 0, 0, 0, 0, 0], 9));
        assert!(names_descriptor(
            libc::SYS_statx,
            &[9, 0, empty, 0, 0, 0],
            9
        ));
        assert!(names_descriptor(
            libc::SYS_execveat,
            &[9, 0, 0, 0, empty, 0],
            9
        ));
        assert!(names_descriptor(
            libc::SYS_utimensat,
            &[9, 0, 0, 0, 0, 0],
            9
        ));
        assert!(!names_descriptor(
            libc::SYS_utimensat,
            &[9, 0x1000, 0, 0, 0, 0],
            9
        ));
        assert!(names_descriptor(
            libc::SYS_move_mount,
            &[0, 0, 9, 0, 0x40, 0],
            9
        ));
        assert!(!names_descriptor(
            libc::SYS_move_mount,
            &[0, 0, 9, 0, 0x4, 0],
            9
        ));
        assert!(names_descriptor(
            libc::SYS_io_uring_enter,
            &[9, 0, 0, 0, 0, 0],
            9
        ));
        // pidfd_getfd's copied number.
        assert!(names_descriptor(
            libc::SYS_pidfd_getfd,
            &[3, 9, 0, 0, 0, 0],
            9
        ));
    }

    #[test]
    fn epoll_wait_on_a_reserved_descriptor_fails_as_linux_does() {
        assert_eq!(
            epoll_wait_result(libc::SYS_epoll_wait, &[9, 0, 8, 0, 0, 0], 9),
            Some(-i64::from(libc::EBADF))
        );
        assert_eq!(
            epoll_wait_result(libc::SYS_epoll_wait, &[9, 0, 0, 0, 0, 0], 9),
            Some(-i64::from(libc::EINVAL))
        );
        assert_eq!(
            epoll_wait_result(libc::SYS_epoll_wait, &[8, 0, 8, 0, 0, 0], 9),
            None
        );
    }

    #[test]
    fn close_range_sparing_checks_then_closes_each_gap() {
        let mut calls = Vec::new();
        let result = unsafe {
            close_range_sparing(
                &[10, 20, (1 << 1) | (1 << 2), 0, 0, 0],
                &[12, 15],
                |n, a| {
                    calls.push((n, a[0], a[1], a[2]));
                    0
                },
            )
        };
        assert_eq!(result, 0);
        assert_eq!(
            calls,
            vec![
                (libc::SYS_unshare, libc::CLONE_FILES as u64, 0, 0),
                (libc::SYS_close_range, 10, 11, 1 << 2),
                (libc::SYS_close_range, 13, 14, 1 << 2),
                (libc::SYS_close_range, 16, 20, 1 << 2),
            ]
        );
        let refuse = |args: [u64; 6]| unsafe {
            close_range_sparing(&args, &[12], |_, _| panic!("no syscall may run"))
        };
        assert_eq!(refuse([10, 20, 1, 0, 0, 0]), -i64::from(libc::EINVAL));
        assert_eq!(refuse([20, 10, 0, 0, 0, 0]), -i64::from(libc::EINVAL));
    }

    #[test]
    fn close_range_sparing_stops_at_the_first_error() {
        let mut calls = 0;
        let result = unsafe {
            close_range_sparing(&[10, 20, 0, 0, 0, 0], &[12], |_, _| {
                calls += 1;
                -i64::from(libc::EPERM)
            })
        };
        assert_eq!((result, calls), (-i64::from(libc::EPERM), 1));
    }
}
