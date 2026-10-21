/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An external supervisor can hold the terminal syscall indefinitely. This
//! control records that excluded outcome; it does not turn it into exit127.

use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use super::*;

#[repr(C)]
#[derive(Default)]
struct NotificationData {
    number: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct Notification {
    id: u64,
    pid: u32,
    flags: u32,
    data: NotificationData,
}

#[repr(C)]
struct Rights {
    header: libc::cmsghdr,
    descriptor: i32,
    padding: i32,
}

const _: () = {
    assert!(size_of::<NotificationData>() == 64);
    assert!(size_of::<Notification>() == 80);
    assert!(size_of::<libc::cmsghdr>() == 16);
    assert!(size_of::<Rights>() == 24);
};

struct ChildCleanup(Option<i64>);

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let Some(pid) = self.0 else { return };
        raw(
            libc::SYS_kill,
            [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
        );
        let end = Instant::now() + FORK_DEADLINE;
        loop {
            let mut status = 0_i32;
            let result = raw(
                libc::SYS_wait4,
                [
                    pid as u64,
                    (&raw mut status) as u64,
                    libc::WNOHANG as u64,
                    0,
                    0,
                    0,
                ],
            );
            if result == pid || result == -i64::from(libc::ECHILD) {
                return;
            }
            if Instant::now() >= end {
                // The outer isolated process group and test box still own
                // this task. A cleanup failure is never a successful control.
                eprintln!("held-terminal child cleanup deadline: pid={pid} wait={result}");
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn child_setup_failed() -> ! {
    // SYS_exit stays allowed by this control's filter. Avoid retrying the
    // deliberately held SYS_exit_group when setup itself failed.
    raw(libc::SYS_exit, [98, 0, 0, 0, 0, 0]);
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn hold_exit_in_child(socket: i32) -> ! {
    disable_dumping();
    let mut instructions = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_exit_group as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_USER_NOTIF,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    if raw(
        libc::SYS_prctl,
        [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
    ) != 0
    {
        child_setup_failed();
    }
    let listener = raw(
        libc::SYS_seccomp,
        [
            libc::SECCOMP_SET_MODE_FILTER as u64,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            (&raw const program) as u64,
            0,
            0,
            0,
        ],
    );
    if listener < 0 {
        child_setup_failed();
    }
    let mut rights = Rights {
        header: libc::cmsghdr {
            cmsg_len: 20,
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        },
        descriptor: listener as i32,
        padding: 0,
    };
    let mut byte = b'L';
    let mut vector = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = (&raw mut rights).cast();
    message.msg_controllen = size_of::<Rights>();
    if raw(
        libc::SYS_sendmsg,
        [
            socket as u64,
            (&raw const message) as u64,
            libc::MSG_NOSIGNAL as u64,
            0,
            0,
            0,
        ],
    ) != 1
    {
        child_setup_failed();
    }
    raw(libc::SYS_close, [listener as u64, 0, 0, 0, 0, 0]);
    // LOCATOR is still empty in this fresh process. Exercise the production
    // unprepared fatal path, not a second test-only terminal instruction.
    unsafe { entry(core::ptr::null_mut(), sample) };
    child_setup_failed()
}

#[test]
fn external_listener_holds_native_exit_until_explicit_kill_and_reap() {
    isolated(
        "external::external_listener_holds_native_exit_until_explicit_kill_and_reap",
        || {
            assert!(snapshot().is_none());
            let mut sizes = [0_u16; 3];
            assert_eq!(
                raw(
                    libc::SYS_seccomp,
                    [
                        libc::SECCOMP_GET_NOTIF_SIZES as u64,
                        0,
                        sizes.as_mut_ptr() as u64,
                        0,
                        0,
                        0
                    ]
                ),
                0
            );
            assert_eq!(sizes, [80, 24, 64], "actual kernel notification layout");
            let mut sockets = [-1_i32; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        sockets.as_mut_ptr(),
                    )
                },
                0
            );
            let receiver = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
            let sender = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
            let timeout = libc::timeval {
                tv_sec: 2,
                tv_usec: 0,
            };
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        receiver.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&raw const timeout).cast(),
                        size_of_val(&timeout) as libc::socklen_t,
                    )
                },
                0
            );
            let pid = raw(libc::SYS_fork, [0; 6]);
            assert!(pid >= 0);
            if pid == 0 {
                raw(
                    libc::SYS_close,
                    [receiver.as_raw_fd() as u64, 0, 0, 0, 0, 0],
                );
                hold_exit_in_child(sender.as_raw_fd());
            }
            let mut cleanup = ChildCleanup(Some(pid));
            drop(sender);
            let mut rights: Rights = unsafe { core::mem::zeroed() };
            let mut byte = 0_u8;
            let mut vector = libc::iovec {
                iov_base: (&raw mut byte).cast(),
                iov_len: 1,
            };
            let mut message: libc::msghdr = unsafe { core::mem::zeroed() };
            message.msg_iov = &raw mut vector;
            message.msg_iovlen = 1;
            message.msg_control = (&raw mut rights).cast();
            message.msg_controllen = size_of::<Rights>();
            assert_eq!(
                unsafe {
                    libc::recvmsg(
                        receiver.as_raw_fd(),
                        &raw mut message,
                        libc::MSG_CMSG_CLOEXEC,
                    )
                },
                1,
                "listener handoff: {}",
                io::Error::last_os_error()
            );
            assert_eq!(byte, b'L');
            assert_eq!(message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
            assert_eq!(message.msg_controllen, size_of::<Rights>());
            assert_eq!(rights.header.cmsg_len, 20);
            assert_eq!(rights.header.cmsg_level, libc::SOL_SOCKET);
            assert_eq!(rights.header.cmsg_type, libc::SCM_RIGHTS);
            assert!(rights.descriptor >= 0);
            let listener = unsafe { OwnedFd::from_raw_fd(rights.descriptor) };
            let mut poll = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&raw mut poll, 1, 2000) }, 1);
            assert_eq!(poll.revents, libc::POLLIN);
            let mut notification = Notification::default();
            // Linux x86-64 _IOWR('!', 0, struct seccomp_notif), independently
            // checked against the kernel's GET_NOTIF_SIZES result above.
            const RECEIVE: libc::c_ulong = 0xc050_2100;
            assert_eq!(
                unsafe { libc::ioctl(listener.as_raw_fd(), RECEIVE, &raw mut notification) },
                0
            );
            assert_eq!(notification.pid as i64, pid);
            assert_eq!(notification.flags, 0);
            assert_eq!(notification.data.number, libc::SYS_exit_group as i32);
            assert_eq!(notification.data.arch, 0xc000_003e);
            assert_eq!(notification.data.ip, crate::trap::trusted_gate().return_ip);
            assert_eq!(notification.data.args[0], 127);
            // Never answer the notification or close its listener while waiting.
            // The lack of a returned exit is the named limitation being measured.
            let began = Instant::now();
            while began.elapsed() < Duration::from_millis(100) {
                let mut status = 0_i32;
                assert_eq!(
                    raw(
                        libc::SYS_wait4,
                        [
                            pid as u64,
                            (&raw mut status) as u64,
                            libc::WNOHANG as u64,
                            0,
                            0,
                            0
                        ]
                    ),
                    0,
                    "held terminal unexpectedly completed"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(
                raw(
                    libc::SYS_kill,
                    [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0]
                ),
                0
            );
            let status = wait_raw(pid);
            cleanup.0 = None;
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            println!(
                "external held exit_group127: notification at real trusted gate, no terminal result for100ms, explicit SIGKILL/reap; excluded outcome, not normal exit127 or guest parity"
            );
        },
    );
}
