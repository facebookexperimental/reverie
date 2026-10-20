/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A launch whose `pipe2` a seccomp filter hands to a user-notification
//! supervisor in the same process completes, even when the supervisor makes a
//! transient open before it answers
//! (<https://github.com/rrnewton/reverie/issues/912>, round-6 R6-1).
//!
//! The launching thread holds the launch lock during its `pipe2`, which waits
//! for the supervisor's answer; the supervisor's transient open waits for the
//! launch. Without a bound on that wait neither ever proceeds.

// The filter matches x86_64 system call numbers only.
#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use reverie_process::Command;
use reverie_process::ExitStatus;
use reverie_process::launch_window;

/// `_IOWR('!', 0, struct seccomp_notif)` and `_IOWR('!', 1, struct
/// seccomp_notif_resp)` from `<linux/seccomp.h>`.
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
/// `AUDIT_ARCH_X86_64` from `<linux/audit.h>`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// How long the test waits for the launch before it calls it a deadlock.
const BOUND: Duration = Duration::from_secs(30);

/// `pipe2` notifications the supervisor answered while a launch held the lock.
static ANSWERED_UNDER_LAUNCH: AtomicU32 = AtomicU32::new(0);
static STOP: AtomicBool = AtomicBool::new(false);

/// Installs, on the calling thread only, a filter that hands every `pipe2` to
/// a user-notification listener, and returns the listener.
fn notify_pipe2_on_this_thread() -> libc::c_int {
    let arch = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let filter = [
        stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, arch),
        jeq(AUDIT_ARCH_X86_64, 0, 3),
        stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, nr),
        jeq(libc::SYS_pipe2 as u32, 0, 1),
        stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_USER_NOTIF),
        stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at `filter`, which outlives both calls; neither
    // flag synchronizes other threads, so only this thread is filtered.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        let listener = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        );
        assert!(
            listener >= 0,
            "seccomp listener: {}",
            std::io::Error::last_os_error()
        );
        listener as libc::c_int
    }
}

/// Answers every notification on `listener` with CONTINUE, after one
/// transient open, until `STOP`.
fn supervise(listener: libc::c_int) {
    while !STOP.load(Ordering::SeqCst) {
        let mut ready = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polls one descriptor this test owns.
        if unsafe { libc::poll(&mut ready, 1, 50) } != 1 {
            continue;
        }
        // SAFETY: zeroed is a valid `seccomp_notif`, which RECV fills.
        let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &mut request) } != 0 {
            continue;
        }
        let under_launch = launch_window::launching();
        // The transient open a supervisor in this process may need before it
        // answers.
        launch_window::read_to_string("/proc/thread-self/status").unwrap();
        if under_launch && request.data.nr == libc::SYS_pipe2 as i32 {
            ANSWERED_UNDER_LAUNCH.fetch_add(1, Ordering::SeqCst);
        }
        let response = libc::seccomp_notif_resp {
            id: request.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };
        // SAFETY: answers the notification just received. It fails only if
        // the notifying thread is gone, which the test reports below.
        unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) };
    }
}

#[test]
fn a_launch_whose_pipe_a_supervisor_here_answers_completes() {
    let (listener_tx, listener_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    // Detached: if the launch deadlocks, its thread can never be joined.
    std::thread::spawn(move || {
        listener_tx.send(notify_pipe2_on_this_thread()).unwrap();
        let began = Instant::now();
        let status = Command::new("/bin/true")
            .spawn()
            .map_err(|e| e.to_string())
            .and_then(|mut child| child.wait_blocking().map_err(|e| e.to_string()));
        done_tx.send((status, began.elapsed())).unwrap();
    });
    let listener = listener_rx.recv().unwrap();
    std::thread::spawn(move || supervise(listener));

    let (status, took) = done_rx.recv_timeout(BOUND).unwrap_or_else(|_| {
        panic!(
            "the launch did not complete within {BOUND:?}: its pipe2 waits for the \
             supervisor, whose transient open waits for the launch"
        )
    });
    STOP.store(true, Ordering::SeqCst);
    eprintln!(
        "launch_supervised_syscall: spawn and wait took {took:?}; {} pipe2 notification(s) \
         answered under the launch lock",
        ANSWERED_UNDER_LAUNCH.load(Ordering::SeqCst)
    );
    assert_eq!(status, Ok(ExitStatus::Exited(0)));
    assert!(
        ANSWERED_UNDER_LAUNCH.load(Ordering::SeqCst) >= 1,
        "no pipe2 was handed to the supervisor while the launch held the lock; the cycle was \
         not exercised"
    );
}
