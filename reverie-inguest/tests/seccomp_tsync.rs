/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A real `SECCOMP_FILTER_FLAG_TSYNC` failure. Another thread loads a filter of
//! its own, which the runtime's filter cannot descend from, so the kernel
//! installs the runtime's filter on no thread and returns that thread's id: a
//! positive value, not an error number. `SeccompFilter::install` must refuse
//! it, naming the thread, and must not record the filter as installed. Had it
//! been installed, this thread's next syscall outside the (fictitious) gate
//! would trap and kill the process, which fails the test as well.
//!
//! The check runs in a child process with no thread besides the two it
//! starts, and no libtest thread in particular: libtest runs even a single
//! test on a thread of its own. The test re-executes this binary with
//! `REVERIE_SECCOMP_TSYNC_CHILD` set. In the child, an `.init_array` entry runs
//! the check and exits before libtest's `main` starts. The parent is an
//! ordinary libtest test, so test discovery (`--list --format json`) and the
//! `--logfile` execution records come from libtest itself.

use std::process::Command;
use std::sync::mpsc;

use reverie_inguest::seccomp::SeccompFilter;
use reverie_inguest::seccomp::TrustedGate;
use reverie_inguest::seccomp::runtime_filter_installed;

/// Set only in the child process the test starts.
const CHILD_ENV: &str = "REVERIE_SECCOMP_TSYNC_CHILD";

/// The child's last line of standard output when the check passes.
const REFUSED_LINE: &str = "seccomp_tsync: refused, naming thread ";

#[test]
fn tsync_against_a_thread_with_its_own_filter_is_refused_naming_that_thread() {
    let output = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(
        stdout
            .lines()
            .last()
            .and_then(|line| line.strip_prefix(REFUSED_LINE))
            .is_some_and(|tid| tid.parse::<u32>().is_ok()),
        "the child did not report the refusal\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[used]
#[unsafe(link_section = ".init_array")]
static RUN_CHILD_BEFORE_LIBTEST: extern "C" fn() = run_child_before_libtest;

/// In the child, runs the check and exits before libtest's `main`; in any
/// other process, returns at once. A failed assertion panics, and a panic
/// cannot unwind out of this `extern "C"` function, so the child aborts after
/// printing it.
extern "C" fn run_child_before_libtest() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    check_tsync_refusal();
    std::process::exit(0);
}

fn thread_count() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn check_tsync_refusal() {
    assert_eq!(thread_count(), 1, "the child must start single-threaded");
    // Set before the other thread starts, so that it inherits it and can load
    // a filter without privilege.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    let (ready, ready_receiver) = mpsc::channel();
    let (finish, finish_receiver) = mpsc::channel::<()>();
    let other = std::thread::spawn(move || {
        // BPF_RET | BPF_K, SECCOMP_RET_ALLOW: allow everything.
        let mut allow = [libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff_0000,
        }];
        let program = libc::sock_fprog {
            len: 1,
            filter: allow.as_mut_ptr(),
        };
        // No TSYNC: this thread only.
        let loaded = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &raw const program,
            )
        };
        assert_eq!(loaded, 0, "{}", std::io::Error::last_os_error());
        ready
            .send(unsafe { libc::syscall(libc::SYS_gettid) })
            .unwrap();
        finish_receiver.recv().unwrap();
    });
    let tid = ready_receiver.recv().unwrap();
    assert_eq!(thread_count(), 2, "only the child and its one thread");
    let mut filter = SeccompFilter::for_trusted_gate(TrustedGate {
        syscall_ip: 0x1000,
        return_ip: 0x1002,
    })
    .unwrap();
    let error = unsafe { filter.install() }
        .expect_err("TSYNC against a thread with its own filter must not install");
    assert!(
        error
            .to_string()
            .contains(&format!("could not synchronize thread {tid}")),
        "{error}"
    );
    assert!(!runtime_filter_installed());
    finish.send(()).unwrap();
    other.join().unwrap();
    println!("{REFUSED_LINE}{tid}");
}
