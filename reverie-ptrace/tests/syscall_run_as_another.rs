/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool may run a guest's syscall as a different one. The guest then resumes
//! with its own argument registers and the result of the syscall that ran: the
//! child of a clone with 0, and its parent with the child's PID.
//!
//! On aarch64 the first argument and the result share `x0`, so restoring the
//! guest's arguments over the result would hand the guest its own first
//! argument instead. On x86_64 the result is in `rax` and the arguments are
//! elsewhere, so these tests pass there either way.

use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Clone;
use reverie::syscalls::Clone3;
use reverie::syscalls::CloneArgs;
use reverie::syscalls::CloneFlags;
use reverie::syscalls::Getpid;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie_ptrace::testing::test_fn_with_config;
use serde::Deserialize;
use serde::Serialize;

/// The `clone3` arguments of a fork: no flags, and SIGCHLD at exit.
const FORK: CloneArgs = CloneArgs {
    flags: CloneFlags::empty(),
    pidfd: 0,
    child_tid: 0,
    parent_tid: 0,
    exit_signal: libc::SIGCHLD as u64,
    stack: 0,
    stack_size: 0,
    tls: 0,
    set_tid: 0,
    set_tid_size: 0,
    cgroup: 0,
};
/// The first argument of the guest's `getppid` that the Tool runs as `getpid`.
const MARKER: usize = 0x7265_7665;
/// The child's exit code when its clone returned 0.
const CHILD_SAW_ZERO: i32 = 42;

/// How the Tool runs the replacement syscall.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
enum Injection {
    /// `Guest::tail_inject`: the guest resumes with the result in its
    /// registers.
    #[default]
    Tail,
    /// `Guest::inject`: the Tool returns the result to the calling guest. A
    /// clone child still resumes with the result in its registers.
    Inline,
}

/// Counts the syscalls the Tool ran as another.
#[derive(Default)]
struct Replaced(AtomicUsize);

#[reverie::global_tool]
impl GlobalTool for Replaced {
    type Request = ();
    type Response = ();
    type Config = Injection;

    async fn receive_rpc(&self, _from: Pid, _request: ()) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Runs a fork asked for with `clone3` as `clone(SIGCHLD, 0, 0, 0, 0)`, and a
/// `getppid(MARKER)` as `getpid()`.
#[derive(Clone, Copy, Debug, Default)]
struct RunAsAnother;

#[reverie::tool]
impl Tool for RunAsAnother {
    type GlobalState = Replaced;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let replacement: Syscall = match syscall {
            Syscall::Clone3(clone3) if asks_for_a_fork(guest, &clone3) => {
                Clone::from(SyscallArgs::new(libc::SIGCHLD as usize, 0, 0, 0, 0, 0)).into()
            }
            Syscall::Getppid(_) if syscall.into_parts().1.arg0 == MARKER => Getpid::new().into(),
            _ => guest.tail_inject(syscall).await,
        };
        guest.send_rpc(()).await;
        match guest.config() {
            Injection::Tail => guest.tail_inject(replacement).await,
            Injection::Inline => Ok(guest.inject(replacement).await?),
        }
    }
}

fn asks_for_a_fork<T: Guest<RunAsAnother>>(guest: &T, clone3: &Clone3) -> bool {
    clone3.size() == std::mem::size_of::<CloneArgs>()
        && clone3
            .args()
            .and_then(|args| guest.memory().read_value(args).ok())
            == Some(FORK)
}

/// Forks with `clone3`; exits 0 if the child saw 0 and the parent its PID.
fn fork_with_clone3() {
    let args = FORK;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw const args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if ret == 0 {
        unsafe { libc::_exit(CHILD_SAW_ZERO) };
    }
    // Only the child's PID can be reaped as itself, and only a child that saw
    // 0 exits with `CHILD_SAW_ZERO`.
    let mut status = 0;
    let reaped = match libc::pid_t::try_from(ret) {
        Ok(pid) if pid > 0 => unsafe { libc::waitpid(pid, &mut status, 0) },
        _ => -1,
    };
    if i64::from(reaped) == ret
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == CHILD_SAW_ZERO
    {
        unsafe { libc::_exit(0) };
    }
    // Written directly: libtest captures `eprintln!` in a forked guest.
    let _ = writeln!(
        std::io::stderr(),
        "clone3 returned {ret:#x}; waitpid returned {reaped}, status {status:#x}"
    );
    unsafe { libc::_exit(1) };
}

/// Exits 0 if `getppid(MARKER)` returned this process's PID.
fn getppid_as_getpid() {
    let pid = unsafe { libc::getpid() };
    let ret = unsafe { libc::syscall(libc::SYS_getppid, MARKER) };
    if ret == i64::from(pid) {
        unsafe { libc::_exit(0) };
    }
    let _ = writeln!(
        std::io::stderr(),
        "getppid({MARKER:#x}) returned {ret:#x}; getpid returned {pid}"
    );
    unsafe { libc::_exit(1) };
}

fn run(guest: fn(), injection: Injection) {
    let (output, replaced) =
        test_fn_with_config::<RunAsAnother, _>(guest, injection, true).unwrap();
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "guest stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(replaced.0.load(Ordering::Relaxed), 1, "syscalls replaced");
}

#[test]
fn clone_run_as_another_by_tail_injection_returns_zero_to_the_child_and_its_pid_to_the_parent() {
    run(fork_with_clone3, Injection::Tail);
}

#[test]
fn clone_run_as_another_by_injection_returns_zero_to_the_child() {
    run(fork_with_clone3, Injection::Inline);
}

#[test]
fn syscall_run_as_another_by_tail_injection_returns_its_result() {
    run(getppid_as_getpid, Injection::Tail);
}
