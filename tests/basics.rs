/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![feature(llvm_asm)]

//! Basic tests that don't fall into some other category.

#[allow(unused_imports)]
use nix::{
    sys::wait::{self, WaitStatus},
    unistd::{self, ForkResult},
};
use reverie::{
    syscalls::{Syscall, SyscallInfo, Sysno},
    Error, ExitStatus, GlobalTool, Guest, Pid, Tool,
};
#[allow(unused_imports)]
use reverie_ptrace::testing::{check_fn, test_cmd, test_fn};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::ffi::CString;
#[allow(unused_imports)]
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct NoopTool;
impl Tool for NoopTool {}

#[test]
fn noop_tool_test() {
    let (output, _) = test_cmd::<NoopTool>("/bin/pwd", &[]).unwrap();
    // pwd should succeed & print some characters:
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct CounterGlobal {
    num_syscalls: AtomicU64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct CounterLocal {}

/// The message sent to the global state method.
/// This contains the syscall number.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct IncrMsg(Sysno);

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = IncrMsg;
    type Response = ();
    async fn receive_rpc(&self, _from: Pid, _: IncrMsg) -> Self::Response {
        AtomicU64::fetch_add(&self.num_syscalls, 1, Ordering::SeqCst);
    }
}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let sysno = syscall.number();
        let _ = guest.send_rpc(IncrMsg(sysno)).await?;
        guest.tail_inject(syscall).await
    }
}

#[test]
fn counter_tool_test() {
    let (output, state) = test_cmd::<CounterLocal>("ls", &[]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    // ls should print some characters and perform some syscalls:
    assert!(!output.stdout.is_empty());
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 30);
}

#[test]
fn error_exit_test() {
    let (output, state) = test_cmd::<CounterLocal>("/bin/bash", &["-c", "exit 42"]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(42));
    assert_eq!(output.stdout.len(), 0);
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 0);
}

#[allow(dead_code)]
fn fn_test() {
    let (output, state) = test_fn::<CounterLocal, _>(|| {
        let pid = nix::unistd::getpid();
        println!("Hello world1!  Pid = {:?}", pid);
        unsafe {
            libc::syscall(libc::SYS_write, 1, "Hello world2!\n", 14);
        }
        let _gid = nix::unistd::getgid();
    })
    .unwrap();

    println!(
        " >>> Command complete, stdout len {}, stderr len {}",
        output.stdout.len(),
        output.stderr.len(),
    );
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stderr.len(), 0);
    assert!(AtomicU64::load(&state.num_syscalls, Ordering::SeqCst) > 1);
}

#[cfg(not(sanitized))]
#[test]
fn run_fn_test() {
    fn_test();
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_command_test() {
    let (output, _state) = test_cmd::<CounterLocal>("/bin/echo", &["-n", "abcd"]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), b"abcd");
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_command_test_closure() {
    let msg = "abcd";
    let (output, _state) = test_cmd::<CounterLocal>("/bin/echo", &["-n", msg]).unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), msg.as_bytes());
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_func_write_test() {
    let msg = "abcd";
    let (output, _state) = test_fn::<CounterLocal, _>(move || {
        std::io::stdout().write_all(msg.as_bytes()).unwrap();
        std::io::stdout().flush().unwrap();
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), msg.as_bytes());
}

#[cfg(not(sanitized))]
#[test]
fn run_guest_func_print_test() {
    let msg = "abcd";
    let (output, _state) = test_fn::<CounterLocal, _>(move || {
        println!("{}", msg);
    })
    .unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.as_slice(), b"abcd\n");
}

#[cfg(not(sanitized))]
#[test]
fn orphans() {
    use nix::unistd::{fork, ForkResult};
    use std::{thread, time::Duration};

    let (output, _state) = test_fn::<CounterLocal, _>(|| {
        // Spawn a child process and make sure the parent exits before the child
        // process.
        match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child: _child } => {
                // Don't wait on the child. Just exit.
            }
            ForkResult::Child => {
                // Sleep for a little while so the parent has time to exit.
                thread::sleep(Duration::from_secs(1));
            }
        }
    })
    .unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0));
}

#[cfg(not(sanitized))]
#[test]
fn rust_execve_noexist_test() {
    use reverie_ptrace::testing::check_fn;
    check_fn::<NoopTool, _>(|| {
        let program = CString::new("I do not exist").unwrap();
        let env = CString::new("foo=bar").unwrap();
        let res = nix::unistd::execve(&program, &[&program], &[&env]);
        assert!(res.is_err());
    });
}

#[cfg(not(sanitized))]
#[test]
fn i_should_segfault() {
    use nix::sys::signal::Signal::SIGSEGV;
    use reverie_ptrace::testing::test_fn;
    let (output, _) = test_fn::<NoopTool, _>(|| {
        unsafe {
            let invalid_pointer = 0x5u64 as *mut u64;
            std::ptr::write(invalid_pointer, 0xdeadbeefu64);
        };
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Signaled(SIGSEGV, true),);
}

#[cfg(not(sanitized))]
#[test]
fn i_should_segfault_2() {
    use nix::sys::signal::Signal::SIGSEGV;
    use reverie_ptrace::testing::test_fn;
    let (output, _) = test_fn::<NoopTool, _>(|| unsafe {
        llvm_asm!(r#"mov $$0, %rax
            jmpq *%rax
            "#:::"rax")
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Signaled(SIGSEGV, true),);
}

#[cfg(not(sanitized))]
#[test]
fn child_should_inherit_fds() {
    check_fn::<NoopTool, _>(move || {
        let (fdread, fdwrite) = unistd::pipe().unwrap();
        let msg: [u8; 8] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                assert!(unistd::close(fdwrite).is_ok());
                let mut buf: [u8; 8] = [0; 8];
                assert_eq!(unistd::read(fdread, &mut buf), Ok(8));
                assert_eq!(buf, msg);
                assert_eq!(wait::waitpid(child, None), Ok(WaitStatus::Exited(child, 0)));
                unsafe {
                    libc::syscall(libc::SYS_exit_group, 0)
                };
                unreachable!();
            }
            Ok(ForkResult::Child) => {
                assert!(unistd::close(fdread).is_ok());
                assert_eq!(unistd::write(fdwrite, &msg), Ok(8));
                unsafe {
                    libc::syscall(libc::SYS_exit_group, 0)
                };
                unreachable!();
            }
            Err(err) => {
                panic!("fork failed: {:?}", err);
            }
        }
    });
}
