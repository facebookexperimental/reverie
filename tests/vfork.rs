/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// FIXME: aarch64 doesn't have a `vfork` syscall. Instead, it uses the `clone`
// syscall. This test should work with both methods of doing a `vfork`.
#![cfg(target_arch = "x86_64")]

// signal handling related tests.

use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;

#[derive(Debug, Default, Clone)]
struct LocalStateVfork;

#[derive(Debug, Default, Clone)]
struct LocalStateVforkClone;

#[reverie::tool]
impl Tool for LocalStateVfork {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Vfork(_) => {
                let (_, args) = syscall.into_parts();
                eprintln!(
                    "[pid = {}] tail_inject vfork (unchanged), args: {:x?}",
                    guest.tid(),
                    args
                );
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[reverie::tool]
impl Tool for LocalStateVforkClone {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Vfork(_) => {
                let (_, args) = syscall.into_parts();
                // NB: glibc's vfork is a assembly function, it uses %%rdi as return address (on stack)
                // vfork is very tricky because child/parent share the same stack. see P153347946 for
                // a bit more context.
                let raw: SyscallArgs = SyscallArgs {
                    arg0: (libc::CLONE_VFORK | libc::CLONE_VM | libc::SIGCHLD) as usize,
                    arg1: 0,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                    arg5: 0,
                };
                eprintln!(
                    "[pid = {}] inject vfork as clone, old arg: {:x?}, injected arg: {:x?}",
                    guest.tid(),
                    args,
                    raw
                );
                guest.tail_inject(reverie::syscalls::Clone::from(raw)).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::ffi::CString;

    use nix::sys::wait;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid;
    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[derive(Clone, Copy)]
    enum VforkTestFlag {
        ImplicitExit, // impicit exit, will run exit_handlers.
        ExplicitExit, // explicit exit, exit_handlers ignored.
        Execve,       // call execve.
    }

    fn implicit_exit(code: i32) -> ! {
        unsafe { libc::exit(code) }
    }

    fn vfork_test_helper(flag: VforkTestFlag) {
        #[allow(deprecated)]
        let pid = unsafe { libc::vfork() } as i32;
        assert!(pid >= 0);

        if pid > 0 {
            let pid = Pid::from_raw(pid);
            let status = wait::waitpid(Some(pid), None).unwrap();
            assert_eq!(status, WaitStatus::Exited(pid, 0));
        } else {
            // do sth trivial making sure stack is altered..
            let tp = libc::timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            };
            unsafe {
                libc::clock_nanosleep(
                    libc::CLOCK_MONOTONIC,
                    0,
                    &tp as *const _,
                    std::ptr::null_mut(),
                )
            };
            match flag {
                VforkTestFlag::ExplicitExit => {
                    let _ = unsafe { libc::syscall(libc::SYS_exit_group, 0) };
                }
                VforkTestFlag::ImplicitExit => {
                    // we should still call libc::exit here. Because `vfork' is not well
                    // supported by rust. see https://github.com/rust-lang/libc/pull/1574.
                    // note we've enabled #[ffi_return_twice], but if we don't call
                    // libc::exit(0) here, we'd end up calling library/std/src/sys/unix/os.rs
                    // then reached the `ud2` (inserted by never return type) instruction and
                    // get SIGILL. So it seems even #[ffi_return_twice] doesn't fix the whole
                    // issue. (The difference might be calling library implicit exit may have
                    // extra heap allocation).
                    implicit_exit(0)
                }
                VforkTestFlag::Execve => {
                    let program = CString::new("/bin/date").unwrap();
                    let env = CString::new("PATH=/bin:/usr/bin").unwrap();
                    let res = nix::unistd::execve(&program, &[&program], &[&env]);
                    assert!(!res.is_err());
                }
            }
        }
    }

    #[test]
    fn vfork_then_exit_group() {
        check_fn::<LocalStateVfork, _>(|| vfork_test_helper(VforkTestFlag::ExplicitExit));
    }

    #[test]
    fn vfork_then_implicit_exit() {
        check_fn::<LocalStateVfork, _>(|| vfork_test_helper(VforkTestFlag::ImplicitExit));
    }

    #[test]
    fn vfork_then_execve() {
        check_fn::<LocalStateVfork, _>(|| vfork_test_helper(VforkTestFlag::Execve));
    }

    #[test]
    fn vfork_into_clone_then_exit_group() {
        check_fn::<LocalStateVforkClone, _>(|| vfork_test_helper(VforkTestFlag::ExplicitExit));
    }

    #[test]
    fn vfork_into_clone_then_implicit_exit() {
        check_fn::<LocalStateVforkClone, _>(|| vfork_test_helper(VforkTestFlag::ImplicitExit));
    }

    #[test]
    fn vfork_into_clone_then_execve() {
        check_fn::<LocalStateVforkClone, _>(|| vfork_test_helper(VforkTestFlag::Execve));
    }
}
