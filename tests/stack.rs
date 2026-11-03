/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests for process and thread state.

#[cfg(all(not(sanitized), test))]
#[path = "support/stack_rust_guest.rs"]
mod stack_rust_guest;
#[cfg(all(not(sanitized), test))]
#[path = "tool_fixtures/stack.rs"]
mod stack_tool;

use reverie::Error;
use reverie::Guest;
use reverie::Stack;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Nanosleep;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::syscalls::Timespec;
use reverie::syscalls::Uname;

#[derive(Debug, Default, Clone)]
struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let exit_failure = ExitGroup::new().with_status(1);
        let exit_success = ExitGroup::new().with_status(0);
        match syscall.number() {
            Sysno::uname => {
                let mut stack = guest.stack().await;

                let uname_on_stack: AddrMut<libc::utsname> = stack.reserve();

                stack.commit()?;
                // inject uname using stack allocator
                let _ = guest
                    .inject(Uname::new().with_buf(Some(uname_on_stack)))
                    .await?;

                // (re-) inject the old uname, with buf allocated by caller
                let _ = guest.inject(syscall).await?;

                let memory = guest.memory();

                let unamebuf: Addr<libc::utsname> =
                    Addr::from_raw(syscall.into_parts().1.arg0).unwrap();
                let uname1 = memory.read_value(unamebuf)?;
                let uname2 = memory.read_value(uname_on_stack)?;

                if uname1 != uname2 {
                    guest.tail_inject(exit_failure).await
                } else {
                    Ok(0)
                }
            }
            Sysno::exit_group => {
                let request = Timespec {
                    tv_sec: 1,
                    tv_nsec: 2,
                };

                let mut stack = guest.stack().await;

                let req = stack.push(request);
                let rem: AddrMut<Timespec> = stack.reserve();
                stack.commit()?;
                let ret = guest
                    .inject(Nanosleep::new().with_req(Some(req)).with_rem(Some(rem)))
                    .await?;

                let memory = guest.memory();
                let rem = memory.read_value(rem)?;
                if ret == 0 && rem.tv_sec != 0 {
                    guest.tail_inject(exit_failure).await
                } else {
                    guest.tail_inject(exit_success).await
                }
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct LocalState2;

#[reverie::tool]
impl Tool for LocalState2 {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let exit_success = ExitGroup::new().with_status(0);
        match syscall.number() {
            Sysno::exit_group => {
                let mut stack = guest.stack().await;
                let ptr1: AddrMut<u64> = stack.reserve();
                let _guard1 = stack.commit().unwrap();
                guest.memory().write_value(ptr1, &3333).unwrap();
                let v1 = guest.memory().read_value(ptr1).unwrap();
                assert_eq!(v1, 3333);

                let mut stack = guest.stack().await;
                let ptr2: AddrMut<u64> = stack.reserve();
                let _guard2 = stack.commit().unwrap();
                guest.memory().write_value(ptr2, &4444).unwrap();
                let v2 = guest.memory().read_value(ptr2).unwrap();
                assert_eq!(v2, 4444);

                guest.tail_inject(exit_success).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

/// Tool for the uncommitted-overlap negative: it holds a stack builder
/// without committing, then asks for a second guest stack, which the
/// allocator refuses with a panic (pending builders are exclusive).
#[derive(Debug, Default, Clone)]
struct LocalStateUncommitted;

#[reverie::tool]
impl Tool for LocalStateUncommitted {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::exit_group => {
                let mut stack = guest.stack().await;
                let _ptr: AddrMut<u64> = stack.reserve();
                // No commit: `stack` is a live uncommitted builder. A second
                // checkout while it is alive must panic.
                let _second = guest.stack().await;
                unreachable!("second uncommitted stack checkout must panic");
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::sync::atomic::Ordering;

    use reverie_ptrace::testing::check_fn;
    use stack_tool::LocalState3;

    use super::*;

    #[test]
    fn stack_allocator_should_work() {
        check_fn::<LocalState, _>(|| {
            assert_ne!(
                nix::sys::utsname::uname()
                    .expect("Failed getting uname.")
                    .sysname(),
                ""
            );
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }

    /// The original two-allocs scenario: two nested stack commits with both
    /// guards still alive. Nested scratch frames are now a supported,
    /// bounded feature (commit ee4fb6e043: committed frames stay disjoint
    /// below live ones), so this is a positive test: both values must be
    /// written and read back by the Tool, and the guest must exit 0.
    #[test]
    fn stack_two_allocs_nested_good() {
        use reverie_ptrace::testing::test_fn;
        let (output, _) = test_fn::<LocalState2, _>(|| {
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        })
        .unwrap();
        assert_eq!(output.status, reverie::ExitStatus::Exited(0));
    }

    /// The negative that must still panic: a second stack checkout while
    /// the first builder is still uncommitted. Pending builders are
    /// exclusive, so retrieving another guest stack panics.
    #[test]
    #[should_panic]
    fn stack_two_allocs_uncommitted_bad() {
        check_fn::<LocalStateUncommitted, _>(|| {
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }

    /// In contrast, this is ok because the guard is dropped.
    #[test]
    fn stack_two_allocs_good() {
        let state = check_fn::<LocalState3, _>(stack_rust_guest::guest);
        let observed = state.observed.load(Ordering::SeqCst);
        eprintln!("stack good function: observed={observed}");
        assert!(observed);

        rust_command_test();
    }

    fn assert_command_output(
        label: &str,
        output: &reverie::process::Output,
        state: &stack_tool::StackObserved,
    ) {
        let observed = state.observed.load(Ordering::SeqCst);
        eprintln!(
            "stack good Rust command {label}: status={:?} stdout={:02x?} stderr={:02x?} observed={observed}",
            output.status, output.stdout, output.stderr,
        );
        assert_eq!(output.status, reverie::ExitStatus::Exited(0));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert!(observed);
    }

    fn rust_command_test() {
        let program = env!("CARGO_BIN_EXE_stack-rust-command-guest");
        eprintln!("stack good Rust command image={program}");

        let native = std::process::Command::new(program).output().unwrap();
        eprintln!(
            "stack good Rust command native: status={:?} stdout={:02x?} stderr={:02x?}",
            native.status, native.stdout, native.stderr,
        );
        assert_eq!(native.status.code(), Some(0));
        assert!(native.stdout.is_empty());
        assert!(native.stderr.is_empty());

        let (output, state) =
            reverie_test_support::test_cmd_with_config::<LocalState3>(program, &[], ()).unwrap();
        assert_command_output("ptrace", &output, &state);
    }
}
