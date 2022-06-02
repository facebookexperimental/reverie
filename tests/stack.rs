/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests for process and thread state.

use serde::{Deserialize, Serialize};

use reverie::{
    syscalls::{
        Addr, AddrMut, ExitGroup, MemoryAccess, Nanosleep, Syscall, SyscallInfo, Sysno, Timespec,
        Uname,
    },
    Error, Guest, Stack, Tool,
};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
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
                    Addr::from_raw(syscall.into_parts().1.arg0 as usize).unwrap();
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

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState2;

#[reverie::tool]
impl Tool for LocalState2 {
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

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState3;

#[reverie::tool]
impl Tool for LocalState3 {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let exit_success = ExitGroup::new().with_status(0);
        match syscall.number() {
            Sysno::exit_group => {
                {
                    let mut stack = guest.stack().await;
                    let ptr1: AddrMut<u64> = stack.reserve();
                    let _guard1 = stack.commit().unwrap();
                    guest.memory().write_value(ptr1, &3333).unwrap();
                    let v1 = guest.memory().read_value(ptr1).unwrap();
                    assert_eq!(v1, 3333);
                }

                {
                    let mut stack = guest.stack().await;
                    let ptr2: AddrMut<u64> = stack.reserve();
                    let _guard2 = stack.commit().unwrap();
                    guest.memory().write_value(ptr2, &4444).unwrap();
                    let v2 = guest.memory().read_value(ptr2).unwrap();
                    assert_eq!(v2, 4444);
                }

                guest.tail_inject(exit_success).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use reverie_ptrace::testing::check_fn;

    #[test]
    fn stack_allocator_should_work() {
        check_fn::<LocalState, _>(|| {
            assert_ne!(nix::sys::utsname::uname().sysname(), "");
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }

    /// A test that allocates on the stack TWICE.
    /// Currently failing because we attempt to grab a second stack while the guard is still alive.
    #[test]
    #[should_panic]
    fn stack_two_allocs_bad() {
        check_fn::<LocalState2, _>(|| {
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }

    /// In contrast, this is ok because the guard is dropped.
    #[test]
    fn stack_two_allocs_good() {
        check_fn::<LocalState3, _>(|| {
            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }
}
