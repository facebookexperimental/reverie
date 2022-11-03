/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests that syscall suppression works. That is, when we intercept a syscall,
//! we should not run the real syscall.

use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;

#[derive(Debug, Default, Clone)]
struct TestTool;

#[reverie::tool]
impl Tool for TestTool {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Tgkill(_) => {
                // Suppress this syscall. This thread shall not be killed.
                Ok(0)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use reverie_ptrace::testing::check_fn;
    use syscalls::syscall;
    use syscalls::Sysno;

    use super::*;

    #[test]
    fn suppress_tgkill() {
        check_fn::<TestTool, _>(|| {
            let pid = unsafe { syscall!(Sysno::getpid) }.unwrap();
            let tid = unsafe { syscall!(Sysno::gettid) }.unwrap();

            // This shouldn't work.
            for _ in 0..100 {
                let ret = unsafe { syscall!(Sysno::tgkill, pid, tid, libc::SIGTERM) };
                assert_eq!(ret, Ok(0));
            }
        });
    }
}
