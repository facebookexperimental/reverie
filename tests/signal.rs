/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// signal handling related tests.

use nix::sys::signal::Signal;
use reverie::{
    syscalls::{AddrMut, ExitGroup, MemoryAccess, RtSigpending, Syscall, SyscallInfo, Sysno},
    Error, Guest, Tool,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

#[reverie::tool]
impl Tool for LocalState {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::exit_group {
            let sigset_rptr = 0x7000_0100usize;
            let sigset: AddrMut<libc::sigset_t> = AddrMut::from_raw(sigset_rptr as _).unwrap();
            let exit_failure = ExitGroup::new().with_status(1);
            let exit_success = syscall;
            if guest
                .inject(
                    RtSigpending::new()
                        .with_set(Some(sigset))
                        .with_sigsetsize(8usize),
                )
                .await
                .is_ok()
            {
                let memory = guest.memory();
                let pending: u64 = memory.read_value(sigset.cast())?;
                if pending != 1u64 << (Signal::SIGVTALRM as i32 - 1) {
                    guest.tail_inject(exit_failure).await
                } else {
                    guest.tail_inject(exit_success).await
                }
            } else {
                guest.tail_inject(exit_success).await
            }
        } else {
            guest.tail_inject(syscall).await
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use nix::sys::signal;
    use reverie_ptrace::testing::check_fn;
    use std::{io, mem::MaybeUninit};

    // kernel_sigset_t used by naked syscall
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct KernelSigset(u64);

    impl From<&[Signal]> for KernelSigset {
        fn from(signals: &[Signal]) -> Self {
            let mut set: u64 = 0;
            for &sig in signals {
                set |= 1u64 << (sig as usize - 1);
            }
            KernelSigset(set)
        }
    }

    #[allow(dead_code)]
    unsafe fn block_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        let set = KernelSigset::from(signals);
        let mut oldset: MaybeUninit<u64> = MaybeUninit::uninit();

        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &set as *const _,
            oldset.as_mut_ptr(),
            8,
        ) != 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(KernelSigset(oldset.assume_init()))
        }
    }

    #[test]
    // The actual test is in `handle_syscall_event`. To test we can get
    // pending signals from tracee, by injecting rt_sigpending.
    fn can_get_pending_signals() {
        check_fn::<LocalState, _>(|| {
            assert!(unsafe { block_signals(&[Signal::SIGVTALRM]) }.is_ok());

            assert!(signal::raise(Signal::SIGVTALRM).is_ok());

            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }
}
