/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// signal handling related tests.

use reverie::syscalls::ExitGroup;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Default, Clone)]
struct LocalState;

#[derive(Debug, Serialize, Deserialize, Default)]
struct ThreadState;

#[reverie::tool]
impl Tool for LocalState {
    type GlobalState = ();
    type ThreadState = ThreadState;

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let exit_failure = ExitGroup::new().with_status(1);
        match syscall {
            // glibc should wrap signalfd -> signalfd4(2).
            #[cfg(target_arch = "x86_64")]
            Syscall::Signalfd(_) => guest.tail_inject(exit_failure).await,
            Syscall::Signalfd4(_) => {
                let (_, args) = syscall.into_parts();
                assert_eq!(args.arg2, 8);
                assert_eq!(args.arg3, libc::SFD_CLOEXEC as usize);
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::fs::File;
    use std::io;
    use std::io::Read;
    use std::mem;
    use std::mem::MaybeUninit;
    use std::os::unix::io::FromRawFd;

    use nix::sys::signal::Signal;
    use reverie_ptrace::testing::check_fn;

    use super::*;

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
    unsafe fn unblock_signals(signals: &[Signal]) -> io::Result<KernelSigset> {
        let set = KernelSigset::from(signals);
        let mut oldset: MaybeUninit<u64> = MaybeUninit::uninit();

        if libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_UNBLOCK,
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
    fn signalfd_sanity_check() {
        check_fn::<LocalState, _>(|| {
            assert!(unsafe { unblock_signals(&[Signal::SIGVTALRM, Signal::SIGALRM]) }.is_ok());
            let mut sigset: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
            let sigset = unsafe {
                libc::sigemptyset(sigset.as_mut_ptr());
                libc::sigaddset(sigset.as_mut_ptr(), libc::SIGALRM);
                libc::sigaddset(sigset.as_mut_ptr(), libc::SIGVTALRM);
                sigset.assume_init()
            };
            let fd = unsafe { libc::signalfd(-1, &sigset as *const _, libc::SFD_CLOEXEC) };
            assert!(fd > 0);

            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut siginfo = [0; mem::size_of::<libc::signalfd_siginfo>()];

            unsafe { libc::alarm(1) };

            assert!(file.read_exact(&mut siginfo).is_ok());

            let siginfo: libc::signalfd_siginfo = unsafe { mem::transmute(siginfo) };

            assert_eq!(siginfo.ssi_signo, libc::SIGALRM as u32);

            unsafe { libc::syscall(libc::SYS_exit_group, 0) };
        });
    }
}
