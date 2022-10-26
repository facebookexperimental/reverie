/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// reinject stat* as fstatat unittest

use reverie::syscalls;
use reverie::syscalls::Displayable;
use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalState;

async fn handle_newfstatat<T: Guest<LocalState>>(
    guest: &mut T,
    call: syscalls::Newfstatat,
) -> Result<i64, Error> {
    let res = guest.inject(call).await;

    println!("{} = {:?}", call.display(&guest.memory()), res);

    Ok(res?)
}

#[reverie::tool]
impl Tool for LocalState {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Stat(stat) => handle_newfstatat(guest, stat.into()).await,
            Syscall::Lstat(lstat) => handle_newfstatat(guest, lstat.into()).await,
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use std::mem::MaybeUninit;

    use reverie_ptrace::testing::check_fn;

    use super::*;

    #[test]
    fn stat_can_be_reinjected() {
        check_fn::<LocalState, _>(|| {
            let path = "/proc/self/exe\0".as_ptr() as _;
            let fd = unsafe { libc::open(path, libc::O_RDONLY) };
            assert!(fd > 0);

            let mut stat_result: MaybeUninit<libc::stat> = MaybeUninit::uninit();
            let mut lstat_result: MaybeUninit<libc::stat> = MaybeUninit::uninit();
            let mut fstat_result: MaybeUninit<libc::stat> = MaybeUninit::uninit();

            assert_eq!(0, unsafe { libc::stat(path, stat_result.as_mut_ptr()) });
            let stat_result = unsafe { stat_result.assume_init() };
            assert_eq!(0, unsafe { libc::lstat(path, lstat_result.as_mut_ptr()) });
            let lstat_result = unsafe { lstat_result.assume_init() };
            assert_eq!(0, unsafe { libc::fstat(fd, fstat_result.as_mut_ptr()) });
            let fstat_result = unsafe { fstat_result.assume_init() };
            assert_eq!(stat_result.st_ino, fstat_result.st_ino);
            assert_ne!(stat_result.st_ino, lstat_result.st_ino);
        })
    }

    // glibc doesn't provide wrapper for statx
    unsafe fn statx(
        dirfd: i32,
        path: *const i8,
        flags: i32,
        mask: u32,
        statxbuf: *mut libc::statx,
    ) -> i64 {
        libc::syscall(libc::SYS_statx, dirfd, path, flags, mask, statxbuf)
    }

    #[test]
    fn statx_fstat_returns_same_ino() {
        check_fn::<LocalState, _>(|| {
            let path = "/proc/self/exe\0".as_ptr() as _;
            let dirfd = libc::AT_FDCWD;

            let mut fstatat_result: MaybeUninit<libc::stat> = MaybeUninit::uninit();
            let mut statx_result: MaybeUninit<libc::statx> = MaybeUninit::uninit();

            assert_eq!(0, unsafe {
                libc::fstatat(
                    dirfd,
                    path,
                    fstatat_result.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            });
            let fstatat_result = unsafe { fstatat_result.assume_init() };

            assert_eq!(0, unsafe {
                statx(
                    dirfd,
                    path,
                    libc::AT_SYMLINK_NOFOLLOW,
                    libc::STATX_INO,
                    statx_result.as_mut_ptr(),
                )
            });
            let statx_result = unsafe { statx_result.assume_init() };

            assert_eq!(fstatat_result.st_ino, statx_result.stx_ino);
        })
    }
}
