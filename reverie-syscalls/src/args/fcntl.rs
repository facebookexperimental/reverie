/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::unix::io::RawFd;

use super::Addr;
use super::Pid;
use crate::FromToRaw;

// TODO: Upstream this struct to libc crate.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct f_owner_ex {
    typ: libc::c_int,
    pid: libc::pid_t,
}

command_enum! {
    /// A `fcntl` command paired with its argument.
    pub enum FcntlCmd<'a>: libc::c_int {
        F_DUPFD(RawFd) = 0,
        F_GETFD = 1,
        F_SETFD(RawFd) = 2,
        F_GETFL = 3,
        F_SETFL(i32) = 4,
        F_GETLK(Option<Addr<'a, libc::flock>>) = 5,
        F_SETLK(Option<Addr<'a, libc::flock>>) = 6,
        F_SETLKW(Option<Addr<'a, libc::flock>>) = 7,
        F_SETOWN = 8,
        F_GETOWN(Pid) = 9,
        F_SETSIG(i32) = 10,
        F_GETSIG = 11,
        F_GETLK64(Option<Addr<'a, libc::flock64>>) = 12,
        F_SETLK64(Option<Addr<'a, libc::flock64>>) = 13,
        F_SETLKW64(Option<Addr<'a, libc::flock64>>) = 14,
        F_SETOWN_EX(Option<Addr<'a, f_owner_ex>>) = 15,
        F_GETOWN_EX(Option<Addr<'a, f_owner_ex>>) = 16,
        F_GETOWNER_UIDS = 17,

        F_OFD_GETLK(Option<Addr<'a, libc::flock>>) = 36,
        F_OFD_SETLK(Option<Addr<'a, libc::flock>>) = 37,
        F_OFD_SETLKW(Option<Addr<'a, libc::flock>>) = 38,

        F_SETLEASE(i32) = 1024,
        F_GETLEASE = 1025,
        F_NOTIFY(i32) = 1026,
        F_DUPFD_CLOEXEC(i32) = 1030,
        F_SETPIPE_SZ(i32) = 1031,
        F_GETPIPE_SZ = 1032,
        F_ADD_SEALS(i32) = 1033,
        F_GET_SEALS = 1034,

        F_GET_RW_HINT(Option<Addr<'a, u64>>) = 1035,
        F_SET_RW_HINT(Option<Addr<'a, u64>>) = 1036,
        F_GET_FILE_RW_HINT(Option<Addr<'a, u64>>) = 1037,
        F_SET_FILE_RW_HINT(Option<Addr<'a, u64>>) = 1038,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fcntl() {
        assert_eq!(format!("{:?}", FcntlCmd::F_DUPFD(2)), "F_DUPFD(2)");
        assert_eq!(format!("{}", FcntlCmd::F_DUPFD(2)), "F_DUPFD(2)");
        assert_eq!(FcntlCmd::from_raw(libc::F_DUPFD, 42), FcntlCmd::F_DUPFD(42));
        assert_eq!(FcntlCmd::from_raw(1337, 42), FcntlCmd::Other(1337, 42));
        assert_eq!(FcntlCmd::F_DUPFD(42).into_raw(), (libc::F_DUPFD, 42));
    }
}
