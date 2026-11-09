/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use syscalls::Sysno;
use syscalls::syscall;

pub fn guest() {
    let pid = unsafe { syscall!(Sysno::getpid) }.unwrap();
    let tid = unsafe { syscall!(Sysno::gettid) }.unwrap();

    // This shouldn't work.
    for _ in 0..100 {
        let ret = unsafe { syscall!(Sysno::tgkill, pid, tid, libc::SIGTERM) };
        assert_eq!(ret, Ok(0));
    }
}
