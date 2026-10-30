/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::mem::MaybeUninit;

pub fn clock_getres() {
    let mut res = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };

    let ret = unsafe { libc::clock_getres(libc::CLOCK_MONOTONIC, &mut res as *mut _) };

    assert_eq!(ret, 0);

    assert_eq!(res.tv_sec, 0);
    assert_eq!(res.tv_nsec, 42);
}

pub fn gettimeofday() {
    let mut tod = MaybeUninit::zeroed();
    let mut tz = MaybeUninit::zeroed();
    assert_eq!(
        unsafe { libc::gettimeofday(tod.as_mut_ptr(), tz.as_mut_ptr()) },
        0
    );
    let tod = unsafe { tod.assume_init() };
    assert_eq!(tod.tv_usec % 1000, 345);
}
