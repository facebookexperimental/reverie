/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;
use std::process;
use std::ptr;

fn main() {
    let path = b"/bin/echo\0";
    let argument = b"should-not-run\0";
    let argv = [
        path.as_ptr().cast::<libc::c_char>(),
        argument.as_ptr().cast::<libc::c_char>(),
        ptr::null(),
    ];
    let environment = [ptr::null::<libc::c_char>()];

    let result = unsafe { libc::execve(path.as_ptr().cast(), argv.as_ptr(), environment.as_ptr()) };
    if result != -1 {
        eprintln!("execve unexpectedly returned {result}");
        process::exit(1);
    }

    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOTSUP) {
        eprintln!("execve returned {error}, expected ENOTSUP");
        process::exit(1);
    }

    println!("exec rejected with ENOTSUP");
}
