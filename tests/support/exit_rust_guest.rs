/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

pub const PRE_BODY_MARKER: &[u8] = b"inject-exit-rust-body\n";

pub fn smoke() {
    unsafe {
        let _ = libc::getpid();
        libc::syscall(libc::SYS_exit_group, 0);
    }
}
