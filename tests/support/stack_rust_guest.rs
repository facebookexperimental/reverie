/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Original good stack test body, shared with its ordinary command image.

pub fn guest() {
    unsafe { libc::syscall(libc::SYS_exit_group, 0) };
}
