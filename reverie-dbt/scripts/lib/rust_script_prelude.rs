/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

/// Restore normal Unix pipeline termination before producing script output.
pub fn init() {
    // SAFETY: a standalone script calls this before creating any threads.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}
