/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A tiny guest used by the smoke test.
//!
//! It issues a **raw** `getpid` syscall (bypassing any libc/vDSO caching) and
//! prints the returned value. Run under `LD_PRELOAD=libreverie_preload.so` with
//! `REVERIE_PRELOAD_TOOL=spoof-getpid`, the trap rewrites the result, so the
//! probe prints the spoof value — direct proof that SIGSYS interception fired
//! and mutated a syscall result.

fn main() {
    // Raw getpid: guaranteed to enter the kernel (and thus the seccomp filter),
    // unlike a cached libc getpid.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    println!("getpid={pid}");
}
