/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The raw syscall request a provider executes.

use crate::syscalls::SyscallInfo;

/// A Linux syscall request transported from guest to host memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallRequest {
    number: u64,
    args: [u64; 6],
}

impl SyscallRequest {
    /// Creates a request from a Linux syscall number and its six ABI arguments.
    pub const fn new(number: u64, args: [u64; 6]) -> Self {
        Self { number, args }
    }

    /// Creates a transport request from a shared Reverie syscall.
    pub fn from_syscall<S: SyscallInfo>(syscall: S) -> Self {
        let (number, args) = syscall.into_parts();
        Self::new(
            number as u64,
            [
                args.arg0 as u64,
                args.arg1 as u64,
                args.arg2 as u64,
                args.arg3 as u64,
                args.arg4 as u64,
                args.arg5 as u64,
            ],
        )
    }

    /// Returns the Linux syscall number.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// Returns the six Linux syscall arguments.
    pub const fn args(&self) -> &[u64; 6] {
        &self.args
    }
}
