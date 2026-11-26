/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Shared Linux signal machinery for Reverie backends.
//!
//! The frame builder in `frame` (x86_64 only) was lifted from LinuxEmu so
//! that every backend constructs and restores the same Linux signal frames.

#[cfg(target_arch = "x86_64")]
pub mod frame;

/// Size in bytes of Linux's `siginfo_t` userspace ABI representation.
pub const SIGNAL_INFO_SIZE: usize = 128;
