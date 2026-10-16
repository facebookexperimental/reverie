/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Deprecated location of the Linux syscall provider interface.
//!
//! [`LinuxProvider`], [`ProviderOutcome`], [`SyscallRequest`],
//! [`GuestMemoryAccess`], [`AddressSpace`] and the types they use now live in
//! Reverie's core, as [`reverie::provider`]. This crate only re-exports that
//! module, unchanged, for one release so that existing imports keep compiling;
//! import from `reverie::provider` instead. It will then be deleted
//! (<https://github.com/rrnewton/hermit/issues/4485>).

pub use reverie::provider::*;
