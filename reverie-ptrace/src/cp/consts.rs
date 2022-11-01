/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// A page that is reserved by Reverie in every guest process.
pub const PRIVATE_PAGE_OFFSET: usize = 0x7000_0000;

/// trampoline data from private pages
pub const TRAMPOLINE_BASE: usize = PRIVATE_PAGE_OFFSET;
pub const TRAMPOLINE_SIZE: usize = 0x1000;

/// total private page size
pub const PRIVATE_PAGE_SIZE: usize = TRAMPOLINE_SIZE;

/// The size of the `ud2` instruction on x86_64.
#[cfg(target_arch = "x86_64")]
pub const UD_INSTR_SIZE: usize = 1;

/// The size of the `udf` instruction on aarch64.
#[cfg(target_arch = "aarch64")]
pub const UD_INSTR_SIZE: usize = 4;

/// The size of the syscall instruction. On x86_64, this is 2 bytes.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_INSTR_SIZE: usize = 2;

/// The size of the syscall instruction. On aarch64, this is 4 bytes.
#[cfg(target_arch = "aarch64")]
pub const SYSCALL_INSTR_SIZE: usize = 4;
