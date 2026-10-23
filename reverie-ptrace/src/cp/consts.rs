/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// A page that is reserved by Reverie in every guest process.
pub const PRIVATE_PAGE_OFFSET: usize = 0x7100_0000;

/// trampoline data from private pages
pub const TRAMPOLINE_BASE: usize = PRIVATE_PAGE_OFFSET;
pub const TRAMPOLINE_SIZE: usize = 0x1000;

/// total private page size
pub const PRIVATE_PAGE_SIZE: usize = TRAMPOLINE_SIZE;

/// The page after the trampoline, where pre-init maps, at every exec, the
/// SIGTRAP repairs' page, read-write and sealed (`mseal`), unless the new
/// image already has something there
/// (<https://github.com/rrnewton/hermit/issues/4409>). Once sealed, no task
/// can unmap, replace or reprotect it.
pub const SCRATCH_BASE: usize = TRAMPOLINE_BASE + TRAMPOLINE_SIZE;
pub const SCRATCH_SIZE: usize = 0x1000;

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
