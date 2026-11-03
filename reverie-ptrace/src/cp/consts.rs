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
#[cfg(target_arch = "x86_64")]
pub const SCRATCH_BASE: usize = TRAMPOLINE_BASE + TRAMPOLINE_SIZE;
/// The repair page on aarch64 (`AARCH64_SCRATCH_BASE`).
#[cfg(target_arch = "aarch64")]
pub const SCRATCH_BASE: usize = AARCH64_SCRATCH_BASE;
pub const SCRATCH_SIZE: usize = 0x1000;

/// The largest page an aarch64 kernel may use: 4, 16 or 64 KiB.
#[cfg(any(test, target_arch = "aarch64"))]
const AARCH64_MAX_PAGE: usize = 0x1_0000;

/// The repair page's address on aarch64, the first 64 KiB boundary past both
/// fixed pages below it, whatever the kernel's page size: the trampoline's
/// mapping covers a whole page from `TRAMPOLINE_BASE` (an `mmap` at an
/// address inside that page fails with `EINVAL`), and the reserved input
/// page, one page at `reverie::reserved_input::RESERVED_INPUT_BASE`, which
/// the backend maps with `MAP_FIXED_NOREPLACE` and which would fail there
/// if the repair page held its address.
#[cfg(any(test, target_arch = "aarch64"))]
const AARCH64_SCRATCH_BASE: usize =
    reverie::reserved_input::RESERVED_INPUT_BASE as usize + AARCH64_MAX_PAGE;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the pages at `a` and `b`, each one page of `page` bytes or
    /// more as a kernel with that page size maps them, overlap.
    fn pages_overlap(a: usize, b: usize, page: usize) -> bool {
        a / page == b / page
    }

    /// The aarch64 repair page shares a page with neither the trampoline nor
    /// the reserved input page at any aarch64 page size, and lies on a
    /// boundary of the largest, so its `mmap` neither fails nor takes the
    /// input page's address. Checked on every host, from the constants.
    #[test]
    fn the_aarch64_repair_page_overlaps_no_fixed_page() {
        let input = reverie::reserved_input::RESERVED_INPUT_BASE as usize;
        assert_eq!(AARCH64_SCRATCH_BASE % AARCH64_MAX_PAGE, 0);
        for page in [0x1000, 0x4000, AARCH64_MAX_PAGE] {
            assert!(
                !pages_overlap(AARCH64_SCRATCH_BASE, TRAMPOLINE_BASE, page),
                "{page:#x}"
            );
            assert!(
                !pages_overlap(AARCH64_SCRATCH_BASE, input, page),
                "{page:#x}"
            );
        }
    }

    /// The x86_64 repair page, the page after the trampoline, is apart from
    /// the reserved input page too.
    #[test]
    fn the_x86_64_repair_page_overlaps_no_fixed_page() {
        let x86_64_scratch = TRAMPOLINE_BASE + TRAMPOLINE_SIZE;
        let input = reverie::reserved_input::RESERVED_INPUT_BASE as usize;
        assert!(!pages_overlap(x86_64_scratch, TRAMPOLINE_BASE, 0x1000));
        assert!(!pages_overlap(x86_64_scratch, input, 0x1000));
    }
}
