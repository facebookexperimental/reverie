/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Host execution of the exact data-only private-image decoder and TLS geometry.
//! No private-libc initialization, mapped owner, signal relay or runtime entry.

#![cfg(all(
    feature = "loader-private-runtime",
    target_arch = "x86_64",
    target_os = "linux"
))]

// Public test modules keep the production public data API visible without a
// dead-code exemption. These paths include the maintained implementation once.
#[path = "../src/private_runtime/tls/layout.rs"]
pub mod tls_layout;

/// Only the namespace expected by the production scalar decoder, not runtime
/// initialization or allocator ownership.
pub mod private_runtime {
    pub mod tls {
        pub use crate::tls_layout as layout;
    }
}

#[path = "../src/guest/exec_private/mapped_initial/mapped_scalar.rs"]
pub mod mapped_scalar;

#[cfg(test)]
mod tls_layout_tests {
    use crate::tls_layout::Error;
    use crate::tls_layout::Extent;
    use crate::tls_layout::Plan;
    use crate::tls_layout::Template;
    use crate::tls_layout::plan;

    fn e(start: usize, bytes: usize) -> Extent {
        Extent { start, bytes }
    }
    fn t(image: usize, file_bytes: usize, memory_bytes: usize, alignment: usize) -> Template {
        Template {
            image,
            file_bytes,
            memory_bytes,
            alignment,
        }
    }
    fn ordinary(template: Template) -> Result<Plan, Error> {
        plan(
            e(0x1000, 0xf000),
            e(0x8000, 0x2000),
            e(0x2000, 0x2000),
            e(0x2000, 0x1000),
            template,
        )
    }
    fn error(actual: Result<Plan, Error>, expected: Error) {
        assert!(
            matches!(actual, Err(found) if found == expected),
            "expected {expected:?}, got {actual:?}"
        );
    }

    #[test]
    fn literal_musl_placements_and_congruence() {
        // Literal hand-worked source table, not a second implementation of plan().
        // image, filesz, memsz, align, backing, module, total, TP, TLS, TLS align.
        let rows = [
            (0x2000, 16, 16, 8, 0x8000, 16, 240, 0x8028, 0x8018, 8),
            (0x2003, 5, 12, 16, 0x8000, 13, 248, 0x8030, 0x8023, 16),
            (0x2003, 5, 13, 16, 0x8000, 13, 248, 0x8030, 0x8023, 16),
            (
                0x2123, 7, 17, 4096, 0x8000, 0xedd, 0x1fb8, 0x9000, 0x8123, 4096,
            ),
            (0x2000, 32, 32, 64, 0x8008, 64, 344, 0x8080, 0x8040, 64),
            (0x2001, 1, 1, 1, 0x8000, 1, 232, 0x8020, 0x801f, 8),
        ];
        for (image, file, memory, align, backing, module, total, tp, tls, tls_align) in rows {
            let p = plan(
                e(0x1000, 0xf000),
                e(backing, 0x2000),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(image, file, memory, align),
            )
            .unwrap();
            assert_eq!(
                (
                    p.module_bytes(),
                    p.total_bytes(),
                    p.pthread().start,
                    p.tls().start,
                    p.tls_align()
                ),
                (module, total, tp, tls, tls_align)
            );
            assert_eq!(p.tls().bytes, module);
            assert_eq!(p.pthread().bytes, 200);
            assert_eq!(p.dtv(), e(backing, 16));
            assert_eq!(p.backing(), e(backing, 0x2000));
            assert_eq!(p.template().image, image);
            assert_eq!(p.tls().start % align, image % align);
            assert_eq!(p.pthread().start % tls_align, 0);
        }
    }

    #[test]
    fn zero_bss_means_no_extra_template_memory_not_backing_zeroing() {
        let p = ordinary(t(0x2000, 32, 32, 16)).unwrap();
        assert_eq!(
            (
                p.module_bytes(),
                p.total_bytes(),
                p.pthread().start,
                p.tls().start
            ),
            (32, 264, 0x8040, 0x8020)
        );
    }
    #[test]
    fn zero_file_bytes_and_empty_file_extent_are_allowed_at_anchor() {
        let p = plan(
            e(0x1000, 0xf000),
            e(0x8000, 0x2000),
            e(0x2000, 0x2000),
            e(0x2000, 0),
            t(0x2000, 0, 32, 16),
        )
        .unwrap();
        assert_eq!(
            (
                p.module_bytes(),
                p.total_bytes(),
                p.pthread().start,
                p.tls().start
            ),
            (32, 264, 0x8040, 0x8020)
        );
    }
    #[test]
    fn exact_backing_boundary_is_accepted() {
        let p = plan(
            e(0x1000, 0xf000),
            e(0x8000, 240),
            e(0x2000, 0x2000),
            e(0x2000, 0x1000),
            t(0x2000, 16, 16, 8),
        )
        .unwrap();
        assert_eq!(p.total_bytes(), 240);
        assert_eq!(p.pthread().start + p.pthread().bytes, 0x80f0);
    }
    #[test]
    fn backing_one_byte_short_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 239),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Outside,
        );
    }
    #[test]
    fn template_ending_at_file_boundary_is_accepted() {
        assert!(ordinary(t(0x2ff0, 16, 16, 16)).is_ok());
    }
    #[test]
    fn template_crossing_file_boundary_is_refused() {
        error(ordinary(t(0x2ff1, 16, 16, 16)), Error::Image);
    }
    #[test]
    fn template_in_mapped_bss_tail_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 0x2000),
                e(0x2000, 0x1000),
                e(0x2000, 0x20),
                t(0x2080, 8, 16, 8),
            ),
            Error::Image,
        );
    }
    #[test]
    fn backing_in_mapped_bss_tail_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x2080, 512),
                e(0x2000, 0x1000),
                e(0x2000, 0x20),
                t(0x2000, 8, 16, 8),
            ),
            Error::Overlap,
        );
    }
    #[test]
    fn file_extent_outside_mapped_load_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 0x2000),
                e(0x2000, 0x1000),
                e(0x1ff0, 0x20),
                t(0x2000, 8, 16, 8),
            ),
            Error::Outside,
        );
    }
    #[test]
    fn file_extent_extending_past_mapped_load_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 0x2000),
                e(0x2000, 0x1000),
                e(0x2000, 0x1001),
                t(0x2000, 8, 16, 8),
            ),
            Error::Outside,
        );
    }
    #[test]
    fn zero_and_non_power_of_two_alignment_are_refused() {
        for a in [0, 3, 24] {
            error(ordinary(t(0x2000, 8, 16, a)), Error::Alignment);
        }
    }
    #[test]
    fn backing_must_be_tcb_aligned() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8001, 0x2000),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 8, 16, 8),
            ),
            Error::Alignment,
        );
    }
    #[test]
    fn filesz_larger_than_memsz_is_refused() {
        error(ordinary(t(0x2000, 17, 16, 8)), Error::Image);
    }
    #[test]
    fn module_rounding_overflow_is_refused() {
        error(ordinary(t(0x2000, 1, usize::MAX, 8)), Error::Overflow);
    }
    #[test]
    fn region_end_overflow_is_refused() {
        error(
            plan(
                e(0x1000, usize::MAX),
                e(0x8000, 240),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Overflow,
        );
    }
    #[test]
    fn template_end_overflow_is_refused() {
        error(ordinary(t(usize::MAX - 3, 8, 16, 8)), Error::Overflow);
    }
    #[test]
    fn empty_mapped_load_and_empty_memory_are_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 240),
                e(0x2000, 0),
                e(0x2000, 0),
                t(0x2000, 0, 16, 8),
            ),
            Error::Empty,
        );
        error(ordinary(t(0x2000, 0, 0, 8)), Error::Empty);
    }
    #[test]
    fn empty_region_and_backing_are_refused() {
        error(
            plan(
                e(0x1000, 0),
                e(0x8000, 240),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Empty,
        );
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 0),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Empty,
        );
    }
    #[test]
    fn mapped_load_outside_region_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x8000, 240),
                e(0x20000, 0x2000),
                e(0x20000, 0x1000),
                t(0x20000, 16, 16, 8),
            ),
            Error::Outside,
        );
    }
    #[test]
    fn backing_outside_region_is_refused() {
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x10000, 240),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Outside,
        );
    }
    #[test]
    fn backing_may_touch_but_not_overlap_mapped_end() {
        assert!(
            plan(
                e(0x1000, 0xf000),
                e(0x4000, 240),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8)
            )
            .is_ok()
        );
        error(
            plan(
                e(0x1000, 0xf000),
                e(0x3ff8, 240),
                e(0x2000, 0x2000),
                e(0x2000, 0x1000),
                t(0x2000, 16, 16, 8),
            ),
            Error::Overlap,
        );
    }
}
