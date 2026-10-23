/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-guest runtime records which file is the C library when it admits
//! guest SIGALRM handlers, during installation, inside the guest. The
//! runtime's private allocation scope redirects only Rust allocations, so
//! recording must not call anything that allocates through the C library's
//! malloc, which inside the guest is the guest's own heap. `dlopen` did, even
//! with `RTLD_NOLOAD`, on the C library's first direct open.
//!
//! This binary holds one test so that nothing else in the process opens the C
//! library first, and measures the C library's heap around the call.

#[test]
fn recording_the_c_library_allocates_nothing_from_its_malloc() {
    // SAFETY: mallinfo2 only reads the allocator's statistics.
    let before = unsafe { libc::mallinfo2() };
    reverie_inguest::guest::restorer::record_libc_identity().unwrap();
    let after = unsafe { libc::mallinfo2() };
    assert_eq!(
        (after.arena, after.uordblks, after.hblkhd),
        (before.arena, before.uordblks, before.hblkhd),
        "recording the C library changed its heap"
    );
}
