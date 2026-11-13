/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An ordinary x86_64 musl program that enables `loader-private-runtime`
//! must reach `main` and keep its own C library. The private runtime exports
//! its allocator and its strong `__init_tls` under the libc names only with
//! the `private-libc-exports` feature, which only a private image's own build
//! enables, so linking this crate does not replace musl's `malloc` or
//! `__init_tls`. Had it done so, this test binary would end before `main`, at
//! the private image's fixed gate address, which an ordinary program never
//! maps.
//!
//! The test also names the layout types and constants that a mapped image
//! records in its layout descriptor, so a consumer's own musl tests can name
//! them too.
#![cfg(all(
    target_arch = "x86_64",
    target_env = "musl",
    feature = "loader-private-runtime"
))]

use reverie_inguest::guest::exec_private::NativeControl;
use reverie_inguest::guest::exec_private::mapped_initial;
use reverie_inguest::guest::exec_private::mapped_initial::libc_relay::RelayStorage;
use reverie_inguest::trap::FIXED_GATE_BASE;
use reverie_inguest::trap::FIXED_NATIVE_ENTRY;

/// The words a mapped image's layout descriptor records, in its order.
const LAYOUT: [u64; 9] = [
    mapped_initial::MAPPED_INPUT_VERSION,
    mapped_initial::MAPPED_INPUT_HEADER_BYTES as u64,
    mapped_initial::MAPPED_INPUT_MAX_BYTES as u64,
    core::mem::size_of::<NativeControl>() as u64,
    core::mem::align_of::<NativeControl>() as u64,
    core::mem::size_of::<RelayStorage>() as u64,
    core::mem::align_of::<RelayStorage>() as u64,
    FIXED_GATE_BASE,
    FIXED_NATIVE_ENTRY,
];

#[test]
fn reaches_main_with_musl_allocator() {
    // Every allocation goes through the C library's malloc and free.
    let boxed = Box::new(LAYOUT);
    let mut words: Vec<u64> = Vec::with_capacity(1);
    words.extend_from_slice(&boxed[..]);
    words.shrink_to_fit();
    let text = format!("{words:x?}");
    assert!(text.len() > 2);
    drop(text);
    assert_eq!(words.as_slice(), &LAYOUT[..]);
}

#[test]
fn names_the_mapped_layout() {
    const {
        assert!(
            mapped_initial::MAPPED_INPUT_HEADER_BYTES <= mapped_initial::MAPPED_INPUT_MAX_BYTES
        );
        assert!(core::mem::size_of::<RelayStorage>() > 0);
        assert!(core::mem::size_of::<NativeControl>() > 0);
    }
    assert_eq!(core::mem::align_of::<RelayStorage>(), 64);
    assert_eq!(core::mem::size_of::<RelayStorage>() % 64, 0);
    // The private gate layout, which only musl builds with this feature select.
    assert_eq!(FIXED_GATE_BASE, 0x6000_e100_1000);
    assert_eq!(FIXED_NATIVE_ENTRY, FIXED_GATE_BASE + 0x7c);
}
