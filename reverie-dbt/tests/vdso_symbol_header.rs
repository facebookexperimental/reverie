/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `native/client.c` patches the vDSO by reverie-core's classification
//! of every vDSO function, through a copy of it as a C header, which must be
//! current.

#![cfg(target_arch = "x86_64")]

/// Run with `REVERIE_BLESS=1` to rewrite the header from the generator.
#[test]
fn vdso_symbol_header_is_generated_from_reverie_core() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/native/reverie_vdso_symbols.h");
    let expected = reverie::vdso::c_header();
    if std::env::var_os("REVERIE_BLESS").is_some_and(|bless| bless == "1") {
        std::fs::write(path, &expected).unwrap();
    }
    let actual = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        actual == expected,
        "{path} is not the output of reverie::vdso::c_header(); \
         rerun this test with REVERIE_BLESS=1 to regenerate it"
    );
}
