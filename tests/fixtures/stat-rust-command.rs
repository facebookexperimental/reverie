/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/stat_rust_guest.rs"]
mod guest;

fn main() {
    let mut args = std::env::args().skip(1);
    let operation = args.next().expect("expected stat or statx");
    assert!(args.next().is_none(), "expected exactly one operation");
    match operation.as_str() {
        "stat" => guest::stat_can_be_reinjected(),
        "statx" => guest::statx_fstat_returns_same_ino(),
        _ => panic!("unknown stat operation: {operation}"),
    }
}
