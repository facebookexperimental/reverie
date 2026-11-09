/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/at_random_rust_guest.rs"]
mod at_random_rust_guest;

fn main() {
    assert_eq!(std::env::args_os().len(), 1);
    at_random_rust_guest::guest_mode();
}
