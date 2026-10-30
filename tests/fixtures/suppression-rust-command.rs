/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/suppression_rust_guest.rs"]
mod suppression_rust_guest;

fn main() {
    suppression_rust_guest::guest();
}
