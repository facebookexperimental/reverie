/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/inject_then_tail_rust_guest.rs"]
mod guest;

fn main() {
    guest::guest_mode();
}
