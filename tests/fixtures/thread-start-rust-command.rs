/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../support/thread_start_guest.rs"]
mod thread_start_guest;

fn main() {
    thread_start_guest::guest();
}
