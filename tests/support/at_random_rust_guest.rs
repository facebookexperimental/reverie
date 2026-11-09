/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "../tool_fixtures/at_random_constants.rs"]
mod at_random_constants;

use at_random_constants::PRNG_SEED;

pub fn guest_mode() {
    println!("Running in guest mode (actual test).");

    let at_random = unsafe { libc::getauxval(libc::AT_RANDOM) as *const u8 };
    let slice = unsafe { std::slice::from_raw_parts(at_random, 16) };

    println!("Entropy (intercepted) at at_random {:02x?}", slice);

    assert_eq!(slice, PRNG_SEED);
}
