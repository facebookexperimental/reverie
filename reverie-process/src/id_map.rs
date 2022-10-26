/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io::Write;

pub fn make_id_map(map: &[(libc::uid_t, libc::uid_t, u32)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (inside, outside, count) in map {
        writeln!(v, "{} {} {}", inside, outside, count).unwrap();
    }
    v
}
