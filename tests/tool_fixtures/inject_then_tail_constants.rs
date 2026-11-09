/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::mem;

/// How many bytes of randomness to peak at.
pub const RAND_SIZE: usize = mem::size_of::<u64>();
