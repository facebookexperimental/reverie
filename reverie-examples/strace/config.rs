/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::filter::Filter;

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub filters: Vec<Filter>,
}
