/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use serde::Deserialize;
use serde::Serialize;

use crate::filter::Filter;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub filters: Vec<Filter>,
}
