/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::gdbstub::{commands::*, hex::*};
use bytes::Bytes;

pub struct QEnvironmentHexEncoded {
    pub key: Bytes,
    pub value: Option<Bytes>,
}
