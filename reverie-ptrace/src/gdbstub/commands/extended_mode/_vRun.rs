/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::Bytes;

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

pub struct vRun {
    pub filename: Option<Bytes>,
    pub args: Bytes, // use Args type here!
}
