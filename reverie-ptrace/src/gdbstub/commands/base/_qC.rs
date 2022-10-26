/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;

#[derive(PartialEq, Debug)]
pub struct qC {}

impl ParseCommand for qC {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if !bytes.is_empty() { None } else { Some(qC {}) }
    }
}
