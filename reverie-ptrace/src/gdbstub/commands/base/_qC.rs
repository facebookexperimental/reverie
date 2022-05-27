/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::gdbstub::commands::*;
use bytes::BytesMut;

#[derive(PartialEq, Debug)]
pub struct qC {}

impl ParseCommand for qC {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if !bytes.is_empty() { None } else { Some(qC {}) }
    }
}
