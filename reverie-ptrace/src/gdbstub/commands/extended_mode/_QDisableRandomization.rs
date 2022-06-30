/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

#[derive(Debug, PartialEq)]
pub struct QDisableRandomization {
    pub val: bool,
}

impl ParseCommand for QDisableRandomization {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes == ":0" {
            Some(QDisableRandomization { val: false })
        } else if bytes == ":1" {
            Some(QDisableRandomization { val: true })
        } else {
            None
        }
    }
}
