/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

#[derive(PartialEq, Debug)]
pub struct G {
    pub vals: Vec<u8>,
}

impl ParseCommand for G {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            let vals = decode_hex_string(&bytes).ok()?;
            Some(G { vals })
        }
    }
}
