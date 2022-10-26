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
pub struct QThreadEvents {
    pub enable: bool,
}

impl ParseCommand for QThreadEvents {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if !bytes.starts_with(b":") {
            None
        } else {
            let value: u32 = decode_hex(&bytes[1..]).ok()?;
            if value != 0 && value != 1 {
                None
            } else {
                let enable = value == 1;
                Some(QThreadEvents { enable })
            }
        }
    }
}
