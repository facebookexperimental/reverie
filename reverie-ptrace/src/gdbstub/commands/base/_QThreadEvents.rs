/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::gdbstub::{commands::*, hex::*};
use bytes::BytesMut;

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
