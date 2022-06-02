/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;
use reverie::Pid;

use crate::gdbstub::{commands::*, hex::*};

#[derive(PartialEq, Debug)]
pub struct D {
    pub pid: Option<Pid>,
}

impl ParseCommand for D {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            Some(D { pid: None })
        } else if !bytes.starts_with(b";") {
            None
        } else {
            let pid = decode_hex(&bytes[1..]).ok()?;
            Some(D {
                pid: Some(Pid::from_raw(pid)),
            })
        }
    }
}
