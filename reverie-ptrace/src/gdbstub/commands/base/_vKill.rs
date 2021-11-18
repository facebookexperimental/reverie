/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::{commands::*, hex::*};
use reverie::Pid;

#[derive(PartialEq, Debug)]
pub struct vKill {
    pub pid: Pid,
}

impl ParseCommand for vKill {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if !bytes.starts_with(b";") {
            None
        } else {
            let pid = decode_hex(&bytes[1..]).ok()?;
            Some(vKill {
                pid: Pid::from_raw(pid),
            })
        }
    }
}
