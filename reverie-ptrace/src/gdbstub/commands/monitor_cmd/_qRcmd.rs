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
use bytes::Bytes;
use bytes::BytesMut;

#[derive(PartialEq, Debug)]
pub struct qRcmd {
    pub cmd: Bytes,
}

impl ParseCommand for qRcmd {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            Some(qRcmd {
                cmd: bytes.freeze(),
            })
        }
    }
}
