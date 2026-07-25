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

/// LLDB `qRegisterInfo<hex>` query. LLDB probes registers one at a time,
/// starting from index 0 and incrementing until the stub replies with an error
/// (`E45`). Each successful reply describes one register.
#[derive(PartialEq, Debug)]
pub struct qRegisterInfo {
    /// Index of the register being queried (encoded in hex by the client).
    pub reg: usize,
}

impl ParseCommand for qRegisterInfo {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            let reg: usize = decode_hex(&bytes).ok()?;
            Some(qRegisterInfo { reg })
        }
    }
}
