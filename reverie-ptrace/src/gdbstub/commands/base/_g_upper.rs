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
    /// Optional thread selected by an LLDB `;thread:<id>;` suffix.
    pub thread: Option<ThreadId>,
}

impl ParseCommand for G {
    fn parse(bytes: BytesMut) -> Option<Self> {
        let (rest, thread) = split_thread_suffix(bytes);
        if rest.is_empty() {
            None
        } else {
            let vals = decode_hex_string(&rest).ok()?;
            Some(G { vals, thread })
        }
    }
}
