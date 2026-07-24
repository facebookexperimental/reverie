/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;

/// LLDB `qHostInfo` query. Requests information about the host the gdbserver is
/// running on (architecture triple, pointer size, endianness, ...).
#[derive(PartialEq, Debug)]
pub struct qHostInfo;

impl ParseCommand for qHostInfo {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            Some(qHostInfo)
        } else {
            None
        }
    }
}
