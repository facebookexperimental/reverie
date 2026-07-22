/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;

/// LLDB `qProcessInfo` query. Requests information about the process currently
/// being debugged (pid, architecture triple, pointer size, endianness, ...).
#[derive(PartialEq, Debug)]
pub struct qProcessInfo;

impl ParseCommand for qProcessInfo {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            Some(qProcessInfo)
        } else {
            None
        }
    }
}
