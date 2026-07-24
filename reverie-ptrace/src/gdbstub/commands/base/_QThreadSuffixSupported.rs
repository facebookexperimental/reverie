/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;

/// LLDB `QThreadSuffixSupported` query. If the stub supports a `;thread:<id>;`
/// suffix on register-access packets (`g`/`G`/`p`/`P`), it replies `OK` and
/// LLDB will subsequently append that suffix to those packets.
#[derive(PartialEq, Debug)]
pub struct QThreadSuffixSupported;

impl ParseCommand for QThreadSuffixSupported {
    fn parse(bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            Some(QThreadSuffixSupported)
        } else {
            None
        }
    }
}
