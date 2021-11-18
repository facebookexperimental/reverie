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
pub struct qAttached {
    pub pid: Option<i32>,
}

impl ParseCommand for qAttached {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if !bytes.starts_with(b":") {
            None
        } else {
            let mut iter = bytes.split_mut(|c| *c == b':');
            let _ = iter.next()?;
            Some(qAttached {
                pid: iter.next().and_then(|x| decode_hex(x).ok()),
            })
        }
    }
}
