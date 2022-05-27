/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::{commands::*, hex::*};

#[derive(PartialEq, Debug)]
pub struct m {
    pub addr: u64,
    pub length: usize,
}

impl ParseCommand for m {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            let mut iter = bytes.split_mut(|c| *c == b',');
            let addr = iter.next().and_then(|x| decode_hex(x).ok())?;
            let length = iter.next().and_then(|x| decode_hex(x).ok())?;
            Some(m { addr, length })
        }
    }
}
