/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::{commands::*, hex::*};

#[derive(PartialEq, Debug)]
pub struct M {
    pub addr: u64,
    pub length: usize,
    pub vals: Vec<u8>,
}

impl ParseCommand for M {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        let mut iter = bytes.split_mut(|c| *c == b',' || *c == b':');
        let addr = iter.next()?;
        let len = iter.next()?;
        let j = 2 + addr.len() + len.len();
        let addr = decode_hex(addr).ok()?;
        let len = decode_hex(len).ok()?;
        let vals = bytes.split_off(j);
        Some(M {
            addr,
            length: len,
            vals: decode_hex_string(&vals).ok()?,
        })
    }
}
