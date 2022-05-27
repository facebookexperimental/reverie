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
pub struct Z {
    pub ty: BreakpointType,
    pub addr: u64,
    pub kind: u8,
    // NB: conditional bkpt here?
}
impl ParseCommand for Z {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        let mut iter = bytes.split_mut(|c| *c == b',');
        let ty = iter
            .next()
            .and_then(|s| decode_hex(s).ok())
            .and_then(BreakpointType::new)?;
        let addr = iter.next().and_then(|s| decode_hex(s).ok())?;
        let kind = iter.next().and_then(|s| decode_hex(s).ok())?;

        Some(Z { ty, addr, kind })
    }
}
