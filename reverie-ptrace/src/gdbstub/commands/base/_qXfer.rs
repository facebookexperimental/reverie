/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

#[derive(PartialEq, Debug)]
pub enum qXfer {
    FeaturesRead { offset: usize, len: usize },
    AuxvRead { offset: usize, len: usize },
}

impl ParseCommand for qXfer {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if bytes.starts_with(b":features:read:") {
            let mut iter =
                bytes[b":features:read:".len()..].split_mut(|c| *c == b':' || *c == b',');
            let annex = iter.next()?;
            if annex != b"target.xml" {
                return None;
            }
            let offset = iter.next()?;
            let len = iter.next()?;
            Some(qXfer::FeaturesRead {
                offset: decode_hex(offset).ok()?,
                len: decode_hex(len).ok()?,
            })
        } else if bytes.starts_with(b":auxv:read:") {
            let mut iter = bytes[b":auxv:read:".len()..].split_mut(|c| *c == b':' || *c == b',');
            let annex = iter.next()?;
            if annex != b"" {
                return None;
            }
            let offset = iter.next()?;
            let len = iter.next()?;
            Some(qXfer::AuxvRead {
                offset: decode_hex(offset).ok()?,
                len: decode_hex(len).ok()?,
            })
        } else {
            None
        }
    }
}
