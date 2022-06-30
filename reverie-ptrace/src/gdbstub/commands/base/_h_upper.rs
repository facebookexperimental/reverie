/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;
use bytes::BytesMut;

#[derive(PartialEq, Debug)]
pub struct H {
    pub op: ThreadOp,
    pub id: ThreadId,
}

impl ParseCommand for H {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            let (ch, bytes) = bytes.split_first_mut()?;
            let op = match *ch {
                b'c' => Some(ThreadOp::c),
                b'g' => Some(ThreadOp::g),
                b'G' => Some(ThreadOp::G),
                b'm' => Some(ThreadOp::m),
                b'M' => Some(ThreadOp::M),
                _ => None,
            }?;
            if bytes == &b"-1"[..] {
                Some(H {
                    op,
                    id: ThreadId::all(),
                })
            } else if bytes == &b"0"[..] {
                Some(H {
                    op,
                    id: ThreadId::any(),
                })
            } else {
                let thread_id = ThreadId::decode(bytes)?;
                Some(H { op, id: thread_id })
            }
        }
    }
}
