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
pub struct X {
    pub addr: u64,
    pub length: usize,
    pub vals: Vec<u8>,
}

impl ParseCommand for X {
    fn parse(mut bytes: BytesMut) -> Option<Self> {
        let mut first_colon = None;
        let mut index = 0;
        for &b in &bytes {
            if b == b':' {
                first_colon = Some(index);
                break;
            } else {
                index += 1;
            }
        }

        let (addr_len, vals) = bytes.split_at_mut(first_colon?);
        let mut iter = addr_len.split_mut(|c| *c == b',');
        let addr = iter.next().and_then(|s| decode_hex(s).ok())?;
        let len = iter.next().and_then(|s| decode_hex(s).ok())?;
        Some(X {
            addr,
            length: len,
            vals: decode_binary_string(&vals[1..]).ok()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_parse_X_special() {
        // Sending packet: $X216eb0,4:,\000\000\000#ae...Packet received: OK
        assert_eq!(
            X::parse(BytesMut::from("216eb0,4:,\0\0\0")),
            Some(X {
                addr: 0x216eb0,
                length: 4,
                vals: vec![0x2c, 0x0, 0x0, 0x0],
            })
        );

        // Sending packet: $X216eb0,4::\000\000\000#bc...Packet received: OK
        assert_eq!(
            X::parse(BytesMut::from("216eb0,4::\0\0\0")),
            Some(X {
                addr: 0x216eb0,
                length: 4,
                vals: vec![0x3a, 0x0, 0x0, 0x0],
            })
        );
    }
}
