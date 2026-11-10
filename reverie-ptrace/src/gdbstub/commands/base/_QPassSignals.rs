/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::BytesMut;

use crate::gdbstub::commands::*;
use crate::gdbstub::hex::*;

/// `QPassSignals:signal[;signal]...`: the signals, by gdb's numbers, that the
/// stub passes to the guest without reporting a stop. Each packet replaces
/// the previous list; an empty one passes nothing.
#[derive(PartialEq, Debug)]
pub struct QPassSignals {
    pub signals: Vec<u8>,
}

impl ParseCommand for QPassSignals {
    fn parse(bytes: BytesMut) -> Option<Self> {
        let list = bytes.strip_prefix(b":")?;
        let signals = list
            .split(|c| *c == b';')
            .filter(|signal| !signal.is_empty())
            .map(|signal| decode_hex::<u8>(signal).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(QPassSignals { signals })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gdbs_list() {
        assert_eq!(
            QPassSignals::parse(BytesMut::from(&b":e;14;1c;2e"[..])),
            Some(QPassSignals {
                signals: vec![0xe, 0x14, 0x1c, 0x2e]
            })
        );
        assert_eq!(
            QPassSignals::parse(BytesMut::from(&b":"[..])),
            Some(QPassSignals { signals: vec![] }),
            "an empty list passes nothing"
        );
        assert_eq!(QPassSignals::parse(BytesMut::from(&b":zz"[..])), None);
    }
}
