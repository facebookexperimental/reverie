/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::{
    commands::{Command, CommandParseError},
    hex::*,
    PacketLogger,
};
use bytes::BytesMut;
use thiserror::Error;

/// Packet parse error.
#[derive(PartialEq, Debug, Error)]
pub enum PacketParseError {
    #[error("Checksum mismatch, expected: {checksum}, got: {calculated}")]
    ChecksumMismatched { checksum: u8, calculated: u8 },
    #[error("empty packet buffer")]
    EmptyBuf,
    #[error("missing checksum")]
    MissingChecksum,
    #[error("mulformed checksum")]
    MalformedChecksum,
    #[error(transparent)]
    CommandError(CommandParseError),
    #[error("unexpected header {0}")]
    UnexpectedHeader(u8),
    #[error(transparent)]
    DecodeHexError(GdbHexError),
}

impl From<GdbHexError> for PacketParseError {
    fn from(err: GdbHexError) -> Self {
        PacketParseError::DecodeHexError(err)
    }
}

/// Packet send/recv from gdb stream.
#[derive(Debug)]
pub enum Packet {
    Ack,
    Nack,
    Interrupt,
    Command(Command),
}

// Remove leading `$' and trailing `#[xx]`, and validate checksum.
fn decode_packet(mut bytes: BytesMut) -> Result<BytesMut, PacketParseError> {
    let end_of_body = bytes
        .iter()
        .position(|b| *b == b'#')
        .ok_or(PacketParseError::MissingChecksum)?;

    // Split buffer into body and checksum, note the packet
    // starts with a `$'.
    let (body, checksum) = bytes.split_at_mut(end_of_body);
    let checksum = &checksum[1..][..2]; // skip the '#'

    // Validate checksum without leading `$'.
    let checksum = decode_hex(checksum).map_err(|_| PacketParseError::MalformedChecksum)?;
    let calculated = body.iter().skip(1).fold(0u8, |a, x| a.wrapping_add(*x));
    if calculated != checksum {
        return Err(PacketParseError::ChecksumMismatched {
            checksum,
            calculated,
        });
    }

    tracing::trace!("{:?}", PacketLogger::incoming(body, checksum));

    Ok(bytes.split_to(end_of_body).split_off(1))
}

impl TryFrom<BytesMut> for Packet {
    type Error = PacketParseError;
    fn try_from(buf: BytesMut) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(PacketParseError::EmptyBuf);
        }
        let prefix = buf[0];
        match prefix {
            b'$' => {
                let body = decode_packet(buf)?;
                Ok(Packet::Command(Command::try_parse(body)?))
            }
            b'+' => Ok(Packet::Ack),
            b'-' => Ok(Packet::Nack),
            0x03 => Ok(Packet::Interrupt),
            _ => Err(PacketParseError::UnexpectedHeader(buf[0])),
        }
    }
}

impl Packet {
    /// Create a new `Packet` from `buf`.
    pub fn new(buf: BytesMut) -> Result<Self, PacketParseError> {
        Self::try_from(buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_decode_packet() {
        let cmd = BytesMut::from("$qC#b4");
        assert_eq!(
            decode_packet(cmd),
            Ok::<_, PacketParseError>(BytesMut::from("qC"))
        );

        assert_eq!(
            // Contains non-ascii bytes
            decode_packet(BytesMut::from(&b"$X7fffffffdbac,4:\x8a\x02\0\0#09"[..])),
            Ok::<_, PacketParseError>(BytesMut::from(&b"X7fffffffdbac,4:\x8a\x02\0\0"[..]))
        );

        let cmd = BytesMut::from("$QPassSignals:e;10;14;17;1a;1b;1c;21;24;25;2c;4c;97;#0a");
        assert_eq!(
            decode_packet(cmd),
            Ok::<_, PacketParseError>(BytesMut::from(
                "QPassSignals:e;10;14;17;1a;1b;1c;21;24;25;2c;4c;97;"
            ))
        );
    }
}
