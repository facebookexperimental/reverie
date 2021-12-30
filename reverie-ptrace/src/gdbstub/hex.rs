/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::{Bytes, BytesMut};
use num_traits::{CheckedAdd, CheckedMul, FromPrimitive, Zero};
use serde::{
    de::{self, Visitor},
    ser::{self, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;

/// Decode gdb hex error code
#[derive(Debug, Error, PartialEq)]
pub enum GdbHexError {
    /// Invalid hex digit
    #[error("Input contains non-ASCII chars")]
    NotAscii,
    /// Input is empty
    #[error("Input is empty")]
    Empty,
    /// Output is too small: overflowed
    #[error("Output is too small/overflowed")]
    Overflow,
    /// Invalid Hex input
    #[error("Gdb hex is malformed")]
    InvalidGdbHex,
    /// Invalid binary inpput
    #[error("Gdb binary is malformed")]
    InvalidGdbBinary,
    /// Invalid Output (num) type.
    #[error("Invalid output num type")]
    InvalidOutput,
}

#[derive(PartialEq, Debug)]
pub struct GdbHexString {
    bytes: Bytes,
}

impl From<Bytes> for GdbHexString {
    fn from(bytes: Bytes) -> Self {
        GdbHexString { bytes }
    }
}

impl From<BytesMut> for GdbHexString {
    fn from(bytes: BytesMut) -> Self {
        GdbHexString {
            bytes: bytes.freeze(),
        }
    }
}

impl GdbHexString {
    /// decode gdb hex encoded binary data into a slice.
    #[cfg(test)]
    pub fn decode(&self) -> Result<Vec<u8>, GdbHexError> {
        let serialized: Vec<u8> =
            bincode::serialize(self).map_err(|_| GdbHexError::InvalidGdbHex)?;
        bincode::deserialize(&serialized).map_err(|_| GdbHexError::InvalidGdbHex)
    }

    /// encode slice into gdb hex encoded data
    #[cfg(test)]
    pub fn encode(bytes: &[u8]) -> Result<Self, GdbHexError> {
        let serialized: Vec<u8> =
            bincode::serialize(bytes).map_err(|_| GdbHexError::InvalidGdbHex)?;
        bincode::deserialize(&serialized).map_err(|_| GdbHexError::InvalidGdbHex)
    }
}

impl Serialize for GdbHexString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.bytes.is_empty() || self.bytes.len() % 2 != 0 {
            return Err(ser::Error::custom(GdbHexError::InvalidGdbHex));
        }
        let mut seq = serializer.serialize_seq(Some(self.bytes.len() / 2))?;
        let mut j = 0;
        while j < self.bytes.len() {
            let val: u8 = from_hex(self.bytes[j])
                .ok_or_else(|| ser::Error::custom(GdbHexError::NotAscii))?
                * 16
                + from_hex(self.bytes[j + 1])
                    .ok_or_else(|| ser::Error::custom(GdbHexError::NotAscii))?;
            seq.serialize_element(&val)?;
            j += 2;
        }
        seq.end()
    }
}

struct HexStringVisitor;
impl<'de> Visitor<'de> for HexStringVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a &[u8] slice")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut res: Vec<u8> = Vec::new();

        for ch in v {
            let hi = to_hex(*ch >> 4).unwrap();
            let lo = to_hex(*ch & 0xf).unwrap();
            res.push(hi);
            res.push(lo);
        }
        Ok(res)
    }
}

impl<'de> Deserialize<'de> for GdbHexString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(HexStringVisitor)?;
        Ok(GdbHexString {
            bytes: Bytes::from(bytes),
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct GdbBinaryString {
    bytes: Bytes,
}

impl From<Bytes> for GdbBinaryString {
    fn from(bytes: Bytes) -> Self {
        GdbBinaryString { bytes }
    }
}

impl From<BytesMut> for GdbBinaryString {
    fn from(bytes: BytesMut) -> Self {
        GdbBinaryString {
            bytes: bytes.freeze(),
        }
    }
}

impl GdbBinaryString {
    /// decode gdb binary encoded binary data into a slice.
    #[cfg(test)]
    pub fn decode(&self) -> Result<Vec<u8>, GdbHexError> {
        let serialized: Vec<u8> =
            bincode::serialize(self).map_err(|_| GdbHexError::InvalidGdbHex)?;
        bincode::deserialize(&serialized).map_err(|_| GdbHexError::InvalidGdbHex)
    }

    /// encode slice into gdb binary encoded data
    #[cfg(test)]
    pub fn encode(bytes: &[u8]) -> Result<Self, GdbHexError> {
        let serialized: Vec<u8> =
            bincode::serialize(bytes).map_err(|_| GdbHexError::InvalidGdbHex)?;
        bincode::deserialize(&serialized).map_err(|_| GdbHexError::InvalidGdbHex)
    }
}

impl Serialize for GdbBinaryString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut res: Vec<u8> = Vec::new();
        let mut j = 0;
        while j < self.bytes.len() {
            let ch = self.bytes[j];
            match ch {
                b'}' => {
                    if j == self.bytes.len() - 1 {
                        return Err(ser::Error::custom(GdbHexError::InvalidGdbBinary));
                    }
                    res.push(self.bytes[1 + j] ^ 0x20);
                    j += 2;
                }
                _ => {
                    res.push(ch);
                    j += 1;
                }
            }
        }
        serializer.serialize_bytes(&res)
    }
}

struct BinaryStringisitor;
impl<'de> Visitor<'de> for BinaryStringisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a &[u8] slice")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let mut res: Vec<u8> = Vec::new();

        for &ch in v {
            match ch {
                b'#' | b'$' | b'}' | b'*' => {
                    res.push(b'}');
                    res.push(ch ^ 0x20)
                }
                _ => res.push(ch),
            }
        }
        Ok(res)
    }
}

impl<'de> Deserialize<'de> for GdbBinaryString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(BinaryStringisitor)?;
        Ok(GdbBinaryString {
            bytes: Bytes::from(bytes),
        })
    }
}

fn from_hex(c: u8) -> Option<u8> {
    if b"0123456789".contains(&c) {
        Some(c - b'0')
    } else if b"abcdef".contains(&c) {
        Some(c - b'a' + 10)
    } else if b"ABCDEF".contains(&c) {
        Some(c - b'A' + 10)
    } else if b"xX".contains(&c) {
        Some(0)
    } else {
        None
    }
}

fn to_hex(c: u8) -> Option<u8> {
    if c > 15 {
        None
    } else if c < 10 {
        Some(c + b'0')
    } else {
        Some(c + b'A')
    }
}

/// Decode a GDB dex string into the specified integer.
///
/// GDB hex strings may include "xx", which represent "missing" data. This
/// method simply treats "xx" as 00.
pub fn decode_hex<I>(buf: &[u8]) -> Result<I, GdbHexError>
where
    I: FromPrimitive + Zero + CheckedAdd + CheckedMul,
{
    if buf.is_empty() {
        return Err(GdbHexError::Empty);
    }

    let radix = I::from_u8(16).ok_or(GdbHexError::InvalidOutput)?;
    let mut result = I::zero();

    for &digit in buf {
        let x = I::from_u8(from_hex(digit).ok_or(GdbHexError::NotAscii)?)
            .ok_or(GdbHexError::InvalidOutput)?;
        result = result.checked_mul(&radix).ok_or(GdbHexError::Overflow)?;
        result = result.checked_add(&x).ok_or(GdbHexError::Overflow)?
    }

    Ok(result)
}

/// Decode a GDB hex string into a u8 Vector.
///
/// GDB hex strings may include "xx", which represent "missing" data. This
/// method simply treats "xx" as 00.
pub fn decode_hex_string(buf: &[u8]) -> Result<Vec<u8>, GdbHexError> {
    let mut res = Vec::new();
    let mut i = 0;

    if buf.len() % 2 != 0 {
        return Err(GdbHexError::InvalidGdbHex);
    }

    while i < buf.len() - 1 {
        let x = from_hex(buf[i]).ok_or(GdbHexError::NotAscii)?;
        let x = 16 * x + from_hex(buf[i + 1]).ok_or(GdbHexError::NotAscii)?;
        res.push(x);
        i += 2;
    }

    Ok(res)
}

/// Decode a GDB binary string into a u8 Vector.
///
/// GDB hex strings may include "xx", which represent "missing" data. This
/// method simply treats "xx" as 00.
pub fn decode_binary_string(buf: &[u8]) -> Result<Vec<u8>, GdbHexError> {
    let mut res = Vec::new();
    let mut i = 0;

    while i < buf.len() {
        match buf[i] {
            b'}' => {
                if i >= buf.len() - 1 {
                    return Err(GdbHexError::InvalidGdbBinary);
                }
                res.push(buf[i + 1] ^ 0x20);
                i += 2;
            }
            _ => {
                res.push(buf[i]);
                i += 1;
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serde_sanity() {
        let test1 = Bytes::from(&[4, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4][..]);
        let test2 = GdbHexString {
            bytes: Bytes::from("01020304"),
        };
        let bytes: Vec<u8> = bincode::serialize(&test2).unwrap();
        assert_eq!(bytes, test1);
        let encoded: GdbHexString = bincode::deserialize(&bytes).unwrap();
        assert_eq!(encoded, test2);

        let bytes: Vec<u8> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn encode_decode_sanity() {
        let test1 = vec![1, 2, 3, 4];
        let hex = GdbHexString {
            bytes: Bytes::from("01020304"),
        };
        let test2 = vec![b'1', b'2', b'$', b'{'];
        let bin = GdbBinaryString {
            bytes: Bytes::from(&b"12}\x04{"[..]),
        };
        assert_eq!(GdbHexString::encode(&test1).unwrap(), hex);
        assert_eq!(GdbHexString::decode(&hex).unwrap(), test1);

        assert_eq!(GdbBinaryString::encode(&test2).unwrap(), bin);
        assert_eq!(GdbBinaryString::decode(&bin).unwrap(), test2);
    }

    #[test]
    fn decode_gdb_hex_test() {
        assert_eq!(
            decode_hex_string(b"31323334"),
            Ok::<_, GdbHexError>(b"1234".to_vec())
        );
        assert_eq!(
            decode_hex_string(b"12345"),
            Err::<Vec<u8>, _>(GdbHexError::InvalidGdbHex)
        );
    }

    #[test]
    fn decode_gdb_binary_test() {
        assert_eq!(
            decode_binary_string(b"12345"),
            Ok::<_, GdbHexError>(b"12345".to_vec())
        );
        assert_eq!(
            decode_binary_string(b"1234}"),
            Err::<Vec<u8>, _>(GdbHexError::InvalidGdbBinary)
        );
        assert_eq!(
            decode_binary_string(b"1234}A"),
            Ok::<_, GdbHexError>(b"1234a".to_vec())
        );
    }
}
