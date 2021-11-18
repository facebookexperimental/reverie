/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use bytes::{BufMut, Bytes, BytesMut};
use num_traits::{AsPrimitive, PrimInt};

use reverie::Errno;

use super::{Error, PacketLogger};
use crate::trace::Error as TraceError;

/// Trait to write gdb reply. This is different than `Fmt` for `Display`,
/// As the response must be a valid gdb packet reply, which does not
/// necessarily translate to either.
pub trait WriteResponse {
    /// Write the value into `f` incrementally. The value got written
    /// to `f` must be valid gdb reply packets.
    fn write_response(&self, f: &mut ResponseWriter);
}

/// Doesn't send resposne
pub struct ResponseNone;

/// Send "OK" as response
pub struct ResponseOk;

/// Response with serialized `T` as plain data
pub struct ResponseAsPlain<T>(pub T);
/// Response with serialized `T` as GDB hex
pub struct ResponseAsHex<T>(pub T);
/// Response with serialized `T` as GDB binary
pub struct ResponseAsBinary<T>(pub T);

impl WriteResponse for ResponseNone {
    fn write_response(&self, _f: &mut ResponseWriter) {}
}

impl WriteResponse for ResponseOk {
    fn write_response(&self, f: &mut ResponseWriter) {
        f.put_str("OK")
    }
}

impl WriteResponse for ! {
    fn write_response(&self, f: &mut ResponseWriter) {
        ResponseNone.write_response(f)
    }
}

impl<T> WriteResponse for ResponseAsPlain<T>
where
    T: AsRef<[u8]>,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        f.put_slice(self.0.as_ref())
    }
}

impl<T> WriteResponse for ResponseAsHex<T>
where
    T: AsRef<[u8]>,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        f.put_hex_encoded(self.0.as_ref())
    }
}

impl<T> WriteResponse for ResponseAsBinary<T>
where
    T: AsRef<[u8]>,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        f.put_binary_encoded(self.0.as_ref())
    }
}

impl<T> WriteResponse for Result<T, Errno>
where
    T: WriteResponse,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        match self {
            Ok(resp) => {
                resp.write_response(f);
            }
            Err(errno) => {
                f.put_str("E");
                f.put_num(errno.into_raw());
            }
        }
    }
}

impl<T> WriteResponse for Result<T, TraceError>
where
    T: WriteResponse,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        match self {
            Ok(resp) => {
                resp.write_response(f);
            }
            Err(err) => match err {
                TraceError::Errno(errno) => {
                    f.put_str("E");
                    f.put_num(errno.into_raw());
                }
                TraceError::Died(_) => f.put_str("E03"),
            },
        }
    }
}

impl<T> WriteResponse for Result<T, Error>
where
    T: WriteResponse,
{
    fn write_response(&self, f: &mut ResponseWriter) {
        match self {
            Ok(resp) => {
                resp.write_response(f);
            }
            Err(err) => match err {
                Error::TraceError(TraceError::Errno(errno)) => {
                    f.put_str("E");
                    f.put_num(errno.into_raw());
                }
                _ => f.put_str("E22"),
            },
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
/// Response writer to be sent to remote client
pub struct ResponseWriter {
    started: bool,
    checksum: u8,
    buf: BytesMut,
}

impl ResponseWriter {
    /// Creates a new ResponseWriter
    pub fn new(mut tx_buf: BytesMut, no_ack_mode: bool) -> Self {
        let mut buf = tx_buf.split();
        if !no_ack_mode {
            buf.put_u8(b'+');
        }
        Self {
            started: false,
            checksum: 0,
            buf,
        }
    }

    fn put_u8(&mut self, byte: u8) {
        if !self.started {
            self.started = true;
            self.buf.put_u8(b'$');
        }

        self.checksum = self.checksum.wrapping_add(byte);
        self.buf.put_u8(byte);
    }

    /// encode u8 as gdb hex
    fn put_u8_hex(&mut self, byte: u8) {
        for digit in [(byte & 0xf0) >> 4, byte & 0x0f] {
            let c = match digit {
                0..=9 => b'0' + digit,
                10..=15 => b'a' + digit - 10,
                _ => unreachable!(),
            };
            self.put_u8(c);
        }
    }

    /// Write a slice over the connection.
    pub fn put_slice(&mut self, s: &[u8]) {
        s.iter().for_each(|c| self.put_u8(*c))
    }

    /// Write an entire string over the connection.
    pub fn put_str(&mut self, s: &str) {
        self.put_slice(s.as_bytes())
    }

    /// Write data as (gdb) hex string.
    pub fn put_hex_encoded(&mut self, data: &[u8]) {
        data.iter().for_each(|c| self.put_u8_hex(*c));
    }

    /// Write data using the binary protocol.
    pub fn put_binary_encoded(&mut self, data: &[u8]) {
        for &b in data.iter() {
            match b {
                b'#' | b'$' | b'}' | b'*' => {
                    self.put_u8(b'}');
                    self.put_u8(b ^ 0x20)
                }
                _ => self.put_u8(b),
            }
        }
    }

    /// Write a number as a big-endian hex string using the most compact
    /// representation possible (i.e: trimming leading zeros).
    pub fn put_num<I: AsPrimitive<u64> + PrimInt>(&mut self, digit: I) {
        if digit.is_zero() {
            return self.put_u8_hex(0);
        }

        let mut buf = [0; 16];
        let mut k = 15;
        let mut x = digit;

        while !x.is_zero() {
            buf[k] = (x.as_() & 0xffu64) as u8;
            k -= 1;
            x = x.unsigned_shr(8);
        }

        self.put_hex_encoded(&buf[1 + k..]);
    }

    /// Consumes self, writing out buffer and the final '#' and checksum
    pub fn finish(mut self) -> Bytes {
        // don't include the '#' in checksum calculation
        let checksum = self.checksum;

        // empty response
        if !self.started {
            self.started = true;
            self.buf.put_u8(b'$');
        }

        tracing::trace!("{:?}", PacketLogger::outgoing(&self.buf, checksum));

        self.buf.put_u8(b'#');
        self.put_u8_hex(checksum);
        self.buf.freeze()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn response_plain_string() {
        let mut left = ResponseWriter::new(BytesMut::new(), true);
        let mut right = ResponseWriter::new(BytesMut::new(), true);
        left.put_str("just a test");
        ResponseAsPlain("just a test").write_response(&mut right);
        assert_eq!(left, right);
    }
}
