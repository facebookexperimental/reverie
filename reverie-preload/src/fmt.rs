/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Async-signal-safe line formatting.
//!
//! The SIGSYS handler runs in async-signal context, where `write!`, `format!`,
//! and the allocator are all unsafe. [`StackLine`] is a fixed-capacity,
//! allocation-free buffer that a dispatcher may use to build a diagnostic line
//! and hand its bytes to a raw `write(2)`.

/// A fixed-capacity line buffer safe to build inside a signal handler.
pub struct StackLine {
    bytes: [u8; Self::CAPACITY],
    len: usize,
}

impl Default for StackLine {
    fn default() -> Self {
        Self::new()
    }
}

impl StackLine {
    const CAPACITY: usize = 192;

    /// A new empty line.
    pub const fn new() -> Self {
        Self {
            bytes: [0; Self::CAPACITY],
            len: 0,
        }
    }

    /// The bytes accumulated so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Append raw bytes, silently truncating at capacity (never panics, never
    /// allocates).
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let available = self.bytes.len().saturating_sub(self.len);
        let count = available.min(bytes.len());
        self.bytes[self.len..self.len + count].copy_from_slice(&bytes[..count]);
        self.len += count;
    }

    /// Append a base-10 signed integer.
    pub fn push_signed(&mut self, value: i64) {
        if value < 0 {
            self.push_bytes(b"-");
        }
        self.push_unsigned(value.unsigned_abs());
    }

    /// Append a base-10 unsigned integer.
    pub fn push_unsigned(&mut self, mut value: u64) {
        let mut digits = [0_u8; 20];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }

    /// Append a lowercase base-16 integer (no `0x` prefix).
    pub fn push_hex(&mut self, mut value: u64) {
        let mut digits = [0_u8; 16];
        let mut cursor = digits.len();
        loop {
            cursor -= 1;
            let digit = (value & 0xf) as u8;
            digits[cursor] = if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            };
            value >>= 4;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(&digits[cursor..]);
    }
}

#[cfg(test)]
mod tests {
    use super::StackLine;

    #[test]
    fn formats_signed_and_hex_values() {
        let mut line = StackLine::new();
        line.push_signed(-123);
        line.push_bytes(b" ");
        line.push_hex(0xdead_beef);
        assert_eq!(line.as_bytes(), b"-123 deadbeef");
    }

    #[test]
    fn truncates_at_capacity_without_panicking() {
        let mut line = StackLine::new();
        for _ in 0..100 {
            line.push_bytes(b"0123456789");
        }
        assert_eq!(line.as_bytes().len(), StackLine::CAPACITY);
    }
}
