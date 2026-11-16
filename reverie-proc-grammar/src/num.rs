/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Strict byte-to-number parsers shared by the format modules.
//!
//! The kernel prints numbers with fixed `seq_printf` conversions and
//! no `+`, no grouping, and no surrounding space inside a field, so
//! these accept exactly the canonical spellings those conversions
//! emit: no leading zeros (a lone `0` excepted), no `-0`, lowercase
//! hex only, range-checked into the target type. Anything else is a
//! spelling the kernel never prints and is refused, never quietly
//! rewritten to canonical form.

use crate::error::ProcParseError;

fn bad(field: &'static str, span: (usize, usize)) -> ProcParseError {
    ProcParseError::BadNumber { field, span }
}

fn digits_value(
    token: &[u8],
    radix: u128,
    field: &'static str,
    span: (usize, usize),
) -> Result<u128, ProcParseError> {
    if token.is_empty() {
        return Err(bad(field, span));
    }
    let mut value: u128 = 0;
    for byte in token {
        let digit = match byte {
            b'0'..=b'9' => u128::from(byte - b'0'),
            // Kernel hex conversions print lowercase only.
            b'a'..=b'f' if radix == 16 => u128::from(byte - b'a' + 10),
            _ => return Err(bad(field, span)),
        };
        if digit >= radix {
            return Err(bad(field, span));
        }
        value = value
            .checked_mul(radix)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| bad(field, span))?;
    }
    Ok(value)
}

fn decimal_u128(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u128, ProcParseError> {
    if token.first() == Some(&b'-') || token.first() == Some(&b'+') {
        return Err(bad(field, span));
    }
    // Canonical decimal: no leading zeros beyond a lone zero.
    if token.len() > 1 && token[0] == b'0' {
        return Err(bad(field, span));
    }
    digits_value(token, 10, field, span)
}

fn decimal_i128(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<i128, ProcParseError> {
    match token.first() {
        Some(b'-') => {
            // `-0` is not a spelling the kernel prints.
            if token[1..] == *b"0" {
                return Err(bad(field, span));
            }
            let magnitude = decimal_u128(&token[1..], field, span)?;
            i128::try_from(magnitude)
                .ok()
                .and_then(|v| v.checked_neg())
                .ok_or_else(|| bad(field, span))
        }
        Some(b'+') => Err(bad(field, span)),
        _ => decimal_u128(token, field, span)
            .and_then(|v| i128::try_from(v).map_err(|_| bad(field, span))),
    }
}

/// A decimal `u64`, as `%llu`/`%lu` print it.
pub fn parse_u64(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u64, ProcParseError> {
    decimal_u128(token, field, span).and_then(|v| u64::try_from(v).map_err(|_| bad(field, span)))
}

/// A decimal `u32`, as `%u` prints it.
pub fn parse_u32(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u32, ProcParseError> {
    decimal_u128(token, field, span).and_then(|v| u32::try_from(v).map_err(|_| bad(field, span)))
}

/// A decimal `i64`, as `%lld`/`%ld` print it.
pub fn parse_i64(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<i64, ProcParseError> {
    decimal_i128(token, field, span).and_then(|v| i64::try_from(v).map_err(|_| bad(field, span)))
}

/// A decimal `i32`, as `%d` prints it.
pub fn parse_i32(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<i32, ProcParseError> {
    decimal_i128(token, field, span).and_then(|v| i32::try_from(v).map_err(|_| bad(field, span)))
}

/// Exactly `digits` decimal digits as a `u64`, leading zeros
/// included — the fractional part of a `%06ld`-style conversion,
/// where zero-padding is the canonical spelling.
pub fn parse_fixed_digits_u64(
    token: &[u8],
    digits: usize,
    field: &'static str,
    span: (usize, usize),
) -> Result<u64, ProcParseError> {
    if token.len() != digits {
        return Err(bad(field, span));
    }
    digits_value(token, 10, field, span)
        .and_then(|v| u64::try_from(v).map_err(|_| bad(field, span)))
}

/// A decimal `i128` (sched counters are checked this wide by the
/// sanitizers that consume them).
pub fn parse_i128(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<i128, ProcParseError> {
    decimal_i128(token, field, span)
}

/// Exactly `digits` lowercase-or-uppercase hex digits as a `u64`
/// (signal and capability masks print 16; mount devices print pairs).
pub fn parse_hex_u64(
    token: &[u8],
    digits: usize,
    field: &'static str,
    span: (usize, usize),
) -> Result<u64, ProcParseError> {
    if token.len() != digits {
        return Err(bad(field, span));
    }
    digits_value(token, 16, field, span)
        .and_then(|v| u64::try_from(v).map_err(|_| bad(field, span)))
}

/// A variable-width lowercase hex `u32`, range-checked instead of
/// truncated: an over-wide token is refused.
pub fn parse_hex_u32(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u32, ProcParseError> {
    if token.is_empty() || token.len() > 8 {
        return Err(bad(field, span));
    }
    digits_value(token, 16, field, span)
        .and_then(|v| u32::try_from(v).map_err(|_| bad(field, span)))
}

/// A `0x`-prefixed lowercase hex `u64`, as `%#lx` prints it
/// (`untag_mask`).
pub fn parse_prefixed_hex_u64(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u64, ProcParseError> {
    let hex = token.strip_prefix(b"0x").ok_or_else(|| bad(field, span))?;
    if hex.is_empty() || hex.len() > 16 || (hex.len() > 1 && hex[0] == b'0') {
        return Err(bad(field, span));
    }
    digits_value(hex, 16, field, span).and_then(|v| u64::try_from(v).map_err(|_| bad(field, span)))
}

/// An octal `u32` with the kernel's literal leading `0`, as fdinfo
/// flags print (`00` for zero, `02`, `0100002`): the leading zero is
/// part of the conversion, never zero-padding, so a second zero is
/// refused unless the value is exactly zero (`00`).
pub fn parse_octal_u32(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u32, ProcParseError> {
    if token.len() < 2 || token[0] != b'0' || (token.len() > 2 && token[1] == b'0') {
        return Err(bad(field, span));
    }
    digits_value(token, 8, field, span).and_then(|v| u32::try_from(v).map_err(|_| bad(field, span)))
}

/// An octal `u32` zero-padded to 4 digits, as `%04o` prints `Umask`.
pub fn parse_octal4_u32(
    token: &[u8],
    field: &'static str,
    span: (usize, usize),
) -> Result<u32, ProcParseError> {
    if token.len() != 4 {
        return Err(bad(field, span));
    }
    digits_value(token, 8, field, span).and_then(|v| u32::try_from(v).map_err(|_| bad(field, span)))
}
