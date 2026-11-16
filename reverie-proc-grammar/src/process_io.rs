/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/io`: seven `label: count` lines printed by
//! `proc_tid_io_accounting` (`fs/proc/base.c`), in a fixed order.

use alloc::format;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// The seven I/O accounting counters, in kernel order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIo {
    /// Bytes read via read-like syscalls (including from cache).
    pub rchar: u64,
    /// Bytes written via write-like syscalls.
    pub wchar: u64,
    /// Read-like syscalls issued.
    pub syscr: u64,
    /// Write-like syscalls issued.
    pub syscw: u64,
    /// Bytes this task caused to be read from storage.
    pub read_bytes: u64,
    /// Bytes this task caused to be written to storage.
    pub write_bytes: u64,
    /// Bytes whose writeback this task cancelled by truncating.
    pub cancelled_write_bytes: u64,
}

const LABELS: [&[u8]; 7] = [
    b"rchar",
    b"wchar",
    b"syscr",
    b"syscw",
    b"read_bytes",
    b"write_bytes",
    b"cancelled_write_bytes",
];

const FIELD_NAMES: [&str; 7] = [
    "rchar",
    "wchar",
    "syscr",
    "syscw",
    "read_bytes",
    "write_bytes",
    "cancelled_write_bytes",
];

/// Parse one `io` file's bytes. The kernel prints the seven lines in
/// fixed order; any other label, order, or count is refused.
pub fn parse_process_io(input: &[u8]) -> Result<ProcessIo, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::ProcessIo,
        });
    }
    let body = strip_final_newline(input, Format::ProcessIo)?;
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    if lines.len() != LABELS.len() {
        return Err(ProcParseError::WrongFieldCount {
            format: Format::ProcessIo,
            expected: LABELS.len(),
            found: lines.len(),
        });
    }
    let mut values = [0u64; 7];
    for (i, line) in lines.iter().enumerate() {
        let colon = line.iter().position(|b| *b == b':');
        let (label, value) = match colon {
            Some(at) => (&line[..at], &line[at + 1..]),
            None => {
                return Err(ProcParseError::BadShape {
                    format: Format::ProcessIo,
                    span: span_of(input, line),
                });
            }
        };
        if label != LABELS[i] {
            return Err(ProcParseError::UnknownLabel {
                format: Format::ProcessIo,
                span: span_of(input, label),
            });
        }
        let value = value.strip_prefix(b" ").ok_or(ProcParseError::BadShape {
            format: Format::ProcessIo,
            span: span_of(input, line),
        })?;
        values[i] = num::parse_u64(value, FIELD_NAMES[i], span_of(input, value))?;
    }
    let io = ProcessIo {
        rchar: values[0],
        wchar: values[1],
        syscr: values[2],
        syscw: values[3],
        read_bytes: values[4],
        write_bytes: values[5],
        cancelled_write_bytes: values[6],
    };
    ensure_canonical(input, &render_process_io(&io), Format::ProcessIo)?;
    Ok(io)
}

/// Render a [`ProcessIo`] in the kernel's byte shape.
pub fn render_process_io(io: &ProcessIo) -> Vec<u8> {
    format!(
        "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: {}\nwrite_bytes: {}\ncancelled_write_bytes: {}\n",
        io.rchar,
        io.wchar,
        io.syscr,
        io.syscw,
        io.read_bytes,
        io.write_bytes,
        io.cancelled_write_bytes
    )
    .into_bytes()
}
