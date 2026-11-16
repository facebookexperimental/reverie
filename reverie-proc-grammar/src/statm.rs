/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/statm`: seven page counts printed by
//! `proc_pid_statm` (`fs/proc/task_mmu.c`) — total program size,
//! resident, shared, text, library (always 0), data, dirty (always 0).

use alloc::format;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// The seven page counts, in kernel order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statm {
    /// Total program size.
    pub size: u64,
    /// Resident set size.
    pub resident: u64,
    /// Resident shared pages.
    pub shared: u64,
    /// Text (code) pages.
    pub text: u64,
    /// Library pages (always 0).
    pub lib: u64,
    /// Data + stack pages.
    pub data: u64,
    /// Dirty pages (always 0).
    pub dirty: u64,
}

const FIELDS: [&str; 7] = ["size", "resident", "shared", "text", "lib", "data", "dirty"];

/// Parse one `statm` file's bytes.
pub fn parse_statm(input: &[u8]) -> Result<Statm, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Statm,
        });
    }
    let body = strip_final_newline(input, Format::Statm)?;
    let tokens: Vec<&[u8]> = body.split(|b| *b == b' ').collect();
    if tokens.len() != 7 {
        return Err(ProcParseError::WrongFieldCount {
            format: Format::Statm,
            expected: 7,
            found: tokens.len(),
        });
    }
    let mut values = [0u64; 7];
    for (i, token) in tokens.iter().enumerate() {
        values[i] = num::parse_u64(token, FIELDS[i], span_of(input, token))?;
    }
    let statm = Statm {
        size: values[0],
        resident: values[1],
        shared: values[2],
        text: values[3],
        lib: values[4],
        data: values[5],
        dirty: values[6],
    };
    ensure_canonical(input, &render_statm(&statm), Format::Statm)?;
    Ok(statm)
}

/// Render a [`Statm`] in the kernel's byte shape.
pub fn render_statm(statm: &Statm) -> Vec<u8> {
    format!(
        "{} {} {} {} {} {} {}\n",
        statm.size, statm.resident, statm.shared, statm.text, statm.lib, statm.data, statm.dirty
    )
    .into_bytes()
}
