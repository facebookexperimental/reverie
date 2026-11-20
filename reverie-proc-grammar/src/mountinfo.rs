/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/mountinfo`: one row per mount, printed by
//! `show_mountinfo` (`fs/proc_namespace.c:135-191` at Linux v6.17;
//! the `%i %i %u:%u ` head is lines 143-144, the tagged optional
//! fields lines 159-169, and the ` - ` separator line 172).
//!
//! A row is `mount_id parent_id major:minor root mount_point
//! mount_options [optional fields...] - fs_type source
//! super_options`. Paths are byte strings with kernel octal escapes
//! for space, tab, newline, and backslash, so no field ever contains
//! a literal space and splitting on spaces is exact.
//!
//! The grammar row exposes the device as the printed
//! `device_major`/`device_minor` pair. Encoding that pair into a
//! `dev_t` is libc ABI (`makedev`), not file grammar, and stays with
//! consumers.
//!
//! Canonical rules, as everywhere in this crate: a nonempty file
//! ends with a final newline and decimals are canonical (no leading
//! zeros). Both are stricter than the loose decimal reader this
//! grammar replaces in `reverie-procfs`, deliberately: accepted
//! input is spelled exactly as the kernel spells it. The one
//! exception is the empty file, which is a valid empty snapshot (a
//! namespace with no visible mounts), not an error.
//!
//! Unknown *numeric* optional fields (`future_peer:19`) refuse:
//! they can carry mount-namespace identity like the peer-group
//! fields, and passing one through would expose an unmapped host
//! identifier. Unknown non-numeric flags carry no numeric identity
//! and are kept verbatim, as are bare flags such as `unbindable`.

use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// The optional-field prefixes that carry mount peer-group numbers
/// (`show_mountinfo`'s tagged fields).
pub const MOUNT_PEER_PREFIXES: [&[u8]; 3] = [b"shared:", b"master:", b"propagate_from:"];

/// One `/proc/<pid>/mountinfo` row, full-fidelity: rendering a
/// parsed row reproduces its kernel bytes exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountInfoRow {
    /// Unique ID of the mount (field 1).
    pub mount_id: u64,
    /// ID of the parent mount, or of this mount for the root of a
    /// mount namespace (field 2).
    pub parent_id: u64,
    /// Device major number (field 3, before the colon).
    pub device_major: u32,
    /// Device minor number (field 3, after the colon).
    pub device_minor: u32,
    /// Root of the mount within its filesystem (field 4).
    pub root: Vec<u8>,
    /// Mount point relative to the reading process's root (field 5).
    pub mount_point: Vec<u8>,
    /// Per-mount options (field 6), verbatim (e.g. `rw,relatime`).
    pub mount_options: Vec<u8>,
    /// Optional fields between the mount options and the `-`
    /// separator, verbatim and in kernel order.
    pub optional_fields: Vec<Vec<u8>>,
    /// Filesystem type (the field after `-`).
    pub fs_type: Vec<u8>,
    /// Mount source, or `none` (the field after the type).
    pub source: Vec<u8>,
    /// Superblock options (the last field), verbatim.
    pub super_options: Vec<u8>,
}

impl MountInfoRow {
    /// The peer-group numbers this row's optional fields carry, in
    /// field order (`shared:`, `master:`, `propagate_from:`).
    pub fn peer_groups(&self) -> Vec<u64> {
        self.optional_fields
            .iter()
            .filter_map(|field| peer_group(field))
            .collect()
    }
}

/// The peer-group number a tagged optional field carries, if it is
/// one. The value was validated canonical at parse time; a
/// hand-built row with an unparsable value simply yields none here.
fn peer_group(field: &[u8]) -> Option<u64> {
    MOUNT_PEER_PREFIXES
        .iter()
        .copied()
        .find_map(|prefix| field.strip_prefix(prefix))
        .and_then(|raw| core::str::from_utf8(raw).ok()?.parse().ok())
}

fn bad_shape(input: &[u8], line: &[u8]) -> ProcParseError {
    ProcParseError::BadShape {
        format: Format::Mountinfo,
        span: span_of(input, line),
    }
}

/// Whether an unknown tagged optional field carries a numeric
/// identity (`name:<digits>`), however spelled. Detection is by
/// digit shape, not canonical form, so no spelling of a numeric
/// identity slips through as a "non-numeric flag".
fn has_numeric_tag_value(field: &[u8]) -> bool {
    field
        .iter()
        .position(|byte| *byte == b':')
        .is_some_and(|colon| {
            let value = &field[colon + 1..];
            !value.is_empty() && value.iter().all(u8::is_ascii_digit)
        })
}

fn parse_row(input: &[u8], line: &[u8]) -> Result<MountInfoRow, ProcParseError> {
    let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
    let Some(separator) = fields.iter().position(|field| *field == b"-") else {
        return Err(bad_shape(input, line));
    };
    if separator < 6 || separator + 4 != fields.len() {
        return Err(bad_shape(input, line));
    }
    // Exactly one field may be empty: the mount source. The kernel
    // prints an empty source string as nothing between its two
    // spaces (`- tmpfs  rw,...` from `mount -t tmpfs "" /x`), and
    // refusing it fails the whole snapshot for every consumer.
    if fields
        .iter()
        .enumerate()
        .any(|(index, field)| field.is_empty() && index != separator + 2)
    {
        return Err(bad_shape(input, line));
    }
    let mut device = fields[2].split(|byte| *byte == b':');
    let (Some(major), Some(minor), None) = (device.next(), device.next(), device.next()) else {
        return Err(ProcParseError::BadValue {
            field: "device",
            span: span_of(input, fields[2]),
        });
    };
    for field in &fields[6..separator] {
        if let Some(prefix) = MOUNT_PEER_PREFIXES
            .iter()
            .copied()
            .find(|prefix| field.starts_with(prefix))
        {
            let raw = &field[prefix.len()..];
            num::parse_u64(raw, peer_field_name(prefix), span_of(input, raw))?;
        } else if has_numeric_tag_value(field) {
            return Err(ProcParseError::BadValue {
                field: "optional",
                span: span_of(input, field),
            });
        }
    }
    Ok(MountInfoRow {
        mount_id: num::parse_u64(fields[0], "mount_id", span_of(input, fields[0]))?,
        parent_id: num::parse_u64(fields[1], "parent_id", span_of(input, fields[1]))?,
        device_major: num::parse_u32(major, "device_major", span_of(input, major))?,
        device_minor: num::parse_u32(minor, "device_minor", span_of(input, minor))?,
        root: fields[3].to_vec(),
        mount_point: fields[4].to_vec(),
        mount_options: fields[5].to_vec(),
        optional_fields: fields[6..separator]
            .iter()
            .map(|field| field.to_vec())
            .collect(),
        fs_type: fields[separator + 1].to_vec(),
        source: fields[separator + 2].to_vec(),
        super_options: fields[separator + 3].to_vec(),
    })
}

fn peer_field_name(prefix: &[u8]) -> &'static str {
    match prefix {
        b"shared:" => "shared",
        b"master:" => "master",
        _ => "propagate_from",
    }
}

/// Parse one `mountinfo` file's bytes. The empty file is a valid
/// empty snapshot; duplicate mount IDs refuse.
pub fn parse_mountinfo(input: &[u8]) -> Result<Vec<MountInfoRow>, ProcParseError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let body = strip_final_newline(input, Format::Mountinfo)?;
    if body.is_empty() {
        return Err(bad_shape(input, input));
    }
    let mut rows = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        let row = parse_row(input, line)?;
        if rows
            .iter()
            .any(|seen: &MountInfoRow| seen.mount_id == row.mount_id)
        {
            return Err(ProcParseError::BadValue {
                field: "mount_id",
                span: span_of(input, line),
            });
        }
        rows.push(row);
    }
    ensure_canonical(input, &render_mountinfo(&rows), Format::Mountinfo)?;
    Ok(rows)
}

/// Render mount rows in the kernel's byte shape.
pub fn render_mountinfo(rows: &[MountInfoRow]) -> Vec<u8> {
    let mut out = Vec::new();
    for row in rows {
        out.extend_from_slice(
            alloc::format!(
                "{} {} {}:{} ",
                row.mount_id,
                row.parent_id,
                row.device_major,
                row.device_minor
            )
            .as_bytes(),
        );
        out.extend_from_slice(&row.root);
        out.push(b' ');
        out.extend_from_slice(&row.mount_point);
        out.push(b' ');
        out.extend_from_slice(&row.mount_options);
        for field in &row.optional_fields {
            out.push(b' ');
            out.extend_from_slice(field);
        }
        out.extend_from_slice(b" - ");
        out.extend_from_slice(&row.fs_type);
        out.push(b' ');
        out.extend_from_slice(&row.source);
        out.push(b' ');
        out.extend_from_slice(&row.super_options);
        out.push(b'\n');
    }
    out
}

/// Extract the one `mnt_id` value from an `fdinfo` file's bytes.
///
/// This is a field extractor, not the `fdinfo` file grammar (that
/// is [`crate::fdinfo::parse_fdinfo`]): identity capture runs it
/// over fdinfo kinds the file grammar deliberately does not model,
/// so it keeps its line-scan tolerances -- the field may sit on any
/// line, preceded by a tab or a space, and the file need not end
/// with a newline. Missing, duplicate, malformed, signed, or
/// out-of-range values refuse (`None`), exactly as the shared
/// parser in `reverie-procfs` did before this move.
pub fn parse_fdinfo_mount_id(contents: &[u8]) -> Option<u64> {
    let mut mount_id = None;
    for line in contents.split(|byte| *byte == b'\n') {
        let Some(value) = line.strip_prefix(b"mnt_id:") else {
            continue;
        };
        let value = value
            .strip_prefix(b"\t")
            .or_else(|| value.strip_prefix(b" "))?;
        if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) || mount_id.is_some()
        {
            return None;
        }
        mount_id = Some(core::str::from_utf8(value).ok()?.parse().ok()?);
    }
    mount_id
}
