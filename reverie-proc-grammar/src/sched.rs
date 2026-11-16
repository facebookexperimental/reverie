/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/sched`: printed by `proc_sched_show_task`
//! (`kernel/sched/debug.c`) — a header (`<comm> (<pid>, #threads:
//! <n>)`, comm raw), a dash separator, then `label : value` lines
//! whose values are integers or fixed-point milliseconds with six
//! decimals, plus optional NUMA-balancing lines
//! (`CONFIG_NUMA_BALANCING`).
//!
//! Labels are intentionally *not* an enumerated set here: the kernel
//! adds observational counters between versions, and which of them a
//! consumer zeroes, keeps, or drops is consumer policy. The grammar
//! owns the shape — header, separator, per-line label/value form —
//! and refuses any line that is none of those. Each field line keeps
//! its exact head bytes (label, padding, colon, spaces) so rendering
//! reproduces the kernel's columns; the typed value is what setters
//! replace.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// One sched field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedValue {
    /// An integer counter.
    Int(i128),
    /// A fixed-point value with six decimals, stored scaled by 10^6.
    Fixed6(i128),
}

impl SchedValue {
    /// The value rendered as the kernel renders it.
    pub fn render(self) -> Vec<u8> {
        match self {
            SchedValue::Int(value) => format!("{value}").into_bytes(),
            SchedValue::Fixed6(scaled) => {
                let sign = if scaled < 0 { "-" } else { "" };
                let abs = scaled.unsigned_abs();
                format!("{sign}{}.{:06}", abs / 1_000_000, abs % 1_000_000).into_bytes()
            }
        }
    }
}

/// One line after the sched header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchedEntry {
    /// A dash separator, with its dash count.
    Separator(usize),
    /// A `label : value` field line.
    Field {
        /// Bytes before the colon (label and its padding), exactly
        /// as printed.
        prefix: Vec<u8>,
        /// The trimmed label (e.g. `se.vruntime`).
        label: Vec<u8>,
        /// The typed value.
        value: SchedValue,
        /// Width of the value column after the colon (spaces plus
        /// token) as printed; rendering right-aligns the value in
        /// this width, as the kernel's fixed-width conversions do.
        value_width: usize,
    },
    /// `current_node=<n>, numa_group_id=<n>` (`sched_show_numa`).
    CurrentNode {
        /// `current_node` value.
        current_node: i64,
        /// `numa_group_id` value.
        numa_group_id: i64,
    },
    /// One `numa_faults node=.. task_private=.. ...` line.
    NumaFaults {
        /// Node number.
        node: u64,
        /// Task-private faults.
        task_private: u64,
        /// Task-shared faults.
        task_shared: u64,
        /// Group-private faults.
        group_private: u64,
        /// Group-shared faults.
        group_shared: u64,
    },
}

/// One task's `sched` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sched {
    /// Header comm bytes, raw (may contain spaces, parens, newline).
    pub comm: Vec<u8>,
    /// Header pid.
    pub pid: i32,
    /// Header thread count.
    pub threads: u64,
    /// Lines after the header, in order.
    pub entries: Vec<SchedEntry>,
}

impl Sched {
    /// The value of the first field line labelled `label`.
    pub fn get(&self, label: &[u8]) -> Option<SchedValue> {
        self.entries.iter().find_map(|entry| match entry {
            SchedEntry::Field {
                label: l, value, ..
            } if l == label => Some(*value),
            _ => None,
        })
    }

    /// Set the first field line labelled `label`; `false` if absent.
    /// A rewritten value renders at the kernel's canonical column
    /// width, never at the width the host value happened to occupy:
    /// the width of the value being replaced is itself host data.
    pub fn set(&mut self, label: &[u8], value: SchedValue) -> bool {
        for entry in &mut self.entries {
            if let SchedEntry::Field { label: l, .. } = entry
                && l == label
            {
                entry.set_value(value);
                return true;
            }
        }
        false
    }
}

impl SchedEntry {
    /// Replace this field line's value, resetting its column width
    /// to the canonical kernel width for the new value (see
    /// [`Sched::set`]). No-op on non-field entries.
    pub fn set_value(&mut self, new_value: SchedValue) {
        if let SchedEntry::Field {
            value, value_width, ..
        } = self
        {
            *value = new_value;
            *value_width = new_value.canonical_width();
        }
    }
}

impl SchedValue {
    /// Width of the value column after the colon in the kernel's
    /// conversions (`%-45s:%21Ld` and `%-45s:%14Ld.%06ld`,
    /// kernel/sched/debug.c:1111-1117 in v6.17).
    fn canonical_width(self) -> usize {
        match self {
            SchedValue::Int(_) => 21.max(self.render().len()),
            SchedValue::Fixed6(scaled) => {
                let whole_digits = (scaled.unsigned_abs() / 1_000_000).to_string().len();
                let whole_len = whole_digits + usize::from(scaled < 0);
                14.max(whole_len) + 1 + 6
            }
        }
    }
}

fn bad_shape(input: &[u8], span_bytes: &[u8]) -> ProcParseError {
    ProcParseError::BadShape {
        format: Format::Sched,
        span: span_of(input, span_bytes),
    }
}

fn bad_value(input: &[u8], token: &[u8], field: &'static str) -> ProcParseError {
    ProcParseError::BadValue {
        field,
        span: span_of(input, token),
    }
}

/// Try to parse a header occupying `candidate` (no trailing newline):
/// `<comm> (<pid>, #threads: <n>)`, resolved from the end. A comm is
/// at most 15 bytes and the fixed suffix is longer than that, so a
/// comm cannot contain a complete fake suffix.
fn parse_header(candidate: &[u8]) -> Option<(Vec<u8>, i32, u64)> {
    let without_paren = candidate.strip_suffix(b")")?;
    let threads_at = rfind(without_paren, b", #threads: ")?;
    let threads_token = &without_paren[threads_at + b", #threads: ".len()..];
    let threads = num::parse_u64(threads_token, "#threads", (0, 0)).ok()?;
    let before = &without_paren[..threads_at];
    let open_at = rfind(before, b" (")?;
    let pid_token = &before[open_at + 2..];
    let pid = num::parse_i32(pid_token, "pid", (0, 0)).ok()?;
    let comm = before[..open_at].to_vec();
    if comm.len() > crate::comm::TASK_COMM_MAX || comm.contains(&0) {
        return None;
    }
    Some((comm, pid, threads))
}

fn parse_sched_value(token: &[u8], input: &[u8]) -> Result<SchedValue, ProcParseError> {
    if let Some(dot) = token.iter().position(|b| *b == b'.') {
        let frac = &token[dot + 1..];
        if frac.len() != 6 {
            return Err(bad_value(input, token, "sched value"));
        }
        // SPLIT_NS prints a signed whole-milliseconds part; a
        // sub-millisecond negative value prints as positive
        // `0.000001`-style (the sign is lost in the kernel's own
        // split), so `-0.xxxxxx` is never printed and the canonical
        // signed parse refuses it.
        let whole = i128::from(num::parse_i64(
            &token[..dot],
            "sched value",
            span_of(input, token),
        )?);
        let frac_value =
            num::parse_fixed_digits_u64(frac, 6, "sched value", span_of(input, frac))? as i128;
        let scaled = whole
            .checked_mul(1_000_000)
            .and_then(|w| {
                if whole < 0 {
                    w.checked_sub(frac_value)
                } else {
                    w.checked_add(frac_value)
                }
            })
            .ok_or_else(|| bad_value(input, token, "sched value"))?;
        Ok(SchedValue::Fixed6(scaled))
    } else {
        Ok(SchedValue::Int(i128::from(num::parse_i64(
            token,
            "sched value",
            span_of(input, token),
        )?)))
    }
}

fn trim_ascii(token: &[u8]) -> &[u8] {
    let start = token
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(token.len());
    let end = token
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &token[start..end]
}

fn parse_assignment(
    token: &[u8],
    want: &[u8],
    input: &[u8],
    field: &'static str,
) -> Result<i64, ProcParseError> {
    let value = token
        .strip_prefix(want)
        .and_then(|t| t.strip_prefix(b"="))
        .ok_or_else(|| bad_value(input, token, field))?;
    num::parse_i64(value, field, span_of(input, value))
}

/// Dashes in the separator `proc_sched_show_task` prints
/// (kernel/sched/debug.c:1153 in v6.17).
const SEPARATOR_DASHES: usize = 67;
/// Label column of the `%-45s:` field conversions.
const LABEL_WIDTH: usize = 45;

fn parse_entry(line: &[u8], input: &[u8]) -> Result<SchedEntry, ProcParseError> {
    if !line.is_empty() && line.iter().all(|b| *b == b'-') {
        if line.len() != SEPARATOR_DASHES {
            return Err(bad_shape(input, line));
        }
        return Ok(SchedEntry::Separator(line.len()));
    }
    if line.starts_with(b"current_node=") {
        let parts: Vec<&[u8]> = line.split(|b| *b == b',').collect();
        if parts.len() != 2 {
            return Err(bad_value(input, line, "current_node"));
        }
        let current_node = parse_assignment(parts[0], b"current_node", input, "current_node")?;
        let second = parts[1]
            .strip_prefix(b" ")
            .ok_or_else(|| bad_value(input, line, "current_node"))?;
        let numa_group_id = parse_assignment(second, b"numa_group_id", input, "numa_group_id")?;
        return Ok(SchedEntry::CurrentNode {
            current_node,
            numa_group_id,
        });
    }
    if line.starts_with(b"numa_faults ") {
        let keys: [&[u8]; 5] = [
            b"node",
            b"task_private",
            b"task_shared",
            b"group_private",
            b"group_shared",
        ];
        let parts: Vec<&[u8]> = line[b"numa_faults ".len()..]
            .split(|b| *b == b' ')
            .collect();
        if parts.len() != 5 {
            return Err(bad_value(input, line, "numa_faults"));
        }
        let mut values = [0u64; 5];
        for (i, part) in parts.iter().enumerate() {
            let value = part
                .strip_prefix(keys[i])
                .and_then(|t| t.strip_prefix(b"="))
                .ok_or_else(|| bad_value(input, line, "numa_faults"))?;
            values[i] = num::parse_u64(value, "numa_faults", span_of(input, value))?;
        }
        return Ok(SchedEntry::NumaFaults {
            node: values[0],
            task_private: values[1],
            task_shared: values[2],
            group_private: values[3],
            group_shared: values[4],
        });
    }
    let colon = line
        .iter()
        .position(|b| *b == b':')
        .ok_or_else(|| bad_shape(input, line))?;
    let after_colon = &line[colon + 1..];
    let value_start_in_after = after_colon
        .iter()
        .position(|b| *b != b' ')
        .ok_or_else(|| bad_shape(input, line))?;
    let value_token = trim_ascii(&after_colon[value_start_in_after..]);
    if value_token.is_empty() {
        return Err(bad_shape(input, line));
    }
    // No trailing whitespace: the value token ends the line.
    if span_of(line, value_token).1 != line.len() {
        return Err(bad_shape(input, line));
    }
    // The value column runs from after the colon through the end of
    // the token (the kernel prints no trailing spaces).
    let value_width = span_of(line, value_token).1 - (colon + 1);
    let prefix = line[..colon].to_vec();
    let label = trim_ascii(&line[..colon]).to_vec();
    if label.is_empty() {
        return Err(bad_shape(input, line));
    }
    // `%-45s:` — the label and exactly its padding, nothing else.
    let expected_prefix = LABEL_WIDTH.max(label.len());
    if prefix.len() != expected_prefix
        || !prefix.starts_with(&label)
        || prefix[label.len()..].iter().any(|b| *b != b' ')
    {
        return Err(bad_shape(input, line));
    }
    let value = parse_sched_value(value_token, input)?;
    if value_width != value.canonical_width() {
        return Err(bad_value(input, value_token, "sched value"));
    }
    Ok(SchedEntry::Field {
        prefix,
        label,
        value,
        value_width,
    })
}

/// Parse one `sched` file's bytes.
///
/// The header can span several physical lines (a newline inside
/// comm), so the header is the shortest prefix ending at a newline
/// that parses as `<comm> (<pid>, #threads: <n>)`.
pub fn parse_sched(input: &[u8]) -> Result<Sched, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Sched,
        });
    }
    let mut header: Option<(Vec<u8>, i32, u64, usize)> = None;
    for (i, byte) in input.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        if let Some((comm, pid, threads)) = parse_header(&input[..i]) {
            header = Some((comm, pid, threads, i + 1));
            break;
        }
    }
    let Some((comm, pid, threads, rest_start)) = header else {
        return Err(bad_shape(input, input));
    };
    let rest = &input[rest_start..];
    let rest_body = if rest.is_empty() {
        rest
    } else {
        strip_final_newline(rest, Format::Sched)?
    };
    let mut entries = Vec::new();
    if !rest_body.is_empty() {
        for line in rest_body.split(|b| *b == b'\n') {
            entries.push(parse_entry(line, input)?);
        }
    }
    let sched = Sched {
        comm,
        pid,
        threads,
        entries,
    };
    // Anything the per-line checks let through but the renderer
    // would spell differently (a tab where the kernel prints a
    // space, say) is not a kernel spelling.
    ensure_canonical(input, &render_sched(&sched), Format::Sched)?;
    Ok(sched)
}

/// Render a [`Sched`] in the kernel's byte shape.
pub fn render_sched(sched: &Sched) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&sched.comm);
    out.extend_from_slice(format!(" ({}, #threads: {})\n", sched.pid, sched.threads).as_bytes());
    for entry in &sched.entries {
        match entry {
            SchedEntry::Separator(count) => {
                out.extend(core::iter::repeat_n(b'-', *count));
                out.push(b'\n');
            }
            SchedEntry::Field {
                prefix,
                value,
                value_width,
                ..
            } => {
                out.extend_from_slice(prefix);
                out.push(b':');
                let rendered = value.render();
                out.extend(core::iter::repeat_n(
                    b' ',
                    value_width.saturating_sub(rendered.len()),
                ));
                out.extend_from_slice(&rendered);
                out.push(b'\n');
            }
            SchedEntry::CurrentNode {
                current_node,
                numa_group_id,
            } => {
                out.extend_from_slice(
                    format!("current_node={current_node}, numa_group_id={numa_group_id}\n")
                        .as_bytes(),
                );
            }
            SchedEntry::NumaFaults {
                node,
                task_private,
                task_shared,
                group_private,
                group_shared,
            } => {
                out.extend_from_slice(
                    format!(
                        "numa_faults node={node} task_private={task_private} task_shared={task_shared} group_private={group_private} group_shared={group_shared}\n"
                    )
                    .as_bytes(),
                );
            }
        }
    }
    out
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
