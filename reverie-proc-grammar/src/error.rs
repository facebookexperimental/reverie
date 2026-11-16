/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The one error type for every parser in this crate.

use core::fmt;

/// A `/proc` format owned by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    /// `/proc/<pid>/stat`.
    Stat,
    /// `/proc/<pid>/status`.
    Status,
    /// `/proc/<pid>/comm`.
    Comm,
    /// `/proc/<pid>/fdinfo/<fd>`.
    Fdinfo,
    /// `/proc/<pid>/io`.
    ProcessIo,
    /// `/proc/<pid>/sched`.
    Sched,
    /// `/proc/<pid>/statm`.
    Statm,
    /// `/proc/<pid>/mountinfo`.
    Mountinfo,
}

impl Format {
    /// The format's name, as the file is named.
    pub fn name(self) -> &'static str {
        match self {
            Format::Stat => "stat",
            Format::Status => "status",
            Format::Comm => "comm",
            Format::Fdinfo => "fdinfo",
            Format::ProcessIo => "io",
            Format::Sched => "sched",
            Format::Statm => "statm",
            Format::Mountinfo => "mountinfo",
        }
    }
}

/// Why a byte string is not the format it claims to be.
///
/// Spans are `(start, end)` byte offsets into the parsed input. The
/// error carries no allocation: field names are `&'static str` from
/// the grammar, so refusing untrusted input stays cheap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcParseError {
    /// The input is empty.
    Empty {
        /// The format being parsed.
        format: Format,
    },
    /// A fixed-shape format has the wrong number of fields.
    WrongFieldCount {
        /// The format being parsed.
        format: Format,
        /// Fields the kernel's printing function emits.
        expected: usize,
        /// Fields found.
        found: usize,
    },
    /// A field that must be a number is not (or overflows its type).
    BadNumber {
        /// The kernel field's name (e.g. `starttime` for stat field 22).
        field: &'static str,
        /// Span of the offending token.
        span: (usize, usize),
    },
    /// A known label carries a value outside its value grammar.
    BadValue {
        /// The label or field name.
        field: &'static str,
        /// Span of the offending value.
        span: (usize, usize),
    },
    /// A labelled line names a label the grammar does not know. On a
    /// guest-visible path this is how a new kernel field is refused
    /// instead of republished.
    UnknownLabel {
        /// The format being parsed.
        format: Format,
        /// Span of the label.
        span: (usize, usize),
    },
    /// A required field or line is absent.
    MissingField {
        /// The field or label name.
        field: &'static str,
    },
    /// Bytes remain that the grammar does not account for.
    TrailingBytes {
        /// The format being parsed.
        format: Format,
        /// Span of the unaccounted bytes.
        span: (usize, usize),
    },
    /// The input's overall shape is wrong (no comm parentheses in a
    /// stat line, a status line with no colon, and so on).
    BadShape {
        /// The format being parsed.
        format: Format,
        /// Span of the malformed region.
        span: (usize, usize),
    },
    /// The input parses but is not spelled as the kernel spells it
    /// (spacing or padding its conversions never emit), detected by
    /// comparing the rendering of the parsed value to the input.
    NonCanonical {
        /// The format being parsed.
        format: Format,
        /// Span of the whole input.
        span: (usize, usize),
    },
}

impl fmt::Display for ProcParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcParseError::Empty { format } => write!(f, "{}: empty input", format.name()),
            ProcParseError::WrongFieldCount {
                format,
                expected,
                found,
            } => write!(
                f,
                "{}: expected {expected} fields, found {found}",
                format.name()
            ),
            ProcParseError::BadNumber { field, span } => {
                write!(f, "field {field}: bad number at {}..{}", span.0, span.1)
            }
            ProcParseError::BadValue { field, span } => {
                write!(f, "field {field}: bad value at {}..{}", span.0, span.1)
            }
            ProcParseError::UnknownLabel { format, span } => write!(
                f,
                "{}: unknown label at {}..{}",
                format.name(),
                span.0,
                span.1
            ),
            ProcParseError::MissingField { field } => write!(f, "missing field {field}"),
            ProcParseError::TrailingBytes { format, span } => write!(
                f,
                "{}: trailing bytes at {}..{}",
                format.name(),
                span.0,
                span.1
            ),
            ProcParseError::BadShape { format, span } => {
                write!(f, "{}: bad shape at {}..{}", format.name(), span.0, span.1)
            }
            ProcParseError::NonCanonical { format, span } => {
                write!(
                    f,
                    "{}: non-canonical spelling at {}..{}",
                    format.name(),
                    span.0,
                    span.1
                )
            }
        }
    }
}

/// The `(start, end)` span of `part` inside `input`. `part` must be a
/// subslice of `input` (every call site derives it by splitting).
pub fn span_of(input: &[u8], part: &[u8]) -> (usize, usize) {
    let start = part.as_ptr() as usize - input.as_ptr() as usize;
    (start, start + part.len())
}

/// The input without its final newline, which every kernel file in
/// this crate ends with. Requiring it refuses truncated reads: a
/// final field cut short must not parse as a shorter number.
pub(crate) fn strip_final_newline(input: &[u8], format: Format) -> Result<&[u8], ProcParseError> {
    input.strip_suffix(b"\n").ok_or(ProcParseError::BadShape {
        format,
        span: (input.len().saturating_sub(1), input.len()),
    })
}

/// Refuse `input` unless it is exactly `rendered`: the canonical-
/// spelling gate each fixed-shape parser applies after parsing, so
/// accepted input is always byte-identical to its rendering.
pub(crate) fn ensure_canonical(
    input: &[u8],
    rendered: &[u8],
    format: Format,
) -> Result<(), ProcParseError> {
    if rendered == input {
        Ok(())
    } else {
        Err(ProcParseError::NonCanonical {
            format,
            span: (0, input.len()),
        })
    }
}
