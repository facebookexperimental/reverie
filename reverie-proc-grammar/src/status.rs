/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `/proc/<pid>/status`: `Label:\tvalue` lines printed by
//! `proc_pid_status` (`fs/proc/array.c`: `task_state`, `task_mem`,
//! `task_sig`, `task_cap`, `task_seccomp`, `task_cpus_allowed`,
//! `cpuset_task_status_allowed`, `task_context_switch_counts`).
//!
//! The label inventory below is the one Linux 7.1 prints on x86_64,
//! with and without an mm (kernel threads and zombies omit the memory
//! block), checked against `proc_pid_status` and its helpers in
//! `fs/proc/array.c` (including the `arch_proc_pid_thread_features`
//! call at fs/proc/array.c:463 in v6.17, after the context-switch
//! counts) and the x86 printer at arch/x86/kernel/cpu/proc.c:184-202
//! in v6.17 (`CONFIG_X86_USER_SHADOW_STACK`, since Linux 6.6). Known
//! labels must appear in kernel order with no duplicates. The
//! default [`parse_status`] refuses a label this grammar does not
//! know; [`parse_status_preserving_unknown`] instead preserves it
//! as [`StatusLine::Unknown`] in place, never silently typed, for a
//! guest-visible consumer to drop by name (see
//! [`Status::drop_unknown`]) rather than republish the host's new
//! field or blank the whole file. Inventory tests still fail on an
//! unknown label so the grammar learns it. The `Name` value is the
//! escaped form the kernel prints (`proc_task_name` with escaping:
//! newline and backslash become two-byte escapes; every other byte,
//! including non-UTF-8, is raw).

use alloc::format;
use alloc::vec::Vec;

use crate::error::Format;
use crate::error::ProcParseError;
use crate::error::ensure_canonical;
use crate::error::span_of;
use crate::error::strip_final_newline;
use crate::num;

/// One `status` line's label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusLabel {
    Name,
    Umask,
    State,
    Tgid,
    Ngid,
    Pid,
    PPid,
    TracerPid,
    Uid,
    Gid,
    FDSize,
    Groups,
    NStgid,
    NSpid,
    NSpgid,
    NSsid,
    Kthread,
    VmPeak,
    VmSize,
    VmLck,
    VmPin,
    VmHWM,
    VmRSS,
    RssAnon,
    RssFile,
    RssShmem,
    VmData,
    VmStk,
    VmExe,
    VmLib,
    VmPTE,
    VmSwap,
    HugetlbPages,
    CoreDumping,
    THPEnabled,
    UntagMask,
    Threads,
    SigQ,
    SigPnd,
    ShdPnd,
    SigBlk,
    SigIgn,
    SigCgt,
    CapInh,
    CapPrm,
    CapEff,
    CapBnd,
    CapAmb,
    NoNewPrivs,
    Seccomp,
    SeccompFilters,
    SpeculationStoreBypass,
    SpeculationIndirectBranch,
    CpusAllowed,
    CpusAllowedList,
    MemsAllowed,
    MemsAllowedList,
    VoluntaryCtxtSwitches,
    NonvoluntaryCtxtSwitches,
    X86ThreadFeatures,
    X86ThreadFeaturesLocked,
}

impl StatusLabel {
    /// The label as the kernel prints it, without the colon.
    pub fn name(self) -> &'static str {
        use StatusLabel::*;
        match self {
            Name => "Name",
            Umask => "Umask",
            State => "State",
            Tgid => "Tgid",
            Ngid => "Ngid",
            Pid => "Pid",
            PPid => "PPid",
            TracerPid => "TracerPid",
            Uid => "Uid",
            Gid => "Gid",
            FDSize => "FDSize",
            Groups => "Groups",
            NStgid => "NStgid",
            NSpid => "NSpid",
            NSpgid => "NSpgid",
            NSsid => "NSsid",
            Kthread => "Kthread",
            VmPeak => "VmPeak",
            VmSize => "VmSize",
            VmLck => "VmLck",
            VmPin => "VmPin",
            VmHWM => "VmHWM",
            VmRSS => "VmRSS",
            RssAnon => "RssAnon",
            RssFile => "RssFile",
            RssShmem => "RssShmem",
            VmData => "VmData",
            VmStk => "VmStk",
            VmExe => "VmExe",
            VmLib => "VmLib",
            VmPTE => "VmPTE",
            VmSwap => "VmSwap",
            HugetlbPages => "HugetlbPages",
            CoreDumping => "CoreDumping",
            THPEnabled => "THP_enabled",
            UntagMask => "untag_mask",
            Threads => "Threads",
            SigQ => "SigQ",
            SigPnd => "SigPnd",
            ShdPnd => "ShdPnd",
            SigBlk => "SigBlk",
            SigIgn => "SigIgn",
            SigCgt => "SigCgt",
            CapInh => "CapInh",
            CapPrm => "CapPrm",
            CapEff => "CapEff",
            CapBnd => "CapBnd",
            CapAmb => "CapAmb",
            NoNewPrivs => "NoNewPrivs",
            Seccomp => "Seccomp",
            SeccompFilters => "Seccomp_filters",
            SpeculationStoreBypass => "Speculation_Store_Bypass",
            SpeculationIndirectBranch => "SpeculationIndirectBranch",
            CpusAllowed => "Cpus_allowed",
            CpusAllowedList => "Cpus_allowed_list",
            MemsAllowed => "Mems_allowed",
            MemsAllowedList => "Mems_allowed_list",
            VoluntaryCtxtSwitches => "voluntary_ctxt_switches",
            NonvoluntaryCtxtSwitches => "nonvoluntary_ctxt_switches",
            X86ThreadFeatures => "x86_Thread_features",
            X86ThreadFeaturesLocked => "x86_Thread_features_locked",
        }
    }

    fn from_name(name: &[u8]) -> Option<StatusLabel> {
        use StatusLabel::*;
        Some(match name {
            b"Name" => Name,
            b"Umask" => Umask,
            b"State" => State,
            b"Tgid" => Tgid,
            b"Ngid" => Ngid,
            b"Pid" => Pid,
            b"PPid" => PPid,
            b"TracerPid" => TracerPid,
            b"Uid" => Uid,
            b"Gid" => Gid,
            b"FDSize" => FDSize,
            b"Groups" => Groups,
            b"NStgid" => NStgid,
            b"NSpid" => NSpid,
            b"NSpgid" => NSpgid,
            b"NSsid" => NSsid,
            b"Kthread" => Kthread,
            b"VmPeak" => VmPeak,
            b"VmSize" => VmSize,
            b"VmLck" => VmLck,
            b"VmPin" => VmPin,
            b"VmHWM" => VmHWM,
            b"VmRSS" => VmRSS,
            b"RssAnon" => RssAnon,
            b"RssFile" => RssFile,
            b"RssShmem" => RssShmem,
            b"VmData" => VmData,
            b"VmStk" => VmStk,
            b"VmExe" => VmExe,
            b"VmLib" => VmLib,
            b"VmPTE" => VmPTE,
            b"VmSwap" => VmSwap,
            b"HugetlbPages" => HugetlbPages,
            b"CoreDumping" => CoreDumping,
            b"THP_enabled" => THPEnabled,
            b"untag_mask" => UntagMask,
            b"Threads" => Threads,
            b"SigQ" => SigQ,
            b"SigPnd" => SigPnd,
            b"ShdPnd" => ShdPnd,
            b"SigBlk" => SigBlk,
            b"SigIgn" => SigIgn,
            b"SigCgt" => SigCgt,
            b"CapInh" => CapInh,
            b"CapPrm" => CapPrm,
            b"CapEff" => CapEff,
            b"CapBnd" => CapBnd,
            b"CapAmb" => CapAmb,
            b"NoNewPrivs" => NoNewPrivs,
            b"Seccomp" => Seccomp,
            b"Seccomp_filters" => SeccompFilters,
            b"Speculation_Store_Bypass" => SpeculationStoreBypass,
            b"SpeculationIndirectBranch" => SpeculationIndirectBranch,
            b"Cpus_allowed" => CpusAllowed,
            b"Cpus_allowed_list" => CpusAllowedList,
            b"Mems_allowed" => MemsAllowed,
            b"Mems_allowed_list" => MemsAllowedList,
            b"voluntary_ctxt_switches" => VoluntaryCtxtSwitches,
            b"nonvoluntary_ctxt_switches" => NonvoluntaryCtxtSwitches,
            b"x86_Thread_features" => X86ThreadFeatures,
            b"x86_Thread_features_locked" => X86ThreadFeaturesLocked,
            _ => return None,
        })
    }
}

/// A CPU/node bitmap as `bitmap_string` prints it: comma-separated
/// 32-bit groups, most significant first, each group zero-padded to
/// its digit width (8 for full groups, fewer for a partial top
/// group).
///
/// The fields are private so the width invariant holds by
/// construction: the most significant group always fits in
/// `first_digits` hex digits. A declared width too narrow for the
/// top group's value is a spelling the kernel never prints — its
/// width comes from the mask's bit count, so the value's top bits
/// are always inside it — and rendering such a value could only
/// produce bytes whose re-parse is a different `Bitmap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    /// Hex digits in the most significant (first printed) group.
    first_digits: u8,
    /// Group values, most significant first.
    groups: Vec<u32>,
}

impl Bitmap {
    /// Build a bitmap from its first group's digit width and its
    /// group values (most significant first). Returns `None` when
    /// the pair cannot be a kernel spelling: no groups, a width
    /// outside `1..=8`, or a most significant group that needs more
    /// digits than `first_digits` declares.
    pub fn new(first_digits: u8, groups: Vec<u32>) -> Option<Self> {
        let first = *groups.first()?;
        if !(1..=8).contains(&first_digits) {
            return None;
        }
        if first_digits < 8 && first >> (4 * u32::from(first_digits)) != 0 {
            return None;
        }
        Some(Self {
            first_digits,
            groups,
        })
    }

    /// Hex digits in the most significant (first printed) group.
    pub fn first_digits(&self) -> u8 {
        self.first_digits
    }

    /// Group values, most significant first.
    pub fn groups(&self) -> &[u32] {
        &self.groups
    }

    fn render(&self, out: &mut Vec<u8>) {
        for (i, group) in self.groups.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            let width = if i == 0 {
                usize::from(self.first_digits)
            } else {
                8
            };
            out.extend_from_slice(format!("{group:0width$x}").as_bytes());
        }
    }
}

/// The value of one `status` line, typed by its label's value grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusValue {
    /// `Name`: the escaped printed bytes.
    Name(Vec<u8>),
    /// `Umask`: the mask (`%04o`).
    Umask(u32),
    /// `State`: the letter byte and the parenthesised word bytes.
    State(u8, Vec<u8>),
    /// One signed decimal (ids and small counts).
    Decimal(i64),
    /// A namespace id list (`NStgid`/`NSpid`/`NSpgid`/`NSsid`):
    /// tab-separated, one id per nesting level, outermost first.
    PidList(Vec<i32>),
    /// One unsigned decimal counter (context switches).
    Counter(u64),
    /// `Uid`/`Gid`: real, effective, saved-set, filesystem ids.
    Ids([u32; 4]),
    /// `Groups`: supplementary groups in printed order.
    Groups(Vec<u32>),
    /// A `task_mem` line, in kibibytes.
    Kb(u64),
    /// `SigQ`: queued signals and the queue limit.
    SigQ(u64, u64),
    /// A signal or capability set (16 lowercase hex digits).
    HexMask(u64),
    /// A speculation-status phrase, verbatim bytes.
    Text(Vec<u8>),
    /// `untag_mask`: a `0x`-prefixed hex value.
    PrefixedHex(u64),
    /// `Cpus_allowed`/`Mems_allowed`.
    Bitmap(Bitmap),
    /// `Cpus_allowed_list`/`Mems_allowed_list`: `(first, last)` ranges
    /// in printed order; a singleton prints without the dash.
    RangeList(Vec<(u32, u32)>),
    /// x86 user shadow-stack features (`dump_x86_features`): each
    /// present feature prints as its name and a trailing space, in
    /// shstk-then-wrss order; no features prints an empty value.
    ThreadFeatures {
        /// `shstk` (shadow stack enabled).
        shstk: bool,
        /// `wrss` (write-to-shadow-stack enabled).
        wrss: bool,
    },
}

/// One parsed `status` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusLine {
    /// A label in the grammar's inventory, with its typed value.
    Known {
        /// The line's label.
        label: StatusLabel,
        /// The line's typed value.
        value: StatusValue,
    },
    /// A label this grammar does not know yet (a newer kernel
    /// field), preserved verbatim in place. Guest-visible consumers
    /// must drop these lines — see [`Status::drop_unknown`] — rather
    /// than republish a host field the grammar cannot type.
    Unknown {
        /// The label bytes, without the colon.
        label: Vec<u8>,
        /// The value bytes after `Label:\t`, verbatim.
        value: Vec<u8>,
    },
}

/// One task's `status` file: its lines in kernel order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The lines, in the order parsed (the kernel's order).
    pub lines: Vec<StatusLine>,
}

impl Status {
    /// The value of the first known line with `label`, if present.
    pub fn get(&self, label: StatusLabel) -> Option<&StatusValue> {
        self.lines.iter().find_map(|line| match line {
            StatusLine::Known {
                label: found,
                value,
            } if *found == label => Some(value),
            _ => None,
        })
    }

    /// Replace the value of the first known line with `label`.
    /// Returns `false` (changing nothing) when the label is absent:
    /// whether a missing label is an error is the caller's policy.
    pub fn set(&mut self, label: StatusLabel, value: StatusValue) -> bool {
        for line in &mut self.lines {
            if let StatusLine::Known {
                label: found,
                value: slot,
            } = line
                && *found == label
            {
                *slot = value;
                return true;
            }
        }
        false
    }

    /// Labels of the preserved unknown lines, in file order. A
    /// nonempty result means the grammar's inventory is behind the
    /// kernel that printed this file.
    pub fn unknown_labels(&self) -> impl Iterator<Item = &[u8]> {
        self.lines.iter().filter_map(|line| match line {
            StatusLine::Unknown { label, .. } => Some(label.as_slice()),
            StatusLine::Known { .. } => None,
        })
    }

    /// Drop every unknown line, returning the labels dropped. The
    /// guest-visible sanitizing policy for a field the grammar
    /// cannot type: the known lines survive sanitized, the unknown
    /// host field is withheld whole — never republished, and the
    /// file is not blanked for one new field.
    pub fn drop_unknown(&mut self) -> Vec<Vec<u8>> {
        let mut dropped = Vec::new();
        self.lines.retain(|line| match line {
            StatusLine::Unknown { label, .. } => {
                dropped.push(label.clone());
                false
            }
            StatusLine::Known { .. } => true,
        });
        dropped
    }

    /// A signal/capability mask line's value, if present and a mask.
    pub fn hex_mask(&self, label: StatusLabel) -> Option<u64> {
        match self.get(label) {
            Some(StatusValue::HexMask(mask)) => Some(*mask),
            _ => None,
        }
    }

    /// Set a signal/capability mask line's value.
    pub fn set_hex_mask(&mut self, label: StatusLabel, mask: u64) -> bool {
        self.set(label, StatusValue::HexMask(mask))
    }

    /// A decimal line's value, if present and decimal.
    pub fn decimal(&self, label: StatusLabel) -> Option<i64> {
        match self.get(label) {
            Some(StatusValue::Decimal(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set a decimal line's value.
    pub fn set_decimal(&mut self, label: StatusLabel, value: i64) -> bool {
        self.set(label, StatusValue::Decimal(value))
    }
}

fn bad_value(field: &'static str, input: &[u8], token: &[u8]) -> ProcParseError {
    ProcParseError::BadValue {
        field,
        span: span_of(input, token),
    }
}

fn parse_bitmap(token: &[u8], input: &[u8], field: &'static str) -> Result<Bitmap, ProcParseError> {
    let parts: Vec<&[u8]> = token.split(|b| *b == b',').collect();
    if parts.is_empty() || parts[0].is_empty() || parts[0].len() > 8 {
        return Err(bad_value(field, input, token));
    }
    let mut groups = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        let digits = if i == 0 { part.len() } else { 8 };
        if part.len() != digits {
            return Err(bad_value(field, input, token));
        }
        let value = num::parse_hex_u64(part, digits, field, span_of(input, part))?;
        groups.push(value as u32);
    }
    Ok(Bitmap {
        first_digits: parts[0].len() as u8,
        groups,
    })
}

/// Parse a kernel bitmap token (also used by callers to build a
/// [`Bitmap`] from their own mask rendering for a setter).
pub fn parse_bitmap_token(token: &[u8]) -> Result<Bitmap, ProcParseError> {
    // Spans are relative to this token alone here.
    parse_bitmap(token, token, "bitmap")
}

fn parse_range_list(
    token: &[u8],
    input: &[u8],
    field: &'static str,
) -> Result<Vec<(u32, u32)>, ProcParseError> {
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for part in token.split(|b| *b == b',') {
        let range = match part.iter().position(|b| *b == b'-') {
            Some(at) => {
                let lo = num::parse_u32(&part[..at], field, span_of(input, &part[..at]))?;
                let hi = num::parse_u32(&part[at + 1..], field, span_of(input, &part[at + 1..]))?;
                // The kernel prints a singleton without a dash and
                // coalesces adjacent ids, so a dashed or touching
                // range is not a spelling it emits.
                if hi <= lo {
                    return Err(bad_value(field, input, part));
                }
                (lo, hi)
            }
            None => {
                let one = num::parse_u32(part, field, span_of(input, part))?;
                (one, one)
            }
        };
        if let Some((_, prev_hi)) = ranges.last()
            && range.0 <= prev_hi.saturating_add(1)
        {
            return Err(bad_value(field, input, part));
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(bad_value(field, input, token));
    }
    Ok(ranges)
}

/// Parse a kernel range-list token (setter companion to
/// [`parse_bitmap_token`]).
pub fn parse_range_list_token(token: &[u8]) -> Result<Vec<(u32, u32)>, ProcParseError> {
    parse_range_list(token, token, "range list")
}

fn parse_value(
    label: StatusLabel,
    token: &[u8],
    input: &[u8],
) -> Result<StatusValue, ProcParseError> {
    use StatusLabel::*;
    let field = label.name();
    let span = span_of(input, token);
    Ok(match label {
        Name => {
            // The escaping printer emits only `\\` and `\n` escape
            // pairs; a lone backslash (or a NUL, which ends the stored
            // name) is not a spelling it produces.
            let mut i = 0;
            while i < token.len() {
                match token[i] {
                    0 => return Err(bad_value(field, input, token)),
                    b'\\' => {
                        if !matches!(token.get(i + 1), Some(b'\\') | Some(b'n')) {
                            return Err(bad_value(field, input, token));
                        }
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            StatusValue::Name(token.to_vec())
        }
        Umask => {
            let value = num::parse_octal4_u32(token, field, span)?;
            if value > 0o777 {
                return Err(bad_value(field, input, token));
            }
            StatusValue::Umask(value)
        }
        State => {
            // Exactly `task_state_array`'s spellings
            // (fs/proc/array.c:126-140 in v6.17).
            let word: &[u8] = match token {
                b"R (running)" | b"S (sleeping)" | b"D (disk sleep)" | b"T (stopped)"
                | b"t (tracing stop)" | b"X (dead)" | b"Z (zombie)" | b"P (parked)"
                | b"I (idle)" => &token[3..token.len() - 1],
                _ => return Err(bad_value(field, input, token)),
            };
            StatusValue::State(token[0], word.to_vec())
        }
        Tgid | Ngid | Pid | PPid | TracerPid | FDSize | Kthread | Threads | NoNewPrivs
        | Seccomp | SeccompFilters | CoreDumping | THPEnabled => {
            // Printed with seq_put_decimal_ull (or %c for Kthread):
            // never negative; the boolean lines print only 0 or 1.
            let value = num::parse_i64(token, field, span)?;
            let boolean = matches!(label, Kthread | CoreDumping | THPEnabled | NoNewPrivs);
            if value < 0 || (boolean && value > 1) {
                return Err(bad_value(field, input, token));
            }
            StatusValue::Decimal(value)
        }
        NStgid | NSpid | NSpgid | NSsid => {
            let mut ids = Vec::new();
            for part in token.split(|b| *b == b'\t') {
                let id = num::parse_i32(part, field, span_of(input, part))?;
                if id < 0 {
                    return Err(bad_value(field, input, part));
                }
                ids.push(id);
            }
            if ids.is_empty() {
                return Err(bad_value(field, input, token));
            }
            StatusValue::PidList(ids)
        }
        VoluntaryCtxtSwitches | NonvoluntaryCtxtSwitches => {
            StatusValue::Counter(num::parse_u64(token, field, span)?)
        }
        Uid | Gid => {
            let parts: Vec<&[u8]> = token.split(|b| *b == b'\t').collect();
            if parts.len() != 4 {
                return Err(bad_value(field, input, token));
            }
            let mut ids = [0u32; 4];
            for (i, part) in parts.iter().enumerate() {
                ids[i] = num::parse_u32(part, field, span_of(input, part))?;
            }
            StatusValue::Ids(ids)
        }
        Groups => {
            // Each group prints with a trailing space, so the token
            // ends with one; an empty group list prints as that lone
            // space.
            if token == b" " {
                StatusValue::Groups(Vec::new())
            } else {
                let parts: Vec<&[u8]> = token.split(|b| *b == b' ').collect();
                if parts.last() != Some(&b"".as_slice()) {
                    return Err(bad_value(field, input, token));
                }
                let mut groups = Vec::with_capacity(parts.len() - 1);
                for part in &parts[..parts.len() - 1] {
                    groups.push(num::parse_u32(part, field, span_of(input, part))?);
                }
                StatusValue::Groups(groups)
            }
        }
        VmPeak | VmSize | VmLck | VmPin | VmHWM | VmRSS | RssAnon | RssFile | RssShmem | VmData
        | VmStk | VmExe | VmLib | VmPTE | VmSwap | HugetlbPages => {
            let digits = token
                .strip_suffix(b" kB")
                .ok_or_else(|| bad_value(field, input, token))?;
            // The value is right-aligned in a field of width 8
            // (`%8lu`): shorter is truncated, longer carries no
            // leading spaces. Anything else is not its spelling.
            if digits.len() < 8 || (digits.len() > 8 && digits[0] == b' ') {
                return Err(bad_value(field, input, token));
            }
            let digits = trim_ascii_start(digits);
            StatusValue::Kb(num::parse_u64(digits, field, span_of(input, digits))?)
        }
        SigQ => {
            let slash = token
                .iter()
                .position(|b| *b == b'/')
                .ok_or_else(|| bad_value(field, input, token))?;
            StatusValue::SigQ(
                num::parse_u64(&token[..slash], field, span_of(input, &token[..slash]))?,
                num::parse_u64(
                    &token[slash + 1..],
                    field,
                    span_of(input, &token[slash + 1..]),
                )?,
            )
        }
        SigPnd | ShdPnd | SigBlk | SigIgn | SigCgt | CapInh | CapPrm | CapEff | CapBnd | CapAmb => {
            StatusValue::HexMask(num::parse_hex_u64(token, 16, field, span)?)
        }
        SpeculationStoreBypass | SpeculationIndirectBranch => {
            if token.is_empty() {
                return Err(bad_value(field, input, token));
            }
            StatusValue::Text(token.to_vec())
        }
        UntagMask => StatusValue::PrefixedHex(num::parse_prefixed_hex_u64(token, field, span)?),
        CpusAllowed | MemsAllowed => StatusValue::Bitmap(parse_bitmap(token, input, field)?),
        CpusAllowedList | MemsAllowedList => {
            StatusValue::RangeList(parse_range_list(token, input, field)?)
        }
        X86ThreadFeatures | X86ThreadFeaturesLocked => {
            // dump_x86_features prints each present feature and a
            // trailing space, shstk before wrss; nothing else.
            let (shstk, wrss) = match token {
                b"" => (false, false),
                b"shstk " => (true, false),
                b"wrss " => (false, true),
                b"shstk wrss " => (true, true),
                _ => return Err(bad_value(field, input, token)),
            };
            StatusValue::ThreadFeatures { shstk, wrss }
        }
    })
}

fn trim_ascii_start(token: &[u8]) -> &[u8] {
    let start = token.iter().position(|b| *b != b' ').unwrap_or(token.len());
    &token[start..]
}

/// Parse one `status` file's bytes, strictly: an unknown label is
/// a refusal ([`ProcParseError::UnknownLabel`]), as for every other
/// format in this crate. Known labels must appear in kernel order
/// (the declaration order of [`StatusLabel`]) with no duplicates;
/// optional labels may be absent.
pub fn parse_status(input: &[u8]) -> Result<Status, ProcParseError> {
    parse_status_impl(input, false)
}

/// Parse one `status` file's bytes, preserving labels this grammar
/// does not know as [`StatusLine::Unknown`] in place (also without
/// duplicates). This is the opt-in for a consumer that serves a
/// sanitized file and drops unknown lines by name
/// ([`Status::drop_unknown`]) instead of refusing the whole file
/// for one newer kernel field; the default [`parse_status`] stays
/// strict.
pub fn parse_status_preserving_unknown(input: &[u8]) -> Result<Status, ProcParseError> {
    parse_status_impl(input, true)
}

fn parse_status_impl(input: &[u8], preserve_unknown: bool) -> Result<Status, ProcParseError> {
    if input.is_empty() {
        return Err(ProcParseError::Empty {
            format: Format::Status,
        });
    }
    let body = strip_final_newline(input, Format::Status)?;
    let mut lines = Vec::new();
    let mut seen_known: Vec<StatusLabel> = Vec::new();
    let mut seen_unknown: Vec<&[u8]> = Vec::new();
    let mut last_known_rank: Option<usize> = None;
    for line in body.split(|b| *b == b'\n') {
        let colon = line.iter().position(|b| *b == b':');
        let (label_token, value_token) = match colon {
            Some(at) if line.get(at + 1) == Some(&b'\t') => (&line[..at], &line[at + 2..]),
            _ => {
                return Err(ProcParseError::BadShape {
                    format: Format::Status,
                    span: span_of(input, line),
                });
            }
        };
        // Kernel labels are identifier-shaped; anything else is not
        // a status line at all.
        if label_token.is_empty()
            || !label_token[0].is_ascii_alphabetic()
            || !label_token
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            return Err(ProcParseError::BadShape {
                format: Format::Status,
                span: span_of(input, label_token),
            });
        }
        match StatusLabel::from_name(label_token) {
            Some(label) => {
                let rank = label as usize;
                if seen_known.contains(&label) || last_known_rank.is_some_and(|last| rank <= last) {
                    return Err(ProcParseError::BadValue {
                        field: label.name(),
                        span: span_of(input, label_token),
                    });
                }
                seen_known.push(label);
                last_known_rank = Some(rank);
                let value = parse_value(label, value_token, input)?;
                lines.push(StatusLine::Known { label, value });
            }
            None => {
                if !preserve_unknown {
                    return Err(ProcParseError::UnknownLabel {
                        format: Format::Status,
                        span: span_of(input, label_token),
                    });
                }
                if seen_unknown.contains(&label_token) {
                    return Err(ProcParseError::BadShape {
                        format: Format::Status,
                        span: span_of(input, label_token),
                    });
                }
                seen_unknown.push(label_token);
                lines.push(StatusLine::Unknown {
                    label: label_token.to_vec(),
                    value: value_token.to_vec(),
                });
            }
        }
    }
    let status = Status { lines };
    ensure_canonical(input, &render_status(&status), Format::Status)?;
    Ok(status)
}

fn render_value(value: &StatusValue, out: &mut Vec<u8>) {
    match value {
        StatusValue::Name(bytes) | StatusValue::Text(bytes) => out.extend_from_slice(bytes),
        StatusValue::Umask(mask) => out.extend_from_slice(format!("{mask:04o}").as_bytes()),
        StatusValue::State(letter, word) => {
            out.push(*letter);
            out.extend_from_slice(b" (");
            out.extend_from_slice(word);
            out.push(b')');
        }
        StatusValue::Decimal(value) => out.extend_from_slice(format!("{value}").as_bytes()),
        StatusValue::PidList(ids) => {
            for (i, id) in ids.iter().enumerate() {
                if i > 0 {
                    out.push(b'\t');
                }
                out.extend_from_slice(format!("{id}").as_bytes());
            }
        }
        StatusValue::Counter(value) => out.extend_from_slice(format!("{value}").as_bytes()),
        StatusValue::Ids(ids) => out.extend_from_slice(
            format!("{}\t{}\t{}\t{}", ids[0], ids[1], ids[2], ids[3]).as_bytes(),
        ),
        StatusValue::Groups(groups) => {
            if groups.is_empty() {
                out.push(b' ');
            }
            for group in groups {
                out.extend_from_slice(format!("{group} ").as_bytes());
            }
        }
        StatusValue::Kb(kb) => out.extend_from_slice(format!("{kb:>8} kB").as_bytes()),
        StatusValue::SigQ(queued, limit) => {
            out.extend_from_slice(format!("{queued}/{limit}").as_bytes())
        }
        StatusValue::HexMask(mask) => out.extend_from_slice(format!("{mask:016x}").as_bytes()),
        StatusValue::PrefixedHex(value) => out.extend_from_slice(format!("{value:#x}").as_bytes()),
        StatusValue::Bitmap(bitmap) => bitmap.render(out),
        StatusValue::ThreadFeatures { shstk, wrss } => {
            if *shstk {
                out.extend_from_slice(b"shstk ");
            }
            if *wrss {
                out.extend_from_slice(b"wrss ");
            }
        }
        StatusValue::RangeList(ranges) => {
            for (i, (lo, hi)) in ranges.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                if lo == hi {
                    out.extend_from_slice(format!("{lo}").as_bytes());
                } else {
                    out.extend_from_slice(format!("{lo}-{hi}").as_bytes());
                }
            }
        }
    }
}

/// The `Name` field escaping of `/proc/<pid>/status`: Linux renders
/// newline and backslash as two-byte escape sequences there
/// (`proc_task_name` with escaping, `fs/proc/array.c`); `stat` keeps
/// the raw bytes. Moved here from the procfs content crate at its
/// rename (Slice 2 S2-R4) so core renderers that cannot depend on
/// the extension crate share the one spelling.
pub fn escape_status_name(comm: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(comm.len());
    for byte in comm {
        match byte {
            b'\n' => escaped.extend_from_slice(b"\\n"),
            b'\\' => escaped.extend_from_slice(b"\\\\"),
            _ => escaped.push(*byte),
        }
    }
    escaped
}

/// Render a [`Status`] in the kernel's byte shape (`Label:\tvalue`
/// per line, in stored order).
pub fn render_status(status: &Status) -> Vec<u8> {
    let mut out = Vec::new();
    for line in &status.lines {
        match line {
            StatusLine::Known { label, value } => {
                out.extend_from_slice(label.name().as_bytes());
                out.extend_from_slice(b":\t");
                render_value(value, &mut out);
            }
            StatusLine::Unknown { label, value } => {
                out.extend_from_slice(label);
                out.extend_from_slice(b":\t");
                out.extend_from_slice(value);
            }
        }
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::escape_status_name;

    #[test]
    fn status_name_escaping() {
        assert_eq!(escape_status_name(b"bash"), b"bash");
        assert_eq!(escape_status_name(b"a\nb"), b"a\\nb");
        assert_eq!(escape_status_name(b"a\\b"), b"a\\\\b");
        assert_eq!(escape_status_name(b""), b"");
    }
}
