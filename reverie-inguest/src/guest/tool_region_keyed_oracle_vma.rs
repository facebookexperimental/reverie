/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Complete native kernel VMA/key coverage supplements the physical oracle.
//! Scan errors/key mismatches are recorded; they never skip the target MOVs.
//! The raw-fork leader streams smaps with fixed storage and no libc allocation.

use super::BASE;
use super::END;
use super::OwnerSnapshot;
use super::PAGE;
use super::Span;
use super::guards;
use super::raw;

const TARGETS: usize = 14; // 4 interiors, 8 guards, key-zero report and observer.
const SCAN_LIMIT: u64 = 8 * 1024 * 1024;
const GAP: u32 = 1;
const BAD_PERMISSION: u32 = 2;
const BAD_KEY: u32 = 4;
const MISSING_KEY: u32 = 8;
const CROSSED_INTERIOR: u32 = 16;
const BAD_PARSE: u32 = 32;
const INCOMPLETE: u32 = 64;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(super) struct Coverage {
    pub scan_errno: i32,
    pub errors: u32,
    pub bytes_read: u64,
    pub vmas_in_reservation: u32,
    pub reserved: u32,
    pub reservation_next: usize,
    pub target_next: [usize; TARGETS],
    pub target_end: [usize; TARGETS],
}

impl Coverage {
    pub(super) fn qualified(&self) -> bool {
        self.scan_errno == 0
            && self.errors == 0
            && self.reservation_next == END
            && self.target_next == self.target_end
    }
}

#[derive(Clone, Copy)]
struct Entry {
    span: Span,
    permissions: [u8; 4],
    key: u32,
    key_seen: bool,
}

fn number(bytes: &[u8], radix: usize) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0_usize;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => usize::from(byte - b'0'),
            b'a'..=b'f' if radix == 16 => usize::from(byte - b'a' + 10),
            b'A'..=b'F' if radix == 16 => usize::from(byte - b'A' + 10),
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        value = value.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(value)
}

fn header(line: &[u8]) -> Option<Entry> {
    let dash = line.iter().position(|byte| *byte == b'-')?;
    let blank = line.iter().position(|byte| *byte == b' ')?;
    if dash >= blank || blank + 5 > line.len() {
        return None;
    }
    let bottom = number(&line[..dash], 16)?;
    let top = number(&line[dash + 1..blank], 16)?;
    if bottom >= top {
        return None;
    }
    Some(Entry {
        span: Span { bottom, top },
        permissions: [
            line[blank + 1],
            line[blank + 2],
            line[blank + 3],
            line[blank + 4],
        ],
        key: 0,
        key_seen: false,
    })
}

fn overlap(a: Span, b: Span) -> Option<Span> {
    let bottom = a.bottom.max(b.bottom);
    let top = a.top.min(b.top);
    (bottom < top).then_some(Span { bottom, top })
}

fn accept(
    entry: Entry,
    owner: &OwnerSnapshot,
    targets: &[Span; TARGETS],
    owned_key: u32,
    result: &mut Coverage,
) {
    if let Some(part) = overlap(
        entry.span,
        Span {
            bottom: BASE,
            top: END,
        },
    ) {
        result.vmas_in_reservation += 1;
        if part.bottom != result.reservation_next {
            result.errors |= GAP;
        }
        result.reservation_next = part.top;
        let mut interior = false;
        for span in owner.interiors {
            if overlap(part, span).is_some() {
                interior = true;
                if part.bottom < span.bottom || part.top > span.top {
                    result.errors |= CROSSED_INTERIOR;
                }
            }
        }
        let expected_permissions = if interior { *b"rw-p" } else { *b"---p" };
        let expected_key = if interior { owned_key } else { 0 };
        if entry.permissions != expected_permissions {
            result.errors |= BAD_PERMISSION;
        }
        if !entry.key_seen {
            result.errors |= MISSING_KEY;
        } else if entry.key != expected_key {
            result.errors |= BAD_KEY;
        }
    }
    for (index, target) in targets.iter().enumerate() {
        let Some(part) = overlap(entry.span, *target) else {
            continue;
        };
        if part.bottom != result.target_next[index] {
            result.errors |= GAP;
        }
        result.target_next[index] = part.top;
        let expected_permissions = if index < 4 || index == 13 {
            *b"rw-p"
        } else if index == 12 {
            *b"rw-s"
        } else {
            *b"---p"
        };
        let expected_key = if index < 4 { owned_key } else { 0 };
        if entry.permissions != expected_permissions {
            result.errors |= BAD_PERMISSION;
        }
        if !entry.key_seen {
            result.errors |= MISSING_KEY;
        } else if entry.key != expected_key {
            result.errors |= BAD_KEY;
        }
    }
}

fn line(
    bytes: &[u8],
    current: &mut Option<Entry>,
    owner: &OwnerSnapshot,
    targets: &[Span; TARGETS],
    key: u32,
    result: &mut Coverage,
) {
    if let Some(next) = header(bytes) {
        if let Some(previous) = current.replace(next) {
            accept(previous, owner, targets, key, result);
        }
        return;
    }
    if let Some(value) = bytes.strip_prefix(b"ProtectionKey:") {
        let start = value.iter().position(|byte| !byte.is_ascii_whitespace());
        let end = value.iter().rposition(|byte| !byte.is_ascii_whitespace());
        let parsed = match (start, end) {
            (Some(start), Some(end)) => number(&value[start..=end], 10),
            _ => None,
        };
        if let (Some(entry), Some(parsed)) = (current.as_mut(), parsed) {
            if parsed <= 15 {
                entry.key = parsed as u32;
                entry.key_seen = true;
                return;
            }
        }
        result.errors |= BAD_PARSE;
    }
}

pub(super) fn inspect(
    owner: &OwnerSnapshot,
    output: Span,
    observer: Span,
    owned_key: u32,
) -> Coverage {
    let empty = Span { bottom: 0, top: 0 };
    let mut targets = [empty; TARGETS];
    targets[..4].copy_from_slice(&owner.interiors);
    for (index, address) in guards(owner).iter().enumerate() {
        targets[4 + index] = Span {
            bottom: *address,
            top: *address + PAGE,
        };
    }
    targets[12] = output;
    targets[13] = observer;
    let mut result = Coverage {
        scan_errno: 0,
        errors: 0,
        bytes_read: 0,
        vmas_in_reservation: 0,
        reserved: 0,
        reservation_next: BASE,
        target_next: [0; TARGETS],
        target_end: [0; TARGETS],
    };
    for (index, target) in targets.iter().enumerate() {
        result.target_next[index] = target.bottom;
        result.target_end[index] = target.top;
    }
    let path = b"/proc/self/smaps\0";
    let fd = raw(
        libc::SYS_openat,
        [
            libc::AT_FDCWD as i64 as u64,
            path.as_ptr() as u64,
            (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            0,
            0,
            0,
        ],
    );
    if fd < 0 {
        result.scan_errno = -fd as i32;
        return result;
    }
    let mut input = [0_u8; 4096];
    // A header's entire address/permissions prefix and a ProtectionKey field
    // fit here. File/path text is intentionally not an input to a predicate.
    // Every byte/line is streamed to EOF; no VMA section is silently omitted.
    let mut prefix = [0_u8; 256];
    let mut length = 0;
    let mut current = None;
    loop {
        let count = raw(
            libc::SYS_read,
            [
                fd as u64,
                input.as_mut_ptr() as u64,
                input.len() as u64,
                0,
                0,
                0,
            ],
        );
        if count == -i64::from(libc::EINTR) {
            continue;
        }
        if count < 0 {
            result.scan_errno = -count as i32;
            break;
        }
        if count == 0 {
            if length != 0 {
                line(
                    &prefix[..length],
                    &mut current,
                    owner,
                    &targets,
                    owned_key,
                    &mut result,
                );
            }
            if let Some(previous) = current {
                accept(previous, owner, &targets, owned_key, &mut result);
            }
            break;
        }
        result.bytes_read += count as u64;
        if count as usize > input.len() || result.bytes_read > SCAN_LIMIT {
            result.scan_errno = libc::EOVERFLOW;
            break;
        }
        for byte in &input[..count as usize] {
            if *byte == b'\n' {
                line(
                    &prefix[..length],
                    &mut current,
                    owner,
                    &targets,
                    owned_key,
                    &mut result,
                );
                length = 0;
            } else if length < prefix.len() {
                prefix[length] = *byte;
                length += 1;
            }
        }
    }
    let closed = raw(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]);
    if closed != 0 && result.scan_errno == 0 {
        result.scan_errno = -closed as i32;
    }
    if result.reservation_next != END || result.target_next != result.target_end {
        result.errors |= INCOMPLETE;
    }
    result
}
