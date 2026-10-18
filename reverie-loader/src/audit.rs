/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The loader's and runtime's syscalls must all go through their declared
//! gate, the only instruction addresses the trap filter allows. This audit
//! checks a validated image for `syscall` encodings (`0f 05`) anywhere in
//! its executable mappings outside the gate ranges.
//!
//! It scans what a page-granular mapping exposes, not only `p_filesz`: the
//! file bytes up to the end of each executable segment's last file page.
//! Executable segments whose mappings are adjacent are scanned as one run,
//! so an encoding split across the boundary is found too.
//!
//! The scan is byte-wise, so it also counts `0f 05` pairs that straddle
//! instruction boundaries or sit inside other instructions' operands. That
//! over-approximates, which is the safe direction: an image with a false
//! positive is refused and relinked, never accepted with a stray site.

use core::ops::Range;

use crate::image::ImageError;
use crate::image::MAX_SEGMENTS;
use crate::image::Segment;
use crate::image::ValidatedImage;

/// The `syscall` instruction's encoding.
pub(crate) const SYSCALL: [u8; 2] = [0x0f, 0x05];

/// A `syscall` encoding found outside every gate range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StraySyscall {
    /// The address of the encoding's first byte.
    pub address: u64,
}

/// Returns the lowest-addressed `syscall` encoding in `image`'s executable
/// mappings that does not lie wholly (both bytes) inside one of `gates`, or
/// `None` if there
/// is none. An error means the audit could not be completed, never that the
/// image is clean.
pub fn stray_syscall(
    image: &ValidatedImage<'_>,
    gates: &[Range<u64>],
) -> Result<Option<StraySyscall>, ImageError> {
    let mut executable: [Option<&Segment>; MAX_SEGMENTS] = [None; MAX_SEGMENTS];
    let mut count = 0;
    for segment in image.segments().filter(|s| s.permissions.execute) {
        *executable
            .get_mut(count)
            .ok_or(ImageError::TooManySegments)? = Some(segment);
        count += 1;
    }
    let executable = &mut executable[..count];
    // Validation refuses empty and overlapping segments, so every start
    // address is distinct and the order is total.
    executable.sort_unstable_by_key(|segment| segment.map(|s| s.memory.start));

    let outside_gates = |address: u64| {
        !gates
            .iter()
            .any(|gate| gate.contains(&address) && address < gate.end.saturating_sub(1))
    };
    // The end of the previous executable mapping and its last byte.
    let mut previous: Option<(u64, u8)> = None;
    for segment in executable.iter().flatten() {
        let bytes = image.mapped_file_bytes(segment)?;
        let pages = segment.pages()?;
        if let (Some((end, last)), Some(&first)) = (previous, bytes.first())
            && end == pages.start
            && [last, first] == SYSCALL
            && outside_gates(end - 1)
        {
            return Ok(Some(StraySyscall { address: end - 1 }));
        }
        for (offset, pair) in bytes.windows(2).enumerate() {
            if pair != SYSCALL {
                continue;
            }
            let offset = u64::try_from(offset).map_err(|_| ImageError::Overflow)?;
            let address = pages
                .start
                .checked_add(offset)
                .ok_or(ImageError::Overflow)?;
            if outside_gates(address) {
                return Ok(Some(StraySyscall { address }));
            }
        }
        // Past the file bytes the mapping is zero-filled.
        let mapped = pages.end - pages.start;
        let last = match u64::try_from(bytes.len()) {
            Ok(len) if len == mapped => bytes.last().copied().unwrap_or(0),
            _ => 0,
        };
        previous = Some((pages.end, last));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use crate::image::tests::BASE;
    use crate::image::tests::build;
    use crate::image::tests::policy;

    const PT_LOAD: u32 = 1;
    const RX: u32 = 4 | 1;
    const RW: u32 = 4 | 2;

    fn audit(bytes: &[u8], gates: &[Range<u64>]) -> Option<StraySyscall> {
        let image = Image::parse(bytes).unwrap().validate(&policy()).unwrap();
        stray_syscall(&image, gates).unwrap()
    }

    #[test]
    fn a_syscall_inside_the_gate_is_allowed_and_one_outside_is_reported() {
        // nop; syscall; ret; ...; syscall
        let body = [0x90, 0x0f, 0x05, 0xc3, 0x90, 0x90, 0x0f, 0x05];
        let bytes = build(
            BASE,
            &[(PT_LOAD, RX, 4096, BASE, body.len() as u64, 64)],
            &body,
        );
        let gate = BASE + 1..BASE + 3;
        assert_eq!(
            audit(&bytes, core::slice::from_ref(&gate)),
            Some(StraySyscall { address: BASE + 6 })
        );
        // A gate holding only the first byte does not allow the encoding.
        let half = BASE + 6..BASE + 7;
        assert_eq!(
            audit(&bytes, &[gate.clone(), half]),
            Some(StraySyscall { address: BASE + 6 })
        );
        let both = [BASE + 1..BASE + 3, BASE + 6..BASE + 8];
        assert_eq!(audit(&bytes, &both), None);
    }

    #[test]
    fn file_bytes_after_filesz_on_the_last_page_are_scanned() {
        // p_filesz covers only the `ret`s; the encoding sits later on the
        // same file page, which a page-granular mapping exposes.
        let mut body = [0xc3u8; 128];
        body[100..102].copy_from_slice(&SYSCALL);
        let bytes = build(BASE, &[(PT_LOAD, RX, 4096, BASE, 8, 8)], &body);
        assert_eq!(
            audit(&bytes, &[]),
            Some(StraySyscall {
                address: BASE + 100
            })
        );
    }

    #[test]
    fn an_encoding_split_across_adjacent_executable_segments_is_reported() {
        let mut body = [0xc3u8; 4097];
        body[4095] = SYSCALL[0];
        body[4096] = SYSCALL[1];
        // Listed out of address order, to show the scan sorts them.
        let phdrs = [
            (PT_LOAD, RX, 8192, BASE + 0x1000, 1, 16),
            (PT_LOAD, RX, 4096, BASE, 4096, 4096),
        ];
        let bytes = build(BASE, &phdrs, &body);
        let found = Some(StraySyscall {
            address: BASE + 0xfff,
        });
        assert_eq!(audit(&bytes, &[]), found);
        let gate = BASE + 0xfff..BASE + 0x1001;
        assert_eq!(audit(&bytes, core::slice::from_ref(&gate)), None);

        // With a page between them, nothing executes across the boundary.
        let apart = [
            (PT_LOAD, RX, 4096, BASE, 4096, 4096),
            (PT_LOAD, RX, 8192, BASE + 0x2000, 1, 16),
        ];
        let bytes = build(BASE, &apart, &body);
        assert_eq!(audit(&bytes, &[]), None);
    }

    #[test]
    fn an_empty_segment_cannot_hide_a_split_encoding() {
        // An empty executable segment at the boundary would reset the
        // remembered last byte; validation refuses it, in either header
        // order, so the audit never sees such an image.
        let mut body = [0xc3u8; 4097];
        body[4095] = SYSCALL[0];
        body[4096] = SYSCALL[1];
        let first = (PT_LOAD, RX, 4096, BASE, 4096, 4096);
        let empty = (PT_LOAD, RX, 8192, BASE + 0x1000, 0, 0);
        let second = (PT_LOAD, RX, 8192, BASE + 0x1000, 1, 16);
        for (phdrs, index) in [([first, empty, second], 1), ([first, second, empty], 2)] {
            let bytes = build(BASE, &phdrs, &body);
            assert_eq!(
                Image::parse(&bytes).unwrap().validate(&policy()),
                Err(ImageError::EmptySegment { index })
            );
        }
    }

    #[test]
    fn non_executable_segments_are_not_scanned() {
        // The executable page holds only `ret`s; the data segment's first
        // file bytes hold a syscall encoding.
        let mut body = [0xc3u8; 4098];
        body[4096..4098].copy_from_slice(&SYSCALL);
        let bytes = build(
            BASE,
            &[
                (PT_LOAD, RX, 4096, BASE, 8, 8),
                (PT_LOAD, RW, 8192, BASE + 0x1000, 2, 16),
            ],
            &body,
        );
        assert_eq!(audit(&bytes, &[]), None);
    }
}
