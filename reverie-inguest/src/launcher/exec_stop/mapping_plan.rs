// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Private numeric mapping operations. A plan is not a reservation, a completed
//! mapping ledger, source qualification or permission to execute an image.

use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::image::PAGE_SIZE;
use reverie_loader::image::ValidatedImage;

use super::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    ImageFile,
    ImageAnonymous,
    #[cfg(feature = "loader-private-runtime")]
    StorageAnonymous,
    #[cfg(feature = "loader-private-runtime")]
    Handoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mapping {
    pub start: u64,
    pub length: u64,
    pub protection: i32,
    pub flags: i32,
    pub offset: u64,
    pub source: Source,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Map(Mapping),
    ZeroTail { start: u64, length: usize },
}

// Also used at the actual mmap call and successful ledger insertion. Plans do
// not append observations; the executor must first observe the exact return.
pub(super) fn effective_flags(flags: i32) -> i32 {
    flags | libc::MAP_FIXED
}

pub(super) fn mapping_row(
    start: u64,
    length: u64,
    protection: i32,
    flags: i32,
) -> Result<[u64; 4]> {
    Ok([
        start,
        start.checked_add(length).ok_or("mapping overflow")?,
        protection as u64,
        effective_flags(flags) as u64,
    ])
}

fn map(mapping: Mapping) -> Result<Step> {
    if mapping.length == 0
        || !mapping.start.is_multiple_of(PAGE_SIZE)
        || !mapping.length.is_multiple_of(PAGE_SIZE)
        || mapping.start < TOOL_REGION.start
        || mapping
            .start
            .checked_add(mapping.length)
            .is_none_or(|end| end > TOOL_REGION.end)
    {
        return Err("loader refused: mapping does not belong to its fresh reservation".into());
    }
    if mapping.protection & libc::PROT_WRITE != 0 && mapping.protection & libc::PROT_EXEC != 0 {
        return Err("loader refused: writable executable mapping".into());
    }
    if mapping.flags & !(libc::MAP_PRIVATE | libc::MAP_SHARED | libc::MAP_ANONYMOUS) != 0
        || (mapping.flags & (libc::MAP_PRIVATE | libc::MAP_SHARED)).count_ones() != 1
    {
        return Err("loader refused: unsupported bootstrap mapping flags".into());
    }
    Ok(Step::Map(mapping))
}

/// Sorted proposed rows only: no reservation/zero-write rows or kernel claims.
pub(super) fn planned_ledger(steps: &[Step]) -> Result<Vec<[u64; 4]>> {
    let mut rows = Vec::new();
    for step in steps {
        if let Step::Map(mapping) = step {
            rows.push(mapping_row(
                mapping.start,
                mapping.length,
                mapping.protection,
                mapping.flags,
            )?);
        }
    }
    rows.sort_unstable_by_key(|row| row[0]);
    for pair in rows.windows(2) {
        if pair[0][1] > pair[1][0] {
            return Err("loader refused: mapping overlaps a live bootstrap mapping".into());
        }
    }
    Ok(rows)
}

/// Keep program-header order, then each load's file map, anonymous map and
/// private-page zero write. Validation still comes from the actual ELF parser.
pub(super) fn image_steps(image: &ValidatedImage<'_>) -> Result<Vec<Step>> {
    let mut steps = Vec::new();
    for segment in image.segments() {
        let pages = segment.pages().map_err(|e| format!("segment: {e:?}"))?;
        let permissions = segment.permissions;
        let protection = (if permissions.read { libc::PROT_READ } else { 0 })
            | (if permissions.write {
                libc::PROT_WRITE
            } else {
                0
            })
            | (if permissions.execute {
                libc::PROT_EXEC
            } else {
                0
            });
        let file_bytes = segment
            .file
            .end
            .checked_sub(segment.file.start)
            .ok_or("mapping overflow")?;
        let file_pages = file_bytes
            .div_ceil(PAGE_SIZE)
            .checked_mul(PAGE_SIZE)
            .ok_or("mapping overflow")?;
        if file_pages != 0 {
            steps.push(map(Mapping {
                start: pages.start,
                length: file_pages,
                protection,
                flags: libc::MAP_PRIVATE,
                offset: segment.file.start,
                source: Source::ImageFile,
            })?);
        }
        let memory_pages = pages
            .end
            .checked_sub(pages.start)
            .ok_or("mapping overflow")?;
        if memory_pages > file_pages {
            steps.push(map(Mapping {
                start: pages
                    .start
                    .checked_add(file_pages)
                    .ok_or("mapping overflow")?,
                length: memory_pages - file_pages,
                protection,
                flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                offset: 0,
                source: Source::ImageAnonymous,
            })?);
        }
        if file_bytes != file_pages {
            steps.push(Step::ZeroTail {
                start: pages
                    .start
                    .checked_add(file_bytes)
                    .ok_or("mapping overflow")?,
                length: usize::try_from(file_pages - file_bytes)?,
            });
        }
    }
    planned_ledger(&steps)?;
    Ok(steps)
}

#[cfg(feature = "loader-private-runtime")]
pub(super) fn interior(
    role: reverie_loader::handoff::Extent,
) -> Result<reverie_loader::handoff::Extent> {
    let start = role.start.checked_add(4096).ok_or("mapped_role_overflow")?;
    let end = role.end.checked_sub(4096).ok_or("mapped_role_underflow")?;
    if start >= end {
        return Err("mapped_role_empty".into());
    }
    Ok(reverie_loader::handoff::Extent { start, end })
}

/// The allocator control prefix and five roles follow the image. Guards remain
/// in the PROT_NONE reservation;
/// only the handoff interior is backed by the real sealed handoff descriptor.
#[cfg(feature = "loader-private-runtime")]
pub(super) fn production_steps(
    image: &ValidatedImage<'_>,
    roles: [reverie_loader::handoff::Extent; 5],
) -> Result<Vec<Step>> {
    let mut steps = image_steps(image)?;
    // The genuine allocator adoption reads its entire pristine control prefix
    // before publishing ToolRegion. It is separate from the five live roles.
    // Use the owner's geometry, never caller-selected metadata coordinates.
    let prefix = crate::guest::tool_region::scalar_control_prefix();
    let free = crate::guest::tool_region::scalar_free_band();
    if prefix.start != TOOL_REGION.start + PAGE_SIZE || prefix.end > free.start {
        return Err("mapped_allocator_control_geometry".into());
    }
    steps.push(map(Mapping {
        start: prefix.start,
        length: prefix
            .end
            .checked_sub(prefix.start)
            .ok_or("mapped_allocator_control_geometry")?,
        protection: libc::PROT_READ | libc::PROT_WRITE,
        flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        offset: 0,
        source: Source::StorageAnonymous,
    })?);
    for (index, role) in roles.into_iter().enumerate() {
        let role = interior(role)?;
        let is_handoff = index == 3;
        steps.push(map(Mapping {
            start: role.start,
            length: role
                .end
                .checked_sub(role.start)
                .ok_or("mapped_role_underflow")?,
            protection: if is_handoff {
                libc::PROT_READ
            } else {
                libc::PROT_READ | libc::PROT_WRITE
            },
            flags: if is_handoff {
                libc::MAP_PRIVATE
            } else {
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS
            },
            offset: 0,
            source: if is_handoff {
                Source::Handoff
            } else {
                Source::StorageAnonymous
            },
        })?);
    }
    planned_ledger(&steps)?;
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use reverie_loader::artifact::RUNTIME_WINDOW;
    use reverie_loader::image::Image;
    use reverie_loader::image::Policy;

    use super::*;

    // A literal ELF fixture, passed through the real public parser/validator.
    // Each tuple is flags, file offset, virtual address, filesz, memsz.
    fn elf(loads: &[(u32, u64, u64, u64, u64)], entry: u64) -> Vec<u8> {
        let size = loads
            .iter()
            .map(|load| load.1 + load.3)
            .max()
            .unwrap()
            .max(4096);
        let mut bytes = vec![0; usize::try_from(size).unwrap()];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&u16::try_from(loads.len()).unwrap().to_le_bytes());
        for (i, &(flags, offset, address, file, memory)) in loads.iter().enumerate() {
            let at = 64 + i * 56;
            bytes[at..at + 4].copy_from_slice(&1_u32.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            for (relative, value) in [
                (8, offset),
                (16, address),
                (32, file),
                (40, memory),
                (48, 4096),
            ] {
                bytes[at + relative..at + relative + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    fn plan(bytes: &[u8]) -> Vec<Step> {
        let parsed = Image::parse(bytes).unwrap();
        let image = parsed
            .validate(&Policy {
                window: RUNTIME_WINDOW,
                allow_tls: true,
            })
            .unwrap();
        image_steps(&image).unwrap()
    }

    #[test]
    fn partial_file_then_anonymous_tail_then_zero_preserves_load_order() {
        let base = RUNTIME_WINDOW.start;
        // Deliberately descending virtual-address order in program headers.
        let bytes = elf(
            &[
                (6, 4096, base + 0x10000, 17, 8193),
                (5, 8192, base, 4096, 4096),
            ],
            base,
        );
        let steps = plan(&bytes);
        assert_eq!(
            steps,
            vec![
                Step::Map(Mapping {
                    start: base + 0x10000,
                    length: 4096,
                    protection: 3,
                    flags: libc::MAP_PRIVATE,
                    offset: 4096,
                    source: Source::ImageFile
                }),
                Step::Map(Mapping {
                    start: base + 0x11000,
                    length: 8192,
                    protection: 3,
                    flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    offset: 0,
                    source: Source::ImageAnonymous
                }),
                Step::ZeroTail {
                    start: base + 0x10011,
                    length: 4079
                },
                Step::Map(Mapping {
                    start: base,
                    length: 4096,
                    protection: 5,
                    flags: libc::MAP_PRIVATE,
                    offset: 8192,
                    source: Source::ImageFile
                }),
            ]
        );
        assert_eq!(
            planned_ledger(&steps).unwrap(),
            vec![
                [
                    base,
                    base + 4096,
                    5,
                    (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64
                ],
                [
                    base + 0x10000,
                    base + 0x11000,
                    3,
                    (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64
                ],
                [
                    base + 0x11000,
                    base + 0x13000,
                    3,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64
                ],
            ]
        );
    }

    #[test]
    fn empty_file_load_is_only_anonymous_and_exact_page_has_no_zero_step() {
        let base = RUNTIME_WINDOW.start;
        let bytes = elf(
            &[(5, 4096, base, 4096, 4096), (6, 8192, base + 0x2000, 0, 1)],
            base,
        );
        assert_eq!(
            plan(&bytes),
            vec![
                Step::Map(Mapping {
                    start: base,
                    length: 4096,
                    protection: 5,
                    flags: libc::MAP_PRIVATE,
                    offset: 4096,
                    source: Source::ImageFile
                }),
                Step::Map(Mapping {
                    start: base + 0x2000,
                    length: 4096,
                    protection: 3,
                    flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    offset: 0,
                    source: Source::ImageAnonymous
                }),
            ]
        );
    }

    #[test]
    fn invalid_real_elf_never_becomes_a_plan() {
        use reverie_loader::image::ImageError;
        let base = RUNTIME_WINDOW.start;
        for (loads, expected) in [
            (
                vec![(7, 4096, base, 16, 16)],
                ImageError::WritableAndExecutable { index: 0 },
            ),
            (
                vec![(5, 4096, base, 16, 4097), (6, 8192, base + 4096, 16, 16)],
                ImageError::Overlapping {
                    first: 0,
                    second: 1,
                },
            ),
        ] {
            let bytes = elf(&loads, base);
            let parsed = Image::parse(&bytes).unwrap();
            assert_eq!(
                parsed
                    .validate(&Policy {
                        window: RUNTIME_WINDOW,
                        allow_tls: true
                    })
                    .unwrap_err(),
                expected
            );
        }
    }

    #[cfg(feature = "loader-private-runtime")]
    #[test]
    fn five_role_maps_keep_guards_and_only_handoff_is_file_backed() {
        use reverie_loader::handoff::Extent;
        let base = RUNTIME_WINDOW.start;
        let bytes = elf(&[(5, 4096, base, 4096, 4096)], base);
        let parsed = Image::parse(&bytes).unwrap();
        let image = parsed
            .validate(&Policy {
                window: RUNTIME_WINDOW,
                allow_tls: true,
            })
            .unwrap();
        let data = crate::guest::tool_region::scalar_free_band().start;
        let roles = core::array::from_fn(|i| Extent {
            start: data + i as u64 * 0x4000,
            end: data + i as u64 * 0x4000 + 0x3000,
        });
        let steps = production_steps(&image, roles).unwrap();
        assert_eq!(steps.len(), 7);
        let prefix = crate::guest::tool_region::scalar_control_prefix();
        assert_eq!(prefix.start, TOOL_REGION.start + 4096);
        assert_eq!(prefix.end, TOOL_REGION.start + 0x24000);
        assert!(prefix.end < data);
        assert_eq!(
            steps[1],
            Step::Map(Mapping {
                start: prefix.start,
                length: 0x23000,
                protection: libc::PROT_READ | libc::PROT_WRITE,
                flags: libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                offset: 0,
                source: Source::StorageAnonymous,
            })
        );
        for (i, step) in steps[2..].iter().enumerate() {
            let Step::Map(mapping) = step else {
                panic!("role was not a map")
            };
            assert_eq!(mapping.start, data + i as u64 * 0x4000 + 4096);
            assert_eq!(mapping.length, 4096);
            assert_eq!(mapping.offset, 0);
            assert_eq!(
                (mapping.protection, mapping.flags, mapping.source),
                if i == 3 {
                    (1, libc::MAP_PRIVATE, Source::Handoff)
                } else {
                    (
                        3,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        Source::StorageAnonymous,
                    )
                }
            );
        }
        let ledger = planned_ledger(&steps).unwrap();
        assert_eq!(ledger.len(), 7);
        assert_eq!(
            ledger[0],
            [
                prefix.start,
                prefix.end,
                3,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64
            ]
        );
        assert_eq!(ledger.last().unwrap()[0], base);
        assert_eq!(
            steps[0],
            Step::Map(Mapping {
                start: base,
                length: 4096,
                protection: 5,
                flags: libc::MAP_PRIVATE,
                offset: 4096,
                source: Source::ImageFile
            })
        );
    }

    #[cfg(feature = "loader-private-runtime")]
    #[test]
    fn malformed_roles_and_collision_are_exact_numeric_refusals() {
        use reverie_loader::handoff::Extent;
        assert_eq!(
            interior(Extent {
                start: u64::MAX,
                end: u64::MAX
            })
            .unwrap_err()
            .to_string(),
            "mapped_role_overflow"
        );
        assert_eq!(
            interior(Extent { start: 0, end: 1 })
                .unwrap_err()
                .to_string(),
            "mapped_role_underflow"
        );
        assert_eq!(
            interior(Extent {
                start: 0,
                end: 8192
            })
            .unwrap_err()
            .to_string(),
            "mapped_role_empty"
        );
        let base = RUNTIME_WINDOW.start;
        let bytes = elf(&[(5, 4096, base, 4096, 4096)], base);
        let parsed = Image::parse(&bytes).unwrap();
        let image = parsed
            .validate(&Policy {
                window: RUNTIME_WINDOW,
                allow_tls: true,
            })
            .unwrap();
        let roles = [Extent {
            start: base - 4096,
            end: base + 8192,
        }; 5];
        assert_eq!(
            production_steps(&image, roles).unwrap_err().to_string(),
            "loader refused: mapping overlaps a live bootstrap mapping"
        );
        assert_eq!(
            mapping_row(u64::MAX, 1, 1, libc::MAP_PRIVATE)
                .unwrap_err()
                .to_string(),
            "mapping overflow"
        );
    }
}
