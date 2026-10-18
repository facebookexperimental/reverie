/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Validation of the images the loader maps: the loader itself and Hermit's
//! runtime. Both are linked at fixed addresses inside Hermit's reserved
//! region, so mapping them needs no relocation and cannot move the guest's
//! own layout.
//!
//! [`Image::parse`] reads the ELF64 header and program headers with checked
//! arithmetic only, and [`Image::validate`] applies a [`Policy`]. Only
//! validation produces a [`ValidatedImage`], so code that needs a checked
//! image (the syscall audit, the mapper) cannot be handed an unchecked one.
//! Every failure is a distinct [`ImageError`], so a refusal names what is
//! wrong.

use core::ops::Range;

/// The page size the loader maps with.
pub const PAGE_SIZE: u64 = 4096;

/// The most loadable segments an image may have. The loader and runtime
/// have a handful; a bound keeps parsing allocation-free.
pub const MAX_SEGMENTS: usize = 16;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
/// `e_phnum` value meaning the real count is in section header 0.
const PN_XNUM: u16 = 0xffff;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Why an image was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// The bytes end before a header or table they claim to contain.
    Truncated,
    /// Not an ELF file.
    NotElf,
    /// Not ELF64, little-endian, version 1.
    UnsupportedIdent,
    /// Not `ET_EXEC`: the loader maps fixed-address images only.
    NotFixedAddress,
    /// Not x86-64.
    WrongMachine,
    /// The program-header entry size is not the ELF64 size.
    BadProgramHeaderSize,
    /// The image uses extended program-header numbering (`e_phnum` is
    /// `PN_XNUM`), which the loader does not support.
    ExtendedNumbering,
    /// More loadable segments than [`MAX_SEGMENTS`].
    TooManySegments,
    /// The image names an interpreter (`PT_INTERP`).
    HasInterpreter,
    /// The image has a dynamic section (`PT_DYNAMIC`), so it may carry
    /// dynamic relocations.
    HasDynamicSection,
    /// The image has a TLS segment, which the policy forbids.
    HasTls,
    /// The image has no loadable segment.
    NoLoadSegment,
    /// A loadable segment's file extent lies outside the file.
    SegmentOutsideFile {
        /// Index of the program header.
        index: usize,
    },
    /// A loadable segment occupies no memory. It would map nothing, and the
    /// loader's images have no reason to contain one.
    EmptySegment {
        /// Index of the program header.
        index: usize,
    },
    /// A loadable segment's file size exceeds its memory size.
    FileSizeExceedsMemorySize {
        /// Index of the program header.
        index: usize,
    },
    /// A loadable segment's address or file offset is not page-aligned, or
    /// its `p_align` is not a power of two of at least [`PAGE_SIZE`], or the
    /// address and offset are not congruent modulo `p_align`.
    Misaligned {
        /// Index of the program header.
        index: usize,
    },
    /// A loadable segment is both writable and executable.
    WritableAndExecutable {
        /// Index of the program header.
        index: usize,
    },
    /// A loadable segment lies, after page rounding, outside the policy's
    /// window.
    OutsideWindow {
        /// Index of the program header.
        index: usize,
    },
    /// Two loadable segments overlap after page rounding.
    Overlapping {
        /// Index of the earlier program header.
        first: usize,
        /// Index of the later program header.
        second: usize,
    },
    /// The entry point is not inside an executable loadable segment.
    EntryNotExecutable,
    /// An address computation overflowed.
    Overflow,
}

/// What a loadable segment may do once mapped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Permissions {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

impl Permissions {
    fn from_flags(flags: u32) -> Self {
        Self {
            read: flags & PF_R != 0,
            write: flags & PF_W != 0,
            execute: flags & PF_X != 0,
        }
    }
}

/// One `PT_LOAD` segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Index of its program header.
    pub index: usize,
    /// The addresses it occupies in memory, before page rounding.
    pub memory: Range<u64>,
    /// The bytes of the file it is initialized from; the rest of `memory` is
    /// zero.
    pub file: Range<u64>,
    /// Its `p_align`.
    pub align: u64,
    /// Its permissions.
    pub permissions: Permissions,
}

impl Segment {
    /// The page-rounded addresses the segment's mapping covers.
    pub fn pages(&self) -> Result<Range<u64>, ImageError> {
        let start = self.memory.start & !(PAGE_SIZE - 1);
        let end = round_up(self.memory.end)?;
        Ok(start..end)
    }
}

/// The policy an image must meet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Every page of every loadable segment must lie inside this window.
    pub window: Range<u64>,
    /// Whether a TLS segment is allowed. The loader allows none; the runtime
    /// may have one, on its own FS base.
    pub allow_tls: bool,
}

/// A parsed image: its entry point and loadable segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image<'a> {
    bytes: &'a [u8],
    entry: u64,
    segments: [Option<Segment>; MAX_SEGMENTS],
    segment_count: usize,
    has_interpreter: bool,
    has_dynamic: bool,
    has_tls: bool,
}

impl<'a> Image<'a> {
    /// Parses the ELF64 header and program headers of `bytes`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ImageError> {
        let header = bytes.get(..EHDR_SIZE).ok_or(ImageError::Truncated)?;
        if header[..4] != ELF_MAGIC {
            return Err(ImageError::NotElf);
        }
        if header[4] != ELFCLASS64 || header[5] != ELFDATA2LSB || header[6] != EV_CURRENT {
            return Err(ImageError::UnsupportedIdent);
        }
        if read_u16(header, 16)? != ET_EXEC {
            return Err(ImageError::NotFixedAddress);
        }
        if read_u16(header, 18)? != EM_X86_64 {
            return Err(ImageError::WrongMachine);
        }
        let entry = read_u64(header, 24)?;
        let phoff = usize::try_from(read_u64(header, 32)?).map_err(|_| ImageError::Overflow)?;
        if usize::from(read_u16(header, 54)?) != PHDR_SIZE {
            return Err(ImageError::BadProgramHeaderSize);
        }
        let phnum = read_u16(header, 56)?;
        if phnum == PN_XNUM {
            return Err(ImageError::ExtendedNumbering);
        }
        let phnum = usize::from(phnum);
        let table_len = phnum.checked_mul(PHDR_SIZE).ok_or(ImageError::Overflow)?;
        let table_end = phoff.checked_add(table_len).ok_or(ImageError::Overflow)?;
        let table = bytes.get(phoff..table_end).ok_or(ImageError::Truncated)?;

        let mut image = Self {
            bytes,
            entry,
            segments: Default::default(),
            segment_count: 0,
            has_interpreter: false,
            has_dynamic: false,
            has_tls: false,
        };
        for (index, header) in table.as_chunks::<PHDR_SIZE>().0.iter().enumerate() {
            match read_u32(header, 0)? {
                PT_LOAD => image.push_load(index, header)?,
                PT_INTERP => image.has_interpreter = true,
                PT_DYNAMIC => image.has_dynamic = true,
                PT_TLS => image.has_tls = true,
                _ => {}
            }
        }
        Ok(image)
    }

    fn push_load(&mut self, index: usize, header: &[u8]) -> Result<(), ImageError> {
        let flags = read_u32(header, 4)?;
        let offset = read_u64(header, 8)?;
        let vaddr = read_u64(header, 16)?;
        let filesz = read_u64(header, 32)?;
        let memsz = read_u64(header, 40)?;
        let align = read_u64(header, 48)?;
        let slot = self
            .segments
            .get_mut(self.segment_count)
            .ok_or(ImageError::TooManySegments)?;
        *slot = Some(Segment {
            index,
            memory: vaddr..vaddr.checked_add(memsz).ok_or(ImageError::Overflow)?,
            file: offset..offset.checked_add(filesz).ok_or(ImageError::Overflow)?,
            align,
            permissions: Permissions::from_flags(flags),
        });
        self.segment_count += 1;
        Ok(())
    }

    /// The entry point.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// The loadable segments, in program-header order.
    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments[..self.segment_count].iter().flatten()
    }

    /// Checks the image against `policy`. On success every segment lies in
    /// the file and in the window, is non-empty and page-aligned, is not
    /// writable and executable, and overlaps no other, and the entry point is
    /// executable.
    pub fn validate(&self, policy: &Policy) -> Result<ValidatedImage<'a>, ImageError> {
        if self.has_interpreter {
            return Err(ImageError::HasInterpreter);
        }
        if self.has_dynamic {
            return Err(ImageError::HasDynamicSection);
        }
        if self.has_tls && !policy.allow_tls {
            return Err(ImageError::HasTls);
        }
        if self.segment_count == 0 {
            return Err(ImageError::NoLoadSegment);
        }
        let file_len = u64::try_from(self.bytes.len()).map_err(|_| ImageError::Overflow)?;
        for segment in self.segments() {
            let index = segment.index;
            if segment.file.end > file_len {
                return Err(ImageError::SegmentOutsideFile { index });
            }
            if segment.file.end - segment.file.start > segment.memory.end - segment.memory.start {
                return Err(ImageError::FileSizeExceedsMemorySize { index });
            }
            if segment.memory.is_empty() {
                return Err(ImageError::EmptySegment { index });
            }
            let align_ok = segment.align.is_power_of_two()
                && segment.align >= PAGE_SIZE
                && segment.memory.start % segment.align == segment.file.start % segment.align;
            if segment.memory.start % PAGE_SIZE != 0
                || segment.file.start % PAGE_SIZE != 0
                || !align_ok
            {
                return Err(ImageError::Misaligned { index });
            }
            if segment.permissions.write && segment.permissions.execute {
                return Err(ImageError::WritableAndExecutable { index });
            }
            let pages = segment.pages()?;
            if pages.start < policy.window.start || pages.end > policy.window.end {
                return Err(ImageError::OutsideWindow { index });
            }
        }
        for (position, earlier) in self.segments().enumerate() {
            let earlier_pages = earlier.pages()?;
            for later in self.segments().skip(position + 1) {
                let later_pages = later.pages()?;
                if earlier_pages.start < later_pages.end && later_pages.start < earlier_pages.end {
                    return Err(ImageError::Overlapping {
                        first: earlier.index,
                        second: later.index,
                    });
                }
            }
        }
        let executable_entry = self
            .segments()
            .any(|segment| segment.permissions.execute && segment.memory.contains(&self.entry));
        if !executable_entry {
            return Err(ImageError::EntryNotExecutable);
        }
        Ok(ValidatedImage(self.clone()))
    }
}

/// An image that has passed [`Image::validate`]. Only validation constructs
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedImage<'a>(Image<'a>);

impl<'a> ValidatedImage<'a> {
    /// The entry point.
    pub fn entry(&self) -> u64 {
        self.0.entry
    }

    /// The loadable segments, in program-header order.
    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.0.segments()
    }

    /// The file bytes a page-granular mapping of `segment` exposes: from its
    /// page-aligned file offset up to its file size rounded up to a page,
    /// clipped to the end of the file. This includes any file bytes after
    /// `p_filesz` that share the segment's last page.
    pub fn mapped_file_bytes(&self, segment: &Segment) -> Result<&'a [u8], ImageError> {
        let index = segment.index;
        let size = segment
            .file
            .end
            .checked_sub(segment.file.start)
            .ok_or(ImageError::Overflow)?;
        let end = segment
            .file
            .start
            .checked_add(round_up(size)?)
            .ok_or(ImageError::Overflow)?;
        let file_len = u64::try_from(self.0.bytes.len()).map_err(|_| ImageError::Overflow)?;
        let start = usize::try_from(segment.file.start).map_err(|_| ImageError::Overflow)?;
        let end = usize::try_from(end.min(file_len)).map_err(|_| ImageError::Overflow)?;
        self.0
            .bytes
            .get(start..end)
            .ok_or(ImageError::SegmentOutsideFile { index })
    }
}

fn round_up(address: u64) -> Result<u64, ImageError> {
    address
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or(ImageError::Overflow)
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16, ImageError> {
    let field = bytes.get(at..at + 2).ok_or(ImageError::Truncated)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, ImageError> {
    let field = bytes.get(at..at + 4).ok_or(ImageError::Truncated)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, ImageError> {
    let field = bytes.get(at..at + 8).ok_or(ImageError::Truncated)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(field);
    Ok(u64::from_le_bytes(word))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A program header for [`build`]: (type, flags, offset, vaddr, filesz, memsz).
    /// [`build`] sets every `p_align` to [`PAGE_SIZE`].
    pub(crate) type Phdr = (u32, u32, u64, u64, u64, u64);

    /// Builds an ELF64 x86-64 `ET_EXEC` image with `phdrs` and with `body`
    /// at file offset 4096; the file is at least 8192 bytes.
    pub(crate) fn build(entry: u64, phdrs: &[Phdr], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; (4096 + body.len()).max(8192)];
        bytes[..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = EV_CURRENT;
        bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[24..32].copy_from_slice(&entry.to_le_bytes());
        bytes[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, &(kind, flags, offset, vaddr, filesz, memsz)) in phdrs.iter().enumerate() {
            let at = phdr_at(i);
            bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            bytes[at + 48..at + 56].copy_from_slice(&PAGE_SIZE.to_le_bytes());
        }
        bytes[4096..4096 + body.len()].copy_from_slice(body);
        bytes
    }

    /// The file offset of program header `i` in a [`build`] image.
    pub(crate) fn phdr_at(i: usize) -> usize {
        EHDR_SIZE + i * PHDR_SIZE
    }

    pub(crate) const BASE: u64 = 0x6000_1000_0000;

    pub(crate) fn policy() -> Policy {
        Policy {
            window: BASE..BASE + 0x100_0000,
            allow_tls: false,
        }
    }

    fn text(memsz: u64) -> Phdr {
        (PT_LOAD, PF_R | PF_X, 4096, BASE, 16, memsz)
    }

    fn validate(bytes: &[u8]) -> Result<(), ImageError> {
        Image::parse(bytes)?.validate(&policy()).map(|_| ())
    }

    #[test]
    fn a_fixed_address_image_in_the_window_is_accepted() {
        let data = (PT_LOAD, PF_R | PF_W, 8192, BASE + 0x1000, 16, 64);
        let bytes = build(BASE, &[text(16), data], &[0xc3; 4112]);
        let image = Image::parse(&bytes).unwrap().validate(&policy()).unwrap();
        assert_eq!(image.segments().count(), 2);
        assert_eq!(image.entry(), BASE);
    }

    #[test]
    fn each_shape_violation_is_refused_by_name() {
        let cases: [(&[Phdr], u64, ImageError); 11] = [
            (
                &[text(16), (PT_INTERP, 0, 0, 0, 0, 0)],
                BASE,
                ImageError::HasInterpreter,
            ),
            (
                &[text(16), (PT_DYNAMIC, 0, 0, 0, 0, 0)],
                BASE,
                ImageError::HasDynamicSection,
            ),
            (
                &[text(16), (PT_TLS, 0, 0, 0, 0, 0)],
                BASE,
                ImageError::HasTls,
            ),
            // PT_NOTE only.
            (&[(4, 0, 0, 0, 0, 0)], BASE, ImageError::NoLoadSegment),
            (
                &[text(16), (PT_LOAD, PF_R | PF_X, 8192, BASE + 0x1000, 0, 0)],
                BASE,
                ImageError::EmptySegment { index: 1 },
            ),
            (
                &[(PT_LOAD, PF_R | PF_W | PF_X, 4096, BASE, 16, 16)],
                BASE,
                ImageError::WritableAndExecutable { index: 0 },
            ),
            (
                &[(PT_LOAD, PF_R | PF_X, 4096, 0x40_0000, 16, 16)],
                0x40_0000,
                ImageError::OutsideWindow { index: 0 },
            ),
            // Both page-aligned; the second shares the first's page.
            (
                &[text(0x1800), (PT_LOAD, PF_R, 8192, BASE + 0x1000, 16, 16)],
                BASE,
                ImageError::Overlapping {
                    first: 0,
                    second: 1,
                },
            ),
            // Address and offset disagree modulo the page.
            (
                &[(PT_LOAD, PF_R | PF_X, 4096, BASE + 1, 16, 16)],
                BASE + 1,
                ImageError::Misaligned { index: 0 },
            ),
            // Congruent modulo the page but not page-aligned.
            (
                &[(PT_LOAD, PF_R | PF_X, 4097, BASE + 1, 16, 16)],
                BASE + 1,
                ImageError::Misaligned { index: 0 },
            ),
            (&[text(16)], BASE + 0x8000, ImageError::EntryNotExecutable),
        ];
        for (phdrs, entry, expected) in cases {
            let bytes = build(entry, phdrs, &[0xc3; 4112]);
            assert_eq!(validate(&bytes), Err(expected), "{phdrs:?}");
        }
    }

    #[test]
    fn an_unsupported_segment_alignment_is_refused() {
        for align in [0u64, 1, 0x10, 0x3000] {
            let mut bytes = build(BASE, &[text(16)], &[0xc3; 16]);
            let at = phdr_at(0) + 48;
            bytes[at..at + 8].copy_from_slice(&align.to_le_bytes());
            assert_eq!(
                validate(&bytes),
                Err(ImageError::Misaligned { index: 0 }),
                "p_align {align:#x}"
            );
        }
        // A larger power of two is accepted when the address and offset are
        // congruent modulo it, including with a nonzero residue, and refused
        // when they are not.
        for (offset, vaddr, expected) in [
            (0, BASE, Ok(())),
            (4096, BASE + 0x1000, Ok(())),
            (4096, BASE, Err(ImageError::Misaligned { index: 0 })),
        ] {
            let mut bytes = build(vaddr, &[(PT_LOAD, PF_R | PF_X, offset, vaddr, 16, 16)], &[]);
            let at = phdr_at(0) + 48;
            bytes[at..at + 8].copy_from_slice(&0x20_0000u64.to_le_bytes());
            assert_eq!(validate(&bytes), expected, "offset {offset:#x}");
        }
    }

    #[test]
    fn tls_is_accepted_only_when_the_policy_allows_it() {
        let bytes = build(BASE, &[text(16), (PT_TLS, 0, 0, 0, 0, 0)], &[0xc3; 16]);
        let image = Image::parse(&bytes).unwrap();
        let mut runtime = policy();
        runtime.allow_tls = true;
        assert!(image.validate(&runtime).is_ok());
    }

    #[test]
    fn a_segment_beyond_the_file_or_larger_than_its_memory_is_refused() {
        let beyond = build(BASE, &[(PT_LOAD, PF_R | PF_X, 8192, BASE, 4096, 4096)], &[]);
        assert_eq!(
            validate(&beyond),
            Err(ImageError::SegmentOutsideFile { index: 0 })
        );
        let larger = build(BASE, &[(PT_LOAD, PF_R | PF_X, 4096, BASE, 32, 16)], &[]);
        assert_eq!(
            validate(&larger),
            Err(ImageError::FileSizeExceedsMemorySize { index: 0 })
        );
    }

    #[test]
    fn page_rounding_past_the_top_of_the_address_space_is_refused() {
        let top = !(PAGE_SIZE - 1);
        let bytes = build(top, &[(PT_LOAD, PF_R | PF_X, 4096, top, 16, 16)], &[]);
        assert_eq!(validate(&bytes), Err(ImageError::Overflow));
        // A segment whose end itself overflows is refused while parsing.
        let wraps = build(
            top,
            &[(PT_LOAD, PF_R | PF_X, 4096, top, 16, PAGE_SIZE)],
            &[],
        );
        assert_eq!(Image::parse(&wraps), Err(ImageError::Overflow));
    }

    #[test]
    fn malformed_headers_are_refused_by_name() {
        assert_eq!(Image::parse(&[0u8; 10]), Err(ImageError::Truncated));
        let header = |at: usize, value: &[u8]| {
            let mut bytes = build(BASE, &[text(16)], &[]);
            bytes[at..at + value.len()].copy_from_slice(value);
            Image::parse(&bytes).map(|_| ())
        };
        assert_eq!(header(0, &[0]), Err(ImageError::NotElf));
        // ELFCLASS32, big-endian, version 0.
        assert_eq!(header(4, &[1]), Err(ImageError::UnsupportedIdent));
        assert_eq!(header(5, &[2]), Err(ImageError::UnsupportedIdent));
        assert_eq!(header(6, &[0]), Err(ImageError::UnsupportedIdent));
        // ET_DYN.
        assert_eq!(header(16, &[3]), Err(ImageError::NotFixedAddress));
        // EM_AARCH64.
        assert_eq!(header(18, &[183]), Err(ImageError::WrongMachine));
        // An ELF32-sized program-header entry.
        assert_eq!(header(54, &[32, 0]), Err(ImageError::BadProgramHeaderSize));
        // Extended numbering.
        assert_eq!(
            header(56, &[0xff, 0xff]),
            Err(ImageError::ExtendedNumbering)
        );
        // A table that runs past the end of the file.
        assert_eq!(header(56, &[200, 0]), Err(ImageError::Truncated));
        // A table offset whose end overflows.
        assert_eq!(header(32, &[0xff; 8]), Err(ImageError::Overflow));
        let many = [text(16); MAX_SEGMENTS + 1];
        let too_many = build(BASE, &many, &[]);
        assert_eq!(Image::parse(&too_many), Err(ImageError::TooManySegments));
    }
}
