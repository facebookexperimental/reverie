// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Derive private-libc inputs from the already validated, retained ELF bytes.
//! This is image geometry, not source qualification or mapping authority.

use core::ops::Range;

use super::ImageError;
use super::PHDR_SIZE;
use super::Segment;
use super::ValidatedImage;
use super::read_u16;
use super::read_u32;
use super::read_u64;

/// The sole TLS template in a private runtime and its actual containing load.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsTemplate {
    /// Template address in the fixed image, including the empty-file anchor.
    pub address: u64,
    /// Number of initialized template bytes in the retained file.
    pub file_bytes: u64,
    /// Per-thread initialized plus zero-filled template bytes.
    pub memory_bytes: u64,
    /// Actual ELF TLS alignment, a nonzero power of two.
    pub alignment: u64,
    /// Actual readable load whose file and memory coordinates agree with TLS.
    pub load: Segment,
}

/// Final-image facts used to construct the private libc's auxiliary vector.
/// A successful projection does not qualify instructions, sources or ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateRuntimeMetadata {
    /// Real program headers in a read-only, non-executable initialized mapping.
    pub program_headers: Range<u64>,
    /// Exact count of retained ELF64 program headers (entry size is 56).
    pub program_header_count: u16,
    /// Exactly one usable TLS template, never a guest's TLS template.
    pub tls: TlsTemplate,
    /// Actual non-executable PT_GNU_STACK memory-size hint, including zero.
    pub gnu_stack_bytes: u64,
}

/// Named reasons private libc inputs cannot be derived from an ELF image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateRuntimeMetadataError {
    /// A previously validated ELF field or range could not be read.
    Image(ImageError),
    /// The private handoff admits at most 64 program headers, without truncation.
    ProgramHeaderCount,
    /// Program headers lack one complete initialized read-only mapping.
    ProgramHeadersNotReadOnly,
    /// A PT_PHDR descriptor contradicts the actual header table/file mapping.
    ContradictoryProgramHeaders,
    /// The image does not contain exactly one TLS program header.
    TlsCount,
    /// TLS size, alignment, file coordinates or containing load are invalid.
    TlsGeometry,
    /// A unique, non-executable PT_GNU_STACK descriptor is required.
    StackDescriptor,
}

impl From<ImageError> for PrivateRuntimeMetadataError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

impl ValidatedImage<'_> {
    /// Derive the actual private PHDR/TLS/stack facts, preserving file identity.
    ///
    /// This adds private-libc geometry checks without changing the probe's
    /// existing no-TLS and syscall-audit rules. Callers still need the separate
    /// production source/instruction qualification and a retained mapped owner.
    pub fn private_runtime_metadata(
        &self,
    ) -> Result<PrivateRuntimeMetadata, PrivateRuntimeMetadataError> {
        use PrivateRuntimeMetadataError as Error;
        let bytes = self.0.bytes;
        let offset = read_u64(bytes, 32)?;
        let count = read_u16(bytes, 56)?;
        if count == 0 || count > 64 {
            return Err(Error::ProgramHeaderCount);
        }
        let length = u64::from(count) * PHDR_SIZE as u64;
        let end = offset.checked_add(length).ok_or(ImageError::Overflow)?;
        let mut headers = None;
        for load in self.segments() {
            if load.permissions.read
                && !load.permissions.write
                && !load.permissions.execute
                && load.file.start <= offset
                && end <= load.file.end
            {
                let address = load
                    .memory
                    .start
                    .checked_add(offset - load.file.start)
                    .ok_or(ImageError::Overflow)?;
                let extent = address..address.checked_add(length).ok_or(ImageError::Overflow)?;
                if headers.replace(extent).is_some() {
                    return Err(Error::ProgramHeadersNotReadOnly);
                }
            }
        }
        let headers = headers.ok_or(Error::ProgramHeadersNotReadOnly)?;
        let start = usize::try_from(offset).map_err(|_| ImageError::Overflow)?;
        let end = usize::try_from(end).map_err(|_| ImageError::Overflow)?;
        let table = bytes.get(start..end).ok_or(ImageError::Truncated)?;
        let mut tls = None;
        let mut stack = None;
        let mut saw_phdr = false;
        for header in table.as_chunks::<PHDR_SIZE>().0 {
            let kind = read_u32(header, 0)?;
            let flags = read_u32(header, 4)?;
            let file_offset = read_u64(header, 8)?;
            let address = read_u64(header, 16)?;
            let file_bytes = read_u64(header, 32)?;
            let memory_bytes = read_u64(header, 40)?;
            let alignment = read_u64(header, 48)?;
            match kind {
                6 => {
                    if saw_phdr
                        || file_offset != offset
                        || address != headers.start
                        || file_bytes != length
                        || memory_bytes != length
                        || flags != 4
                    {
                        return Err(Error::ContradictoryProgramHeaders);
                    }
                    saw_phdr = true;
                }
                7 => {
                    if tls.is_some() {
                        return Err(Error::TlsCount);
                    }
                    if memory_bytes == 0
                        || file_bytes > memory_bytes
                        || !alignment.is_power_of_two()
                        || address % alignment != file_offset % alignment
                        || flags & 4 == 0
                        || flags & !6 != 0
                    {
                        return Err(Error::TlsGeometry);
                    }
                    let file_end = file_offset
                        .checked_add(file_bytes)
                        .ok_or(Error::TlsGeometry)?;
                    let memory_end = address
                        .checked_add(memory_bytes)
                        .ok_or(Error::TlsGeometry)?;
                    let mut containing = None;
                    for load in self.segments() {
                        if load.permissions.read
                            && !load.permissions.execute
                            && load.memory.start <= address
                            && memory_end <= load.memory.end
                            && load.file.start <= file_offset
                            && file_end <= load.file.end
                            && address - load.memory.start == file_offset - load.file.start
                            && containing.replace(load.clone()).is_some()
                        {
                            return Err(Error::TlsGeometry);
                        }
                    }
                    tls = Some(TlsTemplate {
                        address,
                        file_bytes,
                        memory_bytes,
                        alignment,
                        load: containing.ok_or(Error::TlsGeometry)?,
                    });
                }
                0x6474_e551 if flags != 6 || stack.replace(memory_bytes).is_some() => {
                    return Err(Error::StackDescriptor);
                }
                _ => {}
            }
        }
        Ok(PrivateRuntimeMetadata {
            program_headers: headers,
            program_header_count: count,
            tls: tls.ok_or(Error::TlsCount)?,
            gnu_stack_bytes: stack.ok_or(Error::StackDescriptor)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use crate::image::Policy;
    use crate::image::tests::Phdr;
    use crate::image::tests::build;
    const BASE: u64 = 0x6000_e100_0000;

    fn fixture() -> Vec<u8> {
        let phdrs: [Phdr; 6] = [
            (1, 4, 0, BASE, 4096, 4096),
            (1, 5, 4096, BASE + 4096, 4096, 4096),
            (1, 6, 8192, BASE + 8192, 512, 4096),
            (7, 4, 8192, BASE + 8192, 16, 80),
            (0x6474_e551, 6, 0, 0, 0, 8 * 1024 * 1024),
            (6, 4, 64, BASE + 64, 6 * 56, 6 * 56),
        ];
        let mut bytes = build(BASE + 4096, &phdrs, &[0x90; 4608]);
        field(&mut bytes, 3, 48, 16);
        bytes
    }
    fn field(bytes: &mut [u8], ph: usize, field: usize, value: u64) {
        let at = 64 + ph * 56 + field;
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn inspect(bytes: &[u8]) -> Result<PrivateRuntimeMetadata, PrivateRuntimeMetadataError> {
        Image::parse(bytes)?
            .validate(&Policy {
                window: BASE..BASE + 0x10000,
                allow_tls: true,
            })?
            .private_runtime_metadata()
    }
    #[test]
    fn metadata_comes_from_same_mapped_file_coordinates() {
        let bytes = fixture();
        let before = bytes.clone();
        let m = inspect(&bytes).unwrap();
        assert_eq!(m.program_headers, BASE + 64..BASE + 64 + 336);
        assert_eq!(m.program_header_count, 6);
        assert_eq!(
            (
                m.tls.address,
                m.tls.file_bytes,
                m.tls.memory_bytes,
                m.tls.alignment
            ),
            (BASE + 8192, 16, 80, 16)
        );
        assert_eq!(m.tls.load.file, 8192..8704);
        assert_eq!(m.gnu_stack_bytes, 8 * 1024 * 1024);
        assert_eq!(bytes, before);
    }
    #[test]
    fn rejects_unmapped_or_writable_program_headers() {
        for flags in [5_u32, 6] {
            let mut b = fixture();
            b[68..72].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(
                inspect(&b),
                Err(PrivateRuntimeMetadataError::ProgramHeadersNotReadOnly)
            );
        }
    }
    #[test]
    fn rejects_tls_outside_load_or_wrong_file_correspondence() {
        for (field_index, value) in [(8, 8208), (40, 4097), (48, 3), (32, 513)] {
            let mut b = fixture();
            field(&mut b, 3, field_index, value);
            assert_eq!(inspect(&b), Err(PrivateRuntimeMetadataError::TlsGeometry));
        }
    }
    #[test]
    fn rejects_duplicate_missing_tls_and_executable_stack() {
        let mut b = fixture();
        b[64 + 3 * 56..68 + 3 * 56].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(inspect(&b), Err(PrivateRuntimeMetadataError::TlsCount));
        let mut b = fixture();
        let tls = b[64 + 3 * 56..64 + 4 * 56].to_vec();
        b[64 + 5 * 56..64 + 6 * 56].copy_from_slice(&tls);
        assert_eq!(inspect(&b), Err(PrivateRuntimeMetadataError::TlsCount));
        let mut b = fixture();
        b[68 + 4 * 56..72 + 4 * 56].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            inspect(&b),
            Err(PrivateRuntimeMetadataError::StackDescriptor)
        );
    }
    #[test]
    fn rejects_lying_phdr_and_keeps_zero_real_stack_hint() {
        let mut b = fixture();
        field(&mut b, 5, 16, BASE + 128);
        assert_eq!(
            inspect(&b),
            Err(PrivateRuntimeMetadataError::ContradictoryProgramHeaders)
        );
        let mut b = fixture();
        field(&mut b, 4, 40, 0);
        assert_eq!(inspect(&b).unwrap().gnu_stack_bytes, 0);
    }
}
