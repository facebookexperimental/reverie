/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;

use crate::Error;
use crate::Result;

const PAGE_SIZE: usize = 4096;

/// A contiguous, page-aligned guest-physical memory region.
#[derive(Clone, Debug)]
pub struct GuestMemory {
    mapping: Arc<Mapping>,
}

#[derive(Debug)]
struct Mapping {
    mapping: NonNull<u8>,
    guest_base: u64,
    size: usize,
    host_access: Mutex<()>,
}

// SAFETY: Mapping owns an mmap allocation, not a Rust reference. Host access
// is serialized by host_access, and the KVM backend exposes handles only while
// its single vCPU is stopped at an exit.
unsafe impl Send for Mapping {}
// SAFETY: See the Send implementation. All host reads and writes take the
// mapping's mutex before dereferencing the pointer.
unsafe impl Sync for Mapping {}

impl GuestMemory {
    /// Allocates a shared anonymous mapping for a guest-physical address range.
    pub fn new(guest_base: u64, size: usize) -> Result<Self> {
        let size_u64 = u64::try_from(size).expect("usize must fit in u64 on x86-64");
        if size == 0
            || !size.is_multiple_of(PAGE_SIZE)
            || !guest_base.is_multiple_of(PAGE_SIZE as u64)
            || guest_base.checked_add(size_u64).is_none()
        {
            return Err(Error::InvalidMemoryLayout { guest_base, size });
        }

        // SAFETY: mmap is called with an anonymous fd and validated below. The
        // mapping is owned by this value and released exactly once in Drop.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(Error::MemoryMapping(std::io::Error::last_os_error()));
        }

        Ok(Self {
            mapping: Arc::new(Mapping {
                mapping: NonNull::new(mapping.cast()).expect("mmap returned a null mapping"),
                guest_base,
                size,
                host_access: Mutex::new(()),
            }),
        })
    }

    /// Returns the first guest-physical address in the mapping.
    pub fn guest_base(&self) -> u64 {
        self.mapping.guest_base
    }

    /// Returns the mapping size in bytes.
    pub fn len(&self) -> usize {
        self.mapping.size
    }

    /// Returns whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.mapping.size == 0
    }

    /// Copies bytes from guest memory into a host buffer.
    pub fn read(&self, guest_address: u64, destination: &mut [u8]) -> Result<()> {
        let offset = self.checked_offset(guest_address, destination.len())?;
        let _guard = self
            .mapping
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        // SAFETY: checked_offset proves that both ends of the copy lie within
        // the live mapping, and destination is a distinct mutable slice.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.mapping.mapping.as_ptr().add(offset),
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        Ok(())
    }

    /// Copies bytes from a host slice into guest memory.
    pub fn write(&mut self, guest_address: u64, source: &[u8]) -> Result<()> {
        let offset = self.checked_offset(guest_address, source.len())?;
        let _guard = self
            .mapping
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        // SAFETY: checked_offset proves that both ends of the copy lie within
        // the live mapping, and host writes are serialized by host_access.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.mapping.mapping.as_ptr().add(offset),
                source.len(),
            );
        }
        Ok(())
    }

    pub(crate) fn host_address(&self) -> u64 {
        self.mapping.mapping.as_ptr() as u64
    }

    fn checked_offset(&self, guest_address: u64, length: usize) -> Result<usize> {
        let relative = guest_address.checked_sub(self.mapping.guest_base);
        let length_u64 = u64::try_from(length).expect("usize must fit in u64 on x86-64");
        let end = relative.and_then(|offset| offset.checked_add(length_u64));
        if end.is_none_or(|end| end > self.mapping.size as u64) {
            return Err(Error::InvalidGuestAddress {
                address: guest_address,
                length,
                guest_base: self.mapping.guest_base,
                guest_end: self.mapping.guest_base + self.mapping.size as u64,
            });
        }
        Ok(relative.unwrap() as usize)
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: mapping and size are the exact values returned by mmap and
        // this Drop is the unique owner of that mapping.
        unsafe {
            libc::munmap(self.mapping.as_ptr().cast(), self.size);
        }
    }
}

impl MemoryAccess for GuestMemory {
    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            let count = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let address = read_from[source_index].as_ptr() as u64 + source_offset as u64;
            let destination =
                &mut write_to[destination_index][destination_offset..destination_offset + count];
            if GuestMemory::read(self, address, destination).is_err() {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
        }
        Ok(total)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            let count = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let source = &read_from[source_index][source_offset..source_offset + count];
            let address =
                write_to[destination_index].as_mut_ptr() as u64 + destination_offset as u64;
            if GuestMemory::write(self, address, source).is_err() {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_guest_memory() {
        let mut memory = GuestMemory::new(0x1000, PAGE_SIZE).unwrap();
        memory.write(0x1123, b"hello").unwrap();

        let mut bytes = [0; 5];
        memory.read(0x1123, &mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
    }

    #[test]
    fn permits_access_to_last_byte() {
        let mut memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        memory.write(0x2fff, &[0x5a]).unwrap();

        let mut byte = [0];
        memory.read(0x2fff, &mut byte).unwrap();
        assert_eq!(byte, [0x5a]);
    }

    #[test]
    fn rejects_address_below_mapping() {
        let memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        let error = memory.read(0x1fff, &mut [0]).unwrap_err();
        assert!(matches!(error, Error::InvalidGuestAddress { .. }));
    }

    #[test]
    fn rejects_access_past_mapping() {
        let mut memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        let error = memory.write(0x2fff, &[1, 2]).unwrap_err();
        assert!(matches!(error, Error::InvalidGuestAddress { .. }));
    }

    #[test]
    fn cloned_handles_share_memory() {
        let mut first = GuestMemory::new(0x1000, PAGE_SIZE).unwrap();
        let mut second = first.clone();

        first.write(0x1100, b"shared").unwrap();
        let mut bytes = [0; 6];
        second.read(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"shared");

        second.write(0x1200, b"api").unwrap();
        let mut bytes = [0; 3];
        first.read(0x1200, &mut bytes).unwrap();
        assert_eq!(&bytes, b"api");
    }
}
