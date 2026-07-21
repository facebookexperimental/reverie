/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ptr::NonNull;

use crate::Error;
use crate::Result;

const PAGE_SIZE: usize = 4096;

/// A contiguous, page-aligned guest-physical memory region.
#[derive(Debug)]
pub struct GuestMemory {
    mapping: NonNull<u8>,
    guest_base: u64,
    size: usize,
}

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
            mapping: NonNull::new(mapping.cast()).expect("mmap returned a null mapping"),
            guest_base,
            size,
        })
    }

    /// Returns the first guest-physical address in the mapping.
    pub fn guest_base(&self) -> u64 {
        self.guest_base
    }

    /// Returns the mapping size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Copies bytes from guest memory into a host buffer.
    pub fn read(&self, guest_address: u64, destination: &mut [u8]) -> Result<()> {
        let offset = self.checked_offset(guest_address, destination.len())?;
        // SAFETY: checked_offset proves that both ends of the copy lie within
        // the live mapping, and destination is a distinct mutable slice.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.mapping.as_ptr().add(offset),
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        Ok(())
    }

    /// Copies bytes from a host slice into guest memory.
    pub fn write(&mut self, guest_address: u64, source: &[u8]) -> Result<()> {
        let offset = self.checked_offset(guest_address, source.len())?;
        // SAFETY: checked_offset proves that both ends of the copy lie within
        // the live mapping, and &mut self provides exclusive access.
        unsafe {
            std::ptr::copy_nonoverlapping(
                source.as_ptr(),
                self.mapping.as_ptr().add(offset),
                source.len(),
            );
        }
        Ok(())
    }

    pub(crate) fn host_address(&self) -> u64 {
        self.mapping.as_ptr() as u64
    }

    fn checked_offset(&self, guest_address: u64, length: usize) -> Result<usize> {
        let relative = guest_address.checked_sub(self.guest_base);
        let length_u64 = u64::try_from(length).expect("usize must fit in u64 on x86-64");
        let end = relative.and_then(|offset| offset.checked_add(length_u64));
        if end.is_none_or(|end| end > self.size as u64) {
            return Err(Error::InvalidGuestAddress {
                address: guest_address,
                length,
                guest_base: self.guest_base,
                guest_end: self.guest_base + self.size as u64,
            });
        }
        Ok(relative.unwrap() as usize)
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        // SAFETY: mapping and size are the exact values returned by mmap and
        // this Drop is the unique owner of that mapping.
        unsafe {
            libc::munmap(self.mapping.as_ptr().cast(), self.size);
        }
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
}
