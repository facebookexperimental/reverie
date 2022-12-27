/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::io;

use super::Addr;
use super::AddrMut;
use super::Errno;
use super::MemoryAccess;

/// A local address space.
#[derive(Default, Debug)]
pub struct LocalMemory {}

impl LocalMemory {
    /// Creates a new representation of memory in the current address space.
    /// Accessing memory this way is highly unsafe. This interface is subject to
    /// change in the future to reduce the unsafeness of it.
    ///
    /// # Example
    /// ```
    /// # use reverie_memory::LocalMemory;
    /// let memory = LocalMemory::new();
    /// ```
    pub fn new() -> Self {
        // TODO: Make LocalMemory just act as a `&mut [u8]`. Then, the "address
        // space" will simply be pointers within that range. This would enable
        // restriction of the accessible address space on a per-syscall basis.
        Self::default()
    }
}

impl MemoryAccess for LocalMemory {
    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        // Just read from the first non-empty slice.
        if let Some(from) = read_from.iter().find(|slice| !slice.is_empty()) {
            // Write to the first non-empty slice.
            if let Some(to) = write_to.iter_mut().find(|slice| !slice.is_empty()) {
                let count = to.len().min(from.len());
                to[0..count].copy_from_slice(&from[0..count]);
                return Ok(count);
            }
        }
        Ok(0)
    }

    fn write_vectored(
        &mut self,
        _read_from: &[io::IoSlice],
        _write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        todo!("Implement local memory access")
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let addr = addr.into();
        // Simply copy the memory starting at the address into the buffer. This
        // is very unsafe. We need a better way to do this.
        unsafe {
            ::core::intrinsics::copy_nonoverlapping(addr.as_ptr(), buf.as_mut_ptr(), buf.len())
        };

        Ok(buf.len())
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        // Simply copy the memory starting at the address into the buffer. This
        // is very unsafe. We need a better way to do this.
        unsafe {
            ::core::intrinsics::copy_nonoverlapping(buf.as_ptr(), addr.as_mut_ptr(), buf.len())
        };

        Ok(buf.len())
    }

    fn read_cstring(&self, addr: Addr<u8>) -> Result<CString, Errno> {
        Ok(unsafe { CStr::from_ptr(addr.as_ptr() as *const _) }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_value() {
        let m = LocalMemory::new();
        let x = [1u32, 2, 3, 4];
        let addr = Addr::from_ptr(x.as_ptr()).unwrap();
        let v: u32 = m.read_value(addr).unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn read() {
        let m = LocalMemory::new();
        let x = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let addr = Addr::from_ptr(x.as_ptr()).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(m.read(addr, &mut buf).unwrap(), 8);
        assert_eq!(buf, x);
    }

    #[test]
    fn read_cstring() {
        use std::ffi::CStr;

        let m = LocalMemory::new();
        let x = "hello world\0";
        let addr = Addr::from_ptr(x.as_ptr() as *const u8).unwrap();
        assert_eq!(m.read_cstring(addr).unwrap().as_c_str(), unsafe {
            CStr::from_ptr(x.as_ptr() as *const _)
        });
    }
}
