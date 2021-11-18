/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CString;
use std::io;

use super::{Addr, AddrMut, Errno, MemoryAccess};

/// A local address space.
#[derive(Debug)]
pub struct LocalMemory {}

impl LocalMemory {
    /// Creates a new representation of memory in the current address space.
    /// Accessing memory this way is highly unsafe. This interface is subject to
    /// change in the future to reduce the unsafeness of it.
    ///
    /// # Example
    /// ```
    /// # use reverie_syscalls::LocalMemory;
    /// let memory = LocalMemory::new();
    /// ```
    pub fn new() -> Self {
        // TODO: Make LocalMemory just act as a `&mut [u8]`. Then, the "address
        // space" will simply be pointers within that range. This would enable
        // restriction of the accessible address space on a per-syscall basis.
        LocalMemory {}
    }
}

impl MemoryAccess for LocalMemory {
    fn read_vectored(
        &self,
        _read_from: &[io::IoSlice],
        _write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        // TODO: Just write to the first non-empty buffer
        todo!("Implement local memory access")
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
        let ptr = unsafe { addr.as_ptr() };
        let len = unsafe { libc::strlen(ptr as *const libc::c_char) };
        let slice = unsafe { ::core::slice::from_raw_parts(ptr, len) };

        let buf = Vec::from(slice);

        Ok(unsafe { CString::from_vec_unchecked(buf) })
    }
}
