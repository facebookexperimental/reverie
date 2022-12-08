/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod addr;
mod local;

use core::mem;
use std::ffi::CString;
use std::io;

pub use addr::Addr;
pub use addr::AddrMut;
pub use addr::AddrSlice;
pub use addr::AddrSliceMut;
pub use local::LocalMemory;
use syscalls::Errno;

/// Trait for accessing potentially remote memory.
pub trait MemoryAccess {
    /// Reads bytes from the address space. Returns the number of bytes read.
    ///
    /// Note that there is no guarantee that all of the requested buffers will be
    /// filled.
    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno>;

    /// Writes bytes to the address space. Returns the number of bytes written.
    ///
    /// Note that there is no guarantee that all of the requested buffers will
    /// be written.
    fn write_vectored(
        &mut self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno>;

    /// Performs a read starting at the given address. The number of bytes read
    /// is returned. The buffer is not guaranteed to be completely filled.
    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let slice = unsafe { AddrSlice::from_raw_parts(addr.into(), buf.len()) };
        let from = [unsafe { slice.as_ioslice() }];
        let mut to = [io::IoSliceMut::new(buf)];
        self.read_vectored(&from, &mut to)
    }

    /// Performs a write starting at the given address. The number of bytes
    /// written is returned. There is no guarantee that the given buffer will be
    /// fully written.
    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        let mut slice = unsafe { AddrSliceMut::from_raw_parts(addr, buf.len()) };
        let from = [io::IoSlice::new(buf)];
        let mut to = [unsafe { slice.as_ioslice_mut() }];
        self.write_vectored(&from, &mut to)
    }

    /// Reads exactly the number of bytes wanted by `buf`.
    fn read_exact<'a, A>(&self, addr: A, mut buf: &mut [u8]) -> Result<(), Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let mut addr = addr.into();

        while !buf.is_empty() {
            match self.read(addr, buf)? {
                0 => break,
                n => {
                    addr = unsafe { addr.add(n) };
                    buf = &mut buf[n..];
                }
            }
        }

        if !buf.is_empty() {
            // Failed to fill the whole buffer.
            Err(Errno::EFAULT)
        } else {
            Ok(())
        }
    }

    /// Reads exactly the number of bytes wanted by `buf`.
    fn write_exact(&mut self, mut addr: AddrMut<u8>, mut buf: &[u8]) -> Result<(), Errno> {
        while !buf.is_empty() {
            match self.write(addr, buf)? {
                0 => break,
                n => {
                    addr = unsafe { addr.add(n) };
                    buf = &buf[n..];
                }
            }
        }

        if !buf.is_empty() {
            // Failed to fill the whole buffer.
            Err(Errno::EFAULT)
        } else {
            Ok(())
        }
    }

    /// Reads a value at the given address.
    fn read_value<'a, A, T>(&self, addr: A) -> Result<T, Errno>
    where
        A: Into<Addr<'a, T>>,
        T: Sized + 'a,
    {
        let addr = addr.into();
        let mut value = mem::MaybeUninit::uninit();

        let value_buf = unsafe {
            ::core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, mem::size_of::<T>())
        };

        self.read_exact(addr.cast::<u8>(), value_buf)?;

        Ok(unsafe { value.assume_init() })
    }

    /// Writes a value to the given address.
    fn write_value<'a, A, T>(&mut self, addr: A, value: &T) -> Result<(), Errno>
    where
        A: Into<AddrMut<'a, T>>,
        T: Sized + 'a,
    {
        let addr = addr.into();

        let value_buf = unsafe {
            ::core::slice::from_raw_parts(value as *const _ as *const u8, mem::size_of::<T>())
        };

        self.write_exact(addr.cast::<u8>(), value_buf)?;

        Ok(())
    }

    /// Reads a slice of values. Returns an error if the buffer fails to get
    /// fully filled.
    fn read_values<T>(&self, addr: Addr<T>, buf: &mut [T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        let buf = unsafe {
            ::core::slice::from_raw_parts_mut(
                buf.as_mut_ptr() as *mut u8,
                buf.len() * mem::size_of::<T>(),
            )
        };

        self.read_exact(addr.cast::<u8>(), buf)
    }

    /// Writes a slice of values. Returns an error if the buffer fails to get
    /// fully written.
    fn write_values<T>(&mut self, addr: AddrMut<T>, buf: &[T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        let buf = unsafe {
            ::core::slice::from_raw_parts(
                buf.as_ptr() as *const u8,
                buf.len() * mem::size_of::<T>(),
            )
        };

        self.write_exact(addr.cast::<u8>(), buf)
    }

    /// Reads memory at the given starting address while the boolean returned by
    /// the predicate `pred` is true.
    fn read_while<F>(&self, mut addr: Addr<u8>, buf: &mut [u8], mut pred: F) -> Result<usize, Errno>
    where
        F: FnMut(&[u8]) -> Option<usize>,
    {
        let mut count = 0;

        loop {
            let read = self.read(addr, buf)?;
            if read == 0 {
                // We hit an "EOF" (an EFAULT) and the predicate never matched.
                // The predicate should *eventually* return true, so this is
                // always an error.
                return Err(Errno::EFAULT);
            }

            addr = unsafe { addr.add(read) };

            if let Some(used) = pred(&buf[..read]) {
                return Ok(count + used);
            }

            count += read;
        }
    }

    /// Reads a NUL terminated string using the provided buffer to read it in
    /// chunks. Change the size of the buffer to adjust how many bytes are read
    /// at one time. Increasing the buffer size can be more efficient when
    /// reading a remote C string because it reduces the number of syscalls that
    /// are made.
    fn read_cstring_with_buf(&self, addr: Addr<u8>, buf: &mut [u8]) -> Result<CString, Errno> {
        let mut accumulator = Vec::new();

        self.read_while(addr, buf, |slice| {
            if let Some(nul) = slice.iter().position(|&b| b == 0) {
                // Stop once we find a NUL terminator.
                accumulator.extend(&slice[..nul]);
                Some(nul)
            } else {
                accumulator.extend(slice);
                None
            }
        })?;

        // unsafe is okay here; the vector is guaranteed to not contain a nul
        // byte.
        Ok(unsafe { CString::from_vec_unchecked(accumulator) })
    }

    /// Reads a null-terminated string starting at the given address.
    fn read_cstring(&self, addr: Addr<u8>) -> Result<CString, Errno> {
        // Assume most strings are smallish. We need to balance the overhead of
        // copying data vs the average length of C-strings.
        let mut buf: [u8; 512] = [0; 512];

        self.read_cstring_with_buf(addr, &mut buf)
    }

    /// Returns a struct that implements `std::io::Read`. This is useful when
    /// reading memory sequentially.
    fn reader<'a, T>(&'a self, addr: Addr<'a, T>) -> MemoryReader<'a, Self, T>
    where
        Self: Sized,
    {
        MemoryReader::new(self, addr)
    }

    /// Returns a struct that implements `std::io::Write`. This is useful when
    /// writing memory sequentially.
    fn writer<'a, T>(&'a mut self, addr: AddrMut<'a, T>) -> MemoryWriter<'a, Self, T>
    where
        Self: Sized,
    {
        MemoryWriter::new(self, addr)
    }
}

/// A wrapper around both an address space and a pointer for sequential reads.
pub struct MemoryReader<'a, M, T> {
    memory: &'a M,

    addr: Addr<'a, T>,
}

impl<'a, M, T> MemoryReader<'a, M, T> {
    /// Creates a new `MemoryReader`. All reads will start at `addr`. It is the
    /// callers job to avoid buffer overruns.
    pub fn new(memory: &'a M, addr: Addr<'a, T>) -> Self {
        MemoryReader { memory, addr }
    }
}

impl<'a, M, T> MemoryReader<'a, M, T>
where
    M: MemoryAccess,
    T: Sized + Copy,
{
    /// Reads a single typed value from the buffer.
    pub fn read_value(&mut self) -> Result<T, Errno> {
        let value = self.memory.read_value(self.addr)?;
        self.addr = unsafe { self.addr.add(1) };
        Ok(value)
    }
}

impl<'a, M> io::Read for MemoryReader<'a, M, u8>
where
    M: MemoryAccess,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.memory.read(self.addr, buf)?;

        self.addr = unsafe { self.addr.add(count) };

        Ok(count)
    }
}

/// A wrapper around both an address space and a pointer for sequential writes.
pub struct MemoryWriter<'a, M, T> {
    memory: &'a mut M,

    addr: AddrMut<'a, T>,
}

impl<'a, M, T> MemoryWriter<'a, M, T> {
    /// Creates a new `MemoryWriter`. All writes will start at `addr`. It is the
    /// callers job to avoid buffer overruns.
    pub fn new(memory: &'a mut M, addr: AddrMut<'a, T>) -> Self {
        MemoryWriter { memory, addr }
    }
}

impl<'a, M, T> MemoryWriter<'a, M, T>
where
    M: MemoryAccess,
    T: Sized + Copy,
{
    /// Reads a single typed value from the buffer.
    pub fn write_value(&mut self, value: &T) -> Result<(), Errno> {
        self.memory.write_value(self.addr, value)?;
        self.addr = unsafe { self.addr.add(1) };
        Ok(())
    }
}

impl<'a, M> io::Write for MemoryWriter<'a, M, u8>
where
    M: MemoryAccess,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.memory.write(self.addr, buf)?;

        self.addr = unsafe { self.addr.add(count) };

        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Flush doesn't make any sense when writing to memory.
        Ok(())
    }
}
