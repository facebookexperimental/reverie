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
use zerocopy::FromBytes;
use zerocopy::TryFromBytes;

/// One numeric destination in another process's address space.
///
/// Unlike [`io::IoSliceMut`], this forms no Rust reference to the remote
/// address. The address is only a kernel operand for a backend that has
/// independently authenticated the stopped target task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteIoVec {
    address: usize,
    length: usize,
}

impl RemoteIoVec {
    pub fn new(address: AddrMut<u8>, length: usize) -> Result<Self, Errno> {
        address.as_raw().checked_add(length).ok_or(Errno::EFAULT)?;
        Ok(Self {
            address: address.as_raw(),
            length,
        })
    }

    pub fn address(self) -> usize {
        self.address
    }

    pub fn length(self) -> usize {
        self.length
    }
}

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

    /// Performs one synchronous native write to the exact expected task.
    ///
    /// An implementation must check its actual task against `expected_tid`
    /// before any effect, respect the target's VMA access permissions, and
    /// return the unmodified native byte count or errno. It must not retry a
    /// short transfer, collapse `EFAULT` to zero, or fall back to ptrace writes.
    /// All effects must finish before return: no detached work or retained
    /// buffer references are permitted. Remote protection keys are not proved
    /// by this interface; the caller separately owns task-generation, mapping,
    /// foreground and lifetime authority throughout the operation.
    ///
    /// Backends without this exact capability refuse without accessing memory.
    /// An implementation may also cap the number of `remote` segments and
    /// refuse a longer list with `E2BIG`, again without accessing memory; the
    /// ptrace backend accepts at most two.
    fn write_native_user_vectored(
        &mut self,
        _expected_tid: i32,
        _local: &[io::IoSlice],
        _remote: &[RemoteIoVec],
    ) -> Result<usize, Errno> {
        Err(Errno::EOPNOTSUPP)
    }

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

    /// Writes one prefix while respecting the target's user mapping permissions.
    ///
    /// Unlike debugger writes, this must not force access to read-only memory.
    /// Supported implementations perform one increasing-address copy, without
    /// retrying a short transfer. A nonempty first-byte fault is `EFAULT`;
    /// otherwise the count describes exactly the bytes copied. A short count
    /// does not imply that the next byte is unwritable or identify a fault.
    /// Nonempty address-plus-length overflow is `EFAULT` before copying.
    ///
    /// A healthy supported empty copy returns zero without inspecting `addr`.
    /// Other errors retain their identity. A terminal backend failure may
    /// override a count or ordinary fault after effects, including on an empty
    /// operation. Callers must preserve those effects, stop, and not commit a
    /// consuming transaction or retry a terminal error as an ordinary fault.
    ///
    /// The default is unsupported, including for empty copies. `ENOSYS` means
    /// a missing backend capability: the consuming Tool must report a backend
    /// or Tool failure rather than forwarding it as a guest syscall errno.
    /// It must not fall back to generic debugger writes.
    ///
    /// This synchronous operation may block and adds no scheduling guarantee
    /// or snapshot of concurrent mapping changes. Permissions are those the
    /// backend supports; this does not add PKRU or tagged-address emulation.
    fn write_with_user_access(&mut self, _addr: AddrMut<u8>, _buf: &[u8]) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Atomically replaces the aligned 32-bit word at `addr` with `desired`
    /// if it holds `expected`, and returns the value the word held: the store
    /// happened exactly when that value equals `expected`. This is the
    /// compare-and-exchange Linux performs on a futex word
    /// (`futex_cmpxchg_value_locked`), with the same visibility to other
    /// threads and processes that map the word.
    ///
    /// A misaligned address is `EINVAL`, and an address that cannot be read
    /// and written is `EFAULT`, both without storing.
    ///
    /// The default is unsupported. `ENOSYS` means a missing backend
    /// capability, as for [`Self::write_with_user_access`]: the consuming Tool
    /// must not emulate it with a separate read and write.
    fn compare_exchange_u32(
        &mut self,
        _addr: AddrMut<u32>,
        _expected: u32,
        _desired: u32,
    ) -> Result<u32, Errno> {
        Err(Errno::ENOSYS)
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

    /// Reads exactly the number of bytes wanted by `buf`, while respecting the
    /// target process's userspace memory protections.
    ///
    /// This performs one read rather than retrying a partial transfer. A short
    /// read therefore reports `EFAULT`, matching the all-or-error behavior of
    /// Linux helpers such as `copy_from_user`.
    fn read_exact_with_user_access<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<(), Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let addr = addr.into();
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;

        if self.read(addr, buf)? == buf.len() {
            Ok(())
        } else {
            Err(Errno::EFAULT)
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

    /// Reads a value of a type with invalid bit patterns, such as `bool` or
    /// an enum, and validates it. Returns `EINVAL`, without constructing a
    /// `T`, when the bytes read are not a valid `T`.
    fn try_read_value<'a, A, T>(&self, addr: A) -> Result<T, Errno>
    where
        A: Into<Addr<'a, T>>,
        T: TryFromBytes + 'a,
    {
        let mut bytes = vec![0u8; mem::size_of::<T>()];
        self.read_exact(addr.into().cast::<u8>(), &mut bytes)?;
        T::try_read_from_bytes(&bytes).map_err(|_| Errno::EINVAL)
    }

    /// Reads a value whose type is not yet proven valid for every bit
    /// pattern.
    ///
    /// Transitional (dh-g80yq3): only call sites whose type does not yet
    /// derive `FromBytes` and `IntoBytes` use this, each with a `SAFETY`
    /// comment, until they migrate to [`Self::read_value`] or
    /// [`Self::try_read_value`].
    ///
    /// # Safety
    ///
    /// Every sequence of `size_of::<T>()` bytes that `addr` can hold must
    /// form a valid and safe `T`: `T` must be a type that could soundly
    /// implement zerocopy's `FromBytes`. Examples of what that excludes, at
    /// any depth: `bool`, `char`, enums, `NonZero*`, `NonNull`, references,
    /// function pointers, `Duration`, `OwnedFd` and `BorrowedFd`, and any type
    /// whose methods or `Drop` rely on its field values, such as one that
    /// frees or closes what a field names.
    unsafe fn read_value_unchecked<'a, A, T>(&self, addr: A) -> Result<T, Errno>
    where
        A: Into<Addr<'a, T>>,
        T: Sized + 'a,
    {
        let mut value = mem::MaybeUninit::<T>::uninit();

        // Zeroed in place, not by `MaybeUninit::zeroed()`: returning that
        // value would be a typed copy, which need not preserve the zeroes in
        // `T`'s padding.
        // SAFETY: `value` is a live local, valid for writes of one `T`.
        unsafe { value.as_mut_ptr().write_bytes(0, 1) };

        // SAFETY: `value` is a live, exclusively borrowed local of exactly
        // `size_of::<T>()` bytes, all initialized by the zeroing above, with
        // no copy of `value` since; `u8` has alignment 1. The slice is dropped
        // before `value` is read.
        let value_buf = unsafe {
            ::core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), mem::size_of::<T>())
        };

        self.read_exact(addr.into().cast::<u8>(), value_buf)?;

        // SAFETY: every byte of `value` is initialized (zeroed, then
        // overwritten in full by `read_exact`, which returned `Ok`); the
        // caller guarantees that any such bytes form a valid and safe `T`.
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

    /// Writes a value whose type is not yet proven free of padding.
    ///
    /// Transitional (dh-g80yq3): only call sites whose type does not yet
    /// derive `IntoBytes` and `Immutable` use this, each with a `SAFETY`
    /// comment, until they migrate to [`Self::write_value`].
    ///
    /// # Safety
    ///
    /// Every byte of `*value` must be initialized: `T` must have no padding
    /// (including trailing padding) and no field that can hold uninitialized
    /// bytes, and no interior mutability.
    unsafe fn write_value_unchecked<'a, A, T>(&mut self, addr: A, value: &T) -> Result<(), Errno>
    where
        A: Into<AddrMut<'a, T>>,
        T: Sized + 'a,
    {
        // SAFETY: `value` is a live shared reference to `size_of::<T>()`
        // bytes, which the caller guarantees are all initialized; `u8` has
        // alignment 1.
        let value_buf = unsafe {
            ::core::slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>())
        };

        self.write_exact(addr.into().cast::<u8>(), value_buf)
    }

    /// Reads a slice of values. Returns an error if the buffer fails to get
    /// fully filled.
    fn read_values<T>(&self, addr: Addr<T>, buf: &mut [T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        let buf = unsafe {
            ::core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, mem::size_of_val(buf))
        };

        self.read_exact(addr.cast::<u8>(), buf)
    }

    /// Reads a slice of values whose type is not yet proven valid for every
    /// bit pattern. The bytes are read into a zeroed byte buffer first, so
    /// padding inside `buf` is never exposed to the implementation.
    ///
    /// Transitional (dh-g80yq3), like [`Self::read_value_unchecked`].
    ///
    /// # Safety
    ///
    /// As for [`Self::read_value_unchecked`]: every sequence of
    /// `size_of::<T>()` bytes that `addr` can hold must form a valid and safe
    /// `T`, one that could soundly implement zerocopy's `FromBytes`.
    unsafe fn read_values_unchecked<T>(&self, addr: Addr<T>, buf: &mut [T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        let mut bytes = vec![0u8; mem::size_of_val(buf)];
        self.read_exact(addr.cast::<u8>(), &mut bytes)?;
        // SAFETY: `bytes` holds exactly `size_of_val(buf)` initialized bytes
        // and does not overlap `buf`; `buf` is valid for writes of that many
        // bytes. The caller guarantees that each `size_of::<T>()` chunk is a
        // valid and safe `T`, so every element of `buf` is one afterwards.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                buf.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        Ok(())
    }

    /// Writes a slice of values whose type is not yet proven free of padding.
    ///
    /// Transitional (dh-g80yq3), like [`Self::write_value_unchecked`].
    ///
    /// # Safety
    ///
    /// As for [`Self::write_value_unchecked`]: every byte of every element of
    /// `buf` must be initialized.
    unsafe fn write_values_unchecked<T>(&mut self, addr: AddrMut<T>, buf: &[T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        // SAFETY: `buf` is a live shared borrow of `size_of_val(buf)` bytes,
        // which the caller guarantees are all initialized; `u8` has
        // alignment 1.
        let bytes = unsafe {
            ::core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), mem::size_of_val(buf))
        };
        self.write_exact(addr.cast::<u8>(), bytes)
    }

    /// Writes a slice of values. Returns an error if the buffer fails to get
    /// fully written.
    fn write_values<T>(&mut self, addr: AddrMut<T>, buf: &[T]) -> Result<(), Errno>
    where
        T: Sized,
    {
        let buf = unsafe {
            ::core::slice::from_raw_parts(buf.as_ptr() as *const u8, mem::size_of_val(buf))
        };

        self.write_exact(addr.cast::<u8>(), buf)
    }

    /// Reads memory at the given starting address while the boolean returned by
    /// the predicate `pred` is true.
    fn read_while<F>(&self, mut addr: Addr<u8>, buf: &mut [u8], mut pred: F) -> Result<usize, Errno>
    where
        F: FnMut(&[u8]) -> Option<usize>,
    {
        let mut count = 0usize;

        loop {
            let read = self.read(addr, buf)?;
            if read == 0 {
                // We hit an "EOF" (an EFAULT) and the predicate never matched.
                // The predicate should *eventually* return true, so this is
                // always an error.
                return Err(Errno::EFAULT);
            }

            if let Some(used) = pred(&buf[..read]) {
                return count.checked_add(used).ok_or(Errno::EFAULT);
            }

            // Only advance when another chunk is needed. Addresses may name
            // remote memory, so neither in-bounds pointer arithmetic nor a
            // wrapping address is valid for this traversal.
            let next = addr.as_raw().checked_add(read).ok_or(Errno::EFAULT)?;
            addr = Addr::from_raw(next).ok_or(Errno::EFAULT)?;
            count = count.checked_add(read).ok_or(Errno::EFAULT)?;
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

/// Compile-time guard, built by every Buck and Cargo build of this crate:
/// types with invalid bit patterns must never implement `FromBytes`, the
/// trait that admits a type to an unvalidated read from bytes; such types go
/// through `try_read_value`, which validates. If one of these types ever
/// implemented `FromBytes`, both `AmbiguousIfFromBytes` impls would apply to
/// it and the call below would stop resolving, failing the build. (Buck
/// builds no doctest target for this crate, so a doctest could not check it.)
const _: fn() = || {
    trait AmbiguousIfFromBytes<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfFromBytes<()> for T {}
    struct ImplementsFromBytes;
    impl<T: ?Sized + FromBytes> AmbiguousIfFromBytes<ImplementsFromBytes> for T {}

    <bool as AmbiguousIfFromBytes<_>>::check();
    <char as AmbiguousIfFromBytes<_>>::check();
    <core::num::NonZeroU32 as AmbiguousIfFromBytes<_>>::check();
    <&'static u8 as AmbiguousIfFromBytes<_>>::check();
};

/// Tests of the typed value copies: `try_read_value` and the four
/// `*_unchecked` methods. They issue no syscalls, so they also run under
/// `cargo +nightly miri test -p reverie-memory --lib -- value_probe_tests`,
/// which checks that no step reads an uninitialized byte. (The `local` tests
/// issue real syscalls, which Miri cannot execute.)
#[cfg(test)]
mod value_probe_tests {
    use std::cell::Cell;

    use super::*;

    /// Copies through Rust references to memory in this process, like
    /// `LocalMemory`, but in safe code and without syscalls, so Miri can run
    /// it. A read copies at most `readable` bytes in total, then returns 0,
    /// as a remote read does at an unmapped page. Before each read it sums
    /// the destination bytes it was handed: safe code may read them, so the
    /// caller must hand over initialized bytes.
    struct InProcess {
        readable: Cell<usize>,
        destination_sum: Cell<u64>,
    }

    impl InProcess {
        fn new() -> Self {
            Self::with_readable(usize::MAX)
        }

        fn with_readable(readable: usize) -> Self {
            Self {
                readable: Cell::new(readable),
                destination_sum: Cell::new(0),
            }
        }

        fn copy(read_from: &[io::IoSlice], write_to: &mut [io::IoSliceMut], limit: usize) -> usize {
            let mut copied = 0;
            for (from, to) in read_from.iter().zip(write_to.iter_mut()) {
                let length = from.len().min(to.len()).min(limit - copied);
                to[..length].copy_from_slice(&from[..length]);
                copied += length;
            }
            copied
        }
    }

    impl MemoryAccess for InProcess {
        fn read_vectored(
            &self,
            read_from: &[io::IoSlice],
            write_to: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            let sum = write_to
                .iter()
                .flat_map(|to| to.iter())
                .map(|&byte| u64::from(byte))
                .sum::<u64>();
            self.destination_sum.set(self.destination_sum.get() + sum);
            let copied = Self::copy(read_from, write_to, self.readable.get());
            self.readable.set(self.readable.get() - copied);
            Ok(copied)
        }

        fn write_vectored(
            &mut self,
            read_from: &[io::IoSlice],
            write_to: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            Ok(Self::copy(read_from, write_to, usize::MAX))
        }
    }

    /// `repr(C)` with 3 padding bytes after `tag` and 2 trailing: 12 bytes, 7
    /// of them fields.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Padded {
        tag: u8,
        word: u32,
        half: u16,
    }

    const PADDED: Padded = Padded {
        tag: 0x11,
        word: 0x2233_4455,
        half: 0x6677,
    };

    /// The guest bytes of `PADDED`, with 0xee in every padding position.
    fn padded_bytes() -> [u8; 12] {
        let mut bytes = [0xee; 12];
        bytes[0] = PADDED.tag;
        bytes[4..8].copy_from_slice(&PADDED.word.to_ne_bytes());
        bytes[8..10].copy_from_slice(&PADDED.half.to_ne_bytes());
        bytes
    }

    /// `repr(C)` with no padding: 8 bytes, all fields.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Unpadded {
        word: u32,
        low: u16,
        high: u16,
    }

    #[test]
    fn read_value_unchecked_reads_a_padded_struct_through_initialized_bytes() {
        let backing = padded_bytes();
        assert_eq!(mem::size_of::<Padded>(), backing.len());
        let memory = InProcess::new();
        let at = Addr::from_ptr(backing.as_ptr().cast::<Padded>()).unwrap();

        // SAFETY: `Padded` has only integer fields, so any 12 bytes are a
        // valid and safe `Padded`.
        let value = unsafe { memory.read_value_unchecked(at) };

        assert_eq!(value, Ok(PADDED), "every field is read from its offset");
        assert_eq!(
            memory.destination_sum.get(),
            0,
            "the bytes handed to the read are initialized, and zero"
        );
    }

    #[test]
    fn read_values_unchecked_reads_padded_structs_through_initialized_bytes() {
        let backing = [padded_bytes(), padded_bytes()].concat();
        let memory = InProcess::new();
        let at = Addr::from_ptr(backing.as_ptr().cast::<Padded>()).unwrap();
        let mut values = [Padded {
            tag: 0,
            word: 0,
            half: 0,
        }; 2];

        // SAFETY: as above, any bytes are a valid and safe `Padded`.
        let result = unsafe { memory.read_values_unchecked(at, &mut values) };

        assert_eq!(result, Ok(()));
        assert_eq!(values, [PADDED; 2]);
        assert_eq!(
            memory.destination_sum.get(),
            0,
            "staged through zeroed bytes"
        );
    }

    #[test]
    fn unchecked_reads_stop_with_efault_at_a_short_read() {
        // Seven of `Padded`'s twelve bytes are readable.
        let backing = padded_bytes();
        let memory = InProcess::with_readable(7);
        let at = Addr::from_ptr(backing.as_ptr().cast::<Padded>()).unwrap();
        // SAFETY: as above.
        let value = unsafe { memory.read_value_unchecked(at) };
        assert_eq!(value, Err(Errno::EFAULT), "a short read builds no value");

        let memory = InProcess::with_readable(7);
        let mut values = [PADDED; 1];
        // SAFETY: as above.
        let result = unsafe { memory.read_values_unchecked(at, &mut values) };
        assert_eq!(result, Err(Errno::EFAULT));
        assert_eq!(
            values,
            [PADDED],
            "a short read leaves the destination unchanged"
        );
    }

    #[test]
    fn unchecked_writes_round_trip_through_unchecked_reads() {
        let value = Unpadded {
            word: 0x0102_0304,
            low: 0x0506,
            high: 0x0708,
        };
        let mut memory = InProcess::new();
        let mut guest = [0u8; 16];
        let first = AddrMut::from_ptr(guest.as_mut_ptr().cast::<Unpadded>()).unwrap();

        // SAFETY: `Unpadded` has no padding and only integer fields, so every
        // byte of `value` is initialized.
        let wrote = unsafe { memory.write_value_unchecked(first, &value) };
        assert_eq!(wrote, Ok(()));
        let second = AddrMut::from_ptr(guest[8..].as_mut_ptr().cast::<Unpadded>()).unwrap();
        // SAFETY: as for the write above, for each element.
        let wrote = unsafe { memory.write_values_unchecked(second, &[value]) };
        assert_eq!(wrote, Ok(()));

        let expected = [
            &value.word.to_ne_bytes()[..],
            &value.low.to_ne_bytes(),
            &value.high.to_ne_bytes(),
        ]
        .concat();
        assert_eq!(guest[..8], expected[..], "write_value_unchecked bytes");
        assert_eq!(guest[8..], expected[..], "write_values_unchecked bytes");

        let at = Addr::from_ptr(guest.as_ptr().cast::<Unpadded>()).unwrap();
        // SAFETY: `Unpadded` has only integer fields, so any bytes are a valid
        // and safe `Unpadded`.
        assert_eq!(unsafe { memory.read_value_unchecked(at) }, Ok(value));
        let mut both = [Unpadded {
            word: 0,
            low: 0,
            high: 0,
        }; 2];
        // SAFETY: as above.
        let read = unsafe { memory.read_values_unchecked(at, &mut both) };
        assert_eq!(read, Ok(()));
        assert_eq!(both, [value; 2]);
    }

    #[test]
    fn try_read_value_rejects_invalid_bit_patterns() {
        // A `bool` is 0 or 1; 2 is not a valid `bool`.
        let backing = [2u8, 1, 0];
        let memory = InProcess::new();
        let at = |index: usize| Addr::from_ptr(backing[index..].as_ptr().cast::<bool>()).unwrap();

        assert_eq!(
            memory.try_read_value(at(0)),
            Err(Errno::EINVAL),
            "the byte 2 is not a bool, so no bool is built"
        );
        assert_eq!(memory.try_read_value(at(1)), Ok(true), "the byte 1 is true");
        assert_eq!(
            memory.try_read_value(at(2)),
            Ok(false),
            "the byte 0 is false"
        );
    }
}

#[cfg(test)]
mod user_access_default_tests {
    use super::*;
    struct LegacyWriter {
        calls: usize,
    }
    impl MemoryAccess for LegacyWriter {
        fn read_vectored(
            &self,
            _: &[io::IoSlice],
            _: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            panic!("copyout must not probe memory")
        }
        fn write_vectored(
            &mut self,
            _: &[io::IoSlice],
            _: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            panic!("new capability must not fall back to vectored debugger writes")
        }
        fn write(&mut self, _: AddrMut<u8>, bytes: &[u8]) -> Result<usize, Errno> {
            self.calls += 1;
            Ok(bytes.len())
        }
    }
    #[test]
    fn unsupported_user_copy_never_falls_back_to_debugger_write() {
        let mut memory = LegacyWriter { calls: 0 };
        let address = AddrMut::from_raw(usize::MAX).unwrap();
        for bytes in [&[][..], &[1, 2, 3, 4, 5, 6, 7][..], &[0; 8][..]] {
            assert_eq!(
                memory.write_with_user_access(address, bytes),
                Err(Errno::ENOSYS)
            );
            assert_eq!(memory.calls, 0);
        }
        assert_eq!(memory.write(address, &[0; 8]), Ok(8));
        assert_eq!(memory.calls, 1);
    }
}

#[cfg(test)]
mod native_user_write_tests {
    use super::*;

    #[test]
    fn native_user_write_default_refuses_without_using_ordinary_memory_access() {
        struct Unsupported;
        impl MemoryAccess for Unsupported {
            fn read_vectored(
                &self,
                _: &[io::IoSlice],
                _: &mut [io::IoSliceMut],
            ) -> Result<usize, Errno> {
                panic!("native write must not call ordinary read");
            }

            fn write_vectored(
                &mut self,
                _: &[io::IoSlice],
                _: &mut [io::IoSliceMut],
            ) -> Result<usize, Errno> {
                panic!("native write must not call ordinary write");
            }
        }

        let mut memory = Unsupported;
        let local = [io::IoSlice::new(b"newbytes")];
        let target = [0xa5; 8];
        let remote = [RemoteIoVec::new(AddrMut::from_ptr(target.as_ptr()).unwrap(), 8).unwrap()];
        let result = memory.write_native_user_vectored(1, &local, &remote);
        assert_eq!(result, Err(Errno::EOPNOTSUPP));
        assert_eq!(Errno::EOPNOTSUPP, Errno::new(libc::ENOTSUP));
        assert_eq!(target, [0xa5; 8]);
    }
}

#[cfg(test)]
mod compare_exchange_default_tests {
    use super::*;

    #[test]
    fn compare_exchange_default_refuses_without_using_ordinary_memory_access() {
        struct Unsupported;
        impl MemoryAccess for Unsupported {
            fn read_vectored(
                &self,
                _: &[io::IoSlice],
                _: &mut [io::IoSliceMut],
            ) -> Result<usize, Errno> {
                panic!("compare-exchange must not fall back to a read");
            }

            fn write_vectored(
                &mut self,
                _: &[io::IoSlice],
                _: &mut [io::IoSliceMut],
            ) -> Result<usize, Errno> {
                panic!("compare-exchange must not fall back to a write");
            }
        }

        let word = 7u32;
        let address = AddrMut::from_ptr(&word as *const u32).unwrap();
        assert_eq!(
            Unsupported.compare_exchange_u32(address, 7, 8),
            Err(Errno::ENOSYS)
        );
        assert_eq!(word, 7);
    }
}
