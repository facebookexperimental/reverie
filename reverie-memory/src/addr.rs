/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;
// Only used for `IoSlice`. To be fully no_std, this should get replaced with a
// custom `IoSlice` type.
use std::io;

/// An address to some immutable memory. We don't know where the memory lives;
/// it can be either in the current process or a another process.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Addr<'a, T> {
    // This is our non-null pointer. Since this may not point to memory in the
    // same process, we need to be very careful to never dereference this.
    inner: NonNull<T>,
    _p: PhantomData<&'a T>,
}

impl<'a, T> From<usize> for Addr<'a, T> {
    fn from(raw: usize) -> Self {
        Self::from_raw(raw).unwrap()
    }
}

impl<'a, T> Addr<'a, T> {
    /// Construct an address pointing to mutable data from a raw u64. Useful for
    /// converting a syscall register to a pointer.
    pub fn from_raw(raw: usize) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(unsafe { Self::from_raw_unchecked(raw) })
        }
    }

    /// Creates an address pointing to mutable data from a raw pointer. If the
    /// pointer is null, then `None` will be returned.
    pub fn from_ptr(r: *const T) -> Option<Self> {
        NonNull::new(r as *mut T).map(|p| Self {
            inner: p,
            _p: PhantomData,
        })
    }

    /// Construct an address from a raw u64 without checking if it is null.
    ///
    /// # Safety
    ///
    /// `raw` must be non-zero.
    pub unsafe fn from_raw_unchecked(raw: usize) -> Self {
        Self {
            inner: NonNull::new_unchecked(raw as *mut T),
            _p: PhantomData,
        }
    }

    /// Casts this pointer to a mutable pointer.
    ///
    /// # Safety
    ///
    /// This method is unsafe for numerous reasons.
    pub unsafe fn into_mut(self) -> AddrMut<'a, T> {
        AddrMut {
            inner: self.inner,
            _p: PhantomData,
        }
    }

    /// Returns a raw pointer.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the pointer returned by this function
    /// should never be dereferenced as it could point to memory outside of the
    /// current address space.
    #[allow(clippy::wrong_self_convention)]
    pub unsafe fn as_ptr(self) -> *const T {
        self.inner.as_ptr()
    }

    /// Returns the raw integer value of the address.
    #[allow(clippy::wrong_self_convention)]
    pub fn as_raw(self) -> usize {
        self.inner.as_ptr() as usize
    }

    /// Casts the address into an address of another type.
    pub fn cast<U>(self) -> Addr<'a, U> {
        Addr {
            inner: self.inner.cast(),
            _p: PhantomData,
        }
    }

    /// Returns a new address relative to the current address + `count *
    /// size_of::<T>()`.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the new address may not point to valid
    /// memory.
    pub unsafe fn offset(self, count: isize) -> Self {
        Self {
            inner: NonNull::new_unchecked(self.inner.as_ptr().offset(count)),
            _p: PhantomData,
        }
    }

    /// Returns a new address plus `count * size_of::<T>()`.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the new address may not point to valid
    /// memory.
    #[allow(clippy::should_implement_trait)]
    pub unsafe fn add(self, count: usize) -> Self {
        self.offset(count as isize)
    }
}

impl<'a, T> From<&'a T> for Addr<'a, T> {
    fn from(inner: &'a T) -> Self {
        Self {
            inner: NonNull::from(inner),
            _p: PhantomData,
        }
    }
}

impl<'a, T> fmt::Debug for Addr<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

impl<'a, T> fmt::Display for Addr<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

impl<'a, T> fmt::Pointer for Addr<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

/// An address to some mutable memory. We don't know where the memory lives; it
/// can be either in the current process or a another process.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct AddrMut<'a, T> {
    // This is our non-null pointer. Since this may not point to memory in the
    // same process, we need to be very careful to never dereference this.
    inner: NonNull<T>,
    _p: PhantomData<&'a mut T>,
}

impl<'a, T> AddrMut<'a, T> {
    /// Construct an address from a raw `usize`. Useful for converting a syscall
    /// register to a pointer. If the raw value is 0, then `None` is returned.
    pub fn from_raw(raw: usize) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(unsafe { Self::from_raw_unchecked(raw) })
        }
    }

    /// Creates an address from a raw pointer. If the pointer is null, then
    /// `None` will be returned.
    pub fn from_ptr(r: *const T) -> Option<Self> {
        NonNull::new(r as *mut T).map(|p| Self {
            inner: p,
            _p: PhantomData,
        })
    }

    /// Construct an address from a raw u64 without checking if it is null.
    ///
    /// # Safety
    ///
    /// `raw` must be non-zero.
    pub unsafe fn from_raw_unchecked(raw: usize) -> Self {
        Self {
            inner: NonNull::new_unchecked(raw as *mut T),
            _p: PhantomData,
        }
    }

    /// Returns a raw mutable pointer.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the pointer returned by this function
    /// should never be dereferenced as it could point to memory outside of the
    /// current address space.
    #[allow(clippy::wrong_self_convention)]
    pub unsafe fn as_mut_ptr(self) -> *mut T {
        self.inner.as_ptr()
    }

    /// Returns the raw integer value of the address.
    #[allow(clippy::wrong_self_convention)]
    pub fn as_raw(self) -> usize {
        self.inner.as_ptr() as usize
    }

    /// Casts the address into an address of another type.
    pub fn cast<U>(self) -> AddrMut<'a, U> {
        AddrMut {
            inner: self.inner.cast(),
            _p: PhantomData,
        }
    }

    /// Returns a new address relative to the current address + `count *
    /// size_of::<T>()`.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the new address may not point to valid
    /// memory.
    pub unsafe fn offset(self, count: isize) -> Self {
        Self {
            inner: NonNull::new_unchecked(self.inner.as_ptr().offset(count)),
            _p: PhantomData,
        }
    }

    /// Returns a new address plus `count * size_of::<T>()`.
    ///
    /// # Safety
    ///
    /// This method is unsafe because the new address may not point to valid
    /// memory.
    #[allow(clippy::should_implement_trait)]
    pub unsafe fn add(self, count: usize) -> Self {
        self.offset(count as isize)
    }
}

impl<'a, T> From<AddrMut<'a, T>> for Addr<'a, T> {
    fn from(addr: AddrMut<'a, T>) -> Self {
        Self {
            inner: addr.inner,
            _p: PhantomData,
        }
    }
}

impl<'a, T> From<&'a T> for AddrMut<'a, T> {
    fn from(inner: &'a T) -> Self {
        Self {
            inner: NonNull::from(inner),
            _p: PhantomData,
        }
    }
}

impl<'a, T> fmt::Debug for AddrMut<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

impl<'a, T> fmt::Display for AddrMut<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

impl<'a, T> fmt::Pointer for AddrMut<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.inner, f)
    }
}

unsafe impl<'a, T> Send for Addr<'a, T> where T: Send {}
unsafe impl<'a, T> Send for AddrMut<'a, T> where T: Send {}

/// A slice of some read-only memory. The memory can be in this process or in
/// another process.
#[derive(Copy, Clone)]
pub struct AddrSlice<'a, T> {
    inner: &'a [T],
}

impl<'a, T> AddrSlice<'a, T> {
    /// Creates the slice from its raw parts.
    ///
    /// # Safety
    ///
    /// This method is unsafe for the same reasons that
    /// [`std::slice::from_raw_parts`] is unsafe.
    pub unsafe fn from_raw_parts(addr: Addr<'a, T>, len: usize) -> Self {
        Self {
            inner: ::core::slice::from_raw_parts(addr.as_ptr(), len),
        }
    }

    /// Divides one slice into two at an index. Panics if `mid > len`.
    pub fn split_at(&self, mid: usize) -> (Self, Self) {
        let (a, b) = self.inner.split_at(mid);
        (Self { inner: a }, Self { inner: b })
    }

    /// Returns the number of elements in the slice.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Splits the slice at the next page boundary if the slice spans two pages.
    /// Returns `None` if the slice does not span two pages. Thus, both slices
    /// are guaranteed to be non-empty.
    pub fn split_at_page_boundary(&self) -> Option<(Self, Self)> {
        let addr = self.inner.as_ptr() as usize;

        // Get the offset to the next page. If this is larger than (or equal to)
        // the length of the slice, then it's not possible to split the slice.
        let offset = next_page(addr) - addr;

        if offset < self.len() {
            Some(self.split_at(offset))
        } else {
            None
        }
    }
}

impl<'a> AddrSlice<'a, u8> {
    /// Returns an `IoSlice` representing this `AddrSlice`.
    ///
    /// # Safety
    /// This function is unsafe because it gives access to raw pointers, which
    /// may not be valid for the current address space.
    pub unsafe fn as_ioslice(&self) -> io::IoSlice {
        io::IoSlice::new(self.inner)
    }
}

/// A slice of some writable memory. The memory can be in this process or in
/// another process.
pub struct AddrSliceMut<'a, T> {
    inner: &'a mut [T],
}

impl<'a, T> AddrSliceMut<'a, T> {
    /// Creates the slice from its raw parts.
    ///
    /// # Safety
    ///
    /// This method is unsafe for the same reasons that
    /// [`std::slice::from_raw_parts`] is unsafe.
    pub unsafe fn from_raw_parts(addr: AddrMut<'a, T>, len: usize) -> Self {
        Self {
            inner: ::core::slice::from_raw_parts_mut(addr.as_mut_ptr(), len),
        }
    }

    /// Divides one slice into two at an index.
    pub fn split_at(&'a mut self, mid: usize) -> (Self, Self) {
        let (a, b) = self.inner.split_at_mut(mid);
        (Self { inner: a }, Self { inner: b })
    }

    /// Returns the number of elements in the slice.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Splits the slice at the next page boundary if the slice spans two pages.
    /// Returns `None` if the slice does not span two pages. Thus, both slices
    /// are guaranteed to be non-empty.
    pub fn split_at_page_boundary(&'a mut self) -> Option<(Self, Self)> {
        let addr = self.inner.as_ptr() as usize;

        // Get the offset to the next page. If this is larger than (or equal to)
        // the length of the slice, then it's not possible to split the slice.
        let offset = next_page(addr) - addr;

        if offset < self.len() {
            Some(self.split_at(offset))
        } else {
            None
        }
    }
}

impl<'a> AddrSliceMut<'a, u8> {
    /// Returns an `IoSliceMut` representing this `AddrSliceMut`.
    ///
    /// # Safety
    /// This function is unsafe because it gives access to raw pointers, which
    /// may not be valid for the current address space.
    pub unsafe fn as_ioslice_mut(&mut self) -> io::IoSliceMut {
        io::IoSliceMut::new(self.inner)
    }
}

/// Finds the boundary for the next page. Note that this is different than simply
/// aligning an address on a page boundary.
fn next_page(addr: usize) -> usize {
    const PAGE_SIZE: usize = 0x1000;
    (addr + PAGE_SIZE) & (!PAGE_SIZE + 1)
}

#[cfg(test)]
mod test {
    use core::mem::align_of;
    use core::mem::size_of;

    use super::*;

    #[test]
    fn test_next_page() {
        assert_eq!(next_page(0x1000), 0x2000);
        assert_eq!(next_page(0x1), 0x1000);
        assert_eq!(next_page(0x0), 0x1000);
        assert_eq!(next_page(0x1234), 0x2000);
    }

    #[test]
    fn test_addr() {
        // Ensure that we haven't perturbed the size or alignment of the
        // address. We rely on the fact that it is the same size as a regular
        // pointer.
        assert_eq!(size_of::<Addr<u8>>(), size_of::<*const u8>());
        assert_eq!(size_of::<Addr<u8>>(), size_of::<&u8>());
        assert_eq!(size_of::<Option<Addr<u8>>>(), size_of::<*const u8>());
        assert_eq!(size_of::<Option<Addr<u8>>>(), size_of::<&u8>());
        assert_eq!(align_of::<Option<Addr<u8>>>(), align_of::<*const u8>());
        assert_eq!(align_of::<Option<Addr<u8>>>(), align_of::<&u8>());

        assert_eq!(Addr::<u8>::from_raw(0), None);

        // Test comparison operators.
        assert_eq!(
            Addr::<u8>::from_raw(0xdeadbeef),
            Addr::<u8>::from_raw(0xdeadbeef)
        );
        assert_ne!(
            Addr::<u8>::from_raw(0xdeadbeef),
            Addr::<u8>::from_raw(0xbaadf00d)
        );
        assert!(Addr::<u8>::from_raw(0x1000).unwrap() < Addr::<u8>::from_raw(0x1001).unwrap());

        assert_eq!(
            format!("{:p}", Addr::<u8>::from_raw(0x1000).unwrap()),
            "0x1000"
        );
    }

    #[test]
    fn test_addr_slice_size() {
        // Ensure that we haven't purturbed the size. We rely on the fact that
        // it is the same size as a regular slice.
        assert_eq!(size_of::<AddrSlice<u8>>(), size_of::<&[u8]>());
        assert_eq!(size_of::<Option<AddrSlice<u8>>>(), size_of::<&[u8]>());
        assert_eq!(size_of::<AddrSliceMut<u8>>(), size_of::<&mut [u8]>());
        assert_eq!(
            size_of::<Option<AddrSliceMut<u8>>>(),
            size_of::<&mut [u8]>()
        );
    }
}
