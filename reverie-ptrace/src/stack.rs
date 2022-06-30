/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use crate::trace::Error as TraceError;
use crate::trace::Stopped;

use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::Errno;
use reverie::Pid;
use reverie::Stack;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

// NB: leaf function can use redzone without explicit stack allocation, as
// a result it is not safe to just adjust stack pointer. 128B of stack
// space is mostly wasted -- to avoid the corner case when redzone is used.
const REDZONE_SIZE: usize = 128;

// TODO: track actual guest stack size complexity.
// Right now this just uses a conservatively low number and we assume the
// guest stack is bigger than that.
const STACK_CAPACITY: usize = 1024 - REDZONE_SIZE;

// keep in mind stack grows towards lower address, at least on major
// platforms.
pub struct GuestStack {
    top: usize,
    sp: usize,
    capacity: usize,
    buf: Vec<u64>,
    task: Stopped,
    flag: Arc<AtomicBool>,
}

impl GuestStack {
    pub fn new(pid: Pid, flag: Arc<AtomicBool>) -> Result<Self, TraceError> {
        let old = flag.swap(true, Ordering::SeqCst);
        if old {
            panic!(
                "Invariant violation, cannot retrieve handle on guest Stack when there is already a StackGuard still alive."
            );
        }
        let task = Stopped::new_unchecked(pid);
        let rsp = task.getregs()?.rsp as usize;
        let top = rsp - REDZONE_SIZE as usize;
        Ok(GuestStack {
            top,
            sp: top,
            capacity: STACK_CAPACITY,
            buf: Vec::new(),
            task,
            flag,
        })
    }

    fn allocate<'stack, T>(&mut self, value: T) -> AddrMut<'stack, T> {
        let mut buf = unsafe { transmute_u64s(value) };
        let buf_size = buf.len() * core::mem::size_of::<u64>();
        if self.size() + buf_size > self.capacity() {
            panic!(
                "guest(pid={}) stack overflow, capacity = {}",
                self.task.pid(),
                self.capacity()
            );
        } else {
            self.sp -= buf_size;
            buf.reverse();
            self.buf.extend_from_slice(buf.as_slice());
            AddrMut::from_raw(self.sp).unwrap()
        }
    }
}

// We need to use the StackGuard to prevent REENTRANCY.  That is, you cannot call
// `Stack::new` while there is still an outstanding guard.  We don't have any way to keep
// them from colliding at the moment.
#[derive(Debug)]
// TODO: Ideally we would have some way to connect the actual `Addr` references into the
// guest heap to the lifetime of the StackGuard (like the ST monad in Haskell).
pub struct StackGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for StackGuard {
    fn drop(&mut self) {
        let old = self.flag.swap(false, Ordering::SeqCst);
        if !old {
            panic!(
                "Invariant violation, when dropping StackGuard, the internal flag was not set as expected."
            )
        }
    }
}

impl Stack for GuestStack {
    type StackGuard = StackGuard;

    fn size(&self) -> usize {
        (self.top - self.sp) as usize
    }
    fn capacity(&self) -> usize {
        self.capacity
    }
    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        self.allocate(value).into()
    }
    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        let value: T = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        self.allocate(value)
    }
    fn commit(mut self) -> Result<Self::StackGuard, Errno> {
        let remote_sp: AddrMut<u8> = AddrMut::from_raw(self.sp).unwrap();
        self.buf.reverse();
        let from =
            unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const u8, self.size()) };
        self.task.write_exact(remote_sp, from)?;
        Ok(StackGuard { flag: self.flag })
    }
}

impl MemoryAccess for GuestStack {
    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.task.read_vectored(read_from, write_to)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.task.write_vectored(read_from, write_to)
    }
}

#[inline]
pub unsafe fn transmute_u64s<T: Sized>(value: T) -> Vec<u64> {
    let value_ptr = &value as *const T as *const u8;
    let size = core::mem::size_of::<T>();
    let mut result: Vec<u64> = Vec::new();

    let mut k = 0;
    let mut n = size;

    // use copy_nonloverlapping?
    while n >= 8 {
        let ptr: *const u64 = value_ptr.offset(k).cast();
        result.push(ptr.read());
        n -= 8;
        k += 8;
    }

    if n != 0 {
        let mut val: u64 = 0;
        let src = value_ptr.offset(k);
        let dst = &mut val as *mut u64 as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, n);
        result.push(val);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmute_sanity() {
        assert_eq!(unsafe { transmute_u64s(1usize) }, vec![1]);
        assert_eq!(unsafe { transmute_u64s(1u8) }, vec![1]);
        assert_eq!(unsafe { transmute_u64s(0x12u16) }, vec![0x12]);
        assert_eq!(unsafe { transmute_u64s(0x1234u32) }, vec![0x1234]);
        assert_eq!(unsafe { transmute_u64s(0x12345678i32) }, vec![0x12345678]);

        let arr: [u8; 1] = [0x11];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x11]);

        let arr: [u8; 2] = [0x11, 0x22];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x2211]);

        let arr: [u8; 3] = [0x11, 0x22, 0x33];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x332211]);

        let arr: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x44332211]);

        let arr: [u8; 5] = [0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x5544332211]);

        let arr: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x665544332211]);

        let arr: [u8; 7] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x0077665544332211u64]);

        let arr: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        assert_eq!(unsafe { transmute_u64s(arr) }, vec![0x8877665544332211]);

        let arr: [u8; 9] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        assert_eq!(
            unsafe { transmute_u64s(arr) },
            vec![0x8877665544332211, 0x99]
        );

        let arr: [u8; 10] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];
        assert_eq!(
            unsafe { transmute_u64s(arr) },
            vec![0x8877665544332211, 0xaa99]
        );

        let tp: libc::timespec = libc::timespec {
            tv_sec: 0x12,
            tv_nsec: 0x3456789a,
        };

        assert_eq!(unsafe { transmute_u64s(tp) }, vec![0x12, 0x3456789a]);
    }
}
