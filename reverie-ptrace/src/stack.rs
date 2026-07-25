/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Pid;
use reverie::Stack;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use safeptrace::Error as TraceError;
use safeptrace::Stopped;

use super::regs::RegAccess;

// NB: leaf function can use redzone without explicit stack allocation, as
// a result it is not safe to just adjust stack pointer. 128B of stack
// space is mostly wasted -- to avoid the corner case when redzone is used.
const REDZONE_SIZE: usize = 128;

// TODO: track actual guest stack size complexity.
// Right now this just uses a conservatively low number and we assume the
// guest stack is bigger than that.
const STACK_CAPACITY: usize = 1024 - REDZONE_SIZE;

/// RAII token recording that a task's single guest stack is currently checked
/// out. Acquiring flips the per-task flag; dropping the token -- whether from an
/// uncommitted [`GuestStack`] or from the [`StackGuard`] that [`Stack::commit`]
/// hands back -- clears the flag so the next `stack()` acquisition can succeed.
///
/// Previously the flag was cleared *only* by `StackGuard::drop`, and
/// `StackGuard` is produced only by a successful `commit`. Because `GuestStack`
/// had no `Drop`, any acquisition that was dropped without committing leaked the
/// flag forever: every error path inside `commit` itself (the `EFAULT` and
/// `write_exact` returns), a failed register read in `new`, and any early return
/// between `stack()` and `commit()` in a consumer. The next `stack()` on that
/// task then panicked with "already a StackGuard still alive" even though no
/// stack was actually live. Making the checkout RAII releases the flag on every
/// drop path while still catching a genuine *simultaneous* second checkout.
#[derive(Debug)]
struct StackToken {
    flag: Arc<AtomicBool>,
}

impl StackToken {
    /// Acquire the checkout. Returns `None` when a stack is already checked out
    /// for this task, i.e. a real reentrant acquisition while another handle is
    /// still alive.
    fn acquire(flag: Arc<AtomicBool>) -> Option<Self> {
        if flag.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(StackToken { flag })
        }
    }
}

impl Drop for StackToken {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

// keep in mind stack grows towards lower address, at least on major
// platforms.
pub struct GuestStack {
    top: usize,
    sp: usize,
    capacity: usize,
    buf: Vec<u64>,
    task: Stopped,
    token: StackToken,
}

impl GuestStack {
    pub fn new(pid: Pid, flag: Arc<AtomicBool>) -> Result<Self, TraceError> {
        let token = match StackToken::acquire(flag) {
            Some(token) => token,
            None => panic!(
                "Invariant violation, cannot retrieve handle on guest Stack when there is already a StackGuard still alive."
            ),
        };
        let task = Stopped::new_unchecked(pid);
        // If the register read fails, `token` is dropped on this early return and
        // the flag is released, so a later retry on the same task is not poisoned.
        let rsp = task.getregs()?.stack_ptr() as usize;
        let top = rsp - REDZONE_SIZE;
        Ok(GuestStack {
            top,
            sp: top,
            capacity: STACK_CAPACITY,
            buf: Vec::new(),
            task,
            token,
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
            AddrMut::from_raw(self.sp)
                .expect("guest stack allocation produced a null remote stack pointer")
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
    // Holding the checkout token keeps the per-task flag set for as long as the
    // committed stack data must stay live; dropping the guard releases it.
    _token: StackToken,
}

// `reverie::Stack::StackGuard` requires `Drop`. The flag release itself happens
// in the `StackToken` field's own drop glue, which runs after this; an explicit
// (empty) impl is only needed to satisfy that trait bound.
impl Drop for StackGuard {
    fn drop(&mut self) {}
}

impl Stack for GuestStack {
    type StackGuard = StackGuard;

    fn size(&self) -> usize {
        self.top - self.sp
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
        let remote_sp: AddrMut<u8> = AddrMut::from_raw(self.sp).ok_or(Errno::EFAULT)?;
        self.buf.reverse();
        let from =
            unsafe { core::slice::from_raw_parts(self.buf.as_ptr() as *const u8, self.size()) };
        // Any `?` above returns early and drops `self`, releasing the checkout
        // token so a failed commit does not poison the next acquisition. On
        // success we transfer the token into the guard, which keeps the flag set
        // until the caller drops the guard.
        self.task.write_exact(remote_sp, from)?;
        Ok(StackGuard { _token: self.token })
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
    unsafe {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the "already a StackGuard still alive" panic: a stack
    // checkout dropped without a successful `commit` must release the per-task
    // flag so the next acquisition does not spuriously panic. Before the RAII
    // fix, the flag was only cleared by `StackGuard::drop`, so this sequence left
    // it stuck set.
    #[test]
    fn stack_token_releases_on_drop_without_commit() {
        let flag = Arc::new(AtomicBool::new(false));
        {
            let _token = StackToken::acquire(flag.clone()).expect("first acquire succeeds");
            assert!(flag.load(Ordering::SeqCst), "flag is set while checked out");
            // Dropped here WITHOUT transferring into a StackGuard, mirroring an
            // error path or early return between `stack()` and `commit()`.
        }
        assert!(
            !flag.load(Ordering::SeqCst),
            "flag is cleared once the uncommitted checkout drops"
        );
        assert!(
            StackToken::acquire(flag).is_some(),
            "a fresh acquisition after a dropped checkout succeeds instead of panicking"
        );
    }

    // The genuine reentrancy invariant is preserved: an overlapping second
    // checkout is still detected while the first token is alive.
    #[test]
    fn stack_token_detects_simultaneous_checkout() {
        let flag = Arc::new(AtomicBool::new(false));
        let _first = StackToken::acquire(flag.clone()).expect("first acquire succeeds");
        assert!(
            StackToken::acquire(flag).is_none(),
            "an overlapping checkout is refused while the first is still alive"
        );
    }

    // Transferring the token into a StackGuard keeps the flag set until the guard
    // itself drops, matching the committed-stack lifetime.
    #[test]
    fn stack_guard_holds_then_releases_flag() {
        let flag = Arc::new(AtomicBool::new(false));
        let token = StackToken::acquire(flag.clone()).expect("acquire succeeds");
        let guard = StackGuard { _token: token };
        assert!(
            flag.load(Ordering::SeqCst),
            "flag stays set while the guard is alive"
        );
        drop(guard);
        assert!(
            !flag.load(Ordering::SeqCst),
            "flag is cleared after the guard drops"
        );
    }

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
