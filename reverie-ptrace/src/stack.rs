/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;

use reverie::Errno;
use reverie::Pid;
use reverie::Stack;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use safeptrace::Error as TraceError;
use safeptrace::Stopped;

use super::regs::RegAccess;
use crate::tool_memory::ToolMemory;

// NB: leaf function can use redzone without explicit stack allocation, as
// a result it is not safe to just adjust stack pointer. 128B of stack
// space is mostly wasted -- to avoid the corner case when redzone is used.
const REDZONE_SIZE: usize = 128;

// TODO: track actual guest stack size complexity.
// Right now this just uses a conservatively low number and we assume the
// guest stack is bigger than that.
const STACK_CAPACITY: usize = 1024 - REDZONE_SIZE;

#[path = "stack_frames.rs"]
mod frames;
use frames::CheckoutError;
pub(crate) use frames::StackArena;
use frames::StackToken;

// keep in mind stack grows towards lower address, at least on major
// platforms.
pub struct GuestStack {
    top: usize,
    sp: usize,
    capacity: usize,
    buf: Vec<u64>,
    // The commit is a Tool write into guest-chosen memory (the guest controls
    // its stack pointer), so it respects page protection and the private page
    // as every other Tool write does (https://github.com/rrnewton/reverie/issues/1064).
    task: ToolMemory,
    token: StackToken,
}

impl GuestStack {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Preserve the Native constructor; production callbacks retain their existing stopped capability."
        )
    )]
    pub(crate) fn new(pid: Pid, arena: Arc<StackArena>) -> Result<Self, TraceError> {
        Self::from_stopped(Stopped::new_unchecked(pid), arena)
    }

    /// Retain the task's original generation and ptracer-thread authority.
    /// The caller supplies its already stopped capability, without a new PID lookup.
    pub(crate) fn new_on_ptracer_thread(
        task: Stopped,
        arena: Arc<StackArena>,
    ) -> Result<Self, TraceError> {
        Self::from_stopped(task, arena)
    }

    fn from_stopped(task: Stopped, arena: Arc<StackArena>) -> Result<Self, TraceError> {
        // Read through the existing stopped capability before claiming space.
        // A failed/foreign-owner read cannot acquire or release any frame.
        let rsp = task.getregs()?.stack_ptr() as usize;
        let token = match StackToken::acquire(arena, task.generation(), rsp) {
            Ok(token) => token,
            Err(CheckoutError::Uncommitted) => panic!(
                "Invariant violation, cannot retrieve guest Stack while an uncommitted stack builder is still alive."
            ),
            Err(CheckoutError::ChangedContext) => return Err(Errno::EBUSY.into()),
            Err(CheckoutError::AddressUnderflow | CheckoutError::IdExhausted) => {
                return Err(Errno::EFAULT.into());
            }
        };
        let top = token.top();
        Ok(GuestStack {
            top,
            sp: top,
            capacity: token.capacity(),
            buf: Vec::new(),
            task: ToolMemory::new(task),
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

// A committed frame cannot grow. Its token reserves its interval until Drop,
// so a nested Tool can allocate below it without overwriting live bytes.
#[derive(Debug)]
// TODO: Ideally we would have some way to connect the actual `Addr` references into the
// guest heap to the lifetime of the StackGuard (like the ST monad in Haskell).
pub struct StackGuard {
    // This token owns only this frame, including when guards drop out of order.
    _token: StackToken,
}

// `reverie::Stack::StackGuard` requires Drop. The token releases its own
// reservation after this empty implementation.
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
        // A failed write drops only this uncommitted reservation. Existing
        // frames remain reserved, and the next checkout can retry this space.
        self.task.write_exact(remote_sp, from)?;
        Ok(StackGuard {
            _token: self.token.commit(self.sp),
        })
    }
}

impl MemoryAccess for GuestStack {
    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        self.task.write_with_user_access(addr, buf)
    }

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

    include!("stack_owner_tests.rs");

    #[test]
    fn user_copy_stack_forwarder_enforces_permissions_and_exact_prefix() {
        struct Child(libc::pid_t);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0 != 0 {
                    unsafe {
                        libc::kill(self.0, libc::SIGKILL);
                        libc::waitpid(self.0, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page.is_power_of_two());
        for protection in [libc::PROT_READ, libc::PROT_NONE] {
            for (offset, count) in [(page, 0), (page - 3, 3), (0, 8)] {
                let mapping = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        3 * page,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_ne!(mapping, libc::MAP_FAILED);
                unsafe {
                    std::ptr::write_bytes(mapping.cast::<u8>(), 0xa5, 3 * page);
                }
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    // Only async-signal-safe libc calls after the test fork.
                    unsafe {
                        if libc::mprotect(mapping.cast::<u8>().add(page).cast(), page, protection)
                            != 0
                            || libc::ptrace(
                                libc::PTRACE_TRACEME,
                                0,
                                std::ptr::null_mut::<libc::c_void>(),
                                std::ptr::null_mut::<libc::c_void>(),
                            ) != 0
                            || libc::raise(libc::SIGSTOP) != 0
                        {
                            libc::_exit(2);
                        }
                        libc::_exit(0);
                    }
                }
                let mut child = Child(pid);
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                assert!(libc::WIFSTOPPED(status));
                assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
                let arena = Arc::new(StackArena::default());
                let mut stack = GuestStack::new(Pid::from_raw(pid), arena.clone()).unwrap();
                let address = AddrMut::from_raw(mapping as usize + offset).unwrap();
                assert_eq!(
                    stack.write_with_user_access(address, b"12345678"),
                    if count == 0 {
                        Err(Errno::EFAULT)
                    } else {
                        Ok(count)
                    }
                );
                assert_eq!(
                    stack.write_with_user_access(AddrMut::from_raw(usize::MAX).unwrap(), &[]),
                    Ok(0)
                );
                let memory = Stopped::new_unchecked(Pid::from_raw(pid));
                let mut actual = vec![0; 3 * page];
                for (index, bytes) in actual.chunks_mut(8).enumerate() {
                    assert_eq!(
                        memory.read(Addr::from_raw(mapping as usize + index * 8).unwrap(), bytes),
                        Ok(bytes.len())
                    );
                }
                let mut expected = vec![0xa5; 3 * page];
                expected[offset..offset + count].copy_from_slice(&b"12345678"[..count]);
                assert_eq!(actual, expected);
                drop(stack);
                assert_eq!(arena.live(), 0);

                // Use a controlled stack window: its lower page is protected,
                // while the outer frame and a small inner frame are writable.
                // A failed inner commit must not poison the arena or outer bytes.
                let saved_regs = memory.getregs().unwrap();
                let generation = memory.generation();
                let mut regs = saved_regs;
                *regs.stack_ptr_mut() = (mapping as usize + 2 * page + 256) as _;
                memory.setregs(&regs).unwrap();
                let mut outer =
                    GuestStack::new_on_ptracer_thread(generation.assume_stopped(), arena.clone())
                        .unwrap();
                let outer_address = outer.push([0x3cu8; 16]);
                let outer_guard = outer.commit().unwrap();
                let mut bad =
                    GuestStack::new_on_ptracer_thread(generation.assume_stopped(), arena.clone())
                        .unwrap();
                bad.reserve::<[u8; 256]>();
                assert!(matches!(bad.commit(), Err(Errno::EFAULT)));
                assert_eq!(arena.live(), 1);
                let mut outer_bytes = [0u8; 16];
                memory
                    .read_exact(outer_address.cast(), &mut outer_bytes)
                    .unwrap();
                assert_eq!(outer_bytes, [0x3cu8; 16]);
                let mut retry =
                    GuestStack::new_on_ptracer_thread(generation.assume_stopped(), arena.clone())
                        .unwrap();
                let retry_address = retry.push([0x7du8; 8]);
                let retry_guard = retry.commit().unwrap();
                assert!(retry_address.as_raw() + 8 <= outer_address.as_raw());
                memory
                    .read_exact(outer_address.cast(), &mut outer_bytes)
                    .unwrap();
                assert_eq!(outer_bytes, [0x3cu8; 16]);
                drop(retry_guard);
                drop(outer_guard);
                assert_eq!(arena.live(), 0);

                // Now place the entire unchanged 896-byte arena in the final
                // writable page. Filling it exactly succeeds; one more word
                // fails while the outer payload remains byte-identical.
                *regs.stack_ptr_mut() = (mapping as usize + 3 * page) as _;
                memory.setregs(&regs).unwrap();
                let mut full =
                    GuestStack::new_on_ptracer_thread(generation.assume_stopped(), arena.clone())
                        .unwrap();
                assert_eq!(full.capacity(), STACK_CAPACITY);
                let full_address = full.push([0x69u8; STACK_CAPACITY]);
                let full_guard = full.commit().unwrap();
                let overflow = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut extra = GuestStack::new_on_ptracer_thread(
                        generation.assume_stopped(),
                        arena.clone(),
                    )
                    .unwrap();
                    assert_eq!(extra.capacity(), 0);
                    extra.reserve::<u64>();
                }));
                assert!(
                    overflow.is_err(),
                    "aggregate capacity must not grow with nesting"
                );
                assert_eq!(arena.live(), 1);
                let mut full_bytes = [0u8; STACK_CAPACITY];
                memory
                    .read_exact(full_address.cast(), &mut full_bytes)
                    .unwrap();
                assert_eq!(full_bytes, [0x69u8; STACK_CAPACITY]);
                drop(full_guard);
                assert_eq!(arena.live(), 0);
                memory.setregs(&saved_regs).unwrap();
                assert_eq!(
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            pid,
                            std::ptr::null_mut::<libc::c_void>(),
                            std::ptr::null_mut::<libc::c_void>(),
                        )
                    },
                    0
                );
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                child.0 = 0;
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                assert_eq!(unsafe { libc::munmap(mapping, 3 * page) }, 0);
            }
        }
    }

    fn test_token(arena: Arc<StackArena>) -> StackToken {
        let generation =
            Stopped::new_unchecked(Pid::from_raw(std::process::id() as i32)).generation();
        StackToken::acquire(arena, generation, 0x10000).unwrap()
    }

    #[test]
    fn stack_token_releases_on_drop_without_commit() {
        let arena = Arc::new(StackArena::default());
        let token = test_token(arena.clone());
        assert_eq!(arena.live(), 1);
        drop(token);
        assert_eq!(arena.live(), 0);
        let retry = test_token(arena.clone());
        assert_eq!(retry.capacity(), STACK_CAPACITY);
        drop(retry);
        assert_eq!(arena.live(), 0);
    }

    #[test]
    fn stack_token_detects_simultaneous_checkout() {
        let arena = Arc::new(StackArena::default());
        let generation =
            Stopped::new_unchecked(Pid::from_raw(std::process::id() as i32)).generation();
        let first = StackToken::acquire(arena.clone(), generation.clone(), 0x10000).unwrap();
        assert_eq!(
            StackToken::acquire(arena.clone(), generation, 0x10000).unwrap_err(),
            CheckoutError::Uncommitted,
            "a builder can still grow, so another checkout must be refused"
        );
        assert_eq!(arena.live(), 1);
        drop(first);
        assert_eq!(arena.live(), 0);
    }

    #[test]
    fn stack_guard_holds_then_releases_flag() {
        let arena = Arc::new(StackArena::default());
        let token = test_token(arena.clone());
        let top = token.top();
        let guard = StackGuard {
            _token: token.commit(top - 16),
        };
        assert_eq!(arena.live(), 1);
        drop(guard);
        assert_eq!(arena.live(), 0);
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
