/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::io;

use super::Addr;
use super::AddrMut;
use super::Errno;
use super::MemoryAccess;

/// A local address space.
///
/// Copies use the kernel's self `process_vm_readv`/`process_vm_writev` paths,
/// so inaccessible addresses produce faults or partial transfers instead of
/// being dereferenced by Rust. These are ordinary inspection operations: the
/// remote side respects VMA permissions, but does not enforce the guest's PKRU.
/// Tool buffers and syscall metadata must be accessible to the calling thread.
/// Unlike ptrace's small PEEK/POKE operations, these copies cannot force access
/// to PROT_NONE pages or read-only text.
/// Scalar methods return `EFAULT` when no byte can be copied; vectored methods
/// represent that fault as `Ok(0)`, matching safeptrace. Other errors and partial
/// byte counts are preserved in both interfaces.
#[derive(Default, Debug)]
pub struct LocalMemory {}

impl LocalMemory {
    /// Creates a new representation of memory in the current address space.
    /// A copy can be partial and does not provide a snapshot of concurrent
    /// writes or changes to the address space.
    ///
    /// # Example
    /// ```
    /// # use reverie_memory::LocalMemory;
    /// let memory = LocalMemory::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
}

#[repr(C)]
struct Iovec {
    base: *mut core::ffi::c_void,
    len: usize,
}

fn copy(
    syscall: syscalls::Sysno,
    local: *const Iovec,
    local_count: usize,
    remote: *const Iovec,
    remote_count: usize,
) -> Result<usize, Errno> {
    // The kernel validates iovec counts, lengths and address ranges, and
    // returns the actual transferred prefix. In particular, do not preflight
    // later remote addresses or retry a short copy: either would change its
    // side effects. No guest pointee becomes a Rust reference here.
    unsafe {
        syscalls::syscall6(
            syscall,
            std::process::id() as usize,
            local as usize,
            local_count,
            remote as usize,
            remote_count,
            0,
        )
    }
}

fn vectored_result(result: Result<usize, Errno>) -> Result<usize, Errno> {
    // Match safeptrace's vectored convention, while scalar methods retain
    // their raw EFAULT result. Exact operations still reject a short copy.
    match result {
        Err(Errno::EFAULT) => Ok(0),
        result => result,
    }
}

impl MemoryAccess for LocalMemory {
    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        // The scalar method already uses one checked numeric-iovec kernel copy,
        // with raw errno and VMA permissions (including at exactly eight bytes).
        match self.write(addr, buf)? {
            0 if !buf.is_empty() => Err(Errno::EFAULT),
            copied => Ok(copied),
        }
    }

    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        // IoSlice and IoSliceMut are ABI-compatible with iovec on Unix.
        // Pass only their descriptor arrays; never dereference remote slices.
        vectored_result(copy(
            syscalls::Sysno::process_vm_readv,
            write_to.as_ptr().cast(),
            write_to.len(),
            read_from.as_ptr().cast(),
            read_from.len(),
        ))
    }

    fn write_vectored(
        &mut self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        vectored_result(copy(
            syscalls::Sysno::process_vm_writev,
            read_from.as_ptr().cast(),
            read_from.len(),
            write_to.as_ptr().cast(),
            write_to.len(),
        ))
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        let addr = addr.into();
        if buf.is_empty() {
            return Ok(0);
        }
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;

        let remote = Iovec {
            base: addr.as_raw() as *mut core::ffi::c_void,
            len: buf.len(),
        };
        let local = Iovec {
            base: buf.as_mut_ptr().cast(),
            len: buf.len(),
        };
        copy(syscalls::Sysno::process_vm_readv, &local, 1, &remote, 1)
    }

    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        if buf.is_empty() {
            return Ok(0);
        }
        addr.as_raw().checked_add(buf.len()).ok_or(Errno::EFAULT)?;
        let remote = Iovec {
            base: addr.as_raw() as *mut core::ffi::c_void,
            len: buf.len(),
        };
        let local = Iovec {
            base: buf.as_ptr() as *mut core::ffi::c_void,
            len: buf.len(),
        };
        copy(syscalls::Sysno::process_vm_writev, &local, 1, &remote, 1)
    }
}

#[cfg(test)]
#[path = "local/tests.rs"]
mod transfer_tests;

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
    fn invalid_read_returns_efault() {
        let m = LocalMemory::new();
        let addr = Addr::from_raw(1).expect("non-null invalid test address");
        let mut buf = [0u8; 8];
        assert_eq!(m.read(addr, &mut buf), Err(Errno::EFAULT));
    }

    #[test]
    fn read_exact_with_user_access_rejects_prot_none() {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page_size > 0);
        let page_size = page_size as usize;
        let mapping = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        assert_eq!(
            unsafe { libc::mprotect(mapping, page_size, libc::PROT_NONE) },
            0
        );

        let m = LocalMemory::new();
        let addr = Addr::from_raw(mapping as usize).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            m.read_exact_with_user_access(addr, &mut buf),
            Err(Errno::EFAULT)
        );

        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
    }

    #[test]
    fn read_exact_with_user_access_rejects_address_overflow() {
        let m = LocalMemory::new();
        let addr = Addr::from_raw(usize::MAX - 3).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            m.read_exact_with_user_access(addr, &mut buf),
            Err(Errno::EFAULT)
        );
    }

    #[test]
    fn read_cstring() {
        use std::ffi::CStr;

        let m = LocalMemory::new();
        let x = "hello world\0";
        let addr = Addr::from_ptr(x.as_ptr()).unwrap();
        assert_eq!(m.read_cstring(addr).unwrap().as_c_str(), unsafe {
            CStr::from_ptr(x.as_ptr() as *const _)
        });
    }
}
