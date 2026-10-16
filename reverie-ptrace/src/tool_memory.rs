/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The guest memory a Tool writes through.
//!
//! [`Stopped`]'s generic `write` sends an eight-byte buffer through
//! `PTRACE_POKEDATA`, which ignores page protection. That is the debugger
//! contract the GDB server and Reverie's own setup rely on. A Tool, though,
//! writes the results of the syscalls it emulates into guest-chosen output
//! pointers, and Linux fails such a write with `EFAULT` when the page is not
//! writable. So every Tool write goes through the permission-respecting path
//! instead, at every size. A Tool write that overlaps Reverie's private page
//! is refused before any access: that page is read-and-execute, so a native
//! write there fails too, and a forced one could replace the `ud2` that
//! guards the untraced stub (https://github.com/rrnewton/reverie/issues/1064).

use std::io;

use reverie::Errno;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::RemoteIoVec;
use safeptrace::Stopped;

use crate::cp;

/// A stopped task's memory as a Tool sees it. Reads are [`Stopped`]'s; every
/// write respects the target's page permissions and never touches Reverie's
/// private page.
pub struct ToolMemory(Stopped);

impl ToolMemory {
    pub(crate) fn new(stopped: Stopped) -> Self {
        Self(stopped)
    }
}

/// Whether `[address, address + length)` overlaps Reverie's private page.
/// An empty range overlaps nothing; a range that wraps the address space is
/// treated as overlapping, so it is refused rather than reaching the kernel.
fn overlaps_private_page(address: usize, length: usize) -> bool {
    if length == 0 {
        return false;
    }
    let Some(end) = address.checked_add(length) else {
        return true;
    };
    let page_start = cp::PRIVATE_PAGE_OFFSET;
    let page_end = cp::PRIVATE_PAGE_OFFSET + cp::PRIVATE_PAGE_SIZE;
    address < page_end && page_start < end
}

fn refuse_private_page_write(address: usize, length: usize) -> Result<(), Errno> {
    if overlaps_private_page(address, length) {
        tracing::warn!(
            address,
            length,
            "refusing a Tool write into Reverie's private page"
        );
        return Err(Errno::EFAULT);
    }
    Ok(())
}

impl MemoryAccess for ToolMemory {
    fn read_vectored(
        &self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        self.0.read_vectored(read_from, write_to)
    }

    fn write_vectored(
        &mut self,
        read_from: &[io::IoSlice],
        write_to: &mut [io::IoSliceMut],
    ) -> Result<usize, Errno> {
        for remote in write_to.iter() {
            refuse_private_page_write(remote.as_ptr() as usize, remote.len())?;
        }
        // process_vm_writev: permission-respecting.
        self.0.write_vectored(read_from, write_to)
    }

    fn write_native_user_vectored(
        &mut self,
        expected_tid: i32,
        local: &[io::IoSlice],
        remote: &[RemoteIoVec],
    ) -> Result<usize, Errno> {
        for span in remote {
            refuse_private_page_write(span.address(), span.length())?;
        }
        self.0
            .write_native_user_vectored(expected_tid, local, remote)
    }

    fn read<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<usize, Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        self.0.read(addr, buf)
    }

    fn read_exact_with_user_access<'a, A>(&self, addr: A, buf: &mut [u8]) -> Result<(), Errno>
    where
        A: Into<Addr<'a, u8>>,
    {
        self.0.read_exact_with_user_access(addr, buf)
    }

    /// Every size goes through the permission-respecting copy, never the
    /// eight-byte `PTRACE_POKEDATA` path of [`Stopped`]'s debugger `write`.
    fn write(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        refuse_private_page_write(addr.as_raw(), buf.len())?;
        self.0.write_with_user_access(addr, buf)
    }

    fn write_with_user_access(&mut self, addr: AddrMut<u8>, buf: &[u8]) -> Result<usize, Errno> {
        refuse_private_page_write(addr.as_raw(), buf.len())?;
        self.0.write_with_user_access(addr, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_page_overlap_is_exact() {
        let start = cp::PRIVATE_PAGE_OFFSET;
        let end = start + cp::PRIVATE_PAGE_SIZE;
        assert!(!overlaps_private_page(start - 8, 8));
        assert!(overlaps_private_page(start - 8, 9));
        assert!(overlaps_private_page(start + 2, 8));
        assert!(overlaps_private_page(end - 1, 1));
        assert!(!overlaps_private_page(end, 8));
        assert!(!overlaps_private_page(start, 0));
        assert!(overlaps_private_page(usize::MAX - 3, 8));
    }
}
