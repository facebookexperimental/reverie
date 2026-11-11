/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Questions this provider asks the host kernel about a mapping of a file
//! the guest made, by making the same mapping of the same open file
//! description in this process and reading the block the kernel prints for
//! it in this process's own `smaps` (`show_smap` in `fs/proc/task_mmu.c`).
//!
//! The host kernel is the kernel the guest is told it runs (`uname(2)` gives
//! the host's release), and a probe hands it the same `struct file` and the
//! same `mmap(2)` arguments, so it runs the same code on the same inputs:
//! `do_mmap`, then the file's own mmap hook. That holds where the file's
//! filesystem does not show which hook runs, as overlayfs does not
//! (`ovl_mmap` runs the hook of the real file of one of its layers through
//! `backing_file_mmap`, `fs/backing-file.c`), and where a value depends on
//! state no other fact gives, as `THPeligible` does on tmpfs on the mount's
//! `huge=` option and the file's size (`shmem_allowable_huge_orders`).
//!
//! A probe maps at the lowest address it may (`vm.mmap_min_addr`, rounded up
//! to a page), or at the lowest such address with a given offset within a
//! PMD-sized block, with `MAP_FIXED_NOREPLACE`, so that its block is the
//! first `smaps` prints, and only that block need be read, however many
//! mappings this process has. One lock serializes the probes, which share
//! those addresses. A probe that cannot map there, finds another block
//! first, or reads a field it cannot parse answers `None`, never a guess. It
//! touches no page, so it reads nothing from the file. The mapping is made
//! and removed by the system calls themselves, not libc's `mmap` and
//! `munmap`, for the reason [`super::vm_flags`]' guard probe gives.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;

use reverie::VM_HUGEPAGE;
use reverie::VM_NOHUGEPAGE;

/// The page size.
const PAGE: u64 = 4096;

/// The size of a PMD-mapped transparent huge page on x86-64
/// (`HPAGE_PMD_SIZE`), the largest block whose eligibility `THPeligible`
/// reports.
pub(crate) const PMD_SIZE: u64 = 2 << 20;

/// Where a probe's mapping goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Placement {
    /// At the lowest address a mapping may have.
    Lowest,
    /// At the lowest address a mapping may have whose offset within a
    /// [`PMD_SIZE`] block is this one.
    Residue(u64),
    /// At this address.
    Exact(u64),
}

/// The fields a probe read from the block the kernel printed for its
/// mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProbedBlock {
    /// `VmFlags`, as the bits of `reverie::MappingFact::vm_flags`, or `None`
    /// where a name is not one of [`super::vm_flags::VM_FLAG_NAMES`].
    pub(crate) vm_flags: Option<u64>,
    /// `THPeligible`, or `None` where the line is missing or reads as
    /// neither 0 nor 1.
    pub(crate) thp_eligible: Option<bool>,
}

/// The block the host kernel prints for a mapping of `file` made now:
/// `length` bytes from the page-aligned file offset `offset`, with
/// protection `prot` (`PROT_*` bits), shared or private, placed by
/// `placement`. `None` where the mapping cannot be made there, the first
/// block of `smaps` is not its, or the block has no `VmFlags` line.
pub(crate) fn probe(
    file: &std::fs::File,
    prot: u8,
    shared: bool,
    offset: u64,
    length: u64,
    placement: Placement,
) -> Option<ProbedBlock> {
    static PROBES: Mutex<()> = Mutex::new(());
    let _probing = PROBES.lock().unwrap_or_else(PoisonError::into_inner);
    let lowest = lowest_address()?;
    let address = match placement {
        Placement::Lowest => lowest,
        Placement::Residue(residue) => {
            lowest + (residue % PMD_SIZE + PMD_SIZE - lowest % PMD_SIZE) % PMD_SIZE
        }
        Placement::Exact(address) => (address >= lowest).then_some(address)?,
    };
    let aligned = |value: u64| value.is_multiple_of(PAGE);
    if length == 0 || !aligned(length) || !aligned(offset) || !aligned(address) {
        return None;
    }
    let end = address.checked_add(length)?;
    let kind = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    // SAFETY: MAP_FIXED_NOREPLACE never replaces a mapping; the result is
    // checked, and a mapping made anywhere else is removed at once.
    let mapped = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            address as *mut libc::c_void,
            length as usize,
            libc::c_int::from(prot),
            kind | libc::MAP_FIXED_NOREPLACE,
            file.as_raw_fd(),
            offset,
        )
    };
    if mapped == -1 {
        return None;
    }
    let mapping = Unmap {
        address: mapped as u64,
        length,
    };
    if mapping.address != address {
        // A kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint.
        return None;
    }
    // One read gives whole blocks, from the first, as many as fit.
    let mut text = vec![0; 16 * 1024];
    let read = std::fs::File::open("/proc/self/smaps")
        .ok()?
        .read(&mut text)
        .ok()?;
    drop(mapping);
    first_block(&text[..read], address, end)
}

/// The `THPeligible` the host kernel prints now for a mapping of `file` from
/// the page-aligned file offset `offset` with protection `prot`, shared or
/// private, that spans `start` to `end` and that no advice reached (no
/// `VM_HUGEPAGE` and no `VM_NOHUGEPAGE`): the probe's mapping has the same
/// length and the same offset within a PMD-sized block as the guest's, which
/// are all `thp_vma_allowable_orders` reads of a mapping's place (its order
/// filter, `thp_vma_suitable_order`, include/linux/huge_mm.h), and it is
/// placed at `start` itself where the mapping ends below such a block, where
/// that filter's unsigned arithmetic wraps and reads the address. `None`
/// where this process's own address space disabled transparent huge pages
/// (`PR_SET_THP_DISABLE`), whose answer would be its, or the probe fails.
pub(crate) fn thp_eligible(
    file: &std::fs::File,
    prot: u8,
    shared: bool,
    offset: u64,
    start: u64,
    end: u64,
) -> Option<bool> {
    // SAFETY: PR_GET_THP_DISABLE takes no pointers.
    if unsafe { libc::prctl(libc::PR_GET_THP_DISABLE, 0, 0, 0, 0) } != 0 {
        return None;
    }
    let placement = if end < PMD_SIZE {
        Placement::Exact(start)
    } else {
        Placement::Residue(start % PMD_SIZE)
    };
    let block = probe(
        file,
        prot,
        shared,
        offset,
        end.checked_sub(start)?,
        placement,
    )?;
    if block.vm_flags? & (VM_HUGEPAGE | VM_NOHUGEPAGE) != 0 {
        return None;
    }
    block.thp_eligible
}

/// `vm.mmap_min_addr` rounded up to a page, and at least one page: the
/// lowest address a mapping of this process may have, read once per process.
fn lowest_address() -> Option<u64> {
    static LOWEST: OnceLock<Option<u64>> = OnceLock::new();
    *LOWEST.get_or_init(|| {
        let minimum: u64 = std::fs::read_to_string("/proc/sys/vm/mmap_min_addr")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        minimum.max(1).checked_next_multiple_of(PAGE)
    })
}

/// Removes a probe's mapping when dropped.
struct Unmap {
    address: u64,
    length: u64,
}

impl Drop for Unmap {
    fn drop(&mut self) {
        // SAFETY: the mapping is the probe's own.
        unsafe { libc::syscall(libc::SYS_munmap, self.address, self.length) };
    }
}

/// The fields of the first block of the `smaps` text `text`, if its header
/// is the range `start` to `end`. A header begins with the range's first
/// address in lowercase hexadecimal, and every field with a capitalized
/// label, so the first line that begins with a hexadecimal digit ends the
/// block. The block's last field is `VmFlags`; a block without one was cut
/// short, and is not read.
fn first_block(text: &[u8], start: u64, end: u64) -> Option<ProbedBlock> {
    let mut lines = text.split(|byte| *byte == b'\n');
    if !lines
        .next()?
        .starts_with(format!("{start:08x}-{end:08x} ").as_bytes())
    {
        return None;
    }
    let mut thp_eligible = None;
    for line in lines {
        if line
            .first()
            .is_some_and(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return None;
        }
        if let Some(value) = line.strip_prefix(b"THPeligible:") {
            thp_eligible = match value.trim_ascii() {
                b"0" => Some(false),
                b"1" => Some(true),
                _ => None,
            };
        } else if let Some(names) = line.strip_prefix(b"VmFlags:") {
            return Some(ProbedBlock {
                vm_flags: super::vm_flags::parse_vm_flags(names),
                thp_eligible,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block's fields are read up to its `VmFlags`, and only the first
    /// block, if its header is the probe's range.
    #[test]
    fn the_first_block_is_read_when_it_is_the_probes() {
        let text = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                     Size:                  4 kB\n\
                     THPeligible:           0\n\
                     VmFlags: rd mr mw me \n\
                     55550000-55551000 r--p 00000000 00:23 13   /bin/y\n\
                     THPeligible:           1\n\
                     VmFlags: rd mr mw me ac \n";
        assert_eq!(
            first_block(text, 0x10000, 0x11000),
            Some(ProbedBlock {
                vm_flags: Some(
                    reverie::VM_READ
                        | reverie::VM_MAYREAD
                        | reverie::VM_MAYWRITE
                        | reverie::VM_MAYEXEC
                ),
                thp_eligible: Some(false),
            })
        );
        // Another range first, or a block cut short before its VmFlags.
        assert_eq!(first_block(text, 0x10000, 0x12000), None);
        assert_eq!(first_block(&text[..90], 0x10000, 0x11000), None);
        let cut = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                    Size:                  4 kB\n\
                    55550000-55551000 r--p 00000000 00:23 13   /bin/y\n\
                    VmFlags: rd mr mw me \n";
        assert_eq!(first_block(cut, 0x10000, 0x11000), None);
        // A name this provider does not know gives no flags.
        let unknown = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                        VmFlags: rd mr mw me sd \n";
        assert_eq!(
            first_block(unknown, 0x10000, 0x11000),
            Some(ProbedBlock {
                vm_flags: None,
                thp_eligible: None,
            })
        );
    }

    /// A probe of a file on this host (a memfd) reads its own block: one
    /// page at the lowest address, then a longer mapping at an offset within
    /// a PMD block, each with the protection and sharing it was made with.
    #[test]
    fn a_probe_reads_its_own_block() {
        let file = {
            // SAFETY: a new memfd this test owns.
            let fd = unsafe { libc::memfd_create(c"host-probe".as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0);
            // SAFETY: memfd_create returned a new descriptor.
            unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) }
        };
        file.set_len(4 * PMD_SIZE).unwrap();
        let block = probe(
            &file,
            libc::PROT_READ as u8,
            false,
            0,
            PAGE,
            Placement::Lowest,
        )
        .unwrap();
        assert_eq!(
            block.vm_flags,
            Some(
                reverie::VM_READ | reverie::VM_MAYREAD | reverie::VM_MAYWRITE | reverie::VM_MAYEXEC
            )
        );
        // No order a file may have (8 KiB and up) fits one page.
        assert_ne!(block.thp_eligible, Some(true));
        let shared = probe(
            &file,
            (libc::PROT_READ | libc::PROT_WRITE) as u8,
            true,
            PMD_SIZE,
            PMD_SIZE,
            Placement::Residue(0x1000),
        )
        .unwrap();
        assert_eq!(
            shared.vm_flags,
            Some(
                reverie::VM_READ
                    | reverie::VM_WRITE
                    | reverie::VM_SHARED
                    | reverie::VM_MAYREAD
                    | reverie::VM_MAYWRITE
                    | reverie::VM_MAYEXEC
                    | reverie::VM_MAYSHARE
            )
        );
        // Nothing is left mapped: the same probe maps there again.
        assert!(
            probe(
                &file,
                libc::PROT_READ as u8,
                false,
                0,
                PAGE,
                Placement::Lowest
            )
            .is_some()
        );
        // An address below the lowest a mapping may have is refused.
        assert_eq!(
            probe(
                &file,
                libc::PROT_READ as u8,
                false,
                0,
                PAGE,
                Placement::Exact(0)
            ),
            None
        );
    }
}
