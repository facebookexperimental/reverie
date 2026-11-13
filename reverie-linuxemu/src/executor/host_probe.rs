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
//! A probe maps where the kernel chooses: it reserves an inaccessible region
//! at an address the kernel picks, gives a window of it back, and maps the
//! file there with `MAP_FIXED_NOREPLACE`, at a given offset within a
//! PMD-sized block where the question needs one. So it needs no particular
//! address of this process to be free (a non-PIE executable at the linker's
//! default base, 0x200000, holds the lowest such blocks). Its mapping
//! neighbours only its reservation, so it merges with nothing, and its block
//! is found in this process's `smaps`, which prints blocks in address order,
//! by its range. A probe removes only what it holds: a window it gave back
//! and could not map may hold another thread's mapping by then ([`Held`]).
//! A mapping that ends below a PMD-sized block is probed at the guest's own
//! address instead ([`thp_eligible`]). One lock serializes the probes. A
//! probe that cannot map, finds no block for its range, or reads a field it
//! cannot parse answers `None`, never a guess. It touches no page, so it
//! reads nothing from the file. The mappings are made and removed by the
//! system calls themselves, not libc's `mmap` and `munmap`, for the reason
//! [`super::vm_flags`]' guard probe gives.

use std::io::BufRead;
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
    /// Where the kernel chooses.
    Anywhere,
    /// Where the kernel chooses, at an address whose offset within a
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
/// `placement`. `None` where the mapping cannot be made there, `smaps` has
/// no block for its range, or the block has no `VmFlags` line.
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
    let aligned = |value: u64| value.is_multiple_of(PAGE);
    if length == 0 || !aligned(length) || !aligned(offset) {
        return None;
    }
    let kind = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let held = match placement {
        Placement::Exact(address) => {
            if address < lowest_address()? || !aligned(address) {
                return None;
            }
            // MAP_FIXED_NOREPLACE never replaces a mapping.
            let mapped = map_file(
                file,
                address,
                length,
                prot,
                kind | libc::MAP_FIXED_NOREPLACE,
                offset,
            )?;
            let held = Held::mapping(mapped, length);
            if mapped != address {
                // A kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint.
                return None;
            }
            held
        }
        Placement::Anywhere => map_in_reservation(file, prot, kind, offset, length, None)?,
        Placement::Residue(residue) => {
            if !aligned(residue) {
                return None;
            }
            map_in_reservation(file, prot, kind, offset, length, Some(residue))?
        }
    };
    if !held.window_held {
        // The file could not be mapped at the window.
        return None;
    }
    let smaps = std::fs::File::open("/proc/self/smaps").ok()?;
    let block = probed_block(std::io::BufReader::new(smaps), held.window, held.window_end);
    drop(held);
    block
}

/// Maps `length` bytes of `file` from the page-aligned file offset `offset`
/// at `address` with protection `prot` and `flags`, and answers the address
/// the kernel returned.
fn map_file(
    file: &std::fs::File,
    address: u64,
    length: u64,
    prot: u8,
    flags: libc::c_int,
    offset: u64,
) -> Option<u64> {
    // SAFETY: the caller passes MAP_FIXED_NOREPLACE, which never replaces a
    // mapping; the result is checked.
    let mapped = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            address as *mut libc::c_void,
            length as usize,
            libc::c_int::from(prot),
            flags,
            file.as_raw_fd(),
            offset,
        )
    };
    (mapped != -1).then_some(mapped as u64)
}

/// Maps `length` bytes of `file` from the page-aligned file offset `offset`
/// with protection `prot` and the sharing `kind`, in an inaccessible
/// reservation of the probe's own at an address the kernel chooses: at its
/// second page, or at the first address in it whose offset within a
/// PMD-sized block is `residue`, a multiple of the page size. Answers what
/// the probe holds then, which holds the window only where the file was
/// mapped there, or `None` where it holds nothing.
fn map_in_reservation(
    file: &std::fs::File,
    prot: u8,
    kind: libc::c_int,
    offset: u64,
    length: u64,
    residue: Option<u64>,
) -> Option<Held> {
    // Room for the mapping at any offset within a PMD-sized block, with a
    // page of the reservation before it and after it.
    let size = length.checked_add(PMD_SIZE + PAGE)?;
    // SAFETY: a new anonymous mapping at an address the kernel chooses.
    let start = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            std::ptr::null_mut::<libc::c_void>(),
            size as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if start == -1 {
        return None;
    }
    let start = start as u64;
    let first = start + PAGE;
    let window = match residue {
        Some(residue) => first + (residue % PMD_SIZE + PMD_SIZE - first % PMD_SIZE) % PMD_SIZE,
        None => first,
    };
    let mut held = Held {
        start,
        end: start + size,
        window,
        window_end: window + length,
        window_held: true,
    };
    // The window is given back, then mapped with MAP_FIXED_NOREPLACE, which
    // removes nothing. MAP_FIXED over the reservation would remove the window
    // first, and a failure after that leaves it unmapped
    // (`vms_abort_munmap_vmas`, mm/vma.c), for another thread's mapping to
    // take before the probe removes what it holds.
    // SAFETY: the window is this probe's.
    if !unsafe { unmap(window, length) } {
        return None;
    }
    held.window_held = false;
    if let Some(mapped) = map_file(
        file,
        window,
        length,
        prot,
        kind | libc::MAP_FIXED_NOREPLACE,
        offset,
    ) {
        if mapped == window {
            held.window_held = true;
        } else {
            // A kernel before 4.17 takes MAP_FIXED_NOREPLACE as a hint.
            // SAFETY: the mapping is this probe's.
            unsafe { unmap(mapped, length) };
        }
    }
    Some(held)
}

/// Removes the pages from `address` for `length` bytes, and answers whether
/// the kernel did.
///
/// # Safety
///
/// The pages are the caller's: nothing else uses them.
unsafe fn unmap(address: u64, length: u64) -> bool {
    // SAFETY: the caller's contract.
    unsafe { libc::syscall(libc::SYS_munmap, address, length) == 0 }
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

/// The address space a probe holds, removed when dropped: a range of its own
/// (its reservation, or for [`Placement::Exact`] its mapping alone), less the
/// window in it that the probe gave back to the kernel to map the file
/// there, until the probe holds a mapping of its own there. A window the
/// probe gave back and could not map may hold another thread's mapping by
/// then, which a probe never removes.
struct Held {
    start: u64,
    end: u64,
    window: u64,
    window_end: u64,
    /// Whether the window is the probe's: before the probe gives it back,
    /// and once the file is mapped there.
    window_held: bool,
}

impl Held {
    /// A probe's mapping of `length` bytes at `address`, and nothing else.
    fn mapping(address: u64, length: u64) -> Self {
        Self {
            start: address,
            end: address + length,
            window: address,
            window_end: address + length,
            window_held: true,
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if self.window_held {
            // SAFETY: the whole range is the probe's.
            unsafe { unmap(self.start, self.end - self.start) };
        } else {
            // SAFETY: the pages before the window and after it are the
            // probe's, and the window is not.
            unsafe {
                unmap(self.start, self.window - self.start);
                unmap(self.window_end, self.end - self.window_end);
            }
        }
    }
}

/// The fields of the block of the `smaps` text `smaps` whose header is the
/// range `start` to `end`, read only as far as that block's `VmFlags`. A
/// header begins with its range's first address in lowercase hexadecimal,
/// and every field with a capitalized label, so a line that begins with a
/// hexadecimal digit begins the next block. Blocks come in address order, so
/// a header above `start` before the probe's own means it has none. The
/// block's last field is `VmFlags`; a block without one was cut short, and
/// is not read.
fn probed_block(smaps: impl BufRead, start: u64, end: u64) -> Option<ProbedBlock> {
    let header = format!("{start:08x}-{end:08x} ");
    let mut inside = false;
    let mut thp_eligible = None;
    for line in smaps.split(b'\n') {
        let line = line.ok()?;
        if line
            .first()
            .is_some_and(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            if inside {
                return None;
            }
            if line.starts_with(header.as_bytes()) {
                inside = true;
                continue;
            }
            let first = line.split(|byte| *byte == b'-').next()?;
            if u64::from_str_radix(std::str::from_utf8(first).ok()?, 16).ok()? > start {
                return None;
            }
            continue;
        }
        if !inside {
            continue;
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
    use super::super::host_probe_tests::in_namespace;
    use super::*;

    /// A block's fields are read up to its `VmFlags`, from the block whose
    /// header is the probe's range, wherever it is among the others.
    #[test]
    fn the_probes_block_is_read_by_its_range() {
        let text: &[u8] = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                     Size:                  4 kB\n\
                     THPeligible:           0\n\
                     VmFlags: rd mr mw me \n\
                     55550000-55551000 r--p 00000000 00:23 13   /bin/y\n\
                     THPeligible:           1\n\
                     VmFlags: rd mr mw me \n";
        let flags = Some(
            reverie::VM_READ | reverie::VM_MAYREAD | reverie::VM_MAYWRITE | reverie::VM_MAYEXEC,
        );
        assert_eq!(
            probed_block(text, 0x5555_0000, 0x5555_1000),
            Some(ProbedBlock {
                vm_flags: flags,
                thp_eligible: Some(true),
            })
        );
        assert_eq!(
            probed_block(text, 0x10000, 0x11000),
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
        // No block with the range (a later header comes first, or the text
        // ends), or a block cut short before its VmFlags.
        assert_eq!(probed_block(text, 0x10000, 0x12000), None);
        assert_eq!(probed_block(text, 0x20000, 0x21000), None);
        assert_eq!(probed_block(text, 0x6000_0000, 0x6000_1000), None);
        assert_eq!(probed_block(&text[..90], 0x10000, 0x11000), None);
        let cut: &[u8] = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                    Size:                  4 kB\n\
                    55550000-55551000 r--p 00000000 00:23 13   /bin/y\n\
                    VmFlags: rd mr mw me \n";
        assert_eq!(probed_block(cut, 0x10000, 0x11000), None);
        // A name this provider does not know gives no flags.
        let unknown: &[u8] = b"00010000-00011000 r--p 00000000 00:23 12   /lib/x.so\n\
                        VmFlags: rd mr mw me sd \n";
        assert_eq!(
            probed_block(unknown, 0x10000, 0x11000),
            Some(ProbedBlock {
                vm_flags: None,
                thp_eligible: None,
            })
        );
    }

    /// A probe of a file on this host (a memfd) reads its own block: one
    /// page where the kernel chooses, then a longer mapping at an offset
    /// within a PMD block, each with the protection and sharing it was made
    /// with.
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
            Placement::Anywhere,
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
        // The same probe succeeds again (what a probe removes is
        // a_probe_removes_its_whole_reservation's).
        assert!(
            probe(
                &file,
                libc::PROT_READ as u8,
                false,
                0,
                PAGE,
                Placement::Anywhere
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

    /// A memfd of `size` bytes this test owns.
    fn memfd(size: u64) -> std::fs::File {
        // SAFETY: a new memfd this test owns.
        let fd = unsafe { libc::memfd_create(c"host-probe".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: memfd_create returned a new descriptor.
        let file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        file.set_len(size).unwrap();
        file
    }

    /// Whether no page from `start` to `end` is mapped: an inaccessible
    /// mapping of exactly that range that replaces nothing can be made, and
    /// is removed at once.
    fn unmapped(start: u64, end: u64) -> bool {
        // SAFETY: MAP_FIXED_NOREPLACE replaces nothing.
        let mapped = unsafe {
            libc::syscall(
                libc::SYS_mmap,
                start as *mut libc::c_void,
                (end - start) as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if mapped == -1 {
            return false;
        }
        // SAFETY: the mapping was made just now, by this test.
        unsafe { libc::syscall(libc::SYS_munmap, mapped, end - start) };
        mapped as u64 == start
    }

    /// Whether every page from `start` to `end` is mapped: `mincore(2)` fails
    /// with ENOMEM where one is not.
    fn mapped(start: u64, end: u64) -> bool {
        let mut residency = vec![0u8; ((end - start) / PAGE) as usize];
        // SAFETY: residency holds a byte for each page of the range.
        unsafe {
            libc::mincore(
                start as *mut libc::c_void,
                (end - start) as usize,
                residency.as_mut_ptr(),
            ) == 0
        }
    }

    /// The number of mappings this process has: the lines of its `maps`.
    fn mappings() -> usize {
        std::fs::read("/proc/self/maps")
            .unwrap()
            .iter()
            .filter(|byte| **byte == b'\n')
            .count()
    }

    /// A probe removes everything it held: after a mapping in its
    /// reservation, the reservation's whole range is unmapped, and probes
    /// leave this process with as many mappings as it had. It runs in a
    /// child process of this test binary ([`in_namespace`]), so no other
    /// test maps into a range it checks.
    #[test]
    fn a_probe_removes_its_whole_reservation() {
        if !in_namespace(module_path!(), "a_probe_removes_its_whole_reservation") {
            return;
        }
        let file = memfd(4 * PMD_SIZE);
        let read = libc::PROT_READ as u8;
        for (offset, length, residue) in [
            (0, PAGE, None),
            (0, PMD_SIZE, Some(0)),
            (PMD_SIZE, PMD_SIZE, Some(PAGE)),
        ] {
            let held = map_in_reservation(&file, read, libc::MAP_PRIVATE, offset, length, residue)
                .unwrap();
            assert!(held.window_held, "{residue:?}");
            assert!(held.start < held.window && held.window_end < held.end);
            assert_eq!(held.window_end - held.window, length);
            if let Some(residue) = residue {
                assert_eq!(held.window % PMD_SIZE, residue);
            }
            assert!(mapped(held.window, held.window_end), "{residue:?}");
            let (start, end) = (held.start, held.end);
            drop(held);
            assert!(unmapped(start, end), "{residue:?}");
        }
        // Once, so that what reading and probing allocate is in place.
        mappings();
        assert!(probe(&file, read, false, 0, PAGE, Placement::Anywhere).is_some());
        let before = mappings();
        assert!(probe(&file, read, false, 0, PAGE, Placement::Anywhere).is_some());
        assert!(
            probe(
                &file,
                read,
                false,
                PMD_SIZE,
                PMD_SIZE,
                Placement::Residue(PAGE)
            )
            .is_some()
        );
        assert_eq!(mappings(), before);
    }

    /// A probe that fails before it maps the file holds nothing after: where
    /// no reservation can be made (more address space than a process has),
    /// or where the offset within a PMD-sized block it was asked for is not
    /// page-aligned, it answers `None` and leaves this process with as many
    /// mappings as it had. It runs in a child process ([`in_namespace`]).
    #[test]
    fn a_probe_that_fails_early_holds_nothing() {
        if !in_namespace(module_path!(), "a_probe_that_fails_early_holds_nothing") {
            return;
        }
        let file = memfd(4 * PMD_SIZE);
        let read = libc::PROT_READ as u8;
        mappings();
        assert!(probe(&file, read, false, 0, PAGE, Placement::Anywhere).is_some());
        let before = mappings();
        let huge = 1 << 47;
        assert!(map_in_reservation(&file, read, libc::MAP_PRIVATE, 0, huge, None).is_none());
        assert_eq!(
            probe(&file, read, false, 0, huge, Placement::Anywhere),
            None
        );
        assert_eq!(
            probe(
                &file,
                read,
                false,
                0,
                PMD_SIZE,
                Placement::Residue(PAGE / 2)
            ),
            None
        );
        assert_eq!(mappings(), before);
    }

    /// A probe whose mapping fails after it gave its window back removes the
    /// pages it still holds, before the window and after it, and leaves the
    /// window to whoever maps it: here a page standing for another thread's
    /// mapping, which stays mapped and keeps what was written to it. A
    /// description opened for writing only makes the late failure: `do_mmap`
    /// refuses it with EACCES (mm/mmap.c), with the window already given
    /// back. It runs in a child process ([`in_namespace`]).
    #[test]
    fn a_window_a_probe_fails_to_map_is_left_to_whoever_maps_it() {
        if !in_namespace(
            module_path!(),
            "a_window_a_probe_fails_to_map_is_left_to_whoever_maps_it",
        ) {
            return;
        }
        let file = memfd(4 * PMD_SIZE);
        let write_only = std::fs::OpenOptions::new()
            .write(true)
            .open(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&file)
            ))
            .unwrap();
        let held = map_in_reservation(
            &write_only,
            libc::PROT_READ as u8,
            libc::MAP_PRIVATE,
            0,
            PMD_SIZE,
            Some(PAGE),
        )
        .unwrap();
        assert!(!held.window_held, "the mapping failed");
        let (start, end, window, window_end) = (held.start, held.end, held.window, held.window_end);
        assert!(start < window && window_end < end);
        assert!(unmapped(window, window_end), "the window was given back");
        // SAFETY: MAP_FIXED_NOREPLACE replaces nothing.
        let other = unsafe {
            libc::syscall(
                libc::SYS_mmap,
                window as *mut libc::c_void,
                PAGE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(other as u64, window);
        // SAFETY: the page was mapped readable and writable just now.
        unsafe { (window as *mut u8).write_volatile(0x5a) };
        drop(held);
        assert!(mapped(window, window + PAGE), "the other mapping is kept");
        // SAFETY: mincore found the page mapped, and only this test maps or
        // unmaps it.
        assert_eq!(unsafe { (window as *const u8).read_volatile() }, 0x5a);
        assert!(unmapped(start, window), "the pages before the window");
        assert!(unmapped(window_end, end), "the pages after the window");
        assert!(unmapped(window + PAGE, window_end));
        // SAFETY: the page is this test's.
        unsafe { libc::syscall(libc::SYS_munmap, window, PAGE) };
    }
}
