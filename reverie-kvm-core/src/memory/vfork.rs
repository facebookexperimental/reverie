/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A vfork child's changes to private memory, carried back to its parent.
//!
//! On Linux a vfork child (`vfork(2)`, and `clone(2)` or `clone3(2)` with
//! `CLONE_VM|CLONE_VFORK`) shares its parent's whole address space until it
//! execs or exits: `copy_mm()` gives it the parent's mm, and the parent's call
//! returns only then (`wait_for_vfork_done()`). Here the child runs on a copy
//! ([`GuestMemory::snapshot_sharing_address_space`]) whose shared views are the
//! parent's own objects, and the backend keeps the parent inside its call for
//! the whole window. When the window ends, at a successful exec or at the
//! child's last exit (a death by a signal included),
//! [`GuestMemory::return_vfork_changes`] writes what the child changed in
//! private memory into the parent, so the parent resumes with the memory Linux
//! would give it. It first makes the old mm's release effects of Linux's
//! `mm_release()`, which runs before the vfork completion whenever another
//! user of the mm exists, as the waiting parent is: the word the child
//! registered as its `clear_child_tid` (by `set_tid_address(2)`) is cleared
//! in the copy, so the store goes back with the child's other changes, and
//! one waiter on the parent's word is woken once it holds the store.
//!
//! The comparison cannot miss a change. Every guest-visible page of user
//! memory is one of three kinds, in the child and in the parent alike:
//! - a retained shared page (an ordinary-file view, or fork-shared anonymous
//!   memory), the same object on both sides, which needs nothing;
//! - a page with a private backing of its own, compared through the mapping;
//! - any other page, whose bytes are the base backing's at the page's offset.
//!
//! A page of the last kind that is a hole in both bases compared (the copy's
//! and the parent's, or with a baseline the copy's and the baseline's) reads as
//! zeros on both sides, and every other one lies in a data extent (`SEEK_DATA`)
//! of at least one of them, so it is compared. Every write the child's image receives lands
//! in its backing's page cache, and so in a data extent: the guest's own
//! stores, the provider's copies to user memory, and the kernel's writes for
//! the child through the writable alias (`read(2)` into the child's buffer).
//! A page the child zeroed (`MADV_DONTNEED` punches a hole) differs from the
//! parent's data and is written back as zeros.
//!
//! The child may change a mapping only for a while, as a tool that maps a
//! scratch page for a call and unmaps it does. When the window ends, a copy
//! that does not map its user pages exactly as the parent does (with a
//! baseline, as the copy did when the child started) is refused by name: on
//! Linux the change would be the parent's too, and a copy carries back
//! contents, not mappings. Exactly means the same mapping too, not only the
//! same protection: each new mapping has an incarnation of its own, so a page
//! the child unmapped and mapped again, or replaced with `MAP_FIXED`, with
//! the protection and file offset it had, still differs. The executor refuses a `brk` that moves the break
//! at the call, since the break is the parent's too even where it moves
//! within a page. So the copy and the parent map the same pages, and writing
//! contents back is enough. A page the child no longer maps held a mapping it
//! created and removed, whose stores Linux discards with it, and is not
//! written back.
//!
//! A parent with no other live thread cannot change its private memory during
//! the window, since its only thread waits in its call, so every difference
//! between the copy and the parent is the child's. A parent with another live
//! thread can: the copy then keeps a baseline from before the child ran
//! ([`GuestMemory::keep_vfork_baseline`]), and only the bytes the child changed
//! go back. A byte that another thread also changed, to a different value, and
//! a changed page whose mapping another thread replaced (by a new mapping over
//! it, `MAP_FIXED` or an unmap and a new mapping, whatever its protection) or
//! removed, are refused by name: a copy cannot order those stores, and on
//! Linux a store to a replaced mapping went with it. What remains different from
//! Linux, where the two share the address space, is that during the window
//! neither sees the other's stores to private memory: a child that reads memory
//! another thread of its parent changed during the window sees the value from
//! before the window, a thread that reads memory the child changed sees the
//! value from before the child's store, and a store that leaves a byte as it
//! was cannot be told from no store, so the child's change to that byte goes
//! back over it.
//!
//! Comparing the end of the window with its start cannot see what happened in
//! between, so three more cases are documented limits rather than refusals: a
//! byte the child changed and changed back (or another thread did, an ABA),
//! which reads as never changed; a store back to the baseline's value, which
//! reads as no store; and the same final value written independently by the
//! child and another thread, which merges silently, so a counter that both
//! incremented once ends one short of Linux's value.
//!
//! The child must not create threads during its window: the provider refuses
//! that by name at the call. Linux completes the vfork when the creating task
//! execs or exits, whatever threads of the child survive, and a copy whose
//! other threads still run cannot go back then.
//!
//! While the changes go back, the parent's calling thread is still in its
//! call, but its other threads run unless the tool holds them. A tool that
//! serializes the guest's threads, and runs none of them from the child's exit
//! or exec until the parent's call returns, has the write-back see no
//! concurrent store. Without one, a store another thread makes while the
//! changes go back, to a byte the child changed, can be overwritten by the
//! child's value, although on Linux it would come after it.

use super::*;

/// What a vfork child's copy keeps of its parent until the child's changes go
/// back ([`GuestMemory::return_vfork_changes`]).
#[derive(Debug)]
pub(super) struct VforkParent {
    memory: GuestMemory,
    /// The parent's exec count when the copy was taken. A parent that execs
    /// during the window (from another of its threads, which kills the
    /// waiting caller) has a new address space, which the child's changes do
    /// not reach on Linux either.
    exec_count: u64,
    baseline: Option<VforkBaseline>,
}

/// The copy as it was when the child started, kept for a parent with another
/// live thread ([`GuestMemory::keep_vfork_baseline`]).
#[derive(Debug)]
struct VforkBaseline {
    memory: GuestMemory,
    /// The parent's separately backed pages when the copy was taken, with the
    /// generation of each installation.
    parent_backing: BTreeMap<u64, MappingGeneration>,
}

/// What [`GuestMemory::return_vfork_changes`] did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VforkWriteBack {
    /// User pages compared.
    pub pages_compared: usize,
    /// Bytes written into the parent.
    pub bytes_written: usize,
}

/// User pages compared at a time.
const RUN_PAGES: u64 = 256;

impl GuestMemory {
    /// Records `parent` as the parent whose address space this copy stands in
    /// for, from the copy until the child's changes go back.
    pub(super) fn link_vfork_parent(&self, parent: &GuestMemory) {
        let exec_count = parent
            .mapping
            .exec_count
            .load(std::sync::atomic::Ordering::Acquire);
        *self.mapping.vfork_parent.lock().unwrap() = Some(VforkParent {
            memory: parent.clone(),
            exec_count,
            baseline: None,
        });
    }

    /// Keeps this vfork child's copy as it is now, before the child runs, so
    /// that [`GuestMemory::return_vfork_changes`] writes back only the bytes
    /// the child changes. The backend calls it when the parent has another
    /// live thread, whose stores, during the window, reach the parent and not
    /// the copy: comparing the copy with the parent would undo them. Without
    /// a baseline the copy is compared with the parent itself, which nothing
    /// else changes while the parent's only thread waits in its call.
    pub fn keep_vfork_baseline(&self) -> Result<()> {
        let parent = match self.mapping.vfork_parent.lock().unwrap().as_ref() {
            Some(link) => link.memory.clone(),
            None => return Ok(()),
        };
        let parent_backing = parent
            .mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .iter()
            .map(|(&page, installed)| (page, installed._generation))
            .collect();
        let memory = self.snapshot()?;
        if let Some(link) = self.mapping.vfork_parent.lock().unwrap().as_mut() {
            link.baseline = Some(VforkBaseline {
                memory,
                parent_backing,
            });
        }
        Ok(())
    }

    /// Whether this memory is a vfork child's copy whose window is still
    /// open: its changes have yet to go back to its parent
    /// ([`GuestMemory::return_vfork_changes`]), and the child has not exec'd.
    pub fn has_vfork_parent(&self) -> bool {
        self.mapping.vfork_parent.lock().unwrap().is_some()
    }

    /// Ends this vfork child's window: writes what the child changed in
    /// private user memory, the pages from physical `user_start` on, into its
    /// parent, once. The pages below `user_start` are the backend's own (page
    /// tables, syscall transport, Tool stacks), which differ between the two
    /// processes and never go back. Called at the child's successful exec,
    /// before the new image replaces the copy, and at its last exit. Without
    /// a vfork parent (a fork's copy, an initial image, or a child whose
    /// window already ended) it does nothing.
    ///
    /// A copy that does not map its user pages as the parent does (with a
    /// baseline, as it did when the child started) is refused with
    /// [`Error::VforkChildCapability`] before anything is written, and a page
    /// the copy no longer maps is not written.
    ///
    /// `clear_child_tid` is the address the child registered as its
    /// `clear_child_tid`, which the caller has taken from the child: Linux's
    /// `mm_release()` stores zero there and wakes one waiter before the vfork
    /// completes, since the parent still uses the mm. The store goes to this
    /// copy before the comparison, so it goes back with the child's other
    /// changes, best effort as Linux's `put_user` (a bad address stores
    /// nothing); the wake goes to the parent's word once the write-back
    /// reached it, and to nothing when the parent exec'd. Without a vfork
    /// parent the address is not used.
    ///
    /// The parent's calling thread must not run while this runs: the backend
    /// keeps it inside its call until afterwards. With a baseline
    /// ([`GuestMemory::keep_vfork_baseline`]) only the bytes the child
    /// changed are written, and a byte that another thread of the parent
    /// changed to a different value during the window is refused with
    /// [`Error::VforkChildCapability`], as is a changed page whose mapping
    /// another thread replaced or removed: a copy cannot order those stores.
    /// The module documentation says what holds for the parent's other
    /// threads.
    pub fn return_vfork_changes(
        &self,
        user_start: u64,
        clear_child_tid: Option<u64>,
    ) -> Result<VforkWriteBack> {
        let Some(link) = self.mapping.vfork_parent.lock().unwrap().take() else {
            return Ok(VforkWriteBack::default());
        };
        if let Some(address) = clear_child_tid {
            let _ = self.user().put_user_i32(address, 0);
        }
        let Some(result) = self.write_back_to(&link, user_start)? else {
            return Ok(VforkWriteBack::default());
        };
        if let Some(address) = clear_child_tid {
            wake_one_waiter(&link.memory, address);
        }
        Ok(result)
    }

    /// The write-back of [`GuestMemory::return_vfork_changes`], under the
    /// parent's allocation guard; `None` when the parent exec'd since the
    /// copy was taken.
    fn write_back_to(&self, link: &VforkParent, user_start: u64) -> Result<Option<VforkWriteBack>> {
        let parent = &link.memory;
        // No layout change in the parent while its memory is compared. The
        // exec count is read under the same guard: an exec increments it
        // before it takes the guard to replace the image, so either this
        // write-back ends before the old image goes, or it sees the exec.
        let _allocation = parent.allocation_guard();
        if parent
            .mapping
            .exec_count
            .load(std::sync::atomic::Ordering::Acquire)
            != link.exec_count
        {
            return Ok(None);
        }
        let page_size = PAGE_SIZE as u64;
        let first = user_start.max(self.guest_base()).div_ceil(page_size);
        let end = self.guest_end() / page_size;
        // The child may change a mapping only for a while, as a tool's
        // scratch page does: one still changed now would be its parent's on
        // Linux, and the copy carries back contents, not mappings.
        let reference = link
            .baseline
            .as_ref()
            .map_or(parent, |baseline| &baseline.memory);
        if !self.maps_user_pages_as(reference, first) {
            return Err(Error::VforkChildCapability {
                operation: "vfork write-back",
                reason: "the vfork child left a mapping changed (by mmap, munmap, mprotect or \
                         mremap) when its window ended, which on Linux would be its parent's \
                         too, and a copy carries back contents, not mappings",
            });
        }
        // Retained shared pages are the same object on both sides.
        let mut skipped = self.retained_shared_pages();
        skipped.extend(parent.retained_shared_pages());
        let mut candidates = self.base_data_pages(first, end);
        candidates.extend(self.private_backing_pages(first, end));
        match &link.baseline {
            None => {
                candidates.extend(parent.base_data_pages(first, end));
                candidates.extend(parent.private_backing_pages(first, end));
            }
            Some(baseline) => {
                candidates.extend(baseline.memory.base_data_pages(first, end));
            }
        }
        // Only the pages the child still maps: a page it no longer maps held
        // a mapping it created and removed, whose stores Linux discards with
        // it.
        let pages: Vec<u64> = self
            .mapped_pages_among(&merge_page_ranges(candidates))
            .into_iter()
            .filter(|page| !skipped.contains(page))
            .collect();
        let mut result = VforkWriteBack::default();
        let buffers = &mut [
            vec![0; (RUN_PAGES * page_size) as usize],
            vec![0; (RUN_PAGES * page_size) as usize],
            vec![0; (RUN_PAGES * page_size) as usize],
        ];
        let mut index = 0;
        while index < pages.len() {
            let mut last = index + 1;
            while last < pages.len()
                && pages[last] == pages[last - 1] + 1
                && last - index < RUN_PAGES as usize
            {
                last += 1;
            }
            let (run_first, run_end) = (pages[index], pages[last - 1] + 1);
            result.pages_compared += last - index;
            result.bytes_written += match &link.baseline {
                None => self.write_back_run(parent, run_first, run_end, buffers)?,
                Some(baseline) => {
                    self.merge_back_run(parent, baseline, run_first, run_end, buffers)?
                }
            };
            index = last;
        }
        Ok(Some(result))
    }

    /// Writes the pages of `[first, end)` that differ between this copy and
    /// `parent` into `parent`. Nothing else changes the parent meanwhile, so
    /// every difference is the child's.
    fn write_back_run(
        &self,
        parent: &GuestMemory,
        first: u64,
        end: u64,
        buffers: &mut [Vec<u8>; 3],
    ) -> Result<usize> {
        let page_size = PAGE_SIZE;
        let length = (end - first) as usize * page_size;
        let address = first * page_size as u64;
        let [child, current, _] = buffers;
        self.read_raw(address, &mut child[..length])?;
        parent.read_raw(address, &mut current[..length])?;
        let mut written = 0;
        let mut run: Option<usize> = None;
        for index in 0..=length / page_size {
            let differs = index < length / page_size && {
                let range = index * page_size..(index + 1) * page_size;
                child[range.clone()] != current[range]
            };
            match (differs, run) {
                (true, None) => run = Some(index),
                (false, Some(start)) => {
                    let bytes = start * page_size..index * page_size;
                    parent.write_raw(address + bytes.start as u64, &child[bytes.clone()])?;
                    written += bytes.len();
                    run = None;
                }
                _ => {}
            }
        }
        Ok(written)
    }

    /// Writes the bytes of `[first, end)` that the child changed relative to
    /// `baseline` into `parent`, leaving every other byte, which another
    /// thread of the parent may have changed during the window, as it is.
    fn merge_back_run(
        &self,
        parent: &GuestMemory,
        baseline: &VforkBaseline,
        first: u64,
        end: u64,
        buffers: &mut [Vec<u8>; 3],
    ) -> Result<usize> {
        let page_size = PAGE_SIZE;
        let length = (end - first) as usize * page_size;
        let address = first * page_size as u64;
        let [child, start, current] = buffers;
        self.read_raw(address, &mut child[..length])?;
        baseline.memory.read_raw(address, &mut start[..length])?;
        if child[..length] == start[..length] {
            return Ok(0);
        }
        parent.read_raw(address, &mut current[..length])?;
        // Everything a copy cannot order is refused before anything of this
        // run is written.
        for index in 0..length / page_size {
            let range = index * page_size..(index + 1) * page_size;
            if child[range.clone()] == start[range.clone()] {
                continue;
            }
            parent.check_vfork_page_unchanged(first + index as u64, baseline)?;
            if range.into_iter().any(|byte| {
                child[byte] != start[byte]
                    && current[byte] != start[byte]
                    && current[byte] != child[byte]
            }) {
                return Err(Error::VforkChildCapability {
                    operation: "vfork write-back",
                    reason: "the vfork child and another thread of its parent changed the \
                             same bytes during the window, which a copy cannot order",
                });
            }
        }
        let mut written = 0;
        let mut byte = 0;
        while byte < length {
            if child[byte] == start[byte] || child[byte] == current[byte] {
                byte += 1;
                continue;
            }
            let run_start = byte;
            while byte < length && child[byte] != start[byte] && child[byte] != current[byte] {
                byte += 1;
            }
            parent.write_raw(address + run_start as u64, &child[run_start..byte])?;
            written += byte - run_start;
        }
        Ok(written)
    }

    /// Refuses a page the child changed whose mapping another thread of this
    /// parent removed or replaced during the window: on Linux the child's
    /// stores went to the old mapping. A replaced page has another mapping
    /// incarnation than the baseline's, whatever its protection, and a
    /// separately backed one another installation.
    fn check_vfork_page_unchanged(&self, page: u64, baseline: &VforkBaseline) -> Result<()> {
        let started = baseline
            .memory
            .mapping
            .address_space
            .lock()
            .unwrap()
            .mapping_incarnations
            .get(&page)
            .copied();
        let state = self.mapping.address_space.lock().unwrap();
        let installed = state
            .backing_pages
            .get(&page)
            .map(|installed| installed._generation);
        if !state.pages.contains_key(&page)
            || state.mapping_incarnations.get(&page).copied() != started
            || installed != baseline.parent_backing.get(&page).copied()
        {
            return Err(Error::VforkChildCapability {
                operation: "vfork write-back",
                reason: "another thread of the parent removed or replaced the mapping of a \
                         page the vfork child changed during the window",
            });
        }
        Ok(())
    }

    /// Whether this memory maps every user page from `first` on exactly as
    /// `reference` does: the same pages, with the same access and declared
    /// mapping, of the same mapping incarnation (so a page mapped again is
    /// not the same, see `AddressSpaceState::mapping_incarnations`), of the
    /// same files at the same offsets, and the same shared anonymous pages.
    /// (The backend's Tool-scratch pages lie below the user range.)
    fn maps_user_pages_as(&self, reference: &GuestMemory, first: u64) -> bool {
        let mine = self.mapping.address_space.lock().unwrap();
        let theirs = reference.mapping.address_space.lock().unwrap();
        mine.pages.range(first..).eq(theirs.pages.range(first..))
            && mine
                .mapping_incarnations
                .range(first..)
                .eq(theirs.mapping_incarnations.range(first..))
            && mine
                .file_pages
                .range(first..)
                .eq(theirs.file_pages.range(first..))
            && mine
                .shared_anonymous_pages
                .range(first..)
                .eq(theirs.shared_anonymous_pages.range(first..))
    }

    /// The pages of `ranges` (sorted, disjoint `[first, end)` page ranges)
    /// this memory maps, ascending. Before user access is enabled there is no
    /// record of them, and every page of the ranges counts.
    fn mapped_pages_among(&self, ranges: &[(u64, u64)]) -> Vec<u64> {
        let state = self.mapping.address_space.lock().unwrap();
        if !state.enabled {
            return ranges.iter().flat_map(|&(first, end)| first..end).collect();
        }
        ranges
            .iter()
            .flat_map(|&(first, end)| state.pages.range(first..end).map(|(&page, _)| page))
            .collect()
    }

    /// The pages of this memory whose backing is retained and shared (an
    /// ordinary-file view or fork-shared anonymous memory).
    fn retained_shared_pages(&self) -> BTreeSet<u64> {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .iter()
            .filter(|(_, installed)| installed._slice.backing.kind.retained_shared())
            .map(|(&page, _)| page)
            .collect()
    }

    /// The pages of `[first, end)` with a private backing of their own.
    fn private_backing_pages(&self, first: u64, end: u64) -> Vec<(u64, u64)> {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .range(first..end)
            .filter(|(_, installed)| !installed._slice.backing.kind.retained_shared())
            .map(|(&page, _)| (page, page + 1))
            .collect()
    }

    /// The pages of `[first, end)` that lie in a data extent of this memory's
    /// base backing, as ranges. If the extents cannot be read, every page of
    /// the range.
    fn base_data_pages(&self, first: u64, end: u64) -> Vec<(u64, u64)> {
        let page_size = PAGE_SIZE as u64;
        let slice = &self.mapping.slice;
        let fd = slice.backing.fd.as_raw_fd();
        let base = self.guest_base();
        let to_offset = |page: u64| (page * page_size - base) as i64 + slice.offset as i64;
        let to_address = |offset: i64| (offset - slice.offset as i64) as u64 + base;
        let everything = vec![(first, end)];
        let limit = to_offset(end);
        let mut cursor = to_offset(first);
        let mut ranges = Vec::new();
        while cursor < limit {
            // SAFETY: fd is the live base backing owned by this mapping.
            let data = unsafe { libc::lseek(fd, cursor, libc::SEEK_DATA) };
            if data < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) {
                    break;
                }
                return everything;
            }
            if data >= limit {
                break;
            }
            // SAFETY: as above.
            let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
            if hole <= data {
                return everything;
            }
            let extent_end = hole.min(limit);
            ranges.push((
                to_address(data) / page_size,
                to_address(extent_end).div_ceil(page_size),
            ));
            cursor = extent_end;
        }
        ranges
    }
}

/// Linux's `FUTEX_WAKE` of one waiter on the word at `address` in `memory`,
/// as `mm_release()` wakes a cleared `clear_child_tid` word: shared, not
/// private, as the kernel's wake is. A word that is not accessible user memory
/// wakes nobody, as Linux's wake then fails with `EFAULT`.
fn wake_one_waiter(memory: &GuestMemory, address: u64) {
    if memory.user().user_accessible_prefix(address, 4).ok() != Some(4) {
        return;
    }
    let Ok(operand) = memory.user().retain_translated_range(address, 4) else {
        return;
    };
    // SAFETY: the word is accessible user memory, and the operand keeps its
    // host mapping alive for this call. FUTEX_WAKE reads nothing through it.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            operand.address(),
            libc::FUTEX_WAKE,
            1,
            0,
            0,
            0,
        );
    }
}

/// Sorts and merges page ranges `[first, end)`, joining ranges that overlap
/// or touch.
fn merge_page_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (first, end) in ranges {
        match merged.last_mut() {
            Some(last) if first <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((first, end)),
        }
    }
    merged
}
