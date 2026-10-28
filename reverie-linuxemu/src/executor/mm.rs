/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Memory mappings: brk, mmap, munmap, mprotect, mremap, madvise, mincore (gVisor: pkg/sentry/mm, syscalls/linux/sys_mmap.go).

use super::*;

pub(super) fn brk(memory: &mut GuestMemory, state: &mut LoadedStaticElf, requested: u64) -> i64 {
    if requested == 0 {
        return state.program_break as i64;
    }
    // Linux refuses a break below the image's data (end_data).
    if requested < BOOT_RESERVED_END.max(state.min_break) || requested >= state.brk_limit {
        return state.program_break as i64;
    }
    let previous = state.program_break;
    if requested > previous {
        // As on Linux, growth adds only the whole pages from the old break's
        // page end to the new break's; the page holding the old break stays
        // as it is, and growth within it only moves the break.
        let (Some(first), Some(end)) = (
            align_up(previous, PAGE_SIZE),
            align_up(requested, PAGE_SIZE),
        ) else {
            return state.program_break as i64;
        };
        if end > first {
            // Like Linux, refuse growth that reaches a mapping or the page
            // below one (brk keeps a page between the new break and the next
            // mapping), before anything changes. The check stops where the
            // identity addresses above the break end: at the window, or at
            // the end of the mapping range without one.
            let identity_top = if memory.has_mmap_window() {
                state.brk_limit
            } else {
                state.mmap_limit
            };
            let guarded = end.saturating_add(PAGE_SIZE).min(identity_top.max(end));
            // The break is a user address (in a PIE window, not physical);
            // the bookkeeping below is by physical address.
            let Some(physical) = memory.user_range_to_guest(first, guarded - first) else {
                return state.program_break as i64;
            };
            if memory.find_unmapped_user_range(
                physical,
                physical + (guarded - first),
                guarded - first,
            ) != Some(physical)
            {
                return state.program_break as i64;
            }
            let Ok(length) = usize::try_from(end - first) else {
                return state.program_break as i64;
            };
            let Ok(reservation) = memory.reserve_region(physical, end - first, RegionKind::Heap)
            else {
                return state.program_break as i64;
            };
            if memory.zero_raw(physical, length).is_err()
                || memory.map_user_range(physical, end - first, false).is_err()
            {
                return state.program_break as i64;
            }
            reservation.commit();
            memory.record_file_pages(physical, end - first, None);
        }
    } else if requested < previous {
        let Some(unmap_start) = align_up(requested, PAGE_SIZE) else {
            return state.program_break as i64;
        };
        let Some(unmap_end) = align_up(previous, PAGE_SIZE) else {
            return state.program_break as i64;
        };
        if unmap_end > unmap_start {
            let Some(physical) = memory.user_range_to_guest(unmap_start, unmap_end - unmap_start)
            else {
                return state.program_break as i64;
            };
            // Linux (mm/mmap.c, brk) releases the pages only when a mapping
            // intersects them; with none (the program unmapped its heap) it
            // returns the old break unchanged.
            if !memory.user_range_has_mapping(physical, unmap_end - unmap_start)
                || memory
                    .unmap_user_range(physical, unmap_end - unmap_start)
                    .is_err()
            {
                return state.program_break as i64;
            }
        }
    }
    state.program_break = requested;
    requested as i64
}

#[cfg(test)]
pub(crate) fn test_brk(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    requested: u64,
) -> i64 {
    brk(memory, state, requested)
}

// TODO-HUMAN-REVIEW(PR-235): Review deterministic hole-first mmap allocation.
/// Bottom-up placement in `[mmap_base, limit)` for a memory without an mmap
/// window: the lowest hole below the cursor, else the lowest range from the
/// cursor up, else (a hole that the cursor splits) the lowest range anywhere.
fn legacy_placement(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    length: u64,
    limit: u64,
) -> Option<u64> {
    let next = state
        .mmap_next
        .clamp(state.mmap_base, limit.max(state.mmap_base));
    memory
        .find_unmapped_user_range(state.mmap_base, next, length)
        .or_else(|| memory.find_unmapped_user_range(next, limit, length))
        .or_else(|| memory.find_unmapped_user_range(state.mmap_base, limit, length))
}

/// Where mremap moves the mapping at physical `old_address`: as Linux does,
/// by the mapping's kind, a regular file keeping its file offset.
fn find_mremap_destination(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    old_address: u64,
    length: u64,
) -> Option<u64> {
    let kind = memory
        .file_offset(old_address)
        .map_or(MappingKind::Anonymous, MappingKind::RegularFile);
    place_mapping(memory, state, length, 0, kind, false)
}

/// What a mapping without MAP_FIXED maps, which decides Linux's alignment.
#[derive(Clone, Copy)]
pub(crate) enum MappingKind {
    Anonymous,
    /// A regular file at this offset.
    RegularFile(u64),
    /// Anything else (a device, a pipe): no alignment.
    Other,
}

impl MappingKind {
    pub(crate) fn file_offset(self) -> Option<u64> {
        match self {
            Self::RegularFile(offset) => Some(offset),
            _ => None,
        }
    }
}

pub(super) const LARGE_PAGE: u64 = 2 * 1024 * 1024;
/// Linux's default vm.mmap_min_addr: the lowest address a hint is raised to.
pub(super) const MMAP_MIN_ADDR: u64 = 0x1_0000;
/// MAP_32BIT mappings lie below 2 GiB.
pub(super) const MAP_32BIT_END: u64 = 0x8000_0000;

/// The physical address Linux would choose for a `length`-byte mapping without
/// MAP_FIXED. In a memory with Linux's layout (see the K2 design note): a free
/// page-aligned hint is used as it is; otherwise the highest free gap below
/// mmap_base, with Linux's large-page alignment (`__thp_get_unmapped_area`)
/// for an anonymous mapping whose length is a whole number of large pages and
/// for a regular file range holding a whole aligned large page. A MAP_32BIT
/// mapping stays below 2 GiB. A memory a loader never laid out keeps the
/// bottom-up allocator.
pub(crate) fn place_mapping(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    length: u64,
    hint: u64,
    kind: MappingKind,
    map_32bit: bool,
) -> Option<u64> {
    // Linux rounds a hint down to a page and raises a nonzero one to
    // mmap_min_addr (do_mmap's round_hint_to_min).
    let hint = match hint & !(PAGE_SIZE - 1) {
        0 => 0,
        hint => hint.max(MMAP_MIN_ADDR),
    };
    let free_hint = |hint: u64| {
        let physical = memory.user_range_to_guest(hint, length)?;
        (physical >= BOOT_RESERVED_END
            && physical.checked_add(length)? <= state.mmap_limit
            && memory.find_unmapped_user_range(physical, physical + length, length)
                == Some(physical))
        .then_some(physical)
    };
    let window = memory.has_mmap_window();
    // The top of the identity memory a mapping may fall back to: the identity
    // end (below a PIE window, if any) in a laid-out memory, the mapping
    // range's start without a window.
    let identity_top = if window {
        memory.user_layout().1
    } else {
        state.mmap_base
    };
    if map_32bit {
        // Linux takes a free hint that ends below 2 GiB, else the lowest free
        // range in [1 GiB, 2 GiB). KVM's guests back little or no memory
        // there. Without a window, the mapping range's part below 2 GiB comes
        // first, bottom-up as there; then, in either layout, the highest free
        // identity memory below 2 GiB and below the mapping range.
        if hint != 0
            && hint
                .checked_add(length)
                .is_some_and(|end| end <= MAP_32BIT_END)
            && let Some(physical) = free_hint(hint)
        {
            return Some(physical);
        }
        let low_limit = state.mmap_limit.min(MAP_32BIT_END);
        if !window
            && state.mmap_base < low_limit
            && let Some(found) = legacy_placement(memory, state, length, low_limit)
        {
            return Some(found);
        }
        return memory.find_unmapped_user_range_topdown(
            BOOT_RESERVED_END,
            identity_top.min(MAP_32BIT_END),
            length,
        );
    }
    if !window {
        return legacy_placement(memory, state, length, state.mmap_limit);
    }
    if hint != 0
        && let Some(physical) = free_hint(hint)
    {
        return Some(physical);
    }
    // Linux maps at a free hint wherever it is. A low hint KVM cannot back
    // exactly (memory exists only below the identity end and in the windows)
    // gets the highest free range of identity memory below it, so the result
    // stays low and near the hint rather than at the top of the address space.
    // A hint KVM can back but is occupied is ignored, as Linux ignores it.
    if hint != 0
        && hint < MMAP_BASE / 2
        && memory.user_range_to_guest(hint, length).is_none()
        && let Some(found) = memory.find_unmapped_user_range_topdown(
            BOOT_RESERVED_END,
            hint.min(identity_top),
            length,
        )
    {
        return Some(found);
    }
    let top_down =
        |length| memory.find_unmapped_user_range_topdown(state.mmap_base, state.mmap_limit, length);
    let offset = match kind {
        // Linux aligns an anonymous mapping only when it has no hint.
        MappingKind::Anonymous if hint == 0 && length.is_multiple_of(LARGE_PAGE) => Some(0),
        MappingKind::RegularFile(offset)
            if offset.checked_add(length).is_some_and(|end| {
                end / LARGE_PAGE * LARGE_PAGE > align_up(offset, LARGE_PAGE).unwrap_or(u64::MAX)
            }) =>
        {
            Some(offset)
        }
        _ => None,
    };
    if let Some(offset) = offset
        && let Some(padded) = length.checked_add(LARGE_PAGE)
        && let Some(found) = top_down(padded)
    {
        let user = memory.physical_to_user(found)?;
        let shift = offset.wrapping_sub(user) & (LARGE_PAGE - 1);
        return Some(found + if shift == 0 { LARGE_PAGE } else { shift });
    }
    // When the window is full, identity memory below it still holds mappings
    // (at addresses Linux would not choose), as all of memory did before the
    // window existed.
    top_down(length).or_else(|| {
        memory.find_unmapped_user_range_topdown(BOOT_RESERVED_END, identity_top, length)
    })
}

/// Linux x86-64's TASK_SIZE with four-level paging: the end of the user
/// address space a fixed mapping must fit below.
pub(super) const TASK_SIZE: u64 = 0x7fff_ffff_f000;

/// `__get_unmapped_area`'s refusals of a fixed mapping (MAP_FIXED or
/// MAP_FIXED_NOREPLACE) of page-aligned `length` at `address`, in its order:
/// a range past TASK_SIZE (ENOMEM), then an unaligned address (EINVAL).
pub(crate) fn fixed_mapping_address_error(fixed: bool, address: u64, length: u64) -> Option<i32> {
    if !fixed {
        return None;
    }
    if length > TASK_SIZE || address > TASK_SIZE - length {
        return Some(libc::ENOMEM);
    }
    (!address.is_multiple_of(PAGE_SIZE)).then_some(libc::EINVAL)
}

/// MAP_FIXED_NOREPLACE's refusals once the range is known to be one KVM can
/// back, before the limits of KVM's own allocator: a file mapping's bad or
/// `O_PATH` descriptor (EBADF, which Linux looks up first); any page of the
/// physical range `address..end` already mapped (`find_vma_intersection`,
/// EEXIST), a stack page above the mapping range included; then
/// MAP_SHARED_VALIDATE, which refuses MAP_FIXED_NOREPLACE as a flag outside
/// `LEGACY_MAP_MASK` (EOPNOTSUPP).
pub(crate) fn noreplace_error(
    memory: &GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
    address: u64,
    end: u64,
) -> Option<i32> {
    if args[3] & libc::MAP_ANONYMOUS as u64 == 0 {
        let Some(file) = state.files.get(&(args[4] as libc::c_int)) else {
            return Some(libc::EBADF);
        };
        if file_status_flags(file).is_ok_and(|status| status & libc::O_PATH != 0) {
            return Some(libc::EBADF);
        }
    }
    if memory.find_unmapped_user_range(address, end, end - address) != Some(address) {
        return Some(libc::EEXIST);
    }
    (args[3] & libc::MAP_TYPE as u64 == libc::MAP_SHARED_VALIDATE as u64)
        .then_some(libc::EOPNOTSUPP)
}

pub(super) fn mmap(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    // x86-64's sys_mmap refuses an unaligned offset before anything else,
    // for an anonymous mapping too.
    if !args[5].is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    if let Some(error) = non_regular_mmap_early_refusal(state, args) {
        return error;
    }
    if args[1] == 0 {
        return negative_errno(libc::EINVAL);
    }
    let flags = args[3];
    let is_anonymous = flags & libc::MAP_ANONYMOUS as u64 != 0;
    let is_private = flags & libc::MAP_PRIVATE as u64 != 0;
    let is_shared = flags & libc::MAP_SHARED as u64 != 0;
    // mmap ignores protection bits other than these (calc_vm_prot_bits drops
    // PROT_SEM and unknown bits; only mprotect validates them).
    let prot = args[2] & MMAP_PROT_BITS;

    let Some(length) = align_up(args[1], PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    // MAP_FIXED_NOREPLACE maps exactly at the address, as MAP_FIXED does,
    // but fails with EEXIST rather than replace anything there (do_mmap).
    let noreplace = flags & libc::MAP_FIXED_NOREPLACE as u64 != 0;
    let fixed = flags & libc::MAP_FIXED as u64 != 0 || noreplace;
    if let Some(errno) = fixed_mapping_address_error(fixed, args[0], length) {
        return negative_errno(errno);
    }
    if !is_anonymous && signalfd_mask(state, args[4] as libc::c_int).is_some() {
        // Do not expose the non-mappable eventfd carrier's ESPIPE result.
        return negative_errno(libc::ENODEV);
    }
    let kind = if is_anonymous {
        MappingKind::Anonymous
    } else {
        match state
            .files
            .get(&(args[4] as libc::c_int))
            .map(std::fs::File::metadata)
        {
            Some(Ok(metadata)) if metadata.is_file() => MappingKind::RegularFile(args[5]),
            _ => MappingKind::Other,
        }
    };
    // A MAP_FIXED address is a user address; the bookkeeping below is by
    // physical address, and the result is the user address.
    let address = if fixed {
        let Some(address) = memory.user_range_to_guest(args[0], length) else {
            return negative_errno(libc::ENOMEM);
        };
        address
    } else {
        let map_32bit = flags & libc::MAP_32BIT as u64 != 0;
        let Some(address) = place_mapping(memory, state, length, args[0], kind, map_32bit) else {
            return negative_errno(libc::ENOMEM);
        };
        address
    };
    let Some(end) = address.checked_add(length) else {
        return negative_errno(libc::ENOMEM);
    };
    if noreplace && let Some(errno) = noreplace_error(memory, state, args, address, end) {
        return negative_errno(errno);
    }
    if address < BOOT_RESERVED_END || end > state.mmap_limit {
        return negative_errno(libc::ENOMEM);
    }
    // do_mmap refuses an unknown mapping type only after placement. For an
    // object that is not a regular file, the object probe below answers it,
    // after the object's extent check, as do_mmap orders them.
    if !matches!(kind, MappingKind::Other) && !is_private && !is_shared {
        return negative_errno(libc::EINVAL);
    }
    let Ok(length) = usize::try_from(length) else {
        return negative_errno(libc::ENOMEM);
    };
    let file_bytes = if !is_anonymous {
        // Linux syscall argument decoding consumes only the low descriptor word.
        let fd = args[4] as libc::c_int;
        let Some(file) = state.files.get(&fd) else {
            return negative_errno(libc::EBADF);
        };
        if is_shared && prot & libc::PROT_WRITE as u64 != 0 {
            let status = match file_status_flags(file) {
                Ok(status) => status,
                Err(error) => return error,
            };
            if status & libc::O_PATH != 0 {
                return negative_errno(libc::EBADF);
            }
            if status & libc::O_ACCMODE != libc::O_RDWR {
                return negative_errno(libc::EACCES);
            }
            // The backend copies file-backed mappings into guest memory rather
            // than asking host mmap to validate the descriptor. Preserve the
            // host's write-seal rejection before creating that writable copy.
            // SAFETY: file owns a live descriptor and F_GET_SEALS has no third argument.
            let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
            if seals >= 0 && seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0 {
                return negative_errno(libc::EPERM);
            }
            if seals < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINVAL) {
                    return io_error(error);
                }
            }
        }
        if !matches!(kind, MappingKind::RegularFile(_))
            && let Some(error) = host_mmap_probe(file.as_raw_fd(), args)
        {
            return error;
        }
        // Only the first chunk is read before the reservation. The rest is
        // streamed below, so the host never holds a copy of the whole range
        // beside the one in guest memory
        // (https://github.com/rrnewton/reverie/issues/1063).
        let mut first = vec![0; length.min(MMAP_FILE_CHUNK)];
        let read = match read_file_range(file, &mut first, args[5]) {
            Ok(read) => read,
            Err(error) => return io_error(error),
        };
        let reached_end = read < first.len();
        first.truncate(read);
        Some((file, first, reached_end))
    } else if args[4] as i32 != -1 {
        return negative_errno(libc::EINVAL);
    } else {
        None
    };

    let Ok(reservation) = memory.reserve_region(address, length as u64, RegionKind::Mmap) else {
        return negative_errno(libc::ENOMEM);
    };
    if memory.zero_lazily(address, length).is_err() {
        return negative_errno(libc::ENOMEM);
    }
    if let Some((file, first, reached_end)) = file_bytes {
        if memory.write_raw(address, &first).is_err() {
            return abandon_mapping(
                memory,
                reservation,
                address,
                length,
                negative_errno(libc::EFAULT),
            );
        }
        // The rest of the range, one chunk at a time. Every read_at runs
        // outside admission, so the unchanged-mapping fence never waits for
        // file I/O; each chunk is then written with one short admitted copy.
        // Bytes past the end of the file stay zero.
        if !reached_end {
            let mut buffer = vec![0; MMAP_FILE_CHUNK];
            let mut done = first.len();
            while done < length {
                let want = (length - done).min(MMAP_FILE_CHUNK);
                let read = match read_file_range(
                    file,
                    &mut buffer[..want],
                    args[5].saturating_add(done as u64),
                ) {
                    Ok(read) => read,
                    Err(error) => {
                        return abandon_mapping(
                            memory,
                            reservation,
                            address,
                            length,
                            io_error(error),
                        );
                    }
                };
                if read != 0
                    && memory
                        .write_raw(address + done as u64, &buffer[..read])
                        .is_err()
                {
                    return abandon_mapping(
                        memory,
                        reservation,
                        address,
                        length,
                        negative_errno(libc::EFAULT),
                    );
                }
                done += read;
                if read < want {
                    break;
                }
            }
        }
    }
    if memory
        .map_user_permissions(
            address,
            length as u64,
            prot != libc::PROT_NONE as u64,
            prot & libc::PROT_WRITE as u64 != 0,
        )
        .is_err()
    {
        return abandon_mapping(
            memory,
            reservation,
            address,
            length,
            negative_errno(libc::ENOMEM),
        );
    }

    reservation.commit();
    memory.record_page_backing(
        address,
        length as u64,
        kind.file_offset(),
        is_anonymous && is_shared,
    );
    if !fixed {
        state.mmap_next = state.mmap_next.max(end);
    }
    memory.physical_to_user(address).unwrap_or(address) as i64
}

/// The protection bits mmap honours; it ignores every other bit (Linux's
/// calc_vm_prot_bits drops PROT_SEM and unknown bits, and only mprotect
/// validates them).
pub(crate) const MMAP_PROT_BITS: u64 =
    (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;

/// Flags a host mmap probe clears from the guest's request: they choose where
/// a mapping goes, or ask for work beyond creating it (population, locking).
/// The probe maps at an address of the host's choosing and keeps nothing.
pub(super) const HOST_MMAP_PROBE_CLEARED_FLAGS: u64 = (libc::MAP_FIXED
    | libc::MAP_FIXED_NOREPLACE
    | libc::MAP_32BIT
    | libc::MAP_POPULATE
    | libc::MAP_LOCKED
    | libc::MAP_NONBLOCK) as u64;

/// The object's own answer to the guest's mmap of `fd`, for an object that is
/// not a regular file, asked of the host kernel after the guest's placement
/// has succeeded: the host maps `fd` with the guest's raw length, protection,
/// flags (less [`HOST_MMAP_PROBE_CLEARED_FLAGS`]) and offset at an address of
/// its choosing and removes the mapping at once. Returns the kernel's negative
/// errno when it refuses (the object's extent check, the mapping type and
/// MAP_SHARED_VALIDATE flag validation, the access mode, a missing mmap
/// operation), and `None` when it maps.
///
/// Every error, ENOMEM included, is the guest's answer for its original
/// request: the copy below never runs without a successful probe of that
/// exact extent. Absurd lengths do not reach the probe: the checks before
/// placement (zero, overflowing when page-aligned, overflowing the page
/// offset) and the guest's own placement refuse them first.
pub(crate) fn host_mmap_probe(fd: RawFd, args: &[u64; 6]) -> Option<i64> {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(error) = HOST_MMAP_PROBE_TEST_ANSWER.with(std::cell::Cell::get) {
        return Some(error);
    }
    host_mmap_probe_with(fd, args[1], args[2], args[3], args[5])
}

#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    /// A test's injected answer for every host mmap probe on this thread.
    pub(super) static HOST_MMAP_PROBE_TEST_ANSWER: std::cell::Cell<Option<i64>> =
        const { std::cell::Cell::new(None) };
}

/// Makes every host mmap probe on this thread answer `answer` until the
/// returned guard is dropped.
#[cfg(test)]
pub(super) fn inject_host_mmap_probe_answer(answer: i64) -> impl Drop {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOST_MMAP_PROBE_TEST_ANSWER.with(|slot| slot.set(None));
        }
    }
    HOST_MMAP_PROBE_TEST_ANSWER.with(|slot| slot.set(Some(answer)));
    Reset
}

fn host_mmap_probe_with(fd: RawFd, length: u64, prot: u64, flags: u64, offset: u64) -> Option<i64> {
    // SAFETY: without MAP_FIXED or MAP_FIXED_NOREPLACE the kernel places the
    // mapping where nothing is mapped, so no existing mapping is replaced;
    // nothing reads it, and it is unmapped below. The raw operands keep the
    // guest's bits, as its own mmap passes them.
    let mapped = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            0_u64,
            length,
            prot,
            flags & !HOST_MMAP_PROBE_CLEARED_FLAGS,
            fd as libc::c_long,
            offset,
        )
    };
    if mapped == -1 {
        return Some(io_error(std::io::Error::last_os_error()));
    }
    // SAFETY: the host returned this mapping of `length` bytes just above.
    let unmapped = unsafe { libc::munmap(mapped as *mut libc::c_void, length as usize) };
    debug_assert_eq!(unmapped, 0, "the probe mapping could not be removed");
    None
}

/// The refusals Linux gives before it places a file mapping, for a mapping of
/// an object that is not a regular file; `None` for anything else. They do not
/// depend on the object, and come in the kernel's order: x86-64's sys_mmap
/// refuses an unaligned offset (EINVAL); ksys_mmap_pgoff's descriptor lookup
/// refuses O_PATH (EBADF), then MAP_HUGETLB for a file outside hugetlbfs
/// (EINVAL; such a file is always regular); do_mmap refuses a zero length
/// (EINVAL), a length that overflows when page-aligned (ENOMEM) and a file
/// offset whose page index overflows with the length (EOVERFLOW). The
/// caller's placement checks follow, and the object's answer comes last from
/// [`host_mmap_probe`], as in do_mmap. These checks choose their errno here,
/// inside the executor that provides emulated Linux to injected calls.
pub(crate) fn non_regular_mmap_early_refusal(
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> Option<i64> {
    if args[3] & libc::MAP_ANONYMOUS as u64 != 0 {
        return None;
    }
    let file = state.files.get(&(args[4] as libc::c_int))?;
    match file_mode(file) {
        Ok(mode) if mode & libc::S_IFMT == libc::S_IFREG => return None,
        Ok(_) => {}
        Err(error) => return Some(error),
    }
    if !args[5].is_multiple_of(PAGE_SIZE) {
        return Some(negative_errno(libc::EINVAL));
    }
    match file_status_flags(file) {
        Ok(status) if status & libc::O_PATH != 0 => return Some(negative_errno(libc::EBADF)),
        Ok(_) => {}
        Err(error) => return Some(error),
    }
    if args[3] & libc::MAP_HUGETLB as u64 != 0 {
        return Some(negative_errno(libc::EINVAL));
    }
    if args[1] == 0 {
        return Some(negative_errno(libc::EINVAL));
    }
    let Some(length) = align_up(args[1], PAGE_SIZE) else {
        return Some(negative_errno(libc::ENOMEM));
    };
    let page_index = args[5] / PAGE_SIZE;
    if page_index.checked_add(length / PAGE_SIZE).is_none() {
        return Some(negative_errno(libc::EOVERFLOW));
    }
    None
}

/// Fails an mmap after its reservation, returning `result`.
///
/// By then the range has been zeroed and perhaps partly written from a file,
/// and for a MAP_FIXED mapping that range was the guest's old mapping.
/// Dropping the reservation would restore its ownership metadata but leave
/// the old mapping accessible with changed bytes, which Linux never produces:
/// a failed mmap leaves the old mapping intact or unmapped. So the range is
/// committed and then unmapped, as munmap leaves it
/// (https://github.com/rrnewton/reverie/pull/1066).
fn abandon_mapping(
    memory: &GuestMemory,
    reservation: crate::memory::PendingReservation,
    address: u64,
    length: usize,
    result: i64,
) -> i64 {
    reservation.commit();
    let _ = memory.zero_lazily(address, length);
    let _ = memory.unmap_user_range(address, length as u64);
    result
}

/// The host buffer a regular file's mmap is read through: the first chunk
/// before the reservation, then one chunk per admitted copy.
pub(super) const MMAP_FILE_CHUNK: usize = 64 * 1024;

/// Fills `buffer` from `file` at `offset`, stopping early only at end of file.
/// Returns the bytes read.
fn read_file_range(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    let mut count = 0;
    while count < buffer.len() {
        #[cfg(test)]
        entry_host_wait_tests::observe_mmap_file_read();
        match file.read_at(&mut buffer[count..], offset.saturating_add(count as u64)) {
            Ok(0) => break,
            Ok(read) => count += read,
            Err(error) => return Err(error),
        }
    }
    Ok(count)
}

pub(super) fn munmap<M: AddressSpace>(memory: &mut M, address: u64, length: u64) -> i64 {
    let Some(length) = align_up(length, PAGE_SIZE) else {
        return negative_errno(libc::EINVAL);
    };
    if address < memory.layout().reserved_end
        || !address.is_multiple_of(PAGE_SIZE)
        || length == 0
        || !range_is_valid(memory, address, length)
    {
        return negative_errno(libc::EINVAL);
    }
    match memory.unmap(address, length) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EINVAL),
    }
}

// Ordinary shared views synchronize the retained host mappings. Private and
// anonymous mappings retain Linux's mapped-range and flag validation behavior.
pub(super) fn msync(memory: &GuestMemory, args: &[u64; 6]) -> crate::Result<i64> {
    let address = args[0];
    let requested_length = args[1];
    let flags = args[2] as libc::c_int;
    let allowed_flags = libc::MS_ASYNC | libc::MS_SYNC | libc::MS_INVALIDATE;
    if !address.is_multiple_of(PAGE_SIZE)
        || flags & !allowed_flags != 0
        || flags & libc::MS_ASYNC != 0 && flags & libc::MS_SYNC != 0
    {
        return Ok(negative_errno(libc::EINVAL));
    }
    if requested_length == 0 {
        return Ok(0);
    }
    // Linux mm/msync.c rounds the unsigned length with wrapping arithmetic.
    // A rounded zero is a no-op; overflowing address + rounded length is not.
    // https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/mm/msync.c#L51
    let length = requested_length.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if length == 0 {
        return Ok(0);
    }
    let Ok(length) = usize::try_from(length) else {
        return Ok(negative_errno(libc::ENOMEM));
    };
    let Some(address) = memory.user_range_to_guest(address, length as u64) else {
        return Ok(negative_errno(libc::ENOMEM));
    };
    memory.sync_shared_file_range(address, length, flags)
}

pub(super) fn munmap_shared_file(
    memory: &GuestMemory,
    address: u64,
    length: u64,
    allocation: crate::memory::AllocationGuard<'_>,
) -> crate::Result<i64> {
    let Some(length) = align_up(length, PAGE_SIZE) else {
        return Ok(negative_errno(libc::EINVAL));
    };
    if address < BOOT_RESERVED_END
        || !address.is_multiple_of(PAGE_SIZE)
        || length == 0
        || !range_is_valid(&ProviderMemory(memory), address, length)
    {
        return Ok(negative_errno(libc::EINVAL));
    }
    let Ok(length) = usize::try_from(length) else {
        return Ok(negative_errno(libc::EINVAL));
    };
    let Some(address) = memory.user_range_to_guest(address, length as u64) else {
        return Ok(negative_errno(libc::EINVAL));
    };
    memory.publish_private_range(
        allocation,
        crate::memory::PrivateRangePlan {
            address,
            length,
            contents: None,
            permissions: None,
            cursors: None,
        },
    )?;
    Ok(0)
}

// TODO-HUMAN-REVIEW(PR-132): Review KVM mprotect user-copy enforcement.
pub(super) fn mprotect<M: AddressSpace>(memory: &M, args: &[u64; 6]) -> i64 {
    let address = args[0];
    let requested_length = args[1];
    let protection = args[2];
    let allowed_protection = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    if !address.is_multiple_of(PAGE_SIZE) || protection & !allowed_protection != 0 {
        return negative_errno(libc::EINVAL);
    }
    if requested_length == 0 {
        return 0;
    }
    let Some(length) = align_up(requested_length, PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    // The protection bits were validated above, so they fit a c_int.
    match memory.protect(address, length, protection as libc::c_int) {
        Ok(()) => 0,
        // An executable ordinary shared-file mapping: the refusal is already
        // recorded as the run's typed capability failure.
        Err(MapError::Unsupported) => negative_errno(libc::EIO),
        Err(MapError::AccessDenied) => negative_errno(libc::EACCES),
        Err(MapError::Unaddressable | MapError::NotMapped | MapError::Failed) => {
            negative_errno(libc::ENOMEM)
        }
    }
}

pub(super) fn mremap(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    // The source and a MREMAP_FIXED destination are user addresses (a window's,
    // in Linux's layout); the bookkeeping below is by physical address, and the
    // result is the user address of wherever the mapping ends up.
    let user_address = args[0];
    let Some(old_length) = align_up(args[1], PAGE_SIZE) else {
        return negative_errno(libc::EINVAL);
    };
    let Some(new_length) = align_up(args[2], PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let flags = args[3];
    let allowed_flags = (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64;
    if old_length == 0
        || new_length == 0
        || !user_address.is_multiple_of(PAGE_SIZE)
        || flags & !allowed_flags != 0
        || flags & libc::MREMAP_FIXED as u64 != 0 && flags & libc::MREMAP_MAYMOVE as u64 == 0
    {
        return negative_errno(libc::EINVAL);
    }
    let Some(old_address) = memory.user_range_to_guest(user_address, old_length) else {
        return negative_errno(libc::EINVAL);
    };
    if !memory.user_range_is_mapped(old_address, old_length) {
        return negative_errno(libc::EINVAL);
    }

    if flags & libc::MREMAP_FIXED as u64 == 0 && new_length <= old_length {
        if new_length < old_length {
            let tail = old_address + new_length;
            let Ok(length) = usize::try_from(old_length - new_length) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero_raw(tail, length).is_err() {
                return negative_errno(libc::EFAULT);
            }
        }
        if memory
            .remap_user_range(old_address, old_length, old_address, new_length)
            .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
        return user_address as i64;
    }

    let old_end = old_address + old_length;
    if flags & libc::MREMAP_FIXED as u64 == 0 {
        let Some(new_end) = old_address.checked_add(new_length) else {
            return negative_errno(libc::ENOMEM);
        };
        let extension_length = new_length - old_length;
        // The grown range must stay one run of user addresses: growing across
        // the identity end or a window's end would reach pages with no user
        // address.
        if new_end <= state.mmap_limit
            && memory.user_range_to_guest(user_address, new_length) == Some(old_address)
            && memory.find_unmapped_user_range(old_end, new_end, extension_length) == Some(old_end)
        {
            let Ok(extension) = usize::try_from(new_length - old_length) else {
                return negative_errno(libc::ENOMEM);
            };
            let Ok(reservation) = memory.reserve_remap_region(old_end, extension as u64) else {
                return negative_errno(libc::ENOMEM);
            };
            if memory.zero_raw(old_end, extension).is_err() {
                return negative_errno(libc::ENOMEM);
            }
            if memory
                .remap_user_range(old_address, old_length, old_address, new_length)
                .is_err()
            {
                return negative_errno(libc::ENOMEM);
            }
            reservation.commit();
            state.mmap_next = state.mmap_next.max(new_end);
            return user_address as i64;
        }
    }

    if flags & libc::MREMAP_MAYMOVE as u64 == 0 {
        return negative_errno(libc::ENOMEM);
    }
    let destination = if flags & libc::MREMAP_FIXED as u64 != 0 {
        let Some(destination) = memory.user_range_to_guest(args[4], new_length) else {
            return negative_errno(libc::EINVAL);
        };
        destination
    } else {
        let Some(destination) = find_mremap_destination(memory, state, old_address, new_length)
        else {
            return negative_errno(libc::ENOMEM);
        };
        destination
    };
    let Some(destination_end) = destination.checked_add(new_length) else {
        return negative_errno(libc::ENOMEM);
    };
    if destination < BOOT_RESERVED_END
        || !destination.is_multiple_of(PAGE_SIZE)
        || destination_end > state.mmap_limit
        || destination < old_end && old_address < destination_end
    {
        return negative_errno(libc::EINVAL);
    }

    let copy_length = old_length.min(new_length);
    let Ok(copy_length) = usize::try_from(copy_length) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(old_length_usize) = usize::try_from(old_length) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(new_length_usize) = usize::try_from(new_length) else {
        return negative_errno(libc::ENOMEM);
    };
    // Refuse a destination the remap below would refuse, before any byte is
    // copied or zeroed.
    if memory.range_contains_retained_shared(destination, new_length_usize) {
        return negative_errno(libc::EFAULT);
    }
    let Ok(reservation) = memory.reserve_region(destination, new_length, RegionKind::Mmap) else {
        return negative_errno(libc::EFAULT);
    };
    let mut bytes = vec![0; copy_length];
    if memory.read_raw(old_address, &mut bytes).is_err()
        || memory.zero_raw(destination, new_length_usize).is_err()
        || memory.write_raw(destination, &bytes).is_err()
        || memory.zero_raw(old_address, old_length_usize).is_err()
        || memory
            .remap_user_range(old_address, old_length, destination, new_length)
            .is_err()
    {
        return negative_errno(libc::EFAULT);
    }
    reservation.commit();
    if flags & libc::MREMAP_FIXED as u64 == 0 {
        state.mmap_next = state.mmap_next.max(destination_end);
    }
    memory.physical_to_user(destination).unwrap_or(destination) as i64
}

/// Advice whose effect, or whose possible failure, a program can observe and
/// this backend does not implement: what a fork copies or wipes, what a core
/// dump holds, locked-page discards, hole punching, page population and
/// collapse, injected memory failures, and guard regions. madvise(2) answers
/// it with ENOSYS.
pub(super) const MADVISE_UNIMPLEMENTED: [libc::c_int; 15] = [
    libc::MADV_DONTFORK,
    libc::MADV_DOFORK,
    libc::MADV_DONTDUMP,
    libc::MADV_DODUMP,
    libc::MADV_WIPEONFORK,
    libc::MADV_KEEPONFORK,
    libc::MADV_DONTNEED_LOCKED,
    libc::MADV_REMOVE,
    libc::MADV_POPULATE_READ,
    libc::MADV_POPULATE_WRITE,
    25, // MADV_COLLAPSE
    libc::MADV_HWPOISON,
    libc::MADV_SOFT_OFFLINE,
    102, // MADV_GUARD_INSTALL
    103, // MADV_GUARD_REMOVE
];

/// Every advice Linux accepts (`madvise_behavior_valid`, mm/madvise.c, v6.9,
/// with every optional advice configured), and the guard-region advice Linux
/// 6.13 added. madvise(2) answers any other value with EINVAL.
pub(super) const MADVISE_KNOWN: [libc::c_int; 27] = [
    libc::MADV_NORMAL,
    libc::MADV_RANDOM,
    libc::MADV_SEQUENTIAL,
    libc::MADV_WILLNEED,
    libc::MADV_DONTNEED,
    libc::MADV_FREE,
    libc::MADV_REMOVE,
    libc::MADV_DONTFORK,
    libc::MADV_DOFORK,
    libc::MADV_MERGEABLE,
    libc::MADV_UNMERGEABLE,
    libc::MADV_HUGEPAGE,
    libc::MADV_NOHUGEPAGE,
    libc::MADV_DONTDUMP,
    libc::MADV_DODUMP,
    libc::MADV_WIPEONFORK,
    libc::MADV_KEEPONFORK,
    libc::MADV_COLD,
    libc::MADV_PAGEOUT,
    libc::MADV_POPULATE_READ,
    libc::MADV_POPULATE_WRITE,
    libc::MADV_DONTNEED_LOCKED,
    25, // MADV_COLLAPSE
    libc::MADV_HWPOISON,
    libc::MADV_SOFT_OFFLINE,
    102, // MADV_GUARD_INSTALL
    103, // MADV_GUARD_REMOVE
];

/// madvise(2). `MADV_DONTNEED` drops the range's private anonymous pages,
/// which then read as zeros, and leaves shared pages (shared anonymous memory
/// and shared file views) as they are, as Linux keeps their contents. A private
/// copy of a regular file would have to read the file again, which this backend
/// cannot do, so a range holding one is refused with ENOSYS before any page
/// changes. Advice in [`MADVISE_UNIMPLEMENTED`] is refused with ENOSYS. Other
/// advice (the access-pattern hints, `MADV_FREE`, `MADV_COLD`, `MADV_PAGEOUT`,
/// the KSM and huge-page advice) is answered as a hint, which this backend does
/// not act on: success for a mapped range and ENOMEM for one with holes,
/// Linux's answer for advice it applies. Linux may instead refuse some of it
/// for a mapping of the wrong kind (for example `MADV_FREE` on a shared
/// mapping, EINVAL), which this backend does not model. Every advice first gets
/// Linux's argument checks (mm/madvise.c):
/// an advice outside [`MADVISE_KNOWN`] is EINVAL, the start must be page
/// aligned, the length is rounded up to whole pages, and a zero length
/// succeeds.
pub(super) fn madvise<M: AddressSpace>(memory: &M, args: &[u64; 6]) -> i64 {
    let advice = args[2] as libc::c_int;
    if !MADVISE_KNOWN.contains(&advice) {
        return negative_errno(libc::EINVAL);
    }
    let start = args[0];
    if !start.is_multiple_of(PAGE_SIZE) {
        return negative_errno(libc::EINVAL);
    }
    // Linux rounds the length up to whole pages: a length that rounds to zero
    // or a range that wraps is EINVAL, and a zero length succeeds.
    let length = args[1].wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if args[1] != 0 && length == 0 {
        return negative_errno(libc::EINVAL);
    }
    if start.checked_add(length).is_none() {
        return negative_errno(libc::EINVAL);
    }
    if length == 0 {
        return 0;
    }
    if MADVISE_UNIMPLEMENTED.contains(&advice) {
        return negative_errno(libc::ENOSYS);
    }
    if advice != libc::MADV_DONTNEED {
        // A hint: Linux applies it to the mapped parts and reports a hole.
        return match memory.query(start, length) {
            RangeState::Mapped => 0,
            _ => negative_errno(libc::ENOMEM),
        };
    }
    // Linux drops private anonymous pages, which then read as zeros.
    match memory.discard(start, length) {
        Ok(Discarded { had_holes: true }) => negative_errno(libc::ENOMEM),
        Ok(Discarded { had_holes: false }) => 0,
        // A private copy of a regular file would have to be read again.
        Err(MapError::Unsupported) => negative_errno(libc::ENOSYS),
        Err(_) => negative_errno(libc::EFAULT),
    }
}

// TODO-HUMAN-REVIEW(PR-145): Review flat guest-memory munlock validation semantics.
pub(super) fn munlock_guest_range<M: AddressSpace>(memory: &M, address: u64, length: u64) -> i64 {
    let page_start = address & !(PAGE_SIZE - 1);
    let page_offset = address - page_start;
    let page_length =
        length.wrapping_add(page_offset).wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_end = page_start.wrapping_add(page_length);
    if page_end < page_start {
        return negative_errno(libc::EINVAL);
    }
    if page_length != 0 && !range_is_valid(memory, page_start, page_length) {
        return negative_errno(libc::ENOMEM);
    }
    0
}

pub(super) fn mincore<M: GuestMemoryAccess<Error = crate::Error> + AddressSpace>(
    memory: &mut M,
    args: &[u64; 6],
) -> i64 {
    let address = args[0];
    let length = args[1];
    if length == 0 || !address.is_multiple_of(PAGE_SIZE) || !range_is_valid(memory, address, length)
    {
        return negative_errno(libc::EINVAL);
    }
    match memory.query(address, length) {
        RangeState::Mapped => {}
        RangeState::Unaddressable => return negative_errno(libc::EINVAL),
        RangeState::Unmapped | RangeState::Mixed => return negative_errno(libc::ENOMEM),
    }
    let Some(page_count) = length.checked_add(PAGE_SIZE - 1).map(|n| n / PAGE_SIZE) else {
        return negative_errno(libc::ENOMEM);
    };
    let Ok(page_count) = usize::try_from(page_count) else {
        return negative_errno(libc::ENOMEM);
    };
    let residency = vec![1_u8; page_count];
    match memory.write_exact(args[2], &residency) {
        Ok(()) => 0,
        Err(_) => negative_errno(libc::EFAULT),
    }
}
